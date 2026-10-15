const BRANDS = [
  "google",
  "microsoft",
  "paypal",
  "amazon",
  "apple",
  "facebook",
  "instagram",
  "linkedin",
  "netflix",
  "chase",
  "wellsfargo",
  "binance",
  "coinbase",
];

const SUSPICIOUS_TLDS = [
  ".xyz",
  ".top",
  ".click",
  ".work",
  ".info",
  ".buzz",
  ".fit",
  ".cam",
  ".monster",
];

const SUSPICIOUS_PATTERNS = [
  "login",
  "verify",
  "verification",
  "secure",
  "security",
  "account",
  "update",
  "password",
  "signin",
  "confirm",
  "bank",
  "wallet",
  "kyc",
  "billing",
];

export interface MLAnalysis {
  phishing_probability: number;
  ml_score: number;
  ml_verdict: string;
  model_type: string;
  top_signals: string[];
}

export interface TyposquattingResult {
  detected: boolean;
  brand: string | null;
  technique: string | null;
  risk_score: number;
  findings: string[];
}

export interface AnalysisResult {
  url: string;
  domain: string;
  verdict: "LOW RISK" | "SUSPICIOUS" | "HIGH RISK" | "INVALID";
  score: number;
  findings: string[];
  typosquatting?: TyposquattingResult;
  ml_analysis?: MLAnalysis;
  heuristics?: {
    score: number;
    is_ip: boolean;
    has_https: boolean;
  };
}

function levenshteinDistance(s1: string, s2: string): number {
  const m = s1.length;
  const n = s2.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (s1[i - 1] === s2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

function isIPv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d+$/.test(p)) return false;
    const n = parseInt(p, 10);
    return n >= 0 && n <= 255;
  });
}

function isIPAddress(host: string): boolean {
  if (isIPv4(host)) return true;
  return host.includes(":") || (host.startsWith("[") && host.endsWith("]"));
}

function isLegitimateBrandDomain(hostname: string, brand: string): boolean {
  const escaped = brand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(
    `^(?:[a-z0-9-]+\\.)*${escaped}\\.(?:[a-z]{2,3}\\.[a-z]{2}|[a-z]{2,})$`,
    "i"
  );
  return pattern.test(hostname);
}

export function analyzeUrl(inputUrl: string): AnalysisResult {
  const findings: string[] = [];
  let score = 0;

  if (!inputUrl || !inputUrl.trim()) {
    return {
      url: inputUrl || "",
      domain: "",
      verdict: "INVALID",
      score: 0,
      findings: ["No URL provided."],
    };
  }

  const rawUrl = inputUrl.trim();
  const hadExplicitScheme = rawUrl.startsWith("http://") || rawUrl.startsWith("https://");
  const normalizedUrl = hadExplicitScheme ? rawUrl : "https://" + rawUrl;

  let parsed: URL;
  try {
    parsed = new URL(normalizedUrl);
    if (!parsed.hostname) throw new Error("Missing hostname");
  } catch {
    return {
      url: inputUrl,
      domain: "",
      verdict: "INVALID",
      score: 0,
      findings: ["Invalid URL format."],
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = parsed.toString();

  // 1. Long URL
  if (fullUrl.length > 100) {
    score += 15;
    findings.push("URL is unusually long (>100 characters).");
  }

  // 2. IP address
  const isIp = isIPAddress(hostname);
  if (isIp) {
    score += 35;
    findings.push("URL uses a raw IP address instead of a domain name.");
  }

  // 3. @ symbol
  if (rawUrl.includes("@")) {
    score += 20;
    findings.push("URL contains '@', which can mask the true destination authority.");
  }

  // 4. Suspicious patterns
  const matchedPatterns: string[] = [];
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (new RegExp(pattern, "i").test(fullUrl)) {
      matchedPatterns.push(pattern);
    }
  }

  if (matchedPatterns.length > 0) {
    score += 15;
    findings.push(`Suspicious keywords detected: ${matchedPatterns.join(", ")}`);
  }

  // 5. Too many subdomains
  if (!isIp && hostname.split(".").length >= 4) {
    score += 15;
    findings.push("Domain contains an unusually large number of subdomains.");
  }

  // 6. Suspicious TLD
  for (const tld of SUSPICIOUS_TLDS) {
    if (hostname.endsWith(tld)) {
      score += 15;
      findings.push(`Domain uses potentially suspicious TLD: ${tld}`);
      break;
    }
  }

  // 7. Hyphen-heavy
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    score += 10;
    findings.push(`Domain contains multiple hyphens (${hyphenCount}).`);
  }

  // 8. Typosquatting / Brand Impersonation check
  let typoDetected = false;
  let matchedBrand: string | null = null;
  let typoTechnique: string | null = null;
  let typoScore = 0;

  for (const brand of BRANDS) {
    if (isLegitimateBrandDomain(hostname, brand)) continue;

    if (hostname.includes(brand)) {
      typoDetected = true;
      matchedBrand = brand;
      typoTechnique = "Brand Impersonation / Combo-squatting";
      typoScore = 35;
      findings.push(`Possible brand impersonation involving '${brand}'.`);
      break;
    }

    // Levenshtein distance check on core domain parts
    const parts = hostname.split(".");
    for (const part of parts.slice(0, -1)) {
      if (Math.abs(part.length - brand.length) <= 1 && part.length >= 4) {
        const dist = levenshteinDistance(part, brand);
        if (dist === 1) {
          typoDetected = true;
          matchedBrand = brand;
          typoTechnique = "Typosquatting (Edit Distance 1)";
          typoScore = 40;
          findings.push(`Typosquatting detected: '${part}' closely mimics '${brand}'.`);
          break;
        }
      }
    }
    if (typoDetected) break;
  }

  score += typoScore;

  // 9. Insecure HTTP
  if (parsed.protocol === "http:") {
    score += 10;
    findings.push("Connection does not use HTTPS.");
  }

  score = Math.min(score, 100);

  let verdict: "LOW RISK" | "SUSPICIOUS" | "HIGH RISK" = "LOW RISK";
  if (score >= 60) {
    verdict = "HIGH RISK";
  } else if (score >= 30) {
    verdict = "SUSPICIOUS";
  }

  if (findings.length === 0) {
    findings.push("No obvious phishing indicators detected. Safe to browse.");
  }

  return {
    url: fullUrl,
    domain: hostname,
    verdict,
    score,
    findings,
    heuristics: {
      score,
      is_ip: isIp,
      has_https: parsed.protocol === "https:",
    },
    typosquatting: {
      detected: typoDetected,
      brand: matchedBrand,
      technique: typoTechnique,
      risk_score: typoScore,
      findings: typoDetected ? [`Brand mimicry targeting '${matchedBrand}'`] : [],
    },
  };
}
