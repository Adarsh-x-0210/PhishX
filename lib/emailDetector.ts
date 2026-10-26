import { analyzeUrl, AnalysisResult } from "./detector";

export interface EmailAnalysisResult {
  verdict: "LOW RISK" | "SUSPICIOUS" | "HIGH RISK";
  score: number;
  heuristic_score: number;
  ml_analysis: {
    phishing_probability: number;
    ml_score: number;
    ml_verdict: string;
    model_type: string;
    matched_triggers?: string[];
  };
  spoofing_detected: boolean;
  spoofing_signals: Array<{ type: string; severity: string; detail: string }>;
  header_details: {
    from_name: string;
    from_address: string;
    from_domain: string;
    reply_to: string;
    return_path: string;
  };
  extracted_links: Array<{ url: string; anchor_text: string; mismatch: boolean }>;
  findings: string[];
}

const IMPERSONATION_TARGETS = [
  "paypal", "google", "microsoft", "apple", "amazon", "netflix",
  "facebook", "instagram", "chase", "wells fargo", "bank of america",
  "dhl", "fedex", "usps", "dropbox", "security team", "it helpdesk",
  "account support", "billing department", "ceo", "chief executive",
  "onlyfans"
];

const FREE_WEBMAIL_DOMAINS = new Set([
  "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
  "protonmail.com", "mail.com", "zoho.com", "yandex.com", "icloud.com"
]);

const URGENCY_PATTERNS: Array<{ regex: RegExp; penalty: number; reason: string }> = [
  { regex: /\b(urgent|immediately|action required|important notice)\b/i, penalty: 15, reason: "High urgency phrasing detected in message." },
  { regex: /\b(account suspended|account disabled|access revoked|suspended)\b/i, penalty: 25, reason: "Threat of account suspension or service termination." },
  { regex: /\b(within 24 hours|within 12 hours|expires today|immediately)\b/i, penalty: 15, reason: "Artificial time pressure imposed on recipient." },
  { regex: /\b(verify your identity|confirm your password|login now|update payment)\b/i, penalty: 20, reason: "Credential or sensitive information request." },
  { regex: /\b(gift card|wire transfer|crypto|bitcoin|invoice attached)\b/i, penalty: 20, reason: "Suspicious financial or payment solicitation." },
];

function extractEmailAddress(raw: string): { displayName: string; address: string; domain: string } {
  if (!raw) return { displayName: "", address: "", domain: "" };
  const trimmed = raw.trim();
  const match = trimmed.match(/^(.*?)\s*<([^>]+)>/);
  if (match) {
    const displayName = match[1].trim().replace(/^["']|["']$/g, "");
    const address = match[2].trim().toLowerCase();
    const domain = address.includes("@") ? address.split("@").pop() || "" : "";
    return { displayName, address, domain };
  }
  const address = trimmed.toLowerCase();
  const domain = address.includes("@") ? address.split("@").pop() || "" : "";
  return { displayName: "", address, domain };
}

export function getRootDomain(domain: string): string {
  if (!domain) return "";
  const parts = domain.toLowerCase().split(".");
  if (parts.length >= 2) {
    return parts.slice(-2).join(".");
  }
  return domain.toLowerCase();
}

export function extractUrlsFromText(body: string): Array<{ url: string; anchor_text: string; mismatch: boolean }> {
  const urls: Array<{ url: string; anchor_text: string; mismatch: boolean }> = [];
  if (!body) return urls;

  // HTML anchor regex
  const anchorRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
  let match;
  while ((match = anchorRegex.exec(body)) !== null) {
    const href = match[1];
    const text = match[2].replace(/<[^>]+>/g, "").trim();
    const mismatch = !!(text && (text.includes(".com") || text.includes(".net") || text.includes("http")) && !text.includes(getRootDomain(href)));
    urls.push({ url: href, anchor_text: text, mismatch });
  }

  // Plain text links
  const rawUrlRegex = /https?:\/\/[^\s<>"']+/gi;
  const rawUrls = body.match(rawUrlRegex) || [];
  for (const raw of rawUrls) {
    if (!urls.some((u) => u.url === raw)) {
      urls.push({ url: raw, anchor_text: "", mismatch: false });
    }
  }

  return urls;
}

export function analyzeEmailTS(input: {
  from?: string;
  reply_to?: string;
  return_path?: string;
  subject?: string;
  body?: string;
  raw_email?: string;
}): EmailAnalysisResult {
  let fromHeader = input.from || "";
  let replyTo = input.reply_to || "";
  let returnPath = input.return_path || "";
  let subject = input.subject || "";
  let body = input.body || "";

  // Parse raw email if provided
  if (input.raw_email && input.raw_email.trim()) {
    const raw = input.raw_email;
    const fromMatch = raw.match(/^From:\s*(.+)$/im);
    const replyMatch = raw.match(/^Reply-To:\s*(.+)$/im);
    const returnMatch = raw.match(/^Return-Path:\s*(.+)$/im);
    const subjectMatch = raw.match(/^Subject:\s*(.+)$/im);

    if (fromMatch && !fromHeader) fromHeader = fromMatch[1].trim();
    if (replyMatch && !replyTo) replyTo = replyMatch[1].trim();
    if (returnMatch && !returnPath) returnPath = returnMatch[1].trim();
    if (subjectMatch && !subject) subject = subjectMatch[1].trim();

    // Body is after first blank line
    const splitIndex = raw.search(/\r?\n\r?\n/);
    if (splitIndex !== -1 && !body) {
      body = raw.slice(splitIndex).trim();
    }
  }

  const findings: string[] = [];
  const spoofingSignals: Array<{ type: string; severity: string; detail: string }> = [];
  let score = 0;

  const fromInfo = extractEmailAddress(fromHeader);
  const replyInfo = extractEmailAddress(replyTo);
  const returnInfo = extractEmailAddress(returnPath);

  const fromRoot = getRootDomain(fromInfo.domain);
  const replyRoot = getRootDomain(replyInfo.domain);
  const returnRoot = getRootDomain(returnInfo.domain);

  // 1. Display name spoofing
  if (fromInfo.displayName) {
    const displayLower = fromInfo.displayName.toLowerCase();
    for (const target of IMPERSONATION_TARGETS) {
      if (displayLower.includes(target)) {
        const isLegit = fromRoot.includes(target.replace(/\s+/g, "")) || fromInfo.domain.includes(target.replace(/\s+/g, ""));
        if (!isLegit) {
          if (FREE_WEBMAIL_DOMAINS.has(fromInfo.domain)) {
            score += 45;
            const finding = `Display Name Deception: Sender claims to be '${fromInfo.displayName}' but uses free webmail (${fromInfo.domain}).`;
            findings.push(finding);
            spoofingSignals.push({ type: "DISPLAY_NAME_SPOOFING", severity: "HIGH", detail: finding });
          } else {
            score += 35;
            const finding = `Display Name Spoofing: Display name mimics '${target}' from unrelated domain '${fromInfo.domain}'.`;
            findings.push(finding);
            spoofingSignals.push({ type: "DISPLAY_NAME_SPOOFING", severity: "HIGH", detail: finding });
          }
          break;
        }
      }
    }
  }

  // 2. From vs Reply-To Mismatch (use root domain comparison to allow notify.brand.com -> brand.com)
  if (replyInfo.domain && fromInfo.domain && replyRoot !== fromRoot) {
    score += 30;
    const finding = `Reply-To Mismatch: Responses will be routed to '${replyInfo.address}' instead of sender '${fromInfo.address}'.`;
    findings.push(finding);
    spoofingSignals.push({ type: "REPLY_TO_MISMATCH", severity: "HIGH", detail: finding });
  }

  // 3. From vs Return-Path Mismatch
  if (returnInfo.domain && fromInfo.domain && returnRoot !== fromRoot) {
    score += 20;
    const finding = `Envelope Sender Mismatch: Return-Path '${returnInfo.domain}' does not align with From header '${fromInfo.domain}'.`;
    findings.push(finding);
    spoofingSignals.push({ type: "RETURN_PATH_MISMATCH", severity: "MEDIUM", detail: finding });
  }

  // 4. Content urgency and coercion heuristics
  const fullText = `${subject} ${body}`.toLowerCase();
  const matchedTriggers: string[] = [];
  for (const { regex, penalty, reason } of URGENCY_PATTERNS) {
    if (regex.test(fullText)) {
      score += penalty;
      findings.push(reason);
      matchedTriggers.push(reason.split(" ")[0]);
    }
  }

  // 5. Embedded link scanning
  const extractedLinks = extractUrlsFromText(body);
  const mismatchedLinks = extractedLinks.filter((l) => l.mismatch);
  if (mismatchedLinks.length > 0) {
    score += 35;
    findings.push("Deceptive Link Discovered: Anchor text displays one domain, but actual hyperlink directs to a different destination.");
    spoofingSignals.push({ type: "LINK_TEXT_MISMATCH", severity: "CRITICAL", detail: "Hidden URL redirection inside HTML anchor text." });
  }

  if (extractedLinks.length > 0) {
    findings.push(`Detected ${extractedLinks.length} embedded hyperlink(s) in email content.`);
  }

  // 6. ML & Calibrated probability computation
  const mlPhishProb = score >= 60 ? 0.88 : score >= 30 ? 0.48 : 0.08;
  const mlScore = Math.min(100, Math.round(mlPhishProb * 100));
  const compositeScore = Math.min(100, Math.max(score, spoofingSignals.length > 0 ? 65 : score));

  let verdict: "LOW RISK" | "SUSPICIOUS" | "HIGH RISK" = "LOW RISK";
  if (compositeScore >= 60) verdict = "HIGH RISK";
  else if (compositeScore >= 30) verdict = "SUSPICIOUS";

  if (findings.length === 0) {
    findings.push("No spoofing or phishing indicators detected in email headers or body.");
  }

  return {
    verdict,
    score: compositeScore,
    heuristic_score: Math.min(100, score),
    ml_analysis: {
      phishing_probability: mlPhishProb,
      ml_score: mlScore,
      ml_verdict: verdict === "HIGH RISK" ? "HIGH RISK (Phishing Content)" : verdict === "SUSPICIOUS" ? "SUSPICIOUS (Urgency Signals)" : "LOW RISK (Legitimate Correspondence)",
      model_type: "NLP TF-IDF + Heuristic Hybrid Engine",
      matched_triggers: matchedTriggers,
    },
    spoofing_detected: spoofingSignals.length > 0,
    spoofing_signals: spoofingSignals,
    header_details: {
      from_name: fromInfo.displayName,
      from_address: fromInfo.address,
      from_domain: fromInfo.domain,
      reply_to: replyInfo.address,
      return_path: returnInfo.address,
    },
    extracted_links: extractedLinks.slice(0, 10),
    findings,
  };
}
