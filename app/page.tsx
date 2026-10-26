"use client";

import { useState, useRef } from "react";

type MLAnalysis = {
  phishing_probability: number;
  ml_score: number;
  ml_verdict: string;
  model_type: string;
  top_signals?: string[];
  matched_triggers?: string[];
};

type TyposquattingInfo = {
  detected: boolean;
  brand?: string | null;
  technique?: string | null;
  risk_score?: number;
  findings?: string[];
};

type UrlAnalysisResult = {
  url: string;
  domain: string;
  verdict: "LOW RISK" | "SUSPICIOUS" | "HIGH RISK" | "INVALID";
  score: number;
  findings: string[];
  heuristics?: {
    score: number;
    is_ip: boolean;
    has_https: boolean;
  };
  typosquatting?: TyposquattingInfo;
  ml_analysis?: MLAnalysis;
};

type EmailAnalysisResult = {
  verdict: "LOW RISK" | "SUSPICIOUS" | "HIGH RISK";
  score: number;
  heuristic_score: number;
  ml_analysis: MLAnalysis;
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
};

type QRAnalysisResult = {
  success: boolean;
  payload: string;
  payload_type: string;
  verdict: "LOW RISK" | "SUSPICIOUS" | "HIGH RISK" | "INVALID";
  score: number;
  quishing_detected: boolean;
  quishing_signals?: Array<{ type: string; severity: string; detail: string }>;
  url_analysis?: UrlAnalysisResult;
  findings: string[];
  error?: string;
};

export default function Home() {
  const [activeTab, setActiveTab] = useState<"url" | "email" | "qr">("url");

  // URL State
  const [url, setUrl] = useState("");
  const [urlResult, setUrlResult] = useState<UrlAnalysisResult | null>(null);

  // Email State
  const [emailMode, setEmailMode] = useState<"form" | "raw">("form");
  const [fromHeader, setFromHeader] = useState("");
  const [replyTo, setReplyTo] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [rawEmail, setRawEmail] = useState("");
  const [emailResult, setEmailResult] = useState<EmailAnalysisResult | null>(null);

  // QR State
  const [qrFile, setQrFile] = useState<File | null>(null);
  const [qrPreview, setQrPreview] = useState<string | null>(null);
  const [qrResult, setQrResult] = useState<QRAnalysisResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Loading & Error States
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // =================== Handlers ===================

  const analyzeUrl = async (targetUrl?: string) => {
    const inputUrl = (targetUrl !== undefined ? targetUrl : url).trim();
    if (!inputUrl) {
      setError("Please enter a URL to scan.");
      return;
    }

    setLoading(true);
    setError("");
    setUrlResult(null);

    try {
      const response = await fetch("/api/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: inputUrl }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "URL Analysis failed.");
      }
      setUrlResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to analyze URL.");
    } finally {
      setLoading(false);
    }
  };

  const analyzeEmail = async () => {
    setLoading(true);
    setError("");
    setEmailResult(null);

    try {
      const payload =
        emailMode === "raw"
          ? { raw_email: rawEmail }
          : {
              from: fromHeader,
              reply_to: replyTo,
              subject,
              body,
            };

      const response = await fetch("/api/email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Email Analysis failed.");
      }
      setEmailResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to analyze email.");
    } finally {
      setLoading(false);
    }
  };

  const handleQrUpload = (file: File) => {
    setQrFile(file);
    setError("");
    setQrResult(null);

    const reader = new FileReader();
    reader.onload = (e) => {
      setQrPreview(e.target?.result as string);
    };
    reader.readAsDataURL(file);
  };

  const analyzeQr = async () => {
    if (!qrPreview && !qrFile) {
      setError("Please select or drop a QR code image to analyze.");
      return;
    }

    setLoading(true);
    setError("");
    setQrResult(null);

    try {
      const response = await fetch("/api/qr", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image: qrPreview }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "QR Code decoding failed.");
      }
      setQrResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to analyze QR code.");
    } finally {
      setLoading(false);
    }
  };

  // Helper badge style
  const getVerdictStyle = (verdict?: string, score: number = 0) => {
    if (verdict === "INVALID") return "text-gray-400 border-gray-800 bg-gray-900/50";
    if (score >= 60 || verdict?.includes("HIGH"))
      return "text-red-400 border-red-800/80 bg-red-950/40 shadow-red-900/20";
    if (score >= 30 || verdict?.includes("SUSPICIOUS"))
      return "text-yellow-400 border-yellow-800/80 bg-yellow-950/40 shadow-yellow-900/20";
    return "text-emerald-400 border-emerald-800/80 bg-emerald-950/40 shadow-emerald-900/20";
  };

  const getScoreColor = (score: number) => {
    if (score >= 60) return "text-red-500";
    if (score >= 30) return "text-yellow-400";
    return "text-emerald-400";
  };

  return (
    <main className="min-h-screen bg-[#07090e] text-slate-100 px-4 sm:px-6 py-10 selection:bg-red-900 selection:text-white">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <header className="text-center mb-10">
          {/* Tagline Badge */}
          <div className="flex items-center justify-center mb-5">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-red-500/30 bg-red-950/30 text-xs font-semibold tracking-wider text-red-400 uppercase">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
              Next-Gen Threat Intelligence
            </div>
          </div>

          {/* PhishX Shield Icon */}
          <div className="flex items-center justify-center gap-3.5">
            <div className="w-12 h-12 sm:w-14 sm:h-14 rounded-2xl bg-gradient-to-br from-red-600/20 via-slate-900 to-slate-950 border border-red-500/40 p-2.5 flex items-center justify-center shadow-lg shadow-red-950/50">
              <svg viewBox="0 0 64 64" fill="none" className="w-full h-full drop-shadow-[0_0_10px_rgba(239,68,68,0.7)]">
                <path d="M32 4 L56 12 C56 36 44 52 32 60 C20 52 8 36 8 12 Z" fill="#090d16" stroke="#ef4444" strokeWidth="3" />
                <path d="M22 20 L42 44" stroke="#ffffff" strokeWidth="5" strokeLinecap="round" />
                <path d="M42 20 L22 44" stroke="#ffffff" strokeWidth="5" strokeLinecap="round" />
                <circle cx="32" cy="32" r="3.5" fill="#ef4444" />
              </svg>
            </div>

            <h1 className="text-5xl sm:text-6xl font-extrabold tracking-tight">
              PHISH<span className="text-red-500 drop-shadow-[0_0_25px_rgba(239,68,68,0.6)]">X</span>
            </h1>
          </div>

          <p className="text-slate-400 mt-3 text-base sm:text-lg max-w-xl mx-auto">
            Multi-Vector Phishing Detection System powered by Machine Learning, Heuristic Indicators, and Typosquatting String Matching.
          </p>
        </header>

        {/* Main Card */}
        <div className="border border-slate-800/80 rounded-2xl p-6 sm:p-8 bg-slate-950/90 shadow-2xl backdrop-blur-xl">
          {/* Vector Selector Tabs */}
          <div className="grid grid-cols-3 gap-2 p-1.5 bg-slate-900/90 border border-slate-800 rounded-xl mb-8">
            <button
              onClick={() => {
                setActiveTab("url");
                setError("");
              }}
              className={`py-3 px-4 rounded-lg font-medium text-sm transition flex items-center justify-center gap-2 ${
                activeTab === "url"
                  ? "bg-red-600 text-white shadow-lg shadow-red-900/40"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
            >
              <span>🔗</span>
              <span>URL Scanner</span>
            </button>

            <button
              onClick={() => {
                setActiveTab("email");
                setError("");
              }}
              className={`py-3 px-4 rounded-lg font-medium text-sm transition flex items-center justify-center gap-2 ${
                activeTab === "email"
                  ? "bg-red-600 text-white shadow-lg shadow-red-900/40"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
            >
              <span>📧</span>
              <span>Email & Headers</span>
            </button>

            <button
              onClick={() => {
                setActiveTab("qr");
                setError("");
              }}
              className={`py-3 px-4 rounded-lg font-medium text-sm transition flex items-center justify-center gap-2 ${
                activeTab === "qr"
                  ? "bg-red-600 text-white shadow-lg shadow-red-900/40"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
            >
              <span>📱</span>
              <span>QR Quishing</span>
            </button>
          </div>

          {/* ===================== TAB 1: URL SCANNER ===================== */}
          {activeTab === "url" && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium text-slate-300">
                  Target URL to Analyze
                </label>
                <div className="flex gap-2 text-xs">
                  <span className="text-slate-500">Quick tests:</span>
                  <button
                    onClick={() => {
                      const testU = "http://paypal.com.verify-login.xyz/account/login.php";
                      setUrl(testU);
                      analyzeUrl(testU);
                    }}
                    className="text-red-400 hover:underline"
                  >
                    Phishing Bank
                  </button>
                  <span className="text-slate-600">•</span>
                  <button
                    onClick={() => {
                      const testU = "https://paypa1-security.com";
                      setUrl(testU);
                      analyzeUrl(testU);
                    }}
                    className="text-yellow-400 hover:underline"
                  >
                    Typosquatting
                  </button>
                  <span className="text-slate-600">•</span>
                  <button
                    onClick={() => {
                      const testU = "https://google.com";
                      setUrl(testU);
                      analyzeUrl(testU);
                    }}
                    className="text-emerald-400 hover:underline"
                  >
                    Safe Google
                  </button>
                </div>
              </div>

              <div className="relative">
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") analyzeUrl();
                  }}
                  placeholder="e.g. http://login.microsoft.security-verify.xyz/auth"
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-4 text-slate-100 placeholder-slate-500 outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500 transition font-mono text-sm"
                />
              </div>

              <button
                onClick={() => analyzeUrl()}
                disabled={loading}
                className="w-full mt-4 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-500 text-white font-semibold py-3.5 rounded-xl transition shadow-lg shadow-red-950/50 cursor-pointer flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <svg className="animate-spin h-5 w-5 text-white" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                    </svg>
                    <span>EVALUATING HEURISTICS & RUNNING ML MODEL...</span>
                  </>
                ) : (
                  <span>ANALYZE URL MULTI-VECTOR RISK</span>
                )}
              </button>
            </div>
          )}

          {/* ===================== TAB 2: EMAIL SCANNER ===================== */}
          {activeTab === "email" && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex gap-2 bg-slate-900 p-1 border border-slate-800 rounded-lg text-xs">
                  <button
                    onClick={() => setEmailMode("form")}
                    className={`px-3 py-1.5 rounded-md font-medium transition ${
                      emailMode === "form" ? "bg-red-600 text-white" : "text-slate-400 hover:text-white"
                    }`}
                  >
                    Structured Fields
                  </button>
                  <button
                    onClick={() => setEmailMode("raw")}
                    className={`px-3 py-1.5 rounded-md font-medium transition ${
                      emailMode === "raw" ? "bg-red-600 text-white" : "text-slate-400 hover:text-white"
                    }`}
                  >
                    Raw RFC 822 EML
                  </button>
                </div>

                <div className="flex gap-2 text-xs">
                  <span className="text-slate-500">Presets:</span>
                  <button
                    onClick={() => {
                      setEmailMode("form");
                      setFromHeader('"PayPal Security" <service@paypa1-security.xyz>');
                      setReplyTo("attacker.inbox@gmail.com");
                      setSubject("URGENT: Unauthorized access detected on your account");
                      setBody("Dear client, your PayPal account has been temporarily limited. Click here immediately to confirm identity: http://paypal.com.verify-login.xyz/account");
                    }}
                    className="text-red-400 hover:underline"
                  >
                    Spoofed PayPal
                  </button>
                  <span className="text-slate-600">•</span>
                  <button
                    onClick={() => {
                      setEmailMode("form");
                      setFromHeader('"CEO Office" <ceo.internal@yahoo.com>');
                      setReplyTo("exec-confidential@mail.com");
                      setSubject("Quick task: Apple gift cards needed for board presentation");
                      setBody("I am currently in an urgent offsite board meeting. Please purchase 5 x $100 Apple gift cards and reply with the code numbers immediately. Do not call.");
                    }}
                    className="text-yellow-400 hover:underline"
                  >
                    CEO Fraud
                  </button>
                  <span className="text-slate-600">•</span>
                  <button
                    onClick={() => {
                      setEmailMode("form");
                      setFromHeader('"Sarah Jenkins" <sarah@google.com>');
                      setReplyTo("sarah@google.com");
                      setSubject("Meeting notes & sprint deliverables for next Monday");
                      setBody("Hi team, please find the updated roadmap document in Google Drive. Let me know if anyone has suggestions.");
                    }}
                    className="text-emerald-400 hover:underline"
                  >
                    Safe Email
                  </button>
                </div>
              </div>

              {emailMode === "form" ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        From Header (Display Name & Address)
                      </label>
                      <input
                        type="text"
                        value={fromHeader}
                        onChange={(e) => setFromHeader(e.target.value)}
                        placeholder='e.g. "PayPal Support" <alerts@paypa1.xyz>'
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2.5 text-sm outline-none focus:border-red-500 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        Reply-To Header (Optional)
                      </label>
                      <input
                        type="text"
                        value={replyTo}
                        onChange={(e) => setReplyTo(e.target.value)}
                        placeholder="e.g. attacker@gmail.com"
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2.5 text-sm outline-none focus:border-red-500 font-mono"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">
                      Email Subject
                    </label>
                    <input
                      type="text"
                      value={subject}
                      onChange={(e) => setSubject(e.target.value)}
                      placeholder="e.g. URGENT: Your account has been suspended"
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2.5 text-sm outline-none focus:border-red-500 font-medium"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1">
                      Email Body / Message Text
                    </label>
                    <textarea
                      rows={4}
                      value={body}
                      onChange={(e) => setBody(e.target.value)}
                      placeholder="Paste the email body or HTML text here..."
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-sm outline-none focus:border-red-500 font-mono"
                    />
                  </div>
                </div>
              ) : (
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    Raw RFC 822 Headers & MIME Body (.eml format)
                  </label>
                  <textarea
                    rows={8}
                    value={rawEmail}
                    onChange={(e) => setRawEmail(e.target.value)}
                    placeholder={`From: "Security Alert" <alert@attacker.xyz>\nReply-To: phisher@gmail.com\nSubject: Account Verification Required\nReceived-SPF: fail\n\nPlease verify your credentials now...`}
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs outline-none focus:border-red-500 font-mono"
                  />
                </div>
              )}

              <button
                onClick={analyzeEmail}
                disabled={loading}
                className="w-full mt-4 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-500 text-white font-semibold py-3.5 rounded-xl transition shadow-lg shadow-red-950/50 cursor-pointer flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <svg className="animate-spin h-5 w-5 text-white" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                    </svg>
                    <span>PARSING HEADERS & RUNNING NLP CLASSIFIER...</span>
                  </>
                ) : (
                  <span>INSPECT EMAIL FOR SPOOFING & PHISHING</span>
                )}
              </button>
            </div>
          )}

          {/* ===================== TAB 3: QR CODE SCANNER ===================== */}
          {activeTab === "qr" && (
            <div>
              <div className="flex items-center justify-between mb-3">
                <label className="block text-sm font-medium text-slate-300">
                  Upload QR Code Image (Quishing Analysis)
                </label>
                <button
                  type="button"
                  onClick={async () => {
                    // Quick generator of test quishing QR code via canvas
                    try {
                      const canvas = document.createElement("canvas");
                      canvas.width = 200;
                      canvas.height = 200;
                      const ctx = canvas.getContext("2d");
                      if (ctx) {
                        ctx.fillStyle = "#ffffff";
                        ctx.fillRect(0, 0, 200, 200);
                        ctx.fillStyle = "#000000";
                        ctx.fillRect(20, 20, 50, 50);
                        ctx.fillRect(130, 20, 50, 50);
                        ctx.fillRect(20, 130, 50, 50);
                      }
                      // Use an online sample or fallback base64
                      setUrl("http://paypal.com.verify-login.xyz/account/login.php");
                      setActiveTab("url");
                      analyzeUrl("http://paypal.com.verify-login.xyz/account/login.php");
                    } catch {}
                  }}
                  className="text-xs text-red-400 hover:underline"
                >
                  Need a sample? Test Quishing link
                </button>
              </div>

              {/* Upload Dropzone */}
              <div
                onClick={() => fileInputRef.current?.click()}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (e.dataTransfer.files?.[0]) {
                    handleQrUpload(e.dataTransfer.files[0]);
                  }
                }}
                className="border-2 border-dashed border-slate-700 hover:border-red-500/80 rounded-2xl p-8 text-center cursor-pointer bg-slate-900/60 transition group"
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={(e) => {
                    if (e.target.files?.[0]) {
                      handleQrUpload(e.target.files[0]);
                    }
                  }}
                />

                {qrPreview ? (
                  <div className="flex flex-col items-center">
                    <img
                      src={qrPreview}
                      alt="Uploaded QR Code"
                      className="w-40 h-40 object-contain rounded-lg border border-slate-700 bg-white p-2 mb-3 shadow-lg"
                    />
                    <p className="text-sm text-slate-300 font-medium">
                      {qrFile?.name || "QR Code Image Loaded"}
                    </p>
                    <p className="text-xs text-slate-500 mt-1">
                      Click to replace image
                    </p>
                  </div>
                ) : (
                  <div className="flex flex-col items-center">
                    <div className="w-16 h-16 rounded-full bg-slate-800/80 group-hover:bg-red-950/50 flex items-center justify-center text-3xl mb-3 transition">
                      📱
                    </div>
                    <p className="text-base font-semibold text-slate-200">
                      Click to upload or drag & drop QR code image
                    </p>
                    <p className="text-xs text-slate-400 mt-1">
                      Supports PNG, JPG, JPEG, WEBP, or screenshot snips
                    </p>
                  </div>
                )}
              </div>

              <button
                onClick={analyzeQr}
                disabled={loading || !qrPreview}
                className="w-full mt-4 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-500 text-white font-semibold py-3.5 rounded-xl transition shadow-lg shadow-red-950/50 cursor-pointer flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <svg className="animate-spin h-5 w-5 text-white" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                    </svg>
                    <span>DECODING QR & ANALYZING PAYLOAD WITH ML...</span>
                  </>
                ) : (
                  <span>DECODE & SCAN QR CODE</span>
                )}
              </button>
            </div>
          )}

          {/* Error Banner */}
          {error && (
            <div className="mt-6 p-4 rounded-xl border border-red-800/80 bg-red-950/50 text-red-300 text-sm flex items-start gap-3 shadow-lg">
              <span className="text-lg shrink-0">⚠️</span>
              <div>
                <p className="font-semibold">Analysis Notice</p>
                <p className="text-xs text-red-200/90 mt-0.5">{error}</p>
              </div>
            </div>
          )}
        </div>

        {/* ===================== RESULT CARDS ===================== */}

        {/* URL Scanner Result */}
        {activeTab === "url" && urlResult && (
          <div className="mt-8 border border-slate-800 rounded-2xl p-6 sm:p-8 bg-slate-950 shadow-2xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-slate-800/80 gap-4">
              <div>
                <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Target Domain
                </div>
                <div className="text-xl sm:text-2xl font-bold font-mono text-white mt-1 break-all">
                  {urlResult.domain || urlResult.url}
                </div>
              </div>

              <div
                className={`px-5 py-2.5 rounded-xl border text-center ${getVerdictStyle(
                  urlResult.verdict,
                  urlResult.score
                )}`}
              >
                <div className="text-[10px] font-bold tracking-widest uppercase">
                  Verdict
                </div>
                <div className="text-xl font-extrabold tracking-tight">
                  {urlResult.verdict}
                </div>
              </div>
            </div>

            {/* Score & Metrics Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 my-6">
              {/* Overall Risk Score */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 text-center">
                <span className="text-xs text-slate-400 font-medium">Composite Risk Score</span>
                <div className={`text-4xl font-black mt-1 ${getScoreColor(urlResult.score)}`}>
                  {urlResult.score}
                  <span className="text-sm font-normal text-slate-500">/100</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-1.5 mt-3 overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      urlResult.score >= 60 ? "bg-red-500" : urlResult.score >= 30 ? "bg-yellow-500" : "bg-emerald-500"
                    }`}
                    style={{ width: `${urlResult.score}%` }}
                  />
                </div>
              </div>

              {/* Typosquatting Check */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
                <span className="text-xs text-slate-400 font-medium">Typosquatting Check</span>
                <div className="mt-2 text-sm">
                  {urlResult.typosquatting?.detected ? (
                    <div className="text-red-400 font-semibold flex items-center gap-1.5">
                      <span>⚠️ Mimics:</span>
                      <span className="font-mono uppercase px-2 py-0.5 bg-red-950/80 border border-red-800/60 rounded text-xs">
                        {urlResult.typosquatting.brand}
                      </span>
                    </div>
                  ) : (
                    <div className="text-emerald-400 font-medium flex items-center gap-1.5">
                      <span>✅ No Brand Spoofing</span>
                    </div>
                  )}
                  <p className="text-xs text-slate-500 mt-1.5">
                    {urlResult.typosquatting?.technique || "Levenshtein & Homoglyph test passed"}
                  </p>
                </div>
              </div>

              {/* Machine Learning Model */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
                <span className="text-xs text-slate-400 font-medium">Machine Learning Engine</span>
                <div className="mt-1">
                  <div className="flex items-baseline justify-between">
                    <span className="text-xs text-slate-400">Phish Probability:</span>
                    <span
                      className={`text-lg font-bold font-mono ${
                        (urlResult.ml_analysis?.phishing_probability ?? 0) >= 0.6
                          ? "text-red-400"
                          : (urlResult.ml_analysis?.phishing_probability ?? 0) >= 0.3
                          ? "text-yellow-400"
                          : "text-emerald-400"
                      }`}
                    >
                      {Math.round((urlResult.ml_analysis?.phishing_probability ?? 0) * 100)}%
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 mt-1 truncate">
                    {urlResult.ml_analysis?.model_type || "Random Forest Classifier"}
                  </p>
                </div>
              </div>
            </div>

            {/* ML Signals if available */}
            {urlResult.ml_analysis?.top_signals && urlResult.ml_analysis.top_signals.length > 0 && (
              <div className="mb-6 bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <span>🤖 Machine Learning Feature Indicators</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {urlResult.ml_analysis.top_signals.map((sig, i) => (
                    <span
                      key={i}
                      className="px-2.5 py-1 rounded-md bg-slate-800 text-slate-300 text-xs font-mono border border-slate-700"
                    >
                      {sig}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Heuristic Findings */}
            <div>
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-3">
                Detected Indicators & Heuristics
              </h3>
              <div className="space-y-2">
                {urlResult.findings.map((finding, idx) => {
                  const isSafe = urlResult.score < 30 && urlResult.verdict !== "INVALID";
                  return (
                    <div
                      key={idx}
                      className={`border rounded-xl p-3 text-sm flex items-start gap-2.5 ${
                        isSafe
                          ? "border-emerald-800/40 bg-emerald-950/20 text-emerald-300"
                          : urlResult.score >= 60
                          ? "border-red-800/40 bg-red-950/20 text-red-300"
                          : "border-yellow-800/40 bg-yellow-950/20 text-yellow-300"
                      }`}
                    >
                      <span className="shrink-0">{isSafe ? "✅" : "⚠️"}</span>
                      <span>{finding}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* Email Scanner Result */}
        {activeTab === "email" && emailResult && (
          <div className="mt-8 border border-slate-800 rounded-2xl p-6 sm:p-8 bg-slate-950 shadow-2xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-slate-800/80 gap-4">
              <div>
                <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Email Authentication & Content Result
                </div>
                <div className="text-xl sm:text-2xl font-bold text-white mt-1">
                  {emailResult.spoofing_detected ? "Address Spoofing Detected" : "Standard Email Flow"}
                </div>
              </div>

              <div
                className={`px-5 py-2.5 rounded-xl border text-center ${getVerdictStyle(
                  emailResult.verdict,
                  emailResult.score
                )}`}
              >
                <div className="text-[10px] font-bold tracking-widest uppercase">
                  Verdict
                </div>
                <div className="text-xl font-extrabold tracking-tight">
                  {emailResult.verdict}
                </div>
              </div>
            </div>

            {/* Email Header Details Card */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 my-6">
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 text-center">
                <span className="text-xs text-slate-400 font-medium">Email Threat Score</span>
                <div className={`text-4xl font-black mt-1 ${getScoreColor(emailResult.score)}`}>
                  {emailResult.score}
                  <span className="text-sm font-normal text-slate-500">/100</span>
                </div>
              </div>

              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
                <span className="text-xs text-slate-400 font-medium">Spoofing Signals</span>
                <div className="mt-2 text-sm">
                  {emailResult.spoofing_detected ? (
                    <span className="text-red-400 font-semibold">
                      🚨 {emailResult.spoofing_signals.length} Spoofing Anomaly Flagged
                    </span>
                  ) : (
                    <span className="text-emerald-400 font-semibold">
                      ✅ Headers Aligned
                    </span>
                  )}
                  <p className="text-xs text-slate-500 mt-1">
                    From: {emailResult.header_details.from_address || "None"}
                  </p>
                </div>
              </div>

              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
                <span className="text-xs text-slate-400 font-medium">NLP Content Classifier</span>
                <div className="mt-1 flex items-baseline justify-between">
                  <span className="text-xs text-slate-400">ML Phish Prob:</span>
                  <span className="text-lg font-bold font-mono text-red-400">
                    {Math.round(emailResult.ml_analysis.phishing_probability * 100)}%
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  {emailResult.ml_analysis.ml_verdict}
                </p>
              </div>
            </div>

            {/* Spoofing Signals Breakdown */}
            {emailResult.spoofing_signals.length > 0 && (
              <div className="mb-6 space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-red-400">
                  Header Spoofing Flags
                </h3>
                {emailResult.spoofing_signals.map((sig, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-lg border border-red-800/60 bg-red-950/30 text-xs text-red-200"
                  >
                    <span className="font-bold uppercase text-red-400 mr-2">
                      [{sig.type} - {sig.severity}]:
                    </span>
                    {sig.detail}
                  </div>
                ))}
              </div>
            )}

            {/* Extracted Links */}
            {emailResult.extracted_links.length > 0 && (
              <div className="mb-6">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Extracted Links in Body ({emailResult.extracted_links.length})
                </h3>
                <div className="space-y-1.5 font-mono text-xs">
                  {emailResult.extracted_links.map((link, i) => (
                    <div
                      key={i}
                      className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between"
                    >
                      <span className="truncate max-w-md text-slate-300">{link.url}</span>
                      <button
                        onClick={() => {
                          setUrl(link.url);
                          setActiveTab("url");
                          analyzeUrl(link.url);
                        }}
                        className="text-xs text-red-400 hover:text-red-300 underline font-sans ml-2 shrink-0"
                      >
                        Scan Link →
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* General Findings */}
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                Analysis Observations
              </h3>
              <div className="space-y-1.5 text-xs text-slate-300">
                {emailResult.findings.map((f, i) => (
                  <div key={i} className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80">
                    • {f}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* QR Scanner Result */}
        {activeTab === "qr" && qrResult && (
          <div className="mt-8 border border-slate-800 rounded-2xl p-6 sm:p-8 bg-slate-950 shadow-2xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-slate-800/80 gap-4">
              <div>
                <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  QR Code Payload ({qrResult.payload_type})
                </div>
                <div className="text-lg sm:text-xl font-bold font-mono text-white mt-1 break-all">
                  {qrResult.payload}
                </div>
              </div>

              <div
                className={`px-5 py-2.5 rounded-xl border text-center ${getVerdictStyle(
                  qrResult.verdict,
                  qrResult.score
                )}`}
              >
                <div className="text-[10px] font-bold tracking-widest uppercase">
                  Verdict
                </div>
                <div className="text-xl font-extrabold tracking-tight">
                  {qrResult.verdict}
                </div>
              </div>
            </div>

            {/* Quishing Banner */}
            {qrResult.quishing_detected && (
              <div className="my-6 p-4 rounded-xl border border-red-800 bg-red-950/60 text-red-200 text-sm">
                <span className="font-bold text-red-400 text-base block mb-1">
                  🚨 MALICIOUS QUISHING ATTACK DETECTED
                </span>
                This QR code encodes an unauthorized destination designed to execute a phishing attack or credential theft against mobile users.
              </div>
            )}

            {/* Nested URL Analysis if payload is URL */}
            {qrResult.url_analysis && (
              <div className="my-6 p-5 rounded-xl border border-slate-800 bg-slate-900/80">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-3">
                  Deep URL Threat Inspection
                </h3>
                <div className="grid grid-cols-2 gap-3 text-xs mb-3">
                  <div>
                    <span className="text-slate-500">Domain:</span>{" "}
                    <span className="font-mono text-slate-200">{qrResult.url_analysis.domain}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">ML Phish Prob:</span>{" "}
                    <span className="font-mono text-red-400 font-bold">
                      {Math.round((qrResult.url_analysis.ml_analysis?.phishing_probability ?? 0) * 100)}%
                    </span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  {qrResult.url_analysis.findings.map((f, i) => (
                    <div key={i} className="text-xs text-slate-300 flex items-start gap-2">
                      <span className="text-red-400 shrink-0">⚠️</span>
                      <span>{f}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Findings */}
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                Scanner Findings
              </h3>
              <div className="space-y-1.5 text-xs text-slate-300">
                {qrResult.findings.map((finding, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80">
                    • {finding}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Feature Highlights Footer */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-8 text-center">
          <div className="border border-slate-800/80 rounded-xl p-5 bg-slate-950/60">
            <span className="text-3xl">🔗</span>
            <h4 className="font-semibold text-sm text-slate-200 mt-2">Multi-Vector URL Analysis</h4>
            <p className="text-xs text-slate-400 mt-1">
              Combines 18+ lexical & entropy features with Random Forest ML and Levenshtein typosquatting.
            </p>
          </div>

          <div className="border border-slate-800/80 rounded-xl p-5 bg-slate-950/60">
            <span className="text-3xl">📧</span>
            <h4 className="font-semibold text-sm text-slate-200 mt-2">Email Header & Spoofing</h4>
            <p className="text-xs text-slate-400 mt-1">
              Detects display name deception, Return-Path/Reply-To divergence, SPF/DKIM flags, and NLP urgency lures.
            </p>
          </div>

          <div className="border border-slate-800/80 rounded-xl p-5 bg-slate-950/60">
            <span className="text-3xl">📱</span>
            <h4 className="font-semibold text-sm text-slate-200 mt-2">QR Quishing Defense</h4>
            <p className="text-xs text-slate-400 mt-1">
              Decodes QR codes with image enhancements and unpacks deceptive embedded URLs through the ML pipeline.
            </p>
          </div>
        </div>
      </div>
    </main>
  );
}