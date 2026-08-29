"use client";

import { useState } from "react";

type AnalysisResult = {
  url: string;
  domain: string;
  verdict: string;
  score: number;
  findings: string[];
};

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const analyzeUrl = async () => {
    if (!url.trim()) {
      setError("Please enter a URL.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch("/api/url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Analysis failed.");
      }

      setResult(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Something went wrong."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-black text-white px-6 py-12">
      <div className="max-w-3xl mx-auto">

        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-5xl font-bold tracking-tight">
            PHISH<span className="text-red-500">X</span>
          </h1>

          <p className="text-gray-400 mt-4 text-lg">
            Multi-Vector Phishing Detection System
          </p>
        </div>

        {/* Scanner */}
        <div className="border border-gray-800 rounded-2xl p-6 bg-gray-950">

          {/* Tabs */}
          <div className="grid grid-cols-3 gap-2 mb-6">
            <button className="bg-red-600 rounded-lg py-3 font-medium">
              🔗 URL
            </button>

            <button
              disabled
              className="bg-gray-900 rounded-lg py-3 text-gray-500 cursor-not-allowed"
            >
              📧 Email
            </button>

            <button
              disabled
              className="bg-gray-900 rounded-lg py-3 text-gray-500 cursor-not-allowed"
            >
              📱 QR Code
            </button>
          </div>

          {/* Input */}
          <label className="block text-sm text-gray-400 mb-2">
            Enter a suspicious URL
          </label>

          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                analyzeUrl();
              }
            }}
            placeholder="https://example.com"
            className="w-full bg-black border border-gray-800 rounded-lg px-4 py-4 outline-none focus:border-red-500"
          />

          {/* Analyze button */}
          <button
            onClick={analyzeUrl}
            disabled={loading}
            className="w-full mt-4 bg-red-600 hover:bg-red-700 disabled:bg-gray-700 transition rounded-lg py-4 font-semibold"
          >
            {loading ? "ANALYZING..." : "ANALYZE URL"}
          </button>

          {/* Error */}
          {error && (
            <div className="mt-4 p-4 rounded-lg border border-red-800 bg-red-950 text-red-300">
              {error}
            </div>
          )}
        </div>

        {/* Result */}
        {result && (
          <div className="mt-8 border border-gray-800 rounded-2xl p-6 bg-gray-950">

            <h2 className="text-2xl font-bold mb-6">
              Analysis Result
            </h2>

            {/* Verdict */}
            <div className="text-center border border-gray-800 rounded-xl p-6 mb-6">
              <p className="text-gray-400 text-sm">
                RISK LEVEL
              </p>

              <p
                className={`text-3xl font-bold mt-2 ${
                  result.score >= 60
                    ? "text-red-500"
                    : result.score >= 30
                    ? "text-yellow-500"
                    : "text-green-500"
                }`}
              >
                {result.verdict}
              </p>

              <p className="text-gray-400 mt-2">
                Risk Score:{" "}
                <span className="text-white font-semibold">
                  {result.score}/100
                </span>
              </p>
            </div>

            {/* URL information */}
            <div className="mb-6">
              <h3 className="font-semibold mb-3">
                URL Information
              </h3>

              <div className="bg-black rounded-lg p-4 text-sm break-all">
                <p>
                  <span className="text-gray-500">URL:</span>{" "}
                  {result.url}
                </p>

                <p className="mt-2">
                  <span className="text-gray-500">Domain:</span>{" "}
                  {result.domain}
                </p>
              </div>
            </div>

            {/* Findings */}
            <div>
              <h3 className="font-semibold mb-3">
                Findings
              </h3>

              <div className="space-y-2">
                {result.findings.map((finding, index) => (
                  <div
                    key={index}
                    className="border border-gray-800 rounded-lg p-3 text-gray-300"
                  >
                    ⚠️ {finding}
                  </div>
                ))}
              </div>
            </div>

          </div>
        )}

        {/* Features */}
        <div className="grid grid-cols-3 gap-4 mt-6 text-center">

          <div className="border border-gray-800 rounded-xl p-4">
            <p className="text-2xl">🔗</p>
            <p className="text-sm text-gray-400 mt-2">
              URL Analysis
            </p>
          </div>

          <div className="border border-gray-800 rounded-xl p-4">
            <p className="text-2xl">📧</p>
            <p className="text-sm text-gray-400 mt-2">
              Email Analysis
            </p>
          </div>

          <div className="border border-gray-800 rounded-xl p-4">
            <p className="text-2xl">📱</p>
            <p className="text-sm text-gray-400 mt-2">
              QR Analysis
            </p>
          </div>

        </div>

      </div>
    </main>
  );
}