import { NextRequest, NextResponse } from "next/server";
import { runPythonDetector } from "@/lib/pythonRunner";
import { analyzeUrl as analyzeUrlTS } from "@/lib/detector";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const url = body?.url?.trim();

    if (!url) {
      return NextResponse.json(
        { error: "URL is required." },
        { status: 400 }
      );
    }

    // Attempt high-accuracy Python Engine with ML & Typosquatting
    try {
      const pythonResult = await runPythonDetector({
        vector: "url",
        data: url,
      });
      return NextResponse.json(pythonResult);
    } catch (pyErr) {
      console.warn("Python detector fallback invoked:", pyErr);
      // Fallback to TypeScript engine if Python is unavailable
      const tsResult = analyzeUrlTS(url);
      return NextResponse.json({
        ...tsResult,
        ml_analysis: {
          phishing_probability: tsResult.score >= 60 ? 0.85 : tsResult.score >= 30 ? 0.45 : 0.05,
          ml_score: tsResult.score,
          ml_verdict: tsResult.score >= 60 ? "HIGH RISK (Fallback Heuristics)" : "LOW RISK",
          model_type: "TypeScript Fallback Engine",
          top_signals: tsResult.findings.slice(0, 3),
        },
        engine: "typescript_fallback",
      });
    }
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Failed to analyze URL" },
      { status: 500 }
    );
  }
}
