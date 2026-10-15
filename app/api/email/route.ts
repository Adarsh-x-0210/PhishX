import { NextRequest, NextResponse } from "next/server";
import { runPythonDetector } from "@/lib/pythonRunner";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();

    const fromHeader = body?.from || body?.from_header || "";
    const replyTo = body?.reply_to || "";
    const returnPath = body?.return_path || "";
    const subject = body?.subject || "";
    const emailBody = body?.body || "";
    const rawEmail = body?.raw_email || "";

    if (!fromHeader && !subject && !emailBody && !rawEmail) {
      return NextResponse.json(
        { error: "Please provide email headers, content, or raw email text." },
        { status: 400 }
      );
    }

    const payload = {
      from: fromHeader,
      reply_to: replyTo,
      return_path: returnPath,
      subject,
      body: emailBody,
      raw_email: rawEmail || undefined,
    };

    const result = await runPythonDetector({
      vector: "email",
      data: payload,
    });

    return NextResponse.json(result);
  } catch (error) {
    console.error("Email detection error:", error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Failed to analyze email." },
      { status: 500 }
    );
  }
}
