import { NextRequest, NextResponse } from "next/server";
import { runPythonDetector } from "@/lib/pythonRunner";
import { analyzeQrCodeTS } from "@/lib/qrDetector";

export async function POST(req: NextRequest) {
  try {
    const contentType = req.headers.get("content-type") || "";
    let base64Image = "";

    if (contentType.includes("multipart/form-data")) {
      const formData = await req.formData();
      const file = formData.get("file");

      if (!file || typeof file === "string") {
        return NextResponse.json(
          { error: "No image file provided in form data." },
          { status: 400 }
        );
      }

      const blob = file as Blob;
      const arrayBuffer = await blob.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);
      base64Image = buffer.toString("base64");
    } else {
      const body = await req.json();
      base64Image = body?.image || body?.base64 || "";
    }

    if (!base64Image) {
      return NextResponse.json(
        { error: "Please upload a QR code image or provide base64 data." },
        { status: 400 }
      );
    }

    // Attempt Python detector first if runtime environment supports it
    try {
      const result = await runPythonDetector<{ success?: boolean; error?: string }>({
        vector: "qr",
        data: base64Image,
      });

      if (result && result.success === false) {
        return NextResponse.json(
          { error: result.error || "No QR code could be decoded from this image.", ...result },
          { status: 400 }
        );
      }

      return NextResponse.json(result);
    } catch (pyErr) {
      // Seamless fallback to pure TypeScript/Node.js Jimp + jsQR engine
      console.warn("Python runner unavailable, executing TypeScript QR engine:", pyErr);
      const tsResult = await analyzeQrCodeTS(base64Image);
      if (!tsResult.success) {
        return NextResponse.json(
          { error: tsResult.error || "No QR code could be decoded from this image.", ...tsResult },
          { status: 400 }
        );
      }
      return NextResponse.json(tsResult);
    }
  } catch (error) {
    console.error("QR detection error:", error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Failed to analyze QR code." },
      { status: 500 }
    );
  }
}
