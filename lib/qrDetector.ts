import { Jimp } from "jimp";
import jsQR from "jsqr";
import { analyzeUrl, AnalysisResult } from "./detector";

export interface QRAnalysisResult {
  success: boolean;
  payload: string;
  payload_type: string;
  verdict: "LOW RISK" | "SUSPICIOUS" | "HIGH RISK" | "INVALID";
  score: number;
  quishing_detected: boolean;
  quishing_signals?: Array<{ type: string; severity: string; detail: string }>;
  url_analysis?: AnalysisResult;
  findings: string[];
  error?: string;
}

export async function analyzeQrCodeTS(imageInput: string | Buffer): Promise<QRAnalysisResult> {
  try {
    let buffer: Buffer;

    if (typeof imageInput === "string") {
      let base64Data = imageInput.trim();
      if (base64Data.includes(",")) {
        base64Data = base64Data.split(",", 2)[1];
      }
      buffer = Buffer.from(base64Data, "base64");
    } else {
      buffer = imageInput;
    }

    if (!buffer || buffer.length === 0) {
      return {
        success: false,
        payload: "",
        payload_type: "NONE",
        verdict: "INVALID",
        score: 0,
        quishing_detected: false,
        findings: ["No image data provided for QR analysis."],
        error: "No image file or data provided.",
      };
    }

    // Read image using Jimp
    const image = await Jimp.read(buffer);
    const { width, height, data } = image.bitmap;
    const clampedData = new Uint8ClampedArray(data);

    // Attempt 1: Standard read
    let code = jsQR(clampedData, width, height);

    // Attempt 2: Grayscale + Contrast boost if first attempt failed
    if (!code) {
      image.greyscale().contrast(0.6);
      code = jsQR(new Uint8ClampedArray(image.bitmap.data), image.bitmap.width, image.bitmap.height);
    }

    if (!code || !code.data) {
      return {
        success: false,
        payload: "",
        payload_type: "NONE",
        verdict: "INVALID",
        score: 0,
        quishing_detected: false,
        findings: ["No readable QR code pattern detected in the provided image."],
        error: "No QR code could be detected in this image. Please ensure the QR code is clearly focused and well-lit.",
      };
    }

    const payload = code.data.trim();
    const findings: string[] = ["QR code successfully decoded."];
    const quishingSignals: Array<{ type: string; severity: string; detail: string }> = [];
    let payloadType = "TEXT";
    let urlAnalysisResult: AnalysisResult | undefined = undefined;
    let score = 0;
    let verdict: "LOW RISK" | "SUSPICIOUS" | "HIGH RISK" | "INVALID" = "LOW RISK";

    // URL classification
    if (payload.startsWith("http://") || payload.startsWith("https://") || /^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\/.*)?$/.test(payload)) {
      payloadType = "URL";
      urlAnalysisResult = analyzeUrl(payload);
      score = urlAnalysisResult.score;
      verdict = urlAnalysisResult.verdict;
      findings.push(...urlAnalysisResult.findings);

      if (score >= 60) {
        quishingSignals.push({
          type: "MALICIOUS_QUISHING_URL",
          severity: "CRITICAL",
          detail: "QR code encodes a high-risk phishing URL designed for mobile credential theft.",
        });
        findings.splice(1, 0, "QUISHING DETECTED: QR code directs mobile users to a malicious phishing landing page.");
      } else if (score >= 30) {
        quishingSignals.push({
          type: "SUSPICIOUS_QR_URL",
          severity: "MEDIUM",
          detail: "QR code leads to a suspicious or untrusted domain.",
        });
      } else {
        findings.push("Encoded URL appears legitimate and safe.");
      }
    } else if (payload.startsWith("mailto:")) {
      payloadType = "EMAIL_LINK";
      score = 25;
      verdict = "SUSPICIOUS";
      findings.push("QR code triggers an email composition action (mailto: scheme).");
    } else if (payload.startsWith("tel:")) {
      payloadType = "PHONE_CALL";
      score = 20;
      verdict = "LOW RISK";
      findings.push("QR code triggers a telephone call action.");
    } else if (payload.startsWith("WIFI:")) {
      payloadType = "WIFI_CONFIG";
      score = 15;
      verdict = "LOW RISK";
      findings.push("QR code encodes Wi-Fi network credentials.");
    } else {
      payloadType = "TEXT";
      verdict = "LOW RISK";
      score = 0;
      findings.push("QR code contains a plain text payload.");
    }

    return {
      success: true,
      payload,
      payload_type: payloadType,
      verdict,
      score,
      quishing_detected: quishingSignals.length > 0,
      quishing_signals: quishingSignals,
      url_analysis: urlAnalysisResult,
      findings,
    };
  } catch (err) {
    return {
      success: false,
      payload: "",
      payload_type: "NONE",
      verdict: "INVALID",
      score: 0,
      quishing_detected: false,
      findings: ["Failed to decode or parse image file."],
      error: err instanceof Error ? err.message : "Error processing image file.",
    };
  }
}
