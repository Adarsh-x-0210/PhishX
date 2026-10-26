import { execFile } from "child_process";
import fs from "fs";
import path from "path";

/**
 * Resolves the path to the Python executable, preferring the local .venv if available.
 */
function getPythonPath(): string | null {
  const cwd = process.cwd();

  // Windows virtualenv
  const winVenv = path.join(cwd, ".venv", "Scripts", "python.exe");
  if (fs.existsSync(winVenv)) return winVenv;

  // Linux/Unix virtualenv
  const unixVenv = path.join(cwd, ".venv", "bin", "python");
  if (fs.existsSync(unixVenv)) return unixVenv;

  // If deployed on Vercel serverless without venv, skip trying non-existent python binary
  if (process.env.VERCEL) {
    return null;
  }

  // Global fallbacks for local dev
  return process.platform === "win32" ? "python" : "python3";
}

export interface PythonRunnerOptions {
  vector: "url" | "email" | "qr";
  data?: unknown;
  filePath?: string;
  timeoutMs?: number;
}

/**
 * Executes the PhishX Python engine via CLI runner and returns structured JSON.
 */
export async function runPythonDetector<T = unknown>(options: PythonRunnerOptions): Promise<T> {
  const { vector, data, filePath, timeoutMs = 15000 } = options;
  const pythonPath = getPythonPath();

  if (!pythonPath) {
    throw new Error("Python runtime not detected in this environment. Falling back to native TypeScript engine.");
  }

  const cwd = process.cwd();
  const args = ["-m", "lib.cli", "--vector", vector];

  if (filePath) {
    args.push("--file", filePath);
  } else if (data !== undefined) {
    const dataStr = typeof data === "string" ? data : JSON.stringify(data);
    args.push("--data", dataStr);
  }

  return new Promise((resolve, reject) => {
    execFile(
      pythonPath,
      args,
      {
        cwd,
        timeout: timeoutMs,
        maxBuffer: 10 * 1024 * 1024, // 10 MB for base64 images
        env: { ...process.env, PYTHONIOENCODING: "utf-8" },
      },
      (error, stdout, stderr) => {
        if (error) {
          // Try parsing stdout anyway in case the script emitted JSON error payload
          if (stdout && stdout.trim()) {
            try {
              return resolve(JSON.parse(stdout.trim()));
            } catch {
              // ignore
            }
          }
          return reject(
            new Error(
              stderr?.trim() || error.message || "Failed to execute Python phishing detector."
            )
          );
        }

        try {
          const parsed = JSON.parse(stdout.trim());
          resolve(parsed);
        } catch (parseErr) {
          reject(new Error("Invalid response format from Python engine."));
        }
      }
    );
  });
}
