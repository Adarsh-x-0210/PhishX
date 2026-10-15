/**
 * Displays PhishX deployment and environment information during startup.
 */

const reset = "\x1b[0m";
const bold = "\x1b[1m";
const cyan = "\x1b[36m";
const red = "\x1b[31m";
const green = "\x1b[32m";
const yellow = "\x1b[33m";
const gray = "\x1b[90m";

console.log(`
${red}${bold}  🛡️   PHISHX : MULTI-VECTOR PHISHING DETECTION SYSTEM${reset}
${gray}  ────────────────────────────────────────────────────────────${reset}
  ${green}●${reset} ${bold}Local Development:${reset}   ${cyan}http://localhost:3000${reset}
  ${green}●${reset} ${bold}Live Production Vercel:${reset} ${yellow}https://phishx-psi.vercel.app/${reset}
  ${green}●${reset} ${bold}Detection Vectors:${reset}     URL Scanner, Email Spoofing, QR Quishing
  ${green}●${reset} ${bold}AI Engine:${reset}             Random Forest ML + TF-IDF Naive Bayes
${gray}  ────────────────────────────────────────────────────────────${reset}
`);
