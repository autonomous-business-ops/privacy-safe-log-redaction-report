import { createHash } from "node:crypto";

const MAX_INPUT_BYTES = 1024 * 1024;
const MAX_FINDINGS = 10000;

function fail(message) { throw new TypeError(message); }
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }

const RULES = [
  {
    category: "PRIVATE_KEY",
    pattern: /-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----[\s\S]*?(?:-----END \1-----|$)/g,
    replacement(match) { return `<redacted-private-key>${"\n".repeat((match.match(/\n/g) ?? []).length)}`; },
  },
  {
    category: "AUTHORIZATION",
    pattern: /(?:"(?:authorization|proxy-authorization)"|'(?:authorization|proxy-authorization)'|\b(?:authorization|proxy-authorization))\s*:\s*[^\r\n]+/gi,
    replacement(match) { return `authorization: <redacted-auth>${"\n".repeat((match.match(/\n/g) ?? []).length)}`; },
  },
  {
    category: "COOKIE",
    pattern: /(?:"(?:cookie|set-cookie)"|'(?:cookie|set-cookie)'|\b(?:cookie|set-cookie))\s*:\s*[^\r\n]+/gi,
    replacement(match) { return `cookie: <redacted-cookie>${"\n".repeat((match.match(/\n/g) ?? []).length)}`; },
  },
  {
    category: "URL_CREDENTIALS",
    pattern: /\b([a-z][a-z0-9+.-]*):\/\/[^\s/:?#]*:[^\s/?#]*@/gi,
    replacement(match, protocol) { return `${protocol.toLowerCase()}://<redacted-credentials>@`; },
  },
  {
    category: "KNOWN_TOKEN",
    pattern: /\b(?:github_pat_[A-Za-z0-9_]{12,}|gh[pousr]_[A-Za-z0-9]{16,}|glpat-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-(?:[A-Za-z0-9_-]{16,})|sk_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{30,}|AKIA[0-9A-Z]{16})\b/g,
    replacement: "<redacted-token>",
  },
  {
    category: "JWT",
    pattern: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/g,
    replacement: "<redacted-jwt>",
  },
  {
    category: "CREDENTIAL_ASSIGNMENT",
    pattern: /(?<![A-Za-z0-9_-])([A-Za-z0-9_-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret))\b(["']?)(\s*[:=]\s*)[^\r\n]*/gi,
    replacement(match, key, keyQuote, separator) { return `${key}${keyQuote}${separator}<redacted-value>`; },
  },
  {
    category: "EMAIL",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    replacement: "<redacted-email>",
  },
  {
    category: "IPV4",
    pattern: /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g,
    replacement: "<redacted-ipv4>",
  },
  {
    category: "USER_PATH",
    pattern: /\b([A-Za-z]:\\Users\\)[^\\\r\n]+|(\/(?:home|Users)\/)[^/\s]+/gi,
    replacement(match, windowsPrefix, unixPrefix) { return `${windowsPrefix || unixPrefix}<redacted-user>`; },
  },
];

function lineStarts(text) {
  const starts = [0];
  for (let index = 0; index < text.length; index += 1) if (text.charCodeAt(index) === 10) starts.push(index + 1);
  return starts;
}

function lineNumberAt(starts, offset) {
  let low = 0;
  let high = starts.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (starts[middle] <= offset) low = middle + 1;
    else high = middle;
  }
  return low;
}

export function decodeUtf8Log(bytes) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) fail("input must be bytes.");
  if (bytes.byteLength > MAX_INPUT_BYTES) fail(`input exceeds ${MAX_INPUT_BYTES} bytes.`);
  try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { fail("input must be valid UTF-8."); }
}

export function createRedactionReport(input, { maxInputBytes = MAX_INPUT_BYTES } = {}) {
  if (typeof input !== "string") fail("input must be a string.");
  if (!Number.isInteger(maxInputBytes) || maxInputBytes < 1 || maxInputBytes > MAX_INPUT_BYTES) fail(`maxInputBytes must be an integer from 1 through ${MAX_INPUT_BYTES}.`);
  const normalized = input.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
  if (Buffer.byteLength(normalized, "utf8") > maxInputBytes) fail(`input exceeds ${maxInputBytes} bytes.`);
  if (normalized.includes("\0")) fail("input contains a NUL byte.");

  let redacted = normalized;
  const findings = [];
  const rawMatches = [];
  for (const rule of RULES) {
    const source = redacted;
    const starts = lineStarts(source);
    rule.pattern.lastIndex = 0;
    redacted = source.replace(rule.pattern, (...args) => {
      const match = args[0];
      const offset = args.at(-2);
      if (findings.length >= MAX_FINDINGS) fail(`input exceeds ${MAX_FINDINGS} redaction findings.`);
      rawMatches.push(match);
      findings.push({ category: rule.category, line: lineNumberAt(starts, offset) });
      return typeof rule.replacement === "function" ? rule.replacement(...args) : rule.replacement;
    });
  }

  for (const raw of rawMatches) {
    if (raw.length >= 4 && redacted.includes(raw)) fail("redaction verification failed closed.");
  }
  findings.sort((left, right) => left.line - right.line || left.category.localeCompare(right.category));
  const countMap = new Map();
  for (const { category } of findings) countMap.set(category, (countMap.get(category) ?? 0) + 1);
  const categoryCounts = Object.fromEntries([...countMap].sort(([left], [right]) => left.localeCompare(right)));
  const receiptMaterial = JSON.stringify({ redacted_text: redacted, findings, category_counts: categoryCounts });
  return {
    version: 1,
    report_id: `pslr_${sha256(receiptMaterial).slice(0, 32)}`,
    coverage_claim: "KNOWN_PATTERN_REDACTION_ONLY",
    share_decision: "REVIEW_REQUIRED",
    input_lines: normalized === "" ? 0 : normalized.split("\n").length,
    finding_count: findings.length,
    category_counts: categoryCounts,
    findings,
    redacted_text: redacted,
    accounting_effect: "NONE",
  };
}
