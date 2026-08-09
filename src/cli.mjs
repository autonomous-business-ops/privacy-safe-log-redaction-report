#!/usr/bin/env node
import { open } from "node:fs/promises";
import path from "node:path";

import { createRedactionReport, decodeUtf8Log } from "./redact.mjs";

const MAX_INPUT_BYTES = 1024 * 1024;

function options(argv) {
  const parsed = { json: false };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--json") { parsed.json = true; continue; }
    if (token !== "--input" || !argv[index + 1]) throw new TypeError("Unknown or incomplete option.");
    if (parsed.input) throw new Error("--input may be provided only once.");
    parsed.input = argv[++index];
  }
  if (!parsed.input) throw new Error("Usage: --input support.log [--json]");
  return parsed;
}

async function main() {
  const parsed = options(process.argv.slice(2));
  const handle = await open(path.resolve(parsed.input), "r");
  let bytes;
  try {
    const chunks = [];
    let total = 0;
    while (true) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, MAX_INPUT_BYTES + 1 - total));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > MAX_INPUT_BYTES) throw new TypeError(`input exceeds ${MAX_INPUT_BYTES} bytes.`);
      chunks.push(chunk.subarray(0, bytesRead));
    }
    bytes = Buffer.concat(chunks, total);
  } finally { await handle.close(); }
  const report = createRedactionReport(decodeUtf8Log(bytes));
  if (parsed.json) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else process.stdout.write(`${report.redacted_text}${report.redacted_text.endsWith("\n") || !report.redacted_text ? "" : "\n"}\n${report.report_id} findings=${report.finding_count} review=required\n`);
}

main().catch((error) => {
  const message = error instanceof TypeError ? error.message : "Input could not be read or processed.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 2;
});
