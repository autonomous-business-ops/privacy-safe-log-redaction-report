import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { createRedactionReport, decodeUtf8Log } from "../src/redact.mjs";

const syntheticPrivateKeyHeader = ["-----BEGIN", "PRIVATE KEY-----"].join(" ");
const syntheticOpenSshKeyHeader = ["-----BEGIN", "OPENSSH PRIVATE KEY-----"].join(" ");

const secrets = {
  bearer: "bearer-value-1234567890",
  password: ["winter-is-not", "-a-real-password"].join(""),
  token: "github_pat_abcdefghijklmnopqrstuvwxyz123456",
  jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue",
  email: "private.person@example.com",
  ip: "192.168.44.20",
  username: "PrivateUser",
  urlUser: "url-user",
  urlPassword: "url-password",
};

const fixture = [
  "service booted safely",
  `Authorization: Bearer ${secrets.bearer}`,
  `password=${secrets.password}`,
  `token=${secrets.token}`,
  `session=${secrets.jwt}`,
  `contact=${secrets.email}`,
  `peer=${secrets.ip}`,
  `path=C:\\Users\\${secrets.username}\\AppData\\Local`,
  `remote=${"https"}://${secrets.urlUser}:${secrets.urlPassword}@example.com/api`,
  syntheticPrivateKeyHeader,
  "synthetic-private-key-material",
  "-----END PRIVATE KEY-----",
].join("\n");

test("report removes every synthetic sensitive value without retaining the original input", () => {
  const report = createRedactionReport(fixture);
  const serialized = JSON.stringify(report);
  for (const value of [...Object.values(secrets), "synthetic-private-key-material"]) assert.equal(serialized.includes(value), false, value);
  assert.equal(serialized.includes(fixture), false);
  assert.equal(report.coverage_claim, "KNOWN_PATTERN_REDACTION_ONLY");
  assert.equal(report.share_decision, "REVIEW_REQUIRED");
  assert.equal(report.accounting_effect, "NONE");
  assert.ok(report.finding_count >= 8);
  assert.match(report.redacted_text, /service booted safely/);
  assert.match(report.redacted_text, /<redacted-private-key>/);
});

test("reports are deterministic across CRLF and LF without raw-value hashes", () => {
  const left = createRedactionReport(fixture);
  const right = createRedactionReport(fixture.replaceAll("\n", "\r\n"));
  assert.deepEqual(left, right);
  assert.match(left.report_id, /^pslr_[0-9a-f]{32}$/);
  assert.equal(Object.hasOwn(left, "input_sha256"), false);
  assert.deepEqual([...left.findings].sort((a, b) => a.line - b.line || a.category.localeCompare(b.category)), left.findings);
});

test("multiline redactions preserve original line coordinates and path family", () => {
  const input = [
    "before",
    syntheticPrivateKeyHeader,
    "material",
    "-----END PRIVATE KEY-----",
    "contact=person@example.com",
    "mac=/Users/PrivateName/project",
  ].join("\n");
  const report = createRedactionReport(input);
  assert.equal(report.findings.find(({ category }) => category === "EMAIL").line, 5);
  assert.equal(report.findings.find(({ category }) => category === "USER_PATH").line, 6);
  assert.match(report.redacted_text, /\/Users\/<redacted-user>\/project/);
  assert.equal(report.input_lines, 6);
});

test("truncated keys spaced assignments common tokens and spaced Windows users do not leak", () => {
  const values = {
    phrase: "multi word credential value",
    token: "glpat-abcdefghijklmnopqrstuvwxyz",
    user: "Private Person",
    key: "truncated-key-material",
  };
  const report = createRedactionReport([
    `password=${values.phrase}`,
    `service_token ${values.token}`,
    `path=C:\\Users\\${values.user}\\Documents`,
    syntheticOpenSshKeyHeader,
    values.key,
  ].join("\n"));
  const serialized = JSON.stringify(report);
  for (const value of Object.values(values)) assert.equal(serialized.includes(value), false, value);
  assert.equal(report.category_counts.PRIVATE_KEY, 1);
  assert.equal(report.category_counts.KNOWN_TOKEN, 1);
});

test("escaped and JSON credentials plus authorization URL and path variants are fully redacted", () => {
  const values = ["SUPER_SECRET_TAIL", "SUPER_SECRET_JSON", "digest-response-secret", "ipv6-password", "http-password", "PrivateLowerUser"];
  const report = createRedactionReport([
    'password="abc\\"SUPER_SECRET_TAIL"',
    '{"password":"SUPER_SECRET_JSON"}',
    'Authorization: Digest username="user", response="digest-response-secret"',
    `remote=${"https"}://user:ipv6-password@[2001:db8::1]/api`,
    `legacy=${"http"}://user:http-password@example.com/api`,
    'path=c:\\users\\PrivateLowerUser\\Documents',
  ].join("\n"));
  const serialized = JSON.stringify(report);
  for (const value of values) assert.equal(serialized.includes(value), false, value);
  for (const category of ["CREDENTIAL_ASSIGNMENT", "AUTHORIZATION", "URL_CREDENTIALS", "USER_PATH"]) assert.ok(report.category_counts[category] >= 1, category);
});

test("prefixed environment keys quoted headers and non-HTTP credential URLs are redacted", () => {
  const values = [
    "AWS_ACCESS_SECRET_VALUE",
    "DATABASE_PASSWORD_VALUE",
    "GITHUB_TOKEN_VALUE",
    "JSON_AUTH_SECRET",
    "JSON_COOKIE_SECRET",
    "DATABASE_URL_PASSWORD",
  ];
  const report = createRedactionReport([
    `AWS_SECRET_ACCESS_KEY=${values[0]}`,
    `DATABASE_PASSWORD=${values[1]}`,
    `GITHUB_TOKEN=${values[2]}`,
    `{"Authorization":"Bearer ${values[3]}"}`,
    `{"Cookie":"session=${values[4]}"}`,
    `database=postgres://user:${values[5]}@localhost/db`,
  ].join("\n"));
  const serialized = JSON.stringify(report);
  for (const value of values) assert.equal(serialized.includes(value), false, value);
  assert.equal(report.category_counts.CREDENTIAL_ASSIGNMENT, 3);
  assert.equal(report.category_counts.AUTHORIZATION, 1);
  assert.equal(report.category_counts.COOKIE, 1);
  assert.equal(report.category_counts.URL_CREDENTIALS, 1);
});

test("URL credentials consume the full userinfo through its last at-sign", () => {
  const values = ["SUPER_SECRET_TAIL", "USERNAME_FRAGMENT", "URL_PASSWORD"];
  const report = createRedactionReport([
    `remote=${"https"}://user:part1@${values[0]}@localhost/`,
    `remote=${"https"}://u@${values[1]}:${values[2]}@example.com/api`,
  ].join("\n"));
  const serialized = JSON.stringify(report);
  for (const value of values) assert.equal(serialized.includes(value), false, value);
  assert.equal(report.category_counts.URL_CREDENTIALS, 2);
});

test("credential URL nonmatches remain bounded on colon-heavy input", () => {
  const input = `x=https://${"a:".repeat(50000)}host`;
  const started = performance.now();
  const report = createRedactionReport(input);
  assert.ok(performance.now() - started < 1000);
  assert.equal(report.category_counts.URL_CREDENTIALS, undefined);
});

test("multiline quoted headers preserve following finding coordinates", () => {
  const input = '"Authorization":\n  "Bearer MULTILINE_SECRET"\ncontact=a@example.com';
  const report = createRedactionReport(input);
  assert.equal(JSON.stringify(report).includes("MULTILINE_SECRET"), false);
  assert.equal(report.input_lines, 3);
  assert.equal(report.redacted_text.split("\n").length, 3);
  assert.equal(report.findings.find(({ category }) => category === "EMAIL").line, 3);
});

test("caps NUL and malformed UTF-8 fail closed", () => {
  assert.throws(() => createRedactionReport("a\0b"), /NUL/);
  assert.throws(() => createRedactionReport("12345", { maxInputBytes: 4 }), /exceeds/);
  assert.throws(() => decodeUtf8Log(Buffer.from([0xff])), /valid UTF-8/);
  const bom = decodeUtf8Log(Buffer.from([0xef, 0xbb, 0xbf, 0x61]));
  assert.equal(bom.codePointAt(0), 0xfeff);
  assert.throws(() => createRedactionReport(Array.from({ length: 10001 }, () => "a@b.co").join("\n")), /10000 redaction findings/);
});

test("repeated findings contain only category and line metadata", () => {
  const report = createRedactionReport("password=one\npassword=two\ncontact=a@example.com");
  assert.equal(report.category_counts.CREDENTIAL_ASSIGNMENT, 2);
  assert.equal(report.category_counts.EMAIL, 1);
  for (const finding of report.findings) assert.deepEqual(Object.keys(finding).sort(), ["category", "line"]);
  assert.equal(JSON.stringify(report).includes("one"), false);
  assert.equal(JSON.stringify(report).includes("two"), false);
  assert.equal(JSON.stringify(report).includes("a@example.com"), false);
});

test("CLI emits only redacted output and exits 2 for invalid bytes or options", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "redaction-report-"));
  const input = path.join(directory, "support.log");
  await writeFile(input, fixture);
  const cli = path.resolve("src/cli.mjs");
  const result = spawnSync(process.execPath, [cli, "--input", input, "--json"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.share_decision, "REVIEW_REQUIRED");
  for (const value of Object.values(secrets)) assert.equal(result.stdout.includes(value), false, value);
  await writeFile(input, Buffer.from([0xff]));
  assert.equal(spawnSync(process.execPath, [cli, "--input", input], { encoding: "utf8" }).status, 2);
  assert.equal(spawnSync(process.execPath, [cli, "--input", input, "--input", input], { encoding: "utf8" }).status, 2);
  const missingSecretPath = path.join(directory, "password=do-not-echo.log");
  const missing = spawnSync(process.execPath, [cli, "--input", missingSecretPath], { encoding: "utf8" });
  assert.equal(missing.status, 2);
  assert.equal(missing.stderr.includes("do-not-echo"), false);
  await writeFile(input, Buffer.alloc(1024 * 1024 + 1, 0x61));
  const oversized = spawnSync(process.execPath, [cli, "--input", input], { encoding: "utf8" });
  assert.equal(oversized.status, 2);
  assert.match(oversized.stderr, /1048576/);
});
