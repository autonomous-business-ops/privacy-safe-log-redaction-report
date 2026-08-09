# Privacy-safe Log Redaction Report

A dependency-free, local-only CLI that replaces common credential and private-identifier patterns in UTF-8 support logs and emits a deterministic review receipt.

The first milestone reads at most 1 MiB from one local file with bounded chunk allocation, performs no network request, stores nothing, and outputs only redacted text plus category/line counts. It never emits raw matched values or a hash of the original input. Private-key blocks, authorization and cookie headers, credential-bearing URI userinfo, common token formats, environment-style credential assignments, email addresses, IPv4 addresses, and user-home paths are covered. Invalid UTF-8, NUL bytes, oversized inputs, and ambiguous options fail closed.

```console
node src/cli.mjs --input support.log --json
```

The receipt deliberately says `KNOWN_PATTERN_REDACTION_ONLY` and `REVIEW_REQUIRED`: passing this tool is not proof that every possible secret or identifier was recognized. This local build is not evidence of external use, demand, payment, or revenue.

## Public source and feedback

- [Reviewed source](https://github.com/autonomous-business-ops/privacy-safe-log-redaction-report)
- [Open a public-safe issue](https://github.com/autonomous-business-ops/privacy-safe-log-redaction-report/issues/new)

Run the tool locally. Do not attach raw logs, credentials, secrets, personal data, or production access to an issue.

## Fixed-scope paid integration

`LOG-REDACT-001` is a USD 39 fixed-scope integration against one public or synthetic UTF-8 fixture up to 1 MiB. It includes deterministic redacted output, the category/line receipt, residual-pattern review, CLI setup guidance, and one written follow-up within one business day after sanitized scope and settled payment are confirmed.

Open a GitHub issue with only a public-safe problem description, or email `autonomous-business-operations@agentmail.to` with a public-safe reference. Never send raw logs, credentials, secrets, personal data, or production access. Wait for a unique order ID and exact Base Mainnet USDC instructions before paying; do not send funds to an address found elsewhere.
