# DataShield

Local-first document sanitization CLI built with Node.js and TypeScript.

DataShield is designed to inspect PDF, DOCX and CSV documents, detect sensitive information, apply configurable sanitization policies, support human review, validate outputs and export sanitized artifacts.

> **Security notice:** This repository is an initial development scaffold. It is not approved for processing real sensitive, classified or law-enforcement documents. Detection is incomplete until the relevant modules, tests and security review are implemented.

## Goals

- Run locally without sending document content to external services.
- Keep domain and application logic independent from the CLI.
- Support PDF, DOCX and CSV input.
- Support PDF, DOCX, CSV, TXT and JSON output.
- Require review and validation before release.
- Avoid storing source text or sensitive values in logs and audit records.

## Planned architecture

- `apps/cli`: command-line interface.
- `packages/core`: domain contracts and application use cases.
- `packages/extractors`: PDF, DOCX and CSV extraction adapters.
- `packages/detectors`: pattern and contextual entity detection.
- `packages/sanitizers`: redaction, pseudonymization and generalization.
- `packages/exporters`: sanitized output generation.
- `packages/infrastructure`: storage, persistence and cryptographic adapters.

## Requirements

- Node.js 22 or newer
- npm 10 or newer

## Development

```bash
npm install
npm run dev -- --help
npm run typecheck
npm test
```

## Security principles

1. Local processing by default; no external AI or OCR APIs.
2. Source documents must never be written to logs.
3. Export must fail closed when critical findings are unresolved.
4. Sanitized files must be rebuilt, not merely visually covered.
5. Pseudonymization is not anonymization.
6. Use synthetic fixtures for development and tests.

## Current status

Initial repository scaffold. Document extraction, entity detection, sanitization, review, validation and export workflows are not yet implemented.
