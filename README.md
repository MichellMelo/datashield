# DataShield

Local-first document inspection and sanitization CLI built with Node.js and TypeScript.

> **Security notice:** This project is an early development tool, not approved for processing real sensitive, classified or law-enforcement documents. Extraction is implemented for initial testing; detection, sanitization, human review, validation and safe export are not implemented. Do not treat inspection as anonymization.

## Current implementation

- Local extraction for PDF, DOCX and CSV.
- The inspect command reports format, size, section count and extracted character count.
- Extracted content is not printed by default. Use the show-content option only in a trusted terminal.
- Input size is limited to 25 MiB by default; override with max-bytes.
- Basic extension/signature checks and rejection of binary-looking CSV input.
- Unit tests for CSV extraction and basic input validation.

## Requirements

- Node.js 22 or newer
- npm 10 or newer

## Development

```bash
npm install
npm run dev -- inspect ./sample.csv
npm run typecheck
npm test
npm run build
```

## Planned architecture

- apps/cli: command-line interface.
- packages/core: domain contracts and application use cases.
- packages/extractors: PDF, DOCX and CSV extraction adapters.
- packages/detectors: pattern and contextual entity detection.
- packages/sanitizers: redaction, pseudonymization and generalization.
- packages/exporters: sanitized output generation.
- packages/infrastructure: storage, persistence and cryptographic adapters.

## Security principles

1. Local processing by default; no external AI or OCR APIs.
2. Source documents must never be written to logs.
3. Export must fail closed when critical findings are unresolved.
4. Sanitized files must be rebuilt, not merely visually covered.
5. Pseudonymization is not anonymization.
6. Use synthetic fixtures for development and tests.
7. Extraction success does not establish that all document content was captured. Scanned PDFs need OCR, which is not implemented.

## Roadmap

1. Improve extraction fidelity and fixtures for all supported formats.
2. Add local sensitive-entity detection with confidence and provenance.
3. Add review workflow and explicit policy decisions.
4. Add sanitization and independent validation.
5. Add safe export only after validation gates exist.

## Status

The CLI inspection milestone is implemented for initial development and requires local dependency installation, type-checking, build and tests. Sanitization remains deliberately disabled.
