# DataShield

Local-first document inspection and sensitive-entity detection CLI built with Node.js and TypeScript.

> **Security notice:** This project is an early development tool, not approved for processing real sensitive, classified or law-enforcement documents. Detection is a candidate-finding aid, not proof of identity or data validity. Sanitization, human-review persistence, independent validation and safe export are not implemented. Do not treat detection as anonymization.

## Current implementation

- Local extraction for PDF, DOCX and CSV.
- `inspect` reports format, size, section count and extracted character count.
- `detect` identifies candidate CPF, email, phone, RG, address, GPS, vehicle plate/chassis, CNJ process number, person names, alias, organization and operational code.
- Findings include section-local character offsets, confidence, severity, suggested manual review and validation metadata where implemented.
- CPF pattern detection is separate from checksum validation.
- Finding values are hidden in CLI output unless `--show-values` is explicitly supplied.
- Input size is limited to 25 MiB by default.
- Unit tests cover extraction and a synthetic detection fixture.

## Requirements

- Node.js 22 or newer
- npm 10 or newer

## Development

```bash
npm install
npm run dev -- inspect ./sample.docx
npm run dev -- detect ./sample.docx
npm run dev -- detect ./sample.docx --show-values
npm run typecheck
npm test
npm run build
```

## Architecture

- apps/cli: command-line interface.
- packages/core: domain contracts.
- packages/extractors: PDF, DOCX and CSV extraction adapters.
- packages/detectors: deterministic patterns and contextual candidate detection.
- packages/sanitizers: planned; not implemented.
- packages/exporters: planned; not implemented.
- packages/infrastructure: planned; not implemented.

## Detection limitations

- Contextual name/address detection is heuristic and can produce false positives and false negatives.
- RG and operational-code patterns are configurable starting points, not universal Brazilian standards.
- CNJ recognition currently checks visible format only, not its official check digit.
- GPS detection recognizes a DMS-style coordinate pattern; it does not validate a real-world location.
- OCR, embedded images, comments, metadata, headers/footers and all document structures are not guaranteed to be extracted.
- CSV rows are serialized during extraction; offsets refer to serialized section text, not original cell coordinates.

## Security principles

1. Local processing by default; no external AI or OCR APIs.
2. Never write source text or finding values to logs by default.
3. Treat all findings as untrusted candidates requiring review.
4. Do not export sanitized documents while critical findings remain unresolved.
5. Sanitized files must be rebuilt, not merely visually covered.
6. Pseudonymization is not anonymization.
7. Use synthetic fixtures for development and tests.
8. Extraction success does not establish that all document content was captured. Scanned PDFs need OCR, which is not implemented.

## Status

Inspection and first-pass deterministic detection are implemented for development. Run dependency installation, type-checking, tests and build locally before relying on the result. Sanitization remains deliberately disabled.
