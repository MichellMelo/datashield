# DataShield

Local-first document inspection and sensitive-entity detection CLI built with Node.js and TypeScript.

> **Security notice:** This is an educational/development tool, not approved for processing real sensitive, classified or law-enforcement documents. Detection is a candidate-finding aid, not proof of identity or data validity. Sanitization and safe export are deliberately disabled.

## Current implementation

- Local extraction for PDF, DOCX and CSV.
- `inspect` reports format, size, section count and extracted character count.
- `detect` finds candidates such as CPF, email, phone, RG, address, GPS, vehicle plate/chassis, CNJ process number, person names, alias, organization and operational code.
- Findings include section-local character offsets, confidence, severity and suggested manual review.
- CPF pattern recognition is separate from checksum validation.
- `evaluate` measures precision, recall and F1 against a human-authored ground-truth JSON file, including false-positive and false-negative counts.
- `review` supports interactive local confirmation/rejection/skip and writes a sidecar JSON with decisions and offsets, without candidate values or source text.
- Detection values stay hidden in ordinary CLI output unless explicitly requested.
- Input size is limited to 25 MiB by default.

## Requirements

- Node.js 22 or newer
- npm 10 or newer

## Quick start

```bash
npm install
npm run dev -- inspect ./datashield_documento_ficticio_teste.docx
npm run dev -- detect ./datashield_documento_ficticio_teste.docx
npm run typecheck
npm test
npm run build
```

## Classroom practical — synthetic document

The repository contains the annotation/gold-standard file:
`fixtures/synthetic/occurrence-ground-truth.json`

Run the evaluation from the repository root against the matching synthetic DOCX:

```bash
npm run dev -- evaluate ./datashield_documento_ficticio_teste.docx --labels ./fixtures/synthetic/occurrence-ground-truth.json
```

To see the values associated with false positives and false negatives (synthetic data only):

```bash
npm run dev -- evaluate ./datashield_documento_ficticio_teste.docx --labels ./fixtures/synthetic/occurrence-ground-truth.json --show-values
```

Run the interactive human-review exercise in a real terminal:

```bash
npm run dev -- review ./datashield_documento_ficticio_teste.docx --output ./datashield-review.json
```

During review enter:
- `c`: confirm the candidate.
- `r`: reject the candidate as a false positive.
- `s`: skip and leave pending.
- `q`: save current decisions and quit.

The review sidecar records candidate IDs, type, severity, confidence, offsets, decisions, timestamp and source SHA-256. It intentionally does **not** store the detected values or source text. Candidate values are displayed in the terminal during review, so use only synthetic data or a trusted local environment. The output file is created with exclusive-write protection and will not overwrite an existing file.

## Understanding evaluation metrics

- **TP (true positive):** a detected occurrence that matches the ground truth.
- **FP (false positive):** a detected occurrence not present in the ground truth.
- **FN (false negative):** an expected occurrence the detector missed.
- **Precision:** TP / (TP + FP). Of the candidates found, how many were correct?
- **Recall:** TP / (TP + FN). Of the expected sensitive occurrences, how many were found?
- **F1:** harmonic mean of precision and recall.

Matching requires the same entity type and normalized value. The evaluator normalizes case, accents and punctuation, but counts repeated occurrences separately. Metrics are only meaningful when the ground-truth file is complete and accurately annotated for the exact document being evaluated. A high score on one synthetic file does not establish performance on other document types or real-world reports.

## Architecture

- apps/cli: command-line interface.
- packages/core: domain contracts.
- packages/extractors: PDF, DOCX and CSV extraction adapters.
- packages/detectors: deterministic pattern/context detection and evaluation metrics.
- packages/sanitizers: planned; not implemented.
- packages/exporters: planned; not implemented.
- packages/infrastructure: planned; not implemented.

## Detection limitations

- Contextual name/address detection is heuristic and can produce false positives and false negatives.
- Free-text names without reliable context may be missed.
- RG and operational-code patterns are configurable starting points, not universal Brazilian standards.
- CNJ recognition currently checks visible format only, not the official check digit.
- CPF checksum validation does not confirm that a CPF is assigned or active.
- GPS detection recognizes a DMS-style pattern; it does not validate an actual location.
- OCR, embedded images, comments, metadata, headers/footers and all document structures are not guaranteed to be extracted.
- CSV rows are serialized during extraction; offsets refer to serialized section text, not original cell coordinates.

## Security principles

1. Local processing by default; no external AI or OCR APIs.
2. Never write source text or finding values to logs by default.
3. Treat findings as untrusted candidates requiring human review.
4. Do not export sanitized documents while critical findings remain unresolved.
5. Sanitized files must be rebuilt, not merely visually covered.
6. Pseudonymization is not anonymization.
7. Use synthetic fixtures for development and lessons.
8. Extraction success does not establish that all document content was captured. Scanned PDFs need OCR, which is not implemented.

## Status

Inspection, first-pass detection, ground-truth evaluation and interactive review are implemented for development/education. Sanitization remains deliberately disabled. Run dependency installation, type-checking, tests and build locally before relying on the result.
