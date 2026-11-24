#!/usr/bin/env node
import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, dirname, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { Command } from "commander";
import pc from "picocolors";
import { z } from "zod";
import type { DetectedEntity, SensitiveEntityType } from "../../../packages/core/src/index.js";
import { detectSensitiveEntities } from "../../../packages/detectors/src/index.js";
import { evaluateDetections } from "../../../packages/detectors/src/evaluate.js";
import { sanitizeDocument, type SanitizationMode } from "../../../packages/sanitizers/src/index.js";
import { extractDocument, inspectDocument } from "../../../packages/extractors/src/index.js";

const ENTITY_TYPES = [
  "PERSON", "CPF", "RG", "CNPJ", "PHONE", "EMAIL", "ADDRESS", "GPS",
  "VEHICLE_PLATE", "VEHICLE_CHASSIS", "PROCESS_NUMBER", "ORGANIZATION",
  "ALIAS", "SOURCE", "OPERATIONAL_DATA",
] as const;

const groundTruthSchema = z.object({
  schemaVersion: z.literal(1),
  description: z.string().optional(),
  entities: z.array(z.object({
    type: z.enum(ENTITY_TYPES),
    value: z.string().trim().min(1),
  }).strict()),
}).strict();

const reviewReportSchema = z.object({
  schemaVersion: z.literal(1),
  sourceSha256: z.string().regex(/^[a-f0-9]{64}$/i),
  findings: z.array(z.object({
    findingId: z.string().min(1),
    type: z.enum(ENTITY_TYPES),
    sectionId: z.string().min(1),
    start: z.number().int().nonnegative(),
    end: z.number().int().positive(),
    confidence: z.number().min(0).max(1),
    severity: z.enum(["CRITICAL", "HIGH", "MEDIUM"]),
    status: z.enum(["CONFIRMED", "REJECTED", "PENDING"]),
  }).strict()),
}).passthrough();

const program = new Command();
program.name("datashield").description("Local-first document inspection and sensitive-entity detection CLI").version("0.1.0");

function parseMaxBytes(value: string): number {
  const maxBytes = Number(value);
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error("--max-bytes must be a positive safe integer.");
  return maxBytes;
}

function percentage(value: number | null): string {
  return value === null ? "N/A" : `${(value * 100).toFixed(1)}%`;
}

function printEvaluationTable(result: ReturnType<typeof evaluateDetections>): void {
  const columns = [
    ["CATEGORY", 20], ["TP", 5], ["FP", 5], ["FN", 5],
    ["PRECISION", 11], ["RECALL", 11], ["F1", 8],
  ] as const;
  const header = columns.map(([name, width]) => name.padEnd(width)).join(" ");
  console.log(header);
  console.log("-".repeat(header.length));
  for (const item of result.categories) {
    const values = [
      item.type, String(item.truePositives), String(item.falsePositives), String(item.falseNegatives),
      percentage(item.precision), percentage(item.recall), percentage(item.f1),
    ];
    console.log(values.map((value, index) => value.padEnd(columns[index]![1])).join(" "));
  }
  console.log("-".repeat(header.length));
  const total = result.totals;
  console.log([
    "TOTAL".padEnd(20), String(total.truePositives).padEnd(5),
    String(total.falsePositives).padEnd(5), String(total.falseNegatives).padEnd(5),
    percentage(total.precision).padEnd(11), percentage(total.recall).padEnd(11),
    percentage(total.f1).padEnd(8),
  ].join(" "));
}

function printEvaluationErrors(
  result: ReturnType<typeof evaluateDetections>,
  showValues: boolean,
): void {
  const withErrors = result.categories.filter((item) => item.falsePositives > 0 || item.falseNegatives > 0);
  if (withErrors.length === 0) {
    console.log(pc.green("\nNo false positives or false negatives against this ground truth."));
    return;
  }
  console.log(pc.yellow("\nDifferences against ground truth:"));
  for (const item of withErrors) {
    for (const error of item.unmatchedDetections) {
      const detail = showValues ? ` | value: ${error.value}` : "";
      console.log(`  FP ${error.type} | chars: ${error.start}-${error.end}${detail}`);
    }
    for (const error of item.missedEntities) {
      const detail = showValues ? ` | expected: ${error.value}` : "";
      console.log(`  FN ${error.type}${detail}`);
    }
  }
  if (!showValues) console.log(pc.dim("Values hidden. Use --show-values only with synthetic data in a trusted terminal."));
}

program.command("inspect")
  .description("Inspect a PDF, DOCX or CSV document locally")
  .argument("<file>", "Path to the document")
  .option("--show-content", "Print extracted content to the terminal (may expose sensitive data)")
  .option("--max-bytes <bytes>", "Maximum input file size", "26214400")
  .action(async (file: string, options: { showContent?: boolean; maxBytes: string }) => {
    const result = await inspectDocument(file, { maxFileBytes: parseMaxBytes(options.maxBytes) });
    console.log(pc.bold("DataShield — inspection"));
    console.log(`File: ${result.path}`);
    console.log(`Format: ${result.format}`);
    console.log(`Size: ${result.sizeBytes.toLocaleString("en-US")} bytes`);
    console.log(`Sections: ${result.sectionCount}`);
    console.log(`Extracted characters: ${result.characterCount}`);
    if (options.showContent) {
      console.log(pc.yellow("\nContent display enabled. Treat terminal output as sensitive."));
      for (const section of result.sections) {
        console.log(pc.dim(`\n[${section.id}]`));
        console.log(section.content);
      }
    } else console.log(pc.dim("\nContent was not printed. Use --show-content only in a trusted terminal."));
    console.log(pc.yellow("\nInspection only. No detection, sanitization or anonymization was performed."));
  });

program.command("detect")
  .description("Detect possible sensitive entities locally; no sanitization is performed")
  .argument("<file>", "Path to a PDF, DOCX or CSV document")
  .option("--show-values", "Print detected values (may expose sensitive data)")
  .option("--max-bytes <bytes>", "Maximum input file size", "26214400")
  .action(async (file: string, options: { showValues?: boolean; maxBytes: string }) => {
    const document = await extractDocument(file, { maxFileBytes: parseMaxBytes(options.maxBytes) });
    const result = detectSensitiveEntities(document);
    console.log(pc.bold("DataShield — detection"));
    console.log(`File: ${file}`);
    console.log(`Findings: ${result.findings.length}`);
    console.log("\nSummary:");
    for (const [type, count] of Object.entries(result.summary).sort(([a], [b]) => a.localeCompare(b))) {
      console.log(`  ${type}: ${count}`);
    }
    console.log("\nFindings:");
    for (const finding of result.findings) {
      const value = options.showValues ? ` | value: ${finding.value}` : "";
      console.log(`  [${finding.severity}] ${finding.type} | section: ${finding.sectionId} | chars: ${finding.start}-${finding.end} | confidence: ${finding.confidence}${value}`);
      if (finding.validation?.checksumValid === false) console.log(pc.yellow("    Format recognized; checksum invalid."));
    }
    console.log(pc.yellow("\nDetection only. Findings require human review. No sanitization or anonymization was performed."));
    if (!options.showValues) console.log(pc.dim("Values hidden. Use --show-values only in a trusted terminal."));
  });

program.command("evaluate")
  .description("Measure precision, recall and F1 against a human-authored ground-truth JSON file")
  .argument("<file>", "Synthetic PDF, DOCX or CSV file to evaluate")
  .requiredOption("--labels <json>", "Ground-truth JSON file")
  .option("--show-values", "Print false-positive and false-negative values (synthetic data only)")
  .option("--max-bytes <bytes>", "Maximum input file size", "26214400")
  .action(async (file: string, options: { labels: string; showValues?: boolean; maxBytes: string }) => {
    const rawLabels = await readFile(options.labels, "utf8");
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(rawLabels);
    } catch {
      throw new Error("Ground-truth file is not valid JSON.");
    }
    const parsed = groundTruthSchema.safeParse(parsedJson);
    if (!parsed.success) {
      throw new Error(`Invalid ground-truth schema: ${parsed.error.issues.map((issue) => issue.path.join(".")).join(", ")}`);
    }
    const document = await extractDocument(file, { maxFileBytes: parseMaxBytes(options.maxBytes) });
    const detected = detectSensitiveEntities(document);
    const result = evaluateDetections(detected.findings, parsed.data.entities);
    console.log(pc.bold("DataShield — evaluation"));
    console.log(`File: ${basename(file)}`);
    console.log(`Ground truth: ${basename(options.labels)} (${parsed.data.entities.length} expected occurrences)`);
    console.log(`Detector findings: ${detected.findings.length}`);
    console.log("");
    printEvaluationTable(result);
    console.log(pc.yellow("\nMetrics are valid only relative to the supplied ground truth and this document."));
    printEvaluationErrors(result, Boolean(options.showValues));
    console.log(pc.dim("\nTP = true positive; FP = false positive; FN = false negative."));
  });

program.command("review")
  .description("Review detection candidates interactively and save decisions locally")
  .argument("<file>", "Path to a PDF, DOCX or CSV document")
  .option("--output <file>", "Review decisions JSON path", "./datashield-review.json")
  .option("--max-bytes <bytes>", "Maximum input file size", "26214400")
  .action(async (file: string, options: { output: string; maxBytes: string }) => {
    if (!stdin.isTTY || !stdout.isTTY) {
      throw new Error("Interactive review requires a real terminal (TTY).");
    }
    const document = await extractDocument(file, { maxFileBytes: parseMaxBytes(options.maxBytes) });
    const result = detectSensitiveEntities(document);
    const rl = createInterface({ input: stdin, output: stdout });
    const decisions: Array<{
      findingId: string; type: SensitiveEntityType; sectionId: string;
      start: number; end: number; confidence: number; severity: string;
      status: "CONFIRMED" | "REJECTED" | "PENDING";
    }> = [];
    let quitRequested = false;

    console.log(pc.bold("DataShield — human review"));
    console.log(pc.yellow("Candidate values will be displayed in this terminal. Use only synthetic data or a trusted local environment."));
    console.log(`Candidates: ${result.findings.length}`);
    console.log("For each candidate: [c] confirm, [r] reject, [s] skip, [q] save and quit.\n");

    try {
      for (let index = 0; index < result.findings.length; index += 1) {
        const finding: DetectedEntity = result.findings[index]!;
        console.log(pc.bold(`[${index + 1}/${result.findings.length}] ${finding.type} — ${finding.severity}`));
        console.log(`Value: ${finding.value}`);
        console.log(`Location: ${finding.sectionId} chars ${finding.start}-${finding.end} | confidence: ${finding.confidence}`);
        let status: "CONFIRMED" | "REJECTED" | "PENDING" = "PENDING";
        while (true) {
          const answer = (await rl.question("Decision [c/r/s/q]: ")).trim().toLowerCase();
          if (answer === "c") { status = "CONFIRMED"; break; }
          if (answer === "r") { status = "REJECTED"; break; }
          if (answer === "s") break;
          if (answer === "q") { quitRequested = true; break; }
          console.log("Enter c, r, s or q.");
        }
        decisions.push({
          findingId: finding.id, type: finding.type, sectionId: finding.sectionId,
          start: finding.start, end: finding.end, confidence: finding.confidence,
          severity: finding.severity, status,
        });
        if (quitRequested) break;
      }
    } finally {
      rl.close();
    }

    const outputPath = resolve(options.output);
    const sourceSha256 = createHash("sha256").update(await readFile(file)).digest("hex");
    const report = {
      schemaVersion: 1,
      sourceFile: basename(file),
      sourceSha256,
      documentId: document.id,
      createdAt: new Date().toISOString(),
      note: "This sidecar stores decisions and text offsets only; it intentionally does not store detected values or source text.",
      findings: decisions,
    };
    await writeFile(outputPath, JSON.stringify(report, null, 2) + "\n", { encoding: "utf8", flag: "wx" });
    console.log(pc.green(`\nReview decisions saved: ${outputPath}`));
    console.log("The report contains no source text or candidate values. No sanitization was performed.");
  });

function fingerprint(type: SensitiveEntityType, value: string): string {
  const normalized = value
    .normalize("NFKD")
    .replace(/[\\u0300-\\u036f]/g, "")
    .toLocaleLowerCase("pt-BR")
    .replace(/[^\\p{L}\\p{N}]/gu, "");
  return `${type}:${normalized}`;
}

function countFingerprints(items: Array<{ type: SensitiveEntityType; value: string }>): Map<string, number> {
  const counts = new Map<string, number>();
  for (const item of items) {
    const key = fingerprint(item.type, item.value);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

function sameCounts(left: Map<string, number>, right: Map<string, number>): boolean {
  if (left.size !== right.size) return false;
  for (const [key, count] of left) if (right.get(key) !== count) return false;
  return true;
}

program.command("sanitize")
  .description("Create a reviewed, de-identified TXT copy; this does not certify anonymization")
  .argument("<file>", "Original PDF, DOCX or CSV document")
  .requiredOption("--review <json>", "Human-review sidecar created by the review command")
  .option("--mode <mode>", "Transformation: redact, pseudonymize or generalize", "pseudonymize")
  .option("--output <file>", "New TXT output path", "./output/datashield-deidentified.txt")
  .option("--report <file>", "Transformation report path (JSON)")
  .option("--allow-reviewed-rejections", "Allow explicitly rejected candidates to remain, with a warning")
  .option("--max-bytes <bytes>", "Maximum input file size", "26214400")
  .action(async (file: string, options: {
    review: string;
    mode: string;
    output: string;
    report?: string;
    allowReviewedRejections?: boolean;
    maxBytes: string;
  }) => {
    const modeResult = z.enum(["redact", "pseudonymize", "generalize"]).safeParse(options.mode);
    if (!modeResult.success) throw new Error("--mode must be redact, pseudonymize or generalize.");
    const mode: SanitizationMode = modeResult.data;

    const inputPath = resolve(file);
    const reviewPath = resolve(options.review);
    const outputPath = resolve(options.output);
    const reportPath = resolve(options.report ?? `${outputPath}.report.json`);

    if (outputPath === inputPath || reportPath === inputPath || reportPath === outputPath) {
      throw new Error("Input, TXT output and report must use three different paths.");
    }
    if (outputPath === reviewPath || reportPath === reviewPath) {
      throw new Error("Output paths must not overwrite the review sidecar.");
    }
    if (!outputPath.toLowerCase().endsWith(".txt")) {
      throw new Error("Only .txt export is supported. The source PDF/DOCX/CSV will not be rebuilt.");
    }

    let reviewJson: unknown;
    try {
      reviewJson = JSON.parse(await readFile(reviewPath, "utf8"));
    } catch {
      throw new Error("Could not read a valid review JSON file.");
    }
    const parsedReview = reviewReportSchema.safeParse(reviewJson);
    if (!parsedReview.success) {
      throw new Error("Review sidecar has an invalid schema. Generate it again with the current DataShield version.");
    }

    const sourceBytesBefore = await readFile(inputPath);
    const sourceSha256 = createHash("sha256").update(sourceBytesBefore).digest("hex");
    if (sourceSha256 !== parsedReview.data.sourceSha256) {
      throw new Error("Review sidecar does not match this exact source file (SHA-256 mismatch). Export blocked.");
    }

    const document = await extractDocument(inputPath, { maxFileBytes: parseMaxBytes(options.maxBytes) });
    const sourceSha256After = createHash("sha256").update(await readFile(inputPath)).digest("hex");
    if (sourceSha256After !== sourceSha256) {
      throw new Error("Source file changed during processing. Export blocked.");
    }

    const detected = detectSensitiveEntities(document);
    if (document.sections.every((section) => section.content.trim().length === 0)) {
      throw new Error("No text could be extracted. Export blocked; OCR and image-based content are not supported.");
    }

    const decisions = parsedReview.data.findings;
    const decisionsById = new Map(decisions.map((decision) => [decision.findingId, decision]));
    if (decisionsById.size !== decisions.length) {
      throw new Error("Review sidecar contains duplicate finding IDs. Export blocked.");
    }
    if (decisions.length !== detected.findings.length) {
      throw new Error("Review is incomplete or belongs to a different detection result. Review every candidate again.");
    }

    for (const finding of detected.findings) {
      const decision = decisionsById.get(finding.id);
      if (!decision
        || decision.type !== finding.type
        || decision.sectionId !== finding.sectionId
        || decision.start !== finding.start
        || decision.end !== finding.end) {
        throw new Error("Review sidecar does not cover the current findings exactly. Export blocked.");
      }
      if (decision.status === "PENDING") {
        throw new Error("At least one candidate is still pending human review. Export blocked.");
      }
    }

    const confirmedIds = new Set(
      decisions.filter((decision) => decision.status === "CONFIRMED").map((decision) => decision.findingId),
    );
    const rejectedFindings = detected.findings.filter((finding) => !confirmedIds.has(finding.id));
    if (rejectedFindings.length > 0 && !options.allowReviewedRejections) {
      throw new Error(
        `${rejectedFindings.length} candidate(s) were rejected in review. Re-run with --allow-reviewed-rejections only after checking each rejection carefully.`,
      );
    }

    const confirmedFindings = detected.findings.filter((finding) => confirmedIds.has(finding.id));
    const transformed = sanitizeDocument(document, confirmedFindings, mode);
    const postScan = detectSensitiveEntities({ ...document, sections: transformed.sections });
    const expectedRemainders = countFingerprints(rejectedFindings);
    const actualRemainders = countFingerprints(postScan.findings);
    if (!sameCounts(expectedRemainders, actualRemainders)) {
      throw new Error(
        `Post-transformation validation found ${postScan.findings.length} candidate(s), which do not match the reviewed exclusions. Export blocked.`,
      );
    }

    const content = [
      "[DataShield — cópia transformada para exercício; não certifica anonimização]",
      ...transformed.sections.map((section, index) => `### Seção ${index + 1}\\n${section.content}`),
      "",
    ].join("\\n\\n");
    const report = {
      schemaVersion: 1,
      createdAt: new Date().toISOString(),
      sourceSha256,
      sourceFormat: document.format,
      outputFile: basename(outputPath),
      mode,
      transformedFindings: transformed.transformedCount,
      transformedByType: transformed.summary,
      reviewedRejectedCandidates: rejectedFindings.length,
      postTransformationCandidates: postScan.findings.length,
      validationStatus: rejectedFindings.length === 0 ? "PASS_NO_RESIDUAL_CANDIDATES" : "PASS_WITH_REVIEWED_REJECTIONS",
      warnings: [
        "This is a reviewed text transformation, not a guarantee of anonymization or legal compliance.",
        "Detection and validation cover extracted text only; OCR, images, metadata, comments, headers, footers and unextracted content may remain outside this output.",
        "A candidate rejected by the reviewer remains unchanged and may contain identifying information.",
        "Only extracted text sections were exported to TXT; original formatting and document metadata were not preserved.",
      ],
    };

    await mkdir(dirname(outputPath), { recursive: true });
    await mkdir(dirname(reportPath), { recursive: true });
    await writeFile(outputPath, content, { encoding: "utf8", flag: "wx" });
    try {
      await writeFile(reportPath, JSON.stringify(report, null, 2) + "\\n", { encoding: "utf8", flag: "wx" });
    } catch (error) {
      await unlink(outputPath).catch(() => undefined);
      throw error;
    }

    console.log(pc.bold("DataShield — reviewed text transformation"));
    console.log(`Mode: ${mode}`);
    console.log(`Candidates transformed: ${transformed.transformedCount}`);
    console.log(`Post-transformation candidates: ${postScan.findings.length}`);
    console.log(`TXT output: ${outputPath}`);
    console.log(`Audit report: ${reportPath}`);
    if (rejectedFindings.length > 0) {
      console.log(pc.yellow(
        `Warning: ${rejectedFindings.length} reviewed/rejected candidate(s) remain unchanged. Re-check them before using the TXT.`,
      ));
    }
    console.log(pc.yellow(
      "This output is not certified anonymous and is not approved for real, classified or law-enforcement data. Use synthetic material in class.",
    ));
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  console.error(pc.red(error instanceof Error ? error.message : "Unexpected CLI error"));
  process.exitCode = 1;
});
