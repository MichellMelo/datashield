#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
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

program.command("sanitize")
  .description("Sanitize a document (not implemented)")
  .argument("<file>", "Path to a PDF, DOCX or CSV document")
  .option("--policy <name>", "Sanitization policy", "intermediate")
  .option("--output <directory>", "Output directory", "./output")
  .option("--formats <formats>", "Comma-separated output formats", "json,txt")
  .action((file: string) => {
    console.error(pc.red("Sanitization is not implemented. No file has been processed."));
    console.error(pc.dim(`Input: ${file}`));
    process.exitCode = 2;
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  console.error(pc.red(error instanceof Error ? error.message : "Unexpected CLI error"));
  process.exitCode = 1;
});
