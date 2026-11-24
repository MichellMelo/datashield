#!/usr/bin/env node
import { Command } from "commander";
import pc from "picocolors";
import { detectSensitiveEntities } from "../../../packages/detectors/src/index.js";
import { extractDocument, inspectDocument } from "../../../packages/extractors/src/index.js";

const program = new Command();
program.name("datashield").description("Local-first document inspection and sanitization CLI").version("0.1.0");

program.command("inspect")
  .description("Inspect a PDF, DOCX or CSV document locally")
  .argument("<file>", "Path to the document")
  .option("--show-content", "Print extracted content to the terminal (may expose sensitive data)")
  .option("--max-bytes <bytes>", "Maximum input file size", "26214400")
  .action(async (file: string, options: { showContent?: boolean; maxBytes: string }) => {
    const maxBytes = Number(options.maxBytes);
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error("--max-bytes must be a positive safe integer.");
    const result = await inspectDocument(file, { maxFileBytes: maxBytes });
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
    const maxBytes = Number(options.maxBytes);
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error("--max-bytes must be a positive safe integer.");
    const document = await extractDocument(file, { maxFileBytes: maxBytes });
    const result = detectSensitiveEntities(document);
    console.log(pc.bold("DataShield — detection"));
    console.log(`File: ${file}`);
    console.log(`Findings: ${result.findings.length}`);
    console.log("\nSummary:");
    for (const [type, count] of Object.entries(result.summary).sort(([a], [b]) => a.localeCompare(b))) console.log(`  ${type}: ${count}`);
    console.log("\nFindings:");
    for (const finding of result.findings) {
      const value = options.showValues ? ` | value: ${finding.value}` : "";
      console.log(`  [${finding.severity}] ${finding.type} | section: ${finding.sectionId} | chars: ${finding.start}-${finding.end} | confidence: ${finding.confidence}${value}`);
      if (finding.validation?.checksumValid === false) console.log(pc.yellow("    Format recognized; checksum invalid."));
    }
    console.log(pc.yellow("\nDetection only. Findings require human review. No sanitization or anonymization was performed."));
    if (!options.showValues) console.log(pc.dim("Values hidden. Use --show-values only in a trusted terminal."));
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
