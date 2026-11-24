#!/usr/bin/env node
import { Command } from "commander";
import pc from "picocolors";

const program = new Command();

program
  .name("datashield")
  .description("Local-first document inspection and sanitization CLI")
  .version("0.1.0");

program
  .command("inspect")
  .description("Inspect a supported document (implementation pending)")
  .argument("<file>", "Path to a PDF, DOCX or CSV document")
  .action((file: string) => {
    console.log(pc.yellow("Inspection is not implemented yet."));
    console.log(`Selected file: ${file}`);
    console.log(
      pc.dim("Do not use this scaffold with real sensitive documents.")
    );
  });

program
  .command("sanitize")
  .description("Sanitize a document (implementation pending)")
  .argument("<file>", "Path to a PDF, DOCX or CSV document")
  .option("--policy <name>", "Sanitization policy", "intermediate")
  .option("--output <directory>", "Output directory", "./output")
  .option("--formats <formats>", "Comma-separated output formats", "json,txt")
  .action((file: string) => {
    console.error(
      pc.red("Sanitization is not implemented. No file has been processed.")
    );
    console.error(pc.dim(`Input: ${file}`));
    process.exitCode = 2;
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  const message =
    error instanceof Error ? error.message : "Unexpected CLI error";
  console.error(pc.red(message));
  process.exitCode = 1;
});
