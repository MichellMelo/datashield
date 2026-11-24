import { readFile, stat } from "node:fs/promises";
import { extname } from "node:path";
import { parse } from "csv-parse/sync";
import mammoth from "mammoth";
import { getDocument } from "pdfjs-dist/legacy/build/pdf.mjs";
import type { DocumentFormat, DocumentSection, ExtractedDocument } from "../../core/src/index.js";

const MAX_FILE_BYTES = 25 * 1024 * 1024;

export interface InspectOptions {
  maxFileBytes?: number;
}

export interface InspectionMetadata {
  path: string;
  format: DocumentFormat;
  sizeBytes: number;
  sectionCount: number;
  characterCount: number;
  sections: DocumentSection[];
}

function detectFormat(path: string): DocumentFormat {
  const extension = extname(path).toLowerCase();
  if (extension === ".pdf") return "PDF";
  if (extension === ".docx") return "DOCX";
  if (extension === ".csv") return "CSV";
  throw new Error("Unsupported file type. Supported formats: PDF, DOCX and CSV.");
}

function assertSignature(format: DocumentFormat, buffer: Buffer): void {
  if (format === "PDF" && buffer.subarray(0, 5).toString("ascii") !== "%PDF-") {
    throw new Error("The file extension is PDF, but its signature is invalid.");
  }
  if (format === "DOCX" && !(buffer[0] === 0x50 && buffer[1] === 0x4b)) {
    throw new Error("The file extension is DOCX, but it is not a valid ZIP-based document.");
  }
  if (format === "CSV" && buffer.includes(0)) {
    throw new Error("CSV appears to contain binary data and was rejected.");
  }
}

async function extractPdf(buffer: Buffer): Promise<DocumentSection[]> {
  const task = getDocument({ data: new Uint8Array(buffer), useSystemFonts: false });
  const pdf = await task.promise;
  const sections: DocumentSection[] = [];
  try {
    for (let pageNumber = 1; pageNumber <= pdf.numPages; pageNumber += 1) {
      const page = await pdf.getPage(pageNumber);
      const content = await page.getTextContent();
      const text = content.items
        .filter((item) => "str" in item)
        .map((item) => ("str" in item ? item.str : ""))
        .join(" ")
        .replace(/\\s+/g, " ")
        .trim();
      sections.push({ id: `page-${pageNumber}`, type: "TEXT", content: text, page: pageNumber });
    }
  } finally {
    await pdf.destroy();
  }
  return sections;
}

async function extractDocx(buffer: Buffer): Promise<DocumentSection[]> {
  const result = await mammoth.extractRawText({ buffer });
  if (result.messages.some((message) => message.type === "error")) {
    throw new Error("DOCX extraction failed. The document may be malformed.");
  }
  return [{ id: "document-text", type: "TEXT", content: result.value }];
}

function extractCsv(buffer: Buffer): DocumentSection[] {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  const rows = parse(text, {
    bom: true,
    skip_empty_lines: true,
    relax_column_count: false,
    max_record_size: 1024 * 1024,
  }) as string[][];
  return rows.map((row, index) => ({
    id: `row-${index + 1}`,
    type: "TABLE",
    row: index + 1,
    content: JSON.stringify(row),
  }));
}

export async function extractDocument(path: string, options: InspectOptions = {}): Promise<ExtractedDocument> {
  const info = await stat(path);
  const maxFileBytes = options.maxFileBytes ?? MAX_FILE_BYTES;
  if (!info.isFile()) throw new Error("Input path must point to a regular file.");
  if (info.size === 0) throw new Error("The input file is empty.");
  if (info.size > maxFileBytes) throw new Error(`File exceeds the ${maxFileBytes}-byte safety limit.`);

  const format = detectFormat(path);
  const buffer = await readFile(path);
  assertSignature(format, buffer);

  let sections: DocumentSection[];
  if (format === "PDF") sections = await extractPdf(buffer);
  else if (format === "DOCX") sections = await extractDocx(buffer);
  else sections = extractCsv(buffer);

  return { id: `inspection-${Date.now()}`, format, sections };
}

export async function inspectDocument(path: string, options: InspectOptions = {}): Promise<InspectionMetadata> {
  const [info, document] = await Promise.all([stat(path), extractDocument(path, options)]);
  return {
    path,
    format: document.format,
    sizeBytes: info.size,
    sectionCount: document.sections.length,
    characterCount: document.sections.reduce((total, section) => total + section.content.length, 0),
    sections: document.sections,
  };
}
