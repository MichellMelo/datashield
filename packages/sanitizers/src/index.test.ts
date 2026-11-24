import { describe, expect, it } from "vitest";
import type { DetectedEntity, ExtractedDocument } from "../../core/src/index.js";
import { sanitizeDocument } from "./index.js";

function document(content: string): ExtractedDocument {
  return {
    id: "synthetic-document",
    format: "DOCX",
    sections: [{ id: "section-1", type: "TEXT", content }],
  };
}

function finding(
  content: string,
  value: string,
  type: DetectedEntity["type"],
  occurrence = 0,
): DetectedEntity {
  let start = -1;
  let from = 0;
  for (let index = 0; index <= occurrence; index += 1) {
    start = content.indexOf(value, from);
    if (start < 0) throw new Error("Test fixture value not found.");
    from = start + value.length;
  }
  return {
    id: `section-1:${start}:${type}`,
    type,
    value,
    sectionId: "section-1",
    start,
    end: start + value.length,
    confidence: 1,
    severity: "HIGH",
    suggestedAction: "MANUAL_REVIEW",
    reviewed: true,
    reviewStatus: "CONFIRMED",
  };
}

describe("sanitizeDocument", () => {
  it("redacts reviewed values without changing the original document", () => {
    const source = "Pessoa: Marina Exemplo. CPF: 123.456.789-00";
    const input = document(source);
    const result = sanitizeDocument(input, [
      finding(source, "Marina Exemplo", "PERSON"),
      finding(source, "123.456.789-00", "CPF"),
    ], "redact");

    expect(result.sections[0]?.content).toBe(
      "Pessoa: [DADO_REMOVIDO:PERSON]. CPF: [DADO_REMOVIDO:CPF]",
    );
    expect(input.sections[0]?.content).toBe(source);
    expect(result.transformedCount).toBe(2);
    expect(result.summary.PERSON).toBe(1);
    expect(result.summary.CPF).toBe(1);
  });

  it("uses the same pseudonym for repeated occurrences in a document", () => {
    const source = "Marina Exemplo retornou. Marina Exemplo foi ouvida.";
    const result = sanitizeDocument(document(source), [
      finding(source, "Marina Exemplo", "PERSON", 0),
      finding(source, "Marina Exemplo", "PERSON", 1),
    ], "pseudonymize");

    expect(result.sections[0]?.content).toBe("Pessoa_001 retornou. Pessoa_001 foi ouvida.");
    expect(result.sections[0]?.content).not.toContain("Marina Exemplo");
  });

  it("generalizes location and contact data to broad labels", () => {
    const source = "Rua das Palmeiras, nº 123; email teste@example.com";
    const result = sanitizeDocument(document(source), [
      finding(source, "Rua das Palmeiras, nº 123", "ADDRESS"),
      finding(source, "teste@example.com", "EMAIL"),
    ], "generalize");

    expect(result.sections[0]?.content).toBe(
      "[LOCALIZAÇÃO GENERALIZADA]; email [CONTATO REMOVIDO]",
    );
  });

  it("rejects overlapping or stale offsets instead of guessing", () => {
    const source = "ABC123";
    const first = finding(source, "ABC123", "VEHICLE_PLATE");
    const overlap = { ...first, id: "overlap", type: "OPERATIONAL_DATA" as const, value: "BC12", start: 1, end: 5 };

    expect(() => sanitizeDocument(document(source), [first, overlap], "redact"))
      .toThrow(/Overlapping findings/);

    expect(() => sanitizeDocument(document(source), [{ ...first, value: "XYZ999" }], "redact"))
      .toThrow(/offsets no longer match/);
  });

  it("rejects findings tied to an unknown section", () => {
    const source = "Marina";
    const item = { ...finding(source, "Marina", "PERSON"), sectionId: "missing" };
    expect(() => sanitizeDocument(document(source), [item], "redact"))
      .toThrow(/unknown document section/);
  });
});
