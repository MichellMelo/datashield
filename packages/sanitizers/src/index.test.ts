import { describe, expect, it } from "vitest";
import type { DetectedEntity, ExtractedDocument } from "../../core/src/index.js";
import { detectSensitiveEntities } from "../../detectors/src/index.js";
import { sanitizeDocument, type SanitizationMode } from "./index.js";
import { validateResidualContent } from "./validate.js";

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

  it("reuses one person pseudonym for a full name and a linked first-name reference", () => {
    const source = [
      "A proprietária, **Wesley Matos Cordeiro**, vulgo **\"Cabeça\"**.",
      "Mais tarde, **Wesley (\"Cabeça\")** foi visto no local.",
    ].join(" ");
    const input = document(source);
    const detected = detectSensitiveEntities(input);
    const transformed = sanitizeDocument(input, detected.findings, "pseudonymize");
    const personTokens = transformed.sections[0]?.content.match(/Pessoa_\d{3}/gu) ?? [];

    expect(personTokens).toHaveLength(2);
    expect(new Set(personTokens).size).toBe(1);
    expect(transformed.identityWarnings).toHaveLength(0);
  });

  it("does not merge different full names that happen to share an alias", () => {
    const source = [
      "A proprietária, **Ana Silva**, vulgo **\"Xis\"**.",
      "O balconista, **Bruno Souza**, vulgo **\"Xis\"**.",
    ].join(" ");
    const input = document(source);
    const transformed = sanitizeDocument(input, detectSensitiveEntities(input).findings, "pseudonymize");
    const personTokens = transformed.sections[0]?.content.match(/Pessoa_\d{3}/gu) ?? [];

    expect(new Set(personTokens).size).toBe(2);
    expect(transformed.identityWarnings.length).toBeGreaterThan(0);
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

  it.each(["redact", "pseudonymize", "generalize"] as SanitizationMode[])(
    "does not rediscover generated placeholders after %s transformation",
    (mode) => {
      const source = [
        "Organização citada: Grupo Demonstração",
        "Apelido mencionado: Sombra",
        "Código operacional simulado: OP-TESTE-2026-09",
      ].join("\n");
      const transformed = sanitizeDocument(document(source), [
        finding(source, "Grupo Demonstração", "ORGANIZATION"),
        finding(source, "Sombra", "ALIAS"),
        finding(source, "OP-TESTE-2026-09", "OPERATIONAL_DATA"),
      ], mode);
      const rescanned = detectSensitiveEntities({
        ...document(source),
        sections: transformed.sections,
      });

      expect(rescanned.findings).toHaveLength(0);
    },
  );

  it("transforms the temporal and operational residuals from the classroom sample", () => {
    const source = [
      "18/11/2026 — 21h35",
      "Número de referência",
      "SIM-2026-000184",
      "Unidade fictícia",
      "21ª Unidade Demonstrativa — Equipe Alfa",
      "A comunicante Marina Exemplo da Silva caminhava pela Rua das Palmeiras, nas proximidades do imóvel de número 123.",
      "por volta das 21h20",
      "Ponto de referência: Setor de Testes B — área fictícia",
    ].join("\n");
    const input = document(source);
    const detected = detectSensitiveEntities(input);
    const transformed = sanitizeDocument(input, detected.findings, "pseudonymize");
    const rescanned = detectSensitiveEntities({ ...input, sections: transformed.sections });
    const residuals = validateResidualContent(transformed.sections);

    expect(detected.findings.some((item) => item.type === "DATE_TIME")).toBe(true);
    expect(detected.findings.some((item) => item.type === "OCCURRENCE_ID")).toBe(true);
    expect(detected.findings.some((item) => item.type === "OPERATIONAL_UNIT")).toBe(true);
    expect(detected.findings.some((item) => item.type === "TEAM")).toBe(true);
    expect(detected.findings.some((item) => item.type === "OPERATIONAL_LOCATION")).toBe(true);
    expect(rescanned.findings).toHaveLength(0);
    expect(residuals).toHaveLength(0);
    expect(transformed.sections[0]?.content).not.toContain("Rua das Palmeiras");
    expect(transformed.sections[0]?.content).not.toContain("18/11/2026");
    expect(transformed.sections[0]?.content).not.toContain("SIM-2026-000184");
    expect(input.sections[0]?.content).toBe(source);
  });

  it("rejects findings tied to an unknown section", () => {
    const source = "Marina";
    const item = { ...finding(source, "Marina", "PERSON"), sectionId: "missing" };
    expect(() => sanitizeDocument(document(source), [item], "redact"))
      .toThrow(/unknown document section/);
  });
});
