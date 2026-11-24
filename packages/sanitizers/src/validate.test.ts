import { describe, expect, it } from "vitest";
import { validateResidualContent } from "./validate.js";

describe("validateResidualContent", () => {
  it("finds residuals that escaped the primary transformation in the classroom sample", () => {
    const text = [
      "18/11/2026 — 21h35",
      "Número de referência",
      "SIM-2026-000184",
      "Unidade fictícia",
      "21ª Unidade Demonstrativa — Equipe Alfa",
      "A comunicante Pessoa_002 caminhava pela Rua das Palmeiras, nas proximidades do imóvel de número 123, quando foi abordada.",
      "por volta das 21h20",
      "Ponto de referência: Setor de Testes B — área fictícia",
    ].join("\n");

    const findings = validateResidualContent([{ id: "section-1", content: text }]);
    const categories = new Set(findings.map((finding) => finding.type));

    expect(categories.has("DATE_TIME")).toBe(true);
    expect(categories.has("OCCURRENCE_ID")).toBe(true);
    expect(categories.has("ADDRESS")).toBe(true);
    expect(categories.has("OPERATIONAL_UNIT")).toBe(true);
    expect(categories.has("TEAM")).toBe(true);
    expect(categories.has("OPERATIONAL_LOCATION")).toBe(true);

    expect(findings.some((finding) => finding.value === "18/11/2026")).toBe(true);
    expect(findings.some((finding) => finding.value === "21h20")).toBe(true);
    expect(findings.some((finding) => finding.value === "SIM-2026-000184")).toBe(true);
    expect(findings.some((finding) => finding.value.includes("Rua das Palmeiras"))).toBe(true);
    expect(findings.some((finding) => finding.value === "21ª Unidade Demonstrativa")).toBe(true);
    expect(findings.some((finding) => finding.value === "Equipe Alfa")).toBe(true);
    expect(findings.some((finding) => finding.value === "Setor de Testes B")).toBe(true);
  });

  it("ignores DataShield-generated labels and pseudonyms", () => {
    const text = [
      "[DATA/HORÁRIO]",
      "[IDENTIFICADOR DE OCORRÊNCIA]",
      "[UNIDADE OPERACIONAL]",
      "[EQUIPE]",
      "[REFERÊNCIA TERRITORIAL]",
      "DataHora_001 Ocorrencia_001 UnidadeOperacional_001 Equipe_001 LocalOperacional_001",
    ].join("\n");

    expect(validateResidualContent([{ id: "section-1", content: text }])).toHaveLength(0);
  });

  it("returns offsets that point to the exact residual text", () => {
    const text = "O evento ocorreu em 18/11/2026 às 21h20.";
    const findings = validateResidualContent([{ id: "section-1", content: text }]);

    for (const finding of findings) {
      expect(text.slice(finding.start, finding.end)).toBe(finding.value);
    }
  });
});
