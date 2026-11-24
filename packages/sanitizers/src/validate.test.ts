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

  it("detects report-specific residual patterns independently", () => {
    const text = [
      "A proprietária, **Maria do Socorro Lima Freitas**, informou os dados.",
      "Ela é mãe de **Diego Rocha Silva**, vulgo **\"Baixinho\"**.",
      "O balconista **Antônio Carlos Bezerra**, RG 2009.1188.334, relatou o fato.",
      "A **Mercearia Dois Irmãos** foi mencionada junto ao **Bonde do Vale**.",
      "O Bonde do Vale também é citado como BDV.",
      "O assunto envolve os bairros Jardim Aurora, Vila Esperança e Centro Velho.",
      "A ocorrência foi registrada no BO nº 2026/118.455.",
      "A testemunha passou pela Av. Central, nº 1.540, às 19h e às 21h.",
      "Relatório de Campo nº 047/2026; 2º Sgt PM.",
      "Motocicleta Honda CG 160 vermelha e veículo VW Gol prata.",
      "Valor R$ 1.200,00; estacionada a 50 metros do local, 15 minutos antes.",
      "Entre 17 e 27/10/2026, em 2023, foram mais seis roubos, sempre às sextas-feiras ou sábados."
    ].join("\n");

    const findings = validateResidualContent([{ id: "report", content: text }]);
    const byType = (type: string) => findings.filter((finding) => finding.type === type);

    expect(byType("PERSON").map((finding) => finding.value)).toContain("Maria do Socorro Lima Freitas");
    expect(byType("PERSON").map((finding) => finding.value)).toContain("Diego Rocha Silva");
    expect(byType("RG").map((finding) => finding.value)).toContain("2009.1188.334");
    expect(byType("ALIAS").map((finding) => finding.value)).toContain("Baixinho");
    expect(byType("ORGANIZATION").map((finding) => finding.value)).toContain("Mercearia Dois Irmãos");
    expect(byType("ORGANIZATION").map((finding) => finding.value)).toContain("Bonde do Vale");
    expect(byType("ORGANIZATION").map((finding) => finding.value)).toContain("BDV");
    expect(byType("OPERATIONAL_LOCATION").map((finding) => finding.value)).toContain("Jardim Aurora");
    expect(byType("OCCURRENCE_ID").map((finding) => finding.value)).toContain("2026/118.455");
    expect(byType("ADDRESS").map((finding) => finding.value)).toContain("1.540");
    expect(byType("DATE_TIME").map((finding) => finding.value)).toContain("19h");
    expect(byType("DATE_TIME").map((finding) => finding.value)).toContain("17");
    expect(byType("DATE_TIME").map((finding) => finding.value)).toContain("2023");
    const operationalValues = byType("OPERATIONAL_DATA").map((finding) => finding.value);
    expect(operationalValues).toContain("047/2026");
    expect(operationalValues).toContain("2º Sgt PM");
    expect(operationalValues).toContain("Honda CG 160 vermelha");
    expect(operationalValues).toContain("VW Gol prata");
    expect(operationalValues).toContain("R$ 1.200,00");
    expect(operationalValues).toContain("50 metros");
    expect(operationalValues).toContain("15 minutos antes");
    expect(operationalValues).toContain("mais seis roubos");
    expect(operationalValues).toContain("sempre às sextas-feiras ou sábados");

    for (const finding of findings) {
      expect(text.slice(finding.start, finding.end)).toBe(finding.value);
    }
  });

});
