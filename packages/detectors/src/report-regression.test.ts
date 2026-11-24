import { describe, expect, it } from "vitest";
import type { ExtractedDocument } from "../../core/src/index.js";
import { detectSensitiveEntities } from "./index.js";

const reportText = [
  "# Relatório de Campo nº 047/2026 — Seção de Inteligência (FICTÍCIO)",
  "",
  "**Data:** 28/10/2026",
  "**Elaborado por:** 2º Sgt PM Analista R. Moura",
  "**Assunto:** Roubos a estabelecimentos comerciais nos bairros Jardim Aurora, Vila Esperança e Centro Velho",
  "",
  "1.1. Em 02/10/2026, por volta das 19h40, a **Mercearia Dois Irmãos**, situada na Rua Projetada 12, nº 88, Jardim Aurora, foi roubada por dois indivíduos em uma motocicleta **Honda CG 160 vermelha**, placa **QWE4F21**. Levaram cerca de R$ 1.200,00 e celulares de clientes. A proprietária, **Maria do Socorro Lima Freitas**, CPF 401.227.913-50, telefone (85) 99812-4410, registrou o BO nº 2026/118.455.",
  "",
  "1.2. Em 09/10/2026, às 20h10, a **Farmácia Popular Esperança**, na Av. Central, nº 1.540, Vila Esperança, foi roubada por dois homens em motocicleta vermelha, sem placa visível. O balconista **Antônio Carlos Bezerra**, RG 2009.1188.334, relatou que um dos autores era baixo, usava boné preto e era chamado pelo comparsa de **\"Baixinho\"**.",
  "",
  "1.3. Em 16/10/2026, às 19h55, o **Mercadinho Bom Preço**, na Rua do Comércio, nº 210, Centro Velho, foi roubado. As câmeras registraram a motocicleta **QWE4F21** estacionada a 50 metros do local 15 minutos antes do fato.",
  "",
  "1.4. Entre 17 e 27/10/2026 foram registrados mais seis roubos com o mesmo padrão: dupla em motocicleta, horário entre 19h e 21h, estabelecimentos pequenos, sempre às sextas-feiras ou sábados.",
  "",
  "2.1. A motocicleta placa **QWE4F21** está registrada em nome de **Francisca Helena Rocha**, CPF 512.884.069-12, residente na Rua das Acácias, nº 33, Vila Esperança. Ela é mãe de **Diego Rocha Silva**, vulgo **\"Baixinho\"**, nascido em 14/03/2004, CPF 088.441.276-03.",
  "",
  "2.2. **Diego Rocha Silva (\"Baixinho\")** possui passagem por roubo em 2023. Segundo moradores ouvidos informalmente, anda com **Wesley Matos Cordeiro**, vulgo **\"Cabeça\"**, telefone (85) 98877-0192.",
  "",
  "2.3. **Wesley (\"Cabeça\")** foi visto em 20/10/2026 em um bar na Rua 7, Centro Velho, conversando com **Raimundo Nonato Alves**, vulgo **\"Velho Nonato\"**, apontado em relatórios anteriores como **gerente do Bonde do Vale** na região.",
  "",
  "2.4. Em 22/10/2026, um veículo **VW Gol prata**, placa **RTY2B88**, em nome de **Raimundo Nonato Alves**, foi abordado na Av. Central com dois celulares roubados no fato de 02/10/2026. O condutor era **Wesley (\"Cabeça\")**, liberado após registro.",
  "",
  "3.1. Há indícios de que **\"Baixinho\"** e **\"Cabeça\"** formam a dupla autora dos roubos.",
  "",
  "3.2. A ligação com o Bonde do Vale **não está confirmada**: o encontro com \"Velho Nonato\" e o uso do veículo dele podem indicar repasse de produto roubado, mas também podem ser relação pessoal.",
  "",
  "4.1. Confirmar quem conduzia a motocicleta QWE4F21 nas datas dos fatos.",
  "4.2. Verificar se os celulares roubados estão sendo revendidos e por quem.",
  "4.3. Avaliar se o BDV cobra \"taxa\" dos roubos na região."
].join("\n");

const document: ExtractedDocument = {
  id: "field-report-regression",
  format: "DOCX",
  sections: [{ id: "document-text", type: "TEXT", content: reportText }],
};

describe("field report DOCX regression", () => {
  it("detects the 72 expected occurrences across the report categories", () => {
    const result = detectSensitiveEntities(document);

    expect(result.findings).toHaveLength(83);
    expect(result.findings.find((finding) => finding.type === "OCCURRENCE_ID")?.value)
      .toBe("2026/118.455");
    const operationalValues = result.findings
      .filter((finding) => finding.type === "OPERATIONAL_DATA")
      .map((finding) => finding.value);
    expect(operationalValues).toContain("047/2026");
    expect(operationalValues).toContain("2º Sgt PM");
    expect(operationalValues).toContain("Honda CG 160 vermelha");
    expect(operationalValues).toContain("VW Gol prata");
    expect(operationalValues).toContain("R$ 1.200,00");
    expect(operationalValues).toContain("50 metros");
    expect(operationalValues).toContain("15 minutos antes");
    expect(operationalValues).toContain("mais seis roubos");
    expect(operationalValues).toContain("sempre às sextas-feiras ou sábados");
    const dateValues = result.findings
      .filter((finding) => finding.type === "DATE_TIME")
      .map((finding) => finding.value);
    expect(dateValues).toContain("17");
    expect(dateValues).toContain("2023");
    expect(result.summary).toEqual({
      ADDRESS: 10,
      ALIAS: 10,
      CPF: 3,
      DATE_TIME: 16,
      OCCURRENCE_ID: 1,
      OPERATIONAL_DATA: 9,
      OPERATIONAL_LOCATION: 8,
      OPERATIONAL_UNIT: 1,
      ORGANIZATION: 6,
      PERSON: 11,
      PHONE: 2,
      RG: 1,
      VEHICLE_PLATE: 5,
    });
  });

  it("limits street candidates and does not absorb adjacent narrative", () => {
    const addresses = detectSensitiveEntities(document).findings
      .filter((finding) => finding.type === "ADDRESS");
    expect(addresses.filter((finding) => finding.value === "Av. Central")).toHaveLength(2);
    expect(addresses.some((finding) => finding.value.includes("celulares roubados"))).toBe(false);
    expect(addresses.some((finding) => finding.value === "1.540")).toBe(true);
    expect(addresses.some((finding) => finding.value === "88")).toBe(true);
    expect(addresses.some((finding) => finding.value === "210")).toBe(true);
    expect(addresses.some((finding) => finding.value === "33")).toBe(true);
    expect(addresses.some((finding) => finding.value === "Rua 7")).toBe(true);
  });

  it("keeps every finding offset aligned to the extracted source", () => {
    const findings = detectSensitiveEntities(document).findings;
    for (const finding of findings) {
      expect(reportText.slice(finding.start, finding.end)).toBe(finding.value);
    }
  });
});
