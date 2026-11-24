import { describe, expect, it } from "vitest";
import { detectSensitiveEntities } from "./index.js";
import type { ExtractedDocument } from "../../core/src/index.js";

const fixture: ExtractedDocument = {
  id: "synthetic-test", format: "DOCX",
  sections: [{
    id: "document-text", type: "TEXT",
    content: `DOCUMENTO FICTÍCIO
Local informado
Rua das Palmeiras, nº 123, Bairro Lago Azul, Fortaleza/CE
Coordenadas fictícias
03°45'00.0"S, 038°30'00.0"W
Comunicante
Marina Exemplo da Silva
CPF: 123.456.789-00
(85) 90000-1234
Testemunha
Rafael Modelo de Souza
RG: TESTE-CE-000123
rafael.teste@example.com
Pessoa citada
Carlos Demonstração Lima
CPF: 987.654.321-00
(85) 98888-0000
Placa de teste: ABC1D23
Chassi de teste: 9BWZZZ00ZTP000001
Procedimento simulado: 0001234-56.2026.8.06.0001
Apelido mencionado: 'Sombra' (personagem fictício)
Organização citada: Grupo Demonstração (entidade fictícia)
Código operacional simulado: OP-TESTE-2026-09
A comunicante Marina Exemplo da Silva relatou o fato.
marina.exemplo@example.com
A testemunha Rafael Modelo de Souza afirmou ter observado.`
  }]
};

describe("detectSensitiveEntities", () => {
  const result = detectSensitiveEntities(fixture);
  it("detects structured identifiers in the synthetic fixture", () => {
    for (const type of ["CPF", "PHONE", "EMAIL", "RG", "ADDRESS", "GPS", "VEHICLE_PLATE", "VEHICLE_CHASSIS", "PROCESS_NUMBER", "ALIAS", "ORGANIZATION", "OPERATIONAL_DATA"] as const) {
      expect(result.summary[type], type).toBeGreaterThan(0);
    }
    expect(result.summary.CPF).toBe(2);
    expect(result.summary.EMAIL).toBe(2);
    expect(result.summary.PHONE).toBe(2);
  });
  it("detects person names in role context", () => {
    const names = result.findings.filter((item) => item.type === "PERSON").map((item) => item.value);
    expect(names).toContain("Marina Exemplo da Silva");
    expect(names).toContain("Rafael Modelo de Souza");
    expect(names).toContain("Carlos Demonstração Lima");
  });
  it("separates CPF pattern recognition from checksum validity", () => {
    const cpfs = result.findings.filter((item) => item.type === "CPF");
    expect(cpfs).toHaveLength(2);
    expect(cpfs.every((item) => item.validation?.formatValid)).toBe(true);
    expect(cpfs.map((item) => item.validation?.checksumValid)).toEqual([false, true]);
  });
  it("keeps offsets and pending human review for every finding", () => {
    for (const finding of result.findings) {
      expect(finding.start).toBeGreaterThanOrEqual(0);
      expect(finding.end).toBeGreaterThan(finding.start);
      expect(finding.reviewStatus).toBe("PENDING");
      expect(finding.suggestedAction).toBe("MANUAL_REVIEW");
    }
  });
});
