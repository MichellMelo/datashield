import { describe, expect, it } from "vitest";
import type { ExtractedDocument } from "../../core/src/index.js";
import { detectSensitiveEntities } from "./index.js";

function document(content: string): ExtractedDocument {
  return {
    id: "quality-scenario",
    format: "DOCX",
    sections: [{ id: "text", type: "TEXT", content }],
  };
}

describe("detector quality scenarios", () => {
  it("detects explicit name labels and common address abbreviations", () => {
    const result = detectSensitiveEntities(document([
      "Nome completo: André de Oliveira Santos",
      "Endereço: Av. Central, 20 - Centro",
      "Local: R. do Sol, 2 - Bairro Novo",
    ].join("\n")));

    const people = result.findings.filter((item) => item.type === "PERSON");
    const addresses = result.findings.filter((item) => item.type === "ADDRESS");
    expect(people.map((item) => item.value)).toEqual(["André de Oliveira Santos"]);
    expect(addresses.map((item) => item.value)).toEqual([
      "Av. Central, 20 - Centro",
      "R. do Sol, 2 - Bairro Novo",
    ]);
    for (const item of [...people, ...addresses]) {
      expect(result.documentId).toBe("quality-scenario");
      expect(result.findings[0]!.sectionId).toBe("text");
      expect(item.end).toBeGreaterThan(item.start);
    }
  });

  it("does not infer a person from an unlabelled capitalized phrase", () => {
    const result = detectSensitiveEntities(document(
      "João da Silva caminhava pela rua quando o fato ocorreu.",
    ));
    expect(result.findings.filter((item) => item.type === "PERSON")).toHaveLength(0);
  });

  it("does not classify a role with an unavailable identity as a person", () => {
    const result = detectSensitiveEntities(document([
      "Testemunha",
      "",
      "Não identificada",
      "",
      "Relatou que ouviu um barulho.",
    ].join("\n")));
    expect(result.findings.filter((item) => item.type === "PERSON")).toHaveLength(0);
  });

  it("accepts CRLF line endings when extracting names from role blocks", () => {
    const result = detectSensitiveEntities(document(
      "Comunicante\r\n\r\nHelena Exemplo Costa\r\n\r\nTelefone não informado",
    ));
    const people = result.findings.filter((item) => item.type === "PERSON");
    expect(people.map((item) => item.value)).toEqual(["Helena Exemplo Costa"]);
  });
});
