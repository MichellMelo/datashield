import type { SensitiveEntityType } from "../../core/src/index.js";

export interface ResidualCandidate {
  type: SensitiveEntityType;
  sectionId: string;
  start: number;
  end: number;
  value: string;
}

type ResidualRule = {
  type: SensitiveEntityType;
  pattern: RegExp;
};

/**
 * Independent, deliberately conservative residual checks.
 * These rules are separate from the primary detector so a defect in the
 * detection pipeline is less likely to be repeated by the post-scan.
 */
const residualRules: ResidualRule[] = [
  { type: "CPF", pattern: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g },
  { type: "EMAIL", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },
  { type: "PHONE", pattern: /(?:\+55\s?)?(?:\(?\d{2}\)?\s?)9?\d{4}[-.\s]?\d{4}\b/g },
  { type: "GPS", pattern: /\b\d{1,2}[°º]\s*\d{1,2}'\s*\d{1,2}(?:\.\d+)?["”]?\s*[NS],?\s*\d{1,3}[°º]\s*\d{1,2}'\s*\d{1,2}(?:\.\d+)?["”]?\s*[EW]\b/gi },
  { type: "VEHICLE_PLATE", pattern: /(?<![A-Z0-9-])[A-Z]{3}-?\d[A-Z0-9]\d{2}(?![A-Z0-9-])/gi },
  { type: "VEHICLE_CHASSIS", pattern: /\b[A-HJ-NPR-Z0-9]{17}\b/gi },
  { type: "PROCESS_NUMBER", pattern: /\b\d{7}-\d{2}\.\d{4}\.\d\.\d{2}\.\d{4}\b/g },
  { type: "DATE_TIME", pattern: /\b(?:0?[1-9]|[12]\d|3[01])\/(?:0?[1-9]|1[0-2])\/(?:19|20)\d{2}\b/g },
  { type: "DATE_TIME", pattern: /\b(?:[01]?\d|2[0-3])(?:h(?:[0-5]\d)?|:[0-5]\d)\b/gi },
  { type: "OCCURRENCE_ID", pattern: /(?:Número de referência|Número da ocorrência|N[º°.]?\s*(?:da )?ocorrência|Protocolo(?: de atendimento)?|Registro(?: da ocorrência)?)\s*:?[ \t\r\n]*([A-Z0-9][A-Z0-9._/-]{5,50})/giu },
  { type: "OCCURRENCE_ID", pattern: /\b(?:BO|B\.O\.)\s*(?:n[º°.]?\s*)?:?\s*([A-Z0-9][A-Z0-9._/-]{4,50})/giu },
  { type: "ADDRESS", pattern: /(?:Local(?: informado)?|Endereço(?: residencial)?)\s*:?[ \t\r\n]*((?:Rua|R\.|Avenida|Av\.?|Travessa|Tv\.?|Trav\.?|Alameda|Al\.?|Praça|Pça\.?)\s+[^\n.;]{2,120})/giu },
  { type: "ADDRESS", pattern: /\b(?:na|pela|em)\s+((?:Rua|R\.|Avenida|Av\.?|Travessa|Tv\.?|Trav\.?|Alameda|Al\.?|Praça|Pça\.?)\s+(?:(?:do|da|de|dos|das)\s+)?[\p{L}\d]+(?:[ \t]+(?!com\b|na\b|no\b|nas\b|nos\b|quando\b|foi\b|em\b|sobre\b|para\b)[\p{L}\d]+){0,2})/giu },
  { type: "ADDRESS", pattern: /(?:Rua|R\.|Avenida|Av\.?|Travessa|Tv\.?|Trav\.?|Alameda|Al\.?|Praça|Pça\.?)\s+(?:(?:do|da|de|dos|das)\s+)?[\p{L}\d]+(?:[ \t]+[\p{L}\d]+){0,2}[ \t]*,[ \t]*n[º°o.]?[ \t]*(\d{1,6}(?:\.\d{3})?)(?![\d])/giu },
  { type: "ADDRESS", pattern: /(?:imóvel|residência|casa|apartamento)\s+de número\s+(\d{1,6})/giu },
  { type: "PERSON", pattern: /(?:comunicante|testemunha)\s+([A-ZÀ-Ý][\p{L}'-]+(?:[ \t]+(?:(?:da|de|do|dos|das|e)[ \t]+)?[A-ZÀ-Ý][\p{L}'-]+){1,4})[ \t]+(?:relatou|afirmou)/giu },
  { type: "PERSON", pattern: /^(?:Comunicante|Testemunha|Pessoa citada)\s*[\r\n]+\s*([A-ZÀ-Ý][\p{L}'-]+(?:[ \t]+(?:(?:da|de|do|dos|das|e)[ \t]+)?[A-ZÀ-Ý][\p{L}'-]+){1,4})$/gimu },
  { type: "PERSON", pattern: /(?:proprietária|balconista|em nome de|mãe de|anda com|conversando com)\s*,?\s*\*\*([A-ZÀ-Ý][\p{L}'-]*(?:\s+(?:(?:da|de|do|dos|das|e)\s+)?[A-ZÀ-Ý][\p{L}'-]*){1,5})\*\*/giu },
  { type: "PERSON", pattern: /\*\*([A-ZÀ-Ý][\p{L}'-]*(?:\s+(?:(?:da|de|do|dos|das|e)\s+)?[A-ZÀ-Ý][\p{L}'-]*){0,4})\s*\(["“][^"”]+["”]\)\*\*/gu },
  { type: "PERSON", pattern: /\bAnalista\s+([A-Z]\.\s*[A-ZÀ-Ý][\p{L}'-]*)/giu },
  { type: "RG", pattern: /\bRG\s*[:º°]?\s*([A-Z0-9.-]{5,24})/gi },
  { type: "ALIAS", pattern: /Apelido mencionado\s*:\s*['"“]?([^'"”\n(]{2,60})/giu },
  { type: "ALIAS", pattern: /["“]([A-ZÀ-Ý][\p{L}'-]*(?:[ \t]+[A-ZÀ-Ý][\p{L}'-]*){0,2})["”]/gu },
  { type: "ORGANIZATION", pattern: /Organização citada\s*:\s*([^\n(]{2,100})/giu },
  { type: "ORGANIZATION", pattern: /\*\*((?:Mercearia|Farmácia|Mercadinho|Supermercado|Restaurante|Loja|Empresa|Associação|Bar|Hospital|Escola|Igreja)\s+[^*]{2,80})\*\*/giu },
  { type: "ORGANIZATION", pattern: /\b((?:Bonde|Grupo|Facção|Organização)\s+(?:(?:do|da|de|dos|das)\s+)?[\p{Lu}][\p{L}'-]+(?:\s+[\p{Lu}][\p{L}'-]+){0,2})\b/gu },
  { type: "ORGANIZATION", pattern: /\b(BDV)\b/g },
  { type: "OPERATIONAL_DATA", pattern: /Código operacional simulado\s*:\s*([A-Z0-9_-]{4,50})/giu },
  { type: "OPERATIONAL_UNIT", pattern: /(?:Unidade fictícia|Unidade responsável|Unidade policial)\s*:?\s*([\d]{1,3}ª?\s+(?:Unidade|Batalhão|Companhia|Delegacia|Distrito)\s+[A-ZÀ-Ý][^—–\n.;]{1,50})/giu },
  { type: "OPERATIONAL_UNIT", pattern: /\b(\d{1,3}ª?\s+(?:Unidade|Batalhão|Companhia|Delegacia|Distrito)\s+[A-ZÀ-Ý][^—–\n.;]{1,50})/giu },
  { type: "OPERATIONAL_UNIT", pattern: /\b((?:Seção|Subseção|Núcleo|Departamento|Divisão)\s+de\s+[A-ZÀ-Ý][\p{L}-]+(?:\s+[A-ZÀ-Ý][\p{L}-]+){0,2})/gu },
  { type: "TEAM", pattern: /\b(Equipe\s+[A-ZÀ-Ý][\p{L}0-9_-]{1,30})/giu },
  { type: "OPERATIONAL_LOCATION", pattern: /(?:Ponto de referência|Referência territorial|Área operacional)\s*:\s*([^—–\n;]{2,80})/giu },
  { type: "OPERATIONAL_LOCATION", pattern: /\b((?:Setor|Quadrante|Área|Região)\s+(?:de\s+)?[A-ZÀ-Ý][^—–\n.;]{1,45})/gu },
];

const generatedMarker = /^\[(?:DADO_REMOVIDO:[A-Z_]+|LOCALIZAÇÃO GENERALIZADA|IDENTIFICADOR REMOVIDO|CONTATO REMOVIDO|VEÍCULO|PROCEDIMENTO|ORGANIZAÇÃO NÃO IDENTIFICADA|IDENTIFICADOR PESSOAL|FONTE PROTEGIDA|DADO OPERACIONAL REMOVIDO|DATA\/HORÁRIO|IDENTIFICADOR DE OCORRÊNCIA|UNIDADE OPERACIONAL|EQUIPE|REFERÊNCIA TERRITORIAL)\]$/iu;
const generatedPseudonym = /^(?:Pessoa|CPF|RG|CNPJ|Telefone|Email|Local|Coordenada|Veiculo|Chassi|Procedimento|Organizacao|Codinome|Fonte|DadoOperacional|DataHora|Ocorrencia|UnidadeOperacional|Equipe|LocalOperacional)_\d{3}$/u;

function readCapture(match: RegExpExecArray): { value: string; start: number } | null {
  const value = match[1]?.trim();
  if (!value) return null;
  const relativeOffset = match[0].lastIndexOf(value);
  if (relativeOffset < 0) return null;
  return { value, start: match.index + relativeOffset };
}

function collectTerritorialResiduals(sectionId: string, text: string): ResidualCandidate[] {
  const result: ResidualCandidate[] = [];
  const names = new Set<string>();
  const list = /\bbairros?\s+([A-ZÀ-Ý][^.;\n]+)/giu;
  let group: RegExpExecArray | null;

  while ((group = list.exec(text)) !== null) {
    for (const part of (group[1] ?? "").split(/,|\s+e\s+/u)) {
      const candidate = part.trim();
      if (/^[A-ZÀ-Ý][\p{L}'-]+(?:\s+(?:(?:da|de|do|dos|das)\s+)?[A-ZÀ-Ý][\p{L}'-]+){1,3}$/u.test(candidate)) {
        names.add(candidate);
      }
    }
  }

  for (const name of names) {
    let offset = 0;
    while ((offset = text.indexOf(name, offset)) !== -1) {
      const before = offset > 0 ? text[offset - 1] : "";
      const after = text[offset + name.length] ?? "";
      const word = (character: string) => character !== "" && /[\p{L}\p{N}_]/u.test(character);
      if (!word(before) && !word(after)) {
        result.push({
          type: "OPERATIONAL_LOCATION",
          sectionId,
          start: offset,
          end: offset + name.length,
          value: name,
        });
      }
      offset += name.length;
    }
  }
  return result;
}

export function validateResidualContent(
  sections: Array<{ id: string; content: string }>,
): ResidualCandidate[] {
  const found = new Map<string, ResidualCandidate>();

  for (const section of sections) {
    for (const rule of residualRules) {
      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = rule.pattern.exec(section.content)) !== null) {
        const captured = match[1]
          ? readCapture(match)
          : { value: match[0], start: match.index };
        if (!captured || generatedMarker.test(captured.value) || generatedPseudonym.test(captured.value)) {
          continue;
        }

        const candidate: ResidualCandidate = {
          type: rule.type,
          sectionId: section.id,
          start: captured.start,
          end: captured.start + captured.value.length,
          value: captured.value,
        };
        const key = candidate.sectionId + ":" + candidate.start + ":" + candidate.end + ":" + candidate.type;
        if (!found.has(key)) found.set(key, candidate);
      }
    }
  }

  for (const section of sections) {
    for (const candidate of collectTerritorialResiduals(section.id, section.content)) {
      if (!generatedMarker.test(candidate.value) && !generatedPseudonym.test(candidate.value)) {
        const key = candidate.sectionId + ":" + candidate.start + ":" + candidate.end + ":" + candidate.type;
        if (!found.has(key)) found.set(key, candidate);
      }
    }
  }

  return [...found.values()].sort((a, b) =>
    a.sectionId.localeCompare(b.sectionId) || a.start - b.start || a.end - b.end
  );
}
