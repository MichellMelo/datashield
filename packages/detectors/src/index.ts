import type { DetectionResult, DetectedEntity, ExtractedDocument, FindingSeverity, SensitiveEntityType } from "../../core/src/index.js";

type Rule = { type: SensitiveEntityType; pattern: RegExp; severity: FindingSeverity; confidence: number; validate?: (value: string) => { formatValid: boolean; checksumValid?: boolean } };

function validateCpf(value: string) {
  const digits = value.replace(/\D/g, "");
  if (!/^\d{11}$/.test(digits) || /^([\d])\1{10}$/.test(digits)) return { formatValid: true, checksumValid: false };
  const calculate = (length: number) => {
    let sum = 0;
    for (let i = 0; i < length; i += 1) sum += Number(digits[i]) * (length + 1 - i);
    const remainder = (sum * 10) % 11;
    return remainder === 10 ? 0 : remainder;
  };
  return { formatValid: true, checksumValid: calculate(9) === Number(digits[9]) && calculate(10) === Number(digits[10]) };
}

const rules: Rule[] = [
  { type: "CPF", pattern: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g, severity: "CRITICAL", confidence: 1, validate: validateCpf },
  { type: "EMAIL", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, severity: "CRITICAL", confidence: 1 },
  { type: "PHONE", pattern: /(?:\+55\s?)?(?:\(?\d{2}\)?\s?)9?\d{4}[-.\s]?\d{4}\b/g, severity: "CRITICAL", confidence: 0.96 },
  { type: "VEHICLE_PLATE", pattern: /(?<![A-Z0-9-])[A-Z]{3}-?\d[A-Z0-9]\d{2}(?![A-Z0-9-])/gi, severity: "HIGH", confidence: 0.94 },
  { type: "VEHICLE_CHASSIS", pattern: /\b[A-HJ-NPR-Z0-9]{17}\b/gi, severity: "HIGH", confidence: 0.98 },
  { type: "PROCESS_NUMBER", pattern: /\b\d{7}-\d{2}\.\d{4}\.\d\.\d{2}\.\d{4}\b/g, severity: "HIGH", confidence: 1 },
  { type: "GPS", pattern: /\b\d{1,2}[°º]\s*\d{1,2}'\s*\d{1,2}(?:\.\d+)?["”]?\s*[NS],?\s*\d{1,3}[°º]\s*\d{1,2}'\s*\d{1,2}(?:\.\d+)?["”]?\s*[EW]\b/gi, severity: "HIGH", confidence: 0.96 },
  { type: "DATE_TIME", pattern: /\b(?:0?[1-9]|[12]\d|3[01])\/(?:0?[1-9]|1[0-2])\/(?:19|20)\d{2}\b/g, severity: "HIGH", confidence: 0.98 },
  { type: "DATE_TIME", pattern: /\b(?:[01]?\d|2[0-3])h(?:[0-5]\d)?\b/gi, severity: "HIGH", confidence: 0.98 },
  { type: "DATE_TIME", pattern: /\b(?:[01]?\d|2[0-3]):[0-5]\d\b/g, severity: "HIGH", confidence: 0.98 },
];

function isDataShieldPlaceholder(value: string): boolean {
  const marker = /^\[(?:DADO_REMOVIDO:[A-Z_]+|LOCALIZAÇÃO GENERALIZADA|IDENTIFICADOR REMOVIDO|CONTATO REMOVIDO|VEÍCULO|PROCEDIMENTO|ORGANIZAÇÃO NÃO IDENTIFICADA|IDENTIFICADOR PESSOAL|FONTE PROTEGIDA|DADO OPERACIONAL REMOVIDO|DATA\/HORÁRIO|IDENTIFICADOR DE OCORRÊNCIA|UNIDADE OPERACIONAL|EQUIPE|REFERÊNCIA TERRITORIAL)\]$/iu;
  const pseudonym = /^(?:Pessoa|CPF|RG|CNPJ|Telefone|Email|Local|Coordenada|Veiculo|Chassi|Procedimento|Organizacao|Codinome|Fonte|DadoOperacional|DataHora|Ocorrencia|UnidadeOperacional|Equipe|LocalOperacional)_\d{3}$/u;
  return marker.test(value) || pseudonym.test(value);
}

function addContextFinding(sectionId: string, match: RegExpExecArray, type: SensitiveEntityType, severity: FindingSeverity, confidence: number, findings: DetectedEntity[]) {
  const value = match[1]?.trim();
  if (!value || isDataShieldPlaceholder(value)) return;
  const start = match.index + match[0].lastIndexOf(value);
  findings.push({
    id: sectionId + ":" + start + ":" + (start + value.length) + ":" + type, type, value, sectionId, start, end: start + value.length,
    confidence, severity, suggestedAction: "MANUAL_REVIEW", reviewed: false, reviewStatus: "PENDING",
  });
}

function personFindingsFromRoleBlocks(sectionId: string, text: string): DetectedEntity[] {
  const findings: DetectedEntity[] = [];
  const lines: Array<{ value: string; start: number }> = [];
  const lineBreak = /\r\n|\n|\r/g;
  let start = 0;
  let match: RegExpExecArray | null;

  while ((match = lineBreak.exec(text)) !== null) {
    lines.push({ value: text.slice(start, match.index), start });
    start = match.index + match[0].length;
  }
  lines.push({ value: text.slice(start), start });

  const rolePattern = /^(?:Comunicante|Testemunha|Pessoa citada)$/iu;
  const namePattern = /^[A-ZÀ-Ý][\p{L}'-]*(?:[ \t]+(?:(?:da|de|do|dos|das|e)[ \t]+)?[A-ZÀ-Ý][\p{L}'-]*){1,4}$/u;

  for (let index = 0; index < lines.length; index += 1) {
    if (!rolePattern.test(lines[index]!.value.trim())) continue;

    let candidateIndex = index + 1;
    while (candidateIndex < lines.length && lines[candidateIndex]!.value.trim() === "") candidateIndex += 1;
    if (candidateIndex >= lines.length) continue;

    const candidate = lines[candidateIndex]!.value;
    const value = candidate.trim();
    if (!namePattern.test(value)) continue;

    const leadingWhitespace = candidate.length - candidate.trimStart().length;
    const entityStart = lines[candidateIndex]!.start + leadingWhitespace;
    findings.push({
      id: sectionId + ":" + entityStart + ":" + (entityStart + value.length) + ":PERSON",
      type: "PERSON",
      value,
      sectionId,
      start: entityStart,
      end: entityStart + value.length,
      confidence: 0.88,
      severity: "HIGH",
      suggestedAction: "MANUAL_REVIEW",
      reviewed: false,
      reviewStatus: "PENDING",
    });
    index = candidateIndex;
  }
  return findings;
}

function territorialReferenceFindings(sectionId: string, text: string): DetectedEntity[] {
  const findings: DetectedEntity[] = [];
  const names = new Set<string>();
  const listPattern = /\bbairros?\s+([A-ZÀ-Ý][^.;\n]+)/giu;
  let listMatch: RegExpExecArray | null;

  while ((listMatch = listPattern.exec(text)) !== null) {
    for (const part of (listMatch[1] ?? "").split(/,|\s+e\s+/u)) {
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
      const isWordChar = (character: string) => character !== "" && /[\p{L}\p{N}_]/u.test(character);
      if (!isWordChar(before) && !isWordChar(after)) {
        findings.push({
          id: sectionId + ":" + offset + ":" + (offset + name.length) + ":OPERATIONAL_LOCATION",
          type: "OPERATIONAL_LOCATION",
          value: name,
          sectionId,
          start: offset,
          end: offset + name.length,
          confidence: 0.86,
          severity: "HIGH",
          suggestedAction: "MANUAL_REVIEW",
          reviewed: false,
          reviewStatus: "PENDING",
        });
      }
      offset += name.length;
    }
  }
  return findings;
}

function contextualFindings(sectionId: string, text: string): DetectedEntity[] {
  const findings: DetectedEntity[] = [];
  const patterns: Array<{ type: SensitiveEntityType; regex: RegExp; severity: FindingSeverity; confidence: number }> = [
    { type: "RG", regex: /\bRG\s*[:º°]?\s*([A-Z0-9.-]{5,24})/gi, severity: "HIGH", confidence: 0.92 },
    { type: "ADDRESS", regex: /(?:(?:Local(?: informado)?|Endereço(?: residencial)?)\s*:?\s*|(?:residir na|residente em)\s+)((?:Rua|R\.|Avenida|Av\.?|Travessa|Tv\.?|Trav\.?|Alameda|Al\.?|Praça|Pça\.?)\s+[^\n.;]{2,120})/gi, severity: "CRITICAL", confidence: 0.9 },
    { type: "ALIAS", regex: /Apelido mencionado\s*:\s*['"“]?([^'"”\n(]{2,60})/gi, severity: "MEDIUM", confidence: 0.9 },
    { type: "ALIAS", regex: /["“]([A-ZÀ-Ý][\p{L}'-]*(?:[ \t]+[A-ZÀ-Ý][\p{L}'-]*){0,2})["”]/gu, severity: "MEDIUM", confidence: 0.88 },
    { type: "ORGANIZATION", regex: /Organização citada\s*:\s*([^\n(]{2,100})/gi, severity: "MEDIUM", confidence: 0.9 },
    { type: "ORGANIZATION", regex: /\*\*((?:Mercearia|Farmácia|Mercadinho|Supermercado|Restaurante|Loja|Empresa|Associação|Bar|Hospital|Escola|Igreja)\s+[^*]{2,80})\*\*/giu, severity: "MEDIUM", confidence: 0.9 },
    { type: "ORGANIZATION", regex: /\b((?:Bonde|Grupo|Facção|Organização)\s+(?:(?:do|da|de|dos|das)\s+)?[\p{Lu}][\p{L}'-]+(?:\s+[\p{Lu}][\p{L}'-]+){0,2})\b/gu, severity: "MEDIUM", confidence: 0.88 },
    { type: "ORGANIZATION", regex: /\b(BDV)\b/g, severity: "MEDIUM", confidence: 0.86 },
    { type: "OPERATIONAL_DATA", regex: /Código operacional simulado\s*:\s*([A-Z0-9_-]{4,50})/gi, severity: "HIGH", confidence: 0.99 },
    { type: "OCCURRENCE_ID", regex: /(?:Número de referência|Número da ocorrência|N[º°.]?\s*(?:da )?ocorrência|Protocolo(?: de atendimento)?|Registro(?: da ocorrência)?)\s*:?[ \t\r\n]*([A-Z0-9][A-Z0-9._/-]{5,50})/giu, severity: "HIGH", confidence: 0.99 },
    { type: "OCCURRENCE_ID", regex: /\b(?:BO|B\.O\.)\s*(?:n[º°.]?\s*)?:?\s*([A-Z0-9][A-Z0-9._/-]{4,50})/giu, severity: "HIGH", confidence: 0.96 },
    { type: "ADDRESS", regex: /\b(?:na|pela|em)\s+((?:Rua|R\.|Avenida|Av\.?|Travessa|Tv\.?|Trav\.?|Alameda|Al\.?|Praça|Pça\.?)\s+(?:(?:do|da|de|dos|das)\s+)?[\p{L}\d]+(?:[ \t]+(?!com\b|na\b|no\b|nas\b|nos\b|quando\b|foi\b|em\b|sobre\b|para\b)[\p{L}\d]+){0,2})/giu, severity: "CRITICAL", confidence: 0.9 },
    { type: "ADDRESS", regex: /(?:Rua|R\.|Avenida|Av\.?|Travessa|Tv\.?|Trav\.?|Alameda|Al\.?|Praça|Pça\.?)\s+(?:(?:do|da|de|dos|das)\s+)?[\p{L}\d]+(?:[ \t]+[\p{L}\d]+){0,2}[ \t]*,[ \t]*n[º°o.]?[ \t]*(\d{1,6}(?:\.\d{3})?)(?![\d])/giu, severity: "HIGH", confidence: 0.88 },
    { type: "ADDRESS", regex: /(?:imóvel|residência|casa|apartamento)\s+de número\s+(\d{1,6})/giu, severity: "HIGH", confidence: 0.84 },
    { type: "OPERATIONAL_UNIT", regex: /(?:Unidade fictícia|Unidade responsável|Unidade policial)\s*:?\s*([\d]{1,3}ª?\s+(?:Unidade|Batalhão|Companhia|Delegacia|Distrito)\s+[A-ZÀ-Ý][^—–\n.;]{1,50})/giu, severity: "HIGH", confidence: 0.94 },
    { type: "OPERATIONAL_UNIT", regex: /\b(\d{1,3}ª?\s+(?:Unidade|Batalhão|Companhia|Delegacia|Distrito)\s+[A-ZÀ-Ý][^—–\n.;]{1,50})/giu, severity: "HIGH", confidence: 0.9 },
    { type: "OPERATIONAL_UNIT", regex: /\b((?:Seção|Subseção|Núcleo|Departamento|Divisão)\s+de\s+[A-ZÀ-Ý][\p{L}-]+(?:\s+[A-ZÀ-Ý][\p{L}-]+){0,2})/gu, severity: "HIGH", confidence: 0.88 },
    { type: "TEAM", regex: /\b(Equipe\s+[A-ZÀ-Ý][\p{L}0-9_-]{1,30})/giu, severity: "MEDIUM", confidence: 0.9 },
    { type: "OPERATIONAL_LOCATION", regex: /(?:Ponto de referência|Referência territorial|Área operacional)\s*:\s*([^—–\n;]{2,80})/giu, severity: "HIGH", confidence: 0.9 },
    { type: "OPERATIONAL_LOCATION", regex: /\b((?:Setor|Quadrante|Área|Região)\s+(?:de\s+)?[A-ZÀ-Ý][^—–\n.;]{1,45})/gu, severity: "HIGH", confidence: 0.86 },

    { type: "PERSON", regex: /(?:comunicante|testemunha)[ \t]+([A-ZÀ-Ý][\p{L}'-]+(?:[ \t]+[A-ZÀ-Ý][\p{L}'-]+){1,4})[ \t]+(?:relatou|afirmou)/giu, severity: "HIGH", confidence: 0.88 },
    { type: "PERSON", regex: /\b(?:Nome completo|Nome|Identificado como|Pessoa identificada como)\s*:\s*([A-ZÀ-Ý][\p{L}'-]*(?:\s+(?:(?:da|de|do|dos|das|e)\s+)?[A-ZÀ-Ý][\p{L}'-]*){1,4})(?=[,;\t\r\n.]|$)/giu, severity: "HIGH", confidence: 0.9 },
    { type: "PERSON", regex: /(?:proprietária|balconista|em nome de|mãe de|anda com|conversando com)\s*,?\s*\*\*([A-ZÀ-Ý][\p{L}'-]*(?:\s+(?:(?:da|de|do|dos|das|e)\s+)?[A-ZÀ-Ý][\p{L}'-]*){1,5})\*\*/giu, severity: "HIGH", confidence: 0.9 },
    { type: "PERSON", regex: /\*\*([A-ZÀ-Ý][\p{L}'-]*(?:\s+(?:(?:da|de|do|dos|das|e)\s+)?[A-ZÀ-Ý][\p{L}'-]*){0,4})\s*\(["“][^"”]+["”]\)\*\*/gu, severity: "HIGH", confidence: 0.88 },
    { type: "PERSON", regex: /\bAnalista\s+([A-Z]\.\s*[A-ZÀ-Ý][\p{L}'-]*)/giu, severity: "HIGH", confidence: 0.84 },
  ];
  for (const item of patterns) {
    let match: RegExpExecArray | null;
    while ((match = item.regex.exec(text)) !== null) addContextFinding(sectionId, match, item.type, item.severity, item.confidence, findings);
  }
  findings.push(...personFindingsFromRoleBlocks(sectionId, text));
  findings.push(...territorialReferenceFindings(sectionId, text));
  return findings;
}

export function detectSensitiveEntities(document: ExtractedDocument): DetectionResult {
  const findings: DetectedEntity[] = [];
  for (const section of document.sections) {
    for (const rule of rules) {
      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = rule.pattern.exec(section.content)) !== null) {
        const value = match[0];
        findings.push({
          id: section.id + ":" + match.index + ":" + (match.index + value.length) + ":" + rule.type, type: rule.type, value, sectionId: section.id,
          start: match.index, end: match.index + value.length, confidence: rule.confidence, severity: rule.severity,
          ...(rule.validate ? { validation: rule.validate(value) } : {}),
          suggestedAction: "MANUAL_REVIEW", reviewed: false, reviewStatus: "PENDING",
        });
      }
    }
    findings.push(...contextualFindings(section.id, section.content));
  }
  const unique = new Map<string, DetectedEntity>();
  for (const finding of findings) {
    const key = `${finding.sectionId}:${finding.start}:${finding.end}:${finding.type}`;
    if (!unique.has(key)) unique.set(key, finding);
  }
  const candidates = [...unique.values()];
  // Broad address context and narrative street rules may identify nested spans.
  // Keep the widest same-category span to avoid duplicate review decisions.
  const nonRedundant = candidates.filter((finding) => !candidates.some((other) =>
    other !== finding
    && other.sectionId === finding.sectionId
    && other.type === finding.type
    && other.start <= finding.start
    && other.end >= finding.end
    && (other.start < finding.start || other.end > finding.end)
  ));
  const sorted = nonRedundant.sort((a, b) =>
    a.sectionId.localeCompare(b.sectionId) || a.start - b.start || a.end - b.end
  );
  const ids = new Set<string>();
  for (const finding of sorted) {
    if (ids.has(finding.id)) {
      throw new Error("O detector gerou um identificador de achado duplicado.");
    }
    ids.add(finding.id);
  }
  const types = [...new Set([...rules.map((rule) => rule.type), "RG", "ADDRESS", "ALIAS", "ORGANIZATION", "OPERATIONAL_DATA", "OCCURRENCE_ID", "OPERATIONAL_UNIT", "TEAM", "OPERATIONAL_LOCATION", "PERSON"] as SensitiveEntityType[])];
  const summary: DetectionResult["summary"] = {};
  for (const type of types) {
    const count = sorted.filter((item) => item.type === type).length;
    if (count > 0) summary[type] = count;
  }
  return { documentId: document.id, findings: sorted, summary };
}
