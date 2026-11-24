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
];

function addContextFinding(sectionId: string, match: RegExpExecArray, type: SensitiveEntityType, severity: FindingSeverity, confidence: number, findings: DetectedEntity[]) {
  const value = match[1]?.trim();
  if (!value) return;
  const start = match.index + match[0].lastIndexOf(value);
  findings.push({
    id: `${sectionId}:${start}:${type}`, type, value, sectionId, start, end: start + value.length,
    confidence, severity, suggestedAction: "MANUAL_REVIEW", reviewed: false, reviewStatus: "PENDING",
  });
}

function contextualFindings(sectionId: string, text: string): DetectedEntity[] {
  const findings: DetectedEntity[] = [];
  const patterns: Array<{ type: SensitiveEntityType; regex: RegExp; severity: FindingSeverity; confidence: number }> = [
    { type: "RG", regex: /\bRG\s*:\s*([A-Z0-9.-]{5,24})/gi, severity: "HIGH", confidence: 0.92 },
    { type: "ADDRESS", regex: /(?:Local informado\s*:?\s*|residir na\s+)((?:Rua|Avenida|Av\.|Travessa|Alameda|Praça)\s+[^\n.;]{3,120})/gi, severity: "CRITICAL", confidence: 0.9 },
    { type: "ALIAS", regex: /Apelido mencionado\s*:\s*['"“]?([^'"”\n(]{2,60})/gi, severity: "MEDIUM", confidence: 0.9 },
    { type: "ORGANIZATION", regex: /Organização citada\s*:\s*([^\n(]{2,100})/gi, severity: "MEDIUM", confidence: 0.9 },
    { type: "OPERATIONAL_DATA", regex: /Código operacional simulado\s*:\s*([A-Z0-9_-]{4,50})/gi, severity: "HIGH", confidence: 0.99 },
    { type: "PERSON", regex: /(?:^|\n)(?:Comunicante|Testemunha|Pessoa citada)[ \t]*(?:\r?\n[ \t]*|[ \t]+)([A-ZÀ-Ý][\p{L}'-]*(?:[ \t]+(?:(?:da|de|do|dos|das|e)[ \t]+)?[A-ZÀ-Ý][\p{L}'-]*){1,4})(?=[\t\r\n]|$)/gu, severity: "HIGH", confidence: 0.88 },
    { type: "PERSON", regex: /(?:comunicante|testemunha)\s+([A-ZÀ-Ý][\p{L}'-]+(?:\s+[A-ZÀ-Ý][\p{L}'-]+){1,4})\s+(?:relatou|afirmou)/giu, severity: "HIGH", confidence: 0.88 },
  ];
  for (const item of patterns) {
    let match: RegExpExecArray | null;
    while ((match = item.regex.exec(text)) !== null) addContextFinding(sectionId, match, item.type, item.severity, item.confidence, findings);
  }
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
          id: `${section.id}:${match.index}:${rule.type}`, type: rule.type, value, sectionId: section.id,
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
  const sorted = [...unique.values()].sort((a, b) => a.sectionId.localeCompare(b.sectionId) || a.start - b.start);
  const types = [...new Set([...rules.map((rule) => rule.type), "RG", "ADDRESS", "ALIAS", "ORGANIZATION", "OPERATIONAL_DATA", "PERSON"] as SensitiveEntityType[])];
  const summary: DetectionResult["summary"] = {};
  for (const type of types) {
    const count = sorted.filter((item) => item.type === type).length;
    if (count > 0) summary[type] = count;
  }
  return { documentId: document.id, findings: sorted, summary };
}
