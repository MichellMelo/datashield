import type {
  DetectedEntity,
  ExtractedDocument,
  SensitiveEntityType,
} from "../../core/src/index.js";

export type SanitizationMode = "redact" | "pseudonymize" | "generalize";

export interface SanitizationResult {
  sections: ExtractedDocument["sections"];
  transformedCount: number;
  summary: Partial<Record<SensitiveEntityType, number>>;
}

const pseudonymPrefixes: Record<SensitiveEntityType, string> = {
  PERSON: "Pessoa",
  CPF: "CPF",
  RG: "RG",
  CNPJ: "CNPJ",
  PHONE: "Telefone",
  EMAIL: "Email",
  ADDRESS: "Local",
  GPS: "Coordenada",
  VEHICLE_PLATE: "Veiculo",
  VEHICLE_CHASSIS: "Chassi",
  PROCESS_NUMBER: "Procedimento",
  ORGANIZATION: "Organizacao",
  ALIAS: "Codinome",
  SOURCE: "Fonte",
  OPERATIONAL_DATA: "DadoOperacional",
  DATE_TIME: "DataHora",
  OCCURRENCE_ID: "Ocorrencia",
  OPERATIONAL_UNIT: "UnidadeOperacional",
  TEAM: "Equipe",
  OPERATIONAL_LOCATION: "LocalOperacional",
};

const generalizedLabels: Record<SensitiveEntityType, string> = {
  PERSON: "[PESSOA]",
  CPF: "[IDENTIFICADOR REMOVIDO]",
  RG: "[IDENTIFICADOR REMOVIDO]",
  CNPJ: "[IDENTIFICADOR REMOVIDO]",
  PHONE: "[CONTATO REMOVIDO]",
  EMAIL: "[CONTATO REMOVIDO]",
  ADDRESS: "[LOCALIZAÇÃO GENERALIZADA]",
  GPS: "[LOCALIZAÇÃO GENERALIZADA]",
  VEHICLE_PLATE: "[VEÍCULO]",
  VEHICLE_CHASSIS: "[VEÍCULO]",
  PROCESS_NUMBER: "[PROCEDIMENTO]",
  ORGANIZATION: "[ORGANIZAÇÃO NÃO IDENTIFICADA]",
  ALIAS: "[IDENTIFICADOR PESSOAL]",
  SOURCE: "[FONTE PROTEGIDA]",
  OPERATIONAL_DATA: "[DADO OPERACIONAL REMOVIDO]",
  DATE_TIME: "[DATA/HORÁRIO]",
  OCCURRENCE_ID: "[IDENTIFICADOR DE OCORRÊNCIA]",
  OPERATIONAL_UNIT: "[UNIDADE OPERACIONAL]",
  TEAM: "[EQUIPE]",
  OPERATIONAL_LOCATION: "[REFERÊNCIA TERRITORIAL]",
};

function normalizeKey(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLocaleLowerCase("pt-BR")
    .replace(/[^\p{L}\p{N}]/gu, "");
}

function makeReplacement(
  finding: DetectedEntity,
  mode: SanitizationMode,
  pseudonyms: Map<string, string>,
  counters: Map<SensitiveEntityType, number>,
): string {
  if (mode === "redact") return `[DADO_REMOVIDO:${finding.type}]`;
  if (mode === "generalize") return generalizedLabels[finding.type];

  const key = `${finding.type}:${normalizeKey(finding.value)}`;
  const existing = pseudonyms.get(key);
  if (existing) return existing;

  const next = (counters.get(finding.type) ?? 0) + 1;
  counters.set(finding.type, next);
  const token = `${pseudonymPrefixes[finding.type]}_${String(next).padStart(3, "0")}`;
  pseudonyms.set(key, token);
  return token;
}

/**
 * Applies reviewed detector findings to extracted text sections.
 *
 * This is a text transformation only. It does not prove anonymization and
 * cannot sanitize content that extraction or detection did not discover.
 */
export function sanitizeDocument(
  document: ExtractedDocument,
  findings: DetectedEntity[],
  mode: SanitizationMode,
): SanitizationResult {
  const findingsBySection = new Map<string, DetectedEntity[]>();
  for (const finding of findings) {
    const sectionFindings = findingsBySection.get(finding.sectionId) ?? [];
    sectionFindings.push(finding);
    findingsBySection.set(finding.sectionId, sectionFindings);
  }

  const pseudonyms = new Map<string, string>();
  const counters = new Map<SensitiveEntityType, number>();
  const summary: Partial<Record<SensitiveEntityType, number>> = {};

  const sections = document.sections.map((section) => {
    const sectionFindings = findingsBySection.get(section.id) ?? [];
    const ordered = [...sectionFindings].sort((a, b) => a.start - b.start || a.end - b.end);

    let previousEnd = -1;
    for (const finding of ordered) {
      if (!Number.isInteger(finding.start) || !Number.isInteger(finding.end)
        || finding.start < 0 || finding.end <= finding.start
        || finding.end > section.content.length) {
        throw new Error(`Invalid finding offsets in section ${section.id}.`);
      }
      if (finding.start < previousEnd) {
        throw new Error(`Overlapping findings prevent safe transformation in section ${section.id}.`);
      }
      if (section.content.slice(finding.start, finding.end) !== finding.value) {
        throw new Error(`Finding offsets no longer match source text in section ${section.id}.`);
      }
      previousEnd = finding.end;
    }

    let content = section.content;
    for (const finding of [...ordered].reverse()) {
      const replacement = makeReplacement(finding, mode, pseudonyms, counters);
      content = content.slice(0, finding.start) + replacement + content.slice(finding.end);
      summary[finding.type] = (summary[finding.type] ?? 0) + 1;
    }
    return { ...section, content };
  });

  const knownSectionIds = new Set(document.sections.map((section) => section.id));
  for (const sectionId of findingsBySection.keys()) {
    if (!knownSectionIds.has(sectionId)) {
      throw new Error(`Finding references an unknown document section: ${sectionId}.`);
    }
  }

  return {
    sections,
    transformedCount: findings.length,
    summary,
  };
}
