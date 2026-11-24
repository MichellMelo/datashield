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
  identityWarnings: string[];
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

function buildPersonIdentityKeys(
  sections: ExtractedDocument["sections"],
  findings: DetectedEntity[],
): { byName: Map<string, string>; warnings: string[] } {
  const peopleByAlias = new Map<string, Map<string, string>>();

  for (const section of sections) {
    const sectionFindings = findings.filter((finding) => finding.sectionId === section.id);
    const people = sectionFindings.filter((finding) => finding.type === "PERSON");
    const aliases = sectionFindings.filter((finding) => finding.type === "ALIAS");

    for (const person of people) {
      let nearest: { alias: DetectedEntity; distance: number } | undefined;
      for (const alias of aliases) {
        if (person.end > alias.start) continue;
        const gap = section.content.slice(person.end, alias.start);
        if (gap.length > 40 || /[.!?\r\n]/u.test(gap)) continue;

        const introducedByAlias = /\b(?:vulgo|alcunha|apelid[oa])\b/iu.test(gap);
        const parentheticalAlias = /^\s*\(\s*["“']?\s*$/u.test(gap);
        if (!introducedByAlias && !parentheticalAlias) continue;

        const distance = alias.start - person.end;
        if (!nearest || distance < nearest.distance) nearest = { alias, distance };
      }

      if (!nearest) continue;
      const aliasKey = normalizeKey(nearest.alias.value);
      const personKey = normalizeKey(person.value);
      const group = peopleByAlias.get(aliasKey) ?? new Map<string, string>();
      group.set(personKey, person.value);
      peopleByAlias.set(aliasKey, group);
    }
  }

  const proposedKeys = new Map<string, Set<string>>();
  const warnings: string[] = [];

  for (const people of peopleByAlias.values()) {
    const variants = [...people.entries()];
    if (variants.length < 2) continue;

    const fullNames = variants.filter(([, value]) => value.trim().split(/\s+/u).length > 1);
    const canonical = fullNames.length === 1 ? fullNames[0] : undefined;
    const firstNameKey = canonical
      ? normalizeKey(canonical[1].trim().split(/\s+/u)[0] ?? "")
      : "";
    const safeAbbreviationGroup = Boolean(canonical)
      && variants.every(([nameKey]) => nameKey === canonical![0] || nameKey === firstNameKey);

    if (!safeAbbreviationGroup || !canonical) {
      warnings.push("Um mesmo apelido está associado a nomes diferentes; os pseudônimos foram mantidos separados para evitar uma associação automática incorreta.");
      continue;
    }

    for (const [nameKey] of variants) {
      const candidates = proposedKeys.get(nameKey) ?? new Set<string>();
      candidates.add(canonical[0]);
      proposedKeys.set(nameKey, candidates);
    }
  }

  const byName = new Map<string, string>();
  for (const [nameKey, candidates] of proposedKeys) {
    if (candidates.size === 1) {
      byName.set(nameKey, [...candidates][0]!);
    } else {
      warnings.push("Uma referência pessoal participa de associações ambíguas; os pseudônimos foram mantidos separados.");
    }
  }

  return { byName, warnings: [...new Set(warnings)] };
}

function organizationInitials(value: string): string {
  const words = value.trim().split(/\\s+/u).filter(Boolean);
  return words.map((word) => [...normalizeKey(word)][0] ?? "").join("");
}

function buildOrganizationIdentityKeys(
  findings: DetectedEntity[],
): { byName: Map<string, string>; warnings: string[] } {
  const organizations = findings.filter((finding) => finding.type === "ORGANIZATION");
  const fullNames = new Map<string, Set<string>>();
  const acronyms = new Set<string>();

  for (const finding of organizations) {
    const value = finding.value.trim();
    if (/^\\p{Lu}{2,6}$/u.test(value)) {
      acronyms.add(normalizeKey(value));
      continue;
    }
    if (!/\\s/u.test(value)) continue;
    const initials = organizationInitials(value);
    const names = fullNames.get(initials) ?? new Set<string>();
    names.add(normalizeKey(value));
    fullNames.set(initials, names);
  }

  const byName = new Map<string, string>();
  const warnings: string[] = [];
  for (const acronym of acronyms) {
    const matches = fullNames.get(acronym);
    if (!matches || matches.size === 0) continue;
    if (matches.size > 1) {
      warnings.push("Uma sigla de organização corresponde a mais de um nome no documento; os pseudônimos foram mantidos separados para evitar uma associação automática incorreta.");
      continue;
    }
    const canonical = [...matches][0]!;
    byName.set(acronym, canonical);
    byName.set(canonical, canonical);
  }

  return { byName, warnings };
}

function makeReplacement(
  finding: DetectedEntity,
  mode: SanitizationMode,
  pseudonyms: Map<string, string>,
  counters: Map<SensitiveEntityType, number>,
  identityKeys: Map<string, string>,
): string {
  if (mode === "redact") return `[DADO_REMOVIDO:${finding.type}]`;
  if (mode === "generalize") return generalizedLabels[finding.type];

  const identityKey = (finding.type === "PERSON" || finding.type === "ORGANIZATION")
    ? identityKeys.get(normalizeKey(finding.value))
    : undefined;
  const key = `${finding.type}:${identityKey ?? normalizeKey(finding.value)}`;
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
  const personIdentity = mode === "pseudonymize"
    ? buildPersonIdentityKeys(document.sections, findings)
    : { byName: new Map<string, string>(), warnings: [] as string[] };
  const organizationIdentity = mode === "pseudonymize"
    ? buildOrganizationIdentityKeys(findings)
    : { byName: new Map<string, string>(), warnings: [] as string[] };
  const identity = {
    byName: new Map([...personIdentity.byName, ...organizationIdentity.byName]),
    warnings: [...personIdentity.warnings, ...organizationIdentity.warnings],
  };

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
      const replacement = makeReplacement(finding, mode, pseudonyms, counters, identity.byName);
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
    identityWarnings: identity.warnings,
  };
}
