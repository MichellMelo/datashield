import type { DetectedEntity, SensitiveEntityType } from "../../core/src/index.js";

export interface GroundTruthEntity {
  type: SensitiveEntityType;
  value: string;
}

export interface EntityError {
  type: SensitiveEntityType;
  value: string;
  start?: number;
  end?: number;
}

export interface CategoryMetrics {
  type: SensitiveEntityType;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  unmatchedDetections: EntityError[];
  missedEntities: EntityError[];
}

export interface EvaluationResult {
  categories: CategoryMetrics[];
  totals: {
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
    precision: number | null;
    recall: number | null;
    f1: number | null;
  };
}

function normalizeValue(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLocaleLowerCase("pt-BR")
    .replace(/[^\p{L}\p{N}]/gu, "");
}

function ratio(numerator: number, denominator: number): number | null {
  return denominator === 0 ? null : numerator / denominator;
}

function metrics(type: SensitiveEntityType, detections: DetectedEntity[], expected: GroundTruthEntity[]): CategoryMetrics {
  const remaining = new Map<string, number>();
  for (const entity of expected) {
    const key = normalizeValue(entity.value);
    remaining.set(key, (remaining.get(key) ?? 0) + 1);
  }

  let truePositives = 0;
  const unmatchedDetections: EntityError[] = [];
  for (const finding of detections) {
    const key = normalizeValue(finding.value);
    const count = remaining.get(key) ?? 0;
    if (count > 0) {
      truePositives += 1;
      remaining.set(key, count - 1);
    } else {
      unmatchedDetections.push({
        type,
        value: finding.value,
        start: finding.start,
        end: finding.end,
      });
    }
  }

  const missedEntities: EntityError[] = [];
  for (const entity of expected) {
    const key = normalizeValue(entity.value);
    const count = remaining.get(key) ?? 0;
    if (count > 0) {
      missedEntities.push({ type, value: entity.value });
      remaining.set(key, count - 1);
    }
  }

  const falsePositives = unmatchedDetections.length;
  const falseNegatives = missedEntities.length;
  const precision = ratio(truePositives, truePositives + falsePositives);
  const recall = ratio(truePositives, truePositives + falseNegatives);
  const f1 = precision === null || recall === null
    ? null
    : precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  return {
    type, truePositives, falsePositives, falseNegatives, precision, recall, f1,
    unmatchedDetections, missedEntities,
  };
}

/**
 * Compares detector candidates with a human-authored ground-truth list.
 * Matching is by entity type + normalized value and respects duplicate occurrences.
 */
export function evaluateDetections(
  findings: DetectedEntity[],
  groundTruth: GroundTruthEntity[],
): EvaluationResult {
  const types = [...new Set([
    ...findings.map((finding) => finding.type),
    ...groundTruth.map((entity) => entity.type),
  ])].sort((a, b) => a.localeCompare(b));

  const categories = types.map((type) =>
    metrics(
      type,
      findings.filter((finding) => finding.type === type),
      groundTruth.filter((entity) => entity.type === type),
    ),
  );

  const truePositives = categories.reduce((sum, item) => sum + item.truePositives, 0);
  const falsePositives = categories.reduce((sum, item) => sum + item.falsePositives, 0);
  const falseNegatives = categories.reduce((sum, item) => sum + item.falseNegatives, 0);
  const precision = ratio(truePositives, truePositives + falsePositives);
  const recall = ratio(truePositives, truePositives + falseNegatives);
  const f1 = precision === null || recall === null
    ? null
    : precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  return {
    categories,
    totals: { truePositives, falsePositives, falseNegatives, precision, recall, f1 },
  };
}
