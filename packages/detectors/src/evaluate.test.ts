import { describe, expect, it } from "vitest";
import type { DetectedEntity } from "../../core/src/index.js";
import { evaluateDetections } from "./evaluate.js";

function finding(type: DetectedEntity["type"], value: string, start = 0): DetectedEntity {
  return {
    id: `test:${start}:${type}`, type, value, sectionId: "test",
    start, end: start + value.length, confidence: 0.9, severity: "HIGH",
    suggestedAction: "MANUAL_REVIEW", reviewed: false, reviewStatus: "PENDING",
  };
}

describe("evaluateDetections", () => {
  it("calculates precision, recall and F1 with false positives and false negatives", () => {
    const result = evaluateDetections(
      [finding("EMAIL", "maria@example.com"), finding("EMAIL", "wrong@example.com", 30)],
      [{ type: "EMAIL", value: "maria@example.com" }, { type: "EMAIL", value: "ana@example.com" }],
    );
    expect(result.totals).toEqual({
      truePositives: 1, falsePositives: 1, falseNegatives: 1,
      precision: 0.5, recall: 0.5, f1: 0.5,
    });
    expect(result.categories[0]?.unmatchedDetections[0]?.value).toBe("wrong@example.com");
    expect(result.categories[0]?.missedEntities[0]?.value).toBe("ana@example.com");
  });

  it("normalizes case, accents and punctuation but preserves duplicate counts", () => {
    const result = evaluateDetections(
      [finding("PERSON", "MARÍNA Exemplo-da Silva"), finding("PERSON", "Marina Exemplo da Silva", 50)],
      [{ type: "PERSON", value: "Marina Exemplo da Silva" }],
    );
    expect(result.totals.truePositives).toBe(1);
    expect(result.totals.falsePositives).toBe(1);
  });

  it("returns null metrics when there are no detections and no expected entities", () => {
    const result = evaluateDetections([], []);
    expect(result.totals.precision).toBeNull();
    expect(result.totals.recall).toBeNull();
    expect(result.totals.f1).toBeNull();
  });

  it("treats repeated entities as separate occurrences", () => {
    const result = evaluateDetections(
      [finding("PERSON", "Ana"), finding("PERSON", "Ana", 20)],
      [{ type: "PERSON", value: "Ana" }, { type: "PERSON", value: "Ana" }],
    );
    expect(result.totals).toEqual({
      truePositives: 2, falsePositives: 0, falseNegatives: 0,
      precision: 1, recall: 1, f1: 1,
    });
  });
});
