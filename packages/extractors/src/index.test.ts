import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { extractDocument } from "./index.js";

let directory = "";
afterEach(async () => {
  if (directory) await rm(directory, { recursive: true, force: true });
  directory = "";
});
async function fixture(name: string, content: string | Buffer): Promise<string> {
  directory = await mkdtemp(join(tmpdir(), "datashield-test-"));
  const path = join(directory, name);
  await writeFile(path, content);
  return path;
}
describe("extractDocument", () => {
  it("extracts CSV rows", async () => {
    const path = await fixture("sample.csv", "name,phone\nExample,11999990000\n");
    const result = await extractDocument(path);
    expect(result.format).toBe("CSV");
    expect(result.sections).toHaveLength(2);
    expect(result.sections[1]?.content).toContain("11999990000");
  });
  it("rejects an unsupported extension", async () => {
    const path = await fixture("sample.txt", "hello");
    await expect(extractDocument(path)).rejects.toThrow("Unsupported file type");
  });
  it("rejects a file with a mismatched PDF signature", async () => {
    const path = await fixture("fake.pdf", "not a pdf");
    await expect(extractDocument(path)).rejects.toThrow("signature is invalid");
  });
  it("rejects files larger than the configured limit", async () => {
    const path = await fixture("large.csv", "a,b\n1,2\n");
    await expect(extractDocument(path, { maxFileBytes: 2 })).rejects.toThrow("safety limit");
  });
});
