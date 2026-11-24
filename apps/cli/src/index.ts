#!/usr/bin/env node
import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, dirname, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { Command } from "commander";
import pc from "picocolors";
import { z } from "zod";
import type { DetectedEntity, SensitiveEntityType } from "../../../packages/core/src/index.js";
import { detectSensitiveEntities } from "../../../packages/detectors/src/index.js";
import { evaluateDetections } from "../../../packages/detectors/src/evaluate.js";
import { sanitizeDocument, type SanitizationMode } from "../../../packages/sanitizers/src/index.js";
import { extractDocument, inspectDocument } from "../../../packages/extractors/src/index.js";

const ENTITY_TYPES = [
  "PERSON", "CPF", "RG", "CNPJ", "PHONE", "EMAIL", "ADDRESS", "GPS",
  "VEHICLE_PLATE", "VEHICLE_CHASSIS", "PROCESS_NUMBER", "ORGANIZATION",
  "ALIAS", "SOURCE", "OPERATIONAL_DATA",
] as const;

const groundTruthSchema = z.object({
  schemaVersion: z.literal(1),
  description: z.string().optional(),
  entities: z.array(z.object({
    type: z.enum(ENTITY_TYPES),
    value: z.string().trim().min(1),
  }).strict()),
}).strict();

const reviewReportSchema = z.object({
  schemaVersion: z.literal(1),
  sourceSha256: z.string().regex(/^[a-f0-9]{64}$/i),
  findings: z.array(z.object({
    findingId: z.string().min(1),
    type: z.enum(ENTITY_TYPES),
    sectionId: z.string().min(1),
    start: z.number().int().nonnegative(),
    end: z.number().int().positive(),
    confidence: z.number().min(0).max(1),
    severity: z.enum(["CRITICAL", "HIGH", "MEDIUM"]),
    status: z.enum(["CONFIRMED", "REJECTED", "PENDING"]),
  }).strict()),
}).passthrough();

const program = new Command();
program.name("datashield").description("Ferramenta de linha de comando para inspeção local e detecção de dados sensíveis").version("0.1.0");

const ENTITY_LABELS: Record<SensitiveEntityType, string> = {
  PERSON: "PESSOA", CPF: "CPF", RG: "RG", CNPJ: "CNPJ", PHONE: "TELEFONE",
  EMAIL: "E-MAIL", ADDRESS: "ENDEREÇO", GPS: "COORDENADAS GPS",
  VEHICLE_PLATE: "PLACA DE VEÍCULO", VEHICLE_CHASSIS: "CHASSI",
  PROCESS_NUMBER: "NÚMERO DE PROCEDIMENTO", ORGANIZATION: "ORGANIZAÇÃO",
  ALIAS: "APELIDO", SOURCE: "FONTE", OPERATIONAL_DATA: "DADO OPERACIONAL",
};
const SEVERITY_LABELS: Record<"CRITICAL" | "HIGH" | "MEDIUM", string> = {
  CRITICAL: "CRÍTICA", HIGH: "ALTA", MEDIUM: "MÉDIA",
};

function parseMaxBytes(value: string): number {
  const maxBytes = Number(value);
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error("--max-bytes deve ser um número inteiro positivo e seguro.");
  return maxBytes;
}

function percentage(value: number | null): string {
  return value === null ? "N/D" : `${(value * 100).toFixed(1).replace(".", ",")}%`;
}

function printEvaluationTable(result: ReturnType<typeof evaluateDetections>): void {
  const columns = [
    ["CATEGORIA", 20], ["TP", 5], ["FP", 5], ["FN", 5],
    ["PRECISÃO", 11], ["ABRANGÊNCIA", 11], ["F1", 8],
  ] as const;
  const header = columns.map(([name, width]) => name.padEnd(width)).join(" ");
  console.log(header);
  console.log("-".repeat(header.length));
  for (const item of result.categories) {
    const values = [
      ENTITY_LABELS[item.type], String(item.truePositives), String(item.falsePositives), String(item.falseNegatives),
      percentage(item.precision), percentage(item.recall), percentage(item.f1),
    ];
    console.log(values.map((value, index) => value.padEnd(columns[index]![1])).join(" "));
  }
  console.log("-".repeat(header.length));
  const total = result.totals;
  console.log([
    "TOTAL".padEnd(20), String(total.truePositives).padEnd(5),
    String(total.falsePositives).padEnd(5), String(total.falseNegatives).padEnd(5),
    percentage(total.precision).padEnd(11), percentage(total.recall).padEnd(11),
    percentage(total.f1).padEnd(8),
  ].join(" "));
}

function printEvaluationErrors(
  result: ReturnType<typeof evaluateDetections>,
  showValues: boolean,
): void {
  const withErrors = result.categories.filter((item) => item.falsePositives > 0 || item.falseNegatives > 0);
  if (withErrors.length === 0) {
    console.log(pc.green("\nNenhum falso positivo ou falso negativo em relação a este gabarito."));
    return;
  }
  console.log(pc.yellow("\nDiferenças em relação ao gabarito:"));
  for (const item of withErrors) {
    for (const error of item.unmatchedDetections) {
      const detail = showValues ? ` | valor: ${error.value}` : "";
      console.log(`  FP ${ENTITY_LABELS[error.type]} | caracteres: ${error.start}-${error.end}${detail}`);
    }
    for (const error of item.missedEntities) {
      const detail = showValues ? ` | esperado: ${error.value}` : "";
      console.log(`  FN ${ENTITY_LABELS[error.type]}${detail}`);
    }
  }
  if (!showValues) console.log(pc.dim("Valores ocultos. Use --show-values somente com dados sintéticos e em um terminal confiável."));
}

program.command("inspect")
  .description("Inspeciona localmente um documento PDF, DOCX ou CSV")
  .argument("<file>", "Caminho do documento")
  .option("--show-content", "Exibe o conteúdo extraído no terminal (pode revelar dados sensíveis)")
  .option("--max-bytes <bytes>", "Tamanho máximo do arquivo de entrada", "26214400")
  .action(async (file: string, options: { showContent?: boolean; maxBytes: string }) => {
    const result = await inspectDocument(file, { maxFileBytes: parseMaxBytes(options.maxBytes) });
    console.log(pc.bold("DataShield — inspeção"));
    console.log(`Arquivo: ${result.path}`);
    console.log(`Formato: ${result.format}`);
    console.log(`Tamanho: ${result.sizeBytes.toLocaleString("pt-BR")} bytes`);
    console.log(`Seções: ${result.sectionCount}`);
    console.log(`Caracteres extraídos: ${result.characterCount}`);
    if (options.showContent) {
      console.log(pc.yellow("\nExibição do conteúdo ativada. Trate a saída do terminal como informação sensível."));
      for (const section of result.sections) {
        console.log(pc.dim(`\n[${section.id}]`));
        console.log(section.content);
      }
    } else console.log(pc.dim("\nO conteúdo não foi exibido. Use --show-content somente em um terminal confiável."));
    console.log(pc.yellow("\nSomente inspeção. Não foi realizada detecção, transformação ou anonimização."));
  });

program.command("detect")
  .description("Detecta possíveis dados sensíveis localmente; não realiza transformação")
  .argument("<file>", "Caminho de um documento PDF, DOCX ou CSV")
  .option("--show-values", "Exibe os valores detectados (pode revelar dados sensíveis)")
  .option("--max-bytes <bytes>", "Tamanho máximo do arquivo de entrada", "26214400")
  .action(async (file: string, options: { showValues?: boolean; maxBytes: string }) => {
    const document = await extractDocument(file, { maxFileBytes: parseMaxBytes(options.maxBytes) });
    const result = detectSensitiveEntities(document);
    console.log(pc.bold("DataShield — detecção"));
    console.log(`Arquivo: ${file}`);
    console.log(`Achados: ${result.findings.length}`);
    console.log("\nResumo:");
    for (const [type, count] of Object.entries(result.summary).sort(([a], [b]) => a.localeCompare(b))) {
      console.log(`  ${ENTITY_LABELS[type as SensitiveEntityType] ?? type}: ${count}`);
    }
    console.log("\nAchados:");
    for (const finding of result.findings) {
      const value = options.showValues ? ` | valor: ${finding.value}` : "";
      console.log(`  [${SEVERITY_LABELS[finding.severity]}] ${ENTITY_LABELS[finding.type]} | seção: ${finding.sectionId} | caracteres: ${finding.start}-${finding.end} | confiança: ${finding.confidence}${value}`);
      if (finding.validation?.checksumValid === false) console.log(pc.yellow("    Formato reconhecido; dígitos verificadores inválidos."));
    }
    console.log(pc.yellow("\nSomente detecção. Os achados exigem revisão humana. Não foi realizada transformação ou anonimização."));
    if (!options.showValues) console.log(pc.dim("Valores ocultos. Use --show-values somente com dados sintéticos e em um terminal confiável."));
  });

program.command("evaluate")
  .description("Calcula precisão, abrangência (recall) e F1 comparando com um gabarito JSON elaborado por uma pessoa")
  .argument("<file>", "Arquivo sintético PDF, DOCX ou CSV para avaliação")
  .requiredOption("--labels <json>", "Arquivo JSON do gabarito")
  .option("--show-values", "Exibe valores dos falsos positivos e falsos negativos (somente dados sintéticos)")
  .option("--max-bytes <bytes>", "Tamanho máximo do arquivo de entrada", "26214400")
  .action(async (file: string, options: { labels: string; showValues?: boolean; maxBytes: string }) => {
    const rawLabels = await readFile(options.labels, "utf8");
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(rawLabels);
    } catch {
      throw new Error("O arquivo do gabarito não contém JSON válido.");
    }
    const parsed = groundTruthSchema.safeParse(parsedJson);
    if (!parsed.success) {
      throw new Error(`Esquema inválido no arquivo de gabarito: ${parsed.error.issues.map((issue) => issue.path.join(".")).join(", ")}`);
    }
    const document = await extractDocument(file, { maxFileBytes: parseMaxBytes(options.maxBytes) });
    const detected = detectSensitiveEntities(document);
    const result = evaluateDetections(detected.findings, parsed.data.entities);
    console.log(pc.bold("DataShield — avaliação"));
    console.log(`Arquivo: ${basename(file)}`);
    console.log(`Gabarito: ${basename(options.labels)} (${parsed.data.entities.length} ocorrências esperadas)`);
    console.log(`Achados do detector: ${detected.findings.length}`);
    console.log("");
    printEvaluationTable(result);
    console.log(pc.yellow("\nAs métricas são válidas somente em relação ao gabarito fornecido e a este documento."));
    printEvaluationErrors(result, Boolean(options.showValues));
    console.log(pc.dim("\nVP = verdadeiro positivo; FP = falso positivo; FN = falso negativo."));
  });

program.command("review")
  .description("Revisa interativamente os candidatos detectados e salva as decisões localmente")
  .argument("<file>", "Caminho de um documento PDF, DOCX ou CSV")
  .option("--output <file>", "Caminho do arquivo JSON com as decisões da revisão", "./datashield-review.json")
  .option("--max-bytes <bytes>", "Tamanho máximo do arquivo de entrada", "26214400")
  .action(async (file: string, options: { output: string; maxBytes: string }) => {
    if (!stdin.isTTY || !stdout.isTTY) {
      throw new Error("A revisão interativa exige um terminal real (TTY).");
    }
    const document = await extractDocument(file, { maxFileBytes: parseMaxBytes(options.maxBytes) });
    const result = detectSensitiveEntities(document);
    const rl = createInterface({ input: stdin, output: stdout });
    const decisions: Array<{
      findingId: string; type: SensitiveEntityType; sectionId: string;
      start: number; end: number; confidence: number; severity: string;
      status: "CONFIRMED" | "REJECTED" | "PENDING";
    }> = [];
    let quitRequested = false;

    console.log(pc.bold("DataShield — revisão humana"));
    console.log(pc.yellow("Os valores dos candidatos serão exibidos neste terminal. Use somente dados sintéticos ou um ambiente local confiável."));
    console.log(`Candidatos: ${result.findings.length}`);
    console.log("Para cada candidato: [c] confirmar, [r] rejeitar, [s] pular, [q] salvar e sair.\n");

    try {
      for (let index = 0; index < result.findings.length; index += 1) {
        const finding: DetectedEntity = result.findings[index]!;
        console.log(pc.bold(`[${index + 1}/${result.findings.length}] ${ENTITY_LABELS[finding.type]} — ${SEVERITY_LABELS[finding.severity]}`));
        console.log(`Valor: ${finding.value}`);
        console.log(`Localização: ${finding.sectionId} | caracteres ${finding.start}-${finding.end} | confiança: ${finding.confidence}`);
        let status: "CONFIRMED" | "REJECTED" | "PENDING" = "PENDING";
        while (true) {
          const answer = (await rl.question("Decisão [c/r/s/q]: ")).trim().toLowerCase();
          if (answer === "c") { status = "CONFIRMED"; break; }
          if (answer === "r") { status = "REJECTED"; break; }
          if (answer === "s") break;
          if (answer === "q") { quitRequested = true; break; }
          console.log("Digite c, r, s ou q.");
        }
        decisions.push({
          findingId: finding.id, type: finding.type, sectionId: finding.sectionId,
          start: finding.start, end: finding.end, confidence: finding.confidence,
          severity: finding.severity, status,
        });
        if (quitRequested) break;
      }
    } finally {
      rl.close();
    }

    const outputPath = resolve(options.output);
    const sourceSha256 = createHash("sha256").update(await readFile(file)).digest("hex");
    const report = {
      schemaVersion: 1,
      sourceFile: basename(file),
      sourceSha256,
      documentId: document.id,
      createdAt: new Date().toISOString(),
      note: "Este arquivo auxiliar armazena apenas decisões e posições no texto; intencionalmente, não armazena os valores detectados nem o texto original.",
      findings: decisions,
    };
    await writeFile(outputPath, JSON.stringify(report, null, 2) + "\n", { encoding: "utf8", flag: "wx" });
    console.log(pc.green(`\nDecisões da revisão salvas: ${outputPath}`));
    console.log("O relatório não contém o texto original nem os valores dos candidatos. Nenhuma transformação foi realizada.");
  });

function fingerprint(type: SensitiveEntityType, value: string): string {
  const normalized = value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLocaleLowerCase("pt-BR")
    .replace(/[^\p{L}\p{N}]/gu, "");
  return `${type}:${normalized}`;
}

function countFingerprints(items: Array<{ type: SensitiveEntityType; value: string }>): Map<string, number> {
  const counts = new Map<string, number>();
  for (const item of items) {
    const key = fingerprint(item.type, item.value);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

function sameCounts(left: Map<string, number>, right: Map<string, number>): boolean {
  if (left.size !== right.size) return false;
  for (const [key, count] of left) if (right.get(key) !== count) return false;
  return true;
}

program.command("sanitize")
  .description("Cria uma cópia TXT transformada após revisão; isso não certifica a anonimização")
  .argument("<file>", "Documento original PDF, DOCX ou CSV")
  .requiredOption("--review <json>", "Arquivo auxiliar de revisão humana criado pelo comando review")
  .option("--mode <mode>", "Transformação: redact (remover), pseudonymize (pseudonimizar) ou generalize (generalizar)", "pseudonymize")
  .option("--output <file>", "Caminho do novo arquivo TXT", "./output/datashield-deidentified.txt")
  .option("--report <file>", "Caminho do relatório da transformação (JSON)")
  .option("--allow-reviewed-rejections", "Permite manter candidatos explicitamente rejeitados, com um aviso")
  .option("--max-bytes <bytes>", "Tamanho máximo do arquivo de entrada", "26214400")
  .action(async (file: string, options: {
    review: string;
    mode: string;
    output: string;
    report?: string;
    allowReviewedRejections?: boolean;
    maxBytes: string;
  }) => {
    const modeResult = z.enum(["redact", "pseudonymize", "generalize"]).safeParse(options.mode);
    if (!modeResult.success) throw new Error("--mode deve ser redact, pseudonymize ou generalize.");
    const mode: SanitizationMode = modeResult.data;

    const inputPath = resolve(file);
    const reviewPath = resolve(options.review);
    const outputPath = resolve(options.output);
    const reportPath = resolve(options.report ?? `${outputPath}.report.json`);

    if (outputPath === inputPath || reportPath === inputPath || reportPath === outputPath) {
      throw new Error("O arquivo de entrada, o TXT de saída e o relatório devem usar caminhos diferentes.");
    }
    if (outputPath === reviewPath || reportPath === reviewPath) {
      throw new Error("Os arquivos de saída não podem sobrescrever o arquivo auxiliar da revisão.");
    }
    if (!outputPath.toLowerCase().endsWith(".txt")) {
      throw new Error("Somente a exportação .txt é suportada. O PDF/DOCX/CSV original não será reconstruído.");
    }

    let reviewJson: unknown;
    try {
      reviewJson = JSON.parse(await readFile(reviewPath, "utf8"));
    } catch {
      throw new Error("Não foi possível ler um arquivo JSON válido da revisão.");
    }
    const parsedReview = reviewReportSchema.safeParse(reviewJson);
    if (!parsedReview.success) {
      throw new Error("O arquivo auxiliar da revisão possui um esquema inválido. Gere-o novamente com a versão atual do DataShield.");
    }

    const sourceBytesBefore = await readFile(inputPath);
    const sourceSha256 = createHash("sha256").update(sourceBytesBefore).digest("hex");
    if (sourceSha256 !== parsedReview.data.sourceSha256) {
      throw new Error("O arquivo auxiliar da revisão não corresponde exatamente a este arquivo de origem (divergência no SHA-256). Exportação bloqueada.");
    }

    const document = await extractDocument(inputPath, { maxFileBytes: parseMaxBytes(options.maxBytes) });
    const sourceSha256After = createHash("sha256").update(await readFile(inputPath)).digest("hex");
    if (sourceSha256After !== sourceSha256) {
      throw new Error("O arquivo de origem foi alterado durante o processamento. Exportação bloqueada.");
    }

    const detected = detectSensitiveEntities(document);
    if (document.sections.every((section) => section.content.trim().length === 0)) {
      throw new Error("Nenhum texto pôde ser extraído. Exportação bloqueada; OCR e conteúdo em imagens não são suportados.");
    }

    const decisions = parsedReview.data.findings;
    const decisionsById = new Map(decisions.map((decision) => [decision.findingId, decision]));
    if (decisionsById.size !== decisions.length) {
      throw new Error("O arquivo auxiliar da revisão contém IDs de achados duplicados. Exportação bloqueada.");
    }
    if (decisions.length !== detected.findings.length) {
      throw new Error("A revisão está incompleta ou pertence a outro resultado de detecção. Revise novamente todos os candidatos.");
    }

    for (const finding of detected.findings) {
      const decision = decisionsById.get(finding.id);
      if (!decision
        || decision.type !== finding.type
        || decision.sectionId !== finding.sectionId
        || decision.start !== finding.start
        || decision.end !== finding.end) {
        throw new Error("O arquivo auxiliar da revisão não contempla exatamente os achados atuais. Exportação bloqueada.");
      }
      if (decision.status === "PENDING") {
        throw new Error("Ainda existe pelo menos um candidato aguardando revisão humana. Exportação bloqueada.");
      }
    }

    const confirmedIds = new Set(
      decisions.filter((decision) => decision.status === "CONFIRMED").map((decision) => decision.findingId),
    );
    const rejectedFindings = detected.findings.filter((finding) => !confirmedIds.has(finding.id));
    if (rejectedFindings.length > 0 && !options.allowReviewedRejections) {
      throw new Error(
        `${rejectedFindings.length}  candidato(s) foram rejeitados na revisão. Execute novamente com --allow-reviewed-rejections somente depois de verificar cuidadosamente cada rejeição.`,
      );
    }

    const confirmedFindings = detected.findings.filter((finding) => confirmedIds.has(finding.id));
    const transformed = sanitizeDocument(document, confirmedFindings, mode);
    const postScan = detectSensitiveEntities({ ...document, sections: transformed.sections });
    const expectedRemainders = countFingerprints(rejectedFindings);
    const actualRemainders = countFingerprints(postScan.findings);
    if (!sameCounts(expectedRemainders, actualRemainders)) {
      throw new Error(
        `A validação após a transformação encontrou ${postScan.findings.length} candidato(s), que não correspondem às exclusões revisadas. Exportação bloqueada.`,
      );
    }

    const content = [
      "[DataShield — cópia transformada para exercício; não certifica anonimização]",
      ...transformed.sections.map((section, index) => `### Seção ${index + 1}\n${section.content}`),
      "",
    ].join("\n\n");
    const report = {
      schemaVersion: 1,
      createdAt: new Date().toISOString(),
      sourceSha256,
      sourceFormat: document.format,
      outputFile: basename(outputPath),
      mode,
      transformedFindings: transformed.transformedCount,
      transformedByType: transformed.summary,
      reviewedRejectedCandidates: rejectedFindings.length,
      postTransformationCandidates: postScan.findings.length,
      validationStatus: rejectedFindings.length === 0 ? "PASS_NO_RESIDUAL_CANDIDATES" : "PASS_WITH_REVIEWED_REJECTIONS",
      warnings: [
        "Esta é uma transformação de texto revisada, não uma garantia de anonimização ou conformidade legal.",
        "A detecção e a validação abrangem somente o texto extraído; OCR, imagens, metadados, comentários, cabeçalhos, rodapés e conteúdo não extraído podem não estar contemplados nesta saída.",
        "Um candidato rejeitado pelo revisor permanece inalterado e pode conter informações que identifiquem alguém.",
        "Somente as seções de texto extraídas foram exportadas para TXT; a formatação original e os metadados do documento não foram preservados.",
      ],
    };

    await mkdir(dirname(outputPath), { recursive: true });
    await mkdir(dirname(reportPath), { recursive: true });
    await writeFile(outputPath, content, { encoding: "utf8", flag: "wx" });
    try {
      await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", { encoding: "utf8", flag: "wx" });
    } catch (error) {
      await unlink(outputPath).catch(() => undefined);
      throw error;
    }

    console.log(pc.bold("DataShield — transformação de texto revisada"));
    console.log(`Modo: ${mode}`);
    console.log(`Candidatos transformados: ${transformed.transformedCount}`);
    console.log(`Candidatos após a transformação: ${postScan.findings.length}`);
    console.log(`Arquivo TXT de saída: ${outputPath}`);
    console.log(`Relatório de auditoria: ${reportPath}`);
    if (rejectedFindings.length > 0) {
      console.log(pc.yellow(
        `Aviso: ${rejectedFindings.length} candidato(s) revisados/rejeitados permanecem inalterados. Verifique-os novamente antes de utilizar o TXT.`,
      ));
    }
    console.log(pc.yellow(
      "Esta saída não é certificada como anônima e não está aprovada para dados reais, classificados ou policiais. Utilize somente material sintético na aula.",
    ));
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  console.error(pc.red(error instanceof Error ? error.message : "Erro inesperado na CLI"));
  process.exitCode = 1;
});
