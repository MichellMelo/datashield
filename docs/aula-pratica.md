# Aula prática — DataShield (documento sintético)

## Objetivo

Demonstrar, localmente, o ciclo de inspeção, detecção, avaliação, revisão humana e transformação de texto extraído em uma cópia TXT.

**Use exclusivamente o documento fictício preparado para o exercício. Não utilize documentos policiais, administrativos, pessoais ou classificados nesta aula.** O recurso de transformação é experimental, não certifica anonimização e não está homologado para documentos reais.

## Preparação

Requisitos: Node.js 22+, npm 10+ e terminal local.

Na raiz do repositório:

```bash
npm install
npm run typecheck
npm test
npm run build
```

Coloque `datashield_documento_ficticio_teste.docx` na raiz do repositório.

## Roteiro sugerido

### 1. Inspecionar sem exibir o conteúdo

```bash
npm run dev -- inspect ./datashield_documento_ficticio_teste.docx
```

Converse sobre formato, tamanho, quantidade de seções e caracteres extraídos. Extração não é detecção.

### 2. Detectar candidatos

```bash
npm run dev -- detect ./datashield_documento_ficticio_teste.docx
```

Observe categorias, quantidade, criticidade, confiança e posições. Os valores ficam ocultos por padrão.

### 3. Avaliar precisão e cobertura

```bash
npm run dev -- evaluate ./datashield_documento_ficticio_teste.docx --labels ./fixtures/synthetic/occurrence-ground-truth.json
```

Explique:
- Precisão: proporção de detecções corretas entre todas as detecções.
- Recall: proporção de ocorrências esperadas que foram encontradas.
- F1: equilíbrio entre precisão e recall.
- FP: falso positivo; FN: falso negativo.

O gabarito lista cada ocorrência, incluindo repetições de nomes na narrativa. O avaliador compara categoria e valor normalizado e conta as duplicatas separadamente.

### 4. Fazer revisão humana

```bash
npm run dev -- review ./datashield_documento_ficticio_teste.docx --output ./datashield-review.json
```

Para cada candidato:
- `c`: confirmar.
- `r`: rejeitar.
- `s`: pular e deixar pendente.
- `q`: salvar as decisões feitas e sair.

O arquivo lateral guarda IDs, categorias, localizações e decisões, sem copiar os valores encontrados nem o texto original. Os valores são mostrados no terminal durante a revisão.

### 5. Transformar somente após a revisão

Depois de percorrer todos os candidatos, transforme uma cópia TXT:

```bash
npm run dev -- sanitize ./datashield_documento_ficticio_teste.docx --review ./datashield-review.json --mode pseudonymize --output ./output/aula-desidentificada.txt
```

Modos disponíveis:

- `redact`: substitui cada achado confirmado por um marcador de categoria.
- `pseudonymize`: usa pseudônimos consistentes dentro do documento, sem salvar tabela de correspondência.
- `generalize`: troca os achados por rótulos amplos, como `[LOCALIZAÇÃO GENERALIZADA]`.

Se algum candidato tiver sido rejeitado, a exportação será bloqueada por padrão. Após conferir cuidadosamente cada rejeição, o exercício pode permitir a permanência desses candidatos com:

```bash
npm run dev -- sanitize ./datashield_documento_ficticio_teste.docx --review ./datashield-review.json --mode pseudonymize --allow-reviewed-rejections --output ./output/aula-desidentificada.txt
```

O comando confere o SHA-256 do original, exige uma decisão para cada achado e verifica novamente o TXT antes de gravar. Se aparecer um candidato residual que não corresponda exatamente às rejeições revisadas, a exportação será bloqueada. O relatório JSON registra quantidades e avisos sem copiar os valores encontrados.

O resultado é texto extraído, não uma reconstrução do DOCX/PDF. A extração não garante captura de OCR, imagens, metadados, comentários, cabeçalhos, rodapés ou conteúdo oculto. A ausência de achados na segunda varredura não prova anonimização.

### 6. Encerrar e discutir limitações

```bash
npm test
```

Perguntas para discussão:
1. Quais falsos positivos podem surgir de padrões isolados?
2. Que dados podem não aparecer no texto extraído (OCR, imagens, comentários, metadados, cabeçalhos e rodapés)?
3. Por que um CPF com dígitos verificadores válidos não prova existência ou titularidade?
4. Por que um bom resultado neste documento não garante desempenho em relatórios diferentes?
5. Por que revisão humana é necessária antes de qualquer transformação?
6. Por que um candidato rejeitado pode continuar sendo um risco?
7. Por que uma segunda varredura sem achados não prova anonimização?

## Segurança e limites

- Processamento local, sem envio para serviços externos de IA.
- `--show-values` e a revisão interativa exibem dados no terminal; nesta aula, use somente dados sintéticos.
- Métricas são relativas ao gabarito informado. Se o gabarito estiver incompleto ou não corresponder exatamente ao documento, as métricas serão enganosas.
- A transformação inicial opera apenas sobre texto extraído e candidatos revisados. Não há garantia de anonimização, generalização territorial ou cobertura integral do documento.
- Exportação reconstruída em PDF/DOCX, OCR, inspeção de metadados e homologação de segurança não estão implementados.
- Não utilizar para decisões operacionais, investigação, procedimentos disciplinares ou tratamento de documentos reais.
