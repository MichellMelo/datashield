# Aula prática — DataShield (documento sintético)

## Objetivo

Demonstrar, localmente, o ciclo de inspeção, detecção, avaliação contra um gabarito e revisão humana de candidatos a dados sensíveis.

**Use exclusivamente o documento fictício preparado para o exercício. Não utilize documentos policiais, administrativos, pessoais ou classificados nesta aula.** O DataShield ainda não anonimiza documentos.

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

### 5. Encerrar e discutir limitações

```bash
npm test
```

Perguntas para discussão:
1. Quais falsos positivos podem surgir de padrões isolados?
2. Que dados podem não aparecer no texto extraído (OCR, imagens, comentários, metadados, cabeçalhos e rodapés)?
3. Por que um CPF com dígitos verificadores válidos não prova existência ou titularidade?
4. Por que um bom resultado neste documento não garante desempenho em relatórios diferentes?
5. Por que revisão humana é necessária antes de qualquer sanitização?

## Segurança e limites

- Processamento local, sem envio para serviços externos de IA.
- `--show-values` e a revisão interativa exibem dados no terminal; nesta aula, use somente dados sintéticos.
- Métricas são relativas ao gabarito informado. Se o gabarito estiver incompleto ou não corresponder exatamente ao documento, as métricas serão enganosas.
- Sanitização, anonimização, validação independente e exportação segura não estão implementadas.
- Não utilizar para decisões operacionais, investigação, procedimentos disciplinares ou tratamento de documentos reais.
