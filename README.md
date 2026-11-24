# DataShield

CLI local para inspeção de documentos, detecção de possíveis dados sensíveis, revisão humana e transformação de texto. Construído com Node.js e TypeScript.

> **Aviso de segurança:** o DataShield é uma ferramenta experimental para desenvolvimento, testes e atividades educacionais. Não está aprovado para processar documentos reais sensíveis, classificados ou policiais. Os resultados da detecção são candidatos que exigem revisão humana; não comprovam a identidade, a validade ou a titularidade dos dados. O comando `sanitize` gera somente um novo arquivo TXT com o texto extraído e transformado. Ele não garante anonimização nem constitui uma exportação aprovada para uso real.

## Funcionalidades implementadas

- Extração local de texto de arquivos PDF, DOCX e CSV.
- Inspeção de formato, tamanho, quantidade de seções e caracteres extraídos.
- Detecção por padrões estruturados e regras contextuais de possíveis CPFs, CNPJs, RGs, telefones, e-mails, endereços, coordenadas GPS, placas, chassis, números de processo CNJ, nomes de pessoas, apelidos, organizações, códigos e dados operacionais, datas/horários, identificadores de ocorrência, unidades, equipes e referências territoriais.
- Registro de posição inicial e final de cada candidato no texto da seção, confiança heurística, severidade e indicação de revisão manual.
- Reconhecimento do formato de CPF separado da validação dos dígitos verificadores. A validação não confirma se o CPF foi atribuído ou está ativo.
- Avaliação de precisão, abrangência (recall) e F1 em relação a um gabarito JSON elaborado por uma pessoa, com contagem de falsos positivos e falsos negativos.
- Revisão humana interativa para confirmar, rejeitar ou deixar candidatos pendentes.
- Arquivo auxiliar JSON da revisão, sem valores detectados ou texto original, contendo decisões, posições e hash SHA-256 da origem.
- Transformação somente dos candidatos confirmados, desde que a revisão corresponda exatamente ao arquivo original e aos achados atuais.
- Três modos de transformação: redação, pseudonimização local ao documento e generalização por categoria.
- Pseudônimos consistentes para ocorrências repetidas da mesma entidade. Associações de nomes completos/abreviados e de organizações/siglas são feitas somente quando as regras consideram a associação inequívoca; associações ambíguas geram avisos.
- Verificação posterior à transformação com o detector principal e um scanner residual independente. A exportação é bloqueada quando os achados residuais não correspondem exatamente às rejeições revisadas.
- Exibição do texto completo transformado no terminal e aprovação humana explícita antes da gravação.
- Arquivo TXT e relatório de auditoria JSON separados, criados sem sobrescrever arquivos existentes.
- Valores detectados ocultos na saída comum do CLI, salvo quando o operador solicita explicitamente sua exibição.
- Limite padrão de entrada de 25 MiB, configurável por `--max-bytes`.

## Tecnologias

- Node.js 22 ou superior
- npm 10 ou superior
- TypeScript
- Commander
- Zod
- Mammoth (DOCX)
- PDF.js (PDF)
- csv-parse (CSV)
- Vitest (testes)
- tsx (execução do TypeScript durante o desenvolvimento)
- Picocolors (formatação da saída no terminal)

## Requisitos

Instale:

1. [Node.js 22 ou superior](https://nodejs.org/) — inclui npm.
2. [Git](https://git-scm.com/downloads).
3. Um terminal, como PowerShell, Windows Terminal ou shell equivalente.

Confira as versões:

```bash
node -v
npm -v
git --version
```

## Instalação

### 1. Clonar o repositório

```bash
git clone https://github.com/MichellMelo/datashield.git
cd datashield
```

No Windows PowerShell, a pasta pode ser, por exemplo:

```powershell
Set-Location "C:\Projetos\datashield"
```

### 2. Instalar as dependências

Na raiz do repositório:

```bash
npm install
```

### 3. Validar o ambiente

```bash
npm run typecheck
npm test
npm run build
```

Os comandos devem terminar sem erros. A suíte validada na versão atual possui 7 arquivos de teste e 41 testes.

## Execução rápida

Execute os comandos a partir da raiz do repositório:

```bash
npm run dev -- --help
npm run dev -- inspect ./caminho/para/documento-ficticio.docx
npm run dev -- detect ./caminho/para/documento-ficticio.docx
```

O separador `--` informa ao npm que os argumentos seguintes devem ser encaminhados ao programa CLI.

## Comandos disponíveis

### Ajuda

```bash
npm run dev -- --help
npm run dev -- inspect --help
npm run dev -- detect --help
npm run dev -- evaluate --help
npm run dev -- review --help
npm run dev -- sanitize --help
```

### 1. Inspecionar um documento

```bash
npm run dev -- inspect ./documento-ficticio.docx
```

Apresenta o caminho, formato identificado, tamanho, quantidade de seções e quantidade de caracteres extraídos. Não executa detecção nem transformação.

Para exibir o texto extraído:

```bash
npm run dev -- inspect ./documento-ficticio.docx --show-content
```

Use `--show-content` somente com dados sintéticos e em um terminal confiável, pois a saída pode revelar informações sensíveis.

### 2. Detectar possíveis dados sensíveis

```bash
npm run dev -- detect ./documento-ficticio.docx
```

Apresenta a quantidade de achados, o resumo por categoria e os candidatos com posição, confiança e severidade. Os valores ficam ocultos por padrão.

Para exibir valores:

```bash
npm run dev -- detect ./documento-ficticio.docx --show-values
```

Use `--show-values` somente com dados sintéticos e em um terminal confiável. A detecção não realiza transformação; todos os achados exigem revisão.

### 3. Avaliar o detector

O comando `evaluate` compara os achados com um gabarito JSON feito manualmente:

```bash
npm run dev -- evaluate ./documento-ficticio.docx --labels ./caminho/para/gabarito.json
```

Para exibir valores dos falsos positivos e falsos negativos:

```bash
npm run dev -- evaluate ./documento-ficticio.docx --labels ./caminho/para/gabarito.json --show-values
```

A opção `--show-values` deve ser usada somente com dados sintéticos.

**Importante sobre os arquivos de exemplo:** o repositório contém o gabarito `fixtures/synthetic/occurrence-ground-truth.json`, mas o DOCX correspondente não está versionado neste repositório. Disponibilize localmente o documento sintético correspondente antes de executar a avaliação. O documento e o gabarito precisam descrever exatamente as mesmas ocorrências.

### 4. Revisar os candidatos

A revisão exige um terminal interativo:

```bash
npm run dev -- review ./documento-ficticio.docx --output ./datashield-review.json
```

Para cada candidato, o programa solicita uma decisão:

| Tecla | Decisão |
|---|---|
| `c` | Confirmar: o candidato deve ser transformado. |
| `r` | Rejeitar: o candidato foi considerado falso positivo ou não aplicável. |
| `s` | Pular: deixar o candidato pendente. |
| `q` | Salvar as decisões já tomadas e sair da revisão. |

A revisão salva um arquivo auxiliar com IDs dos achados, categoria, severidade, confiança, posições, decisões, data/hora e SHA-256 do documento original. O arquivo não guarda os valores detectados nem o texto original.

Os valores dos candidatos são exibidos no terminal durante a revisão. Utilize somente dados sintéticos ou um ambiente local confiável.

**Atenção:**
- `s` deixa o candidato pendente; não significa aprovação.
- `q` salva a revisão parcial, mas candidatos pendentes impedem a exportação.
- O arquivo de revisão é criado com proteção contra sobrescrita (`wx`). Escolha um nome novo para cada rodada.
- A revisão é vinculada ao hash do arquivo de origem e aos achados atuais. Se o documento mudar ou a detecção atual não corresponder à revisão, gere uma nova revisão.

### 5. Transformar o texto revisado

Depois de revisar todos os candidatos, execute:

```bash
npm run dev -- sanitize ./documento-ficticio.docx --review ./datashield-review.json --mode pseudonymize --output ./output/documento-pseudonimizado.txt
```

Modos disponíveis:

| Modo | Comportamento |
|---|---|
| `redact` | Substitui cada candidato confirmado por um marcador de categoria, como `[DADO_REMOVIDO:CPF]`. |
| `pseudonymize` | Substitui valores por tokens locais ao documento, como `Pessoa_001`. Ocorrências repetidas da mesma entidade podem receber o mesmo token. |
| `generalize` | Usa rótulos amplos, como `[LOCALIZAÇÃO GENERALIZADA]`. Não calcula áreas geográficas seguras nem datas generalizadas. |

O modo padrão é `pseudonymize`.

#### Candidatos rejeitados

Por padrão, a exportação é bloqueada quando a revisão contém candidatos rejeitados. Depois de verificar cuidadosamente cada rejeição e aceitar que esses trechos permanecerão inalterados, o operador pode permitir a exportação com:

```bash
npm run dev -- sanitize ./documento-ficticio.docx --review ./datashield-review.json --mode pseudonymize --allow-reviewed-rejections --output ./output/documento-pseudonimizado.txt
```

Essa opção não transforma os candidatos rejeitados. Eles permanecem no texto e podem conter informações identificáveis. Use-a somente após avaliação consciente.

#### Aprovação final

Antes de gravar os arquivos, o CLI:
1. valida o modo e os caminhos;
2. valida o JSON da revisão;
3. compara o SHA-256 da origem;
4. extrai novamente o documento e verifica se a origem não mudou durante o processamento;
5. executa novamente o detector;
6. compara os achados atuais com as decisões;
7. bloqueia candidatos pendentes;
8. aplica as substituições confirmadas;
9. executa o detector principal e o scanner residual independente;
10. compara os resíduos com as rejeições autorizadas;
11. exibe o texto transformado completo e solicita aprovação humana.

Leia o texto inteiro. Digite `s` ou `sim` somente se aprovar a gravação; qualquer outra resposta cancela a exportação.

A saída TXT e o relatório de auditoria JSON são gravados somente após a aprovação final. O CLI cria as pastas de saída necessárias, não sobrescreve arquivos existentes e tenta remover o TXT recém-criado caso a gravação do relatório falhe.

#### Relatório de auditoria

Por padrão, o relatório é gravado no caminho do TXT acrescido de `.report.json`. É possível indicar outro caminho com `--report`:

```bash
npm run dev -- sanitize ./documento-ficticio.docx --review ./datashield-review.json --mode pseudonymize --output ./output/documento.txt --report ./output/auditoria.json
```

O relatório registra metadados, contagens, modo, estado da validação e avisos, sem armazenar os valores detectados nem o texto original.

## Avaliação das métricas

O avaliador utiliza as seguintes definições:

- **TP (verdadeiro positivo):** ocorrência detectada que corresponde ao gabarito.
- **FP (falso positivo):** ocorrência detectada que não consta no gabarito.
- **FN (falso negativo):** ocorrência esperada no gabarito que não foi detectada.
- **Precisão (precision):** TP / (TP + FP). Entre os candidatos detectados, quantos correspondiam ao gabarito?
- **Abrangência (recall):** TP / (TP + FN). Entre as ocorrências esperadas, quantas foram encontradas?
- **F1:** média harmônica entre precisão e abrangência.

O casamento exige a mesma categoria e o mesmo valor normalizado. O avaliador normaliza maiúsculas/minúsculas, acentos e pontuação, mas conta ocorrências repetidas separadamente.

As métricas só são confiáveis em relação a um gabarito completo e corretamente anotado para aquele documento exato. Uma pontuação alta em um único documento sintético não demonstra desempenho equivalente em outros formatos ou documentos.

## Arquitetura

O projeto utiliza uma arquitetura de monólito modular, executada em um único processo Node.js:

- `apps/cli`: interface de linha de comando e orquestração dos casos de uso.
- `packages/core`: contratos, tipos e estruturas compartilhadas do domínio.
- `packages/extractors`: adaptadores de extração de PDF, DOCX e CSV.
- `packages/detectors`: detecção determinística por padrões e contexto, além das métricas de avaliação.
- `packages/sanitizers`: transformação do texto revisado, pseudonimização e validação residual.

Os diretórios `packages/exporters` e `packages/infrastructure` constavam como planejados no desenho inicial, mas não estão implementados.

### Fluxo de dados

```text
Documento PDF / DOCX / CSV
          |
          v
      Extractors
          |
          v
  ExtractedDocument
          |
          v
       Detectors
          |
          v
  Candidatos + offsets
          |
          v
   Revisão humana (CLI)
          |
          v
     Arquivo JSON
          |
          v
      Sanitizers
          |
          v
  Verificação residual
          |
          v
 Aprovação humana final
          |
          v
      TXT + auditoria
```

## Scripts de desenvolvimento

Execute na raiz do projeto:

| Comando | Finalidade |
|---|---|
| `npm run dev -- <comando>` | Executa o CLI em desenvolvimento com tsx. |
| `npm run typecheck` | Verifica os tipos sem gerar arquivos compilados. |
| `npm test` | Executa a suíte de testes uma vez. |
| `npm run test:watch` | Executa os testes em modo de observação. |
| `npm run build` | Compila o projeto para `dist/`. |

## Limitações conhecidas

- As regras contextuais para nomes, endereços, datas/horários e dados operacionais são heurísticas e podem gerar falsos positivos e falsos negativos.
- Nomes em texto livre sem contexto reconhecível podem não ser detectados.
- Padrões de RG e códigos operacionais são pontos de partida configuráveis, não padrões universais brasileiros.
- A identificação de número CNJ verifica apenas o formato visível, não o dígito verificador oficial.
- A validação do CPF verifica dígitos verificadores, mas não confirma atribuição ou situação cadastral.
- A detecção de GPS reconhece um padrão de coordenadas em graus, minutos e segundos (DMS), mas não valida a localização real.
- OCR não está implementado. PDFs digitalizados e texto presente em imagens podem não ser extraídos.
- Imagens incorporadas, comentários, metadados, cabeçalhos, rodapés e outras estruturas do documento não têm extração garantida.
- No DOCX, o extrator recupera texto bruto; não reconstrói a estrutura visual original.
- No PDF, a extração reúne os itens textuais de cada página; a ordem e a disposição visual podem não ser preservadas.
- No CSV, cada linha é serializada durante a extração; offsets referem-se ao texto serializado, não às coordenadas das células originais.
- A exportação gera somente TXT com as seções de texto extraídas. Não reconstrói PDF/DOCX/CSV nem preserva formatação ou metadados.
- O scanner residual é uma salvaguarda adicional, não uma prova de remoção de todos os identificadores.
- Pseudonimização não é anonimização. Os tokens são locais ao documento e não são estáveis entre documentos.
- Relações entre pessoas, apelidos, organizações e siglas são inferências conservadoras baseadas em contexto. Ambiguidades podem permanecer e exigem revisão.

## Princípios de segurança

1. Processamento local por padrão; o fluxo implementado não utiliza APIs externas de IA ou OCR.
2. Não registrar texto original nem valores detectados na saída comum do CLI.
3. Tratar achados como candidatos que precisam de revisão humana.
4. Bloquear exportações com candidatos pendentes e com resíduos não explicados pelas rejeições revisadas.
5. Gerar uma nova saída de texto; não ocultar visualmente informações no documento original.
6. Não confundir pseudonimização com anonimização.
7. Utilizar documentos e dados sintéticos em desenvolvimento, testes e aulas.
8. Não interpretar sucesso da extração como garantia de captura integral do conteúdo.

## Estado do projeto

O DataShield implementa inspeção, extração inicial, detecção, avaliação com gabarito, revisão humana e uma primeira implementação experimental de transformação de texto revisado.

O projeto é destinado a desenvolvimento e educação. Não é um sistema de anonimização certificado nem um fluxo aprovado para documentos reais sensíveis, classificados ou policiais.

Antes de validar qualquer alteração, execute:

```bash
npm install
npm run typecheck
npm test
npm run build
```

## Referências

- [Repositório no GitHub](https://github.com/MichellMelo/datashield)
- [Pull request #1 — melhorias na cobertura de detecção](https://github.com/MichellMelo/datashield/pull/1)
- [Node.js](https://nodejs.org/)
- [Git](https://git-scm.com/downloads)
