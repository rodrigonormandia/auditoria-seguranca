# Auditoria de Segurança

Skill para Claude Code que audita um projeto atrás de falhas de segurança e entrega
um relatório em PDF, em português, com as issues do GitHub já escritas.

---

## O que é

**Auditoria de segurança sob demanda — do código ao relatório executivo, em uma conversa.**

Uma varredura adversarial que lê o seu código de verdade e devolve um dossiê que dá
para levar a uma reunião de diretoria, a um cliente ou a um auditor externo. Não é um
linter nem um scanner genérico: antes de procurar qualquer coisa, ela faz um
reconhecimento — produto, principais, fronteiras de confiança, superfícies de entrada,
stack, arquivos de deploy — e traduz cada categoria de falha para o mecanismo que o seu
projeto de fato usa. Buscar "RLS ausente" num projeto Express é perder tempo; a pergunta
certa lá é outra.

**O que ela procura.** Cinco frentes sempre: dados de um cliente visíveis para outro,
permissão que só existe no navegador enquanto o servidor aceita qualquer um, objetos
acessados por ID sem checar de quem são, chaves e senhas embutidas no código, no CI, no
Docker, no histórico do Git e no bundle que vai para o navegador, e entrada de usuário
renderizada sem tratamento. Mais oito frentes que entram automaticamente quando a stack
pede: SSRF, escalada de privilégio por campo no corpo da requisição, recuperação de
conta e sessão, upload e armazenamento, assinatura de webhook, injeção em SQL e shell,
endpoints caros sem limite, e riscos específicos de IA. E um catálogo de classes de
ataque por domínio — lógica de negócio, abuso de funcionalidade, cadeia de CI/release,
nuvem e containers, isolamento e ciclo de vida dos dados, cliente/navegador, protocolos e
filas, exaustão de recursos, agentes e MCP — que entra quando o reconhecimento encontra a
fronteira correspondente.

**Como ela trabalha.** Monta um mapa de cobertura (superfície × fronteira × classe de
ataque), distribui a caça entre subagentes com prompts estruturados, roda um crítico de
cobertura para achar o que ficou de fora e, antes de qualquer coisa entrar no relatório,
entrega cada candidato a um **painel de três verificadores independentes**, um para alcance,
um para impacto e um para defesas, que tentam refutá-lo. O placar é calculado em código, e quem
verifica nunca é quem achou. Depois, um **revisor de correção** — outro agente — parte do
princípio de que a correção proposta quebra uma regra de negócio: abre a spec, o plano
ou a story da funcionalidade, cita a frase literal de cada regra e reescreve a correção
se ela contrariar o que está documentado (ou a marca como decisão do dono). O validador
confere que cada citação existe no documento; sem essa revisão não sai PDF nem issue. O
resultado se separa em três vereditos que não se
misturam: **confirmado** (rastro completo, resultado observado, severidade), **pendente de
validação** (hipótese bloqueada por um fato fora do repositório — sem severidade, com o
fato exato que falta e como obtê-lo) e **descartado** (refutado; fica registrado para a
próxima rodada não repetir).

**O que você recebe.** Um PDF em português, com capa, escopo, perfil da rodada, commit,
nota metodológica, resumo executivo com gráficos, a lista de achados com severidade,
calibração (probabilidade × impacto × confiança), rastro entrada → destino, causa-raiz
e evidência linha a linha, uma seção de pontos fortes que documenta o que já está
protegido, os pendentes de validação, recomendações priorizadas, o mapa de cobertura com
o status de cada unidade, o apêndice de descartados — e, ao final, cada achado já escrito
como uma issue de GitHub pronta. Se o repositório estiver no GitHub, a auditoria se
oferece para abrir as issues; o time acorda no dia seguinte com o backlog de segurança
montado.

**O que a diferencia.** Todo achado carrega arquivo, linha e trecho — nada de "considere
revisar suas permissões". Antes de propor uma correção, o verificador confronta o achado
com a documentação do projeto e registra se a correção respeita o que está escrito,
contraria uma decisão (e aí é assunto para o dono, não só uma tarefa), já está no
planejamento ou cai num ponto que ninguém documentou. Boa prática ausente sem fronteira
violada é nota de endurecimento, não achado. Quando a exploração depende de uma condição, a condição vem
declarada, inclusive quando ela torna a falha hoje inexplorável. A evidência é conferida no
commit auditado, valor de credencial nunca entra no relatório e todo diretório versionado tem de
estar coberto ou excluído com motivo. Rodada limpa pode ter
zero achados, e o relatório diz isso em vez de inventar achado baixo. Cada registro tem
um `fingerprint` estável, então a segunda rodada reconhece o que carregar, o que
revalidar e o que não repetir — e custa uma fração da primeira.

---

## Como instalar

**Pré-requisitos:** Claude Code (app Windows), **Git** e **Python 3** instalado — é ele que gera o
PDF, num ambiente isolado, sem instalar nada no seu sistema. Para checar, abra o
PowerShell e rode `python --version`; se não responder, instale pela Microsoft Store ou
em python.org. O `gh` (GitHub CLI) é opcional: só é usado se você quiser que a auditoria
abra as issues no repositório ao final.

### Passo a passo

**1.** Salve o arquivo `auditoria-seguranca.zip` em qualquer pasta — Downloads serve.

**2.** Abra o Claude Code no aplicativo Windows. Pode ser em qualquer projeto: a skill
será instalada no seu perfil e passa a valer para **todos** eles.

**3.** Arraste o zip para dentro da caixa de mensagem do chat (ou digite o caminho
completo do arquivo) e envie este pedido:

> Instale esta skill no meu perfil: extraia o zip para a pasta `.claude/skills` do meu
> usuário, de modo que fique `.claude/skills/auditoria-seguranca/SKILL.md`. Depois
> confirme que o SKILL.md está nesse caminho exato.

**4.** A skill fica disponível na hora. Se não aparecer, abra uma conversa nova (a lista
de skills é carregada no início da sessão).

**5.** Teste digitando `/auditoria-seguranca` ou pedindo *"faça uma auditoria de
segurança neste projeto"*.

### Se preferir instalar na mão

Sem passar pelo chat, no PowerShell:

```powershell
Expand-Archive -Path "$HOME\Downloads\auditoria-seguranca.zip" -DestinationPath "$HOME\.claude\skills" -Force
Get-Item "$HOME\.claude\skills\auditoria-seguranca\SKILL.md"
```

A segunda linha é a conferência: se ela imprimir o arquivo, está instalado. Depois é só
abrir uma conversa nova no Claude Code.

### O erro mais comum

Extrair com um nível a mais de pasta, ficando
`skills/auditoria-seguranca/auditoria-seguranca/SKILL.md`. Nesse caso a skill **não é
encontrada**. O `SKILL.md` tem que estar direto dentro de `auditoria-seguranca/`. Se
acontecer, mova o conteúdo um nível para cima — ou peça ao Claude: *"o SKILL.md ficou
aninhado demais, corrija a estrutura"*.

### Instalar só para um projeto

Se preferir que a skill exista apenas num repositório específico (por exemplo, para
versioná-la junto com o time), extraia em `<pasta-do-projeto>/.claude/skills/` em vez da
pasta do usuário. O funcionamento é idêntico; muda só o alcance.

### Desinstalar

Apague a pasta `.claude/skills/auditoria-seguranca` e abra uma conversa nova.

---

## Como usar

No diretório do projeto:

```
/auditoria-seguranca
```

Ou em linguagem natural: *"faça uma auditoria de segurança neste projeto"*, *"procura
falhas de segurança aqui"*, *"quero um relatório de segurança em PDF"*. Pergunta pontual
("este handler tem IDOR?") entra em **modo orientação**: a skill responde usando só a
parte relevante, sem criar arquivos.

Dá para pedir o perfil: *"auditoria rápida"* (uma onda, lacunas ficam adiadas),
*"padrão"* (até o crítico de cobertura não achar lacuna) ou *"profunda"* (unidades por
subsistema e ciclo de vida, segunda passada no que já foi coberto). E o escopo: *"só o
diretório `api/`"*, *"só o que mudou desde a tag v2.3"*.

### O que acontece, em ordem

1. **Preparação** — remote do GitHub, commit auditado, leitura da rodada anterior
   (se houver) e escolha do perfil.
2. **Reconhecimento** — cinco agentes em paralelo mapeiam produto, principais e
   controles, superfícies de entrada e sinks, o que dá para validar localmente e a
   **documentação do projeto** (PRD, épicos, stories, specs, ADRs, planos, issues
   abertas). Saem `reconhecimento.md` e `contexto-produto.md` em `docs/security-audit/`.
3. **Mapa de cobertura** — uma unidade por superfície × fronteira × subsistema × classe
   de ataque. É o que prova, no fim, o que foi e o que não foi revisado.
4. **Caça** — subagentes com prompt estruturado, um por grupo de unidades; cada
   candidato vira um arquivo de rascunho e o agente devolve só o índice. Depois de cada
   onda, um crítico de cobertura procura o que ficou de fora.
   Se o plugin `claude-security` estiver instalado, ele pode entrar como segundo caçador.
5. **Validação adversarial** — cada candidato vai para um painel de três votantes novos. O
   placar é calculado por `apurar_votos.py`, e um relator grava o registro final em
   `registros/<slug>.json`. No perfil rápido, é um verificador só.
6. **Relatório** — `registros/` e `cobertura.json` (dados), `findings.py` (cabeçalho e
   carregador), `validar_findings.py` (consistência) e `gerar_relatorio.py` (layout) em
   `docs/security-audit/`, com venv isolado.
7. **Verificação final** — um revisor por registro checa o que vai impresso. Depois,
   as páginas são rasterizadas e conferidas.
8. **Issues no GitHub** — ao terminar, ela **pergunta** se você quer cadastrar os
   achados na aba Issues do projeto: todas, só críticas e altas, as que você escolher ou
   nenhuma. Nunca cria sozinha. O `abrir_issues.py` monta os textos a partir dos
   registros, não duplica o que já existe, cria os labels que faltam e anota o número de
   cada issue no registro. Em repositório público ela avisa que a issue divulga a falha
   e recomenda não abrir; sem `gh` autenticado, oferece exportar os `.md` para colar à
   mão.
9. **Entrega** — o PDF, a lista de achados e pendentes no chat, o resumo da cobertura e
   o caminho de tudo que foi gerado.
10. **Patches (opcional)** — cada correção é escrita num clone à parte, verificada por um
    revisor que roda os testes e por um atacante, e entregue como `.patch`. Nada é aplicado.

Para revisar só um branch, PR ou commit, peça *"revisão de segurança desta mudança"*: a skill
olha o diff e separa o que a mudança causou do que já existia.

### Regerar o PDF depois

Sem repetir a auditoria — útil ao corrigir um texto, marcar um achado como resolvido ou
anotar o número da issue:

```bash
python docs/security-audit/validar_findings.py
docs/security-audit/.venv/Scripts/python.exe docs/security-audit/gerar_relatorio.py   # Windows
docs/security-audit/.venv/bin/python docs/security-audit/gerar_relatorio.py           # Linux/macOS
```

Se o venv ainda não existir:

```bash
python -m venv docs/security-audit/.venv
docs/security-audit/.venv/Scripts/python.exe -m pip install reportlab matplotlib
```

### Personalizar

O conteúdo vive em três lugares de `docs/security-audit/`; `gerar_relatorio.py` é só
layout e não precisa ser tocado.

Em `findings.py` (cabeçalho):

| Campo | Efeito |
| --- | --- |
| `AUTOR` | Assinatura na capa e no rodapé de todas as páginas |
| `CONFIDENCIALIDADE` | Texto do canto superior direito (padrão: "Confidencial · uso interno") |
| `PERFIL`, `REF_FONTE`, `RODADA_ANTERIOR` | Perfil da rodada, commit auditado e rodada usada como entrada — saem na capa |
| `ISSUES_AGRUPADAS` | Junta achados triviais do mesmo tema numa issue só, para não virar spam no repositório |

Em cada `registros/<slug>.json` (um achado, pendente ou descartado por arquivo):

| Campo | Efeito |
| --- | --- |
| `"veredito"` | `confirmado`, `pendente` ou `descartado` — decide a seção do PDF |
| `"fingerprint"` | Identificador estável da causa-raiz; é por ele que a próxima rodada reconhece o registro |
| `"id": "A3"` | Fixa o número; sem ele, a numeração segue a severidade |
| `"status": "CORRIGIDO em dd/mm/aaaa"` | Marca a correção em verde no relatório |
| `"issue": 624` | Vincula o achado à issue já aberta |

Em `cobertura.json`: o mapa de unidades com status, que vira a seção de cobertura.

Os registros são escritos como **documento de correção** — o controle que falta, onde,
o impacto e a correção, sem passo a passo de exploração — e gravados um por arquivo,
direto pelo agente que os validou. Assim nenhum conteúdo de achado passa por uma escrita
grande, que era o que interrompia a geração do relatório em auditorias com muitos
achados.

Nas próximas rodadas, a auditoria lê os registros anteriores pelo fingerprint, regrava
só o que mudou e roda o gerador. O layout não se mexe, e é isso que torna a segunda
auditoria barata.

---

## O que tem dentro

| Arquivo | Papel |
| --- | --- |
| `SKILL.md` | Modos, princípios, segurança da execução, perfis, o fluxo em 11 passos e os anti-padrões |
| `REFERENCE.md` | Categorias 1-13 por stack, vereditos, escala de severidade (probabilidade × impacto), condições, fingerprint |
| `CLASSES-DE-ATAQUE.md` | Catálogo de classes comuns (injeção, acesso, lógica de negócio, abuso de funcionalidade, encadeamento, curinga, óbvios) e de 10 domínios |
| `PROMPTS.md` | Prompts de reconhecimento, caçador (método, regras, redação, contrato), formato do registro, crítico de cobertura, verificador adversarial e verificação final |
| `assets/gerar_relatorio.py` | Layout do PDF. Não contém conteúdo de auditoria |
| `assets/validar_findings.py` | Validador do conjunto, sem dependência; o gerador o chama |
| `assets/redigir.py` | Detecta e redige valores de credencial |
| `assets/apurar_votos.py` | Calcula o placar do painel de verificação |
| `assets/importar_claude_security.py` | Converte o JSONL do plugin `claude-security` em candidatos |
| `assets/patches.py` | Patches verificados, em clone isolado |
| `assets/findings_template.py` | Cabeçalho dos dados e carregador de `registros/*.json` e `cobertura.json` |
| `assets/abrir_issues.py` | Lista, exporta ou cadastra os achados como issues no GitHub, sem duplicar |
| `assets/dividir_registros.py` | Divide um `findings.py` antigo ou um JSON intermediário em um arquivo por registro |
| `assets/README.md`, `assets/gitignore` | Vão junto para `docs/security-audit/` no projeto auditado |
| `tests/` | Testes da própria skill: `pytest tests` |

Inspirada na metodologia do
[security-audit-skill](https://github.com/cloudflare/security-audit-skill) da Cloudflare
(reconhecimento, mapa de cobertura, validação adversarial, três vereditos, classes por
domínio), adaptada para pt-BR e para o relatório em PDF. O painel de lentes, a revisão de mudança
e os patches verificados vêm do plugin `claude-security`, da Anthropic. Por isso esta skill é de
uso pessoal e não deve ser redistribuída.
