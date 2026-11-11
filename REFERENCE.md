# Referência — categorias, mapeamento por stack, vereditos e severidade

## Como mapear uma categoria para a stack

Antes de procurar qualquer coisa, responda: **qual é o mecanismo desta stack para
isso?** A falha é sempre "o mecanismo existe e não foi aplicado aqui" ou "não
existe mecanismo nenhum". Sem essa resposta, a busca vira grep sem hipótese.

| Categoria | Supabase / Postgres | API própria (Express, Nest, Rails, Django, Laravel) | Firebase |
| --- | --- | --- | --- |
| 1. Isolamento | RLS: tabela sem RLS, RLS sem policy, `USING (true)`, policy que ignora `tenant_id`, função `SECURITY DEFINER` executável por `authenticated` | Filtro manual: `WHERE user_id` / escopo de tenant ausente em listagem, busca, agregação, relatório e exportação | Security Rules com `allow read: if true` |
| 2. Permissão no navegador | A policy de escrita é o guard final — o PostgREST é exposto ao navegador, então Server Action protegida com policy frouxa continua furada | Cada gate de UI (`isAdmin`, `canEdit`) cruzado com o middleware/decorator da rota correspondente | Rules por papel vs. claim custom |
| 3. IDOR | Toda função exportada que recebe id e toca o banco: tem guard de sessão? confere posse? filtra tenant? | Todo handler que lê id de path/query/body | Documento acessado por id sem `request.auth.uid` |
| 4. Chaves | `SERVICE_ROLE_KEY` no cliente, `NEXT_PUBLIC_*` no bundle, `.env` no histórico do git | `${VAR:-default}` em compose/Helm, secrets em CI, credencial default sem validação de startup | `google-services.json` com chave de admin |
| 5. XSS | `dangerouslySetInnerHTML`, markdown sem sanitizar, `javascript:` em href, template de e-mail sem escape | idem + templates do servidor (`\|safe`, `raw`, `html_safe`) | idem |

Quando a categoria não existir na stack (projeto sem frontend, sem banco
multi-inquilino), **diga isso explicitamente** na nota metodológica em vez de
forçar achado.

## Núcleo — as 5 categorias

1. **Banco sem tranca** — identifique primeiro qual é o mecanismo de isolamento e
   aponte onde ele falta ou está furado. Consultas de listagem, busca, agregação,
   relatório e exportação são o ponto cego clássico: o CRUD costuma filtrar, o
   relatório não. Siga também as **cópias derivadas** (cache, índice, export, backup):
   ver "Dados: isolamento e ciclo de vida" no [CLASSES-DE-ATAQUE.md](CLASSES-DE-ATAQUE.md).
2. **Permissão definida no navegador** — catalogue cada gate de papel do frontend
   e cruze com o endpoint. O achado é o par (UI esconde, servidor não confere).
3. **IDOR** — percorra **todos** os handlers, não amostras. Varredura em dois
   níveis: a função e os helpers de autorização que ela chama, senão helper
   correto vira falso positivo e helper decorativo vira falso negativo. Inclua
   operações em lote, import, export e caminhos legados — conferem **por item**?
4. **Chaves expostas** — código, configs, compose, charts, CI, scripts, docs,
   **histórico do git** e **bundle do frontend**. Para segredo no histórico,
   compare o hash do valor vazado com o valor em uso hoje: sem isso não dá para
   afirmar se houve rotação, e é essa comparação que separa "risco histórico" de
   "credencial ativa exposta". Referência a segredo (`${SECRET}`) não é vazamento:
   exija leitor de menor confiança, log, artefato ou fallback inseguro.
5. **XSS** — front (`dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, markdown,
   `javascript:` em href/src, `eval`) e back (input do usuário em HTML de e-mail,
   template ou resposta). Verifique se existe lib de sanitização no projeto e se
   ela é de fato aplicada nos pontos encontrados. Interpolação escapada pelo
   framework não é achado.

## Extras — entram automaticamente quando a stack dispara

Não são opcionais: se o gatilho existe no projeto, a categoria entra na auditoria
e na nota metodológica. Se não existe, a nota registra que não se aplica. O detalhe
de cada uma (disciplina, classes, regras de validação) está no
[CLASSES-DE-ATAQUE.md](CLASSES-DE-ATAQUE.md); aqui fica o gatilho e o resumo.

| # | Categoria | Dispara quando | O que procurar |
| --- | --- | --- | --- |
| 6 | **SSRF** | o servidor busca URL vinda do usuário | webhooks de saída, importadores por URL, proxy de imagem/avatar, previews de link. Sem allowlist de host, IP privado e `169.254.169.254` ficam alcançáveis — inclusive após redirect |
| 7 | **Mass assignment / vazamento na resposta** | ORM ou `update(body)` | `update(req.body)` sem allowlist (mandar `role: "OWNER"` no corpo), `select *` devolvendo hash de senha, PII ou coluna interna |
| 8 | **Autenticação e recuperação de conta** | há login próprio | rate limit no login, token de reset previsível ou sem expiração, sessão que não rotaciona após login/MFA/troca de conta, `redirect` de callback OAuth sem allowlist, `state` solto, JWT sem `aud`/`iss`, enumeração de usuário, confiança em `X-Forwarded-*`/`Host` |
| 9 | **Upload e storage** | existe upload | validação por `Content-Type` em vez de magic bytes, extensão vinda de `file.name`, path derivado de input do usuário (traversal), bucket público, signed URL sem expiração ou válida após mudança de ACL, HTML servido do mesmo domínio (XSS armazenado) |
| 10 | **Webhook e assinatura** | há webhook de entrada | assinatura ausente, comparada com `===` em vez de tempo constante, sem timestamp (replay), segredo global em vez de por-tenant, entrega duplicada sem idempotência |
| 11 | **Injeção além de XSS** | há SQL cru, shell ou template | `query(\`... ${x}\`)`, `child_process` com input do usuário, template server-side com dado não escapado, NoSQL com operador vindo do corpo, injeção por nome de campo/chave/cabeçalho, segunda ordem (dado guardado e usado em outro contexto) |
| 12 | **Rate limit e custo** | há endpoint caro | envio de e-mail/SMS, chamada de LLM, geração de PDF, exportação, regex/parse superlinear, descompressão sem limite: exige impacto em outro usuário, serviço compartilhado ou gasto do operador — limite ausente sozinho é endurecimento |
| 13 | **IA / LLM** | o projeto chama modelo | prompt injection **que cruza fronteira** (contexto de outro principal, autoridade que o solicitante não tem, sink que não alcança direto), contexto montado com dado de outro inquilino, memória envenenada, tool de escrita sem vínculo entre o aprovado e o executado, chave BYOK em log — guardrail em prompt não é controle |

Complementos rápidos, sem virar categoria (ficam em `INFORMATIVOS` quando não há
fronteira violada): cabeçalhos e CORS (`Access-Control-Allow-Origin` refletido com
credenciais, CSP com `unsafe-inline`, cookie sem `HttpOnly`/`SameSite`), CSRF em
stacks sem proteção nativa, dependências (`npm audit`, `postinstall`, action de CI
não fixada por SHA, imagem `latest`), logs que imprimem PII ou segredo, e o checklist
"Óbvios" do CLASSES-DE-ATAQUE.md.

Domínios que a stack pode disparar além dos 13 (CI/release, nuvem e implantação,
cliente/navegador, protocolos e mensageria, desktop/mobile, memória): entram como
categoria extra com número a partir de 14, com entrada própria em `METODOLOGIA`.

## Vereditos

| Veredito | O que exige | Onde fica | Severidade |
| --- | --- | --- | --- |
| **Confirmado** | rastro completo na fonte (entrada → destino), resultado observado, impacto através de fronteira declarada, condições completas, nenhuma camada visível que impeça | `ACHADOS` | sim |
| **Pendente de validação** | hipótese com rastro na fonte, bloqueada por um fato **específico** fora do repositório (proxy, IdP, política do provedor, cabeçalho implantado, ACL de broker); bloqueadores exatos + plano local e/ou de implantação | `PENDENTES_VALIDACAO` | **não** |
| **Descartado** | candidato que a fonte, o comportamento local, um controle visível, a falta de impacto ou um pré-requisito impossível refutam | `DESCARTADOS` | não |
| **Endurecimento** | boa prática ausente sem principal/recurso afetado; a camada A barra, falta a camada B | `INFORMATIVOS` | informativa |
| **Anterior** | só em revisão de mudança: real, mas fonte, destino e controles são iguais antes e depois | `ANTERIORES` | não |

Pendente **não** é "achado de baixa confiança" nem estacionamento de ideia: tem de
nomear fronteira, resultado possível e o fato exato que decide.

## Painel (perfis `padrao` e `profunda`)

Três votantes, um por lente (`alcance`, `impacto`, `defesas`). O placar sai do
`apurar_votos.py`, e o validador recalcula a partir de `votos/`:

| Votos | Resultado |
| --- | --- |
| 2 ou 3 `confirmado` | confirmado |
| 2 ou 3 `descartado` | descartado |
| 2 ou 3 `anterior` | anterior |
| 2 ou 3 `endurecimento` | endurecimento, em `INFORMATIVOS` |
| um voto de cada, com `endurecimento` e sem `pendente` nem `anterior` | endurecimento |
| qualquer outra combinação | pendente |
| falta lente, lente repetida ou voto inválido | incompleto: refaz, nunca decide |

A severidade não passa da mediana dos votos confirmadores (só reduz), e confiança `alta` exige
unanimidade. Importados do plugin passam pelo mesmo painel.

## Severidade (só para confirmados)

Probabilidade × impacto, com âncoras — e a **geral nunca acima do impacto
demonstrado**:

- **Crítica** — ator sem autenticação obtém execução de código, acesso total ao banco
  ou tomada de contas arbitrárias; ou credencial ativa exposta.
- **Alta** — ator derrota por completo um controle explícito com consequência real:
  bypass de autenticação, leitura/escrita cross-tenant, XSS armazenado que atinge
  outros usuários, execução de código autenticada, parada remota de serviço
  compartilhado sem autenticação.
- **Média** — violação real de fronteira com raio limitado, pré-condição incomum ou
  consequência confinada a um conjunto estreito de recursos; ou exploração que depende
  de configuração plausível e próxima.
- **Baixa** — vazamento de interno não secreto, ou efeito que exige esforço sustentado
  por ganho mínimo; defesa em profundidade.
- **Informativa** — observação confirmada de impacto mínimo, útil como pré-requisito
  de um achado maior (vai em `INFORMATIVOS`).

Discriminador alta/média: o resultado demonstrado **derrota** um controle explícito
para uma ação com consequência real, ou só o **enfraquece**? Se não dá para dizer o
dano concreto, a severidade é menor do que parece. Entre dois níveis, fique no menor: um falso
crítico custa mais a quem lê do que uma nota conservadora. Dúvida vai em `confianca`.

Campos opcionais em cada achado: `probabilidade`, `impacto_nivel` (mesma escala) e
`confianca` (`alta|media|baixa`, sobre a evidência, não sobre o risco). Achado crítico
ou alto sem `confianca` e sem `rastro` gera aviso no validador.

**Condições** (`condicao`): declare sempre que houver — nível de autenticação, papel,
interação do usuário, configuração do sistema, roteamento de rede, dependência de
ambiente, estado dos dados, tempo, terceiro. Inclusive quando a condição torna a falha
hoje inexplorável. Achado sem condição declarada vira alarme falso para quem corrige.

## Fingerprint

Identificador estável da **causa-raiz**, igual em todas as rodadas e vereditos:
`caminho/arquivo:escopo:causa` (ex.: `src/api/users.ts:updateUser:mass-assignment-role`),
no padrão `^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`, **sem** linha, onda, agente, severidade
ou veredito. Uma causa que expõe vários caminhos é um candidato com o rastro mais
completo; controles ausentes independentes são fingerprints separados. É pelo
fingerprint que a rodada seguinte reconhece o que carregar, revalidar ou não repetir.

## Contexto do projeto (`contexto_projeto`)

Todo achado e todo pendente é confrontado com a documentação do projeto. Para os
confirmados, a **correção** passa por um revisor independente (passo 5b), que parte do
princípio de que ela quebra uma regra de negócio até ler os documentos. O resultado vai
no campo `contexto_projeto` do registro, **uma entrada por regra**, com `documento`
(arquivo e seção), `trecho` (a frase da regra, literal — o validador confere que está no
arquivo), `relacao` e `nota`. O revisor grava também `revisao_correcao` (documentos que
abriu e regras que conferiu) e, quando há `contraria`, `decisao_necessaria`.

| Relação | Quando usar | Efeito no relatório |
| --- | --- | --- |
| `respeita` | a correção segue o requisito, a regra ou a decisão citada | quem corrige sabe em que se apoiar |
| `contraria` | a correção exige mudar um requisito ou uma decisão documentada | destacado: é decisão do dono antes de virar tarefa |
| `ja_planejado` | há story, épico, issue ou item de plano que cobre o problema | a issue aponta para o trabalho existente, sem duplicar |
| `intencional` | o comportamento é documentado como intencional **e** cruza uma fronteira | achado de desenho: a correção começa pela spec |
| `sem_documentacao` | nenhum documento trata do tema | registra a lacuna (`documento` vazio) |

Comportamento intencional que **não** cruza fronteira de segurança não é achado: o
candidato é descartado e o motivo cita o documento. Documento desatualizado (cita código
que não existe mais) pesa menos que a fonte — diga isso na nota. Nunca cite documento
que não foi lido.

## Regras da auditoria

- Só entra achado **verificado no código real**, com caminho, linha exata, trecho,
  por que é explorável e severidade. Nada de especulação.
- Declare a **condição de explorabilidade** quando houver — inclusive quando ela torna
  a falha hoje inexplorável.
- Registre o que está **CORRETO**, com evidência. É o que prova a cobertura.
- Se uma leitura anterior desta auditoria errou, corrija **dentro do achado**, com
  a evidência nova. Relatório que esconde a própria correção não é auditoria.
- Rodada limpa pode ter zero achados: diga isso e os limites da cobertura, sem
  inventar achado baixo.

## Estrutura do PDF (o gerador cuida do layout)

Capa (título, data, autor, perfil, commit, escopo/stack, nota metodológica) → resumo
executivo (tabela por severidade, pendentes, rosca, barras) → pontos fortes e fracos →
tabela-índice de achados → detalhamento por categoria (com causa-raiz, rastro,
condição, correção) → observações informativas → **pendentes de validação** (sem
severidade; bloqueador e plano) → recomendações priorizadas → **cobertura** (resumo por
status + tabela de unidades) → anteriores à mudança (só em revisão de mudança) → apêndice de
candidatos descartados → issues do GitHub em blocos `--- ISSUE n ---`.

Paleta: crítica `#B91C1C`, alta `#EA580C`, média `#D97706`, baixa `#2563EB`,
informativa `#6B7280`, ponto forte `#059669`, pendente `#7C3AED`.
