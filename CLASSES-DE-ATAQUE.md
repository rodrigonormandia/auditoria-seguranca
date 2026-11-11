# Classes de ataque — comuns e por domínio

Catálogo de hipóteses que a caça percorre. As categorias 1-13 do
[REFERENCE.md](REFERENCE.md) continuam sendo o eixo do relatório; este arquivo é o que
cada caçador recebe para saber **o que procurar** dentro delas e além delas.

Regras de uso:

- As classes comuns entram em toda auditoria. As de domínio entram quando o
  reconhecimento encontra a **fronteira** descrita em "Quando usar" — nunca só porque a
  linguagem ou a dependência aparece no `package.json`.
- Ao delegar a um subagente, copie o bloco inteiro no prompt (disciplina + classes +
  regras de validação). Nome de bloco sozinho não orienta ninguém.
- Cada unidade do mapa de cobertura aponta o bloco que a cobre, no formato
  `CLASSES-DE-ATAQUE.md#Nome da classe`.
- Veredito: **confirmado** só com rastro completo na fonte e resultado observado;
  **pendente de validação** quando um fato de implantação, provedor, navegador ou
  identidade decide e não está na fonte; **descartado** quando a fonte refuta.
- Nada aqui autoriza explorar além do mínimo: o objetivo é provar que a invariante
  falha, não desenvolver cadeia de exploração.

---

## Classes comuns (toda auditoria)

### Injeção
Siga a entrada não confiável da porta de entrada ao sink perigoso. O sink depende do
alvo: web (SQL, HTML, shell, template, caminho de arquivo, redirect, desserialização);
biblioteca (qualquer função que processa dado do chamador sem validar); CLI (montagem de
comando, caminho, interpolação de env); serviço (consulta, serialização de mensagem,
injeção em log, LDAP/XPath). Não pare no caminho direto: procure injeção **indireta**
(dado guardado com segurança e usado depois em outro contexto), por **nome de campo,
chave, cabeçalho e metadado** — não só por valor — e em **sistemas secundários** (log,
cache, índice de busca, analytics).

### Controle de acesso
Não basta ver que existe verificação: ela confere a permissão **certa** para o recurso
**certo** pelo mecanismo **certo**?
- Há outro caminho para a mesma mudança de estado com uma permissão mais fraca?
- Um campo no corpo da requisição sobrepõe o que o sistema de permissão restringiu?
- Endpoint que autentica mas esquece de autorizar?
- O mesmo recurso tem vários caminhos de acesso com verificações inconsistentes?
- Operações em lote, importação e exportação conferem permissão **por item**?
Modelo complexo: separe "bypass de autenticação" de "lógica de autorização".

### Recursos e arquivos
Path traversal (inclusive por symlink, sequência codificada, byte nulo); SSRF (inclusive
por redirect, DNS rebinding, diferença entre parsers de URL); desserialização insegura,
extração de arquivo (zip slip), arquivo temporário; condição de corrida entre
verificação e uso (TOCTOU).

### Criptografia e segredos
Aleatoriedade fraca em token, chave ou nonce; segredo em código, log, erro, URL ou
resposta visível ao cliente; derivação de chave quebrada, HMAC sem verificação, nonce
reutilizado; comparação de segredo sem tempo constante; primitiva mal usada (ECB, IV
fixo, cifra sem autenticação); e **o que acontece quando a operação criptográfica
falha** — o erro cai em "sem cripto"?

### Lógica de negócio
Scanner não acha; é caça manual, e rende achado de alto impacto. Por fluxo principal:
- **Máquina de estado:** dá para pular etapa, voltar, atingir estado inválido, repetir
  fluxo concluído? Falha parcial (etapa 2 de 3 falha) desfaz a etapa 1?
- **Corrida com impacto de negócio:** operações concorrentes que produzem estado
  inválido (gasto duplo, aprovação dupla, atualização perdida); foco em check-then-act
  não atômico.
- **Quantidade e número:** negativo, zero, overflow, perda de precisão, coerção
  string↔número.
- **Fronteira de acesso:** não "a verificação existe", mas "é a verificação certa para a
  regra de negócio"; a entrada de uma operação burla a restrição de outra com o mesmo
  efeito?
- **Confiança implícita:** dado de storage, config, outro componente ou plugin tido como
  seguro porque "foi validado na entrada" — e se outro caminho gravou?
- **Tempo:** expiração, agendamento, janela de rate limit, deriva de relógio, fuso
  diferente entre componentes, o instante exato da fronteira.
- **Default e fallback:** postura quando a config falta, a flag está desligada, a
  dependência cai, o sistema está no meio de uma migração.

### Abuso de funcionalidade e vazamento
Funcionalidade legítima usada para fim não previsto — defeito de desenho, não só de
código:
- **Exportação/backup como exfiltração:** usuário de baixo privilégio dispara export,
  snapshot ou backup com dado acima do seu acesso, de outros usuários, apagado,
  rascunho ou privado; histórico de revisões que devia ter sido podado.
- **Importação/restore como injeção:** import sobrescreve dado existente, cria registro
  que burla validação, injeta em coleção sem permissão de escrita, ignora o modelo de
  permissão da UI.
- **Busca/filtro/ordenação como oráculo:** a busca revela que existe conteúdo que o
  usuário não pode ler; filtro sonda status, papel ou campo oculto; ordenar por campo
  escondido vaza o valor pela ordem.
- **Enumeração por efeito colateral:** mensagem, tempo, tamanho ou status diferentes
  entre "não existe" e "sem acesso"; enumeração de usuário por reset, convite ou
  cadastro.
- **Preview/rascunho/staging:** token de preview que abre mais que um item; rascunho
  descoberto por busca, RSS, sitemap ou listagem da API; cabeçalho de cache que faz o
  CDN servir conteúdo privado.
- **Notificação/webhook como SSRF:** URL de callback definida pelo usuário e buscada
  pelo servidor sem validar rede interna — inclusive depois de um redirect.

### Encadeamento e segunda ordem
Comportamento permitido ou contido vira vulnerabilidade quando outro componente ou etapa
confia numa garantia mais forte:
- **Falha em várias etapas:** mapeie o que o principal de baixo privilégio pode ler,
  gravar, invocar e reter; ligue só saídas concretas a decisões posteriores; confirme
  cada pré-requisito, nunca presuma o efeito seguinte.
- **Lacuna entre componentes:** A valida e passa a B — compare a garantia exata que A
  produz com o que B assume (truncamento, coerção, normalização, escopo de tenant).
- **Uso de segunda ordem:** nome de campo vira JSON path, slug vira caminho, texto
  escapado entra em renderização crua, string gravada vira URL, regex, template ou
  expressão de política.
- **Crescimento de escopo:** token, API key, plugin, OAuth ou capacidade de agente que
  alarga após delegação, refresh, cache, troca de papel ou composição; nomeie a operação
  concreta que o principal resultante não deveria ter.
- **Ordem e tempo:** setup, migração, soft-delete, expiração de cache de revogação,
  janela entre validar e consumir; confirme que o estado antigo é aceito antes de
  reportar.
- **Rollback e recuperação:** undelete, restore, reversão de revisão e cancelamento têm
  de aplicar posse, validação e autorização **atuais**.

### Curinga
Sem categoria. Leia o código que parece chato ou desligado de segurança; siga o
inacabado, o experimental, o de compatibilidade e o fallback, com a mesma exigência de
fronteira concreta:
- Qual é o código mais estranho do repositório? Por que existe? O que acontece se for
  abusado?
- Funcionalidade meio pronta ou "pendurada" — teve menos revisão.
- O que acontece ao usar a API de um jeito que o frontend nunca usaria? Que chamadas são
  possíveis mas o cliente nunca faz?
- Endpoint, parâmetro, cabeçalho ou feature escondido (registro de rotas, middleware,
  config) fora da documentação.
- Misturar features que não foram desenhadas juntas: localização + preview + cache;
  import + plugin + webhook; OAuth + impersonação + API key.
- Histórico do git: correção de segurança revertida, verificação comentada, segredo
  commitado e removido.
- Que ações de conta válida afetam outros usuários, integridade compartilhada,
  disponibilidade ou custo do operador? Há contenção, cota, autorização e recuperação?
- Operações irreversíveis ou que exigem confirmação elevada: autorização e aprovação
  presas ao principal, à ação e ao recurso **finais**?
- Suposições sobre o ambiente: banco local, relógio certo, DNS confiável, sistema de
  arquivos sensível a maiúsculas.
- Testes: o que **não** está testado? Compare os casos de borda que o autor pensou (há
  teste) com os que não pensou.
Se algo parece estranho, leia até conseguir afirmar se é seguro. Comentário que explica
por que é seguro: verifique a explicação. Variável `temp`, `hack`, `legacy`: leia de
perto.

### Óbvios (checklist literal)
Outros agentes caçam o sutil; este confere o básico que todo mundo assume que alguém já
viu. Não precisa ser criativo, precisa ser **completo e literal** — cada item, um
resultado:
- Senha, API key, token ou segredo no código (`password`, `secret`, `apikey`, `token`,
  `Bearer`, `-----BEGIN`, senhas default conhecidas).
- `TODO/FIXME/HACK/XXX` que mencionam segurança (`TODO: add auth`, `HACK: skip
  permission check`).
- Modo debug/dev bem fechado? Dá para ligar em produção por env, query ou cabeçalho?
- Credencial de teste/exemplo/seed que funciona em produção.
- `/debug`, `/admin`, `/test`, `/status`, `/health`, `/metrics`, `/env`, `/.env`,
  `/config` sem proteção.
- `.env`, `credentials.json`, `*.pem`, `*.key` versionados; o `.gitignore` cobre
  segredos, uploads e config local?
- Dependências fixadas? CVE conhecida na árvore (lockfile)?
- `eval`, `exec`, `child_process`, `Function()`, `vm.runInContext`, `import()` com
  entrada dinâmica.
- CORS `*` ou permissivo demais; `Allow-Credentials` com origem curinga.
- Cookie sem `HttpOnly`, `Secure`, `SameSite`.
- Open redirect (`redirect`, `return`, `next`, `url`, `goto`, `continue` sem validar).
- TLS obrigatório? Endpoint só-HTTP?
- Erro em produção devolvendo stack trace, caminho interno ou erro de SQL.
**Importante:** um sinal não é achado. Cookie sem `HttpOnly`: o cookie carrega dado
sensível? O JS precisa lê-lo por desenho? Campo em mensagem de erro: ele chega a conter
dado sensível? Rastreie o impacto antes de reportar.

---

## Domínios — entram quando o reconhecimento encontra a fronteira

| Domínio | Quando usar |
| --- | --- |
| Web, HTTP e autenticação | app web, API, proxy reverso, CDN, gateway, parser HTTP próprio, sessão, CSRF, JWT, OAuth/OIDC, SAML, MFA, passkey, recuperação de conta, API key, mTLS |
| Cliente e navegador | SPA, extensão, webview, service worker, storage do navegador, `postMessage`, CORS, WebSocket, renderização no DOM |
| Dados: isolamento e ciclo de vida | store multi-inquilino, cache/busca derivados, link de objeto, export/backup, migração, exclusão, retenção, restore |
| Nuvem e implantação | IAM, infra como código, container/Kubernetes/Swarm, service mesh, serverless/edge, ingress, evento de provedor, config por ambiente |
| Cadeia de suprimentos e release | resolução de dependência, CI, build de contribuição externa, artefato de release, assinatura, atualizador, plugin |
| Protocolos, RPC e mensageria | gRPC, GraphQL, Protobuf/Thrift, protocolo próprio, fila, broker, pub/sub, webhook, RPC em stream |
| Exaustão de recursos | trabalho não confiável que consome CPU, memória, disco, conexão, worker, fila, cota ou gasto do operador |
| IA, LLM e agentes | chatbot, RAG, memória persistente, agente com ferramentas, servidor/cliente MCP, prompt montado com entrada do usuário, ação dirigida por modelo |
| Desktop, mobile e IPC local | app nativo, deep link, ponte de webview, componente exportado, helper privilegiado, daemon local, socket Unix/XPC/Binder/D-Bus |
| Memória e binários | C/C++/Rust `unsafe`, módulo de kernel, parser/decoder, FFI, loader binário, JIT, firmware |

---

### Web, HTTP e autenticação

**Disciplina (copiar no prompt):**
- Achado de framing ou cache exige **duas interpretações** da mesma requisição, resposta
  ou chave: nomeie os dois componentes e o valor normalizado de cada lado.
- Para cada credencial, ache a verificação de assinatura/segredo e **cada vínculo** que o
  papel dela exige: emissor, audiência, origem, RP, cliente, sessão, principal, recurso,
  nível de garantia, expiração, estado de uso único.
- `Host`, `Forwarded`, `X-Forwarded-*`, `Origin`, `Referer`, destino de redirect,
  `state` de callback e URL derivada da requisição são decisões de confiança: rastreie
  cada uma até a identidade ou resposta afetada.
- Cabeçalho, atributo de cookie, prompt de MFA ou rate limit ausente **não é achado
  sozinho**: exige requisição inválida aceita, impacto em outro principal, rebaixamento
  de garantia ou vazamento de credencial.
- Confirmado só com fonte completa e teste local limitado de requisição/token; pendente
  quando proxy, IdP, navegador, certificado, segredo ou config implantada decide e não
  está visível.

**Framing e cache:** request smuggling/desync (vários `Content-Length`,
`Transfer-Encoding`, downgrade de HTTP/2-3, normalização de nome de cabeçalho, CR/LF);
cache poisoning por entrada fora da chave (host/esquema encaminhado, cookie, query,
idioma/dispositivo, estado de autorização); cache deception (caminho privado tratado
como estático; normalização de sufixo); confiança em `Host`/`X-Forwarded-*` para URL
absoluta, roteamento de tenant, link de reset, IP do cliente; injeção em cabeçalho de
resposta (`Location`, `Set-Cookie`, CSP).

**Sessão no navegador:** CSRF comum (toda mutação autenticada por cookie: form, JSON,
multipart, override de método, rota legada; `SameSite` só vale para o cookie e contexto
realmente usados; login CSRF); fixação e invalidação (ID de sessão não rotaciona em
login, troca de conta, MFA, impersonação; continua válido após logout, troca de senha,
revogação, conta desativada — sessão no servidor, refresh token, cookie assinado,
websocket, cache); escopo e transporte de cookie (`Domain`/`Path` largo, transporte
inseguro, cookie irmão escolhido por outro componente).

**Identidade federada:** primeiro defina o papel — controle de servidor de autorização
(allowlist de redirect, emissão de code) não pertence ao cliente relying-party. JWT:
verificação de assinatura, algoritmo e fonte de chave fixados no servidor, depois `exp`,
`nbf`, `aud`, `iss`; `kid`/`jku`/`x5u` como seletores não confiáveis; caminho que
decodifica sem verificar; token válido para outro serviço é inválido aqui. OAuth/OIDC:
`redirect_uri` exato (no AS), `state` preso à sessão, PKCE, vínculo do code, ID token
(iss/aud/assinatura/nonce), IdP selecionado em fluxo multi-provedor; compare callback
inicial, retry, deep link mobile e vínculo de conta. SAML: o elemento cuja assinatura é
validada é o elemento usado como identidade? caminhos sem assinatura, parser XML seguro,
canonicalização, janela de validade, audiência/destinatário, correlação, replay.

**MFA, passkey e transição de conta:** inscrição e rebaixamento (inscrever, substituir,
desativar fator, gerar código de recuperação, criar dispositivo confiável exigem a
garantia prévia; fator desativado para de autorizar?); step-up preso à sessão, conta,
tenant, ação e expiração, com rota alternativa (API, lote, recuperação, fluxo retomado)
que omite a checagem; WebAuthn (challenge, RP ID, origem, credencial, userHandle,
algoritmo, verificação de usuário presos à sessão que iniciou; confusão credencial→conta
em descoberta/vínculo); vínculo de conta (adicionar IdP, passkey, e-mail, telefone,
dispositivo exige sessão atual, posse verificada da nova identidade, step-up, `state`
preso à conta); reset de senha e recuperação em geral (aleatoriedade, vínculo
usuário/ação, expiração, uso único, rate limit, confiança na URL de entrega,
invalidação de tokens e sessões anteriores).

**API key e mTLS:** chave com escopo maior que o registro no servidor (tenant, recurso,
ação, ambiente) ou parâmetro que sobrepõe o vínculo; lookup por prefixo, confusão
publishable×secret, rotação, cache de revogação, endpoints em lote; chave em bundle,
URL, redirect, log, erro, artefato de build (identificador público chamado de "key" não
é segredo — confirme o tipo e a autoridade); mTLS: cabeçalho de identidade de
certificado aceito de qualquer peer, subject mapeado para conta de forma influenciável,
certificado do domínio de confiança errado; proxy que termina mTLS tem de ser o único a
conectar e remover cabeçalhos de identidade de entrada; fallback silencioso para bearer
ou anônimo quando o certificado expira/falha; conexão pooled que retém autorização após
revogação.

**Movimentos universais:** percorra emitir → guardar → transmitir → consumir → renovar →
revogar para cada credencial e challenge, nos caminhos normal, erro, retry, migração,
legado e troca de conta. Enumere **toda porta** para a mesma identidade e **toda rota**
para a mesma operação sensível: a política efetiva é o caminho paralelo mais fraco.
Compare normalização de parser, proxy, roteador, cache e aplicação lado a lado com o
mesmo fixture, nunca com tráfego para a implantação.

**Validação:** (1) proxy, chave de cache do edge, política do IdP, confiança de
certificado, comportamento de cookie do navegador, segredos e modo de auth implantado
podem estar fora do repositório — registre pendente preciso em vez de afirmar; (2)
framing/cache: nomeie os dois componentes e a divergência, prove impacto entre
requisições/usuários com fixture local; (3) token/MFA/passkey/vínculo/recuperação/API
key/mTLS: cite a linha de verificação e o vínculo ausente, prove que o servidor aceita a
transição inválida; (4) CSRF: credencial ambiente, rota que muda estado, forma da
requisição cross-site aceita, política de cookie, checagem ausente — ação só-leitura e
rota com bearer não ambiente não contam; (5) verifique defaults do framework na versão
fixada; versão desconhecida → pendente, nunca "confirmado em severidade menor".

---

### Cliente e navegador

**Disciplina:**
- Candidato precisa de **fonte controlável** e **sink que executa ou revela**; mostre o
  dado influenciado chegando ao sink.
- O impacto tem de alcançar a sessão de uma vítima, outra origem ou persistência
  compartilhada. Auto-injeção e vazamento do próprio dado não são achado.
- Escape do framework, same-origin policy, CSP, COOP/CORP, escopo de service worker e
  `noopener` implícito são controles reais: verifique antes de atribuir impacto.
- Storage e cache são por origem e sobrevivem ao logout: quem grava, quem lê, que ciclo
  (conta, tenant, worker) limpa cada registro.
- Confirmado só com fonte completa e teste local no navegador; pendente quando renderer,
  permissão de extensão, cabeçalho implantado ou política do navegador decide.

**DOM e estado de objeto:** XSS baseado em DOM (`location`, `document.referrer`,
`window.name`, dado de mensagem, storage → `innerHTML`, `outerHTML`, `document.write`,
API que avalia string, URL executável, API HTML do jQuery, escape hatch do framework;
interpolação escapada não é achado); DOM clobbering (`id`/`name` injetado que sombreia
global, propriedade de form, objeto de config ou flag de inicialização usados depois —
exige markup que preserva o atributo **e** uso relevante); prototype pollution com
gadget (chave controlada chega a deep merge ou atribuição por caminho **e** um gadget
alcançável consome a propriedade — `JSON.parse`, cópia rasa ou poluição sem gadget não
bastam).

**Mensageria e rede entre origens:** `postMessage` sem allowlist exata de origem (e
`event.source` quando frames compartilham origem); envio sensível para `*`; match de
origem por substring/prefixo/sufixo/regex sem âncora não é checagem; WebSocket que
aceita cookie ambiente de origem não confiável sem checar `Origin` ou token do canal
(exige handler de mensagem relevante); CORS com credencial que reflete ou casa `Origin`
fracamente e devolve resposta sensível (curinga + credencial o navegador rejeita;
reporte só o caminho de origem realmente refletida).

**Service worker e storage:** registro/escopo tomado por conteúdo influenciável (URL
final do script, MIME, origem, `Service-Worker-Allowed` largo, import sem integridade);
cache do worker sem conta/tenant/estado de autorização/modo na política, servido após
troca de conta ou logout (rotas de fetch, nomes e chaves de cache, fallback de
navegação, limpeza, caminho offline/erro); token, resposta privada ou decisão de
autorização em `localStorage`/`sessionStorage`/IndexedDB/Cache Storage/storage de
extensão legíveis por outra conta ou componente same-origin de menor confiança, ou
usados após revogação (guardar token sozinho não é achado); `storage` event,
`BroadcastChannel`, shared worker levando identidade ou comando entre abas sem prender à
sessão atual (troca de conta, janela privada, aba velha sobrescrevendo auth nova).

**Vazamento entre sites:** XS-Leaks (eventos de load/error, estado de frame/janela,
redirect, tempo, cache, tamanho de resposta distinguindo estado protegido com credencial
da vítima — exige um predicado concreto com segredo; variância genérica não conta);
metadado de janela cross-origin ou relação `opener`/janela nomeada que revela estado ou
influencia navegação privilegiada (COOP, proteção de frame, `noopener`, origem exata).

**UI redress e navegação:** clickjacking (ação que muda estado, emoldurável, sem
`frame-ancestors`/`X-Frame-Options` efetivo — confirme que a ação completa emoldurada;
só-leitura é endurecimento); navegação controlada pelo cliente sem política de esquema e
destino (`javascript:`, `data:`); reverse tabnabbing só onde o código mantém
`window.opener` explicitamente, usa `window.open` sem isolamento ou suporta navegador
sem `noopener` implícito.

**Movimentos universais:** comece pelos sinks (DOM, navegação, worker, mensagem,
storage) e volte às fontes só-navegador e controladas pelo servidor; registre a política
que deveria barrar o caminho. Teste troca de conta, logout, update do worker, fallback
offline e aba velha numa origem local com contas fictícias.

**Validação:** cite fonte, sink, política do navegador, origem/sessão afetada e mutação
ou vazamento observável; prototype pollution exige escrita recursiva **e** gadget; DOM
clobbering exige markup que sobrevive **e** valor sombreado usado; service worker e
storage exigem alcançabilidade de ciclo (escrita ou cache do atacante chegando a outra
conta/tenant/estado); mensageria, CORS, WebSocket e XS-Leaks: mostre a validação exata
de origem/fonte e o estado protegido exposto, e confirme que CSP, COOP/CORP, cookies e
SameSite ainda não barram.

---

### Dados: isolamento e ciclo de vida

**Disciplina:**
- Campo `tenant_id`/`owner_id` no registro **não é isolamento**: ache a query, chave,
  caminho, política ou RLS que o impõe em cada leitura e escrita.
- Siga as **cópias derivadas**: dado primário sanitizado pode virar inseguro em busca,
  cache, analytics, export, preview, log, réplica e backup, com ACL e retenção
  diferentes.
- Exclusão e revogação são contratos de ciclo de vida: confira cópia atual, histórica,
  em cache, indexada, exportada, restaurada e enfileirada, dentro da fronteira que o
  produto promete.
- Preferência de privacidade/retenção não é automaticamente vulnerabilidade: exija
  fronteira explícita de acesso ou garantia de exclusão/revogação **e** um leitor ou
  operação não autorizados.
- Confirmado com linhagem completa na fonte e teste com dois tenants fictícios; pendente
  quando política externa de storage, retenção, CDN, atraso de réplica ou acesso a
  backup decide.

**Isolamento de tenant e objeto:** read/update/delete/list/count/bulk que identificam o
objeto sem prender ao tenant/dono autenticado ou que aceitam o tenant pelo corpo
(compare lookup direto, relação aninhada, job em background, admin, import, legado);
colisão de chave composta/namespace (chave de cache, caminho de objeto, unicidade no
banco, ID de documento de busca, arquivo temporário, dedup sem tenant/ambiente);
desacordo entre política e query (RLS, escopo default do ORM, filtro de autorização e
cliente cru/`unscoped`/service role aplicando predicados diferentes — joins, agregados,
views, transações, caminhos de erro sem contexto); referência a blob/URL assinada que
permite operação ou namespace além do emissor ou que continua válida após mudança de
ACL (prenda operação, objeto/versão exatos, audiência, expiração, tenant).

**Dado derivado e vazamento:** ACL do registro muda sem invalidar cópia pesquisável, em
cache, embedding, thumbnail, RSS, preview ou índice (filtrar na recuperação, não só na
ingestão); analytics, log, trace e diagnóstico como leitores alternativos com acesso mais
amplo, retenção mais longa ou mistura de tenants (confirme a classe de dado e o leitor
realista); oráculos de enumeração e agregado (contagem, filtro, ordenação, erro,
constraint única, tempo, notificação, existência) — exija predicado confidencial
concreto.

**Export, backup, restore e migração:** export/snapshot/relatório/backup com outros
tenants, campos inacessíveis, soft-deleted, segredos ou histórico acima do acesso
(autorização por item **após** a seleção e autorização para baixar o artefato final);
import/restore que burla dono, schema, ACL, unicidade ou validação, sobrescreve ou
recria em tenant onde o solicitante não escreve (arquivo é entrada não confiável;
autorize a operação resultante, não a procedência); migração com registro antigo sem
tenant/ACL, colisão de ID, rollout parcial com defaults diferentes entre leitor novo e
velho (backfill, dual-write, rollback, migração retomada); backup/réplica com chave,
conta de storage, região ou ambiente de restauração de escopo mais amplo que o primário.

**Exclusão, revogação e ciclo:** bypass de soft-delete/tombstone (lookup direto, busca,
travessia de relação, link de objeto, processador em background ou restore ignorando o
predicado; identificador soft-deleted re-registrável antes de sumirem as referências);
autorização velha em cópia derivada (remoção de membro, mudança de ACL, retirada de
consentimento, revogação de segredo, rebaixamento de papel que não invalida sessão,
cache, assinatura, job ou dado materializado); trabalho enfileirado que recria ou retém
dado após a exclusão primária (processador, retry, export, analytics, artefato gerado —
exclusão idempotente e propagação de tombstone); restore que reintroduz dado,
credencial, membro ou permissão que a política atual não permite.

**Movimentos universais:** escolha um registro protegido e desenhe escrita primária,
query, cache, índice, evento, export, backup, exclusão e restore, marcando principal e
tenant em cada aresta. Compare dois tenants fictícios pelos mesmos métodos de serviço,
depois repita após mudança de ACL, exclusão, troca de conta e restore. Comece pelos
clientes de bypass, jobs em background, migrações, unicidade global e chaves de cache —
são os caminhos que costumam omitir a identidade da requisição.

**Validação:** nomeie atacante, dado/estado protegido, dono/tenant afetado, cópia ou
operação alternativa e vazamento/mutação não autorizados; cite a política fonte da
verdade **e** o caminho que a omite, confirmando que outra camada não impõe a mesma
condição; prove com tenants fictícios e pare no mínimo observável; cache, storage de
objeto, réplica, analytics, backup ou retenção externos → pendente com a verificação que
o dono deve fazer.

---

### Nuvem e implantação

**Disciplina:**
- **Manifest não é exposição viva.** Estabeleça qual ambiente o consome, que defaults ou
  overlays o modificam e se o caminho está ativo.
- Mapeie a identidade de cada workload para operações e recursos específicos. Política
  larga só é achado quando entrada de menor confiança alcança ação não autorizada.
- Ingress, proxy, mesh, serviço de metadata e admission são fronteiras reais, mas só
  contam quando a configuração **e o acoplamento** estão visíveis.
- Referência a segredo não é vazamento de segredo: exija leitor de menor confiança,
  saída, artefato, log ou fallback inseguro.
- Confirmado para configuração ativa no repositório e renderização/política validadas
  localmente; pendente para política de conta, acoplamento de rede, admission em
  runtime, metadata hospedado ou drift que exige observação do dono.

**Identidade de workload e IAM:** workload/pod/função/edge worker/nó que age sobre
tenants, contas, recursos ou APIs além do papel, com entrada não confiável escolhendo o
alvo (condições de política, padrões de recurso, service account, mapeamento de
namespace, credencial de fallback); assunção de papel, external ID, troca de token,
federação ou política de recurso aceitando claims não presos à conta/audiência/repo/
namespace/workload de origem; aplicação que confia em cabeçalho de identidade, tag,
label, account ID ou metadado fornecidos pelo chamador sem provar que vieram do control
plane ou de proxy confiável (IAM e autorização da aplicação são checagens separadas).

**Ingress, rede e control plane:** ingress, service, listener, security group, anotação
de LB, mapeamento de porta ou bind que expõe admin, debug, métricas, nó, control plane
ou API interna a rede de menor confiança (rota pública controlada pelo repositório para
handler sensível pode ser confirmado; controle de rede ausente é pendente); backend que
aceita identidade encaminhada, subject mTLS ou metadado de autorização de peer fora do
ingress/sidecar previsto, ou porta/caminho alternativo que burla o mesh (strip de
cabeçalho, alcance do peer, fail-open sem proxy); URL, destino ou protocolo não confiável
alcançando metadata de instância, socket do control plane ou API interna com credencial
do workload.

**Container e orquestração:** workload de menor confiança que escolhe privileged,
capabilities, namespaces do host, host path, device, socket do runtime ou token de
service account cruzando para autoridade de nó/control plane (ausência de seccomp ou FS
read-only é endurecimento, salvo operação que cruza a fronteira); uma rota de deploy
impõe identidade de imagem/namespace/recurso/segredo/privilégio e outra (controller,
job, upgrade, restore, compatibilidade) não; política que depende de label, anotação,
nome ou namespace que um principal menos confiável define.

**Configuração e ciclo de segredo:** precedência que desliga controle (valor de dev,
default de chart, env, flag de CLI, feature gate, injeção de sidecar, overlay por região
desligando autenticação, TLS, escopo de tenant ou auditoria no ambiente implantado —
renderize a configuração **final** de cada ambiente mantido); segredo em log, crash
report, argumento de processo, env compartilhado, volume largo, saída de build, service
discovery ou API de leitura acessível a outro workload/tenant (endpoint público ou key ID
não é credencial); falha em montar, renovar, rotacionar ou revogar credencial que deixa
credencial velha ativa ou cai em modo de identidade menos confiável (startup, readiness,
reconnect, cliente em cache).

**Storage gerenciado, eventos e edge:** política de bucket, chave de objeto, origem de
CDN ou URL assinada que não prende principal, operação, namespace, audiência ou
expiração (inclua list/versions e escrita); função/worker que confia em campos do corpo
do evento como identidade de origem sem validar envelope assinado pelo provedor,
subscription/tópico, conta, região e replay (push, pull, retry, dead-letter); runtime de
edge/serverless que assume segredo, API, FS, isolamento ou política de tenant diferentes
da origem, com fallback para a origem mudando autoridade ou cache.

**Movimentos universais:** renderize cada ambiente mantido e monte a matriz porta
externa × identidade do workload × peers de rede × segredos montados × recursos de
nuvem; diferença exige explicação de política ou do dono. Siga uma requisição, objeto,
label ou evento de menor confiança até a política de nuvem e mostre qual credencial de
workload executa a operação final e que condição deveria restringi-la. Faça diff entre
deploy normal, migração, restore, manutenção de nó, failover e caminho local/emulador;
avalie o comportamento quando mesh, admission, identidade, segredo ou serviço de
política estão indisponíveis.

**Validação:** estabeleça o caminho ativo e o objeto implantado efetivo, senão pendente
com o manifest renderizado ou o acoplamento que falta; nomeie chamador/workload de menor
confiança, identidade, seletor controlável, recurso e operação/vazamento não autorizados;
verifique defaults do provedor/orquestrador na versão fixada (não assuma IP público,
metadata alcançável, firewall permissivo ou admission ausente); validação local pode
renderizar template, avaliar política, inspecionar namespaces em fixture isolado ou rodar
emulador com identidades fictícias — nunca sondar endpoint vivo nem alterar recurso
compartilhado.

---

### Cadeia de suprimentos, CI e release

**Disciplina:**
- Dependência mutável ou com CVE **não é achado sozinha**: mostre quem influencia a
  resolução, que build a consome e que fronteira de execução ou release vem depois.
- Siga a integridade em cada passagem: identidade da fonte, entradas resolvidas, worker
  de build, identidade do artefato, resultado de teste, assinatura/attestation,
  promoção, consumidor do update.
- **Configuração de CI é código de autorização.** Que evento disparou, código de quem
  roda, que segredos e tokens existem, o que pode publicar ou mutar.
- Checksum buscado do mesmo lugar não confiável que o artefato não prova integridade
  independente. Identifique a raiz de confiança e o comportamento em falha.
- Confirmado para falha de fluxo dentro do repositório com validação local; pendente
  para branch protection, runner hospedado, registry, serviço de assinatura ou promoção
  de produção não observáveis.

**Dependência e entrada de build:** confusão de fonte/namespace (registry de fallback,
mirror, prioridade de fonte, lockfile e checksum, build file alternativo, resolução por
plataforma, primeira instalação × update); entradas mutáveis (branch, tag, submódulo não
verificado, ferramenta baixada, asset gerado, include remoto, action de CI flutuante,
tag de container — exija escritor de menor confiança e caminho até a saída confiável;
reprodutibilidade não prova autenticidade); fonte gerada/codegen sem a mesma revisão e
integridade (schema, vendored, cliente gerado, localização, exemplo de doc, blob
binário); inclusão de contexto de build (segredo, config local, metadado do repositório,
fixture, artefato de dev entrando em pacote/imagem por `.dockerignore` frouxo — confirme
que o artefato expõe credencial real).

**CI e automação:** código não confiável em workflow privilegiado (PR, comentário de
issue, fork, update de dependência, evento externo rodando código do contribuidor com
segredos protegidos, token de escrita, autoridade de deploy ou runner confiável —
compare tipo de trigger, ref do checkout, gate de aprovação, proteção de environment,
estreitamento de permissão; não assuma defaults do host que não estão na fonte);
injeção por nome de branch, mensagem de commit, campo de issue, nome de artefato, valor
de matrix ou saída gerada em shell, expressão de template, caminho ou input
privilegiado; mistura de confiança entre cache, artefato e workspace (job de menor
confiança popula cache/artefato que job de maior confiança restaura e executa ou
publica — chave e namespace do cache, identidade do produtor, vínculo por digest,
retenção, promoção re-resolvendo por nome mutável); identidade de automação além da
operação/repo/environment/duração necessária, com input não confiável escolhendo o
recurso afetado (menor privilégio ausente sozinho é endurecimento).

**Release e update:** substituição entre build e promoção (teste, revisão, assinatura e
publicação referindo tag, nome, canal ou ID mutáveis em vez do mesmo digest imutável —
cada cópia, repack, merge de arquitetura e passo de proveniência); autorização de
release/política de assinatura aceita do workflow, repo, branch, environment, papel de
chave ou threshold errados (o consumidor valida as claims dentro do attestation, não só
a assinatura válida; rotação, expiração e revogação falham fechado?); updater que
autentica bytes mas não versão, produto, plataforma, canal, caminho de destino,
expiração ou estado de rollback, ou aceita metadado e payload de transações diferentes
(instalação atômica e recuperação); plugin/extensão que ganha autoridade além do escopo
declarado, publisher de menor confiança substituindo identidade de outro, hook de
install/update rodando antes das checagens de autenticidade e capacidade.

**Movimentos universais:** ande para trás do digest publicado ou update instalado até
cada fonte, entrada gerada, credencial, worker, cache, resultado de teste e decisão de
autorização. Compare eventos de workflow não confiáveis e protegidos lado a lado,
marcando cada canal persistido que cruza entre eles. Revise chave revogada, download
falho, attestation ausente, release parcial por plataforma, rollback e indisponibilidade
de registry — a política de falha é parte da integridade.

**Validação:** nomeie ator de menor confiança, fonte/cache/artefato/metadado
controlável, job ou updater confiável que consome e a publicação, inclusão de código,
vazamento de segredo ou execução privilegiada resultantes; prove a identidade do
artefato através da passagem quebrada (nome mutável ou digest solto chegando a
consumidor real); verifique defaults do gerenciador de pacote, host, registry e
assinatura na versão fixada; validação local com repositório fixture, credencial
fictícia, registry/config local e namespace de artefato não produtivo — nunca publicar
ou alterar release real.

---

### Protocolos, RPC e mensageria

**Disciplina:**
- **"Interno" não é autenticação.** Nomeie a identidade do peer em cada salto e mostre
  como ela vira o principal da aplicação usado na autorização.
- Validação de schema prova forma, não procedência, autoridade sobre recurso, ordem ou
  valor seguro. Siga os campos decodificados até política e efeito colateral.
- Garantia do broker ≠ garantia da aplicação: anote retry, ordem, ack, dedup e transação
  antes de avaliar mudança de estado.
- Desacordo de parser exige dois consumidores, versões de schema ou representações
  concretas e um valor divergente relevante para segurança.
- Confirmado com caminho completo e teste local produtor/consumidor; pendente para ACL do
  broker, identidade do mesh, acoplamento de tópico ou compatibilidade fora do
  repositório.

**Framing, schema e interpretação:** desacordo de fronteira/canonicalização (tamanho,
compressão, campo duplicado, campo desconhecido, encoding, largura numérica,
normalização, precedência envelope×corpo entre parser gerado e custom, gateway, binding
de linguagem, conversor de versão); confusão de union/enum/default (variante
desconhecida, discriminador ausente, valor zero, privilégio default, mapeamento de
compatibilidade chegando a código que assume caso validado); identidade do envelope ≠
identidade do payload (autorização pelo roteamento/metadado, handler agindo sobre
tenant/conta/sujeito/objeto/remetente conflitante no corpo).

**Identidade e autorização em RPC:** interceptor de authn/authz que cobre unários mas
não streams, reflection, health, caminhos transcodificados pelo gateway, serviços de
compatibilidade ou mensagens individuais do stream; identidade de canal (mTLS, workload,
bearer em metadata, credencial de broker) com campo controlado pelo chamador escolhendo
usuário/tenant; stream, subscription, batch ou bulk autorizado uma vez e depois
nomeando outros recursos ou continuando após revogação; correlação previsível,
reutilizada ou cross-tenant em resposta, webhook, cancelamento ou ack satisfazendo
operação pendente de outro chamador.

**Broker e fila:** publisher/subscriber que escolhe tópico, wildcard, consumer group,
partição, reply queue ou dead-letter de outro tenant (ACL do broker visível + construção
de namespace na aplicação; tenant no payload não é isolamento); dead-letter, tópico de
erro, tracing ou visão de operador com segredo ou payload cross-tenant acessível a
consumidor de menor confiança; corpo de mensagem que se declara evento admin, callback
de provedor, registro de replicação ou instrução de migração sem produtor e tipo
autenticados independentemente.

**Replay, ordem e transação:** entrega duplicada sem idempotência (dedup ausente, após a
mutação, ou com chave que colide entre tenants/operações); aceitação de mensagem velha ou
fora de ordem (estado antigo, membro revogado, trabalho cancelado ou autorização pré
step-up sobrescrevendo estado mais novo — sequência/versão, tombstone, mudança de
partição, replay de restore); ack antes do commit durável (perde trabalho) ou commit
antes de ack não confiável (duplica mutação) — outbox/inbox transacional; transição
implementada por vários consumidores com retry e falha parcial deixando só parte
commitada.

**Movimentos universais:** desenhe produtor → broker/transporte → consumidor com a
identidade e o principal em cada salto; para cada efeito colateral, verifique
idempotência, ordem e ack; compare o parser de cada consumidor com o mesmo fixture.

**Validação:** nomeie peer de menor confiança, mensagem/campo controlável, consumidor,
recurso e operação/vazamento não autorizados; prove o caminho da identidade do canal ao
principal da aplicação; para replay/ordem, cite o modelo de entrega e o efeito não
idempotente; ACL de broker, mesh e compatibilidade externos → pendente.

---

### Exaustão de recursos e disponibilidade

**Disciplina:**
- Exija caminho entrada→custo, limite efetivo ausente **e** impacto em outro usuário,
  serviço compartilhado, função de segurança ou gasto do operador. Trabalho autolimitado
  no próprio processo do solicitante não é vulnerabilidade de serviço.
- Rate limit ausente não basta: confira limite de corpo/mensagem/arquivo, concorrência,
  fila, deadline, constraint de banco, gateway upstream e cota por tenant antes de
  chamar um caminho de ilimitado.
- **Nunca** teste com estresse, saturação ou produção: análise assintótica, fixture
  pequeno de fronteira, chamada paga mockada, limite local estrito, teste determinístico
  de cancelamento.
- Declare custo do atacante, trabalho do serviço, persistência, escopo e recuperação. Uma
  entrada limitada com efeito superlinear ou persistente é materialmente diferente de
  volume sustentado.
- Confirmado para falha de limite visível na fonte demonstrada com segurança; pendente
  quando cap upstream, topologia, autoscaling, cota paga ou recuperação estão fora do
  repositório.

**Amplificação computacional:** parse/match/avaliação superlinear (regex com
backtracking catastrófico, parse aninhado, validação recursiva, travessia de grafo,
expansão de template, sort/hash adversarial — derive profundidade/cardinalidade aceita
e complexidade, demonstre curva local limitada); amplificação por
descompressão/representação (comprimido, esparso, aninhado, alias, codificado expandindo
muito além do tamanho checado — limite após **cada** expansão: arquivo, imagem, fonte,
documento, tabela de compressão de protocolo); amplificação de query e downstream
(requisição pequena causando scan largo, join patológico, fan-out, sort/agregação sem
limite, muitas chamadas — profundidade, cardinalidade de filtro, paginação, campos de
expansão).

**Acúmulo de recurso:** buffer e cardinalidade sem limite (corpo, stream fora de ordem,
upload, sessão, chave de cache única, label de métrica, campo de log, subscription, job
pendente — limpeza e expiração em disconnect, timeout, cancelamento, parse parcial);
vazamento de descritor/handle/recurso temporário em trabalho malformado ou cancelado
(socket, arquivo, cursor, timer, subprocesso, arquivo temporário — repete em iterações
locais e afeta pool compartilhado); trabalho desgarrado após cancelamento (timeout do
cliente, disconnect, job cancelado ou autorização falha devolvendo controle mas deixando
banco, modelo, rede ou worker rodando).

**Cota e escalonamento:** desequilíbrio pré-autenticação (parse caro, lookup de chave,
criptografia, descompressão ou requisição externa antes da autenticação e do primeiro
gate de tamanho/taxa); escopo e reset de contabilidade influenciáveis (IP, rota, tenant,
prefixo de chave, ID de task permitindo escapar do orçamento ou consumir o de outro —
overflow, corrida distribuída, retry, reconnect, troca de conta); starvation de worker,
pool e prioridade (job de baixa prioridade ou controlado pelo atacante segurando lock,
worker, pool de banco, turno do event loop ou prioridade — caminho que burla fairness ou
retém slot além do deadline).

**Falha e recuperação:** erro fatal ou deadlock alcançável (`panic`, abort, assertion,
exceção não tratada, exit, ciclo de lock, loop infinito em processo compartilhado —
escopo do supervisor: um worker ou o serviço inteiro? worker isolado reiniciado reduz
impacto mas não apaga o defeito); tempestade de retry e fail-open (timeout, erro de
dependência, mensagem parcial, health check falho disparando retries sincronizados ou
ilimitados sem jitter, teto, circuit breaker ou dedup); registro envenenado e
head-of-line blocking (um registro malformado falhando repetidamente na frente de fila,
partição, scan de startup, migração ou loop de recuperação — skip/quarentena, offsets,
outros tenants na mesma unidade); recuperação insegura (restart, restore, fallback ou
limpeza que reconstrói estado ilimitado, ignora cota atual ou restaura a entrada que
repete a falha).

**Movimentos universais:** monte a tabela entrada→recurso: tamanho/cardinalidade aceitos
no ponto mais cedo, trabalho antes da auth, fan-out downstream, persistência, pool
compartilhado, dono do limite e da limpeza, recuperação. Compare limite agregado com
limite por objeto: dez mil itens válidos de um byte escapam do cap por mensagem e
esgotam estado por tenant ou por processo.

**Validação:** nomeie entrada não confiável, trabalho do solicitante, amplificação ou
recurso retido, raio de dano compartilhado e recuperação — limite ausente sem impacto
compartilhado concreto é endurecimento; confirme que nenhum limite upstream, de parser,
fila, tenant ou framework barra o caminho; para superlinear, estabeleça complexidade
aceita e crescimento local limitado; para vazamento, retenção repetível após a limpeza
devida; para fatal, isolamento de processo/supervisor; priorize por pouco trabalho do
solicitante, alcance sem autenticação, escopo cross-tenant, persistência e má
recuperação.

---

### IA, LLM e agentes

Fluxo que importa: *conteúdo não confiável → modelo ou memória → capacidade, autoridade
ou sink*. Usa-se **junto** com as classes comuns, não no lugar: transporte, controle de
acesso, montagem de query, uso de arquivo e renderização continuam sendo fronteiras
comuns; aqui é a camada de delegação ao modelo.

**Disciplina:**
- **Prompt injection sozinho não é achado.** Exige falha de fronteira no código:
  conteúdo chega ao contexto de outro principal, invoca autoridade que o solicitante
  não tem, revela dado que ele não pode ler ou dirige um sink que ele não alcança
  diretamente.
- Saída do modelo, memória, descrição de ferramenta e resposta de MCP são **entradas não
  confiáveis**. Aponte o código que concede autoridade, confia na saída, grava estado
  durável ou alimenta um sink.
- **Prompt de guardrail não é fronteira de segurança.** Só contam verificação
  determinística, autorização por recurso, isolamento, vínculo e credencial restrita.
- Declare atacante, principal afetado, identidade efetiva de execução, recurso, ação
  exata, autoridade usada e impacto observável. Pedido direto e intencional de usar a
  própria autoridade não é defeito de delegação só porque um modelo executa.
- Autorização e **vínculo de ação** são controles separados: conteúdo do atacante que
  causa ação sob a autoridade válida da vítima é falha de vínculo quando a vítima não
  pediu nem aprovou **aquela** ação exata.
- Confirmado só com fonte e validação local limitada; pendente quando provedor,
  implantação, modelo, renderer ou identidade decidem e não são observáveis.

**Contexto, recuperação e memória:** injeção indireta por conteúdo recuperado/ingerido
(documento de RAG, página indexada, arquivo, e-mail, corpo de issue, resposta de
ferramenta ou metadado que entra no contexto de outro principal — quem escreve cada
fonte, como a recuperação escopa, que sessão consome, que capacidade existe ali;
isolamento, autorização de recurso e vínculo à intenção do consumidor são checagens
separadas); vazamento de contexto entre sessões/tenants (histórico, embeddings,
resultado de busca ou cache de prompt com chave larga demais — filtro de tenant/ACL **na
query** e em cada chave de cache); envenenamento de memória persistente (conteúdo do
atacante ou resumo do modelo gravado em memória que molda outra tarefa, usuário ou
sessão privilegiada — quem cria/atualiza/mescla/apaga, procedência e tenant, observação
de baixa confiança virando instrução durável, preferência de usuário × política de
ferramenta); confusão de papel e procedência (concatenação de string, histórico sem
tipo, campo de papel controlado pelo chamador, round-trip de serialização que perde o
rótulo de origem — confirme que a procedência forjada muda uma decisão determinística ou
alcança capacidade).

**Ferramenta e ação:** argumento gerado pelo modelo chegando a SQL, shell, arquivo,
fetch de URL ou API privilegiada sem validação no handler (schema é parsing, não
autorização nem caminho/URL/semântica seguros); agência excessiva e confused deputy
(agente com identidade de serviço ou credencial larga, handler que não reconfere a
permissão do solicitante sobre o recurso nomeado — credencial compartilhada com escopo
por usuário imposto na query não é defeito); vínculo de confirmação (usuário aprova uma
ação descrita, execução usa argumentos, recurso, principal ou turno diferentes; conteúdo
do atacante causa efeito sob autoridade válida da vítima sem pedido/aprovação
intencional; aprovação prende nome normalizado da ferramenta, objeto completo de
argumentos, solicitante, alvo, valor, expiração e membros do lote? retry e sessão
retomada não podem reautorizar efeito mutado ou duplicado); desacordo schema×dispatcher
(alias, campo extra, chave duplicada, coerção, objeto livre aninhado, valor fora da
faixa interpretados de forma diferente — revalide onde o valor vira seletor de recurso);
loops delegados sem limite (pedido limitado enfileirando gasto, envio, mutação ou API
externa repetidos sem orçamento por pedido, autorização por ação, cancelamento ou
idempotência — contabilidade no código e loop local limitado, nunca exaurindo serviço).

**MCP e subagentes:** herança de confiança (tarefa delegada recebendo sessão completa,
credenciais, memória ou capacidades em vez do mínimo — principal e tenant em cada
chamada, estreitamento, audiência da credencial, resultado delegado tratado como não
confiável na volta); confusão de identidade de servidor/ferramenta (roteamento por nome
de servidor, nome de ferramenta, request ID, URI de recurso ou alias escolhido pelo
modelo em vez da conexão autenticada e do pedido pendente — dois servidores reivindicando
a mesma identidade, reconnect mudando o vínculo, resposta de um satisfazendo chamada de
outro); metadado/schema como política (descrição de ferramenta, metadado de recurso,
prompt, hint de completion ou schema do peer tratados como autorização — podem guiar o
modelo, não conceder capacidade; ache a allowlist determinística, a checagem de
identidade e a autorização do handler que valem quando o metadado conflita).

**Saída e divulgação:** renderização insegura (saída do modelo chegando a HTML,
Markdown, template, URL ou comando sem o encoding e a política do sink; renderer fora do
repositório → pendente); extração de contexto sensível (contexto montado com credencial,
dado de outro usuário, fonte privada ou valor de política que concede acesso, exposto
por saída influenciada pelo usuário — revelar instruções genéricas sem cruzar fronteira
de dado não é achado).

**Movimentos universais:** desenhe quatro mapas: identidades de execução, capacidades,
fontes graváveis de contexto/memória, destinos de saída; ligue o principal do começo à
autoridade do fim. Comece pelas ferramentas com efeito colateral e volte por dispatcher,
schema, confirmação, contexto, recuperação, ingestão; comece pelas leituras de memória
durável e rastreie cada escritor. Compare caminhos direto, enfileirado, retry, retomado,
em lote e delegado para a mesma ação: o gate mais forte tem de valer **depois** dos
argumentos finais e **antes** de cada efeito.

**Validação:** (1) nomeie fronteira cruzada e resultado: atacante, principal afetado ou
recurso compartilhado, identidade de execução, alvo, ação/divulgação não autorizada ou
não pedida; (2) confused deputy: prove que a ferramenta não autoriza solicitante+recurso
**e** que o atacante não faz o mesmo pelo caminho normal; vínculo de ação: prove que
conteúdo do atacante causou ação sob autoridade da vítima sem pedido intencional
(autorização genérica válida não prova intenção); (3) memória/recuperação: cite a
escrita do atacante **e** a leitura cross-principal ou decisão privilegiada posterior;
(4) vínculo: estabeleça o pedido intencional ou objeto aprovado normalizado e compare com
o objeto que o handler usa; (5) identidade MCP: conexão autenticada, correlação, namespace
e credencial efetiva — identidade externa ou roteamento implantado → pendente.

---

### Desktop, mobile e IPC local

**Disciplina:**
- Estabeleça o atacante local ou de conteúdo remoto realista: outro app, outro usuário
  do SO, filho em sandbox, documento não confiável, origem remota. Dano a si mesmo na
  mesma conta e autoridade não é violação de fronteira.
- Caminho, nome de processo, bundle/package ID e campo de remetente alegado **não são
  autenticação de peer**: use credenciais de peer do SO, identidade de código, handle de
  capability ou estado de canal protegido.
- A ponte nativa ou o helper autoriza **cada** operação e recurso final após o parse; UI
  ou broker confiável não torna argumentos influenciáveis confiáveis.
- Sandbox do SO, assinatura, entitlements, permissões, ACL de keychain, política de
  componente exportado e prompts são controles reais quando fixados e visíveis.
- Confirmado com fonte e teste local/emulador limitado; pendente quando assinatura,
  merge de manifest, versão do SO, política de dispositivo, ACL de instalador ou
  empacotamento decidem e não são observáveis.

**Deep link, callback e navegação:** esquema customizado/deep link ambíguo (outro app ou
página invocando rota que muta estado, importa dado, completa autenticação ou escolhe
conta sem vínculo à sessão atual e callback de uso único — normalização de URI, query
duplicada, match de esquema/host/caminho, política de componente exportado, link
replayado); handoff de app/conta (OAuth, SSO, magic link, convite, pareamento,
passwordless, pagamento voltando ao app, perfil, tenant ou transação errados); autoridade
de arquivo/intent (arquivo associado, share intent, drag/drop, clipboard, ação de
notificação ou evento open-file disparando operação privilegiada sem confirmar tipo,
confiança do remetente, intenção atual e alvo final).

**Webview e ponte nativa:** frame remoto ou controlado alcançando ponte JS/nativa
destinada ao conteúdo próprio (origem/navegação → ponte); API da ponte que confia em
argumentos para caminho, URL, identificador ou operação sem reautorizar; estado do
webview (cookie, storage, cache) compartilhado entre contas ou origens.

**Componentes exportados, helpers e daemons:** activity/service/receiver/content
provider exportado sem permissão ou com permissão fraca; helper privilegiado (XPC,
serviço SYSTEM, setuid, daemon root) aceitando comandos por socket, pipe ou arquivo sem
autenticar o peer e sem autorizar a operação; socket Unix/named pipe/D-Bus com
permissões largas; condição de corrida em arquivo/diretório temporário ou de
atualização gravável por outro usuário (symlink, TOCTOU, hijack de caminho de DLL/
dylib); segredo em preferências, log, crash dump ou keychain com ACL larga.

**Validação:** nomeie o atacante com sua capacidade inicial, o canal, a verificação de
peer ausente, a operação e o recurso final; prove com dois usuários/apps fictícios ou
emulador; assinatura, entitlements e política de dispositivo não observáveis → pendente.

---

### Memória e binários

**Disciplina:**
- Rederive **cada** limite e tempo de vida a partir das entradas controladas e de todos
  os chamadores; valide contra o pior caso aceito, não contra o vetor típico.
- Panic, achado de sanitizer ou crash prova defeito só quando entrada não confiável
  realista o alcança. Não infira corrupção de memória, execução de código ou impacto de
  disponibilidade compartilhada de um rótulo.
- Valide em harness local com sanitizers, teste determinístico de concorrência, fuzz
  target existente e classificação de falha com debugger. **Pare** ao provar a invariante
  violada e o impacto observável; não desenvolva técnica pós-corrupção.
- Assembly, JIT, alocador próprio, acesso intra-objeto e biblioteca externa escapam da
  cobertura do sanitizer: identifique o que está instrumentado.
- Confirmado só após fonte e validação local estabelecerem defeito e efeito; pendente
  quando ABI, alocador, arquitetura, feature, implantação ou alcançabilidade são
  desconhecidos.

**Limites, inteiros e representação:** leitura/escrita fora dos limites (tamanho,
offset, índice ou terminador chegando a buffer sem limite correto — recalcule a folga
após prefixo, alinhamento, padding e terminador; capacidade de origem **e** destino;
entrada curta lida antes de o tamanho declarado ser confiado); overflow, underflow,
truncamento e sinal (`a - b` com `b > a`, `count * size`, soma perto do máximo,
negativo→unsigned, 64→32 bits, sentinela `-1` virando tamanho enorme — qual
representação checada é usada depois); confusão de unidade e profundidade de ponteiro
(bytes × elementos × code units × páginas × palavras; checagem com a mesma unidade errada
da alocação continua errada); dado não inicializado ou parcialmente inicializado.

**Tempo de vida e concorrência:** use-after-free, double free, ponteiro pendurado após
realloc/shrink, referência a elemento de container que cresce; corrida de dados em
estado compartilhado, TOCTOU em memória, ordem de inicialização/destruição, callback
reentrante durante iteração.

**FFI, ABI e loader:** fronteira FFI que assume string terminada, tamanho ou
alinhamento; `unsafe` em Rust sem invariante documentada; parse de formato binário
(cabeçalho, seção, relocação, tabela de símbolos) com offsets não checados; JIT que
emite código de entrada influenciável; interface privilegiada (ioctl, syscall, driver)
copiando de/para o usuário sem validar tamanho e ponteiro.

**Validação:** nomeie a entrada não confiável realista, o caminho até a operação de
memória, a invariante violada e o efeito observado localmente (sanitizer, assertion,
valor errado); classifique o escopo (processo, worker, kernel); ABI/alocador/arquitetura
desconhecidos → pendente.
