"""
Cadastra os achados da auditoria como issues no GitHub do projeto.

O texto de cada issue é montado a partir dos registros (o mesmo Markdown dos blocos
`--- ISSUE n ---` do PDF); ninguém precisa redigir nem colar nada. Rode com o python do
venv do relatório, a partir da raiz do repositório:

    PY=docs/security-audit/.venv/Scripts/python.exe        # Linux/macOS: .venv/bin/python
    $PY docs/security-audit/abrir_issues.py                 # só lista (não cria nada)
    $PY docs/security-audit/abrir_issues.py --exportar      # grava os .md para colar à mão
    $PY docs/security-audit/abrir_issues.py --criar --simular            # mostra o que faria
    $PY docs/security-audit/abrir_issues.py --criar                      # todos os achados
    $PY docs/security-audit/abrir_issues.py --criar --severidade critica,alta
    $PY docs/security-audit/abrir_issues.py --criar --ids A1,A4 --agrupadas --pendentes
    $PY docs/security-audit/abrir_issues.py --atualizar     # regrava as issues já abertas

Regras:
- nunca cria sem `--criar`; a decisão é de quem pediu a auditoria;
- não cria nem atualiza enquanto `validar_findings.py` apontar erro — em especial, achado
  cuja correção não foi revisada contra as regras de negócio documentadas não vira issue;
- achado com `decisao_necessaria` (a correção contraria algo documentado) sai com o label
  `decisao-de-produto` e a decisão no topo do corpo: não é tarefa pronta para implementar;
- não duplica: pula o que já tem `issue` no registro, o que está em `issues.json` e o que
  já existe no repositório com o mesmo fingerprint no corpo;
- repositório PÚBLICO: recusa, porque issue pública divulga a falha antes da correção
  (use `--repositorio-publico-ok` só se for mesmo essa a intenção);
- cria os labels que faltarem (`security` + severidade) sem mexer nos que já existem;
- anota o número de volta no arquivo do registro (campo `issue`) e em `issues.json`.

Depois de criar, rode `gerar_relatorio.py` de novo: o PDF passa a citar as issues.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)

LIVRO = os.path.join(AQUI, "issues.json")
PASTA_MD = os.path.join(AQUI, ".trabalho", "issues")
LABEL_PENDENTE = "needs-validation"
LABEL_DECISAO = "decisao-de-produto"


def _gh(args: list[str], entrada: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["gh", *args], input=entrada, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def _ambiente() -> tuple[dict | None, str]:
    """Devolve (dados do repositório, problema). Problema vazio = pode criar."""
    if not shutil.which("gh"):
        return None, "o GitHub CLI (gh) não está instalado"
    if _gh(["auth", "status"]).returncode != 0:
        return None, "o gh não está autenticado (rode: gh auth login)"
    r = _gh(["repo", "view", "--json", "nameWithOwner,visibility,hasIssuesEnabled,url"])
    if r.returncode != 0:
        return None, "este diretório não tem um repositório do GitHub que o gh reconheça"
    repo = json.loads(r.stdout)
    if not repo.get("hasIssuesEnabled", True):
        return repo, "o repositório está com Issues desativadas"
    return repo, ""


def _markdown_pendente(p: dict, limpar) -> str:
    linhas = [
        f'# [Segurança · validar] {limpar(p["titulo"])}',
        "",
        f"**Labels:** `security`, `{LABEL_PENDENTE}`",
        "",
        "Hipótese levantada na auditoria. **Não é uma falha confirmada**: a confirmação "
        "depende de um fato que não está no repositório.",
        "",
        "## O que foi visto",
        "",
        limpar(p["descricao"]),
        "",
        f'`{p["arquivo"]}`' + (f' — linha(s) {p["linha"]}' if p.get("linha") else ""),
        "",
        "```",
        p["evidencia"],
        "```",
        "",
        "## O que falta para decidir",
        "",
        *[f"- {limpar(b)}" for b in p["bloqueadores"]],
        "",
        "## Como validar",
        "",
    ]
    plano = p.get("plano_validacao") or {}
    if plano.get("local"):
        linhas.append(f'- **Local:** {limpar(plano["local"])}')
    if plano.get("implantacao"):
        linhas.append(f'- **Na implantação:** {limpar(plano["implantacao"])}')
    if p.get("fingerprint"):
        linhas += ["", f'**Fingerprint:** `{p["fingerprint"]}`']
    return "\n".join(linhas)


def _montar(F, G) -> list[dict]:
    """Uma entrada por issue possível, na ordem do PDF."""
    itens = []
    rotulo = F.ROTULO_SEVERIDADE
    for a in F.ACHADOS:
        if not a.get("exploravel"):
            continue
        sev = a["severidade"]
        # Correção que contraria regra documentada não é tarefa pronta: é decisão.
        decisao = bool(a.get("decisao_necessaria"))
        itens.append({
            "tipo": "achado", "id": a["id"], "severidade": sev, "decisao": decisao,
            "chave": a.get("fingerprint") or f'id:{a["id"]}',
            "fingerprint": a.get("fingerprint"),
            "titulo": f'[Segurança] {G._limpar(a["titulo"])}',
            "labels": ["security", rotulo[sev].lower()] + ([LABEL_DECISAO] if decisao else []),
            "corpo": G._markdown_issue(a),
            "issue": a.get("issue"), "arquivo": a.get("_arquivo"),
        })
    for n, g in enumerate(getattr(F, "ISSUES_AGRUPADAS", []), start=1):
        itens.append({
            "tipo": "agrupada", "id": f"G{n}", "severidade": "informativa",
            "chave": f'agrupada:{g["titulo"]}', "fingerprint": None,
            "titulo": f'[Segurança] {G._limpar(g["titulo"])}',
            "labels": list(g.get("labels", ["security"])),
            "corpo": G._markdown_issue_agrupada(g),
            "issue": g.get("issue"), "arquivo": None,
        })
    for p in getattr(F, "PENDENTES_VALIDACAO", []):
        itens.append({
            "tipo": "pendente", "id": p["id"], "severidade": "",
            "chave": p.get("fingerprint") or f'id:{p["id"]}',
            "fingerprint": p.get("fingerprint"),
            "titulo": f'[Segurança · validar] {G._limpar(p["titulo"])}',
            "labels": ["security", LABEL_PENDENTE],
            "corpo": _markdown_pendente(p, G._limpar),
            "issue": p.get("issue"), "arquivo": p.get("_arquivo"),
        })
    for item in itens:
        # A primeira linha do Markdown é o título; no GitHub ele vai no campo próprio.
        corpo = item["corpo"].split("\n")
        if corpo and corpo[0].startswith("# "):
            corpo = corpo[1:]
        while corpo and (not corpo[0].strip() or corpo[0].startswith("**Labels:**")):
            corpo = corpo[1:]
        aviso = ("> **Não implementar antes da decisão de produto.** A correção sugerida contraria "
                 "uma regra documentada — ver \"Decisão necessária antes de implementar\" abaixo.\n\n"
                 if item.get("decisao") else "")
        item["corpo"] = aviso + "\n".join(corpo).strip() + "\n\n---\n_Aberta a partir da auditoria de segurança (docs/security-audit)._\n"
    return itens


def _ler_livro() -> dict:
    if os.path.exists(LIVRO):
        with open(LIVRO, encoding="utf-8") as f:
            return json.load(f)
    return {}


def _gravar_livro(livro: dict) -> None:
    with open(LIVRO, "w", encoding="utf-8") as f:
        json.dump(livro, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")


def _anotar_no_registro(item: dict, numero: int) -> None:
    if not item.get("arquivo"):
        return
    caminho = os.path.join(AQUI, "registros", item["arquivo"])
    if not os.path.exists(caminho):
        return
    with open(caminho, encoding="utf-8") as f:
        reg = json.load(f)
    reg["issue"] = numero
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=1)
        f.write("\n")


def _ja_existe_no_github(item: dict) -> int | None:
    """Procura issue (aberta ou fechada) que cite o fingerprint ou tenha o mesmo título."""
    if item.get("fingerprint"):
        consulta = f'"{item["fingerprint"]}" in:body'
    else:
        consulta = f'"{item["titulo"]}" in:title'
    r = _gh(["issue", "list", "--state", "all", "--search", consulta,
             "--json", "number,title,body", "--limit", "20"])
    if r.returncode != 0:
        return None
    for achada in json.loads(r.stdout or "[]"):
        if item.get("fingerprint") and item["fingerprint"] in (achada.get("body") or ""):
            return achada["number"]
        if not item.get("fingerprint") and achada.get("title") == item["titulo"]:
            return achada["number"]
    return None


def _garantir_labels(labels: set[str], cores: dict, simular: bool) -> None:
    r = _gh(["label", "list", "--limit", "300", "--json", "name"])
    existentes = {l["name"].lower() for l in json.loads(r.stdout or "[]")} if r.returncode == 0 else set()
    cor_por_label = {"security": "B91C1C", LABEL_PENDENTE: "7C3AED", LABEL_DECISAO: "0E7490",
                     "crítica": cores["critica"], "alta": cores["alta"], "média": cores["media"],
                     "baixa": cores["baixa"], "informativa": cores["informativa"]}
    for label in sorted(labels):
        if label.lower() in existentes:
            continue
        cor = cor_por_label.get(label, "6B7280").lstrip("#")
        if simular:
            print(f"  criaria o label {label!r}")
            continue
        _gh(["label", "create", label, "--color", cor,
             "--description", "Auditoria de segurança"])


def _selecionar(itens: list[dict], args: list[str]) -> list[dict]:
    def valor(flag):
        return args[args.index(flag) + 1] if flag in args and args.index(flag) + 1 < len(args) else ""

    ids = {x.strip().upper() for x in valor("--ids").split(",") if x.strip()}
    sevs = {x.strip().lower() for x in valor("--severidade").split(",") if x.strip()}
    escolhidos = []
    for item in itens:
        if ids:
            if item["id"].upper() in ids:
                escolhidos.append(item)
            continue
        if item["tipo"] == "achado" and (not sevs or item["severidade"] in sevs):
            escolhidos.append(item)
        elif item["tipo"] == "agrupada" and "--agrupadas" in args:
            escolhidos.append(item)
        elif item["tipo"] == "pendente" and "--pendentes" in args:
            escolhidos.append(item)
    return escolhidos


def main(argv: list[str]) -> int:
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(encoding="utf-8", errors="replace")
    args = argv[1:]

    try:
        import findings as F
        import gerar_relatorio as G
    except ImportError as exc:
        print(f"não consegui carregar os dados: {exc}\n"
              "rode com o python do venv do relatório (docs/security-audit/.venv)")
        return 1

    itens = _montar(F, G)
    livro = _ler_livro()
    for item in itens:
        if not item["issue"] and item["chave"] in livro:
            item["issue"] = livro[item["chave"]]["numero"]

    if "--exportar" in args:
        # Exportar também publica: o .md vai para quem colar à mão. Mesma trava de --criar.
        import validar_findings
        erros_exportacao, _ = validar_findings.validar(F)
        if erros_exportacao:
            for e in erros_exportacao[:15]:
                print(f"ERRO   {e}")
            print(f"BLOQUEADO: {len(erros_exportacao)} erro(s) em validar_findings.py — "
                  "nada foi exportado.")
            return 1
        os.makedirs(PASTA_MD, exist_ok=True)
        for item in itens:
            nome = os.path.basename(item["id"])
            with open(os.path.join(PASTA_MD, f"{nome}.md"), "w", encoding="utf-8") as f:
                f.write(f'# {item["titulo"]}\n\nLabels: {", ".join(item["labels"])}\n\n{item["corpo"]}')
        print(f"{len(itens)} arquivo(s) em {PASTA_MD}")
        return 0

    repo, problema = _ambiente()

    # Trava: issue só sai de registro consistente — inclusive com a correção revisada
    # contra as regras de negócio documentadas (o validador cobra isso).
    import validar_findings
    erros_validacao, _ = validar_findings.validar(F)

    if "--criar" not in args and "--atualizar" not in args:
        if repo:
            print(f'Repositório: {repo["nameWithOwner"]} ({repo["visibility"].lower()})')
        print(f'GitHub pronto para criar: {"sim" if not problema else "não — " + problema}')
        if erros_validacao:
            print(f"BLOQUEADO: validar_findings.py aponta {len(erros_validacao)} erro(s); "
                  "nenhuma issue é criada ou atualizada até zerar.")
        precisam_decisao = [i["id"] for i in itens if i.get("decisao")]
        if precisam_decisao:
            print("Exigem decisão do dono antes de implementar (label "
                  f"{LABEL_DECISAO}): {', '.join(precisam_decisao)}")
        por_sev: dict[str, int] = {}
        for item in itens:
            estado = f'já é a #{item["issue"]}' if item["issue"] else "a criar"
            sev = item["severidade"] or item["tipo"]
            if not item["issue"]:
                por_sev[sev if item["tipo"] == "achado" else item["tipo"]] = por_sev.get(
                    sev if item["tipo"] == "achado" else item["tipo"], 0) + 1
            print(f'  {item["id"]:<5} {sev:<12} {estado:<14} {item["titulo"][:90]}')
        print("A criar: " + (", ".join(f"{k}: {v}" for k, v in por_sev.items()) or "nada"))
        if repo and repo["visibility"] == "PUBLIC":
            print("ATENÇÃO: repositório público — issue pública divulga a falha antes da correção.")
        return 0

    simular = "--simular" in args
    if erros_validacao:
        for e in erros_validacao[:15]:
            print(f"ERRO   {e}")
        print(f"{len(erros_validacao)} erro(s) em validar_findings.py — corrija antes de criar "
              "ou atualizar issues. Achado sem a correção revisada contra a documentação do "
              "projeto não vira issue.")
        return 1
    if problema and not simular:
        print(f"não dá para criar: {problema}")
        print("alternativa: --exportar grava os .md para colar à mão")
        return 1

    if "--atualizar" in args:
        # Regrava título, corpo e labels das issues que já existem, a partir dos
        # registros atuais (por exemplo, depois de revisar as correções).
        alvo = [i for i in _selecionar(itens, args) if i["issue"]]
        if not alvo:
            print("nenhuma issue existente entre os itens selecionados")
            return 1
        _garantir_labels({l for i in alvo for l in i["labels"]}, F.CORES, simular)
        ok = falhou = 0
        for item in alvo:
            if simular:
                print(f'  atualizaria #{item["issue"]}: {item["id"]} [{", ".join(item["labels"])}]')
                continue
            comando = ["issue", "edit", str(item["issue"]), "--title", item["titulo"],
                       "--body-file", "-"]
            for label in item["labels"]:
                comando += ["--add-label", label]
            r = _gh(comando, entrada=item["corpo"])
            if r.returncode == 0:
                ok += 1
                print(f'atualizada #{item["issue"]} ({item["id"]})')
            else:
                falhou += 1
                print(f'FALHOU   #{item["issue"]} ({item["id"]}): {(r.stderr or "").strip()[:160]}')
        print(f"{ok} atualizada(s), {falhou} falha(s)")
        return 1 if falhou else 0
    if repo and repo["visibility"] == "PUBLIC" and "--repositorio-publico-ok" not in args:
        print(f'{repo["nameWithOwner"]} é público: issue pública divulga a falha antes da '
              "correção. Prefira um security advisory privado, ou repita com "
              "--repositorio-publico-ok se for mesmo a intenção.")
        return 1

    escolhidos = _selecionar(itens, args)
    if not escolhidos:
        print("nenhum item selecionado")
        return 1

    if repo and not problema:
        _garantir_labels({l for item in escolhidos if not item["issue"] for l in item["labels"]},
                         F.CORES, simular)

    criadas, puladas, falhas = [], [], []
    for item in escolhidos:
        if item["issue"]:
            puladas.append((item, item["issue"]))
            continue
        if repo and not problema:
            existente = _ja_existe_no_github(item)
            if existente:
                puladas.append((item, existente))
                if not simular:
                    livro[item["chave"]] = {"numero": existente, "id": item["id"]}
                    _anotar_no_registro(item, existente)
                continue
        if simular:
            print(f'  criaria: {item["id"]} — {item["titulo"]}  [{", ".join(item["labels"])}]')
            continue
        comando = ["issue", "create", "--title", item["titulo"], "--body-file", "-"]
        for label in item["labels"]:
            comando += ["--label", label]
        r = _gh(comando, entrada=item["corpo"])
        url = (r.stdout or "").strip().split("\n")[-1]
        numero = re.search(r"/issues/(\d+)", url)
        if r.returncode != 0 or not numero:
            falhas.append((item, (r.stderr or r.stdout).strip()[:200]))
            continue
        n = int(numero.group(1))
        livro[item["chave"]] = {"numero": n, "url": url, "id": item["id"]}
        _gravar_livro(livro)                     # grava a cada issue: nada se perde se parar
        _anotar_no_registro(item, n)
        criadas.append((item, url))

    if not simular:
        _gravar_livro(livro)
    for item, url in criadas:
        print(f'criada   {item["id"]:<5} {url}')
    for item, n in puladas:
        print(f'já havia {item["id"]:<5} #{n}')
    for item, erro in falhas:
        print(f'FALHOU   {item["id"]:<5} {erro}')
    print(f"{len(criadas)} criada(s), {len(puladas)} já existente(s), {len(falhas)} falha(s)")
    if criadas:
        print("Rode gerar_relatorio.py de novo para o PDF citar as issues.")
    return 1 if falhas else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
