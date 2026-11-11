"""
Fase 12: patches verificados, um por achado, que o dono aplica quando quiser.

    python docs/security-audit/patches.py preparar A1 [--ligar-dependencias]
    python docs/security-audit/patches.py congelar A1
    python docs/security-audit/patches.py julgar A1 [--rodada 2]
    python docs/security-audit/patches.py escrever A1
    python docs/security-audit/patches.py recusar A1 --motivo "..."
    python docs/security-audit/patches.py remover A1
    python docs/security-audit/patches.py indice

Cada correção nasce num clone à parte, em `.trabalho/patches/scratch-<id>`, com os hooks do usuário
desligados. A árvore de trabalho e o índice do dono nunca são tocados, e nada aqui aplica, faz
commit ou push. O gerador deixa a mudança no stage e `congelar` registra o hash dela, apagando
relatórios antigos; o verificador e o atacante gravam seus relatórios em
`.trabalho/patches/<id>/`; o julgamento é calculado aqui, não pelo modelo, e só vale para o diff
congelado. Mudou o stage, o julgamento cai.

Regras: quatro alegações, todas CONFIDENT. UNSURE, relatório ausente ou achado não confirmado
recusa. Objeção tem uma rodada de revisão. Correção com `decisao_necessaria` não vira patch, porque
a decisão é do dono.

`--ligar-dependencias` liga o `node_modules` do projeto ao clone por junction, para os testes
rodarem. É opcional e pede aceite: a ligação não é somente leitura, então um teste que grave ali
(cache de build, por exemplo) altera o `node_modules` real.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ALEGACOES = ("DIRECIONADA", "SEM_FALHA_NOVA", "COMPORTAMENTO_MANTIDO", "REGRAS_MANTIDAS")
CAMINHO_NAO_CONTA = "preexistente"
CAMINHO_OUTRO_ACHADO = "outro_achado"
_ID = re.compile(r"^A[0-9]{1,6}$")


def _git(diretorio, *args: str, verificar: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(
        ["git", "-C", str(diretorio), *args], capture_output=True, text=True, encoding="utf-8",
        errors="replace", env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}, timeout=300)
    if verificar and r.returncode != 0:
        raise ValueError(f"git {args[0]} falhou: {(r.stderr or r.stdout).strip()[:200]}")
    return r


def _validar_id(id_achado: str) -> str:
    if not _ID.match(str(id_achado)):
        raise ValueError(f"id de achado inválido: {id_achado!r}")
    return id_achado


def _carregar(pasta: str):
    arquivo = Path(pasta) / "findings.py"
    if not arquivo.exists():
        raise ValueError(f"findings.py não encontrado em {pasta}")
    spec = importlib.util.spec_from_file_location("_findings_patches", arquivo)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def _registro(pasta: str, id_achado: str) -> dict:
    """O achado como o relatório o numera: o id pode vir da ordem do carregador."""
    for reg in _carregar(pasta).ACHADOS:
        if reg.get("id") == id_achado:
            return reg
    raise ValueError(f"achado {id_achado} não existe nesta rodada")


def ids_da_rodada(pasta: str, id_achado: str) -> set[str]:
    """Outros registros abertos: é a eles que um caminho `outro_achado` pode apontar."""
    modulo = _carregar(pasta)
    regs = [*modulo.ACHADOS, *getattr(modulo, "PENDENTES_VALIDACAO", [])]
    return {r["id"] for r in regs if r.get("id") and r["id"] != id_achado}


def _pasta_trabalho(pasta: str) -> Path:
    return Path(pasta) / ".trabalho" / "patches"


def _scratch(pasta: str, id_achado: str) -> Path:
    return _pasta_trabalho(pasta) / f"scratch-{id_achado}"


def _ligar(origem: Path, destino: Path) -> None:
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(destino), str(origem)],
                       check=True, capture_output=True)
    else:
        os.symlink(origem, destino, target_is_directory=True)


def _e_ligacao(caminho: Path) -> bool:
    return caminho.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(caminho))


def _relatorios(pasta: str, id_achado: str) -> Path:
    return _pasta_trabalho(pasta) / id_achado


def _limpar_relatorios(pasta: str, id_achado: str) -> None:
    for nome in ("verificador.json", "atacante.json", "julgamento.json", "stage.json"):
        (_relatorios(pasta, id_achado) / nome).unlink(missing_ok=True)


def _diff_stage(scratch: Path) -> str:
    return _git(scratch, "diff", "--cached", "--binary", "--no-ext-diff", "--no-textconv",
                "--src-prefix=a/", "--dst-prefix=b/").stdout


def _hash(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def _linhas_alteradas(scratch: Path, *opcoes: str) -> int:
    total = 0
    for linha in _git(scratch, "diff", "--cached", "--numstat", *opcoes).stdout.splitlines():
        partes = linha.split("\t")
        if len(partes) == 3 and partes[0].isdigit() and partes[1].isdigit():
            total += int(partes[0]) + int(partes[1])
    return total


def congelar(pasta: str, id_achado: str) -> str:
    """Registra o hash do stage e apaga relatórios antigos. Rode antes de cada verificação."""
    _validar_id(id_achado)
    scratch = _scratch(pasta, id_achado)
    diff = _diff_stage(scratch)
    if not diff.strip():
        raise ValueError(f"{id_achado}: diff vazio no stage do clone")
    # Editor que troca LF por CRLF reescreve o arquivo inteiro: nenhum revisor enxerga a mudança
    # real num diff assim, e o patch deixaria de ser estreito.
    bruto, real = _linhas_alteradas(scratch), _linhas_alteradas(scratch, "--ignore-space-at-eol")
    if bruto > 20 and bruto > 3 * real:
        raise ValueError(f"{id_achado}: {bruto} linhas no diff, {real} sem contar fim de linha; "
                         "o gerador trocou o fim de linha do arquivo. Refaça preservando-o")
    _limpar_relatorios(pasta, id_achado)
    pasta_id = _relatorios(pasta, id_achado)
    pasta_id.mkdir(parents=True, exist_ok=True)
    selo = _hash(diff)
    (pasta_id / "stage.json").write_text(json.dumps({"diff_sha": selo}), encoding="utf-8")
    return selo


def caminhos_do_stage(scratch: Path) -> list[str]:
    return sorted(c for c in _git(scratch, "diff", "--cached", "--name-only", "-z").stdout.split("\0")
                  if c)


def selar(pasta: str, id_achado: str, julgamento: dict, verificador: dict | None = None) -> dict:
    """Amarra o julgamento ao diff congelado. O stage mudou depois: não há julgamento.

    Com `verificador`, confere ainda se ele revisou exatamente os arquivos do diff: um arquivo que
    ninguém olhou não pode entrar no patch por estar no stage.
    """
    _validar_id(id_achado)
    scratch = _scratch(pasta, id_achado)
    registro = _ler_relatorio(_relatorios(pasta, id_achado) / "stage.json") or {}
    atual = _hash(_diff_stage(scratch))
    if registro.get("diff_sha") != atual:
        raise ValueError(f"{id_achado}: o stage mudou depois de congelar; rode congelar e "
                         "verifique de novo")
    if verificador is not None and julgamento.get("status") == "aprovado":
        revisados = sorted(str(c).replace("\\", "/") for c in
                           verificador.get("caminhos_revisados") or [])
        if revisados != caminhos_do_stage(scratch):
            julgamento = {"status": "recusado",
                          "motivo": "o verificador não revisou exatamente os arquivos do diff"}
    return {**julgamento, "diff_sha": atual}


def preparar(repo: str, pasta: str, id_achado: str, ref: str,
             ligar_dependencias: bool = False) -> Path:
    """Cria o clone do achado no commit auditado. Recusa relatório desatualizado."""
    _validar_id(id_achado)
    reg = _registro(pasta, id_achado)
    if reg.get("decisao_necessaria"):
        raise ValueError(f"{id_achado}: a correção depende de decisão do dono; não gera patch")
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    if not ref or not head.startswith(ref):
        raise ValueError(f"HEAD {head[:12]} não é o commit auditado {ref}: rode uma nova rodada")
    scratch = _scratch(pasta, id_achado)
    if scratch.exists():
        remover(scratch)
    _limpar_relatorios(pasta, id_achado)
    scratch.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--shared", "--no-checkout", "--quiet", "-c", "core.hooksPath=/dev/null",
         "-c", "core.longpaths=true", str(repo), str(scratch)],
        check=True, capture_output=True, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    _git(scratch, "checkout", "--detach", "--quiet", head)
    # Arquivo que a cópia não trouxe (caminho longo no Windows, por exemplo) viraria exclusão
    # no `git add -A` do gerador e entraria no patch.
    faltam = _git(scratch, "ls-files", "--deleted").stdout.split("\n")
    faltam = [c for c in faltam if c]
    if faltam:
        remover(scratch)
        raise ValueError(f"o clone ficou incompleto ({len(faltam)} arquivo(s), como {faltam[0]})")
    # `remover` desfaz a ligação antes de apagar o clone; senão o rmtree alcançaria o real.
    modulos = Path(repo) / "node_modules"
    if ligar_dependencias and modulos.is_dir() and not (scratch / "node_modules").exists() \
            and _git(repo, "check-ignore", "-q", "node_modules", verificar=False).returncode == 0:
        _ligar(modulos.resolve(), scratch / "node_modules")
    return scratch


def _estado(valor) -> str | None:
    """Estado da alegação. Aceita 'CONFIDENT: evidência'; qualquer outra forma não responde."""
    m = re.match(r"^\s*(NOT_CONFIDENT|CONFIDENT|UNSURE)\b", valor) if isinstance(valor, str) else None
    return m.group(1) if m else None


def julgar(verificador: dict | None, atacante: dict | None, rodada: int,
           achados=()) -> dict:
    """Decide por código. Sem relatório completo, recusa: nunca aprova por omissão.

    Um caminho `outro_achado` só deixa de contar se apontar um id de `achados`: quem o rotula tem
    de nomear o registro que já cuida dele, e esse registro tem de existir.
    """
    if not isinstance(verificador, dict) or not isinstance(atacante, dict):
        return {"status": "recusado", "motivo": "verificador ou atacante não reportou"}
    if verificador.get("confirmado") is not True:
        return {"status": "recusado", "motivo": "achado não confirmado nesta revisão"}
    brutas = verificador.get("alegacoes") or {}
    alegacoes = {a: _estado(brutas.get(a)) for a in ALEGACOES}
    faltam = [a for a in ALEGACOES if alegacoes[a] is None]
    if faltam or "UNSURE" in alegacoes.values():
        return {"status": "recusado",
                "motivo": f"alegação sem resposta: {', '.join(faltam) or 'UNSURE'}"}
    objecoes = [a for a in ALEGACOES if alegacoes[a] != "CONFIDENT"]
    if verificador.get("veredito") != "PASS":
        objecoes.append("verificador rejeitou")
    caminhos = atacante.get("caminhos")
    if not isinstance(caminhos, list):
        return {"status": "recusado", "motivo": "relatório do atacante sem lista de caminhos"}
    def conta(caminho) -> bool:
        if not isinstance(caminho, dict):
            return True
        if caminho.get("tipo") == CAMINHO_OUTRO_ACHADO:
            return caminho.get("achado") not in achados
        return caminho.get("tipo") != CAMINHO_NAO_CONTA

    contam = [c for c in caminhos if conta(c)]
    if contam:
        objecoes.append(f"{len(contam)} caminho(s) de ataque")
    if not objecoes:
        return {"status": "aprovado", "motivo": ""}
    motivo = "; ".join(objecoes)
    if rodada >= 2:
        return {"status": "recusado", "motivo": f"segunda objeção: {motivo}"}
    return {"status": "objecao", "motivo": motivo}


def _pasta_patches(pasta: str) -> Path:
    destino = Path(pasta) / "patches"
    destino.mkdir(parents=True, exist_ok=True)
    return destino


def escrever(repo: str, pasta: str, id_achado: str, julgamento: dict, verificador: dict) -> Path:
    """Grava `patches/<id>.patch` e `<id>.md` a partir do stage do clone."""
    _validar_id(id_achado)
    if julgamento.get("status") != "aprovado":
        raise ValueError(f"{id_achado}: só patch aprovado é escrito ({julgamento.get('status')})")
    reg = _registro(pasta, id_achado)
    if reg.get("decisao_necessaria"):
        raise ValueError(f"{id_achado}: a correção agora depende de decisão do dono")
    diff = _diff_stage(_scratch(pasta, id_achado))
    if not diff.strip():
        raise ValueError(f"{id_achado}: diff vazio no stage do clone")
    if julgamento.get("diff_sha") != _hash(diff):
        raise ValueError(f"{id_achado}: o stage não é o diff julgado")
    sem_teste = bool(verificador.get("sem_teste"))
    aviso = "Nenhum teste do projeto cobre este código: o comportamento foi revisado, não testado."
    cabecalho = [f"Patch do achado {id_achado}: {reg.get('titulo', '')}",
                 "Quatro alegações do painel: " + ", ".join(ALEGACOES)]
    if sem_teste:
        cabecalho.append(aviso)
    destino = _pasta_patches(pasta)
    caminho = destino / f"{id_achado}.patch"
    with open(caminho, "w", encoding="utf-8", newline="\n") as f:
        f.write("".join(f"# {linha}\n" for linha in cabecalho) + diff)
    check = _git(repo, "apply", "--check", str(caminho.resolve()), verificar=False)
    aplica = "aplica na árvore atual" if check.returncode == 0 else \
        "não aplica na árvore atual: ela mudou depois do commit auditado"
    alterados = ", ".join(caminhos_do_stage(_scratch(pasta, id_achado)))
    nota = [f"# {id_achado}: {reg.get('titulo', '')}", "",
            f"Aplicar: `git apply {caminho.as_posix()}`", "", f"- Arquivos: {alterados}",
            f"- `git apply --check`: {aplica}",
            f"- Testes: {verificador.get('testes') or 'nenhum'}"]
    if sem_teste:
        nota.append(f"- {aviso}")
    atacante = _ler_relatorio(_relatorios(pasta, id_achado) / "atacante.json") or {}
    for c in atacante.get("caminhos") or []:
        if isinstance(c, dict) and c.get("tipo") == CAMINHO_OUTRO_ACHADO:
            nota.append(f"- Segue aberto, em {c.get('achado')}: {c.get('descricao', '')}")
    (destino / f"{id_achado}.md").write_text("\n".join(nota) + "\n", encoding="utf-8")
    return caminho


def registrar_recusa(pasta: str, id_achado: str, motivo: str) -> Path:
    _validar_id(id_achado)
    caminho = _pasta_patches(pasta) / f"{id_achado}.md"
    caminho.write_text(f"# {id_achado}: sem patch\n\n{motivo}\n", encoding="utf-8")
    return caminho


def remover(scratch) -> None:
    """Apaga o clone. A ligação do node_modules sai antes, para o rmtree não a atravessar."""
    scratch = Path(scratch)
    ligacao = scratch / "node_modules"
    if _e_ligacao(ligacao):
        if ligacao.is_symlink():
            ligacao.unlink()
        else:
            os.rmdir(ligacao)

    def _forcar(funcao, caminho, _):
        os.chmod(caminho, stat.S_IWRITE)
        funcao(caminho)

    if sys.version_info >= (3, 12):
        shutil.rmtree(scratch, onexc=_forcar)
    else:  # pragma: no cover
        shutil.rmtree(scratch, onerror=_forcar)


def indice(pasta: str) -> Path:
    """`patches/PATCHES.md`: uma linha por achado, com patch ou com o motivo da recusa."""
    destino = _pasta_patches(pasta)
    linhas = ["# Patches da auditoria", "",
              "Nada foi aplicado. Leia cada patch antes de usar `git apply`.", ""]
    for nota in sorted(destino.glob("A*.md")):
        id_achado = nota.stem
        patch = destino / f"{id_achado}.patch"
        if patch.exists():
            linhas.append(f"- **{id_achado}**: [{patch.name}]({patch.name})")
        else:
            corpo = nota.read_text(encoding="utf-8").split("\n", 2)
            linhas.append(f"- **{id_achado}**: sem patch. {corpo[2].strip() if len(corpo) > 2 else ''}")
    caminho = destino / "PATCHES.md"
    caminho.write_text("\n".join(linhas) + "\n", encoding="utf-8")
    return caminho


def _ler_relatorio(caminho: Path) -> dict | None:
    try:
        return json.loads(caminho.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def relatorios_ilegiveis(pasta: Path) -> list[str]:
    """Relatórios que não existem ou não são um objeto JSON."""
    return [nome for nome in ("verificador.json", "atacante.json")
            if not isinstance(_ler_relatorio(pasta / nome), dict)]


def _raiz(pasta: str) -> str:
    return _git(pasta, "rev-parse", "--show-toplevel").stdout.strip()


def _ref_auditada(pasta: str) -> str:
    texto = (Path(pasta) / "findings.py").read_text(encoding="utf-8")
    m = re.search(r'^REF_FONTE = ["\']([0-9a-f]{7,64})\b', texto, re.MULTILINE)
    return m.group(1) if m else ""


def main(argv: list[str]) -> int:
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(encoding="utf-8", errors="replace")
    args = argparse.ArgumentParser(description="Patches verificados da auditoria.")
    args.add_argument("acao", choices=("preparar", "congelar", "julgar", "escrever", "recusar",
                                       "remover", "indice"))
    args.add_argument("id", nargs="?")
    args.add_argument("--pasta", default=os.path.dirname(os.path.abspath(__file__)))
    args.add_argument("--rodada", type=int, default=1)
    args.add_argument("--motivo", default="")
    args.add_argument("--ligar-dependencias", action="store_true")
    op = args.parse_args(argv[1:])
    relatorios = _pasta_trabalho(op.pasta) / str(op.id)
    try:
        if op.acao == "preparar":
            print(preparar(_raiz(op.pasta), op.pasta, op.id, _ref_auditada(op.pasta),
                           op.ligar_dependencias))
        elif op.acao == "congelar":
            print(congelar(op.pasta, op.id))
        elif op.acao == "julgar":
            ilegiveis = relatorios_ilegiveis(relatorios)
            if ilegiveis:
                # Falha do agente, não da correção: refaz o agente, não recusa o patch.
                print(f"ERRO   relatório ausente ou ilegível: {', '.join(ilegiveis)}. Rode de "
                      "novo esse agente, com um novo, sobre o mesmo stage.", file=sys.stderr)
                return 2
            verificador = _ler_relatorio(relatorios / "verificador.json")
            veredito = selar(op.pasta, op.id, julgar(
                verificador, _ler_relatorio(relatorios / "atacante.json"), op.rodada,
                ids_da_rodada(op.pasta, op.id)), verificador or {})
            (relatorios / "julgamento.json").write_text(
                json.dumps(veredito, ensure_ascii=False), encoding="utf-8")
            print(json.dumps(veredito, ensure_ascii=False))
        elif op.acao == "escrever":
            print(escrever(_raiz(op.pasta), op.pasta, op.id,
                           _ler_relatorio(relatorios / "julgamento.json") or {},
                           _ler_relatorio(relatorios / "verificador.json") or {}))
        elif op.acao == "recusar":
            print(registrar_recusa(op.pasta, op.id, op.motivo))
        elif op.acao == "remover":
            remover(_scratch(op.pasta, _validar_id(op.id)))
        else:
            print(indice(op.pasta))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"ERRO   {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
