"""
Converte o relatório do plugin claude-security em candidatos da auditoria (segundo caçador).

    python docs/security-audit/importar_claude_security.py \\
        CLAUDE-SECURITY-<ts>/CLAUDE-SECURITY-RESULTS.jsonl --ref <sha>

Grava um arquivo por achado em `.trabalho/candidatos/` e imprime o mesmo índice JSON do caçador.
Daí em diante o candidato segue o caminho normal: painel, relator, revisão da correção e PDF.

O que o plugin descartou não está no JSONL e não vira `descartado`: silêncio dele não é refutação.
`exploit_scenario` fica de fora, porque o relatório é documento de correção, não roteiro de ataque.
`categoria` vem vazia: quem a escolhe é o relator, entre as entradas da METODOLOGIA.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys

try:
    import redigir
except ImportError:  # pragma: no cover
    redigir = None

SEVERIDADE = {"CRITICAL": "critica", "HIGH": "alta", "MEDIUM": "media", "LOW": "baixa"}
CONFIANCA = {"HIGH": "alta", "MEDIUM": "media", "LOW": "baixa"}
_PROIBIDAS = re.compile(r"\b(critica|alta|media|baixa|confirmado|pendente|descartado)\b", re.I)


def _slug(fingerprint: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", fingerprint)


def _fingerprint(arquivo: str, simbolo: str, cwe: str, trecho: str) -> str:
    """Estável entre rodadas: sem linha, e o hash do trecho separa dois destinos da mesma função."""
    sufixo = ""
    if trecho and trecho != "[REDACTED]":
        sufixo = "-" + hashlib.sha256(re.sub(r"\s+", " ", trecho).encode("utf-8")).hexdigest()[:8]
    bruto = f"{arquivo}:{simbolo or 'global'}:{(cwe or 'cwe-desconhecido').lower()}{sufixo}"
    limpo = re.sub(r"[^A-Za-z0-9._:/@+-]", "-", bruto)
    limpo = re.sub(r"^[^A-Za-z0-9._]+", "", limpo)
    # O validador recusa estas palavras para que o fingerprint não carregue veredito.
    return _PROIBIDAS.sub(lambda m: m.group(0) + "_", limpo)


def converter(registro: dict) -> dict:
    """Um candidato no formato da auditoria. ValueError se a severidade for desconhecida."""
    sev = str(registro.get("severity", "")).strip().upper()
    if sev not in SEVERIDADE:
        raise ValueError(f"severidade desconhecida: {registro.get('severity')!r}")
    arquivo = str(registro.get("file", "")).replace("\\", "/").strip()
    linha = registro.get("line") or 0
    simbolo = str(registro.get("symbol") or "").strip()
    cwe = str(registro.get("cwe_id") or "").strip()
    descricao = str(registro.get("description") or "").strip()
    condicoes = [str(c).strip() for c in registro.get("preconditions") or [] if str(c).strip()]
    recomendacao = str(registro.get("recommendation") or "").strip()
    if redigir is None:
        raise ValueError("redigir.py ausente: sem ele a importação não copia texto externo")
    trecho = redigir.redigir_texto(str(registro.get("snippet") or "").strip())[0]
    candidato = {
        "veredito": "confirmado",
        "fingerprint": _fingerprint(arquivo, simbolo, cwe, trecho),
        "titulo": str(registro.get("title") or "").strip(),
        "categoria": "",
        "severidade": SEVERIDADE[sev],
        "impacto_nivel": SEVERIDADE[sev],
        "confianca": CONFIANCA.get(str(registro.get("confidence", "")).strip().upper(), "baixa"),
        "arquivo": arquivo,
        "linha": str(linha),
        "descricao": descricao,
        "causa_raiz": descricao,
        "evidencia": str(registro.get("snippet") or "").strip() or "[REDACTED]",
        "impacto": str(registro.get("impact") or "").strip(),
        "condicao": "; ".join(condicoes),
        "correcao": [recomendacao] if recomendacao else [],
        "rastro": [{"tipo": "destino", "arquivo": arquivo, "linha": int(linha) or 1,
                    "descricao": simbolo or "ponto apontado pelo plugin"}],
        "cwe": cwe,
        "origem": "claude-security",
        "id_externo": str(registro.get("claudeSecurityPluginFindingId") or ""),
    }
    candidato, _ = redigir.redigir_objeto(candidato)
    return candidato


def _conferir_carimbo(jsonl: str, ref: str | None, aceitar_outro_commit: bool) -> None:
    if aceitar_outro_commit:
        return
    carimbos = glob.glob(os.path.join(glob.escape(os.path.dirname(os.path.abspath(jsonl))),
                                      "CLAUDE-SECURITY-REVISION-*.json"))
    if not carimbos:
        if ref:
            raise ValueError("relatório sem carimbo de revisão: não dá para saber o commit varrido")
        return
    with open(carimbos[0], encoding="utf-8-sig") as f:
        revisao = json.load(f).get("revision") or {}
    if revisao.get("dirty"):
        raise ValueError("relatório de árvore suja: pode citar código que não existe em commit")
    commit = str(revisao.get("commit") or "")
    if ref and not commit.startswith(ref) and not ref.startswith(commit or "?"):
        raise ValueError(f"o relatório varreu o commit {commit[:12]}, não {ref}")


def importar(jsonl, destino, ref: str | None = None,
             aceitar_outro_commit: bool = False) -> dict:
    """Grava os candidatos em `destino` e devolve {"candidatos": [...], "ignorados": [...]}."""
    jsonl, destino = str(jsonl), str(destino)
    _conferir_carimbo(jsonl, ref, aceitar_outro_commit)
    registros = []
    with open(jsonl, encoding="utf-8-sig") as f:
        for n, linha in enumerate(f, start=1):
            if not linha.strip():
                continue
            try:
                registro = json.loads(linha)
            except ValueError as exc:
                raise ValueError(f"JSON inválido na linha {n}: {exc}") from exc
            if not isinstance(registro, dict):
                raise ValueError(f"linha {n} não é um objeto JSON")
            registros.append(registro)
    # Converte tudo antes de gravar: erro no meio não deixa importação pela metade.
    convertidos = [converter(registro) for registro in registros]
    candidatos, ignorados = [], []
    for candidato in convertidos:
        nome = _slug(candidato["fingerprint"])
        caminho = os.path.join(destino, f"{nome}.json")
        local = f'{candidato["arquivo"]}:{candidato["linha"]}'
        if os.path.exists(caminho):
            ignorados.append({"fingerprint": candidato["fingerprint"], "local": local,
                              "motivo": "mesmo fingerprint de um candidato já gravado"})
            continue
        os.makedirs(destino, exist_ok=True)
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(candidato, f, ensure_ascii=False, indent=2)
        candidatos.append({
            "arquivo_candidato": f".trabalho/candidatos/{nome}.json",
            "fingerprint": candidato["fingerprint"], "titulo": candidato["titulo"],
            "veredito_proposto": "confirmado", "severidade": candidato["severidade"],
            "local": local,
        })
    return {"candidatos": candidatos, "ignorados": ignorados}


def main(argv: list[str]) -> int:
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(encoding="utf-8", errors="replace")
    aqui = os.path.dirname(os.path.abspath(__file__))
    args = argparse.ArgumentParser(description="Importa o JSONL do claude-security.")
    args.add_argument("jsonl")
    args.add_argument("--destino", default=os.path.join(aqui, ".trabalho", "candidatos"))
    args.add_argument("--ref", help="commit auditado; o relatório tem de ser desse commit")
    args.add_argument("--aceitar-outro-commit", action="store_true")
    opcoes = args.parse_args(argv[1:])
    try:
        saida = importar(opcoes.jsonl, opcoes.destino, opcoes.ref, opcoes.aceitar_outro_commit)
    except (OSError, ValueError) as exc:
        print(f"ERRO   {exc}", file=sys.stderr)
        return 1
    print(json.dumps(saida, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
