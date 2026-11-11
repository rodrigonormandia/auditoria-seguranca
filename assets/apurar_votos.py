"""
Apura o painel de verificação: três votantes, uma lente cada, e o placar calculado em código.

    python docs/security-audit/apurar_votos.py    # índice JSON; sai 2 se houver painel incompleto

Voto: `votos/<slug>/<lente>.json` com {"lente", "veredito", "severidade", "motivo"}.
- 2 de 3 `confirmado` confirma; 2 de 3 `descartado` descarta; 2 de 3 `anterior` marca como
  anterior à mudança; 2 de 3 `endurecimento` vira nota informativa. Sem maioria, um voto de
  `endurecimento` sem fato externo em aberto resolve em endurecimento; o resto é `pendente`.
- Faltou lente, repetiu lente ou há voto inválido: `incompleto`. Refaça; incompleto nunca decide.
- Todo voto, exceto `pendente`, cita arquivo:linha no motivo. Sem citação, o voto é inválido.
- A severidade do registro não passa do teto dos votos confirmadores (só reduz). Confiança `alta`
  exige unanimidade.

Os registros `descartado`, `anterior` e `endurecimento` são gravados aqui, a partir do candidato e
dos motivos. Os demais são escritos pelo relator e conferidos no `validar_findings.py` contra este
mesmo placar.
"""

from __future__ import annotations

import json
import os
import re
import sys
from math import ceil

try:
    import redigir
except ImportError:  # pragma: no cover
    redigir = None

LENTES = ("alcance", "impacto", "defesas")
VEREDITOS = ("confirmado", "pendente", "descartado", "anterior", "endurecimento")
AUTOMATICOS = ("descartado", "anterior", "endurecimento")
ORDEM_SEVERIDADE = ("baixa", "media", "alta", "critica")
_CITACAO = re.compile(r"[\w./@()\[\]-]+:\d+")


def slug(fingerprint: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", fingerprint)


def _voto_valido(voto) -> bool:
    if not isinstance(voto, dict) or voto.get("lente") not in LENTES:
        return False
    veredito = voto.get("veredito")
    motivo = voto.get("motivo")
    if veredito not in VEREDITOS or not isinstance(motivo, str) or not motivo.strip():
        return False
    sev = voto.get("severidade")
    if sev is not None and sev not in ORDEM_SEVERIDADE:
        return False
    return veredito == "pendente" or _CITACAO.search(motivo) is not None


def _teto(confirmadores: list[dict]) -> str | None:
    notas = sorted((v["severidade"] for v in confirmadores if v.get("severidade")),
                   key=ORDEM_SEVERIDADE.index)
    return notas[ceil((len(notas) - 1) / 2)] if notas else None


def apurar(votos: list) -> dict:
    """Placar de um painel. `veredito` só existe com as três lentes em votos válidos."""
    validos = [v for v in votos if _voto_valido(v)]
    lentes = [v["lente"] for v in validos]
    completo = len(votos) == len(LENTES) and len(validos) == len(LENTES) \
        and sorted(lentes) == sorted(LENTES)
    placar = {v: sum(1 for x in validos if x["veredito"] == v) for v in VEREDITOS}
    if not completo:
        return {"estado": "incompleto", "veredito": None, "placar": placar,
                "severidade_teto": None, "confianca_maxima": None}
    if placar["confirmado"] >= 2:
        veredito = "confirmado"
    elif placar["descartado"] >= 2:
        veredito = "descartado"
    elif placar["anterior"] >= 2:
        veredito = "anterior"
    elif placar["endurecimento"] >= 2 or (
            placar["endurecimento"] == 1 and placar["pendente"] == 0 and placar["anterior"] == 0):
        veredito = "endurecimento"
    else:
        veredito = "pendente"
    confirmadores = [v for v in validos if v["veredito"] == "confirmado"]
    return {
        "estado": "completo", "veredito": veredito, "placar": placar,
        "severidade_teto": _teto(confirmadores) if veredito == "confirmado" else None,
        "confianca_maxima": "alta" if placar["confirmado"] == len(LENTES) else "media",
    }


def ler_votos(pasta: str, nome: str) -> list:
    """Votos de um painel. Arquivo ilegível entra como voto inválido: nunca é ignorado."""
    dir_votos = os.path.join(pasta, "votos", nome)
    if not os.path.isdir(dir_votos):
        return []
    votos = []
    for arquivo in sorted(os.listdir(dir_votos)):
        if not arquivo.endswith(".json"):
            continue
        try:
            with open(os.path.join(dir_votos, arquivo), encoding="utf-8") as f:
                votos.append(json.load(f))
        except (OSError, ValueError):
            votos.append(None)
    return votos


def conferir_registro(reg: dict, veredito: str, pasta: str) -> list[str]:
    """Erros entre o registro e o placar dos votos gravados."""
    fingerprint = reg.get("fingerprint")
    if not fingerprint:
        return ["registro sem fingerprint não tem painel"]
    votos = ler_votos(pasta, slug(fingerprint))
    r = apurar(votos)
    if r["estado"] != "completo":
        return [f"painel incompleto ({len(votos)} de {len(LENTES)} votos válidos exigidos)"]
    erros = []
    if redigir is None:
        erros.append("redigir.py ausente: votos não conferidos")
    elif any(redigir.achar_credenciais(s) for s in redigir.strings_de(votos)):
        erros.append("credencial no texto de um voto — rode redigir.py --aplicar")
    if r["veredito"] != veredito:
        erros.append(f"registro diz {veredito!r}, o placar diz {r['veredito']!r}")
    sev = reg.get("severidade")
    teto = r["severidade_teto"]
    if veredito == "confirmado" and teto and sev in ORDEM_SEVERIDADE \
            and ORDEM_SEVERIDADE.index(sev) > ORDEM_SEVERIDADE.index(teto):
        erros.append(f"severidade {sev!r} acima do teto {teto!r} dos votos")
    if reg.get("confianca") == "alta" and r["confianca_maxima"] != "alta":
        erros.append("confiança 'alta' exige unanimidade do painel")
    return erros


def citacoes(motivo: str) -> list[tuple[str, int]]:
    """(arquivo, linha) citados no motivo de um voto."""
    saida = []
    for trecho in _CITACAO.findall(str(motivo or "")):
        arquivo, linha = trecho.rsplit(":", 1)
        saida.append((arquivo, int(linha)))
    return saida


def placar_de(pasta: str, reg: dict) -> str | None:
    """'2/3' para o relatório, ou None sem painel completo."""
    if not reg.get("fingerprint"):
        return None
    r = apurar(ler_votos(pasta, slug(reg["fingerprint"])))
    if r["estado"] != "completo":
        return None
    return f'{max(r["placar"].values())}/{len(LENTES)}'


def carimbo(pasta: str, registros: list[dict], perfil: str) -> str:
    """Linha da capa, derivada dos votos gravados, nunca declarada."""
    if perfil not in ("padrao", "profunda"):
        return "1 verificador por candidato (sem painel)"
    completos = sum(1 for r in registros if placar_de(pasta, r))
    return f"painel de 3 lentes: {completos} de {len(registros)} registros com votos completos"


def _texto(valor) -> str:
    return valor.strip() if isinstance(valor, str) else ""


def _registro_automatico(candidato: dict, votos: list, veredito: str) -> dict:
    motivos = [v["motivo"].strip() for v in votos if v["veredito"] == veredito]
    if veredito == "endurecimento":
        return {
            "veredito": veredito,
            "fingerprint": candidato["fingerprint"],
            "titulo": _texto(candidato.get("titulo")) or candidato["fingerprint"],
            "categoria": _texto(candidato.get("categoria")) or "Endurecimento",
            "arquivo": _texto(candidato.get("arquivo")) or "desconhecido",
            "linha": str(candidato.get("linha") or ""),
            "descricao": " / ".join(motivos),
        }
    return {
        "veredito": veredito,
        "fingerprint": candidato["fingerprint"],
        "titulo": _texto(candidato.get("titulo")) or candidato["fingerprint"],
        "arquivo": _texto(candidato.get("arquivo")) or "desconhecido",
        "linha": str(candidato.get("linha") or ""),
        "causa_alegada": (_texto(candidato.get("causa_raiz"))
                          or _texto(candidato.get("causa_alegada"))
                          or _texto(candidato.get("descricao")) or "sem descrição"),
        "motivo": " / ".join(motivos),
    }


def processar(pasta: str) -> dict:
    """Apura todos os painéis e grava os registros que não dependem de redação."""
    dir_candidatos = os.path.join(pasta, ".trabalho", "candidatos")
    dir_votos = os.path.join(pasta, "votos")
    nomes = set()
    for base, extensao in ((dir_candidatos, ".json"), (dir_votos, "")):
        if os.path.isdir(base):
            nomes |= {n[:-len(extensao)] if extensao else n for n in os.listdir(base)
                      if not extensao or n.endswith(extensao)}
    saida: dict = {"paineis": {}, "incompletos": [], "registros_gravados": []}
    for nome in sorted(nomes):
        votos = ler_votos(pasta, nome)
        r = apurar(votos)
        saida["paineis"][nome] = r
        if r["estado"] != "completo":
            saida["incompletos"].append(nome)
            continue
        if r["veredito"] not in AUTOMATICOS:
            continue
        caminho = os.path.join(dir_candidatos, f"{nome}.json")
        if not os.path.exists(caminho):
            continue  # registro de rodada anterior, sem rascunho
        with open(caminho, encoding="utf-8") as f:
            candidato = json.load(f)
        reg = _registro_automatico(candidato, votos, r["veredito"])
        if redigir is not None:
            reg, _ = redigir.redigir_objeto(reg)
        os.makedirs(os.path.join(pasta, "registros"), exist_ok=True)
        destino = os.path.join(pasta, "registros", f"{nome}.json")
        with open(destino, "w", encoding="utf-8") as f:
            json.dump(reg, f, ensure_ascii=False, indent=2)
        saida["registros_gravados"].append(f"registros/{nome}.json")
    return saida


def main(argv: list[str]) -> int:
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(encoding="utf-8", errors="replace")
    pasta = argv[1] if len(argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    saida = processar(pasta)
    print(json.dumps(saida, ensure_ascii=False, indent=2))
    return 2 if saida["incompletos"] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
