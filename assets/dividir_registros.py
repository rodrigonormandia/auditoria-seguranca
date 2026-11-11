"""
Divide um conjunto de registros num arquivo por registro, em `registros/<slug>.json`.

Serve para dois casos, ambos mecânicos (o script não contém nem altera texto de achado):
  1. migrar um `findings.py` antigo, que tinha ACHADOS/PENDENTES_VALIDACAO/DESCARTADOS
     embutidos, para o formato de um arquivo por registro;
  2. aproveitar um JSON intermediário de uma rodada interrompida (lista de registros, ou
     um objeto com listas como "achados", "pendentes", "descartados").

Uso:
    python dividir_registros.py <origem.json | findings_antigo.py> [pasta_registros]

Sem o segundo argumento, grava em `registros/` ao lado deste script. Não sobrescreve
arquivo existente (use --forcar). O veredito vem do campo "veredito", do nome da lista
de origem ou, na falta, dos campos do registro (severidade → confirmado, bloqueadores →
pendente, motivo → descartado). Campos vazios e o bloco "reproducao" não são copiados.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys

LISTAS = {
    "confirmado": ("ACHADOS", "achados", "confirmados", "confirmado"),
    "pendente": ("PENDENTES_VALIDACAO", "pendentes", "pendentes_validacao", "pendente"),
    "descartado": ("DESCARTADOS", "descartados", "descartado"),
}
FORA = {"reproducao", "veredito_proposto", "decisao"}


def slug(reg: dict, n: int) -> str:
    base = reg.get("fingerprint") or reg.get("id") or f"registro-{n}"
    return re.sub(r"[^A-Za-z0-9._-]", "-", str(base))


def inferir(reg: dict) -> str | None:
    v = reg.get("veredito") or reg.get("decisao") or reg.get("veredito_proposto")
    if v in LISTAS:
        return v
    if reg.get("severidade"):
        return "confirmado"
    if reg.get("bloqueadores"):
        return "pendente"
    if reg.get("motivo"):
        return "descartado"
    return None


def coletar(origem: str) -> list[tuple[str | None, dict]]:
    if origem.endswith(".py"):
        spec = importlib.util.spec_from_file_location("findings_antigo", origem)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        dados = {nome: getattr(mod, nome) for nomes in LISTAS.values() for nome in nomes
                 if hasattr(mod, nome)}
    else:
        with open(origem, encoding="utf-8") as f:
            dados = json.load(f)

    pares: list[tuple[str | None, dict]] = []
    if isinstance(dados, list):
        pares = [(None, r) for r in dados if isinstance(r, dict)]
    elif isinstance(dados, dict):
        for veredito, nomes in LISTAS.items():
            for nome in nomes:
                for r in dados.get(nome) or []:
                    if isinstance(r, dict):
                        pares.append((veredito, r))
    return pares


def main(argv: list[str]) -> int:
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(encoding="utf-8", errors="replace")
    args = [a for a in argv[1:] if a != "--forcar"]
    forcar = "--forcar" in argv
    if not args:
        print(__doc__)
        return 1
    origem = args[0]
    destino = args[1] if len(args) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "registros")
    os.makedirs(destino, exist_ok=True)

    gravados = pulados = sem_veredito = 0
    for n, (veredito, reg) in enumerate(coletar(origem), start=1):
        veredito = veredito or inferir(reg)
        if veredito is None:
            sem_veredito += 1
            print(f"sem veredito, ignorado: {reg.get('id') or reg.get('titulo') or n}")
            continue
        limpo = {"veredito": veredito}
        limpo.update({k: v for k, v in reg.items()
                      if k not in FORA and k != "veredito" and v not in ("", None, [], {})})
        if veredito != "confirmado":
            limpo.pop("condicao", None)
        elif "condicao" not in limpo and "condicao" in reg:
            limpo["condicao"] = ""
        caminho = os.path.join(destino, slug(reg, n) + ".json")
        if os.path.exists(caminho) and not forcar:
            pulados += 1
            continue
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(limpo, f, ensure_ascii=False, indent=1)
            f.write("\n")
        gravados += 1

    print(f"{gravados} registro(s) gravado(s) em {destino}; {pulados} já existiam; "
          f"{sem_veredito} sem veredito")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
