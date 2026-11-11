"""
Detecta e redige credenciais nos registros da auditoria. Sem dependência externa.

    python docs/security-audit/redigir.py              # só conta; sai 1 se houver credencial
    python docs/security-audit/redigir.py --aplicar    # regrava registros/ e votos/

O relatório sai do repositório (PDF, issue), então o valor de uma credencial nunca entra nele:
o achado localiza a credencial por arquivo e linha e a evidência traz `[REDACTED]`. A detecção é
determinística e serve de trava no `validar_findings.py`. Nenhuma mensagem imprime o valor.

Falso positivo (chave pública por desenho, como a `anon` do Supabase): liste o valor exato em
`falso_positivo_redacao` no registro. O validador avisa, em vez de barrar.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Iterable

MARCA = "[REDACTED]"
CAMPO_EXCECOES = "falso_positivo_redacao"

_TEXTO = re.IGNORECASE | re.MULTILINE

# (tipo, expressão, grupo que contém o valor)
_CHAVES = (r"""(?:password|passwd|pwd|senha|secret|token|api[_-]?key|auth[_-]?key|access[_-]?key"""
           r"""|private[_-]?key|encryption[_-]?key|signing[_-]?key|service[_-]?(?:role|key)"""
           r"""|(?<![a-z])pass(?![a-z])|(?-i:[a-z]Pass)\b)""")
_CHAVES_ENV = (r"""(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ENCRYPTION_?KEY"""
               r"""|SIGNING_?KEY|SERVICE_?(?:ROLE|KEY))[A-Z0-9_]*|(?:[A-Z0-9]+_)*PASS)""")

_PADROES: list[tuple[str, "re.Pattern[str]", object]] = [
    ("chave privada", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\n|\s)*(?:[A-Za-z0-9+/=]{16,}(?:\\n|\s)*)+"
        r"(?:-----END [A-Z ]*PRIVATE KEY-----)?"), 0),
    ("chave AWS", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("token GitHub", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"), 0),
    ("chave sk", re.compile(r"\bsk-(?=[A-Za-z0-9_-]*[0-9])(?=[A-Za-z0-9_-]*[A-Z])[A-Za-z0-9_-]{20,}"), 0),
    ("chave Stripe", re.compile(r"\b(?:[sr]k_(?:live|test)_|whsec_)[A-Za-z0-9]{16,}\b"), 0),
    ("chave Supabase", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{16,}"), 0),
    ("token Slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), 0),
    ("chave Google", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0),
    ("chave SendGrid", re.compile(r"\bSG\.[\w-]{16,}\.[\w-]{16,}"), 0),
    ("chave Resend", re.compile(r"\bre_(?=[A-Za-z0-9_]*[0-9])(?=[A-Za-z0-9_]*[A-Z])[A-Za-z0-9_]{20,}\b"), 0),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), 0),
    ("senha em URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s\"'`<>]+)@", re.IGNORECASE), 1),
    ("Bearer", re.compile(r"\bbearer\s+([A-Za-z0-9._~+/=-]{16,})", re.IGNORECASE), 1),
    ("valor em atribuição", re.compile(
        r"[\w.-]*" + _CHAVES + r"""[\w-]*["']?\s*(?:=>|=|:)\s*"""
        r"""(?P<q>["'`])(?P<v>(?:\\.|(?!(?P=q))[^\\]){4,512}?)(?P=q)""",
        re.IGNORECASE | re.MULTILINE | re.DOTALL), "v"),
    ("valor em .env", re.compile(
        r"^[ \t]*(?:export[ \t]+)?" + _CHAVES_ENV + r"""=(?P<v>[^\s"'`$#][^\s"'`]{7,})""",
        re.MULTILINE), "v"),
    ("valor em YAML", re.compile(
        r"^[ \t]*(?:-[ \t]+)?" + _CHAVES_ENV + r":[ \t]+(?P<v>[^\s\"'`$#{\[][^\s\"'`]{7,})[ \t]*$",
        re.MULTILINE), "v"),
    ("valor em YAML", re.compile(
        r"^[ \t]*[\w.-]*" + _CHAVES + r"[\w-]*:[ \t]+(?=[^\s]*[0-9])"
        r"(?P<v>[A-Za-z0-9_+/=!@%^&*~-]{8,})[ \t]*$", re.IGNORECASE | re.MULTILINE), "v"),
]

_STAND_IN = re.compile(
    r"""^(?:\$\{.*\}|<.*>|\{\{.*\}\}|\[REDACTED\]|x{4,}|\*{4,}|\.{4,}"""
    r"""|your[_-].*|seu[_-].*|sua[_-].*|example.*|placeholder.*"""
    r"""|undefined|null|none|true|false|bearer|basic)$""",
    re.IGNORECASE)
_PORTA = re.compile(r"^\d{1,5}(?:/|$)")


def _e_stand_in(valor: str) -> bool:
    v = valor.strip()
    return (not v or MARCA in v or "${" in v or "$(" in v or "process.env" in v
            or "import.meta.env" in v or _STAND_IN.match(v) is not None
            or _PORTA.match(v) is not None)


def _ocorrencias(texto: str, permitidos: frozenset) -> list[tuple[int, int, str, str]]:
    """(início, fim, tipo, valor) sem sobreposição, das mais longas para as mais curtas."""
    achados = []
    for tipo, padrao, grupo in _PADROES:
        for m in padrao.finditer(texto):
            valor = m.group(grupo)
            if not valor or _e_stand_in(valor) or valor in permitidos:
                continue
            achados.append((m.start(grupo), m.end(grupo), tipo, valor))
    achados.sort(key=lambda a: (-(a[1] - a[0]), a[0]))
    escolhidos: list[tuple[int, int, str, str]] = []
    for a in achados:
        if all(a[1] <= b[0] or a[0] >= b[1] for b in escolhidos):
            escolhidos.append(a)
    return sorted(escolhidos)


def achar_credenciais(texto: str, permitidos: Iterable[str] = ()) -> list[tuple[str, str]]:
    """Lista (tipo, valor) de cada credencial no texto. Não imprima o valor."""
    return [(tipo, valor) for _, _, tipo, valor in _ocorrencias(texto, frozenset(permitidos))]


def redigir_texto(texto: str, permitidos: Iterable[str] = ()) -> tuple[str, int]:
    """Devolve o texto com cada valor trocado por `[REDACTED]` e quantos foram trocados."""
    ocorrencias = _ocorrencias(texto, frozenset(permitidos))
    for inicio, fim, _, _ in reversed(ocorrencias):
        texto = texto[:inicio] + MARCA + texto[fim:]
    return texto, len(ocorrencias)


def redigir_objeto(obj, permitidos: Iterable[str] = ()):
    """Redige os valores de dict/list/str, preservando chaves e a lista de exceções."""
    if isinstance(obj, str):
        return redigir_texto(obj, permitidos)
    if isinstance(obj, list):
        total, saida = 0, []
        for item in obj:
            novo, n = redigir_objeto(item, permitidos)
            saida.append(novo)
            total += n
        return saida, total
    if isinstance(obj, dict):
        total, saida = 0, {}
        for chave, valor in obj.items():
            if chave == CAMPO_EXCECOES:
                saida[chave] = valor
                continue
            novo, n = redigir_objeto(valor, permitidos)
            saida[chave] = novo
            total += n
        return saida, total
    return obj, 0


def strings_de(obj) -> Iterable[str]:
    """Todas as strings de um objeto, sem entrar na lista de exceções."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from strings_de(item)
    elif isinstance(obj, dict):
        for chave, valor in obj.items():
            if chave != CAMPO_EXCECOES:
                yield from strings_de(valor)


def _arquivos_json(pasta: str) -> list[str]:
    caminhos = []
    for sub in ("registros", "votos"):
        for raiz, _, nomes in os.walk(os.path.join(pasta, sub)):
            caminhos += [os.path.join(raiz, n) for n in nomes if n.endswith(".json")]
    return sorted(caminhos)


def processar(pasta: str, aplicar: bool) -> tuple[int, list[str]]:
    """Devolve (valores encontrados, arquivos onde restou credencial)."""
    total, restam = 0, []
    for caminho in _arquivos_json(pasta):
        with open(caminho, encoding="utf-8") as f:
            dado = json.load(f)
        permitidos = dado.get(CAMPO_EXCECOES, []) if isinstance(dado, dict) else []
        novo, n = redigir_objeto(dado, permitidos)
        if not n:
            continue
        total += n
        if aplicar:
            with open(caminho, "w", encoding="utf-8") as f:
                json.dump(novo, f, ensure_ascii=False, indent=2)
        else:
            restam.append(os.path.relpath(caminho, pasta))
    return total, restam


def main(argv: list[str]) -> int:
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(encoding="utf-8", errors="replace")
    args = [a for a in argv[1:] if a != "--aplicar"]
    aplicar = "--aplicar" in argv
    pasta = args[0] if args else os.path.dirname(os.path.abspath(__file__))
    total, restam = processar(pasta, aplicar)
    if aplicar:
        print(f"{total} valor(es) trocado(s) por {MARCA}")
        return 0
    for caminho in restam:
        print(f"credencial em {caminho}")
    print(f"{total} valor(es) encontrado(s); rode com --aplicar para redigir")
    return 1 if restam else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
