"""Fixtura: um projeto git mínimo com docs/security-audit/ montado a partir de assets/."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ASSETS = Path(__file__).resolve().parent.parent / "assets"
sys.path.insert(0, str(ASSETS))

FONTE_APP = """\
import { db } from "./db";

export async function atualizar(req, res) {
  const dados = req.body;
  await db.users.update({ where: { id: req.params.id }, data: dados });
  res.json({ ok: true });
}
"""

SEGREDO_TESTE = "ghp_" + "a1B2c3D4e5F6" * 3 + "abcd"


def git(raiz, *args, entrada=None):
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(
        ["git", "-C", str(raiz), "-c", "core.autocrlf=false", *args], input=entrada,
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=True, env=env,
    ).stdout.strip()


class Projeto:
    def __init__(self, raiz: Path):
        self.raiz = raiz
        self.pasta = raiz / "docs" / "security-audit"
        self.registros = self.pasta / "registros"
        self.votos = self.pasta / "votos"
        self.sha = ""
        self._cabecalho: dict = {}

    def commit(self, mensagem="c"):
        git(self.raiz, "add", "-A")
        git(self.raiz, "commit", "-q", "-m", mensagem)
        self.sha = git(self.raiz, "rev-parse", "HEAD")[:7]
        return self.sha

    def cabecalho(self, **campos):
        """Sobrescreve variáveis do findings.py (PERFIL, REF_FONTE, EXCLUSOES...)."""
        self._cabecalho.update(campos)
        return self

    def _escrever_findings(self):
        base = {
            "PROJETO": "Teste", "DATA_AUDITORIA": "31 de outubro de 2026",
            "PERFIL": "rapida", "REF_FONTE": f"{self.sha} (árvore limpa)",
            "METODOLOGIA": [("1. Teste", "mapeado")],
            "PONTOS_FORTES": [("Algo", "Verificado.")],
            "RESUMO": ["{total} {criticos} {pendentes}"],
        }
        base.update(self._cabecalho)
        texto = (ASSETS / "findings_template.py").read_text(encoding="utf-8")
        marcador = "# ─────────────────────────────────────────────────────────────────────────────\n# Carregador"
        cabeca, carregador = texto.split(marcador, 1)
        extra = "".join(f"{k} = {v!r}\n" for k, v in base.items())
        (self.pasta / "findings.py").write_text(
            cabeca + extra + marcador + carregador, encoding="utf-8")

    def gravar_registro(self, reg: dict, nome: str | None = None) -> Path:
        self.registros.mkdir(parents=True, exist_ok=True)
        slug = nome or "".join(c if c.isalnum() or c in "._-" else "-" for c in reg["fingerprint"])
        caminho = self.registros / f"{slug}.json"
        caminho.write_text(json.dumps(reg, ensure_ascii=False, indent=2), encoding="utf-8")
        return caminho

    def gravar_cobertura(self, unidades: list[dict]):
        (self.pasta / "cobertura.json").write_text(
            json.dumps(unidades, ensure_ascii=False), encoding="utf-8")

    def carregar(self):
        self._escrever_findings()
        nome = f"findings_{abs(hash((str(self.raiz), os.urandom(4))))}"
        spec = importlib.util.spec_from_file_location(nome, self.pasta / "findings.py")
        modulo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(modulo)
        return modulo

    def validar(self):
        import validar_findings
        return validar_findings.validar(self.carregar())


def achado(**campos) -> dict:
    base = {
        "veredito": "confirmado",
        "fingerprint": "src/app.ts:atualizar:mass-assignment",
        "titulo": "Update aceita o corpo inteiro",
        "categoria": "1. Teste",
        "severidade": "alta", "probabilidade": "alta", "impacto_nivel": "alta",
        "confianca": "alta",
        "arquivo": "src/app.ts", "linha": "5",
        "descricao": "O handler repassa o corpo ao ORM.",
        "evidencia": "await db.users.update({ where: { id: req.params.id }, data: dados });",
        "exploravel": "Usuário autenticado alcança o handler.",
        "impacto": "Alteração de campos protegidos.",
        "correcao": ["Restringir os campos."],
        "criterios": ["Teste de regressão rejeita role no corpo."],
    }
    base.update(campos)
    return base


@pytest.fixture
def projeto(tmp_path) -> Projeto:
    raiz = tmp_path / "repo"
    (raiz / "src").mkdir(parents=True)
    (raiz / "src" / "app.ts").write_text(FONTE_APP, encoding="utf-8", newline="\n")
    git(raiz.parent, "init", "-q", str(raiz))
    git(raiz, "config", "user.email", "t@t.t")
    git(raiz, "config", "user.name", "t")
    pasta = raiz / "docs" / "security-audit"
    pasta.mkdir(parents=True)
    for arq in ASSETS.glob("*.py"):
        shutil.copy(arq, pasta / arq.name)
    p = Projeto(raiz)
    (raiz / ".gitignore").write_text("docs/security-audit/\n", encoding="utf-8")
    p.commit()
    return p
