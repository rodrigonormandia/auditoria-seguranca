"""Do JSONL do plugin ao PDF e às issues exportadas, com credencial no caminho."""

import json
import subprocess
import sys

import pytest

import apurar_votos as av
import importar_claude_security as ics
from conftest import SEGREDO_TESTE, git

pytest.importorskip("reportlab")
pytest.importorskip("matplotlib")
pypdf = pytest.importorskip("pypdf", reason="pip install pypdf para ler o PDF gerado")


def _rodar(projeto, script, *args):
    return subprocess.run([sys.executable, str(projeto.pasta / script), *args],
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          cwd=projeto.raiz)


def _jsonl(tmp_path, commit):
    relatorio = tmp_path / "CLAUDE-SECURITY-X"
    relatorio.mkdir()
    (relatorio / "CLAUDE-SECURITY-REVISION-x.json").write_text(
        json.dumps({"revision": {"commit": commit, "dirty": False}}), encoding="utf-8")
    regs = [{
        "title": "Token de produção no código", "impact": "acesso à API", "file": "src/conf.ts",
        "line": 1, "description": "O token está no fonte.", "exploit_scenario": "ROTEIRO-SECRETO",
        "preconditions": [], "severity": "HIGH", "confidence": "high",
        "recommendation": "Mover para o ambiente.", "cwe_id": "CWE-798",
        "snippet": f'export const token = "{SEGREDO_TESTE}";', "symbol": "token",
        "claudeSecurityPluginFindingId": "1:a",
    }, {
        "title": "Alegação que o painel derruba", "impact": "nenhum", "file": "src/app.ts",
        "line": 5, "description": "Suposta injeção.", "preconditions": [], "severity": "LOW",
        "confidence": "low", "recommendation": "n/a", "cwe_id": "CWE-89", "snippet": "db.users",
        "symbol": "atualizar", "claudeSecurityPluginFindingId": "1:b",
    }]
    caminho = relatorio / "CLAUDE-SECURITY-RESULTS.jsonl"
    caminho.write_text("".join(json.dumps(r) + "\n" for r in regs), encoding="utf-8")
    return caminho


def _votar(projeto, fingerprint, veredito, severidade=None):
    pasta = projeto.votos / av.slug(fingerprint)
    pasta.mkdir(parents=True, exist_ok=True)
    for lente in av.LENTES:
        voto = {"lente": lente, "veredito": veredito, "motivo": "decidido em src/app.ts:5"}
        if severidade:
            voto["severidade"] = severidade
        (pasta / f"{lente}.json").write_text(json.dumps(voto), encoding="utf-8")


def test_do_jsonl_ao_pdf_sem_vazar_credencial(projeto, tmp_path):
    (projeto.raiz / "src" / "conf.ts").write_text(
        f'export const token = "{SEGREDO_TESTE}";\n', encoding="utf-8")
    sha = projeto.commit()
    completo = git(projeto.raiz, "rev-parse", "HEAD")
    projeto.cabecalho(PERFIL="padrao", REF_FONTE=f"{sha} (árvore limpa)")

    # Segundo caçador
    candidatos = projeto.pasta / ".trabalho" / "candidatos"
    r = ics.importar(_jsonl(tmp_path, completo), candidatos, ref=sha)
    assert len(r["candidatos"]) == 2
    real, falso = (c["fingerprint"] for c in r["candidatos"])
    projeto.gravar_cobertura([{
        "id": "U1", "superficie": "s", "fronteira": "f", "subsistema": "x", "classe": "c",
        "status": "candidata", "caminhos": ["src"], "verificacao": "lida",
        "fingerprints": [real]}])

    # Painel
    _votar(projeto, real, "confirmado", "alta")
    _votar(projeto, falso, "descartado")
    apuracao = _rodar(projeto, "apurar_votos.py")
    assert apuracao.returncode == 0, apuracao.stdout + apuracao.stderr

    # Relator: parte do candidato e completa o que é dele
    reg = json.loads((candidatos / f"{av.slug(real)}.json").read_text(encoding="utf-8"))
    assert SEGREDO_TESTE not in json.dumps(reg)
    reg.update(categoria="1. Teste", probabilidade="alta", exploravel="Quem lê o repositório.",
               criterios=["O token sai do fonte."])
    reg.pop("origem")
    projeto.gravar_registro(reg)
    projeto.carregar()

    assert _rodar(projeto, "redigir.py").returncode == 0
    validacao = _rodar(projeto, "validar_findings.py")
    assert validacao.returncode == 0, validacao.stdout + validacao.stderr

    gerado = _rodar(projeto, "gerar_relatorio.py")
    assert gerado.returncode == 0, gerado.stdout + gerado.stderr
    pdf = pypdf.PdfReader(str(projeto.pasta / "relatorio-auditoria-seguranca.pdf"))
    texto = "\n".join(p.extract_text() for p in pdf.pages)
    assert "[REDACTED]" in texto
    assert SEGREDO_TESTE not in texto
    assert "ROTEIRO-SECRETO" not in texto
    assert "painel de 3 lentes: 2 de 2" in texto
    assert "Alegação que o painel derruba" in texto

    exportado = _rodar(projeto, "abrir_issues.py", "--exportar")
    assert exportado.returncode == 0, exportado.stdout + exportado.stderr
    corpos = [p.read_text(encoding="utf-8")
              for p in (projeto.pasta / ".trabalho" / "issues").glob("*.md")]
    assert len(corpos) == 1
    assert SEGREDO_TESTE not in corpos[0]
    assert "[REDACTED]" in corpos[0]
