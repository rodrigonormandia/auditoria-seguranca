import json
import subprocess
import sys

import pytest

import importar_claude_security as ics
from conftest import SEGREDO_TESTE


def registro(**campos):
    base = {
        "id": "F1", "title": "SQL injetado", "impact": "lê a tabela", "file": "api/x.ts",
        "line": 12, "description": "concatena", "exploit_scenario": "PASSO-A-PASSO-PROIBIDO",
        "preconditions": ["autenticado", "plano pago"], "category": "CWE-74", "severity": "HIGH",
        "confidence": "medium", "recommendation": "parametrizar", "cwe_id": "CWE-89",
        "snippet": "db.query(sql)", "symbol": "buscar", "declared_line": 12, "via_change": None,
        "other_cwe_ids": ["CWE-20"], "claudeSecurityPluginFindingId": "1:abc",
    }
    base.update(campos)
    return base


def _jsonl(tmp_path, regs, commit=None):
    relatorio = tmp_path / "CLAUDE-SECURITY-20261031-120000"
    relatorio.mkdir(exist_ok=True)
    caminho = relatorio / "CLAUDE-SECURITY-RESULTS.jsonl"
    caminho.write_text("".join(json.dumps(r) + "\n" for r in regs), encoding="utf-8")
    if commit:
        (relatorio / f"CLAUDE-SECURITY-REVISION-{commit[:12]}.json").write_text(
            json.dumps({"revision": {"commit": commit, "dirty": False}}), encoding="utf-8")
    return caminho


def test_mapa_de_campos():
    c = ics.converter(registro())
    assert c["veredito"] == "confirmado"
    assert c["severidade"] == c["impacto_nivel"] == "alta"
    assert c["confianca"] == "media"
    assert (c["arquivo"], c["linha"]) == ("api/x.ts", "12")
    assert c["titulo"] == "SQL injetado"
    assert c["descricao"] == c["causa_raiz"] == "concatena"
    assert c["impacto"] == "lê a tabela"
    assert c["condicao"] == "autenticado; plano pago"
    assert c["correcao"] == ["parametrizar"]
    assert c["evidencia"] == "db.query(sql)"
    assert c["cwe"] == "CWE-89"
    assert c["categoria"] == ""
    assert c["origem"] == "claude-security"
    assert c["id_externo"] == "1:abc"
    assert c["rastro"] == [{"tipo": "destino", "arquivo": "api/x.ts", "linha": 12,
                            "descricao": "buscar"}]
    assert c["fingerprint"].startswith("api/x.ts:buscar:cwe-89-")


def test_roteiro_de_exploracao_nao_entra():
    assert "PROIBIDO" not in json.dumps(ics.converter(registro()))


@pytest.mark.parametrize("sev,esperado", [("CRITICAL", "critica"), ("high", "alta"),
                                          ("Medium", "media"), (" LOW ", "baixa")])
def test_severidade_em_qualquer_caixa(sev, esperado):
    assert ics.converter(registro(severity=sev))["severidade"] == esperado


def test_severidade_desconhecida_para():
    with pytest.raises(ValueError):
        ics.converter(registro(severity="URGENTE"))


def test_caminho_windows_e_rota_com_colchetes():
    c = ics.converter(registro(file="src\\pages\\[id].tsx", symbol="Pagina<T>"))
    assert c["arquivo"] == "src/pages/[id].tsx"
    import validar_findings as v
    assert v.FINGERPRINT.match(c["fingerprint"])
    assert not v.FINGERPRINT_PROIBIDO.search(c["fingerprint"])


def test_simbolo_com_palavra_de_severidade_nao_quebra_fingerprint():
    import validar_findings as v
    c = ics.converter(registro(symbol="alta"))
    assert not v.FINGERPRINT_PROIBIDO.search(c["fingerprint"])


def test_sem_simbolo_usa_arquivo_e_cwe():
    fp = ics.converter(registro(symbol="", snippet=""))["fingerprint"]
    assert fp == "api/x.ts:global:cwe-89"


def test_dois_destinos_da_mesma_funcao_nao_colidem(tmp_path):
    r = ics.importar(_jsonl(tmp_path, [registro(line=140, snippet="html += nome"),
                                       registro(line=195, snippet="html += patrimonio")]),
                     tmp_path / "c")
    assert len(r["candidatos"]) == 2
    assert r["ignorados"] == []


def test_fingerprint_nao_depende_da_linha():
    assert ics.converter(registro(line=10))["fingerprint"] ==         ics.converter(registro(line=99))["fingerprint"]


def test_snippet_vazio_vira_redacted():
    assert ics.converter(registro(snippet=""))["evidencia"] == "[REDACTED]"


def test_credencial_e_redigida():
    c = ics.converter(registro(description=f"usa {SEGREDO_TESTE}", snippet=f"t='{SEGREDO_TESTE}'"))
    assert SEGREDO_TESTE not in json.dumps(c)


def test_grava_candidatos_e_devolve_indice(tmp_path):
    destino = tmp_path / "candidatos"
    r = ics.importar(_jsonl(tmp_path, [registro()]), destino)
    assert r["ignorados"] == []
    item = r["candidatos"][0]
    assert item["veredito_proposto"] == "confirmado"
    assert item["local"] == "api/x.ts:12"
    nome = item["arquivo_candidato"].rsplit("/", 1)[-1]
    gravado = json.loads((destino / nome).read_text(encoding="utf-8"))
    assert gravado["fingerprint"] == item["fingerprint"]


def test_candidato_repetido_e_ignorado(tmp_path):
    destino = tmp_path / "candidatos"
    r = ics.importar(_jsonl(tmp_path, [registro(), registro(line=13)]), destino)
    assert len(r["candidatos"]) == 1
    assert r["ignorados"][0]["motivo"].startswith("mesmo fingerprint")
    r2 = ics.importar(_jsonl(tmp_path, [registro()]), destino)
    assert r2["candidatos"] == []
    assert len(r2["ignorados"]) == 1


def test_json_quebrado_para_com_a_linha(tmp_path):
    caminho = _jsonl(tmp_path, [registro()])
    caminho.write_text(caminho.read_text(encoding="utf-8") + "{quebrado\n", encoding="utf-8")
    with pytest.raises(ValueError, match="linha 2"):
        ics.importar(caminho, tmp_path / "c")


def test_outro_commit_recusa_sem_aceite(tmp_path):
    caminho = _jsonl(tmp_path, [registro()], commit="a" * 40)
    with pytest.raises(ValueError, match="commit"):
        ics.importar(caminho, tmp_path / "c", ref="b" * 7)
    r = ics.importar(caminho, tmp_path / "c", ref="b" * 7, aceitar_outro_commit=True)
    assert len(r["candidatos"]) == 1


def test_mesmo_commit_abreviado_passa(tmp_path):
    caminho = _jsonl(tmp_path, [registro()], commit="abcdef1" + "0" * 33)
    assert len(ics.importar(caminho, tmp_path / "c", ref="abcdef1")["candidatos"]) == 1


def test_relatorio_sujo_recusa_sem_aceite(tmp_path):
    caminho = _jsonl(tmp_path, [registro()])
    (caminho.parent / "CLAUDE-SECURITY-REVISION-abc-dirty.json").write_text(
        json.dumps({"revision": {"commit": "a" * 40, "dirty": True}}), encoding="utf-8")
    with pytest.raises(ValueError, match="sujo|suja"):
        ics.importar(caminho, tmp_path / "c", ref="a" * 7)


def test_jsonl_vazio_nao_cria_descartado(tmp_path):
    destino = tmp_path / "c"
    r = ics.importar(_jsonl(tmp_path, []), destino)
    assert r == {"candidatos": [], "ignorados": []}
    assert not list(destino.glob("*.json")) if destino.exists() else True


def test_cli(tmp_path):
    from conftest import ASSETS
    caminho = _jsonl(tmp_path, [registro()])
    destino = tmp_path / "saida"
    r = subprocess.run([sys.executable, str(ASSETS / "importar_claude_security.py"), str(caminho),
                        "--destino", str(destino)], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    assert r.returncode == 0, r.stdout + r.stderr
    assert len(json.loads(r.stdout)["candidatos"]) == 1
