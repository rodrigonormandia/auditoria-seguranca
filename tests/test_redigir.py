import json
import subprocess
import sys

import pytest

import redigir
from conftest import SEGREDO_TESTE, achado

CHAVE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
JWT = ("eyJhbGciOiJIUzI1NiJ9." + "eyJyb2xlIjoiYW5vbiJ9." + "c2lnbmF0dXJhLWZpY3RpY2lh")


@pytest.mark.parametrize("texto", [
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEabcdefghijklmnop1234\n-----END RSA PRIVATE KEY-----",
    f"chave {CHAVE_AWS} aqui",
    f"token {SEGREDO_TESTE}",
    "sk-" + "abcdefghijKLMNOPqrstuvwx1234",
    "sk_live_" + "abcdefghijklmnop1234",
    "whsec_" + "abcdefghijklmnop1234",
    "xoxb-" + "1234567890-abcdefghij",
    JWT,
    "Authorization: Bearer abcdefghijklmnop1234567890",
    'password: "x1y2z3w4"',
    "const senha = 'changeme';",
    'API_KEY="naoEhPlaceholder123"',
    "DB_PASSWORD=semAspas12345",
    "export SECRET_TOKEN=semAspas12345",
])
def test_detecta_credencial(texto):
    assert redigir.achar_credenciais(texto), texto


@pytest.mark.parametrize("texto", [
    'password: "${DB_PASSWORD}"',
    'api_key: "<your-token>"',
    'token: "{{ secrets.TOKEN }}"',
    "const k = process.env.API_KEY;",
    "const k = import.meta.env.VITE_KEY;",
    'password: "[REDACTED]"',
    "password: string",
    "postgres://user:[REDACTED]@host/db",
    "O campo password é obrigatório no formulário.",
    'secret: "xxxxxxxx"',
    "`token=${valor}`",
])
def test_nao_detecta_stand_in(texto):
    assert redigir.achar_credenciais(texto) == [], texto


def test_url_redige_so_a_senha():
    saida, n = redigir.redigir_texto("postgres://admin:s3nh4F0rte@db.interno:5432/app")
    assert n == 1
    assert saida == "postgres://admin:[REDACTED]@db.interno:5432/app"


def test_atribuicao_preserva_nome_e_aspas():
    saida, _ = redigir.redigir_texto('const senha = "abc12345";')
    assert saida == 'const senha = "[REDACTED]";'


def test_permitido_nao_e_redigido():
    assert redigir.achar_credenciais(JWT, permitidos=[JWT]) == []


def test_redigir_objeto_preserva_chaves_e_lista_de_excecoes():
    obj = {"token": "normal", "evidencia": f"x {SEGREDO_TESTE}", "lista": [f"{CHAVE_AWS}"],
           "falso_positivo_redacao": [JWT]}
    saida, n = redigir.redigir_objeto(obj)
    assert n == 2
    assert SEGREDO_TESTE not in json.dumps(saida)
    assert saida["falso_positivo_redacao"] == [JWT]
    assert "token" in saida


@pytest.mark.parametrize("campo", ["evidencia", "descricao"])
def test_validador_barra_credencial_sem_imprimir_valor(projeto, campo):
    valor = f"const t = '{SEGREDO_TESTE}';"
    projeto.gravar_registro(achado(**{campo: valor}))
    erros, _ = projeto.validar()
    assert any("credencial" in e for e in erros), erros
    assert not any(SEGREDO_TESTE in e for e in erros)


def test_validador_barra_credencial_no_rastro(projeto):
    projeto.gravar_registro(achado(rastro=[
        {"tipo": "destino", "arquivo": "src/app.ts", "linha": 5,
         "descricao": f"usa {SEGREDO_TESTE}"}]))
    erros, _ = projeto.validar()
    assert any("credencial" in e for e in erros), erros


def test_validador_barra_credencial_no_cabecalho(projeto):
    projeto.cabecalho(RESUMO=[f"chave {CHAVE_AWS}"],
                      PONTOS_FORTES=[("Título", f"texto {SEGREDO_TESTE}")])
    erros, _ = projeto.validar()
    assert sum("credencial" in e for e in erros) >= 2, erros


def test_validador_barra_credencial_na_cobertura(projeto):
    projeto.gravar_cobertura([{
        "id": "U1", "superficie": "s", "fronteira": "f", "subsistema": "x", "classe": "c",
        "status": "coberta", "caminhos": ["src"], "verificacao": f"vi {SEGREDO_TESTE}"}])
    erros, _ = projeto.validar()
    assert any("credencial" in e for e in erros), erros


def test_falso_positivo_declarado_vira_aviso(projeto):
    projeto.gravar_registro(achado(descricao=f"chave anon {JWT}",
                                   falso_positivo_redacao=[JWT]))
    erros, avisos = projeto.validar()
    assert not any("credencial" in e for e in erros), erros
    assert any("falso_positivo_redacao" in a for a in avisos)


def test_validador_falha_fechado_sem_redigir(projeto, monkeypatch):
    import validar_findings
    monkeypatch.setattr(validar_findings, "redigir", None)
    erros, _ = projeto.validar()
    assert any("redigir.py" in e for e in erros)


def test_abrir_issues_recusa_com_credencial(projeto):
    projeto.gravar_registro(achado(evidencia=f"const t = '{SEGREDO_TESTE}';"))
    projeto.carregar()
    r = subprocess.run([sys.executable, str(projeto.pasta / "abrir_issues.py"), "--exportar"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       cwd=projeto.raiz)
    assert r.returncode != 0 or "BLOQUEADO" in r.stdout
    pasta = projeto.pasta / ".trabalho" / "issues"
    assert not pasta.exists() or not list(pasta.glob("*.md"))


def test_cli_conta_e_aplica(projeto):
    caminho = projeto.gravar_registro(achado(evidencia=f"const t = '{SEGREDO_TESTE}';"))
    cmd = [sys.executable, str(projeto.pasta / "redigir.py"), str(projeto.pasta)]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert r.returncode == 1
    assert SEGREDO_TESTE not in r.stdout + r.stderr
    assert SEGREDO_TESTE in caminho.read_text(encoding="utf-8")
    r = subprocess.run(cmd + ["--aplicar"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    assert r.returncode == 0, r.stdout + r.stderr
    assert SEGREDO_TESTE not in caminho.read_text(encoding="utf-8")
    assert "[REDACTED]" in caminho.read_text(encoding="utf-8")
