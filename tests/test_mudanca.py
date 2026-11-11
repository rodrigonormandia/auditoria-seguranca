import subprocess
import sys

from conftest import achado, git


def _mudanca(projeto):
    base = projeto.sha
    arquivo = projeto.raiz / "src" / "app.ts"
    arquivo.write_text(arquivo.read_text(encoding="utf-8") + "// nova linha\n", encoding="utf-8")
    (projeto.raiz / "src" / "outro.ts").write_text("export {};\n", encoding="utf-8")
    head = projeto.commit()
    git(projeto.raiz, "rm", "-q", "src/outro.ts")
    projeto.commit()
    git(projeto.raiz, "reset", "-q", "--hard", head)
    projeto.sha = head
    projeto.cabecalho(MUDANCA={"base": base, "head": head})
    return base, head


def test_sem_mudanca_nada_e_cobrado(projeto):
    projeto.gravar_registro(achado())
    erros, _ = projeto.validar()
    assert erros == [], erros


def test_via_mudanca_ausente_e_erro(projeto):
    _mudanca(projeto)
    projeto.gravar_registro(achado())
    erros, _ = projeto.validar()
    assert any("via_mudanca" in e for e in erros), erros


def test_via_mudanca_em_arquivo_alterado_passa(projeto):
    _mudanca(projeto)
    projeto.gravar_registro(achado(via_mudanca="src/app.ts:8 expõe o handler"))
    erros, _ = projeto.validar()
    assert erros == [], erros


def test_via_mudanca_fora_do_diff_e_erro(projeto):
    _mudanca(projeto)
    projeto.gravar_registro(achado(via_mudanca="src/naomudou.ts:1 expõe o handler"))
    erros, _ = projeto.validar()
    assert any("via_mudanca" in e for e in erros), erros


def test_via_mudanca_sem_formato_e_erro(projeto):
    _mudanca(projeto)
    projeto.gravar_registro(achado(via_mudanca="a mudança expõe o handler"))
    erros, _ = projeto.validar()
    assert any("via_mudanca" in e for e in erros), erros


def test_mudanca_com_sha_invalido_e_erro(projeto):
    projeto.cabecalho(MUDANCA={"base": "main; rm -rf", "head": projeto.sha})
    erros, _ = projeto.validar()
    assert any("MUDANCA" in e for e in erros), erros


def _anterior(**campos):
    base = {"veredito": "anterior", "fingerprint": "src/app.ts:atualizar:antiga", "titulo": "t",
            "arquivo": "src/app.ts", "linha": "5", "causa_alegada": "c", "motivo": "m"}
    base.update(campos)
    return base


def test_anterior_carrega_com_prefixo_x(projeto):
    projeto.gravar_registro(_anterior())
    assert [r["id"] for r in projeto.carregar().ANTERIORES] == ["X1"]
    erros, _ = projeto.validar()
    assert erros == [], erros


def test_anterior_nao_tem_severidade(projeto):
    projeto.gravar_registro(_anterior(severidade="alta"))
    erros, _ = projeto.validar()
    assert any("anterior" in e.lower() for e in erros), erros


def test_anterior_nao_vira_issue(projeto):
    projeto.gravar_registro(_anterior())
    projeto.carregar()
    r = subprocess.run([sys.executable, str(projeto.pasta / "abrir_issues.py"), "--exportar"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       cwd=projeto.raiz)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not list((projeto.pasta / ".trabalho" / "issues").glob("*.md"))


def test_cwe_invalido_e_erro(projeto):
    projeto.gravar_registro(achado(cwe="XSS"))
    erros, _ = projeto.validar()
    assert any("cwe" in e for e in erros), erros
    projeto.gravar_registro(achado(cwe="CWE-79"))
    erros, _ = projeto.validar()
    assert erros == [], erros
