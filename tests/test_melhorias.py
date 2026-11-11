"""Correções aprovadas depois do teste real: endurecimento, outro_achado e layout do PDF."""

import json
import subprocess
import sys

import pytest

import apurar_votos as av
import patches
from conftest import achado
from test_apurar_votos import _candidato, _gravar_votos, _rodar_cli, painel, voto


# ── Saída `endurecimento` do painel ─────────────────────────────────────────

def test_dois_votos_de_endurecimento_decidem():
    assert av.apurar(painel("endurecimento", "endurecimento", "confirmado"))["veredito"] \
        == "endurecimento"


def test_um_de_cada_sem_pendente_fica_em_endurecimento():
    assert av.apurar(painel("confirmado", "descartado", "endurecimento"))["veredito"] \
        == "endurecimento"


def test_com_fato_externo_em_aberto_continua_pendente():
    assert av.apurar(painel("pendente", "descartado", "endurecimento"))["veredito"] == "pendente"


def test_voto_de_endurecimento_precisa_citar_linha():
    votos = painel("endurecimento", "endurecimento", "endurecimento")
    votos[0]["motivo"] = "parece só higiene"
    assert av.apurar(votos)["estado"] == "incompleto"


def test_cli_grava_endurecimento_e_ele_vira_informativo(projeto):
    fp = "src/app.ts:atualizar:higiene"
    _candidato(projeto, fp, categoria="1. Teste", descricao="Prefixo curto no log.")
    _gravar_votos(projeto, fp, painel("endurecimento", "endurecimento", "confirmado"))
    r = _rodar_cli(projeto)
    assert r.returncode == 0, r.stdout + r.stderr
    reg = json.loads((projeto.registros / f"{av.slug(fp)}.json").read_text(encoding="utf-8"))
    assert reg["veredito"] == "endurecimento"
    assert "src/app.ts:5" in reg["descricao"]
    assert "severidade" not in reg
    modulo = projeto.carregar()
    assert [i["id"] for i in modulo.INFORMATIVOS] == ["I1"]
    assert modulo.ACHADOS == []


def test_endurecimento_passa_no_painel_do_perfil_padrao(projeto):
    fp = "src/app.ts:atualizar:higiene"
    _candidato(projeto, fp, categoria="1. Teste")
    _gravar_votos(projeto, fp, painel("endurecimento", "endurecimento", "endurecimento"))
    _rodar_cli(projeto)
    projeto.cabecalho(PERFIL="padrao")
    projeto.gravar_cobertura([{
        "id": "U1", "superficie": "s", "fronteira": "f", "subsistema": "x", "classe": "c",
        "status": "candidata", "caminhos": ["src"], "verificacao": "lida", "fingerprints": [fp]}])
    erros, _ = projeto.validar()
    assert erros == [], erros


def test_registro_confirmado_nao_pode_divergir_de_endurecimento(projeto):
    projeto.cabecalho(PERFIL="padrao")
    reg = achado()
    projeto.gravar_registro(reg)
    _gravar_votos(projeto, reg["fingerprint"],
                  painel("endurecimento", "endurecimento", "confirmado"))
    erros, _ = projeto.validar()
    assert any("painel" in e and "endurecimento" in e for e in erros), erros


def test_candidato_sem_categoria_vira_endurecimento_valido(projeto):
    fp = "src/app.ts:atualizar:sem-categoria"
    _candidato(projeto, fp)
    _gravar_votos(projeto, fp, painel("endurecimento", "endurecimento", "endurecimento"))
    _rodar_cli(projeto)
    erros, _ = projeto.validar()
    assert erros == [], erros


def test_id_de_informativo_do_cabecalho_nao_colide(projeto):
    fp = "src/app.ts:atualizar:higiene"
    _candidato(projeto, fp, categoria="1. Teste")
    _gravar_votos(projeto, fp, painel("endurecimento", "endurecimento", "endurecimento"))
    _rodar_cli(projeto)
    projeto.cabecalho(INFORMATIVOS=[{"id": "I1", "titulo": "t", "categoria": "1. Teste",
                                     "arquivo": "src/app.ts", "descricao": "d"}])
    assert [i["id"] for i in projeto.carregar().INFORMATIVOS] == ["I1", "I2"]


# ── Caminho `outro_achado` do atacante ──────────────────────────────────────

TODOS = {c: "CONFIDENT" for c in patches.ALEGACOES}


def _verificador(**campos):
    return {"veredito": "PASS", "confirmado": True, "alegacoes": dict(TODOS), **campos}


def _caminho(**campos):
    return {"caminhos": [{"tipo": "outro_achado", "descricao": "x", **campos}]}


def test_caminho_de_outro_achado_nao_bloqueia():
    r = patches.julgar(_verificador(), _caminho(achado="A1"), 1, achados={"A1", "A3"})
    assert r["status"] == "aprovado"


@pytest.mark.parametrize("campos", [{}, {"achado": "A9"}, {"achado": "../A1"}])
def test_outro_achado_precisa_apontar_id_existente(campos):
    r = patches.julgar(_verificador(), _caminho(**campos), 1, achados={"A1"})
    assert r["status"] == "objecao"


def test_outro_achado_nao_vale_sem_lista_de_achados():
    assert patches.julgar(_verificador(), _caminho(achado="A1"), 1)["status"] == "objecao"


def test_nota_do_patch_lista_o_que_segue_aberto(projeto):
    projeto.gravar_registro(achado(id="A1"))
    projeto.carregar()
    scratch = patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha)
    (scratch / "src" / "app.ts").write_text("// corrigido\n", encoding="utf-8", newline="\n")
    patches._git(scratch, "add", "-A")
    patches.congelar(str(projeto.pasta), "A1")
    pasta = projeto.pasta / ".trabalho" / "patches" / "A1"
    (pasta / "atacante.json").write_text(
        json.dumps(_caminho(achado="A2", descricao="destinatário livre")), encoding="utf-8")
    julgamento = patches.selar(str(projeto.pasta), "A1", {"status": "aprovado", "motivo": ""})
    caminho = patches.escrever(str(projeto.raiz), str(projeto.pasta), "A1", julgamento,
                               _verificador())
    nota = (caminho.parent / "A1.md").read_text(encoding="utf-8")
    assert "Segue aberto" in nota
    assert "A2" in nota and "destinatário livre" in nota


def test_cli_julgar_entrega_os_ids_da_rodada(projeto):
    projeto.gravar_registro(achado(id="A1"))
    projeto.gravar_registro(achado(id="A2", fingerprint="src/app.ts:atualizar:outra"))
    projeto.carregar()
    scratch = patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha)
    (scratch / "src" / "app.ts").write_text("// corrigido\n", encoding="utf-8", newline="\n")
    patches._git(scratch, "add", "-A")
    patches.congelar(str(projeto.pasta), "A1")
    pasta = projeto.pasta / ".trabalho" / "patches" / "A1"
    (pasta / "verificador.json").write_text(
        json.dumps(_verificador(caminhos_revisados=["src/app.ts"])), encoding="utf-8")
    (pasta / "atacante.json").write_text(json.dumps(_caminho(achado="A2")), encoding="utf-8")
    assert patches.main(["patches.py", "julgar", "A1", "--pasta", str(projeto.pasta)]) == 0
    assert json.loads((pasta / "julgamento.json").read_text(encoding="utf-8"))["status"] \
        == "aprovado"


def test_achado_nao_pode_apontar_para_si_mesmo(projeto):
    projeto.gravar_registro(achado(id="A1"))
    projeto.carregar()
    assert patches.ids_da_rodada(str(projeto.pasta), "A1") == set()


# ── PDF ─────────────────────────────────────────────────────────────────────

pypdf = pytest.importorskip("pypdf")
pytest.importorskip("reportlab")


def _texto_do_pdf(projeto):
    projeto.carregar()
    r = subprocess.run([sys.executable, str(projeto.pasta / "gerar_relatorio.py")],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       cwd=projeto.raiz)
    assert r.returncode == 0, r.stdout + r.stderr
    leitor = pypdf.PdfReader(str(projeto.pasta / "relatorio-auditoria-seguranca.pdf"))
    return [p.extract_text() for p in leitor.pages]


def test_sem_pontos_fracos_a_secao_nao_sai(projeto):
    projeto.gravar_registro(achado())
    assert not any("Pontos fracos" in p for p in _texto_do_pdf(projeto))


def test_com_pontos_fracos_a_secao_sai(projeto):
    projeto.gravar_registro(achado())
    projeto.cabecalho(PONTOS_FRACOS=[("Risco", "Texto do risco.")])
    assert any("Pontos fracos" in p for p in _texto_do_pdf(projeto))


def test_nome_longo_nao_invade_o_rodape(projeto):
    projeto.gravar_registro(achado())
    projeto.cabecalho(PROJETO="Projeto com um nome realmente muito comprido " * 3)
    paginas = _texto_do_pdf(projeto)
    assert "…" in paginas[-1]
    assert "Análise por" in paginas[-1]


def test_encurtar_respeita_a_largura():
    from conftest import ASSETS
    fonte = (ASSETS / "gerar_relatorio.py").read_text(encoding="utf-8")
    bloco = fonte[fonte.index("def encurtar("):fonte.index("def _moldura")]
    espaco: dict = {}
    exec(bloco, espaco)
    medir = len
    assert espaco["encurtar"]("curto", 10, medir) == "curto"
    longo = espaco["encurtar"]("x" * 50, 10, medir)
    assert len(longo) <= 10 and longo.endswith("…")
