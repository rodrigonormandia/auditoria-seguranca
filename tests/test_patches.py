import json
import os

import pytest

import patches
from conftest import achado, git

TODOS = {c: "CONFIDENT" for c in patches.ALEGACOES}


def verificador(**campos):
    base = {"veredito": "PASS", "confirmado": True, "alegacoes": dict(TODOS),
            "sem_teste": False, "testes": "npm test"}
    base.update(campos)
    return base


def atacante(**campos):
    base = {"caminhos": []}
    base.update(campos)
    return base


def test_julgar_aprova_tudo_confiante():
    assert patches.julgar(verificador(), atacante(), 1)["status"] == "aprovado"


def test_julgar_relatorio_ausente_recusa():
    assert patches.julgar(None, atacante(), 1)["status"] == "recusado"
    assert patches.julgar(verificador(), None, 1)["status"] == "recusado"


def test_julgar_achado_nao_confirmado_recusa():
    r = patches.julgar(verificador(confirmado=False), atacante(), 1)
    assert r["status"] == "recusado"
    assert "não confirmado" in r["motivo"]


def test_julgar_unsure_recusa_sem_revisao():
    v = verificador(alegacoes={**TODOS, "SEM_FALHA_NOVA": "UNSURE"})
    assert patches.julgar(v, atacante(), 1)["status"] == "recusado"


def test_julgar_alegacao_faltando_recusa():
    alegacoes = dict(TODOS)
    del alegacoes["REGRAS_MANTIDAS"]
    assert patches.julgar(verificador(alegacoes=alegacoes), atacante(), 1)["status"] == "recusado"


def test_julgar_not_confident_e_objecao_e_depois_recusa():
    v = verificador(alegacoes={**TODOS, "COMPORTAMENTO_MANTIDO": "NOT_CONFIDENT"})
    assert patches.julgar(v, atacante(), 1)["status"] == "objecao"
    assert patches.julgar(v, atacante(), 2)["status"] == "recusado"


def test_julgar_reject_e_objecao():
    assert patches.julgar(verificador(veredito="REJECT"), atacante(), 1)["status"] == "objecao"


def test_julgar_caminho_do_atacante_conta():
    a = atacante(caminhos=[{"tipo": "aberto_pela_mudanca", "descricao": "x"}])
    assert patches.julgar(verificador(), a, 1)["status"] == "objecao"
    a = atacante(caminhos=[{"tipo": "ainda_alcancavel", "descricao": "x"}])
    assert patches.julgar(verificador(), a, 1)["status"] == "objecao"


def test_julgar_caminho_preexistente_nao_conta():
    a = atacante(caminhos=[{"tipo": "preexistente", "descricao": "x"}])
    assert patches.julgar(verificador(), a, 1)["status"] == "aprovado"


def test_julgar_tipo_de_caminho_desconhecido_conta():
    a = atacante(caminhos=[{"tipo": "outra-coisa", "descricao": "x"}])
    assert patches.julgar(verificador(), a, 1)["status"] == "objecao"


def _preparar_registro(projeto, **campos):
    projeto.gravar_registro(achado(id="A1", **campos))
    projeto.carregar()


def test_preparar_recusa_id_invalido(projeto):
    with pytest.raises(ValueError):
        patches.preparar(str(projeto.raiz), str(projeto.pasta), "../A1", projeto.sha)


def test_preparar_recusa_head_diferente(projeto):
    _preparar_registro(projeto)
    with pytest.raises(ValueError, match="HEAD"):
        patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", "abcdef1")


def test_preparar_recusa_decisao_do_dono(projeto):
    _preparar_registro(projeto, decisao_necessaria="decidir X")
    with pytest.raises(ValueError, match="decisão"):
        patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha)


def test_preparar_recusa_id_inexistente(projeto):
    projeto.carregar()
    with pytest.raises(ValueError, match="A9"):
        patches.preparar(str(projeto.raiz), str(projeto.pasta), "A9", projeto.sha)


def _selado(projeto, julgamento=None):
    patches.congelar(str(projeto.pasta), "A1")
    return patches.selar(str(projeto.pasta), "A1", julgamento or {"status": "aprovado", "motivo": ""})


def _fluxo(projeto):
    _preparar_registro(projeto)
    scratch = patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha)
    alvo = scratch / "src" / "app.ts"
    alvo.write_text(alvo.read_text(encoding="utf-8").replace("data: dados", "data: { nome: dados.nome }"),
                    encoding="utf-8", newline="\n")
    patches._git(scratch, "add", "-A")
    return scratch


def test_escrever_gera_patch_que_aplica_e_nao_toca_a_arvore(projeto):
    antes = (projeto.raiz / "src" / "app.ts").read_text(encoding="utf-8")
    scratch = _fluxo(projeto)
    julgamento = _selado(projeto, patches.julgar(verificador(), atacante(), 1))
    caminho = patches.escrever(str(projeto.raiz), str(projeto.pasta), "A1", julgamento,
                               verificador())
    assert caminho.name == "A1.patch"
    assert (projeto.raiz / "src" / "app.ts").read_text(encoding="utf-8") == antes
    patches._git(projeto.raiz, "apply", "--check", str(caminho))
    nota = (caminho.parent / "A1.md").read_text(encoding="utf-8")
    assert "npm test" in nota
    assert scratch.exists()


def test_escrever_avisa_sem_teste(projeto):
    _fluxo(projeto)
    caminho = patches.escrever(str(projeto.raiz), str(projeto.pasta), "A1",
                               _selado(projeto), verificador(sem_teste=True))
    assert "nenhum teste do projeto" in caminho.read_text(encoding="utf-8").lower()


def test_escrever_recusa_quem_nao_foi_aprovado(projeto):
    _fluxo(projeto)
    with pytest.raises(ValueError, match="aprovado"):
        patches.escrever(str(projeto.raiz), str(projeto.pasta), "A1",
                         {"status": "objecao", "motivo": "x"}, verificador())


def test_escrever_recusa_diff_vazio(projeto):
    _preparar_registro(projeto)
    patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha)
    with pytest.raises(ValueError, match="vazio"):
        patches.escrever(str(projeto.raiz), str(projeto.pasta), "A1",
                         {"status": "aprovado", "motivo": "", "diff_sha": "x"}, verificador())
    with pytest.raises(ValueError, match="vazio"):
        patches.congelar(str(projeto.pasta), "A1")


def test_hooks_do_usuario_nao_rodam_no_clone(projeto):
    gancho = projeto.raiz / ".git" / "hooks" / "post-checkout"
    marca = projeto.raiz / "hook-rodou"
    gancho.write_text(f'#!/bin/sh\ntouch "{marca.as_posix()}"\n', encoding="utf-8")
    os.chmod(gancho, 0o755)
    _preparar_registro(projeto)
    scratch = patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha)
    assert not marca.exists()
    assert git(scratch, "config", "core.hooksPath") == "/dev/null"


def _com_node_modules(projeto):
    gi = projeto.raiz / ".gitignore"
    gi.write_text(gi.read_text(encoding="utf-8") + "node_modules/\n", encoding="utf-8")
    projeto.commit()
    pacote = projeto.raiz / "node_modules" / "lib"
    pacote.mkdir(parents=True)
    (pacote / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")


def test_remover_preserva_o_node_modules_real(projeto):
    _com_node_modules(projeto)
    _preparar_registro(projeto)
    scratch = patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha,
                               ligar_dependencias=True)
    assert (scratch / "node_modules" / "lib" / "index.js").exists()
    assert patches._git(scratch, "status", "--porcelain").stdout.strip() == ""
    patches.remover(scratch)
    assert not scratch.exists()
    assert (projeto.raiz / "node_modules" / "lib" / "index.js").exists()


def test_node_modules_versionado_nao_e_ligado(projeto):
    pacote = projeto.raiz / "node_modules"
    pacote.mkdir()
    (pacote / "a.js").write_text("1\n", encoding="utf-8")
    projeto.commit()
    _preparar_registro(projeto)
    scratch = patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha,
                               ligar_dependencias=True)
    assert not patches._e_ligacao(scratch / "node_modules")
    patches.remover(scratch)
    assert (pacote / "a.js").exists()


def test_indice_lista_patches_e_recusas(projeto):
    _fluxo(projeto)
    patches.escrever(str(projeto.raiz), str(projeto.pasta), "A1", _selado(projeto), verificador())
    patches.registrar_recusa(str(projeto.pasta), "A2", "2 tentativas sem aprovação")
    texto = patches.indice(str(projeto.pasta)).read_text(encoding="utf-8")
    assert "A1.patch" in texto
    assert "A2" in texto and "2 tentativas" in texto


def test_cli_julgar_le_os_relatorios(projeto):
    _fluxo(projeto)
    assert patches.main(["patches.py", "congelar", "A1", "--pasta", str(projeto.pasta)]) == 0
    pasta = projeto.pasta / ".trabalho" / "patches" / "A1"
    (pasta / "verificador.json").write_text(
        json.dumps(verificador(caminhos_revisados=["src/app.ts"])), encoding="utf-8")
    (pasta / "atacante.json").write_text(json.dumps(atacante()), encoding="utf-8")
    assert patches.main(["patches.py", "julgar", "A1", "--pasta", str(projeto.pasta)]) == 0
    julgamento = json.loads((pasta / "julgamento.json").read_text(encoding="utf-8"))
    assert julgamento["status"] == "aprovado"
    assert julgamento["diff_sha"]
