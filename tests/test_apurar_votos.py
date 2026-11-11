import json
import subprocess
import sys

import pytest

import apurar_votos as av
from conftest import SEGREDO_TESTE, achado


def voto(lente, veredito, severidade=None, motivo="decide em src/app.ts:5"):
    v = {"lente": lente, "veredito": veredito, "motivo": motivo}
    if severidade:
        v["severidade"] = severidade
    return v


def painel(a, b, c, sev=("alta", "alta", "alta")):
    return [voto(l, x, s) for l, x, s in zip(av.LENTES, (a, b, c), sev)]


def test_unanime_confirma_e_libera_confianca_alta():
    r = av.apurar(painel("confirmado", "confirmado", "confirmado"))
    assert (r["estado"], r["veredito"], r["confianca_maxima"]) == ("completo", "confirmado", "alta")


def test_dois_de_tres_confirma_e_limita_confianca():
    r = av.apurar(painel("confirmado", "confirmado", "descartado"))
    assert r["veredito"] == "confirmado"
    assert r["confianca_maxima"] == "media"


def test_dois_descartados_descartam():
    assert av.apurar(painel("descartado", "confirmado", "descartado"))["veredito"] == "descartado"


def test_empate_de_tres_vira_pendente():
    assert av.apurar(painel("confirmado", "pendente", "descartado"))["veredito"] == "pendente"


def test_dois_pendentes_nao_viram_descarte():
    assert av.apurar(painel("pendente", "pendente", "descartado"))["veredito"] == "pendente"


def test_dois_anteriores_marcam_anterior():
    assert av.apurar(painel("anterior", "anterior", "confirmado"))["veredito"] == "anterior"


def test_lente_faltando_e_incompleto():
    r = av.apurar(painel("confirmado", "confirmado", "confirmado")[:2])
    assert r["estado"] == "incompleto"
    assert r["veredito"] is None


def test_lente_repetida_e_incompleto():
    votos = [voto("alcance", "confirmado"), voto("alcance", "confirmado"),
             voto("defesas", "confirmado")]
    assert av.apurar(votos)["estado"] == "incompleto"


@pytest.mark.parametrize("ruim", [
    voto("defesas", "talvez"),
    voto("mistica", "confirmado"),
    voto("defesas", "confirmado", motivo="parece explorável"),
    voto("defesas", "descartado", motivo=""),
    "nao-e-dict",
])
def test_voto_invalido_nunca_decide(ruim):
    votos = [voto("alcance", "confirmado"), voto("impacto", "confirmado"), ruim]
    assert av.apurar(votos)["estado"] == "incompleto"


def test_pendente_nao_precisa_citar_linha():
    votos = [voto("alcance", "pendente", motivo="depende do proxy implantado"),
             voto("impacto", "confirmado"), voto("defesas", "confirmado")]
    assert av.apurar(votos)["estado"] == "completo"


def test_teto_e_a_mediana_dos_confirmadores():
    r = av.apurar(painel("confirmado", "confirmado", "confirmado", ("critica", "alta", "media")))
    assert r["severidade_teto"] == "alta"


def test_teto_com_dois_votos_fica_no_maior():
    r = av.apurar(painel("confirmado", "confirmado", "descartado", ("alta", "media", None)))
    assert r["severidade_teto"] == "alta"


def test_sem_nota_nao_ha_teto():
    r = av.apurar(painel("confirmado", "confirmado", "descartado", (None, None, None)))
    assert r["severidade_teto"] is None


def _gravar_votos(projeto, fingerprint, votos):
    pasta = projeto.votos / av.slug(fingerprint)
    pasta.mkdir(parents=True, exist_ok=True)
    for v in votos:
        (pasta / f'{v["lente"]}.json').write_text(json.dumps(v, ensure_ascii=False),
                                                  encoding="utf-8")


def test_padrao_sem_votos_e_erro(projeto):
    projeto.cabecalho(PERFIL="padrao")
    projeto.gravar_registro(achado())
    erros, _ = projeto.validar()
    assert any("painel" in e for e in erros), erros


def test_rapida_nao_cobra_votos(projeto):
    projeto.gravar_registro(achado())
    erros, _ = projeto.validar()
    assert erros == [], erros


def test_registro_coerente_com_votos_passa(projeto):
    projeto.cabecalho(PERFIL="padrao")
    projeto.gravar_cobertura([{
        "id": "U1", "superficie": "s", "fronteira": "f", "subsistema": "x", "classe": "c",
        "status": "candidata", "caminhos": ["src"], "verificacao": "lida",
        "fingerprints": ["src/app.ts:atualizar:mass-assignment"]}])
    reg = achado()
    projeto.gravar_registro(reg)
    _gravar_votos(projeto, reg["fingerprint"], painel("confirmado", "confirmado", "confirmado"))
    erros, _ = projeto.validar()
    assert erros == [], erros


def test_veredito_diferente_do_placar_e_erro(projeto):
    projeto.cabecalho(PERFIL="padrao")
    reg = achado()
    projeto.gravar_registro(reg)
    _gravar_votos(projeto, reg["fingerprint"], painel("confirmado", "descartado", "descartado"))
    erros, _ = projeto.validar()
    assert any("painel" in e and "descartado" in e for e in erros), erros


def test_severidade_acima_do_teto_e_erro(projeto):
    projeto.cabecalho(PERFIL="padrao")
    reg = achado(severidade="critica", impacto_nivel="critica")
    projeto.gravar_registro(reg)
    _gravar_votos(projeto, reg["fingerprint"], painel("confirmado", "confirmado", "confirmado",
                                                      ("alta", "media", "media")))
    erros, _ = projeto.validar()
    assert any("teto" in e for e in erros), erros


def test_confianca_acima_do_permitido_e_erro(projeto):
    projeto.cabecalho(PERFIL="padrao")
    reg = achado(confianca="alta")
    projeto.gravar_registro(reg)
    _gravar_votos(projeto, reg["fingerprint"], painel("confirmado", "confirmado", "descartado"))
    erros, _ = projeto.validar()
    assert any("unanimidade" in e for e in erros), erros


def test_voto_com_credencial_e_erro(projeto):
    projeto.cabecalho(PERFIL="padrao")
    reg = achado()
    projeto.gravar_registro(reg)
    votos = painel("confirmado", "confirmado", "confirmado")
    votos[0]["motivo"] = f"src/app.ts:5 usa {SEGREDO_TESTE}"
    _gravar_votos(projeto, reg["fingerprint"], votos)
    erros, _ = projeto.validar()
    assert any("credencial" in e for e in erros), erros
    assert not any(SEGREDO_TESTE in e for e in erros)


def _rodar_cli(projeto):
    return subprocess.run([sys.executable, str(projeto.pasta / "apurar_votos.py"),
                           str(projeto.pasta)], capture_output=True, text=True, encoding="utf-8",
                          errors="replace")


def _candidato(projeto, fingerprint, **campos):
    pasta = projeto.pasta / ".trabalho" / "candidatos"
    pasta.mkdir(parents=True, exist_ok=True)
    base = {"veredito": "confirmado", "fingerprint": fingerprint, "titulo": "t",
            "arquivo": "src/app.ts", "linha": "5", "causa_raiz": "causa"}
    base.update(campos)
    (pasta / f"{av.slug(fingerprint)}.json").write_text(json.dumps(base), encoding="utf-8")


def test_cli_grava_descartado_sozinho(projeto):
    fp = "src/app.ts:atualizar:falso"
    _candidato(projeto, fp)
    _gravar_votos(projeto, fp, painel("descartado", "descartado", "confirmado"))
    r = _rodar_cli(projeto)
    assert r.returncode == 0, r.stdout + r.stderr
    reg = json.loads((projeto.registros / f"{av.slug(fp)}.json").read_text(encoding="utf-8"))
    assert reg["veredito"] == "descartado"
    assert "src/app.ts:5" in reg["motivo"]
    assert json.loads(r.stdout)["paineis"][av.slug(fp)]["veredito"] == "descartado"


def test_cli_nao_grava_confirmado(projeto):
    fp = "src/app.ts:atualizar:real"
    _candidato(projeto, fp)
    _gravar_votos(projeto, fp, painel("confirmado", "confirmado", "confirmado"))
    assert _rodar_cli(projeto).returncode == 0
    assert not (projeto.registros / f"{av.slug(fp)}.json").exists()


def test_cli_candidato_sem_votos_sai_2(projeto):
    fp = "src/app.ts:atualizar:sem-votos"
    _candidato(projeto, fp)
    r = _rodar_cli(projeto)
    assert r.returncode == 2
    assert av.slug(fp) in json.loads(r.stdout)["incompletos"]


def test_carimbo_rapida_e_padrao(projeto):
    assert "sem painel" in av.carimbo(str(projeto.pasta), [], "rapida")
    reg = achado()
    _gravar_votos(projeto, reg["fingerprint"], painel("confirmado", "confirmado", "descartado"))
    texto = av.carimbo(str(projeto.pasta), [reg], "padrao")
    assert "1 de 1" in texto
    assert av.placar_de(str(projeto.pasta), reg) == "2/3"
