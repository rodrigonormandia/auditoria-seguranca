"""Defeitos apontados na revisão independente, cada um fixado por um teste."""

import subprocess
import sys

import pytest

import apurar_votos as av
import importar_claude_security as ics
import patches
import redigir
from conftest import ASSETS, achado
from test_apurar_votos import _gravar_votos, painel
from test_importar import _jsonl, registro


# ── Detecção de credencial ──────────────────────────────────────────────────

@pytest.mark.parametrize("texto", [
    'const serviceKey = "sb_secret_abcdefghij1234567890";',
    'SUPABASE_SERVICE_ROLE_KEY="valorRealDaChave123"',
    "POSTGRES_PASSWORD: mysecretpass123",
    "DB_PASSWORD=Xk9$mQ2pLz8wRt",
    'DB_PASS="hunter2hunter2"',
    r'const password = "pa\"ss1234abcd";',
    'SESSION_SECRET="primeira\nsegunda"',
    'ENCRYPTION_KEY="abc123def456"',
    "password: S3nhaForte99",
])
def test_formatos_comuns_sao_detectados(texto):
    assert redigir.achar_credenciais(texto), texto


@pytest.mark.parametrize("texto,senha", [
    ("postgres://postgres:Abc@def9876@db.x/app", "def9876"),
    ("postgres://u:Xq7/pLm2Rt9@host/app", "pLm2Rt9"),
])
def test_senha_de_url_some_inteira(texto, senha):
    saida, _ = redigir.redigir_texto(texto)
    assert senha not in saida
    assert "@" in saida


@pytest.mark.parametrize("texto", [
    'const token_type = "Bearer";',
    'PWD="$(pwd)"',
    "const re_validate_email_address = 1;",
    'class="sk-loading-spinner-container-wrapper"',
    "O marcador -----BEGIN PRIVATE KEY----- aparece sem o resto",
    "token: z.string().min(8),",
    "password: hashedPassword",
    "https://unpkg.com:443/react@18.3.1",
    "BYPASS_CACHE=enabled12",
    'const compass = "norte-sul";',
])
def test_codigo_comum_nao_trava_o_relatorio(texto):
    assert redigir.achar_credenciais(texto) == [], texto


# ── Validador ───────────────────────────────────────────────────────────────

def test_exclusoes_e_projeto_sao_varridos(projeto):
    projeto.cabecalho(EXCLUSOES=[{"caminho": "legado", "motivo": "usar postgres://a:S3nha99x@h/d"}],
                      PROJETO="Projeto AKIAABCDEFGHIJKLMNOP")
    erros, _ = projeto.validar()
    assert any("EXCLUSOES" in e and "credencial" in e for e in erros), erros
    assert any("PROJETO" in e and "credencial" in e for e in erros), erros


def test_evidencia_fora_da_fonte_ainda_confere_o_arquivo(projeto):
    projeto.gravar_registro(achado(arquivo="naoexiste/x.ts", evidencia="saída do teste",
                                   evidencia_fora_da_fonte="teste local"))
    erros, _ = projeto.validar()
    assert any("naoexiste" in e for e in erros), erros


def test_anterior_com_arquivo_fantasma_e_erro(projeto):
    projeto.gravar_registro({
        "veredito": "anterior", "fingerprint": "fantasma/y.ts:f:antiga", "titulo": "t",
        "arquivo": "fantasma/y.ts", "linha": "1", "causa_alegada": "c", "motivo": "m"})
    erros, _ = projeto.validar()
    assert any("fantasma" in e for e in erros), erros


def test_descartado_pode_citar_arquivo_inexistente(projeto):
    projeto.gravar_registro({
        "veredito": "descartado", "fingerprint": "fantasma/y.ts:f:refutada", "titulo": "t",
        "arquivo": "fantasma/y.ts", "linha": "1", "causa_alegada": "c", "motivo": "não existe"})
    erros, _ = projeto.validar()
    assert erros == [], erros


def test_via_mudanca_exige_linha_alterada(projeto):
    base = projeto.sha
    arquivo = projeto.raiz / "src" / "app.ts"
    arquivo.write_text(arquivo.read_text(encoding="utf-8") + "// nova\n", encoding="utf-8",
                       newline="\n")
    head = projeto.commit()
    projeto.cabecalho(MUDANCA={"base": base, "head": head})
    projeto.gravar_registro(achado(via_mudanca="src/app.ts:1 linha que não mudou"))
    erros, _ = projeto.validar()
    assert any("via_mudanca" in e for e in erros), erros
    projeto.gravar_registro(achado(via_mudanca="src/app.ts:8 linha nova"))
    erros, _ = projeto.validar()
    assert erros == [], erros


def _unidade(**campos):
    base = {"id": "U1", "superficie": "s", "fronteira": "f", "subsistema": "x", "classe": "c",
            "status": "coberta", "caminhos": ["src"], "verificacao": "ok"}
    base.update(campos)
    return base


def test_curinga_nao_cobre_o_repositorio(projeto):
    (projeto.raiz / "api").mkdir()
    (projeto.raiz / "api" / "x.ts").write_text("x\n", encoding="utf-8")
    projeto.commit()
    projeto.gravar_cobertura([_unidade(caminhos=["*"])])
    erros, _ = projeto.validar()
    assert any("api" in e for e in erros), erros


def test_ponto_literal_cobre_o_repositorio(projeto):
    (projeto.raiz / "api").mkdir()
    (projeto.raiz / "api" / "x.ts").write_text("x\n", encoding="utf-8")
    projeto.commit()
    projeto.gravar_cobertura([_unidade(caminhos=["."])])
    erros, _ = projeto.validar()
    assert erros == [], erros


def test_padrao_sem_mapa_de_cobertura_e_erro(projeto):
    projeto.cabecalho(PERFIL="padrao")
    erros, _ = projeto.validar()
    assert any("COBERTURA" in e for e in erros), erros


def test_perfil_ausente_e_erro(projeto):
    projeto.cabecalho(PERFIL=None)
    erros, _ = projeto.validar()
    assert any("PERFIL" in e for e in erros), erros


def test_rapida_com_votos_divergentes_e_erro(projeto):
    reg = achado()
    projeto.gravar_registro(reg)
    _gravar_votos(projeto, reg["fingerprint"], painel("descartado", "descartado", "descartado"))
    erros, _ = projeto.validar()
    assert any("painel" in e for e in erros), erros


def test_slug_que_colide_e_erro(projeto):
    projeto.gravar_registro(achado(fingerprint="src/app/x", arquivo="src/app.ts"), nome="um")
    projeto.gravar_registro(achado(fingerprint="src/app-x", arquivo="src/app.ts"), nome="dois")
    erros, _ = projeto.validar()
    assert any("colide" in e for e in erros), erros


def test_teto_com_uma_nota_so_vale():
    r = av.apurar(painel("confirmado", "confirmado", "descartado", ("baixa", None, None)))
    assert r["severidade_teto"] == "baixa"


def test_voto_que_cita_linha_inexistente_e_erro(projeto):
    projeto.cabecalho(PERFIL="padrao")
    projeto.gravar_cobertura([_unidade()])
    reg = achado()
    projeto.gravar_registro(reg)
    votos = painel("confirmado", "confirmado", "confirmado")
    votos[0]["motivo"] = "ver src/app.ts:99999"
    _gravar_votos(projeto, reg["fingerprint"], votos)
    erros, _ = projeto.validar()
    assert any("cita" in e for e in erros), erros


@pytest.mark.parametrize("id_ruim", ["../../escapou", "A 1", "a1", "A1/x"])
def test_id_fora_do_formato_e_erro(projeto, id_ruim):
    projeto.gravar_registro(achado(id=id_ruim))
    erros, _ = projeto.validar()
    assert any("id" in e and "formato" in e for e in erros), erros


def test_prefixo_do_read_com_tab_passa(projeto):
    projeto.gravar_registro(achado(linha="4", evidencia="     4\t  const dados = req.body;"))
    erros, _ = projeto.validar()
    assert erros == [], erros


def test_gerador_recusa_sem_validador(projeto):
    projeto.gravar_registro(achado())
    projeto.carregar()
    (projeto.pasta / "validar_findings.py").unlink()
    r = subprocess.run([sys.executable, str(projeto.pasta / "gerar_relatorio.py")],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       cwd=projeto.raiz)
    assert r.returncode != 0
    assert not (projeto.pasta / "relatorio-auditoria-seguranca.pdf").exists()


# ── Importação ──────────────────────────────────────────────────────────────

def test_jsonl_com_bom_passa(tmp_path):
    caminho = _jsonl(tmp_path, [registro()])
    caminho.write_bytes(b"\xef\xbb\xbf" + caminho.read_bytes())
    assert len(ics.importar(caminho, tmp_path / "c")["candidatos"]) == 1


def test_erro_no_meio_nao_grava_parcial(tmp_path):
    destino = tmp_path / "c"
    caminho = _jsonl(tmp_path, [registro(), registro(symbol="b", severity="INFO")])
    with pytest.raises(ValueError):
        ics.importar(caminho, destino)
    assert not destino.exists() or not list(destino.glob("*.json"))


# ── Patches ─────────────────────────────────────────────────────────────────

TODOS = {c: "CONFIDENT" for c in patches.ALEGACOES}


def _verificador(**campos):
    return {"veredito": "PASS", "confirmado": True, "alegacoes": dict(TODOS), **campos}


def _pronto(projeto, **campos):
    projeto.gravar_registro(achado(id="A1", **campos))
    projeto.carregar()
    scratch = patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha)
    alvo = scratch / "src" / "app.ts"
    alvo.write_text("// corrigido\n", encoding="utf-8", newline="\n")
    patches._git(scratch, "add", "-A")
    patches.congelar(str(projeto.pasta), "A1")
    return scratch


def test_confirmado_precisa_ser_true():
    for valor in ("não", None):
        assert patches.julgar(_verificador(confirmado=valor), {"caminhos": []}, 1)["status"] \
            == "recusado"
    sem_campo = _verificador()
    del sem_campo["confirmado"]
    assert patches.julgar(sem_campo, {"caminhos": []}, 1)["status"] == "recusado"


def test_escrever_recusa_stage_diferente_do_julgado(projeto):
    scratch = _pronto(projeto)
    julgamento = patches.selar(str(projeto.pasta), "A1", {"status": "aprovado", "motivo": ""})
    (scratch / "src" / "app.ts").write_text("// outra mudança\n", encoding="utf-8", newline="\n")
    patches._git(scratch, "add", "-A")
    with pytest.raises(ValueError, match="stage"):
        patches.escrever(str(projeto.raiz), str(projeto.pasta), "A1", julgamento, _verificador())


def test_julgar_recusa_stage_mudado_depois_de_congelar(projeto):
    scratch = _pronto(projeto)
    (scratch / "src" / "app.ts").write_text("// outra\n", encoding="utf-8", newline="\n")
    patches._git(scratch, "add", "-A")
    with pytest.raises(ValueError, match="stage"):
        patches.selar(str(projeto.pasta), "A1", {"status": "aprovado", "motivo": ""})


def test_congelar_apaga_relatorios_antigos(projeto):
    _pronto(projeto)
    pasta = projeto.pasta / ".trabalho" / "patches" / "A1"
    (pasta / "verificador.json").write_text("{}", encoding="utf-8")
    (pasta / "julgamento.json").write_text("{}", encoding="utf-8")
    patches.congelar(str(projeto.pasta), "A1")
    assert not (pasta / "verificador.json").exists()
    assert not (pasta / "julgamento.json").exists()


def test_escrever_reconfere_decisao_do_dono(projeto):
    _pronto(projeto)
    julgamento = patches.selar(str(projeto.pasta), "A1", {"status": "aprovado", "motivo": ""})
    projeto.gravar_registro(achado(id="A1", decisao_necessaria="decidir"))
    projeto.carregar()
    with pytest.raises(ValueError, match="decisão"):
        patches.escrever(str(projeto.raiz), str(projeto.pasta), "A1", julgamento, _verificador())


def test_node_modules_so_e_ligado_com_pedido(projeto):
    gi = projeto.raiz / ".gitignore"
    gi.write_text(gi.read_text(encoding="utf-8") + "node_modules/\n", encoding="utf-8")
    projeto.commit()
    (projeto.raiz / "node_modules").mkdir()
    (projeto.raiz / "node_modules" / "a.js").write_text("1\n", encoding="utf-8")
    projeto.gravar_registro(achado(id="A1"))
    projeto.carregar()
    scratch = patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha)
    assert not (scratch / "node_modules").exists()
    patches.remover(scratch)


def test_alegacao_com_evidencia_na_mesma_string_vale():
    alegacoes = {c: "CONFIDENT: visto em api/x.ts:1" for c in patches.ALEGACOES}
    assert patches.julgar(_verificador(alegacoes=alegacoes), {"caminhos": []}, 1)["status"] \
        == "aprovado"


@pytest.mark.parametrize("valor,status", [
    ("NOT_CONFIDENT: quebra um chamador", "objecao"),
    ("UNSURE: não deu para saber", "recusado"),
    ("acho que sim", "recusado"),
    ("CONFIDENTE", "recusado"),
    (True, "recusado"),
])
def test_alegacao_fora_do_formato_nao_aprova(valor, status):
    alegacoes = {**TODOS, "SEM_FALHA_NOVA": valor}
    assert patches.julgar(_verificador(alegacoes=alegacoes), {"caminhos": []}, 1)["status"] == status


def test_relatorio_ilegivel_pede_novo_agente_e_nao_julga(projeto):
    _pronto(projeto)
    pasta = projeto.pasta / ".trabalho" / "patches" / "A1"
    (pasta / "verificador.json").write_text('{"veredito": "PASS"}', encoding="utf-8")
    (pasta / "atacante.json").write_text(r'{"caminhos": "\d quebrado"', encoding="utf-8")
    assert patches.main(["patches.py", "julgar", "A1", "--pasta", str(projeto.pasta)]) == 2
    assert not (pasta / "julgamento.json").exists()


def test_congelar_recusa_troca_de_fim_de_linha(projeto):
    alvo = projeto.raiz / "src" / "grande.ts"
    alvo.write_text("".join(f"const a{i} = {i};\n" for i in range(40)), encoding="utf-8",
                    newline="\n")
    projeto.commit()
    projeto.gravar_registro(achado(id="A1"))
    projeto.carregar()
    scratch = patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha)
    copia = scratch / "src" / "grande.ts"
    texto = copia.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    copia.write_bytes(texto.replace(b"a0 = 0", b"a0 = 9"))
    patches._git(scratch, "-c", "core.autocrlf=false", "add", "-A")
    with pytest.raises(ValueError, match="fim de linha"):
        patches.congelar(str(projeto.pasta), "A1")


def test_clone_liga_caminhos_longos(projeto):
    projeto.gravar_registro(achado(id="A1"))
    projeto.carregar()
    scratch = patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha)
    assert patches._git(scratch, "config", "core.longpaths").stdout.strip() == "true"


def test_clone_incompleto_e_recusado(projeto, monkeypatch):
    projeto.gravar_registro(achado(id="A1"))
    projeto.carregar()
    original = patches._git

    def sem_arquivo(diretorio, *args, **kw):
        if args[:1] == ("ls-files",):
            return subprocess.CompletedProcess(args, 0, "caminho/muito/longo.md\n", "")
        return original(diretorio, *args, **kw)

    monkeypatch.setattr(patches, "_git", sem_arquivo)
    with pytest.raises(ValueError, match="incompleto"):
        patches.preparar(str(projeto.raiz), str(projeto.pasta), "A1", projeto.sha)
    assert not patches._scratch(str(projeto.pasta), "A1").exists()


def test_verificador_precisa_revisar_os_arquivos_do_diff(projeto):
    _pronto(projeto)
    aprovado = {"status": "aprovado", "motivo": ""}
    ok = patches.selar(str(projeto.pasta), "A1", aprovado,
                       {"caminhos_revisados": ["src/app.ts"]})
    assert ok["status"] == "aprovado"
    faltou = patches.selar(str(projeto.pasta), "A1", aprovado, {"caminhos_revisados": []})
    assert faltou["status"] == "recusado"


def test_exportar_nao_sai_da_pasta(projeto):
    fonte = (ASSETS / "abrir_issues.py").read_text(encoding="utf-8")
    assert 'nome = os.path.basename(item["id"])' in fonte
