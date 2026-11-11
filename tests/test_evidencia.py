from conftest import SEGREDO_TESTE, achado, git


def _erros_evidencia(projeto):
    erros, _ = projeto.validar()
    return [e for e in erros if "evidencia" in e or "rastro" in e or "arquivo" in e]


def test_evidencia_correta_passa(projeto):
    projeto.gravar_registro(achado())
    assert _erros_evidencia(projeto) == []


def test_trecho_inexistente_e_erro(projeto):
    projeto.gravar_registro(achado(evidencia="linha que nao existe no arquivo"))
    assert _erros_evidencia(projeto)


def test_arquivo_inexistente_e_erro(projeto):
    projeto.gravar_registro(achado(arquivo="src/nao-existe.ts"))
    assert _erros_evidencia(projeto)


def test_caminho_que_sai_do_repositorio_e_erro(projeto):
    projeto.gravar_registro(achado(arquivo="../fora.ts"))
    assert _erros_evidencia(projeto)


def test_linha_distante_e_erro(projeto):
    projeto.gravar_registro(achado(linha="55"))
    assert _erros_evidencia(projeto)


def test_linha_com_folga_passa(projeto):
    projeto.gravar_registro(achado(linha="3-4"))
    assert _erros_evidencia(projeto) == []


def test_crlf_passa(projeto):
    alvo = projeto.raiz / "src" / "crlf.ts"
    alvo.write_bytes(b"const a = 1;\r\nconst b = req.body;\r\n")
    projeto.commit()
    projeto.gravar_registro(achado(arquivo="src/crlf.ts", linha="2",
                                   evidencia="const a = 1;\nconst b = req.body;"))
    assert _erros_evidencia(projeto) == []


def test_redacted_e_curinga_dentro_da_linha(projeto):
    alvo = projeto.raiz / "src" / "conf.ts"
    alvo.write_text(f'export const t = "{SEGREDO_TESTE}";\n', encoding="utf-8")
    projeto.commit()
    projeto.gravar_registro(achado(arquivo="src/conf.ts", linha="1",
                                   evidencia='export const t = "[REDACTED]";'))
    erros, _ = projeto.validar()
    assert erros == [], erros


def test_redacted_nao_aceita_o_resto_diferente(projeto):
    alvo = projeto.raiz / "src" / "conf.ts"
    alvo.write_text(f'export const t = "{SEGREDO_TESTE}";\n', encoding="utf-8")
    projeto.commit()
    projeto.gravar_registro(achado(arquivo="src/conf.ts", linha="1",
                                   evidencia='export const OUTRO = "[REDACTED]";'))
    assert _erros_evidencia(projeto)


def test_evidencia_so_com_redacted_confere_arquivo_e_linha(projeto):
    projeto.gravar_registro(achado(evidencia="[REDACTED]", linha="2"))
    assert _erros_evidencia(projeto) == []
    projeto.gravar_registro(achado(evidencia="[REDACTED]", linha="999"))
    assert _erros_evidencia(projeto)


def test_elisao_e_escape_passam(projeto):
    projeto.gravar_registro(achado(
        linha="4-5",
        evidencia="const dados = req.body;\n// ...\nawait db.users.update({ where: "
                  "{ id: req.params.id }, data: dados });"))
    assert _erros_evidencia(projeto) == []


def test_prefixo_de_numero_de_linha_passa(projeto):
    projeto.gravar_registro(achado(linha="4", evidencia="4: const dados = req.body;"))
    assert _erros_evidencia(projeto) == []


def test_ordem_invertida_e_erro(projeto):
    projeto.gravar_registro(achado(
        linha="4-5",
        evidencia="res.json({ ok: true });\nconst dados = req.body;"))
    assert _erros_evidencia(projeto)


def test_evidencia_de_dois_arquivos_do_rastro_passa(projeto):
    (projeto.raiz / "src" / "db.ts").write_text("export const db = criar();\n", encoding="utf-8")
    projeto.commit()
    projeto.gravar_registro(achado(
        evidencia="const dados = req.body;\nexport const db = criar();", linha="4",
        rastro=[
            {"tipo": "entrada", "arquivo": "src/app.ts", "linha": 4, "descricao": "corpo"},
            {"tipo": "destino", "arquivo": "src/db.ts", "linha": 1, "descricao": "banco"},
        ]))
    assert _erros_evidencia(projeto) == []


def test_rastro_alem_do_fim_do_arquivo_e_erro(projeto):
    projeto.gravar_registro(achado(rastro=[
        {"tipo": "destino", "arquivo": "src/app.ts", "linha": 900, "descricao": "x"}]))
    assert any("rastro" in e for e in _erros_evidencia(projeto))


def test_arquivo_alterado_depois_do_commit_auditado_passa(projeto):
    projeto.gravar_registro(achado(status="CORRIGIDO em 31/10/2026"))
    auditado = projeto.sha
    (projeto.raiz / "src" / "app.ts").write_text("// corrigido\n", encoding="utf-8")
    projeto.commit()
    projeto.cabecalho(REF_FONTE=f"{auditado} (árvore limpa)")
    assert _erros_evidencia(projeto) == []


def test_arvore_suja_confere_a_copia_de_trabalho(projeto):
    (projeto.raiz / "src" / "novo.ts").write_text("const novo = 1;\n", encoding="utf-8")
    projeto.cabecalho(REF_FONTE=f"{projeto.sha} (árvore suja)")
    projeto.gravar_registro(achado(arquivo="src/novo.ts", linha="1",
                                   evidencia="const novo = 1;"))
    assert _erros_evidencia(projeto) == []


def test_arquivo_apagado_usa_ref_evidencia(projeto):
    alvo = projeto.raiz / ".env.antigo"
    alvo.write_text("PORTA=3000\n", encoding="utf-8")
    com_arquivo = projeto.commit()
    git(projeto.raiz, "rm", "-q", ".env.antigo")
    projeto.commit()
    projeto.gravar_registro(achado(arquivo=".env.antigo", linha="1", evidencia="PORTA=3000",
                                   ref_evidencia=com_arquivo))
    assert _erros_evidencia(projeto) == []


def test_evidencia_fora_da_fonte_vira_aviso(projeto):
    projeto.gravar_registro(achado(evidencia="com dois inquilinos fictícios, devolveu o outro",
                                   evidencia_fora_da_fonte="saída de teste local"))
    erros, avisos = projeto.validar()
    assert not [e for e in erros if "evidencia" in e], erros
    assert any("evidencia_fora_da_fonte" in a for a in avisos)


def test_pendente_tambem_e_conferido(projeto):
    projeto.gravar_registro({
        "veredito": "pendente", "fingerprint": "src/app.ts:atualizar:pendente-teste",
        "titulo": "t", "categoria": "1. Teste", "arquivo": "src/app.ts", "linha": "5",
        "descricao": "d", "causa_alegada": "c", "evidencia": "nada disso existe",
        "bloqueadores": ["b"], "plano_validacao": {"local": "l"}})
    assert _erros_evidencia(projeto)


def test_mensagem_nao_imprime_conteudo_da_evidencia(projeto):
    projeto.gravar_registro(achado(evidencia="texto-unico-da-evidencia-xyz"))
    assert not any("texto-unico" in e for e in _erros_evidencia(projeto))
