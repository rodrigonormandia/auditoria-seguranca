from conftest import achado


def _unidade(**campos):
    base = {"id": "U1", "superficie": "s", "fronteira": "f", "subsistema": "x", "classe": "c",
            "status": "coberta", "caminhos": ["src"], "verificacao": "ok"}
    base.update(campos)
    return base


def _com_dirs(projeto):
    (projeto.raiz / "api").mkdir()
    (projeto.raiz / "api" / "x.ts").write_text("export {};\n", encoding="utf-8")
    projeto.commit()


def _erros_cob(projeto):
    erros, _ = projeto.validar()
    return [e for e in erros if "cobertura" in e.lower() or "EXCLUSOES" in e or "nao_alcancados" in e]


def test_diretorio_sem_unidade_nem_exclusao_e_erro(projeto):
    _com_dirs(projeto)
    projeto.gravar_cobertura([_unidade()])
    erros = _erros_cob(projeto)
    assert any("api" in e for e in erros), erros


def test_unidade_dentro_do_diretorio_resolve(projeto):
    _com_dirs(projeto)
    projeto.gravar_cobertura([_unidade(caminhos=["src/app.ts", "api/x.ts"])])
    assert _erros_cob(projeto) == []


def test_glob_conta_para_o_diretorio(projeto):
    _com_dirs(projeto)
    projeto.gravar_cobertura([_unidade(caminhos=["src/**/*.ts", "./api/*.ts"])])
    assert _erros_cob(projeto) == []


def test_exclusao_com_motivo_resolve(projeto):
    _com_dirs(projeto)
    projeto.gravar_cobertura([_unidade()])
    projeto.cabecalho(EXCLUSOES=[{"caminho": "api", "motivo": "gerado"}])
    assert _erros_cob(projeto) == []


def test_exclusao_sem_motivo_e_erro(projeto):
    _com_dirs(projeto)
    projeto.gravar_cobertura([_unidade()])
    projeto.cabecalho(EXCLUSOES=[{"caminho": "api", "motivo": ""}])
    assert any("EXCLUSOES" in e for e in _erros_cob(projeto))


def test_exclusao_da_raiz_e_erro(projeto):
    projeto.gravar_cobertura([_unidade()])
    projeto.cabecalho(EXCLUSOES=[{"caminho": ".", "motivo": "tudo"}])
    assert any("EXCLUSOES" in e for e in _erros_cob(projeto))


def test_fora_de_escopo_com_caminhos_presta_contas(projeto):
    _com_dirs(projeto)
    projeto.gravar_cobertura([
        _unidade(),
        _unidade(id="U2", status="fora_de_escopo", caminhos=["api"], verificacao="",
                 pendencia="rodada com escopo em src"),
    ])
    assert _erros_cob(projeto) == []


def test_nao_alcancados_gera_aviso(projeto):
    projeto.gravar_cobertura([_unidade(nao_alcancados=[{"caminho": "src/x", "motivo": "parou"}])])
    erros, avisos = projeto.validar()
    assert not _erros_cob(projeto), erros
    assert any("nao_alcancados" in a for a in avisos)


def test_nao_alcancados_malformado_e_erro(projeto):
    projeto.gravar_cobertura([_unidade(nao_alcancados=[{"caminho": "src/x"}])])
    assert any("nao_alcancados" in e for e in _erros_cob(projeto))


def test_sem_mapa_nao_cobra_diretorios(projeto):
    _com_dirs(projeto)
    projeto.gravar_registro(achado())
    assert _erros_cob(projeto) == []


def test_arquivo_na_raiz_nao_exige_unidade(projeto):
    (projeto.raiz / "package.json").write_text("{}\n", encoding="utf-8")
    projeto.commit()
    projeto.gravar_cobertura([_unidade()])
    assert _erros_cob(projeto) == []
