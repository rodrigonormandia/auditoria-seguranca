"""
Dados da auditoria de segurança de <PROJETO> (<AAAA-MM-DD>).

Este arquivo tem só o CABEÇALHO da auditoria (escopo, metodologia, resumo, pontos
fortes, recomendações). Os registros ficam um por arquivo:

    registros/<slug>.json   um achado, pendente ou descartado, gravado pelo verificador
                            que o validou (formato no PROMPTS.md da skill)
    cobertura.json          o mapa de cobertura (lista de unidades)

Nenhum achado é escrito aqui dentro. É de propósito: cada registro é pequeno, revisável
sozinho e corrigível com uma edição pontual — e reexecutar a auditoria não exige
reescrever um arquivo enorme. Antes de gerar, `validar_findings.py` confere a
consistência (o gerador o chama).

Três vereditos, que não se misturam (campo "veredito" de cada registro):
  confirmado  → ACHADOS              rastro completo + resultado observado; têm severidade.
  pendente    → PENDENTES_VALIDACAO  hipótese fundamentada na fonte, bloqueada por um fato
                                     fora do repositório; SEM severidade; têm bloqueadores
                                     e plano de validação.
  descartado  → DESCARTADOS          refutados na validação; ficam para a próxima rodada
                                     não repetir a mesma alegação.
  anterior    → ANTERIORES           revisão de mudança: real, mas a mudança não participa.
                                     Sem severidade e sem issue; entra na próxima auditoria.
  endurecimento → INFORMATIVOS       verdadeiro, mas não cruza fronteira: quem colhe o resultado
                                     já tem esse acesso, ou outra camada barra. Sem severidade.

Redação: documento de correção, não roteiro de ataque — o controle que falta, onde,
o trecho do próprio código, o impacto e a correção. Sem passo a passo de exploração.

Marcação aceita nos textos: <b>negrito</b>, <i>itálico</i>, <br/> e
<font color="#RRGGBB">. Sinais de menor/maior dentro do texto precisam ir
escapados (&lt; e &gt;) — o reportlab lê os campos como mini-XML.
"""

import json
import os
import re

PROJETO = "<Nome do projeto>"
DATA_AUDITORIA = "<28 de agosto de 2026>"
AUTOR = "Rodrigo Normandia"          # vai ao rodapé de todas as páginas e à capa
CONFIDENCIALIDADE = "Confidencial · uso interno"

# Perfil da rodada: "rapida" | "padrao" | "profunda" (ver SKILL.md). Sai na capa.
PERFIL = "padrao"
# Commit auditado e se a árvore estava suja. Ex.: "a1b2c3d (árvore limpa)".
REF_FONTE = ""
# Rodada anterior usada como entrada (caminho/data) ou "" na primeira auditoria.
RODADA_ANTERIOR = ""
# Revisão de mudança: {"base": "<sha>", "head": "<sha>"}. None em auditoria da base inteira.
MUDANCA = None
# Diretórios deliberadamente fora da caça: {"caminho": "dist", "motivo": "gerado no build"}.
# Todo diretório de topo versionado precisa aparecer aqui ou nos `caminhos` de uma unidade.
EXCLUSOES = []

# Paleta fixa da auditoria — não alterar sem motivo.
CORES = {
    "critica": "#B91C1C",
    "alta": "#EA580C",
    "media": "#D97706",
    "baixa": "#2563EB",
    "informativa": "#6B7280",
    "forte": "#059669",
    "pendente": "#7C3AED",
}

ORDEM_SEVERIDADE = ["critica", "alta", "media", "baixa", "informativa"]

ROTULO_SEVERIDADE = {
    "critica": "CRÍTICA",
    "alta": "ALTA",
    "media": "MÉDIA",
    "baixa": "BAIXA",
    "informativa": "INFORMATIVA",
}

# Stack detectada. Sai na capa, como escopo auditado.
STACK = {
    "Linguagem": "",
    "Framework": "",
    "Backend / dados": "",
    "Acesso a dados": "",
    "Autenticação": "",
    "Frontend": "",
    "Deploy": "",
}

# Uma frase sobre a superfície coberta (quantos handlers, quantas actions, se o
# banco e o histórico do git entraram). É o que prova a cobertura.
ESCOPO_TEXTO = (
    "Foram auditados N route handlers, N unidades de <b>...</b> e o histórico completo do "
    "repositório. A revisão cobre as categorias abaixo, mapeadas para os mecanismos que "
    "esta stack de fato usa."
)

# Como cada categoria foi traduzida para ESTA stack. Uma entrada por categoria,
# inclusive as que não se aplicam ("projeto sem frontend: n/a"). A "categoria" de
# cada registro tem de ser o título de uma entrada daqui (ou o começo dele).
METODOLOGIA = [
    ("1. Banco sem tranca (isolamento de inquilino)", ""),
    ("2. Permissão definida no navegador", ""),
    ("3. IDOR", ""),
    ("4. Chaves expostas", ""),
    ("5. Inputs sem tratamento (XSS)", ""),
]

# Dois ou três parágrafos de leitura executiva. Aceitam {total}, {criticos} e {pendentes}.
RESUMO = [
    "A auditoria registrou <b>{total} achados confirmados</b>, sendo <b>{criticos} de "
    "severidade crítica</b>, e <b>{pendentes} hipóteses pendentes de validação</b>. ",
    "",
]

# Notas de endurecimento: verificadas, sem fronteira violada (a camada A segura;
# falta a camada B). Entram na tabela e numa seção própria, mas não geram issue
# individual (ver ISSUES_AGRUPADAS).
INFORMATIVOS = [
    # {"id": "I1", "titulo": "", "categoria": "", "arquivo": "", "descricao": ""},
]

# O que foi verificado e está CORRETO. Prova a cobertura da auditoria.
PONTOS_FORTES = [
    # ("Título curto", "Evidência do que foi verificado e por que segura."),
]

PONTOS_FRACOS = [
    # ("Título curto", "O risco central, em prosa."),
]

# (prioridade, ação, detalhe, severidade_para_a_cor)
RECOMENDACOES = [
    # ("P1", "", "", "critica"),
]

NOTA_RECOMENDACOES = "A ordem reflete risco e janela de exposição, não esforço."

# Uma frase sobre o resultado do crítico de cobertura final e o que ficou de fora.
NOTA_COBERTURA = ""

# Issues que agrupam vários achados relacionados de baixo risco, para não gerar
# spam de issues. Cada uma vira um bloco Markdown a mais no fim do PDF.
ISSUES_AGRUPADAS = [
    # {
    #     "titulo": "Higiene: observações informativas da auditoria (I1-I4)",
    #     "labels": ["security", "informativa", "good first issue"],
    #     "problema": "",
    #     "itens": INFORMATIVOS,
    #     "impacto": "",
    #     "correcao": ["", ""],
    #     "criterios": ["", ""],
    # },
]


# ─────────────────────────────────────────────────────────────────────────────
# Carregador — não editar. Lê registros/*.json e cobertura.json ao lado deste
# arquivo, separa por veredito e numera (A1.., P1.., D1..) o que vier sem "id".
#
# Campos de cada registro: ver "Formato do registro" no PROMPTS.md da skill.
# Opcionais que se acrescentam depois, editando o arquivo do registro:
#   "id": "A3"                         fixa o número (senão é dado pela ordem)
#   "status": "CORRIGIDO em dd/mm/aaaa"
#   "issue": 123                       nº da issue já aberta
#
# Status das unidades de cobertura.json:
#   coberta        revisada, sem candidato (exige caminhos e verificacao)
#   candidata      gerou registro (exige fingerprints que existam em registros/)
#   bloqueada      revisão parcial; falta fato (exige caminhos e pendencia)
#   nao_aplicavel  o gatilho não existe nesta stack (exige pendencia = motivo)
#   fora_de_escopo auditoria com escopo; fica visível para a próxima rodada
#   adiada         orçamento/perfil não alcançou (exige pendencia = motivo)
# Unidade: {"id", "superficie", "fronteira", "subsistema", "classe", "status",
#           "caminhos": [], "verificacao": "", "fingerprints": [], "pendencia": "",
#           "nao_alcancados": [{"caminho": "", "motivo": ""}]}
# ─────────────────────────────────────────────────────────────────────────────

_AQUI = os.path.dirname(os.path.abspath(__file__))
_VEREDITOS = {"confirmado": "A", "pendente": "P", "descartado": "D", "anterior": "X",
              "endurecimento": "I"}


def _ler_json(caminho):
    with open(caminho, encoding="utf-8") as f:
        return json.load(f)


def _carregar_registros():
    por_veredito = {v: [] for v in _VEREDITOS}
    pasta = os.path.join(_AQUI, "registros")
    # listdir, não glob: o slug de ".github/..." começa com ponto e o glob o esconde.
    nomes = sorted(n for n in os.listdir(pasta) if n.endswith(".json")) if os.path.isdir(pasta) else []
    for nome in nomes:
        caminho = os.path.join(pasta, nome)
        try:
            reg = _ler_json(caminho)
        except ValueError as exc:
            raise SystemExit(f"registros/{nome}: JSON inválido — {exc}")
        veredito = reg.pop("veredito", None) if isinstance(reg, dict) else None
        if veredito not in _VEREDITOS:
            raise SystemExit(
                f'registros/{nome}: "veredito" tem de ser confirmado, pendente, descartado, '
                'anterior ou endurecimento')
        reg["_arquivo"] = nome          # para anotar a issue de volta no registro
        por_veredito[veredito].append(reg)
    return por_veredito


def _numerar(registros, prefixo, ordem, reservados=()):
    """Dá id a quem não tem, na ordem pedida, sem colidir com ids fixados à mão."""
    usados = {r["id"] for r in registros if r.get("id")} | set(reservados)
    n = 0
    for reg in sorted(registros, key=ordem):
        if reg.get("id"):
            continue
        n += 1
        while f"{prefixo}{n}" in usados:
            n += 1
        reg["id"] = f"{prefixo}{n}"
        usados.add(reg["id"])
    return sorted(registros, key=lambda r: (int(re.sub(r"\D", "", r["id"]) or 0), r["id"]))


def _sev(reg):
    sev = reg.get("severidade")
    return ORDEM_SEVERIDADE.index(sev) if sev in ORDEM_SEVERIDADE else len(ORDEM_SEVERIDADE)


_REG = _carregar_registros()

# Confirmados: do mais severo para o menos, depois por categoria e fingerprint.
ACHADOS = _numerar(
    _REG["confirmado"], "A",
    lambda r: (_sev(r), str(r.get("categoria", "")), str(r.get("fingerprint", ""))))
PENDENTES_VALIDACAO = _numerar(
    _REG["pendente"], "P",
    lambda r: (str(r.get("categoria", "")), str(r.get("fingerprint", ""))))
DESCARTADOS = _numerar(
    _REG["descartado"], "D", lambda r: str(r.get("fingerprint", "")))
ANTERIORES = _numerar(
    _REG["anterior"], "X", lambda r: str(r.get("fingerprint", "")))
# Notas do cabeçalho e as decididas pelo painel saem na mesma seção.
INFORMATIVOS = list(INFORMATIVOS) + _numerar(
    _REG["endurecimento"], "I", lambda r: str(r.get("fingerprint", "")),
    reservados=[i.get("id") for i in INFORMATIVOS])

_COBERTURA_JSON = os.path.join(_AQUI, "cobertura.json")
COBERTURA = _ler_json(_COBERTURA_JSON) if os.path.exists(_COBERTURA_JSON) else []
