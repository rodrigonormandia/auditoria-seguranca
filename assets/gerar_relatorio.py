"""
Gerador do relatório de auditoria de segurança (PDF). Só layout — nenhum conteúdo
de auditoria mora aqui.

Uso (a partir da raiz do repositório):
    docs/security-audit/.venv/Scripts/python.exe docs/security-audit/gerar_relatorio.py   # Windows
    docs/security-audit/.venv/bin/python docs/security-audit/gerar_relatorio.py           # Linux/macOS

Dependências (no venv isolado docs/security-audit/.venv):
    reportlab, matplotlib

Os dados vivem em `findings.py`, ao lado deste arquivo. Reexecutar a auditoria é
reescrever findings.py e rodar isto de novo, sem tocar em layout.
"""

from __future__ import annotations

import os
import re
import sys
import textwrap
from datetime import date

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)

import findings as F  # noqa: E402

ACHADOS = F.ACHADOS
CORES = F.CORES
DATA_AUDITORIA = F.DATA_AUDITORIA
METODOLOGIA = F.METODOLOGIA
ORDEM_SEVERIDADE = F.ORDEM_SEVERIDADE
PONTOS_FORTES = F.PONTOS_FORTES
PONTOS_FRACOS = F.PONTOS_FRACOS
PROJETO = F.PROJETO
RECOMENDACOES = F.RECOMENDACOES
ROTULO_SEVERIDADE = F.ROTULO_SEVERIDADE
STACK = F.STACK

# Campos opcionais: o relatório sai coerente mesmo quando a rodada não os usa.
INFORMATIVOS = getattr(F, "INFORMATIVOS", [])
ISSUES_AGRUPADAS = getattr(F, "ISSUES_AGRUPADAS", [])
AUTOR = getattr(F, "AUTOR", "")
ESCOPO_TEXTO = getattr(F, "ESCOPO_TEXTO", "")
RESUMO = getattr(F, "RESUMO", [])
NOTA_RECOMENDACOES = getattr(
    F, "NOTA_RECOMENDACOES",
    "A ordem reflete risco e janela de exposição, não esforço.",
)
CONFIDENCIALIDADE = getattr(F, "CONFIDENCIALIDADE", "Confidencial · uso interno")
PERFIL = getattr(F, "PERFIL", "")
REF_FONTE = getattr(F, "REF_FONTE", "")
RODADA_ANTERIOR = getattr(F, "RODADA_ANTERIOR", "")
PENDENTES = getattr(F, "PENDENTES_VALIDACAO", [])
DESCARTADOS = getattr(F, "DESCARTADOS", [])
COBERTURA = getattr(F, "COBERTURA", [])
NOTA_COBERTURA = getattr(F, "NOTA_COBERTURA", "")
ANTERIORES = getattr(F, "ANTERIORES", [])
EXCLUSOES = getattr(F, "EXCLUSOES", [])
MUDANCA = getattr(F, "MUDANCA", None)
CORES.setdefault("pendente", "#7C3AED")

try:
    import apurar_votos
except ImportError:
    apurar_votos = None

ROTULO_PERFIL = {"rapida": "rápida", "padrao": "padrão", "profunda": "profunda"}
# Status de cobertura → (rótulo do chip, cor). O mapa de cobertura é a alegação de
# cobertura da auditoria; o chip deixa visível o que ficou de fora.
STATUS_COBERTURA = {
    "coberta": ("COBERTA", CORES["forte"]),
    "candidata": ("CANDIDATA", CORES["alta"]),
    "bloqueada": ("BLOQUEADA", CORES["media"]),
    "nao_aplicavel": ("N/A", CORES["informativa"]),
    "fora_de_escopo": ("FORA", CORES["informativa"]),
    "adiada": ("ADIADA", CORES["baixa"]),
    "planejada": ("PLANEJADA", CORES["baixa"]),
}
ORDEM_STATUS = ["coberta", "candidata", "bloqueada", "adiada", "fora_de_escopo",
                "nao_aplicavel", "planejada"]

SAIDA = os.path.join(AQUI, "relatorio-auditoria-seguranca.pdf")
NOME_RELATORIO = f"Relatório de Auditoria de Segurança — {PROJETO}"

MARGEM = 2 * cm
LARGURA_UTIL = A4[0] - 2 * MARGEM

TINTA = colors.HexColor("#111827")
TINTA_SUAVE = colors.HexColor("#4B5563")
LINHA = colors.HexColor("#E5E7EB")
FUNDO_CODIGO = colors.HexColor("#F8FAFC")


# ─────────────────────────────────────────────────────────────────────────────
# Estilos
# ─────────────────────────────────────────────────────────────────────────────

def montar_estilos():
    base = getSampleStyleSheet()
    e = {}

    e["titulo_capa"] = ParagraphStyle(
        "titulo_capa", parent=base["Title"], fontName="Helvetica-Bold",
        fontSize=25, leading=31, textColor=TINTA, alignment=TA_CENTER, spaceAfter=6,
    )
    e["sub_capa"] = ParagraphStyle(
        "sub_capa", parent=base["Normal"], fontName="Helvetica",
        fontSize=12, leading=18, textColor=TINTA_SUAVE, alignment=TA_CENTER,
    )
    e["h1"] = ParagraphStyle(
        "h1", parent=base["Heading1"], fontName="Helvetica-Bold",
        fontSize=16, leading=21, textColor=TINTA, spaceBefore=2, spaceAfter=9,
    )
    e["h2"] = ParagraphStyle(
        "h2", parent=base["Heading2"], fontName="Helvetica-Bold",
        fontSize=12, leading=16, textColor=TINTA, spaceBefore=13, spaceAfter=5,
    )
    e["h3"] = ParagraphStyle(
        "h3", parent=base["Heading3"], fontName="Helvetica-Bold",
        fontSize=9.5, leading=13, textColor=TINTA_SUAVE, spaceBefore=8, spaceAfter=3,
    )
    e["corpo"] = ParagraphStyle(
        "corpo", parent=base["Normal"], fontName="Helvetica",
        fontSize=9.3, leading=13.6, textColor=TINTA, alignment=TA_JUSTIFY, spaceAfter=6,
    )
    e["corpo_tab"] = ParagraphStyle(
        "corpo_tab", parent=e["corpo"], fontSize=8.4, leading=12, spaceAfter=0,
    )
    e["mono_tab"] = ParagraphStyle(
        "mono_tab", parent=base["Normal"], fontName="Courier",
        fontSize=6.9, leading=9.4, textColor=TINTA,
    )
    e["codigo"] = ParagraphStyle(
        "codigo", parent=base["Code"], fontName="Courier",
        fontSize=7.1, leading=9.4, textColor=colors.HexColor("#1F2937"),
        backColor=FUNDO_CODIGO, borderPadding=6, leftIndent=2, spaceAfter=7,
    )
    e["chip"] = ParagraphStyle(
        "chip", parent=base["Normal"], fontName="Helvetica-Bold",
        fontSize=7.4, leading=9.6, textColor=colors.white, alignment=TA_CENTER,
    )
    e["legenda"] = ParagraphStyle(
        "legenda", parent=base["Normal"], fontName="Helvetica-Oblique",
        fontSize=8, leading=11, textColor=TINTA_SUAVE, alignment=TA_CENTER, spaceAfter=3,
    )
    return e


ESTILOS = montar_estilos()

# Marcação que o mini-parser do reportlab entende. Qualquer outro "<" nos textos
# da auditoria é conteúdo (`<script>`, `<iframe ...>`) e derruba o parser com
# "unclosed tags" — daí o escape defensivo abaixo, aplicado em todo Paragraph.
_TAGS_PERMITIDAS = ("b", "/b", "i", "/i", "u", "/u", "br/", "font", "/font", "super", "sub")


def P(texto: str, estilo) -> Paragraph:
    """
    Paragraph com escape do que não é marcação reconhecida e com as crases do
    markdown viradas em monoespaçado — os mesmos textos alimentam as issues em
    Markdown, onde a crase é a marcação certa, e o PDF, onde ela seria literal.
    """
    saida, i = [], 0
    while i < len(texto):
        c = texto[i]
        if c != "<":
            saida.append(c)
            i += 1
            continue
        fim = texto.find(">", i)
        interior = texto[i + 1:fim] if fim != -1 else ""
        nome = interior.split(" ", 1)[0].strip().lower()
        if fim != -1 and nome in _TAGS_PERMITIDAS:
            saida.append(texto[i:fim + 1])
            i = fim + 1
        else:
            saida.append("&lt;")
            i += 1

    # Feito depois do escape para que `<script>` entre crases já esteja seguro.
    marcado = re.sub(r"`([^`]+)`", r'<font face="Courier">\1</font>', "".join(saida))
    return Paragraph(marcado, estilo)


def chip(rotulo: str, cor: str) -> Table:
    """Etiqueta colorida genérica (severidade, pendente, status de cobertura)."""
    p = P(rotulo, ESTILOS["chip"])
    t = Table([[p]], colWidths=[2.35 * cm], rowHeights=[0.52 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(cor)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def chip_severidade(sev: str) -> Table:
    """Etiqueta colorida da severidade, usada nas tabelas de achados."""
    return chip(ROTULO_SEVERIDADE[sev], CORES[sev])


def chip_pendente() -> Table:
    return chip("PENDENTE", CORES["pendente"])


def chip_status(status: str) -> Table:
    rotulo, cor = STATUS_COBERTURA.get(status, (status.upper(), CORES["informativa"]))
    return chip(rotulo, cor)


def bloco_codigo(texto: str, largura_cols: int = 112):
    """
    Bloco monoespaçado. `Preformatted` não quebra linha sozinho, então as linhas
    longas são dobradas aqui — senão o texto vaza para fora da margem direita.
    """
    linhas = []
    for linha in texto.split("\n"):
        if len(linha) <= largura_cols:
            linhas.append(linha)
            continue
        recuo = len(linha) - len(linha.lstrip())
        dobradas = textwrap.wrap(
            linha, width=largura_cols,
            subsequent_indent=" " * (recuo + 4),
            break_long_words=True, break_on_hyphens=False,
            replace_whitespace=False, drop_whitespace=False,
        )
        linhas.extend(dobradas or [linha])
    return Preformatted("\n".join(linhas), ESTILOS["codigo"])


# ─────────────────────────────────────────────────────────────────────────────
# Gráficos
# ─────────────────────────────────────────────────────────────────────────────

def grafico_rosca(caminho: str, contagem: dict) -> str | None:
    itens = [(s, contagem[s]) for s in ORDEM_SEVERIDADE if contagem.get(s)]
    if not itens:
        return None

    rotulos = [ROTULO_SEVERIDADE[s].capitalize() for s, _ in itens]
    valores = [v for _, v in itens]
    cores = [CORES[s] for s, _ in itens]

    fig, ax = plt.subplots(figsize=(4.5, 3.5), dpi=200)
    wedges, _ = ax.pie(
        valores, colors=cores, startangle=90, counterclock=False,
        wedgeprops={"width": 0.42, "edgecolor": "white", "linewidth": 2},
    )
    ax.text(0, 0.10, str(sum(valores)), ha="center", va="center",
            fontsize=25, fontweight="bold", color="#111827")
    ax.text(0, -0.22, "achados", ha="center", va="center",
            fontsize=9.5, color="#6B7280")
    ax.legend(
        wedges, [f"{r}  ({v})" for r, v in zip(rotulos, valores)],
        loc="center left", bbox_to_anchor=(1.0, 0.5),
        frameon=False, fontsize=9,
    )
    ax.set_aspect("equal")
    fig.tight_layout()
    fig.savefig(caminho, transparent=True, bbox_inches="tight")
    plt.close(fig)
    return caminho


def grafico_barras(caminho: str, por_categoria: dict) -> str | None:
    if not por_categoria:
        return None

    # Categoria mais severa define a cor da barra — a contagem sozinha esconderia
    # que uma barra de 1 achado pode ser a crítica.
    nomes, valores, cores = [], [], []
    for cat in sorted(por_categoria, key=lambda c: c[0]):
        sevs = por_categoria[cat]
        pior = min(sevs, key=lambda s: ORDEM_SEVERIDADE.index(s))
        nomes.append("\n".join(textwrap.wrap(cat, 22)))
        valores.append(len(sevs))
        cores.append(CORES[pior])

    fig, ax = plt.subplots(figsize=(7.2, 3.1), dpi=200)
    barras = ax.bar(nomes, valores, color=cores, width=0.56)
    for b, v in zip(barras, valores):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.06, str(v),
                ha="center", va="bottom", fontsize=10, fontweight="bold", color="#111827")

    ax.set_ylim(0, max(valores) + 0.9)
    ax.set_ylabel("achados", fontsize=9, color="#6B7280")
    ax.tick_params(axis="x", labelsize=7.6, colors="#374151")
    ax.tick_params(axis="y", labelsize=8.5, colors="#6B7280")
    ax.set_yticks(range(0, max(valores) + 1))
    for lado in ("top", "right", "left"):
        ax.spines[lado].set_visible(False)
    ax.spines["bottom"].set_color("#D1D5DB")
    ax.grid(axis="y", color="#F3F4F6", linewidth=1)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(caminho, transparent=True, bbox_inches="tight")
    plt.close(fig)
    return caminho


# ─────────────────────────────────────────────────────────────────────────────
# Cabeçalho / rodapé
# ─────────────────────────────────────────────────────────────────────────────

def encurtar(texto, largura_max, medir):
    """Corta o texto com reticências até caber em `largura_max`, segundo `medir(texto)`."""
    if medir(texto) <= largura_max:
        return texto
    while texto and medir(texto + "…") > largura_max:
        texto = texto[:-1]
    return texto.rstrip() + "…"


def _moldura(canvas, doc, com_cabecalho: bool):
    canvas.saveState()
    largura, altura = A4

    def medir(texto):
        return canvas.stringWidth(texto, "Helvetica", 7.6)

    if com_cabecalho:
        canvas.setFont("Helvetica", 7.6)
        canvas.setFillColor(TINTA_SUAVE)
        titulo_max = largura - 2 * MARGEM - medir(CONFIDENCIALIDADE) - 0.5 * cm
        canvas.drawString(MARGEM, altura - MARGEM + 0.42 * cm,
                          encurtar(NOME_RELATORIO, titulo_max, medir))
        canvas.drawRightString(largura - MARGEM, altura - MARGEM + 0.42 * cm,
                               CONFIDENCIALIDADE)
        canvas.setStrokeColor(LINHA)
        canvas.setLineWidth(0.5)
        canvas.line(MARGEM, altura - MARGEM + 0.24 * cm,
                    largura - MARGEM, altura - MARGEM + 0.24 * cm)

    canvas.setStrokeColor(LINHA)
    canvas.setLineWidth(0.5)
    canvas.line(MARGEM, MARGEM - 0.42 * cm, largura - MARGEM, MARGEM - 0.42 * cm)
    canvas.setFont("Helvetica", 7.6)
    canvas.setFillColor(TINTA_SUAVE)
    # O centro é do autor e a direita, da página: o projeto encolhe, a data continua inteira.
    autor = f"Análise por {AUTOR}" if AUTOR else ""
    limite = largura / 2 - medir(autor) / 2 if autor else largura - 2.5 * cm
    data = f" · {DATA_AUDITORIA}"
    projeto = encurtar(PROJETO, limite - MARGEM - 0.4 * cm - medir(data), medir)
    canvas.drawString(MARGEM, MARGEM - 0.85 * cm, projeto + data)
    if autor:
        canvas.drawCentredString(largura / 2, MARGEM - 0.85 * cm, autor)
    canvas.drawRightString(largura - MARGEM, MARGEM - 0.85 * cm, f"página {doc.page}")
    canvas.restoreState()


def moldura_capa(canvas, doc):
    _moldura(canvas, doc, com_cabecalho=False)


def moldura_miolo(canvas, doc):
    _moldura(canvas, doc, com_cabecalho=True)


# ─────────────────────────────────────────────────────────────────────────────
# Seções
# ─────────────────────────────────────────────────────────────────────────────

def secao_capa(hist):
    hist.append(Spacer(1, 3.6 * cm))
    hist.append(P(f"Relatório de Auditoria<br/>de Segurança — {PROJETO}", ESTILOS["titulo_capa"]))
    hist.append(Spacer(1, 0.5 * cm))

    faixa = Table([[""]], colWidths=[5 * cm], rowHeights=[0.13 * cm])
    faixa.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(CORES["critica"]))]))
    faixa.hAlign = "CENTER"
    hist.append(faixa)

    hist.append(Spacer(1, 0.75 * cm))
    hist.append(P(DATA_AUDITORIA, ESTILOS["sub_capa"]))
    hist.append(P("Revisão adversarial de código e de banco de dados", ESTILOS["sub_capa"]))
    if AUTOR:
        hist.append(P(f"Análise por {AUTOR}", ESTILOS["sub_capa"]))
    hist.append(Spacer(1, 1.5 * cm))

    hist.append(P("Escopo auditado", ESTILOS["h2"]))
    linhas = [[P(f"<b>{k}</b>", ESTILOS["corpo_tab"]), P(v, ESTILOS["corpo_tab"])]
              for k, v in STACK.items()]
    # Perfil, commit e rodada anterior dizem o quanto esta rodada cobre — uma
    # rodada rápida ou com escopo se apresenta como parcial, não como completa.
    if PERFIL:
        linhas.append([P("<b>Perfil da rodada</b>", ESTILOS["corpo_tab"]),
                       P(ROTULO_PERFIL.get(PERFIL, PERFIL), ESTILOS["corpo_tab"])])
    if REF_FONTE:
        linhas.append([P("<b>Commit auditado</b>", ESTILOS["corpo_tab"]),
                       P(REF_FONTE, ESTILOS["mono_tab"])])
    if RODADA_ANTERIOR:
        linhas.append([P("<b>Rodada anterior</b>", ESTILOS["corpo_tab"]),
                       P(RODADA_ANTERIOR, ESTILOS["corpo_tab"])])
    if MUDANCA:
        linhas.append([P("<b>Mudança revisada</b>", ESTILOS["corpo_tab"]),
                       P(f'{MUDANCA["base"]}..{MUDANCA["head"]}', ESTILOS["mono_tab"])])
    if apurar_votos:
        # Derivado dos votos gravados: é o que impede o relatório de alegar uma verificação
        # que não aconteceu.
        linhas.append([P("<b>Verificação</b>", ESTILOS["corpo_tab"]),
                       P(apurar_votos.carimbo(
                           AQUI, [*ACHADOS, *PENDENTES, *DESCARTADOS, *ANTERIORES,
                                  *[i for i in INFORMATIVOS if i.get("fingerprint")]], PERFIL),
                         ESTILOS["corpo_tab"])])
    t = Table(linhas, colWidths=[4.3 * cm, LARGURA_UTIL - 4.3 * cm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINHA),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    hist.append(t)

    if ESCOPO_TEXTO:
        hist.append(Spacer(1, 0.7 * cm))
        hist.append(P(ESCOPO_TEXTO, ESTILOS["corpo"]))

    hist.append(P("Nota metodológica", ESTILOS["h2"]))
    for titulo, texto in METODOLOGIA:
        hist.append(P(f"<b>{titulo}</b>", ESTILOS["h3"]))
        hist.append(P(texto, ESTILOS["corpo"]))

    hist.append(P(
        "Só entram como <b>achados</b> falhas confirmadas no código ou no banco reais, cada uma com "
        "arquivo, linha e trecho, verificadas por um revisor independente de quem as encontrou. "
        "Onde a exploração depende de uma condição (uma configuração que ainda não existe, uma "
        "barreira em outro arquivo), a condição está declarada junto ao achado — inclusive quando "
        "ela torna a falha hoje inexplorável. Hipóteses cuja confirmação depende de um fato fora "
        "do repositório (proxy, provedor de identidade, política de infraestrutura) ficam na seção "
        "<b>pendentes de validação</b>, sem severidade, com o fato que falta e como obtê-lo. "
        "Candidatos refutados ficam no apêndice, para que a próxima rodada não os repita.",
        ESTILOS["corpo"]))
    hist.append(NextPageTemplate("miolo"))
    hist.append(PageBreak())


def secao_resumo(hist, contagem, por_categoria, img_rosca, img_barras):
    hist.append(P("Resumo executivo", ESTILOS["h1"]))

    total = sum(contagem.values())
    criticos = contagem.get("critica", 0)
    pendentes = len(PENDENTES)
    paragrafos = RESUMO or [
        f"A auditoria registrou <b>{total} achados</b>, sendo <b>{criticos} de severidade "
        "crítica</b>. O detalhamento por categoria vem adiante, cada achado com arquivo, linha "
        "e trecho."
    ]
    for texto in paragrafos:
        hist.append(P(texto.format(total=total, criticos=criticos, pendentes=pendentes),
                      ESTILOS["corpo"]))

    dados = [[
        P("<b>Severidade</b>", ESTILOS["corpo_tab"]),
        P("<b>Quantidade</b>", ESTILOS["corpo_tab"]),
        P("<b>Leitura</b>", ESTILOS["corpo_tab"]),
    ]]
    leitura = {
        "critica": "Exposição ativa; exige ação imediata.",
        "alta": "Exploração direta por ator com acesso parcial.",
        "media": "Exploração condicionada a uma configuração plausível e próxima.",
        "baixa": "Sem exploração conhecida hoje; risco de manutenção ou defesa em profundidade.",
        "informativa": "Observação verificada, sem exploração; higiene.",
    }
    for sev in ORDEM_SEVERIDADE:
        if not contagem.get(sev):
            continue
        dados.append([chip_severidade(sev),
                      P(str(contagem[sev]), ESTILOS["corpo_tab"]),
                      P(leitura[sev], ESTILOS["corpo_tab"])])

    # Pendentes entram na mesma tabela, mas fora da contagem de achados e sem
    # severidade: são hipóteses bloqueadas por um fato externo, não falhas.
    if pendentes:
        dados.append([chip_pendente(),
                      P(str(pendentes), ESTILOS["corpo_tab"]),
                      P("Hipótese fundamentada na fonte, à espera de um fato fora do "
                        "repositório; sem severidade até ser validada.", ESTILOS["corpo_tab"])])

    t = Table(dados, colWidths=[2.9 * cm, 2.4 * cm, LARGURA_UTIL - 5.3 * cm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, TINTA),
        ("LINEBELOW", (0, 1), (-1, -2), 0.4, LINHA),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    hist.append(Spacer(1, 0.2 * cm))
    hist.append(t)
    hist.append(Spacer(1, 0.7 * cm))

    if img_rosca:
        hist.append(P("Distribuição por severidade", ESTILOS["h2"]))
        hist.append(Image(img_rosca, width=10.2 * cm, height=5.7 * cm, hAlign="CENTER"))
        hist.append(Spacer(1, 0.35 * cm))

    if img_barras:
        bloco = [
            P("Achados por categoria", ESTILOS["h2"]),
            Image(img_barras, width=15.3 * cm, height=6.0 * cm, hAlign="CENTER"),
            P("A cor de cada barra corresponde ao achado mais severo daquela categoria.",
                      ESTILOS["legenda"]),
        ]
        hist.append(KeepTogether(bloco))
        hist.append(Spacer(1, 0.55 * cm))


def secao_fortes_fracos(hist):
    hist.append(P("Pontos fortes", ESTILOS["h1"]))
    hist.append(P(
        "Esta seção existe tanto para registrar o que protege o sistema hoje quanto para provar a "
        "cobertura da auditoria: cada item abaixo foi verificado, não presumido.", ESTILOS["corpo"]))

    for titulo, texto in PONTOS_FORTES:
        marca = Table([[""]], colWidths=[0.13 * cm], rowHeights=[0.36 * cm])
        marca.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(CORES["forte"]))]))
        cabecalho = Table(
            [[marca, P(f"<b>{titulo}</b>", ESTILOS["corpo_tab"])]],
            colWidths=[0.42 * cm, LARGURA_UTIL - 0.42 * cm],
        )
        cabecalho.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        hist.append(KeepTogether([cabecalho, P(texto, ESTILOS["corpo"])]))

    if PONTOS_FRACOS:
        hist.append(P("Pontos fracos", ESTILOS["h1"]))
        hist.append(P("Os riscos centrais, na ordem em que importam.", ESTILOS["corpo"]))
    for titulo, texto in PONTOS_FRACOS:
        hist.append(KeepTogether([
            P(f"<b>{titulo}</b>", ESTILOS["h3"]),
            P(texto, ESTILOS["corpo"]),
        ]))
    hist.append(PageBreak())


def _linha_rotulo(rotulo, valor, mono=False):
    estilo = ESTILOS["mono_tab"] if mono else ESTILOS["corpo_tab"]
    t = Table(
        [[P(f"<b>{rotulo}</b>", ESTILOS["corpo_tab"]), P(valor, estilo)]],
        colWidths=[2.6 * cm, LARGURA_UTIL - 2.6 * cm],
    )
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def _calibracao(a: dict) -> str:
    """Probabilidade × impacto × confiança, quando a rodada os informou."""
    partes = []
    if a.get("probabilidade"):
        partes.append(f"probabilidade <b>{ROTULO_SEVERIDADE[a['probabilidade']].lower()}</b>")
    if a.get("impacto_nivel"):
        partes.append(f"impacto <b>{ROTULO_SEVERIDADE[a['impacto_nivel']].lower()}</b>")
    if a.get("confianca"):
        partes.append(f"confiança na evidência <b>{a['confianca']}</b>")
    placar = apurar_votos.placar_de(AQUI, a) if apurar_votos else None
    if placar:
        partes.append(f"painel <b>{placar}</b>")
    return " · ".join(partes)


_ROTULO_RASTRO = {"entrada": "entrada", "propagacao": "propagação", "destino": "destino"}

# Como o registro se relaciona com a documentação de produto do projeto (épicos,
# stories, specs, ADRs, planos). Quem corrige precisa saber se a correção segue o
# que está escrito, bate de frente com uma decisão ou já está no plano.
_ROTULO_CONTEXTO = {
    "respeita": "a correção segue o que está documentado",
    "contraria": "a correção contraria o documentado — exige decisão do dono",
    "ja_planejado": "já previsto no planejamento",
    "intencional": "comportamento documentado como intencional",
    "sem_documentacao": "sem documentação sobre o tema",
}


def _bloco_contexto(reg: dict) -> list:
    """Flowables do bloco "Contexto do projeto", ou lista vazia se o registro não tem."""
    itens = reg.get("contexto_projeto") or []
    if not itens:
        return []
    bloco = []
    if reg.get("decisao_necessaria"):
        bloco += [
            P(f'<font color="{CORES["alta"]}">Decisão necessária antes de implementar</font>',
              ESTILOS["h3"]),
            P(reg["decisao_necessaria"], ESTILOS["corpo"]),
        ]
    bloco.append(P("Contexto do projeto", ESTILOS["h3"]))
    for c in itens:
        rotulo = _ROTULO_CONTEXTO.get(c.get("relacao"), c.get("relacao", ""))
        cor = CORES["alta"] if c.get("relacao") == "contraria" else "#4B5563"
        doc = f' <font face="Courier" size="7.5">{c["documento"]}</font>' if c.get("documento") else ""
        regra = f'<br/><i>“{c["trecho"]}”</i>' if c.get("trecho") else ""
        bloco.append(P(f'• <font color="{cor}"><b>{rotulo}</b></font>{doc}{regra}'
                       f'<br/>{c.get("nota", "")}', ESTILOS["corpo"]))
    return bloco


def _md_contexto(reg: dict) -> list[str]:
    """O mesmo bloco, em Markdown, para a issue."""
    itens = reg.get("contexto_projeto") or []
    if not itens:
        return []
    linhas = []
    if reg.get("decisao_necessaria"):
        linhas += ["## Decisão necessária antes de implementar", "",
                   _limpar(reg["decisao_necessaria"]), ""]
    linhas += ["## Contexto do projeto", ""]
    for c in itens:
        rotulo = _ROTULO_CONTEXTO.get(c.get("relacao"), c.get("relacao", ""))
        doc = f' `{c["documento"]}`' if c.get("documento") else ""
        linhas.append(f'- **{rotulo}**{doc}')
        if c.get("trecho"):
            linhas.append(f'  > {_limpar(c["trecho"])}')
        linhas.append(f'  {_limpar(c.get("nota", ""))}')
    return linhas + [""]


def _tabela_rastro(rastro: list) -> Table:
    """Caminho entrada → propagação → destino, um passo por linha."""
    dados = []
    for passo in rastro:
        dados.append([
            P(f"<b>{_ROTULO_RASTRO.get(passo['tipo'], passo['tipo'])}</b>", ESTILOS["corpo_tab"]),
            P(f"{passo['arquivo']}:{passo['linha']}", ESTILOS["mono_tab"]),
            P(passo["descricao"], ESTILOS["corpo_tab"]),
        ])
    t = Table(dados, colWidths=[2.2 * cm, 5.4 * cm, LARGURA_UTIL - 7.6 * cm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINHA),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-2, -1), 6),
    ]))
    return t


def secao_achados(hist):
    hist.append(P("Achados detalhados", ESTILOS["h1"]))

    # Índice — severidade, localização e descrição, como pedido.
    dados = [[
        P("<b>Severidade</b>", ESTILOS["corpo_tab"]),
        P("<b>Arquivo : linha</b>", ESTILOS["corpo_tab"]),
        P("<b>Descrição</b>", ESTILOS["corpo_tab"]),
    ]]
    for a in ACHADOS:
        desc = f'<b>{a["id"]}.</b> {a["titulo"]}'
        if a.get("status"):
            desc += f'<br/><font color="{CORES["forte"]}"><b>{a["status"]}</b></font>'
        if a.get("issue"):
            desc += f'<br/><font color="#6B7280">issue #{a["issue"]}</font>'
        dados.append([
            chip_severidade(a["severidade"]),
            P(f'{a["arquivo"]}<br/><font color="#6B7280">{a["linha"]}</font>',
                      ESTILOS["mono_tab"]),
            P(desc, ESTILOS["corpo_tab"]),
        ])
    for i in INFORMATIVOS:
        dados.append([
            chip_severidade("informativa"),
            P(i["arquivo"], ESTILOS["mono_tab"]),
            P(f'<b>{i["id"]}.</b> {i["titulo"]}', ESTILOS["corpo_tab"]),
        ])
    for p in PENDENTES:
        local = p["arquivo"] + (f'<br/><font color="#6B7280">{p["linha"]}</font>'
                                if p.get("linha") else "")
        dados.append([
            chip_pendente(),
            P(local, ESTILOS["mono_tab"]),
            P(f'<b>{p["id"]}.</b> {p["titulo"]}', ESTILOS["corpo_tab"]),
        ])

    t = Table(dados, colWidths=[2.9 * cm, 6.6 * cm, LARGURA_UTIL - 9.5 * cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, TINTA),
        ("LINEBELOW", (0, 1), (-1, -2), 0.4, LINHA),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, -1), 8),
    ]))
    hist.append(t)
    hist.append(PageBreak())

    # Detalhamento, agrupado por categoria.
    categorias = []
    for a in ACHADOS:
        if a["categoria"] not in categorias:
            categorias.append(a["categoria"])

    for cat in sorted(categorias):
        hist.append(P(f"Categoria {cat}", ESTILOS["h1"]))
        for a in [x for x in ACHADOS if x["categoria"] == cat]:
            cab = Table(
                [[chip_severidade(a["severidade"]),
                  P(f'<b>{a["id"]} — {a["titulo"]}</b>', ESTILOS["corpo_tab"])]],
                colWidths=[2.6 * cm, LARGURA_UTIL - 2.6 * cm],
            )
            cab.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (0, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            hist.append(KeepTogether([
                cab,
                _linha_rotulo("Arquivo", a["arquivo"], mono=True),
                _linha_rotulo("Linha", a["linha"], mono=True),
                *([_linha_rotulo("Fingerprint", a["fingerprint"], mono=True)]
                  if a.get("fingerprint") else []),
                *([_linha_rotulo("Calibração", _calibracao(a))] if _calibracao(a) else []),
                *([_linha_rotulo(
                    "Situação",
                    f'<font color="{CORES["forte"]}"><b>{a["status"]}</b></font>',
                )] if a.get("status") else []),
                *([_linha_rotulo("Issue", f'#{a["issue"]} no GitHub')]
                  if a.get("issue") else []),
                Spacer(1, 0.2 * cm),
                P(a["descricao"], ESTILOS["corpo"]),
            ]))

            if a.get("causa_raiz") or a.get("comportamento_esperado"):
                bloco = [P("Causa-raiz e comportamento esperado", ESTILOS["h3"])]
                if a.get("causa_raiz"):
                    bloco.append(P(f"<b>Causa-raiz:</b> {a['causa_raiz']}", ESTILOS["corpo"]))
                if a.get("comportamento_esperado"):
                    bloco.append(P(f"<b>Esperado:</b> {a['comportamento_esperado']}",
                                   ESTILOS["corpo"]))
                hist.append(KeepTogether(bloco))

            if a.get("rastro"):
                hist.append(KeepTogether([P("Rastro", ESTILOS["h3"]), _tabela_rastro(a["rastro"])]))

            hist.append(P("Evidência", ESTILOS["h3"]))
            hist.append(bloco_codigo(a["evidencia"]))

            hist.append(KeepTogether([
                P("Por que é explorável", ESTILOS["h3"]),
                P(a["exploravel"], ESTILOS["corpo"]),
            ]))
            if a.get("condicao"):
                hist.append(KeepTogether([
                    P("Condição de explorabilidade", ESTILOS["h3"]),
                    P(a["condicao"], ESTILOS["corpo"]),
                ]))
            if a.get("reproducao"):
                r = a["reproducao"]
                bloco = [P("Reprodução (dado fictício, efeito mínimo)", ESTILOS["h3"]),
                         P(f"<b>Perspectiva:</b> {r['perspectiva']}", ESTILOS["corpo"])]
                if r.get("entrada"):
                    bloco.append(bloco_codigo("\n".join(r["entrada"])))
                for k, passo in enumerate(r.get("passos", []), start=1):
                    bloco.append(P(f"{k}. {passo}", ESTILOS["corpo"]))
                bloco.append(P(f"<b>Resultado observado:</b> {r['resultado_observado']}",
                               ESTILOS["corpo"]))
                hist.append(KeepTogether(bloco))
            hist.append(KeepTogether([
                P("Impacto", ESTILOS["h3"]),
                P(a["impacto"], ESTILOS["corpo"]),
            ]))
            if _bloco_contexto(a):
                hist.append(KeepTogether(_bloco_contexto(a)))
            hist.append(P("Correção sugerida", ESTILOS["h3"]))
            for passo in a["correcao"]:
                hist.append(P(f"• {passo}", ESTILOS["corpo"]))
            hist.append(Spacer(1, 0.45 * cm))
        hist.append(PageBreak())

    # Informativos
    if not INFORMATIVOS:
        return
    hist.append(P("Observações informativas", ESTILOS["h1"]))
    hist.append(P(
        "Verificadas e sem fronteira violada: a camada que segura existe, falta a seguinte. "
        "São notas de endurecimento, registradas para que a próxima auditoria não gaste tempo "
        "redescobrindo o que já foi avaliado.", ESTILOS["corpo"]))
    for i in INFORMATIVOS:
        hist.append(KeepTogether([
            P(f'<b>{i["id"]} — {i["titulo"]}</b>', ESTILOS["h3"]),
            _linha_rotulo("Local", i["arquivo"], mono=True),
            _linha_rotulo("Categoria", i["categoria"]),
            Spacer(1, 0.15 * cm),
            P(i["descricao"], ESTILOS["corpo"]),
        ]))
    hist.append(PageBreak())


def secao_pendentes(hist):
    """Hipóteses bloqueadas por um fato fora do repositório. Sem severidade."""
    if not PENDENTES:
        return
    hist.append(P("Pendentes de validação", ESTILOS["h1"]))
    hist.append(P(
        "Cada item abaixo tem rastro na fonte, mas a confirmação depende de um fato que o "
        "repositório não mostra — a configuração do proxy, uma política do provedor, um "
        "cabeçalho que só existe na implantação. <b>Não têm severidade</b>: não são achados até "
        "que o fato seja observado. O plano diz o que o dono verifica, sem sondar ambiente vivo.",
        ESTILOS["corpo"]))

    for p in PENDENTES:
        cab = Table(
            [[chip_pendente(), P(f'<b>{p["id"]} — {p["titulo"]}</b>', ESTILOS["corpo_tab"])]],
            colWidths=[2.6 * cm, LARGURA_UTIL - 2.6 * cm],
        )
        cab.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (0, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        hist.append(KeepTogether([
            cab,
            _linha_rotulo("Arquivo", p["arquivo"], mono=True),
            *([_linha_rotulo("Linha", p["linha"], mono=True)] if p.get("linha") else []),
            _linha_rotulo("Categoria", p["categoria"]),
            *([_linha_rotulo("Fingerprint", p["fingerprint"], mono=True)]
              if p.get("fingerprint") else []),
            Spacer(1, 0.2 * cm),
            P(p["descricao"], ESTILOS["corpo"]),
        ]))
        hist.append(KeepTogether([
            P("Causa alegada", ESTILOS["h3"]),
            P(p["causa_alegada"], ESTILOS["corpo"]),
        ]))
        hist.append(P("Evidência na fonte", ESTILOS["h3"]))
        hist.append(bloco_codigo(p["evidencia"]))
        bloco = [P("O que falta para decidir", ESTILOS["h3"])]
        for b in p["bloqueadores"]:
            bloco.append(P(f"• {b}", ESTILOS["corpo"]))
        hist.append(KeepTogether(bloco))
        plano = p.get("plano_validacao", {})
        bloco = [P("Plano de validação", ESTILOS["h3"])]
        if plano.get("local"):
            bloco.append(P(f"<b>Local (fixture, sem ambiente vivo):</b> {plano['local']}",
                           ESTILOS["corpo"]))
        if plano.get("implantacao"):
            bloco.append(P(f"<b>Na implantação (o dono observa):</b> {plano['implantacao']}",
                           ESTILOS["corpo"]))
        hist.append(KeepTogether(bloco))
        if _bloco_contexto(p):
            hist.append(KeepTogether(_bloco_contexto(p)))
        hist.append(Spacer(1, 0.45 * cm))
    hist.append(PageBreak())


def secao_cobertura(hist):
    """O mapa de cobertura é a alegação de cobertura — não a prosa."""
    if not COBERTURA:
        return
    hist.append(P("Cobertura da auditoria", ESTILOS["h1"]))
    hist.append(P(
        "Cada unidade abaixo é uma combinação de superfície de entrada, fronteira de confiança, "
        "subsistema e classe de ataque. <b>Coberta</b> foi revisada sem candidato; "
        "<b>candidata</b> gerou um registro (achado, pendente ou descartado); <b>bloqueada</b> "
        "é revisão parcial à espera de um fato; <b>adiada</b> e <b>fora</b> de escopo ficaram "
        "visíveis para a próxima rodada; <b>n/a</b> não existe nesta stack.", ESTILOS["corpo"]))

    contagem = {s: 0 for s in ORDEM_STATUS}
    for u in COBERTURA:
        contagem[u["status"]] = contagem.get(u["status"], 0) + 1
    resumo = [[chip_status(s), P(str(contagem[s]), ESTILOS["corpo_tab"])]
              for s in ORDEM_STATUS if contagem.get(s)]
    # Duas colunas de (chip, número) lado a lado para não gastar uma página.
    linhas = []
    for k in range(0, len(resumo), 2):
        par = resumo[k:k + 2]
        if len(par) == 1:
            par.append(["", ""])
        linhas.append([*par[0], *par[1]])
    if linhas:
        t = Table(linhas, colWidths=[2.9 * cm, 1.6 * cm, 2.9 * cm, 1.6 * cm], hAlign="LEFT")
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ]))
        hist.append(t)
        hist.append(Spacer(1, 0.3 * cm))
    if NOTA_COBERTURA:
        hist.append(P(NOTA_COBERTURA, ESTILOS["corpo"]))
    if EXCLUSOES:
        hist.append(P("<b>Fora da caça por decisão:</b> " + "; ".join(
            f'<font face="Courier">{e["caminho"]}</font> ({e["motivo"]})' for e in EXCLUSOES),
            ESTILOS["corpo"]))
    hist.append(Spacer(1, 0.3 * cm))

    dados = [[
        P("<b>Status</b>", ESTILOS["corpo_tab"]),
        P("<b>Unidade</b>", ESTILOS["corpo_tab"]),
        P("<b>Classe</b>", ESTILOS["corpo_tab"]),
        P("<b>Verificação / pendência</b>", ESTILOS["corpo_tab"]),
    ]]
    ordem = {s: n for n, s in enumerate(ORDEM_STATUS)}
    for u in sorted(COBERTURA, key=lambda x: (ordem.get(x["status"], 99), x["id"])):
        unidade = (f'<b>{u["id"]}</b> {u["superficie"]}<br/>'
                   f'<font color="#6B7280">{u["fronteira"]} · {u["subsistema"]}</font>')
        nota = u.get("verificacao") or u.get("pendencia") or ""
        if u.get("fingerprints"):
            nota += "<br/>" + "<br/>".join(
                f'<font face="Courier" size="6.5">{fp}</font>' for fp in u["fingerprints"])
        for item in u.get("nao_alcancados") or []:
            nota += (f'<br/><font color="#6B7280">sem leitura: {item["caminho"]} '
                     f'({item["motivo"]})</font>')
        classe = u["classe"].split("#", 1)[-1]
        dados.append([
            chip_status(u["status"]),
            P(unidade, ESTILOS["corpo_tab"]),
            P(classe, ESTILOS["corpo_tab"]),
            P(nota, ESTILOS["corpo_tab"]),
        ])
    t = Table(dados, colWidths=[2.9 * cm, 5.3 * cm, 3.2 * cm, LARGURA_UTIL - 11.4 * cm],
              repeatRows=1)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, TINTA),
        ("LINEBELOW", (0, 1), (-1, -2), 0.4, LINHA),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-2, -1), 6),
    ]))
    hist.append(t)
    hist.append(PageBreak())


def secao_anteriores(hist):
    """Revisão de mudança: real, mas a mudança não participa. Fica visível, sem severidade."""
    if not ANTERIORES:
        return
    hist.append(P("Anteriores à mudança", ESTILOS["h1"]))
    hist.append(P(
        "O painel considerou estas falhas reais, mas a mudança revisada não participa delas: "
        "fonte, destino e controles são os mesmos antes e depois. Estão fora desta revisão e "
        "ficam para a próxima auditoria da base.", ESTILOS["corpo"]))
    dados = [[
        P("<b>Id</b>", ESTILOS["corpo_tab"]),
        P("<b>Alegação</b>", ESTILOS["corpo_tab"]),
        P("<b>Por que é anterior</b>", ESTILOS["corpo_tab"]),
    ]]
    for x in ANTERIORES:
        local = x["arquivo"] + (f':{x["linha"]}' if x.get("linha") else "")
        dados.append([
            P(x["id"], ESTILOS["corpo_tab"]),
            P(f'<b>{x["titulo"]}</b><br/><font face="Courier" size="6.5">{local}</font>'
              f'<br/>{x["causa_alegada"]}', ESTILOS["corpo_tab"]),
            P(x["motivo"], ESTILOS["corpo_tab"]),
        ])
    t = Table(dados, colWidths=[1.2 * cm, 7.6 * cm, LARGURA_UTIL - 8.8 * cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, TINTA),
        ("LINEBELOW", (0, 1), (-1, -2), 0.4, LINHA),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-2, -1), 6),
    ]))
    hist.append(t)
    hist.append(PageBreak())


def secao_descartados(hist):
    """Apêndice: candidatos refutados. Não são achados; evitam retrabalho."""
    if not DESCARTADOS:
        return
    hist.append(P("Apêndice — candidatos descartados", ESTILOS["h1"]))
    hist.append(P(
        "Hipóteses levantadas durante a caça e refutadas na validação independente. Não são "
        "achados. Ficam aqui para que a próxima rodada não repita a mesma alegação sem evidência "
        "nova — e para mostrar o que foi considerado.", ESTILOS["corpo"]))
    dados = [[
        P("<b>Id</b>", ESTILOS["corpo_tab"]),
        P("<b>Alegação</b>", ESTILOS["corpo_tab"]),
        P("<b>Por que foi descartada</b>", ESTILOS["corpo_tab"]),
    ]]
    for d in DESCARTADOS:
        local = d["arquivo"] + (f':{d["linha"]}' if d.get("linha") else "")
        alegacao = (f'<b>{d["titulo"]}</b><br/><font face="Courier" size="6.5">{local}</font>'
                    f'<br/>{d["causa_alegada"]}')
        dados.append([
            P(d["id"], ESTILOS["corpo_tab"]),
            P(alegacao, ESTILOS["corpo_tab"]),
            P(d["motivo"], ESTILOS["corpo_tab"]),
        ])
    t = Table(dados, colWidths=[1.2 * cm, 7.6 * cm, LARGURA_UTIL - 8.8 * cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, TINTA),
        ("LINEBELOW", (0, 1), (-1, -2), 0.4, LINHA),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-2, -1), 6),
    ]))
    hist.append(t)
    hist.append(PageBreak())


def secao_recomendacoes(hist):
    hist.append(P("Recomendações priorizadas", ESTILOS["h1"]))
    hist.append(P(NOTA_RECOMENDACOES, ESTILOS["corpo"]))

    dados = [[
        P("<b></b>", ESTILOS["corpo_tab"]),
        P("<b>Ação</b>", ESTILOS["corpo_tab"]),
        P("<b>Detalhe</b>", ESTILOS["corpo_tab"]),
    ]]
    estilo_tab = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, TINTA),
        ("LINEBELOW", (0, 1), (-1, -2), 0.4, LINHA),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (1, -1), 8),
    ]
    for idx, (pri, acao, detalhe, sev) in enumerate(RECOMENDACOES, start=1):
        dados.append([
            P(f'<b><font color="{CORES[sev]}">{pri}</font></b>', ESTILOS["corpo_tab"]),
            P(f"<b>{acao}</b>", ESTILOS["corpo_tab"]),
            P(detalhe, ESTILOS["corpo_tab"]),
        ])
        estilo_tab.append(("TEXTCOLOR", (0, idx), (0, idx), colors.HexColor(CORES[sev])))

    t = Table(dados, colWidths=[1.3 * cm, 5.4 * cm, LARGURA_UTIL - 6.7 * cm], repeatRows=1)
    t.setStyle(TableStyle(estilo_tab))
    hist.append(t)
    hist.append(PageBreak())


# ─────────────────────────────────────────────────────────────────────────────
# Issues para o GitHub
# ─────────────────────────────────────────────────────────────────────────────

def _markdown_issue(a: dict) -> str:
    sev = ROTULO_SEVERIDADE[a["severidade"]].lower()
    linhas = [
        f'# [Segurança] {a["titulo"]}',
        "",
        f"**Labels:** `security`, `{sev}`",
        "",
        "## Problema",
        "",
        _limpar(a["descricao"]),
        "",
        "**Por que é explorável**",
        "",
        _limpar(a["exploravel"]),
    ]
    if a.get("condicao"):
        linhas += ["", "**Condição de explorabilidade**", "", _limpar(a["condicao"])]
    calibracao = _calibracao(a)
    if calibracao:
        linhas += ["", f"**Calibração:** {_limpar(calibracao)}"]
    if a.get("fingerprint"):
        linhas += ["", f'**Fingerprint:** `{a["fingerprint"]}`']
    linhas += [
        "",
        "## Evidência",
        "",
        f'`{a["arquivo"]}` — linha(s) {a["linha"]}',
        "",
        "```",
        a["evidencia"],
        "```",
    ]
    if a.get("rastro"):
        linhas += ["", "**Rastro**", ""]
        for passo in a["rastro"]:
            linhas.append(f'- {_ROTULO_RASTRO.get(passo["tipo"], passo["tipo"])}: '
                          f'`{passo["arquivo"]}:{passo["linha"]}` — {_limpar(passo["descricao"])}')
    if a.get("reproducao"):
        r = a["reproducao"]
        linhas += ["", "## Reprodução (dado fictício)", "", f'**Perspectiva:** {_limpar(r["perspectiva"])}', ""]
        if r.get("entrada"):
            linhas += ["```", *r["entrada"], "```", ""]
        linhas += [f"{k}. {_limpar(p)}" for k, p in enumerate(r.get("passos", []), start=1)]
        linhas += ["", f'**Resultado observado:** {_limpar(r["resultado_observado"])}']
    linhas += [
        "",
        "## Impacto",
        "",
        _limpar(a["impacto"]),
        "",
        *_md_contexto(a),
        "## Correção sugerida",
        "",
    ]
    linhas += [f"- {_limpar(p)}" for p in a["correcao"]]
    linhas += ["", "## Critérios de aceite", ""]
    linhas += [f"- {_marcar(c)}" for c in a["criterios"]]
    return "\n".join(linhas)


def _markdown_issue_agrupada(g: dict) -> str:
    """Renderiza uma issue que agrupa vários achados relacionados.

    Agrupar existe para não gerar ruído: quatro issues de higiene sobre o mesmo
    tema informam menos que uma issue com quatro evidências.
    """
    labels = ", ".join(f"`{l}`" for l in g.get("labels", ["security"]))
    linhas = [
        f'# [Segurança] {g["titulo"]}',
        "",
        f"**Labels:** {labels}",
        "",
        "## Problema",
        "",
        _limpar(g["problema"]),
        "",
        "## Evidência",
        "",
    ]
    for item in g.get("itens", []):
        linhas += [
            f'### {item["id"]} — {item["titulo"]}',
            "",
            f'`{item["arquivo"]}`',
            "",
            _limpar(item["descricao"]),
            "",
        ]
    linhas += ["## Impacto", "", _limpar(g["impacto"]), "", "## Correção sugerida", ""]
    linhas += [f"- {_limpar(c)}" for c in g["correcao"]]
    linhas += ["", "## Critérios de aceite", ""]
    linhas += [f"- {_marcar(c)}" for c in g["criterios"]]
    return "\n".join(linhas)


def _marcar(criterio: str) -> str:
    """Devolve o criterio como item de checklist do GitHub, preservando o estado.

    Um criterio pode chegar com o proprio marcador (`[x]` para o que ja foi
    concluido durante a auditoria). Prefixar `- [ ]` nele cegamente produzia
    `- [ ] [x] ...`, que o GitHub renderiza como PENDENTE: o item concluido
    voltava a aparecer em aberto, tanto no PDF quanto na issue pronta para
    colar. Sem marcador proprio, o padrao continua sendo pendente.
    """
    texto = _limpar(criterio).strip()
    if texto.startswith("[x]") or texto.startswith("[ ]"):
        return texto
    return f"[ ] {texto}"


def _limpar(texto: str) -> str:
    """Converte a marcação do reportlab para markdown e desfaz o escape de XML."""
    return (texto.replace("<b>", "**").replace("</b>", "**")
                 .replace("<i>", "_").replace("</i>", "_")
                 .replace("<br/>", "\n")
                 .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"))


def secao_issues(hist):
    hist.append(P("Issues para o GitHub", ESTILOS["h1"]))
    texto = ("Cada bloco abaixo é o texto completo de uma issue em Markdown, pronto para copiar "
             "e colar.")
    if ISSUES_AGRUPADAS:
        texto += (" Achados relacionados de baixo risco foram agrupados numa issue só, para não "
                  "gerar ruído no repositório.")
    hist.append(P(texto, ESTILOS["corpo"]))

    blocos = ([_markdown_issue(a) for a in ACHADOS if a.get("exploravel")]
              + [_markdown_issue_agrupada(g) for g in ISSUES_AGRUPADAS])
    for n, md in enumerate(blocos, start=1):
        hist.append(P(f"Issue {n}", ESTILOS["h2"]))
        hist.append(bloco_codigo(f"--- ISSUE {n} ---\n\n{md}\n\n--- FIM ISSUE {n} ---"))
        hist.append(Spacer(1, 0.3 * cm))


# ─────────────────────────────────────────────────────────────────────────────

def _validar_antes() -> bool:
    """
    Roda o validador estrutural (validar_findings.py, ao lado) antes de gerar.
    Prosa e dados não podem discordar: achado sem evidência, pendente com
    severidade ou unidade de cobertura inconsistente derrubam a geração.
    """
    try:
        import validar_findings  # noqa: WPS433 — mesmo diretório, já no sys.path
    except ImportError:
        print("ERRO   validar_findings.py não está ao lado do gerador; sem ele não há PDF")
        return False
    erros, avisos = validar_findings.validar(F)
    for a in avisos:
        print(f"AVISO  {a}")
    for e in erros:
        print(f"ERRO   {e}")
    if erros:
        print(f"findings.py com {len(erros)} erro(s) — corrija antes de gerar o PDF")
        return False
    return True


def main() -> int:
    # Console do Windows pode estar em cp1252; as mensagens têm acento.
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(encoding="utf-8", errors="replace")
    if not _validar_antes():
        return 1

    contagem = {s: 0 for s in ORDEM_SEVERIDADE}
    por_categoria: dict[str, list[str]] = {}

    for a in ACHADOS:
        contagem[a["severidade"]] += 1
        por_categoria.setdefault(a["categoria"], []).append(a["severidade"])
    for i in INFORMATIVOS:
        contagem["informativa"] += 1
        por_categoria.setdefault(i["categoria"], []).append("informativa")

    img_rosca = grafico_rosca(os.path.join(AQUI, "_grafico-severidade.png"), contagem)
    img_barras = grafico_barras(os.path.join(AQUI, "_grafico-categoria.png"), por_categoria)

    doc = BaseDocTemplate(
        SAIDA, pagesize=A4,
        leftMargin=MARGEM, rightMargin=MARGEM, topMargin=MARGEM, bottomMargin=MARGEM,
        title=NOME_RELATORIO, author=AUTOR or "Auditoria de segurança",
        subject="Revisão adversarial",
    )
    frame_capa = Frame(MARGEM, MARGEM, LARGURA_UTIL, A4[1] - 2 * MARGEM, id="capa")
    frame_miolo = Frame(MARGEM, MARGEM, LARGURA_UTIL, A4[1] - 2 * MARGEM - 0.5 * cm, id="miolo")
    doc.addPageTemplates([
        PageTemplate(id="capa", frames=[frame_capa], onPage=moldura_capa),
        PageTemplate(id="miolo", frames=[frame_miolo], onPage=moldura_miolo),
    ])

    hist: list = []
    secao_capa(hist)
    secao_resumo(hist, contagem, por_categoria, img_rosca, img_barras)
    secao_fortes_fracos(hist)
    secao_achados(hist)
    secao_pendentes(hist)
    secao_recomendacoes(hist)
    secao_cobertura(hist)
    secao_anteriores(hist)
    secao_descartados(hist)
    secao_issues(hist)

    doc.build(hist)

    for tmp in (img_rosca, img_barras):
        if tmp and os.path.exists(tmp):
            os.remove(tmp)

    tamanho = os.path.getsize(SAIDA) / 1024
    print(f"PDF gerado: {SAIDA}  ({tamanho:.0f} KB)")
    detalhe = ", ".join(f"{ROTULO_SEVERIDADE[s]}: {contagem[s]}"
                        for s in ORDEM_SEVERIDADE if contagem[s] and s != "informativa")
    print(f"Achados: {len(ACHADOS)}" + (f" — {detalhe}" if detalhe else ""))
    if contagem["informativa"]:
        print(f"Informativos: {contagem['informativa']}")
    if PENDENTES or DESCARTADOS:
        print(f"Pendentes de validação: {len(PENDENTES)} — Descartados: {len(DESCARTADOS)}")
    if COBERTURA:
        por_status = {}
        for u in COBERTURA:
            por_status[u["status"]] = por_status.get(u["status"], 0) + 1
        print("Cobertura: " + ", ".join(f"{s}: {por_status[s]}"
                                       for s in ORDEM_STATUS if por_status.get(s)))
    print(f"Gerado em {date.today().isoformat()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
