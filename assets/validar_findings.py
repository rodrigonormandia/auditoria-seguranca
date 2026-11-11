"""
Validador estrutural de `findings.py`. Sem dependência externa.

Uso (a partir da raiz do repositório):
    python docs/security-audit/validar_findings.py                 # findings.py ao lado
    python docs/security-audit/validar_findings.py outro/findings.py

Sai com código 1 se houver erro. Avisos não impedem a geração, mas devem ser lidos.
`gerar_relatorio.py` importa `validar()` e se recusa a gerar o PDF com erro — é o que
garante que prosa e dados não discordam.

O que confere:
- vereditos separados: achado tem severidade; pendente não tem e traz bloqueador +
  plano; descartado traz motivo;
- categoria de todo registro consta em METODOLOGIA;
- ids únicos entre ACHADOS, INFORMATIVOS, PENDENTES_VALIDACAO e DESCARTADOS;
- fingerprints únicos e no formato estável (sem linha/severidade/veredito);
- severidade geral não excede o impacto demonstrado (quando informados);
- rastro com mais de um passo começa em "entrada" e termina em "destino";
- COBERTURA: status válido, invariantes por status, fingerprints referenciados existem;
- issues agrupadas, recomendações e campos obrigatórios não vazios;
- nenhum texto que vai ao PDF ou à issue carrega valor de credencial (redigir.py);
- a evidência de achados e pendentes existe em arquivo:linha no commit auditado.
"""

from __future__ import annotations

import html
import importlib.util
import os
import re
import subprocess
import sys

# Módulos irmãos em assets/. Ausentes, o validador falha fechado em vez de pular a trava.
try:
    import redigir
except ImportError:  # pragma: no cover - coberto pelo teste de falha fechada
    redigir = None
try:
    import apurar_votos
except ImportError:  # pragma: no cover
    apurar_votos = None

SEVERIDADES = ("critica", "alta", "media", "baixa")
NIVEIS = ("critica", "alta", "media", "baixa", "informativa")
CONFIANCAS = ("alta", "media", "baixa")
PERFIS = ("rapida", "padrao", "profunda")
TIPOS_RASTRO = ("entrada", "propagacao", "destino")
RELACOES_CONTEXTO = ("respeita", "contraria", "ja_planejado", "intencional", "sem_documentacao")
STATUS_COBERTURA = ("coberta", "candidata", "bloqueada", "nao_aplicavel",
                    "fora_de_escopo", "adiada", "planejada")
# Primeiro caractere aceita "." por causa de caminhos como .github/workflows/x.yml.
FINGERPRINT = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._:/@+-]*$")
# Fingerprint não carrega linha, severidade nem veredito — senão muda entre rodadas.
FINGERPRINT_PROIBIDO = re.compile(
    r"(:\d+$|:\d+:|\b(critica|alta|media|baixa|confirmado|pendente|descartado)\b)", re.I)

CAMPOS_ACHADO = ("id", "titulo", "categoria", "severidade", "arquivo", "linha",
                 "descricao", "evidencia", "exploravel", "impacto", "correcao", "criterios")
CAMPOS_PENDENTE = ("id", "titulo", "categoria", "arquivo", "descricao",
                   "causa_alegada", "evidencia", "bloqueadores", "plano_validacao")
CAMPOS_DESCARTADO = ("id", "titulo", "arquivo", "causa_alegada", "motivo")
CAMPOS_ANTERIOR = CAMPOS_DESCARTADO
CWE = re.compile(r"^CWE-[1-9][0-9]{0,4}$")
VIA_MUDANCA = re.compile(r"^(.+?):([1-9][0-9]*)(?:-([1-9][0-9]*))? \S")
CAMPOS_INFORMATIVO = ("id", "titulo", "categoria", "arquivo", "descricao")
CAMPOS_COBERTURA = ("id", "superficie", "fronteira", "subsistema", "classe", "status")


def _vazio(v) -> bool:
    if v is None:
        return True
    if isinstance(v, str):
        return not v.strip()
    if isinstance(v, (list, tuple, dict)):
        return len(v) == 0
    return False


def _lista_preenchida(v) -> bool:
    return isinstance(v, (list, tuple)) and len(v) > 0 and all(
        isinstance(x, str) and x.strip() for x in v)


# ── Fonte auditada ──────────────────────────────────────────────────────────
# A evidência é conferida no commit da rodada, não na árvore atual: assim, regerar o PDF
# depois de corrigir o código não quebra o relatório.

_SHA = re.compile(r"^[0-9a-f]{7,64}$")
FOLGA_LINHAS = 3
_ELISAO = re.compile(r"^(?:\.{3,}|…|(?://|#|--|/\*|<!--|\{/\*)\s*(?:\.{3,}|…).*)$")
_PREFIXO_LINHA = re.compile(r"^\s*\d+(?:\s*[:|]\s?|\t)")
_ID = re.compile(r"^[A-Z][0-9]{1,6}$")
_MARCA = "[REDACTED]"


def _git(raiz: str, *args: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            ["git", "-C", raiz, *args], capture_output=True, text=True, encoding="utf-8",
            errors="replace", env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None


def ref_auditada(F) -> str | None:
    """Sha de REF_FONTE; None se não há sha ou se a árvore estava suja."""
    ref = str(getattr(F, "REF_FONTE", "") or "").strip()
    m = re.match(r"^([0-9a-f]{7,64})\b", ref)
    if not m or re.search(r"\bsuja\b", ref, re.I):
        return None
    return m.group(1)


def caminho_seguro(caminho: str) -> bool:
    """Relativo ao repositório, sem sair dele."""
    c = str(caminho or "").replace("\\", "/").strip()
    return bool(c) and not c.startswith("/") and not re.match(r"^[A-Za-z]:", c) \
        and ".." not in c.split("/")


def ler_fonte(raiz: str, caminho: str, ref: str | None) -> list[str] | None:
    """Linhas do arquivo no commit `ref` (ou na árvore de trabalho); None se não existe."""
    caminho = caminho.replace("\\", "/").strip()
    if ref:
        r = _git(raiz, "show", f"{ref}:{caminho}")
        if r is None or r.returncode != 0:
            return None
        texto = r.stdout
    else:
        alvo = os.path.join(raiz, caminho)
        if not os.path.isfile(alvo):
            return None
        with open(alvo, encoding="utf-8", errors="replace", newline="") as f:
            texto = f.read()
    return re.split(r"\r\n|\n|\r", texto)


def _espacos(texto: str) -> str:
    return re.sub(r"\s+", " ", texto).strip()


def _alvos_da_linha(linha: str) -> list[list[str]]:
    """Formas aceitas de uma linha da evidência, cada uma como partes separadas por [REDACTED]."""
    formas = {linha, html.unescape(linha), _PREFIXO_LINHA.sub("", linha, count=1)}
    return [[_espacos(p) for p in f.split(_MARCA) if _espacos(p)] for f in formas]


def _linhas_da_evidencia(evidencia: str) -> list[tuple[int, list[list[str]]]]:
    """(número da linha na evidência, formas aceitas), sem elisões e linhas só de [REDACTED]."""
    saida = []
    for n, bruta in enumerate(str(evidencia or "").splitlines(), start=1):
        limpa = bruta.strip()
        if not limpa or _ELISAO.match(limpa) or not limpa.replace(_MARCA, "").strip():
            continue
        saida.append((n, _alvos_da_linha(bruta)))
    return saida


def _casa_partes(partes: list[str], linha: str) -> bool:
    posicao = 0
    for parte in partes:
        achou = linha.find(parte, posicao)
        if achou < 0:
            return False
        posicao = achou + len(parte)
    return bool(partes)


def _casa(alvos: list[list[str]], linha: str) -> bool:
    return any(_casa_partes(p, linha) for p in alvos)


def casar_evidencia(evidencia: str, linhas: list[str]) -> list[tuple[int, int]]:
    """Ocorrências (linha inicial, linha final, base 1) da evidência, com as linhas em ordem."""
    alvos = [a for _, a in _linhas_da_evidencia(evidencia)]
    fonte = [_espacos(x) for x in linhas]
    if not alvos:
        return []
    ocorrencias = []
    for inicio, texto in enumerate(fonte):
        if not _casa(alvos[0], texto):
            continue
        j = inicio
        for alvo in alvos[1:]:
            j += 1
            while j < len(fonte) and not _casa(alvo, fonte[j]):
                j += 1
            if j >= len(fonte):
                break
        else:
            ocorrencias.append((inicio + 1, j + 1))
    return ocorrencias


def _faixa_linhas(linha) -> tuple[int, int] | None:
    numeros = [int(n) for n in re.findall(r"\d+", str(linha or ""))]
    return (min(numeros), max(numeros)) if numeros else None


def trechos_alterados(diff: str) -> dict[str, list[tuple[int, int]]]:
    """Por arquivo, as faixas de linhas do lado novo em um `git diff -U0`."""
    saida: dict[str, list[tuple[int, int]]] = {}
    atual = None
    for linha in diff.splitlines():
        if linha.startswith("+++ "):
            atual = None if linha == "+++ /dev/null" else linha[4:].strip().strip('"')[2:]
            if atual is not None:
                saida.setdefault(atual, [])
            continue
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", linha)
        if m and atual is not None:
            inicio = int(m.group(1))
            total = int(m.group(2)) if m.group(2) is not None else 1
            saida[atual].append((inicio, inicio + max(total, 1) - 1))
    return saida


def diretorios_topo(raiz: str, ref: str | None) -> list[str] | None:
    """Diretórios de topo versionados no commit (ou na árvore); None se o git não responder."""
    r = _git(raiz, "ls-tree", "-r", "-z", "--name-only", ref) if ref \
        else _git(raiz, "ls-files", "-z")
    if r is None or r.returncode != 0:
        return None
    return sorted({c.split("/", 1)[0] for c in r.stdout.split("\0") if "/" in c})


def _base_do_caminho(caminho) -> str:
    """Caminho sem `./`, sem barra final e cortado no primeiro curinga."""
    c = re.sub(r"^\./", "", str(caminho or "").replace("\\", "/").strip())
    c = re.split(r"[*?\[]", c, maxsplit=1)[0]
    return "" if c == "." else c.rstrip("/")


def validar(F) -> tuple[list[str], list[str]]:
    """Recebe o módulo findings carregado. Devolve (erros, avisos)."""
    erros: list[str] = []
    avisos: list[str] = []

    def erro(msg):
        erros.append(msg)

    def aviso(msg):
        avisos.append(msg)

    # ── topo ────────────────────────────────────────────────────────────────
    for nome in ("PROJETO", "DATA_AUDITORIA", "STACK", "METODOLOGIA", "ACHADOS",
                 "PONTOS_FORTES", "PONTOS_FRACOS", "RECOMENDACOES", "CORES",
                 "ORDEM_SEVERIDADE", "ROTULO_SEVERIDADE"):
        if not hasattr(F, nome):
            erro(f"falta a variável {nome}")
    if erros:
        return erros, avisos

    for nome in ("PROJETO", "DATA_AUDITORIA"):
        v = getattr(F, nome)
        if _vazio(v) or (isinstance(v, str) and v.strip().startswith("<")):
            erro(f"{nome} não preenchido")

    perfil = getattr(F, "PERFIL", None)
    if perfil is not None and perfil not in PERFIS:
        erro(f"PERFIL inválido: {perfil!r} (use {', '.join(PERFIS)})")
    if perfil is None:
        erro("PERFIL ausente — a capa tem de dizer se a rodada foi rápida, padrão ou profunda, "
             "e sem ele o painel não seria conferido")
    if _vazio(getattr(F, "REF_FONTE", "")):
        aviso("REF_FONTE vazio — registre o commit auditado")

    metod = getattr(F, "METODOLOGIA")
    titulos_metod: list[str] = []
    for i, item in enumerate(metod):
        if not (isinstance(item, (list, tuple)) and len(item) == 2):
            erro(f"METODOLOGIA[{i}] deve ser (titulo, texto)")
            continue
        titulo, texto = item
        titulos_metod.append(titulo)
        if _vazio(texto):
            erro(f"METODOLOGIA {titulo!r}: texto vazio — diga como a categoria foi "
                 "mapeada para esta stack ou por que não se aplica")

    class _Categorias:
        """A categoria do registro pode ser o título inteiro da METODOLOGIA ou só o
        prefixo ("03 IDOR" para "03 IDOR — IDOR e autorização por recurso")."""

        def __contains__(self, cat) -> bool:
            if not isinstance(cat, str) or not cat.strip():
                return False
            return any(t == cat or t.startswith(cat) for t in titulos_metod)

    categorias = _Categorias()

    achados = getattr(F, "ACHADOS", [])
    pendentes = getattr(F, "PENDENTES_VALIDACAO", [])
    descartados = getattr(F, "DESCARTADOS", [])
    anteriores = getattr(F, "ANTERIORES", [])
    informativos = getattr(F, "INFORMATIVOS", [])
    cobertura = getattr(F, "COBERTURA", [])

    ids: dict[str, str] = {}
    fingerprints: dict[str, str] = {}
    slugs: dict[str, str] = {}

    # Só cobra o confronto com a documentação quando a rodada a levantou.
    pasta = os.path.dirname(os.path.abspath(getattr(F, "__file__", "") or "."))
    tem_contexto_produto = os.path.exists(os.path.join(pasta, "contexto-produto.md"))

    # Raiz do repositório: é em relação a ela que os documentos são citados.
    raiz = pasta
    while raiz and not os.path.exists(os.path.join(raiz, ".git")):
        acima = os.path.dirname(raiz)
        if acima == raiz:
            raiz = os.path.dirname(os.path.dirname(pasta))
            break
        raiz = acima

    tem_git = (_git(raiz, "rev-parse", "--is-inside-work-tree") or
               subprocess.CompletedProcess([], 1, "", "")).returncode == 0
    ref = ref_auditada(F) if tem_git else None
    if ref:
        r = _git(raiz, "cat-file", "-e", f"{ref}^{{commit}}")
        if r is None or r.returncode != 0:
            aviso(f"REF_FONTE {ref} não existe neste repositório — evidência conferida na "
                  "árvore de trabalho")
            ref = None

    def checar_credenciais():
        """Nada que vai ao PDF ou à issue pode carregar o valor de uma credencial."""
        if redigir is None:
            erro("redigir.py não está ao lado do validador — sem ele não há como garantir que "
                 "o relatório não carrega credencial")
            return

        def varrer(obj, origem, permitidos=()):
            tipos = sorted({tipo for s in redigir.strings_de(obj)
                            for tipo, _ in redigir.achar_credenciais(s, permitidos)})
            if tipos:
                erro(f"{origem}: credencial no texto ({', '.join(tipos)}) — rode redigir.py "
                     "--aplicar ou, se for pública por desenho, liste em falso_positivo_redacao")

        for nome, regs in (("ACHADOS", achados), ("PENDENTES_VALIDACAO", pendentes),
                           ("DESCARTADOS", descartados), ("ANTERIORES", anteriores),
                           ("INFORMATIVOS", informativos), ("COBERTURA", cobertura)):
            for reg in regs:
                if not isinstance(reg, dict):
                    continue
                permitidos = reg.get(redigir.CAMPO_EXCECOES) or []
                varrer(reg, f"{nome} ({reg.get('id', '?')})", permitidos)
                if permitidos:
                    aviso(f"{nome} ({reg.get('id', '?')}): {len(permitidos)} valor(es) em "
                          "falso_positivo_redacao vão impressos — confirme que são públicos")
        # Todo atributo público do cabeçalho: lista fixa deixaria de fora o campo que vier depois.
        ja_varridos = {"ACHADOS", "PENDENTES_VALIDACAO", "DESCARTADOS", "ANTERIORES",
                       "INFORMATIVOS", "COBERTURA", "CORES", "ORDEM_SEVERIDADE",
                       "ROTULO_SEVERIDADE"}
        for nome in sorted(n for n in vars(F) if n.isupper() and not n.startswith("_")
                           and n not in ja_varridos):
            varrer(getattr(F, nome), nome)

    def checar_evidencia(reg, origem):
        """Prova de que o trecho citado existe em arquivo:linha no commit auditado."""
        motivo = reg.get("evidencia_fora_da_fonte")
        if motivo:
            aviso(f"{origem}: evidencia_fora_da_fonte ({motivo}) — só arquivo e linha foram "
                  "conferidos, não o trecho")
        arquivo = reg.get("arquivo") or ""
        if not caminho_seguro(arquivo):
            erro(f"{origem}: arquivo {arquivo!r} não é um caminho relativo ao repositório")
            return
        ref_reg = reg.get("ref_evidencia")
        if ref_reg is not None and not _SHA.match(str(ref_reg)):
            erro(f"{origem}: ref_evidencia {ref_reg!r} não é um sha")
            return
        ref_usada = ref_reg or ref
        linhas = ler_fonte(raiz, arquivo, ref_usada)
        if linhas is None:
            erro(f"{origem}: arquivo {arquivo!r} não existe em "
                 f"{ref_usada or 'na árvore de trabalho'}")
            return
        rastro = reg.get("rastro") if isinstance(reg.get("rastro"), list) else []
        outros: dict[str, list[str]] = {}
        for k, passo in enumerate(rastro):
            if not isinstance(passo, dict):
                continue
            alvo = passo.get("arquivo") or ""
            if not caminho_seguro(alvo):
                erro(f"{origem}: rastro[{k}].arquivo {alvo!r} não é relativo ao repositório")
                continue
            conteudo = linhas if alvo == arquivo else ler_fonte(raiz, alvo, ref_usada)
            if conteudo is None:
                erro(f"{origem}: rastro[{k}].arquivo {alvo!r} não existe em "
                     f"{ref_usada or 'na árvore de trabalho'}")
                continue
            outros[alvo] = conteudo
            n = passo.get("linha")
            if isinstance(n, int) and n > len(conteudo):
                erro(f"{origem}: rastro[{k}].linha {n} além do fim de {alvo!r} "
                     f"({len(conteudo)} linhas)")
        faixa = _faixa_linhas(reg.get("linha"))
        if faixa and faixa[0] > len(linhas):
            erro(f"{origem}: linha {reg.get('linha')} além do fim de {arquivo!r} "
                 f"({len(linhas)} linhas) — evidencia não pode estar lá")
            return
        alvos = _linhas_da_evidencia(reg.get("evidencia"))
        if motivo or not alvos:
            return  # sem trecho a conferir: arquivo e linha já foram conferidos
        ocorrencias = casar_evidencia(reg.get("evidencia"), linhas)
        if ocorrencias:
            if faixa and not any(fim >= faixa[0] - FOLGA_LINHAS and ini <= faixa[1] + FOLGA_LINHAS
                                 for ini, fim in ocorrencias):
                locais = ", ".join(f"{i}-{f}" for i, f in ocorrencias[:3])
                erro(f"{origem}: evidencia encontrada em {locais}, longe da linha "
                     f"{reg.get('linha')} declarada em {arquivo!r}")
            return
        # Trecho de vários arquivos do rastro: cada linha precisa existir em algum deles.
        fontes = [[_espacos(x) for x in c] for c in (linhas, *outros.values())]
        for n, formas in alvos:
            if not any(_casa(formas, texto) for fonte in fontes for texto in fonte):
                erro(f"{origem}: evidencia, linha {n} do trecho, não existe em {arquivo!r} "
                     f"{'nem no rastro ' if outros else ''}em {ref_usada or 'árvore de trabalho'}"
                     " — a citação tem de ser literal")
                return
        if set(outros) <= {arquivo}:
            erro(f"{origem}: evidencia fora de ordem em {arquivo!r} — as linhas existem, mas "
                 "não nessa sequência")

    mudanca = getattr(F, "MUDANCA", None)
    arquivos_mudanca: dict[str, list[tuple[int, int]]] | None = None
    if mudanca is not None:
        base = mudanca.get("base") if isinstance(mudanca, dict) else None
        head = mudanca.get("head") if isinstance(mudanca, dict) else None
        if not (isinstance(base, str) and isinstance(head, str)
                and _SHA.match(base) and _SHA.match(head)):
            erro("MUDANCA deve ser {'base': sha, 'head': sha}")
        else:
            r = _git(raiz, "diff", "-U0", "--no-ext-diff", "--no-color", base, head)
            if r is None or r.returncode != 0:
                erro(f"MUDANCA: não consegui ler o diff {base}..{head}")
            else:
                arquivos_mudanca = trechos_alterados(r.stdout)

    def checar_mudanca(reg, origem):
        """Na revisão de mudança, o achado tem de nomear a linha alterada que participa."""
        if arquivos_mudanca is None:
            return
        via = reg.get("via_mudanca")
        m = VIA_MUDANCA.match(via) if isinstance(via, str) else None
        if not m:
            erro(f"{origem}: via_mudanca ausente ou fora do formato 'arquivo:linha o que faz'")
            return
        arquivo = m.group(1).replace("\\", "/")
        if arquivo not in arquivos_mudanca:
            erro(f"{origem}: via_mudanca aponta {arquivo!r}, que não está no diff")
            return
        ini = int(m.group(2))
        fim = int(m.group(3) or ini)
        # Folga de uma linha: remoção pura aponta a vizinha do trecho apagado.
        if not any(fim >= a - 1 and ini <= b + 1 for a, b in arquivos_mudanca[arquivo]):
            erro(f"{origem}: via_mudanca aponta {arquivo}:{ini}, linha que a mudança não altera")

    def checar_cwe(reg, origem):
        if reg.get("cwe") and not CWE.match(str(reg["cwe"])):
            erro(f"{origem}: cwe {reg['cwe']!r} fora do formato CWE-<número>")

    def checar_citacoes(reg, nome, fontes_cache):
        """Voto que confirma ou refuta tem de citar um arquivo:linha que existe."""
        for voto in apurar_votos.ler_votos(pasta, apurar_votos.slug(reg["fingerprint"])):
            if not isinstance(voto, dict) or voto.get("veredito") == "pendente":
                continue
            validas = 0
            for arquivo, linha in apurar_votos.citacoes(voto.get("motivo")):
                if not caminho_seguro(arquivo):
                    continue
                if arquivo not in fontes_cache:
                    fontes_cache[arquivo] = ler_fonte(raiz, arquivo, ref)
                conteudo = fontes_cache[arquivo]
                if conteudo is not None and 1 <= linha <= len(conteudo):
                    validas += 1
            if not validas:
                erro(f"{nome} ({reg.get('id', '?')}): painel: voto de {voto.get('lente')} não "
                     "cita arquivo:linha que exista no commit auditado")

    def checar_painel():
        """O veredito do registro tem de sair do placar dos votos, não da palavra do relator."""
        exige = perfil in ("padrao", "profunda")
        if apurar_votos is None:
            if exige:
                erro("apurar_votos.py não está ao lado do validador — o painel não foi conferido")
            return
        cache: dict[str, list[str] | None] = {}
        for veredito, nome, regs in (("confirmado", "ACHADOS", achados),
                                     ("pendente", "PENDENTES_VALIDACAO", pendentes),
                                     ("descartado", "DESCARTADOS", descartados),
                                     ("anterior", "ANTERIORES", anteriores),
                                     ("endurecimento", "INFORMATIVOS",
                                      [i for i in informativos if i.get("fingerprint")])):
            for reg in regs:
                fp = reg.get("fingerprint")
                # Em `rapida` não há painel, mas voto gravado não pode ser ignorado.
                tem_votos = bool(fp) and os.path.isdir(
                    os.path.join(pasta, "votos", apurar_votos.slug(fp)))
                if not (exige or tem_votos):
                    continue
                for problema in apurar_votos.conferir_registro(reg, veredito, pasta):
                    erro(f"{nome} ({reg.get('id', '?')}): painel: {problema}")
                if tem_votos:
                    checar_citacoes(reg, nome, cache)

    def _normalizar(texto: str) -> str:
        return re.sub(r"\s+", " ", re.sub(r"[*_`>#|]", "", texto)).strip().lower()

    textos_doc: dict[str, str | None] = {}

    def _texto_do_documento(documento: str) -> str | None:
        """Conteúdo normalizado do arquivo citado, ou None se não é arquivo do repositório."""
        caminho = re.sub(r":\d+(-\d+)?$", "", documento.split("#", 1)[0]).strip()
        if caminho not in textos_doc:
            alvo = os.path.join(raiz, caminho)
            if caminho and os.path.isfile(alvo):
                with open(alvo, encoding="utf-8", errors="replace") as f:
                    textos_doc[caminho] = _normalizar(f.read())
            else:
                textos_doc[caminho] = None
        return textos_doc[caminho]

    def checar_contexto(reg, origem):
        ctx = reg.get("contexto_projeto")
        if ctx is None:
            return
        if not isinstance(ctx, list) or not ctx:
            erro(f"{origem}: contexto_projeto deve ser lista não vazia (ou não existir)")
            return
        for k, c in enumerate(ctx):
            if not isinstance(c, dict):
                erro(f"{origem}: contexto_projeto[{k}] deve ser dict")
                continue
            rel = c.get("relacao")
            if rel not in RELACOES_CONTEXTO:
                erro(f"{origem}: contexto_projeto[{k}].relacao {rel!r} inválida "
                     f"(use {', '.join(RELACOES_CONTEXTO)})")
            if _vazio(c.get("nota")):
                erro(f"{origem}: contexto_projeto[{k}].nota vazia")
            if rel == "sem_documentacao":
                continue
            documento = c.get("documento") or ""
            if _vazio(documento):
                erro(f"{origem}: contexto_projeto[{k}].documento vazio — cite o arquivo "
                     "(e a seção) que sustenta a relação")
                continue
            # Issue ou link externo: não há arquivo para conferir.
            if re.match(r"^(issue\s*#|#\d+|https?://)", documento.strip(), re.I):
                continue
            # Prova de leitura: o trecho citado tem de existir no documento citado.
            # Sem isso, "respeita" vira carimbo de quem escreveu a correção.
            trecho = c.get("trecho")
            if _vazio(trecho):
                erro(f"{origem}: contexto_projeto[{k}] sem 'trecho' — copie do documento a "
                     "frase da regra (citação literal); sem ela não há prova de leitura")
                continue
            texto = _texto_do_documento(documento)
            if texto is None:
                erro(f"{origem}: contexto_projeto[{k}].documento {documento!r} não existe "
                     "no repositório")
            elif len(_normalizar(trecho)) < 20:
                erro(f"{origem}: contexto_projeto[{k}].trecho curto demais para identificar a regra")
            elif _normalizar(trecho) not in texto:
                erro(f"{origem}: contexto_projeto[{k}].trecho não foi encontrado em "
                     f"{documento.split('#', 1)[0]!r} — a citação tem de ser literal")
        if any(isinstance(c, dict) and c.get("relacao") == "contraria" for c in ctx) \
                and _vazio(reg.get("decisao_necessaria")):
            erro(f"{origem}: há relação 'contraria' e falta 'decisao_necessaria' — diga o que "
                 "o dono precisa decidir antes de a correção virar tarefa")

    def checar_revisao_da_correcao(reg, origem):
        """Achado confirmado só passa com a correção revisada contra a documentação."""
        if not tem_contexto_produto:
            return
        if not reg.get("contexto_projeto"):
            erro(f"{origem}: sem 'contexto_projeto' — existe contexto-produto.md; a correção "
                 "tem de ser confrontada com as regras de negócio documentadas (fase 5b)")
        rev = reg.get("revisao_correcao")
        if not isinstance(rev, dict) or not _lista_preenchida(rev.get("documentos_lidos")):
            erro(f"{origem}: sem 'revisao_correcao.documentos_lidos' — a correção ainda não "
                 "passou pelo revisor independente (fase 5b)")
            return
        for doc in rev["documentos_lidos"]:
            if _texto_do_documento(doc) is None:
                erro(f"{origem}: revisao_correcao cita {doc!r}, que não existe no repositório")
        if _vazio(rev.get("regras_verificadas")):
            erro(f"{origem}: revisao_correcao sem 'regras_verificadas' — liste as regras de "
                 "negócio da funcionalidade afetada que a correção foi confrontada")

    def registrar_id(reg, origem):
        i = reg.get("id")
        if _vazio(i):
            erro(f"{origem}: id vazio")
            return
        if not _ID.match(str(i)):
            erro(f"{origem}: id {i!r} fora do formato (letra maiúscula e número, como A3)")
        if i in ids:
            erro(f"id {i!r} repetido ({ids[i]} e {origem})")
        ids[i] = origem

    def registrar_fingerprint(reg, origem):
        fp = reg.get("fingerprint")
        if _vazio(fp):
            aviso(f"{origem}: sem fingerprint — a próxima rodada não vai reconhecer esta causa")
            return
        if not FINGERPRINT.match(fp):
            erro(f"{origem}: fingerprint {fp!r} fora do formato "
                 "(^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$)")
        if FINGERPRINT_PROIBIDO.search(fp):
            erro(f"{origem}: fingerprint {fp!r} carrega linha, severidade ou veredito — "
                 "tem de ser estável entre rodadas")
        if fp in fingerprints:
            erro(f"{origem}: fingerprint {fp!r} repetido (já em {fingerprints[fp]}) — "
                 "mesma causa-raiz só pode ter um veredito")
        # O slug nomeia registro e pasta de votos, e o NTFS ignora caixa: duas causas no mesmo
        # slug dividiriam o painel.
        chave = re.sub(r"[^A-Za-z0-9._-]", "-", fp).lower()
        if chave in slugs and slugs[chave] != fp:
            erro(f"{origem}: fingerprint {fp!r} colide com {slugs[chave]!r} no nome de arquivo")
        slugs.setdefault(chave, fp)
        fingerprints[fp] = origem

    # ── ACHADOS ─────────────────────────────────────────────────────────────
    for n, a in enumerate(achados):
        origem = f"ACHADOS[{n}] ({a.get('id', '?')})"
        if not isinstance(a, dict):
            erro(f"{origem}: deve ser dict")
            continue
        registrar_id(a, origem)
        registrar_fingerprint(a, origem)
        for campo in CAMPOS_ACHADO:
            if campo not in a:
                erro(f"{origem}: falta o campo {campo!r}")
            elif _vazio(a[campo]):
                erro(f"{origem}: campo {campo!r} vazio")
        if a.get("categoria") and a["categoria"] not in categorias:
            erro(f"{origem}: categoria {a['categoria']!r} não consta em METODOLOGIA")
        sev = a.get("severidade")
        if sev not in SEVERIDADES:
            erro(f"{origem}: severidade {sev!r} inválida (use {', '.join(SEVERIDADES)}) — "
                 "informativa não é achado, vai em INFORMATIVOS")
        for campo in ("correcao", "criterios"):
            if campo in a and not _lista_preenchida(a[campo]):
                erro(f"{origem}: {campo!r} deve ser lista de strings não vazias")
        for campo in ("bloqueadores", "plano_validacao", "motivo", "causa_alegada"):
            if campo in a:
                erro(f"{origem}: campo {campo!r} é de pendente/descartado, não de achado")

        prob = a.get("probabilidade")
        imp = a.get("impacto_nivel")
        conf = a.get("confianca")
        for rotulo, valor in (("probabilidade", prob), ("impacto_nivel", imp)):
            if valor is not None and valor not in NIVEIS:
                erro(f"{origem}: {rotulo} {valor!r} inválido (use {', '.join(NIVEIS)})")
        if conf is not None and conf not in CONFIANCAS:
            erro(f"{origem}: confianca {conf!r} inválida (use {', '.join(CONFIANCAS)})")
        if sev in SEVERIDADES and imp in NIVEIS and NIVEIS.index(sev) < NIVEIS.index(imp):
            erro(f"{origem}: severidade {sev!r} acima do impacto demonstrado {imp!r} — "
                 "a severidade geral nunca excede o impacto")
        if sev in ("critica", "alta"):
            if conf is None:
                aviso(f"{origem}: achado {sev} sem 'confianca'")
            if _vazio(a.get("rastro")):
                aviso(f"{origem}: achado {sev} sem 'rastro' entrada→destino")

        rastro = a.get("rastro")
        if rastro:
            if not isinstance(rastro, list):
                erro(f"{origem}: rastro deve ser lista")
            else:
                for k, passo in enumerate(rastro):
                    if not isinstance(passo, dict):
                        erro(f"{origem}: rastro[{k}] deve ser dict")
                        continue
                    if passo.get("tipo") not in TIPOS_RASTRO:
                        erro(f"{origem}: rastro[{k}].tipo {passo.get('tipo')!r} inválido "
                             f"(use {', '.join(TIPOS_RASTRO)})")
                    for campo in ("arquivo", "descricao"):
                        if _vazio(passo.get(campo)):
                            erro(f"{origem}: rastro[{k}].{campo} vazio")
                    linha = passo.get("linha")
                    if not isinstance(linha, int) or linha < 1:
                        erro(f"{origem}: rastro[{k}].linha deve ser inteiro ≥ 1")
                if len(rastro) > 1 and isinstance(rastro[0], dict) and isinstance(rastro[-1], dict):
                    if rastro[0].get("tipo") != "entrada":
                        erro(f"{origem}: rastro com vários passos começa em 'entrada'")
                    if rastro[-1].get("tipo") != "destino":
                        erro(f"{origem}: rastro com vários passos termina em 'destino'")
                    for passo in rastro[1:-1]:
                        if isinstance(passo, dict) and passo.get("tipo") != "propagacao":
                            erro(f"{origem}: passos intermediários do rastro são 'propagacao'")

        # O relatório é documento de correção: passo a passo não entra. O campo é
        # tolerado em findings antigos, mas a skill não o pede mais.
        if a.get("reproducao"):
            aviso(f"{origem}: campo 'reproducao' em desuso — o relatório descreve o controle "
                  "que falta e a correção; como conferir vai em 'criterios'")

        if "issue" in a and not isinstance(a["issue"], int):
            erro(f"{origem}: issue deve ser inteiro (nº da issue)")

        checar_contexto(a, origem)
        checar_revisao_da_correcao(a, origem)
        checar_evidencia(a, origem)
        checar_mudanca(a, origem)
        checar_cwe(a, origem)

    # ── PENDENTES_VALIDACAO ────────────────────────────────────────────────
    for n, p in enumerate(pendentes):
        origem = f"PENDENTES_VALIDACAO[{n}] ({p.get('id', '?')})"
        if not isinstance(p, dict):
            erro(f"{origem}: deve ser dict")
            continue
        registrar_id(p, origem)
        registrar_fingerprint(p, origem)
        for campo in CAMPOS_PENDENTE:
            if campo not in p:
                erro(f"{origem}: falta o campo {campo!r}")
            elif _vazio(p[campo]):
                erro(f"{origem}: campo {campo!r} vazio")
        if p.get("categoria") and p["categoria"] not in categorias:
            erro(f"{origem}: categoria {p['categoria']!r} não consta em METODOLOGIA")
        for campo in ("severidade", "probabilidade", "impacto_nivel", "reproducao",
                      "correcao", "criterios", "exploravel"):
            if campo in p:
                erro(f"{origem}: pendente não tem {campo!r} — sem severidade, sem correção; "
                     "se dá para corrigir e explorar, é achado")
        if "bloqueadores" in p and not _lista_preenchida(p["bloqueadores"]):
            erro(f"{origem}: bloqueadores deve ser lista de strings não vazias")
        checar_contexto(p, origem)
        checar_evidencia(p, origem)
        checar_mudanca(p, origem)
        checar_cwe(p, origem)
        plano = p.get("plano_validacao")
        if plano is not None:
            if not isinstance(plano, dict):
                erro(f"{origem}: plano_validacao deve ser dict com 'local' e/ou 'implantacao'")
            else:
                extras = set(plano) - {"local", "implantacao"}
                if extras:
                    erro(f"{origem}: plano_validacao com chave desconhecida {sorted(extras)}")
                if _vazio(plano.get("local")) and _vazio(plano.get("implantacao")):
                    erro(f"{origem}: plano_validacao precisa de 'local' ou 'implantacao' preenchido")

    # ── DESCARTADOS ───────────────────────────────────────────────────────
    for n, d in enumerate(descartados):
        origem = f"DESCARTADOS[{n}] ({d.get('id', '?')})"
        if not isinstance(d, dict):
            erro(f"{origem}: deve ser dict")
            continue
        registrar_id(d, origem)
        registrar_fingerprint(d, origem)
        for campo in CAMPOS_DESCARTADO:
            if _vazio(d.get(campo)):
                erro(f"{origem}: campo {campo!r} vazio")
        if "severidade" in d:
            erro(f"{origem}: descartado não tem severidade")

    # ── ANTERIORES ────────────────────────────────────────────────────────
    for n, x in enumerate(anteriores):
        origem = f"ANTERIORES[{n}] ({x.get('id', '?')})"
        registrar_id(x, origem)
        registrar_fingerprint(x, origem)
        for campo in CAMPOS_ANTERIOR:
            if _vazio(x.get(campo)):
                erro(f"{origem}: campo {campo!r} vazio")
        if "severidade" in x:
            erro(f"{origem}: anterior não tem severidade — a próxima auditoria a atribui")
        arquivo = x.get("arquivo") or ""
        if not caminho_seguro(arquivo) or ler_fonte(raiz, arquivo, ref) is None:
            erro(f"{origem}: arquivo {arquivo!r} não existe em "
                 f"{ref or 'na árvore de trabalho'}")

    # ── INFORMATIVOS ──────────────────────────────────────────────────────
    for n, i in enumerate(informativos):
        origem = f"INFORMATIVOS[{n}] ({i.get('id', '?')})"
        if not isinstance(i, dict):
            erro(f"{origem}: deve ser dict")
            continue
        registrar_id(i, origem)
        if i.get("fingerprint"):  # decidido pelo painel; as notas do cabeçalho não têm
            registrar_fingerprint(i, origem)
        for campo in CAMPOS_INFORMATIVO:
            if _vazio(i.get(campo)):
                erro(f"{origem}: campo {campo!r} vazio")
        # Aviso, não erro: rodadas antigas usavam rótulo curto aqui, e o informativo
        # só alimenta o gráfico de barras — não tem seção própria por categoria.
        if i.get("categoria") and i["categoria"] not in categorias:
            aviso(f"{origem}: categoria {i['categoria']!r} não consta em METODOLOGIA")
        if i.get("severidade") not in (None, "informativa"):
            erro(f"{origem}: informativo com severidade {i['severidade']!r} — se é explorável, é achado")

    # ── PONTOS, RECOMENDACOES, ISSUES ─────────────────────────────────────
    for nome in ("PONTOS_FORTES", "PONTOS_FRACOS"):
        for n, item in enumerate(getattr(F, nome, [])):
            if not (isinstance(item, (list, tuple)) and len(item) == 2
                    and not _vazio(item[0]) and not _vazio(item[1])):
                erro(f"{nome}[{n}] deve ser (titulo, texto) preenchidos")
    if not getattr(F, "PONTOS_FORTES", []):
        aviso("PONTOS_FORTES vazio — o que foi verificado e está correto prova a cobertura")

    for n, r in enumerate(getattr(F, "RECOMENDACOES", [])):
        if not (isinstance(r, (list, tuple)) and len(r) == 4):
            erro(f"RECOMENDACOES[{n}] deve ser (prioridade, acao, detalhe, severidade)")
            continue
        if r[3] not in NIVEIS:
            erro(f"RECOMENDACOES[{n}]: severidade {r[3]!r} inválida")
        if any(_vazio(x) for x in r[:3]):
            erro(f"RECOMENDACOES[{n}]: campo vazio")

    for n, g in enumerate(getattr(F, "ISSUES_AGRUPADAS", [])):
        origem = f"ISSUES_AGRUPADAS[{n}]"
        for campo in ("titulo", "problema", "impacto"):
            if _vazio(g.get(campo)):
                erro(f"{origem}: campo {campo!r} vazio")
        for campo in ("correcao", "criterios"):
            if not _lista_preenchida(g.get(campo)):
                erro(f"{origem}: {campo!r} deve ser lista de strings não vazias")
        if not g.get("itens"):
            erro(f"{origem}: 'itens' vazio")
        for k, item in enumerate(g.get("itens", [])):
            for campo in ("id", "titulo", "arquivo", "descricao"):
                if _vazio(item.get(campo)):
                    erro(f"{origem}.itens[{k}]: campo {campo!r} vazio")

    # ── COBERTURA ─────────────────────────────────────────────────────────
    ids_cob: set[str] = set()
    if not cobertura:
        aviso("COBERTURA vazia — sem mapa, a alegação de cobertura é só prosa")
    for n, u in enumerate(cobertura):
        origem = f"COBERTURA[{n}] ({u.get('id', '?')})"
        if not isinstance(u, dict):
            erro(f"{origem}: deve ser dict")
            continue
        for campo in CAMPOS_COBERTURA:
            if _vazio(u.get(campo)):
                erro(f"{origem}: campo {campo!r} vazio")
        uid = u.get("id")
        if uid in ids_cob:
            erro(f"{origem}: id de unidade repetido")
        ids_cob.add(uid)
        st = u.get("status")
        if st not in STATUS_COBERTURA:
            erro(f"{origem}: status {st!r} inválido (use {', '.join(STATUS_COBERTURA)})")
            continue
        if st == "planejada":
            erro(f"{origem}: unidade ainda 'planejada' — a auditoria não terminou ou a "
                 "unidade tem de virar adiada/fora_de_escopo com motivo")
        caminhos = u.get("caminhos") or []
        verif = u.get("verificacao") or ""
        fps = u.get("fingerprints") or []
        pend = u.get("pendencia") or ""
        if st in ("coberta", "candidata"):
            if not _lista_preenchida(caminhos):
                erro(f"{origem}: unidade {st} exige 'caminhos' revisados")
            if _vazio(verif):
                erro(f"{origem}: unidade {st} exige 'verificacao' (o que foi checado)")
        if st == "coberta":
            if fps:
                erro(f"{origem}: unidade coberta não tem fingerprints — se gerou candidato, é 'candidata'")
            if not _vazio(pend):
                erro(f"{origem}: unidade coberta com pendência — é 'bloqueada'")
        if st == "candidata":
            if not fps:
                erro(f"{origem}: unidade candidata exige fingerprints")
            for fp in fps:
                if fp not in fingerprints:
                    erro(f"{origem}: fingerprint {fp!r} não existe em ACHADOS, "
                         "PENDENTES_VALIDACAO nem DESCARTADOS")
        if st in ("bloqueada", "nao_aplicavel", "fora_de_escopo", "adiada"):
            if _vazio(pend):
                erro(f"{origem}: unidade {st} exige 'pendencia' (o motivo ou o fato que falta)")
            if st != "bloqueada" and fps:
                erro(f"{origem}: unidade {st} não carrega fingerprints")
        if st == "bloqueada" and not _lista_preenchida(caminhos):
            erro(f"{origem}: unidade bloqueada é revisão parcial — registre os caminhos lidos")
        if st == "bloqueada" and fps:
            erro(f"{origem}: unidade bloqueada não tem fingerprint — com candidato, é 'candidata'")

    checar_credenciais()
    checar_painel()

    # Prestação de contas: todo diretório de topo versionado tem unidade ou exclusão motivada.
    exclusoes = getattr(F, "EXCLUSOES", [])
    bases_exclusao: list[str] = []
    for n, ex in enumerate(exclusoes):
        base = _base_do_caminho(ex.get("caminho")) if isinstance(ex, dict) else ""
        if not base or base == "." or not caminho_seguro(base):
            erro(f"EXCLUSOES[{n}]: nomeie o diretório excluído; 'tudo' não é exclusão")
        elif _vazio(ex.get("motivo")):
            erro(f"EXCLUSOES[{n}] ({base}): falta o motivo")
        else:
            bases_exclusao.append(base)

    for u in cobertura:
        for item in (u.get("nao_alcancados") or []) if isinstance(u, dict) else []:
            if not isinstance(item, dict) or _vazio(item.get("caminho")) or _vazio(item.get("motivo")):
                erro(f"COBERTURA ({u.get('id', '?')}): nao_alcancados pede caminho e motivo")
        if isinstance(u, dict) and u.get("status") == "coberta" and u.get("nao_alcancados"):
            aviso(f"COBERTURA ({u.get('id', '?')}): unidade coberta com nao_alcancados — "
                  "o relatório lista o que ficou sem leitura")

    if perfil in ("padrao", "profunda") and not cobertura:
        erro("COBERTURA vazia — neste perfil o mapa é obrigatório: sem ele a alegação de "
             "cobertura é só prosa")
    if cobertura:
        topo = diretorios_topo(raiz, ref) if tem_git else None
        if not tem_git:
            aviso("projeto sem git: a conferência de diretórios da cobertura não rodou")
        elif topo is None:
            erro("cobertura: o git não listou os arquivos, então a prestação de contas de "
                 "diretórios não foi feita")
        else:
            # Só o `.` literal cobre tudo: um curinga como `*` não diz o que foi lido.
            literais = [(str(c).replace("\\", "/").strip(), u.get("status")) for u in cobertura
                        if isinstance(u, dict) for c in (u.get("caminhos") or [])]
            inteira = any(c in (".", "./") and st in ("coberta", "candidata")
                          for c, st in literais)
            bases = [b for b in (_base_do_caminho(c) for c, _ in literais) if b]
            faltam = [d for d in topo if not inteira
                      and not any(c == d or c.startswith(d + "/") for c in bases)
                      and not any(e == d for e in bases_exclusao)]
            if faltam:
                erro(f"cobertura não presta contas de {', '.join(faltam)} — crie unidade ou "
                     "liste em EXCLUSOES com motivo")

    # fingerprint de achado/pendente sem unidade candidata que o referencie
    if cobertura:
        referenciados = {fp for u in cobertura for fp in (u.get("fingerprints") or [])}
        for fp, origem in fingerprints.items():
            if origem.startswith(("DESCARTADOS", "ANTERIORES", "INFORMATIVOS")):
                continue
            if fp not in referenciados:
                aviso(f"{origem}: fingerprint {fp!r} não está ligado a nenhuma unidade de COBERTURA")

    return erros, avisos


def carregar(caminho: str):
    spec = importlib.util.spec_from_file_location("findings_sob_validacao", caminho)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)  # type: ignore[union-attr]
    return modulo


def main(argv: list[str]) -> int:
    # Console do Windows pode estar em cp1252; as mensagens têm acento e setas.
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(encoding="utf-8", errors="replace")
    caminho = argv[1] if len(argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "findings.py")
    if not os.path.exists(caminho):
        print(f"não encontrei {caminho}")
        return 1
    erros, avisos = validar(carregar(caminho))
    for a in avisos:
        print(f"AVISO  {a}")
    for e in erros:
        print(f"ERRO   {e}")
    print(f"{caminho}: {len(erros)} erro(s), {len(avisos)} aviso(s)")
    return 1 if erros else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
