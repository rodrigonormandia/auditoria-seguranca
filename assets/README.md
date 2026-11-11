# Auditoria de Segurança

Relatório: [`relatorio-auditoria-seguranca.pdf`](relatorio-auditoria-seguranca.pdf) — <N> páginas,
gerado em <data>. Análise por <autor>. Perfil da rodada: <rapida|padrao|profunda>; commit auditado
`<sha>`.

## Como regerar

```bash
python -m venv docs/security-audit/.venv
docs/security-audit/.venv/Scripts/python.exe -m pip install reportlab matplotlib
python docs/security-audit/redigir.py --aplicar
python docs/security-audit/validar_findings.py
docs/security-audit/.venv/Scripts/python.exe docs/security-audit/gerar_relatorio.py
```

O ambiente é isolado e fica fora do versionamento — nada é instalado globalmente.
Em Linux/macOS, troque `Scripts/python.exe` por `bin/python`. O gerador roda o validador
sozinho e se recusa a gerar com erro.

## Organização

| Arquivo | Papel |
| --- | --- |
| `reconhecimento.md` | Síntese do reconhecimento: principais, fronteiras, superfícies de entrada, domínios selecionados. |
| `contexto-produto.md` | O que a documentação do projeto (PRD, épicos, stories, specs, ADRs, planos) diz sobre papéis, regras, decisões e trabalho planejado. Cada achado é confrontado com ele antes de a correção ser proposta. |
| `registros/*.json` | Um arquivo por registro: achado confirmado, pendente de validação ou descartado (campo `veredito`). É aqui que se corrige um texto, se marca `status` ou se anota a `issue`. |
| `cobertura.json` | O mapa de cobertura: uma unidade por superfície × fronteira × subsistema × classe, com status. |
| `findings.py` | O cabeçalho (escopo, metodologia, resumo, pontos fortes, recomendações) e o carregador de `registros/` e `cobertura.json`. |
| `votos/<slug>/*.json` | Um voto por lente do painel. O placar é recalculado daqui. |
| `validar_findings.py` | Confere o conjunto: vereditos, categorias, fingerprints, credenciais, evidência no commit auditado, diretórios da cobertura e placar do painel. |
| `redigir.py` | Troca valores de credencial por `[REDACTED]`. |
| `apurar_votos.py` | Calcula o placar do painel. |
| `importar_claude_security.py` | Converte o relatório do plugin `claude-security` em candidatos. |
| `patches.py` | Prepara, julga e escreve patches verificados em `patches/`. |
| `gerar_relatorio.py` | Só layout (capa, gráficos, tabelas, pendentes, cobertura, issues). Não contém conteúdo de auditoria. |
| `abrir_issues.py` | Lista (padrão), exporta (`--exportar`) ou cadastra (`--criar`) os achados como issues no GitHub. Não duplica e anota o número no registro. |
| `issues.json` | Criado pelo `abrir_issues.py`: qual registro virou qual issue. |

A separação é proposital: reexecutar a auditoria significa regravar registros e rodar o gerador,
sem tocar em layout. Cada achado carrega arquivo, linha e trecho conferidos no commit auditado,
foi verificado por revisores independentes de quem o encontrou e tem um `fingerprint` estável — é por ele que a próxima rodada
reconhece o que carregar, revalidar ou não repetir. Os registros são escritos como documento de
correção: o controle que falta, onde, o impacto e a correção.

## Escopo desta rodada

<Categorias auditadas e como foram mapeadas para a stack do projeto; o que ficou adiado ou fora
de escopo, e o que o crítico de cobertura final disse.>
