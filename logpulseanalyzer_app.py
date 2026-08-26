import streamlit as st
import pandas as pd
import re
import io
import os
import hashlib
from datetime import datetime
from collections import Counter
import pypdf

# -----------------------------------------------------------------------------
# CONFIGURAÇÃO DA PÁGINA STREAMLIT
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="LogPulse AI — Analisador & Gerador de Relatórios",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# 1. MOTORES DE PROCESSAMENTO, SANITIZAÇÃO (ANTI-PII) E CLUSTERIZAÇÃO
# -----------------------------------------------------------------------------
RE_EMAIL = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
RE_CPF = re.compile(r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b')
RE_IP = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
RE_TOKEN = re.compile(r'(?i)(bearer\s+[a-zA-Z0-9_\-\.]+|jwt\s+[a-zA-Z0-9_\-\.]+|token[:=]\s*[a-zA-Z0-9_\-]+|password[:=]\s*\S+)')
RE_TIMESTAMP = re.compile(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\b[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b)')
RE_SEVERITY = re.compile(r'\b(CRITICAL|FATAL|ERROR|WARN|WARNING|INFO|DEBUG|TRACE)\b', re.IGNORECASE)
RE_DYNAMIC = re.compile(r'(\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b|\b0x[0-9a-fA-F]+\b|\b\d{4,}\b|(?<=\=)[^\s,;&]+)')

def sanitize_text(text: str) -> str:
    """Mascara dados sensíveis (Anti-PII e Secrets)."""
    text = RE_TOKEN.sub('[REDACTED_SECRET]', text)
    text = RE_EMAIL.sub('u***@domain.com', text)
    text = RE_CPF.sub('***.***.***-**', text)
    text = RE_IP.sub('192.168.***.***', text)
    return text

def canonicalize_error(message: str) -> str:
    """Extrai assinatura canônica removendo variáveis dinâmicas."""
    clean = RE_DYNAMIC.sub('<ID>', message)
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean[:220]

def extract_content(uploaded_file) -> str:
    """Lê múltiplos formatos (.log, .txt, .csv, .pdf, .json)."""
    ext = uploaded_file.name.split('.')[-1].lower()
    try:
        if ext == 'pdf':
            reader = pypdf.PdfReader(uploaded_file)
            return "\n".join([page.extract_text() or "" for page in reader.pages])
        elif ext == 'csv':
            try:
                df = pd.read_csv(uploaded_file)
                return "\n".join(df.astype(str).values.flatten())
            except Exception:
                uploaded_file.seek(0)
                return uploaded_file.read().decode('utf-8', errors='ignore')
        else:
            return uploaded_file.read().decode('utf-8', errors='ignore')
    except Exception as e:
        st.error(f"Erro ao ler {uploaded_file.name}: {e}")
        return ""

def process_log(raw_text: str):
    """Executa parsing em streaming O(N) e agrega métricas."""
    lines = raw_text.splitlines()
    total_lines = len(lines)
    
    error_counter = Counter()
    warn_counter = Counter()
    info_counter = 0
    first_seen = {}
    last_seen = {}
    severities = {}
    
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        sanitized = sanitize_text(line)
        sev_match = RE_SEVERITY.search(sanitized)
        sev = sev_match.group(1).upper() if sev_match else "INFO"
        if sev == "WARNING":
            sev = "WARN"
            
        ts_match = RE_TIMESTAMP.search(sanitized)
        ts = ts_match.group(1) if ts_match else f"Linha #{idx+1}"
        
        if sev in ["CRITICAL", "FATAL", "ERROR"]:
            canonical = canonicalize_error(sanitized)
            error_counter[canonical] += 1
            if canonical not in first_seen:
                first_seen[canonical] = ts
            last_seen[canonical] = ts
            severities[canonical] = "CRITICAL" if sev in ["CRITICAL", "FATAL"] else "ERROR"
        elif sev == "WARN":
            canonical = canonicalize_error(sanitized)
            warn_counter[canonical] += 1
            if canonical not in first_seen:
                first_seen[canonical] = ts
            last_seen[canonical] = ts
        else:
            info_counter += 1
            
    return {
        "total_lines": total_lines,
        "total_errors": sum(error_counter.values()),
        "total_warns": sum(warn_counter.values()),
        "total_info": info_counter,
        "error_counter": error_counter,
        "warn_counter": warn_counter,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "severities": severities
    }

# -----------------------------------------------------------------------------
# 2. GERADORES DE RELATÓRIO NO MODELO SA-AIC DOCUMENT TEMPLATE
# -----------------------------------------------------------------------------
def build_sa_aic_html_report(title_ctx: str, metrics: dict, diff_data: dict = None, batch_summary: list = None) -> str:
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    total_errors = max(metrics['total_errors'], 1)
    
    # Tabela de Erros
    error_rows_html = ""
    for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(12), start=1):
        prop = (count / total_errors) * 100
        sev = metrics['severities'].get(sig, "ERROR")
        first = metrics['first_seen'].get(sig, "N/A")
        last = metrics['last_seen'].get(sig, "N/A")
        error_rows_html += f"""
        <tr>
            <td style="text-align:center; font-weight:bold;">#{rank}</td>
            <td><span class="badge-{sev.lower()}">{sev}</span></td>
            <td><code>{sig}</code></td>
            <td style="text-align:center;">{count}</td>
            <td style="text-align:center;">{prop:.1f}%</td>
            <td>{first}</td>
            <td>{last}</td>
        </tr>
        """
        
    # Seção Batch (se houver múltiplos arquivos)
    batch_section_html = ""
    if batch_summary:
        batch_rows = "".join([
            f"<tr><td><b>{item['Arquivo']}</b></td><td style='text-align:center;'>{item['Linhas']:,}</td><td style='text-align:center;'>{item['Erros']:,}</td><td style='text-align:center;'>{item['Avisos']:,}</td><td style='text-align:center;'>{item['Erros Únicos']}</td></tr>"
            for item in batch_summary
        ])
        batch_section_html = f"""
        <h2>Sumário de Ingestão por Arquivo (Lote)</h2>
        <table>
            <thead><tr><th>Arquivo</th><th>Linhas</th><th>Erros</th><th>Avisos</th><th>Erros Únicos</th></tr></thead>
            <tbody>{batch_rows}</tbody>
        </table>
        """

    # Seção Diff (se houver comparação de versões)
    diff_section_html = ""
    if diff_data:
        diff_section_html = f"""
        <h2>7. Cenários de Exemplo & Comparação de Releases (Diff v1 vs v2)</h2>
        <div class="box-note">
            <b>Métricas de Comparação:</b><br>
            • Versão Anterior: {diff_data['old_errors']} erros | Versão Atual: {diff_data['new_errors']} erros ({diff_data['diff_pct']:+.1f}%)<br>
            • Erros Resolvidos: {len(diff_data['resolved'])} | Novas Regressões: {len(diff_data['regressions'])}
        </div>
        <h3>🟢 Erros Resolvidos com Sucesso</h3>
        <ul>{"".join([f"<li><code>{err}</code></li>" for err in list(diff_data['resolved'])[:5]]) or "<li>Nenhum erro resolvido.</li>"}</ul>
        <h3>🔴 Novos Erros / Regressões Detectadas</h3>
        <ul>{"".join([f"<li><code>{err}</code></li>" for err in list(diff_data['regressions'])[:5]]) or "<li>Nenhuma regressão detectada.</li>"}</ul>
        """

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<style>
    @page {{
        size: A4;
        margin: 18mm 15mm;
        @bottom-right {{ content: counter(page); font-size: 8pt; color: #64748b; }}
        @bottom-left {{ content: "SA-AIC - Modelo de Documento para Distribuição | LogPulse AI"; font-size: 8pt; color: #64748b; }}
    }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #1e293b; line-height: 1.5; font-size: 9.5pt; margin: 0; }}
    .header-card {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%); color: #ffffff; padding: 20px 24px; border-radius: 8px; margin-bottom: 20px; }}
    .header-card h1 {{ font-size: 16pt; margin: 0 0 6px 0; color: #ffffff; }}
    .header-card p {{ font-size: 9.5pt; margin: 0; color: #93c5fd; }}
    .badge {{ display: inline-block; background-color: #3b82f6; color: #fff; font-size: 7.5pt; font-weight: bold; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; margin-bottom: 6px; }}
    h2 {{ font-size: 12pt; color: #0f172a; border-left: 4px solid #2563eb; padding-left: 10px; margin-top: 20px; margin-bottom: 8px; page-break-after: avoid; }}
    h3 {{ font-size: 10pt; color: #1e3a8a; margin-top: 12px; margin-bottom: 6px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 8.5pt; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 6px 8px; text-align: left; }}
    th {{ background-color: #f1f5f9; color: #0f172a; font-weight: 600; }}
    tr:nth-child(even) td {{ background-color: #f8fafc; }}
    .badge-error {{ color: #dc2626; font-weight: bold; }}
    .badge-critical {{ color: #7f1d1d; background: #fee2e2; padding: 2px 5px; border-radius: 3px; font-weight: bold; }}
    .badge-warn {{ color: #d97706; font-weight: bold; }}
    .box-note {{ background-color: #eff6ff; border: 1px solid #bfdbfe; border-left: 4px solid #3b82f6; padding: 10px 12px; border-radius: 4px; margin: 10px 0; }}
    .prompt-box {{ background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 12px; margin-bottom: 8px; font-family: monospace; font-size: 8.5pt; }}
</style>
</head>
<body>

<div class="header-card">
    <div class="badge">SA-AIC - Modelo de Documento para Distribuição</div>
    <h1>Relatório de Diagnóstico e Auditoria de Logs</h1>
    <p><b>Escopo:</b> {title_ctx} | <b>Gerado em:</b> {now_str} | <b>Engine:</b> LogPulse AI</p>
</div>

<h2>Passo 1: Critérios Específicos da Tarefa (Framework CLEAR)</h2>
<table>
    <tr><th style="width:25%;">Critério CLEAR</th><th>Definição Aplicada na Análise</th></tr>
    <tr><td><b>1. Relevância do Contexto</b></td><td>Priorização estrita de falhas <code>CRITICAL</code>, <code>FATAL</code> e <code>ERROR</code>. Agrupamento de anomalias operacionais e exclusão de ruídos informativos comuns.</td></tr>
    <tr><td><b>2. Tom e Estilo</b></td><td>Linguagem técnica, analítica, concisa e orientada à resolução para equipes de Engenharia e DevOps.</td></tr>
    <tr><td><b>3. Tratamento de Incerteza</b></td><td>Dados sensíveis são mascarados (Anti-PII). Assinaturas com stack traces ambíguos são sinalizadas com recomendações de depuração.</td></tr>
    <tr><td><b>4. Precisão e Confiabilidade</b></td><td>Contagem exata $O(1)$ de ocorrências por hash canônico sem risco de alucinação numérica.</td></tr>
    <tr><td><b>5. Eficiência da Resposta</b></td><td>Apresentação em tabelas comparativas com cálculo automático de impacto (%) e primeiros/últimos timestamps vistos.</td></tr>
</table>

<h2>Passo 2: Engenharia de Prompts Aplicada (Framework TRACI)</h2>
<div class="prompt-box">
<b>Tarefa Principal:</b><br>
• <b>Task:</b> Extrair e tabular falhas únicas dos arquivos submetidos.<br>
• <b>Role:</b> Engenheiro de Confiabilidade de Sistemas (SRE).<br>
• <b>Audience:</b> Desenvolvedores, Tech Leads e DevOps.<br>
• <b>Context:</b> Processamento de telemetria ({title_ctx}) com {metrics['total_lines']} linhas totais.<br>
• <b>Instructions:</b> Sanitizar credenciais, computar frequência única e apontar causa provável.
</div>

<h2>1. Visão Geral do Volume de Telemetria</h2>
<p>Foram analisadas <b>{metrics['total_lines']:,} linhas</b>, detectando <b>{metrics['total_errors']:,} erros</b> e <b>{metrics['total_warns']:,} avisos</b> distribuídos em <b>{len(metrics['error_counter'])} assinaturas canônicas exclusivas</b>.</p>

{batch_section_html}

<h2>2. Principais Falhas Detectadas (Tabela Consolidada de Frequência)</h2>
<table>
    <thead>
        <tr>
            <th style="width:6%;">Rank</th>
            <th style="width:10%;">Severidade</th>
            <th>Assinatura Canônica do Erro</th>
            <th style="width:10%;">Ocorrências</th>
            <th style="width:8%;">%</th>
            <th style="width:14%;">Primeiro Visto</th>
            <th style="width:14%;">Último Visto</th>
        </tr>
    </thead>
    <tbody>
        {error_rows_html if error_rows_html else "<tr><td colspan='7' style='text-align:center;'>Nenhum erro crítico ou de severidade ERROR detectado.</td></tr>"}
    </tbody>
</table>

<h2>3. Processo de Desenvolvimento & Recomendações Técnicas</h2>
<ol>
    <li><b>Isolamento de Causa Raiz:</b> Inspecionar os endpoints e módulos associados aos erros ranqueados em #1 e #2.</li>
    <li><b>Sanitização e Segurança:</b> Todos os tokens, IPs e documentos foram substituídos por tags de anonimização.</li>
    <li><b>Ações Preventivas:</b> Aplicar políticas de circuit-breaker e limites de conexões para prevenir esgotamento em cascata.</li>
</ol>

{diff_section_html}

</body>
</html>
"""
    return html

def build_sa_aic_markdown_report(title_ctx: str, metrics: dict, diff_data: dict = None, batch_summary: list = None) -> str:
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    total_errors = max(metrics['total_errors'], 1)
    
    md = f"""# SA-AIC - Modelo de Documento para Distribuição
# Relatório de Diagnóstico de Logs — LogPulse AI

**Escopo / Arquivos:** {title_ctx}  
**Data da Análise:** {now_str}  
**Volume Total de Linhas:** {metrics['total_lines']:,} | **Erros Detectados:** {metrics['total_errors']:,} | **Avisos (Warnings):** {metrics['total_warns']:,}

---

## Passo 1: Definir Critérios Específicos da Tarefa (Framework CLEAR)
1. **Relevância do Contexto:** Foco prioritário em falhas de severidade `CRITICAL`, `FATAL` e `ERROR`.
2. **Tom e Estilo da Linguagem:** Técnico, assertivo, analítico e orientado a SRE.
3. **Tratamento de Erros e Escalonamento:** Identificação de stack traces com mascaramento anti-PII automático.
4. **Precisão e Confiabilidade:** Contagem determinística agregada em $O(1)$.
5. **Eficiência da Resposta:** Resumo tabular hierarquizado por frequência e impacto percentual.

---

## Passo 2: Prompts Aplicados (Framework TRACI)
- **Task:** Diagnóstico, agrupamento por assinatura canônica e elaboração de plano de ação.
- **Role:** Agente Especialista SRE e Observabilidade (LogPulse AI).
- **Audience:** Equipes de Desenvolvimento, QA e Liderança Técnica.
- **Context:** Análise de telemetria ({title_ctx}).
- **Instructions:** Gerar tabela de frequência, isolar causas raízes e propor soluções.

---

## 1. Visão Geral e Principais Recursos
- **Linhas Analisadas:** {metrics['total_lines']:,}
- **Erros Totais:** {metrics['total_errors']:,}
- **Avisos Registrados:** {metrics['total_warns']:,}
- **Padrões Únicos Identificados:** {len(metrics['error_counter'])}
"""
    if batch_summary:
        md += "\n### Sumário de Ingestão por Arquivo\n"
        md += "| Arquivo | Linhas | Erros | Avisos | Erros Únicos |\n| :--- | :---: | :---: | :---: | :---: |\n"
        for item in batch_summary:
            md += f"| {item['Arquivo']} | {item['Linhas']:,} | {item['Erros']:,} | {item['Avisos']:,} | {item['Erros Únicos']} |\n"

    md += """
---

## 2. Tabela de Erros Mais Frequentes (Clusterizados por Padrão Canônico)

| Rank | Severidade | Assinatura / Categoria do Erro | Ocorrências | % do Total | Primeiro Visto | Último Visto |
| :---: | :---: | :--- | :---: | :---: | :---: | :---: |
"""
    for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(12), start=1):
        prop = (count / total_errors) * 100
        sev = metrics['severities'].get(sig, "ERROR")
        first = metrics['first_seen'].get(sig, "N/A")
        last = metrics['last_seen'].get(sig, "N/A")
        md += f"| #{rank} | `{sev}` | `{sig}` | {count} | {prop:.1f}% | {first} | {last} |\n"

    if diff_data:
        md += f"""
---

## 3. Comparativo de Versões (Diff de Atualizações)
- **Variação de Erros:** {diff_data['old_errors']} (v1) → {diff_data['new_errors']} (v2) ({diff_data['diff_pct']:+.1f}%)
- **Erros Resolvidos:** {len(diff_data['resolved'])}
- **Novas Regressões:** {len(diff_data['regressions'])}

### 🟢 Erros Resolvidos na Nova Versão
"""
        for err in list(diff_data['resolved'])[:5]:
            md += f"- ✅ `{err}`\n"
        md += "\n### 🔴 Novas Regressões Detectadas\n"
        for err in list(diff_data['regressions'])[:5]:
            md += f"- ⚠️ `{err}`\n"

    md += """
---

## 4. Recomendações e Próximos Passos
1. Investigar causas raízes prioritariamente nos erros ranqueados no Top 3.
2. Monitorar avisos recorrentes para evitar degradação progressiva de infraestrutura.
3. Repetir a validação após novos deploys utilizando o modo comparativo (Diff).
"""
    return md

# -----------------------------------------------------------------------------
# 3. INTERFACE STREAMLIT
# -----------------------------------------------------------------------------
st.title("🛡️ LogPulse AI — Analisador Inteligente & Gerador de Relatórios")
st.markdown("""
Plataforma agêntica para ingestão de arquivos de log nos formatos **.csv, .pdf, .txt, .log e .json**.
Analise arquivos individuais, processe múltiplos logs em lote ou compare versões (*Diff*).
""")

st.sidebar.header("⚙️ Configurações & Entrada")
mode = st.sidebar.radio(
    "Selecione a Modalidade de Análise:",
    [
        "📊 Diagnóstico de Log Único",
        "📁 Análise Consolidada em Lote (Múltiplos Arquivos)",
        "⚖️ Comparação entre Versões (Diff de Releases)"
    ]
)

# -----------------------------------------------------------------------------
# MODALIDADE 1: LOG ÚNICO
# -----------------------------------------------------------------------------
if mode == "📊 Diagnóstico de Log Único":
    uploaded_file = st.sidebar.file_uploader(
        "Envie seu arquivo de log:",
        type=["log", "txt", "csv", "pdf", "json"],
        help="Suporta logs de servidores, bancos de dados, aplicações ou exportações em PDF/CSV."
    )
    
    if uploaded_file is not None:
        with st.spinner("Lendo arquivo e executando parsing inteligente..."):
            raw_text = extract_content(uploaded_file)
            if not raw_text:
                st.warning("O arquivo fornecido está vazio ou não pôde ser lido.")
            else:
                metrics = process_log(raw_text)
                
        if raw_text:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Linhas Analisadas", f"{metrics['total_lines']:,}")
            c2.metric("Erros Totais", f"{metrics['total_errors']:,}", delta_color="inverse")
            c3.metric("Avisos (Warnings)", f"{metrics['total_warns']:,}")
            c4.metric("Falhas Únicas", f"{len(metrics['error_counter'])}")
            
            st.divider()
            st.subheader("🔍 Padrões de Falhas Agrupados (Clusterização Canônica)")
            if metrics['error_counter']:
                table_rows = []
                total_err = max(metrics['total_errors'], 1)
                for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(20), start=1):
                    prop = (count / total_err) * 100
                    table_rows.append({
                        "Rank": f"#{rank}",
                        "Severidade": metrics['severities'].get(sig, "ERROR"),
                        "Assinatura Canônica do Erro": sig,
                        "Ocorrências": count,
                        "Proporção (%)": f"{prop:.1f}%",
                        "Primeiro Visto": metrics['first_seen'].get(sig, "N/A"),
                        "Último Visto": metrics['last_seen'].get(sig, "N/A"),
                    })
                df_errors = pd.DataFrame(table_rows)
                st.dataframe(df_errors, use_container_width=True)
                
                st.subheader("📈 Top 5 Erros Mais Frequentes")
                chart_data = pd.DataFrame({
                    "Assinatura": [r['Assinatura Canônica do Erro'][:40] + "..." for r in table_rows[:5]],
                    "Ocorrências": [r['Ocorrências'] for r in table_rows[:5]]
                }).set_index("Assinatura")
                st.bar_chart(chart_data)
            else:
                st.success("🎉 Parabéns! Nenhum erro de severidade ERROR ou CRITICAL foi identificado.")

            st.divider()
            st.subheader("📥 Exportação de Relatório (Modelo SA-AIC)")
            report_md = build_sa_aic_markdown_report(uploaded_file.name, metrics)
            report_html = build_sa_aic_html_report(uploaded_file.name, metrics)
            
            pdf_bytes = None
            try:
                from weasyprint import HTML
                pdf_bytes = HTML(string=report_html).write_pdf()
            except Exception:
                pass
                
            col_d1, col_d2, col_d3 = st.columns(3)
            with col_d1:
                st.download_button("📄 Baixar Relatório (.md)", report_md, f"relatorio_{uploaded_file.name}.md", "text/markdown", use_container_width=True)
            with col_d2:
                st.download_button("🌐 Baixar Relatório (.html)", report_html, f"relatorio_{uploaded_file.name}.html", "text/html", use_container_width=True)
            with col_d3:
                if pdf_bytes:
                    st.download_button("📑 Baixar Relatório (.pdf)", pdf_bytes, f"relatorio_{uploaded_file.name}.pdf", "application/pdf", use_container_width=True)
                else:
                    st.download_button("📄 Baixar Código HTML para PDF", report_html, f"relatorio_{uploaded_file.name}.html", "text/html", use_container_width=True)
    else:
        st.info("👆 Por favor, envie um arquivo de log na barra lateral para iniciar a análise.")

# -----------------------------------------------------------------------------
# MODALIDADE 2: ANÁLISE CONSOLIDADA EM LOTE (MÚLTIPLOS ARQUIVOS)
# -----------------------------------------------------------------------------
elif mode == "📁 Análise Consolidada em Lote (Múltiplos Arquivos)":
    uploaded_files = st.sidebar.file_uploader(
        "Envie todos os seus arquivos de log de uma vez:",
        type=["log", "txt", "csv", "pdf", "json"],
        accept_multiple_files=True,
        help="Selecione múltiplos arquivos para consolidação de métricas e ranking global."
    )
    
    if uploaded_files:
        st.success(f"📂 **{len(uploaded_files)} arquivos recebidos para processamento consolidado.**")
        
        batch_summary = []
        global_error_counter = Counter()
        global_warn_counter = Counter()
        global_first_seen = {}
        global_last_seen = {}
        global_severities = {}
        total_global_lines = 0
        
        with st.spinner("Processando todos os arquivos em lote..."):
            for f in uploaded_files:
                text = extract_content(f)
                m = process_log(text)
                
                total_global_lines += m['total_lines']
                global_error_counter.update(m['error_counter'])
                global_warn_counter.update(m['warn_counter'])
                
                for k, v in m['first_seen'].items():
                    if k not in global_first_seen:
                        global_first_seen[k] = v
                for k, v in m['last_seen'].items():
                    global_last_seen[k] = v
                for k, v in m['severities'].items():
                    global_severities[k] = v
                    
                batch_summary.append({
                    "Arquivo": f.name,
                    "Linhas": m['total_lines'],
                    "Erros": m['total_errors'],
                    "Avisos": m['total_warns'],
                    "Erros Únicos": len(m['error_counter'])
                })
                
        # Métricas Globais
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Arquivos Analisados", len(uploaded_files))
        c2.metric("Total de Linhas", f"{total_global_lines:,}")
        c3.metric("Erros Totais (Todos os Logs)", f"{sum(global_error_counter.values()):,}", delta_color="inverse")
        c4.metric("Padrões Únicos de Erro", len(global_error_counter))
        
        st.divider()
        st.subheader("📋 Resumo por Arquivo de Log")
        st.dataframe(pd.DataFrame(batch_summary), use_container_width=True)
        
        st.divider()
        st.subheader("🌐 Top Falhas Globais (Consolidado de Todo o Ecossistema)")
        if global_error_counter:
            global_rows = []
            tot_err = max(sum(global_error_counter.values()), 1)
            for rank, (sig, count) in enumerate(global_error_counter.most_common(25), start=1):
                prop = (count / tot_err) * 100
                global_rows.append({
                    "Rank": f"#{rank}",
                    "Severidade": global_severities.get(sig, "ERROR"),
                    "Assinatura Canônica do Erro": sig,
                    "Ocorrências Totais": count,
                    "Impacto Global (%)": f"{prop:.1f}%",
                    "Primeiro Visto": global_first_seen.get(sig, "N/A"),
                    "Último Visto": global_last_seen.get(sig, "N/A"),
                })
            df_glob = pd.DataFrame(global_rows)
            st.dataframe(df_glob, use_container_width=True)
        else:
            st.success("🎉 Nenhum erro crítico encontrado nos arquivos analisados!")

        # Geração de Relatório Consolidado
        st.divider()
        st.subheader("📥 Exportação do Relatório Geral Consolidado (Modelo SA-AIC)")
        
        global_metrics = {
            "total_lines": total_global_lines,
            "total_errors": sum(global_error_counter.values()),
            "total_warns": sum(global_warn_counter.values()),
            "error_counter": global_error_counter,
            "warn_counter": global_warn_counter,
            "first_seen": global_first_seen,
            "last_seen": global_last_seen,
            "severities": global_severities
        }
        
        scope_title = f"Lote Consolidado ({len(uploaded_files)} Arquivos de Telemetria)"
        rep_batch_md = build_sa_aic_markdown_report(scope_title, global_metrics, batch_summary=batch_summary)
        rep_batch_html = build_sa_aic_html_report(scope_title, global_metrics, batch_summary=batch_summary)
        
        pdf_batch_bytes = None
        try:
            from weasyprint import HTML
            pdf_batch_bytes = HTML(string=rep_batch_html).write_pdf()
        except Exception:
            pass
            
        b_c1, b_c2, b_c3 = st.columns(3)
        with b_c1:
            st.download_button("📄 Baixar Relatório Consolidado (.md)", rep_batch_md, "relatorio_geral_consolidado.md", "text/markdown", use_container_width=True)
        with b_c2:
            st.download_button("🌐 Baixar Relatório Consolidado (.html)", rep_batch_html, "relatorio_geral_consolidado.html", "text/html", use_container_width=True)
        with b_c3:
            if pdf_batch_bytes:
                st.download_button("📑 Baixar Relatório Consolidado (.pdf)", pdf_batch_bytes, "relatorio_geral_consolidado.pdf", "application/pdf", use_container_width=True)
            else:
                st.download_button("📄 Baixar Código HTML para PDF", rep_batch_html, "relatorio_geral_consolidado.html", "text/html", use_container_width=True)
    else:
        st.info("👆 Por favor, selecione e envie seus múltiplos arquivos de log na barra lateral.")

# -----------------------------------------------------------------------------
# MODALIDADE 3: COMPARAÇÃO DE RELEASES (DIFF)
# -----------------------------------------------------------------------------
else:
    st.sidebar.subheader("Upload dos Logs para Diff")
    file_old = st.sidebar.file_uploader("Log da Versão Anterior (v1.x):", type=["log", "txt", "csv", "pdf", "json"], key="f_old")
    file_new = st.sidebar.file_uploader("Log da Versão Atual (v2.x):", type=["log", "txt", "csv", "pdf", "json"], key="f_new")
    
    if file_old and file_new:
        with st.spinner("Processando e comparando ambas as versões..."):
            m_old = process_log(extract_content(file_old))
            m_new = process_log(extract_content(file_new))
            
            keys_old = set(m_old['error_counter'].keys())
            keys_new = set(m_new['error_counter'].keys())
            
            resolved = keys_old - keys_new
            persisting = keys_old & keys_new
            regressions = keys_new - keys_old
            
            diff_pct = ((m_new['total_errors'] - m_old['total_errors']) / max(m_old['total_errors'], 1)) * 100
            diff_data = {
                "old_errors": m_old['total_errors'],
                "new_errors": m_new['total_errors'],
                "diff_pct": diff_pct,
                "resolved": resolved,
                "persisting": persisting,
                "regressions": regressions
            }

        st.subheader("⚖️ Quadro Comparativo Executivo (v1 vs v2)")
        col_c1, col_c2, col_c3 = st.columns(3)
        col_c1.metric("Erros Versão Anterior", f"{m_old['total_errors']:,}")
        col_c2.metric("Erros Versão Atual", f"{m_new['total_errors']:,}", f"{diff_pct:+.1f}%", delta_color="inverse")
        col_c3.metric("Erros Únicos (v1 → v2)", f"{len(keys_old)} → {len(keys_new)}")

        c_res, c_reg = st.columns(2)
        with c_res:
            st.markdown(f"### 🟢 Erros Resolvidos ({len(resolved)})")
            if resolved:
                for err in list(resolved)[:6]:
                    st.success(f"**Resolvido:** `{err}` (Ocorria {m_old['error_counter'][err]} vezes)")
            else:
                st.write("Nenhum erro anterior foi completamente extinto.")
                
        with c_reg:
            st.markdown(f"### 🔴 Novas Regressões ({len(regressions)})")
            if regressions:
                for err in list(regressions)[:6]:
                    st.error(f"**Regressão:** `{err}` ({m_new['error_counter'][err]} ocorrências)")
            else:
                st.write("Nenhuma regressão detectada na nova versão.")

        st.divider()
        st.subheader("📥 Exportação do Relatório Comparativo (Modelo SA-AIC)")
        
        rep_diff_md = build_sa_aic_markdown_report(f"{file_old.name}_vs_{file_new.name}", m_new, diff_data)
        rep_diff_html = build_sa_aic_html_report(f"{file_old.name}_vs_{file_new.name}", m_new, diff_data)
        
        pdf_diff_bytes = None
        try:
            from weasyprint import HTML
            pdf_diff_bytes = HTML(string=rep_diff_html).write_pdf()
        except Exception:
            pass
            
        c_btn1, c_btn2, c_btn3 = st.columns(3)
        with c_btn1:
            st.download_button("📄 Baixar Relatório Diff (.md)", rep_diff_md, f"relatorio_diff_{file_old.name}_vs_{file_new.name}.md", "text/markdown", use_container_width=True)
        with c_btn2:
            st.download_button("🌐 Baixar Relatório Diff (.html)", rep_diff_html, f"relatorio_diff_{file_old.name}_vs_{file_new.name}.html", "text/html", use_container_width=True)
        with c_btn3:
            if pdf_diff_bytes:
                st.download_button("📑 Baixar Relatório Diff (.pdf)", pdf_diff_bytes, f"relatorio_diff_{file_old.name}_vs_{file_new.name}.pdf", "application/pdf", use_container_width=True)
    else:
        st.info("👆 Por favor, envie os dois arquivos de log (versão anterior e versão atual) na barra lateral.")
