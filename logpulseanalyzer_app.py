import streamlit as st
import pandas as pd
import re
import io
import os
import requests
from datetime import datetime
from collections import Counter
import pypdf
from fpdf import FPDF

st.set_page_config(
    page_title="LogPulse AI — Analisador & Gerador SA-AIC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# 1. PARSER, SANITIZAÇÃO (ANTI-PII) E CLUSTERIZAÇÃO CANÔNICA
# -----------------------------------------------------------------------------
RE_EMAIL = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
RE_CPF = re.compile(r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b')
RE_IP = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
RE_TOKEN = re.compile(r'(?i)(bearer\s+[a-zA-Z0-9_\-\.]+|jwt\s+[a-zA-Z0-9_\-\.]+|token[:=]\s*[a-zA-Z0-9_\-]+|password[:=]\s*\S+)')
RE_TIMESTAMP = re.compile(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\b[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b)')
RE_SEVERITY = re.compile(r'\b(CRITICAL|FATAL|ERROR|WARN|WARNING|INFO|DEBUG|TRACE)\b', re.IGNORECASE)
RE_DYNAMIC = re.compile(r'(\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b|\b0x[0-9a-fA-F]+\b|\b\d{4,}\b|(?<=\=)[^\s,;&]+)')

def sanitize_text(text: str) -> str:
    text = RE_TOKEN.sub('[REDACTED_SECRET]', text)
    text = RE_EMAIL.sub('u***@domain.com', text)
    text = RE_CPF.sub('***.***.***-**', text)
    text = RE_IP.sub('192.168.***.***', text)
    return text

def canonicalize_error(message: str) -> str:
    clean = RE_DYNAMIC.sub('<ID>', message)
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean[:200]

def extract_content(uploaded_file) -> str:
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
        st.error(f"Erro ao processar {uploaded_file.name}: {e}")
        return ""

def process_log(raw_text: str):
    lines = raw_text.splitlines()
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
        "total_lines": len(lines),
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
# 2. GERADOR DE PDF PURO PYTHON COM FPDF2 (100% ESTÁVEL)
# -----------------------------------------------------------------------------
class PDFReport(FPDF):
    def header(self):
        self.set_fill_color(30, 58, 138)
        self.rect(0, 0, 210, 22, 'F')
        self.set_font('Helvetica', 'B', 12)
        self.set_text_color(255, 255, 255)
        self.set_xy(10, 6)
        self.cell(0, 10, 'SA-AIC - Modelo de Documento para Distribuicao | LogPulse AI', 0, 1, 'L')
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 10, f'Pagina {self.page_no()}', 0, 0, 'R')

def generate_pdf_report(context_title: str, metrics: dict, diff_data: dict = None, batch_summary: list = None) -> bytes:
    pdf = PDFReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    pdf.set_text_color(15, 23, 42)
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 8, 'Relatorio de Auditoria e Inteligencia de Logs', ln=True)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(71, 85, 105)
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    pdf.cell(0, 5, f'Escopo: {context_title} | Emissao: {now_str}', ln=True)
    pdf.ln(4)

    # 1. Framework CLEAR
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 7, '1. Criterios Especificos da Tarefa (Framework CLEAR)', ln=True)
    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(30, 41, 59)
    clear_items = [
        ("Context Relevance:", "Foco prioritario em falhas CRITICAL, FATAL e ERROR. Ignora ruidos de INFO."),
        ("Language Tone:", "Tecnico, analitico, formal e voltado para Confiabilidade de Sistemas (SRE)."),
        ("Error Escalation:", "Mascaramento rigoroso de PII, senhas e tokens Bearer/JWT."),
        ("Accuracy:", "Contagem deterministica O(1) de ocorrencias baseada em hash canonico."),
        ("Response Efficiency:", "Matrizes ordenadas por impacto percentual (%) e deteccao de regressoes.")
    ]
    for k, v in clear_items:
        pdf.set_font('Helvetica', 'B', 8)
        pdf.cell(35, 5, k, 0, 0)
        pdf.set_font('Helvetica', '', 8)
        pdf.cell(0, 5, v, 0, 1)
    pdf.ln(3)

    # 2. Resumo de Métricas
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 7, '2. Visao Geral da Telemetria Analisada', ln=True)
    pdf.set_font('Helvetica', '', 8.5)
    pdf.cell(0, 5, f"Linhas Analisadas: {metrics['total_lines']:,} | Erros Totais: {metrics['total_errors']:,} | Avisos: {metrics['total_warns']:,} | Erros Unicos: {len(metrics['error_counter'])}", ln=True)
    pdf.ln(3)

    # Sumário de Lote (se houver)
    if batch_summary:
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 6, 'Resumo da Ingestao por Arquivo:', ln=True)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.cell(80, 5, 'Arquivo', 1, 0, 'L', True)
        pdf.cell(25, 5, 'Linhas', 1, 0, 'C', True)
        pdf.cell(25, 5, 'Erros', 1, 0, 'C', True)
        pdf.cell(25, 5, 'Avisos', 1, 0, 'C', True)
        pdf.cell(35, 5, 'Erros Unicos', 1, 1, 'C', True)
        pdf.set_font('Helvetica', '', 7.5)
        for it in batch_summary:
            pdf.cell(80, 5, str(it['Arquivo'])[:45], 1, 0, 'L')
            pdf.cell(25, 5, f"{it['Linhas']:,}", 1, 0, 'C')
            pdf.cell(25, 5, f"{it['Erros']:,}", 1, 0, 'C')
            pdf.cell(25, 5, f"{it['Avisos']:,}", 1, 0, 'C')
            pdf.cell(35, 5, str(it['Erros Únicos']), 1, 1, 'C')
        pdf.ln(3)

    # 3. Tabela de Erros
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 7, '3. Principais Falhas Detectadas (Clusterizacao Canonica)', ln=True)
    pdf.set_fill_color(241, 245, 249)
    pdf.set_font('Helvetica', 'B', 7.5)
    pdf.cell(12, 5, 'Rank', 1, 0, 'C', True)
    pdf.cell(18, 5, 'Sev', 1, 0, 'C', True)
    pdf.cell(105, 5, 'Assinatura Canonica do Erro', 1, 0, 'L', True)
    pdf.cell(18, 5, 'Qtd', 1, 0, 'C', True)
    pdf.cell(17, 5, '% Total', 1, 0, 'C', True)
    pdf.cell(20, 5, 'Visto', 1, 1, 'C', True)

    pdf.set_font('Helvetica', '', 7)
    tot_err = max(metrics['total_errors'], 1)
    for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(12), start=1):
        prop = (count / tot_err) * 100
        sev = metrics['severities'].get(sig, "ERROR")
        first = str(metrics['first_seen'].get(sig, "N/A"))[:10]
        clean_sig = sig.encode('latin-1', 'replace').decode('latin-1')[:68]
        pdf.cell(12, 5, f"#{rank}", 1, 0, 'C')
        pdf.cell(18, 5, str(sev)[:7], 1, 0, 'C')
        pdf.cell(105, 5, clean_sig, 1, 0, 'L')
        pdf.cell(18, 5, f"{count:,}", 1, 0, 'C')
        pdf.cell(17, 5, f"{prop:.1f}%", 1, 0, 'C')
        pdf.cell(20, 5, first, 1, 1, 'C')
    pdf.ln(3)

    # 4. Seção Diff (se houver)
    if diff_data:
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(0, 7, '4. Comparativo de Releases (Diff de Versoes)', ln=True)
        pdf.set_font('Helvetica', '', 8)
        pdf.cell(0, 5, f"Erros v1: {diff_data['old_errors']:,} -> Erros v2: {diff_data['new_errors']:,} ({diff_data['diff_pct']:+.1f}%)", ln=True)
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_text_color(22, 163, 74)
        pdf.cell(0, 5, f"Erros Resolvidos com Sucesso: {len(diff_data['resolved'])} falhas eliminadas", ln=True)
        pdf.set_text_color(220, 38, 38)
        pdf.cell(0, 5, f"Novas Regressoes Introduzidas: {len(diff_data['regressions'])} novas assinaturas", ln=True)
        pdf.set_text_color(15, 23, 42)
        pdf.ln(2)

    # 5. Recomendações
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 6, '5. Recomendacoes Tecnicas e Proximos Passos', ln=True)
    pdf.set_font('Helvetica', '', 7.5)
    pdf.multi_cell(0, 4, '1. Isolar a causa raiz das falhas do Top 3 de frequencia.\n2. Aplicar circuit breakers e timeouts ajustados nos microsservicos.\n3. Repetir a comparacao automatizada no proximo deploy.')

    return bytes(pdf.output())

# -----------------------------------------------------------------------------
# 3. TEMPLATES HTML & MARKDOWN
# -----------------------------------------------------------------------------
DEFAULT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<style>
    body { font-family: Arial, sans-serif; color: #0f172a; padding: 20px; line-height: 1.4; font-size: 9pt; }
    .header-card { background-color: #1e3a8a; color: #ffffff; padding: 16px; border-radius: 6px; margin-bottom: 14px; }
    .header-card h1 { font-size: 14pt; margin: 0 0 4px 0; color: #ffffff; }
    .badge { display: inline-block; background-color: #2563eb; color: #fff; font-size: 7pt; font-weight: bold; padding: 2px 6px; border-radius: 3px; }
    h2 { font-size: 11pt; color: #0f172a; border-left: 4px solid #2563eb; padding-left: 8px; margin-top: 14px; }
    table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 8pt; }
    th, td { border: 1px solid #cbd5e1; padding: 5px; text-align: left; }
    th { background-color: #f1f5f9; font-weight: bold; }
    tr:nth-child(even) td { background-color: #f8fafc; }
</style>
</head>
<body>
<div class="header-card">
    <div class="badge">SA-AIC - Modelo de Documento para Distribuicao</div>
    <h1>Relatorio Oficial de Auditoria & Inteligencia de Logs</h1>
    <p>Contexto: {{CONTEXT_TITLE}} | Emissao: {{GENERATION_DATE}} | Engine: LogPulse AI</p>
</div>
<h2>1. Visao Geral da Telemetria</h2>
<p>Linhas: <b>{{TOTAL_LINES}}</b> | Erros: <b>{{TOTAL_ERRORS}}</b> | Avisos: <b>{{TOTAL_WARNS}}</b> | Erros Unicos: <b>{{UNIQUE_ERRORS}}</b></p>
{{BATCH_SECTION}}
<h2>2. Tabela de Erros Mais Frequentes</h2>
<table><thead><tr><th>Rank</th><th>Severidade</th><th>Assinatura Canonica</th><th>Qtd</th><th>%</th><th>Primeiro Visto</th><th>Ultimo Visto</th></tr></thead>
<tbody>{{ERROR_TABLE_ROWS}}</tbody></table>
{{DIFF_SECTION}}
</body></html>"""

def load_template(custom_url: str = None, uploaded_template = None) -> str:
    if uploaded_template is not None:
        fname = uploaded_template.name.lower()
        try:
            if fname.endswith('.pdf'):
                reader = pypdf.PdfReader(uploaded_template)
                text = "\n".join([p.extract_text() or "" for p in reader.pages])
                return f"""<!DOCTYPE html><html><body><pre>{text}</pre></body></html>"""
            else:
                return uploaded_template.read().decode('utf-8', errors='ignore')
        except Exception:
            pass
    if custom_url and custom_url.strip():
        try:
            r = requests.get(custom_url.strip(), timeout=5)
            if r.status_code == 200:
                return r.text
        except Exception:
            pass
    if os.path.exists("report_template.html"):
        try:
            with open("report_template.html", "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            pass
    return DEFAULT_HTML_TEMPLATE

def render_html_report(template_str: str, context_title: str, metrics: dict, diff_data: dict = None, batch_summary: list = None) -> str:
    tot_err = max(metrics['total_errors'], 1)
    error_rows_html = ""
    for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(15), start=1):
        prop = (count / tot_err) * 100
        sev = metrics['severities'].get(sig, "ERROR")
        first = metrics['first_seen'].get(sig, "N/A")
        last = metrics['last_seen'].get(sig, "N/A")
        error_rows_html += f"<tr><td>#{rank}</td><td style='color:#dc2626;font-weight:bold;'>{sev}</td><td><code>{sig}</code></td><td>{count:,}</td><td>{prop:.1f}%</td><td>{first}</td><td>{last}</td></tr>"

    batch_section_html = ""
    if batch_summary:
        b_rows = "".join([f"<tr><td><b>{it['Arquivo']}</b></td><td>{it['Linhas']:,}</td><td style='color:#dc2626;'>{it['Erros']:,}</td><td>{it['Avisos']:,}</td><td>{it['Erros Únicos']}</td></tr>" for it in batch_summary])
        batch_section_html = f"<h3>Sumario do Lote</h3><table><thead><tr><th>Arquivo</th><th>Linhas</th><th>Erros</th><th>Avisos</th><th>Erros Unicos</th></tr></thead><tbody>{b_rows}</tbody></table>"

    diff_section_html = ""
    if diff_data:
        diff_section_html = f"""<h3>Quadro Comparativo de Releases</h3><table><thead><tr><th>Metrica</th><th>v1</th><th>v2</th><th>Variacao</th></tr></thead>
<tbody><tr><td>Total de Erros</td><td>{diff_data['old_errors']:,}</td><td>{diff_data['new_errors']:,}</td><td>{diff_data['diff_pct']:+.1f}%</td></tr>
<tr><td>Erros Resolvidos</td><td colspan='3' style='color:#16a34a;'>{len(diff_data['resolved'])} corrigidos</td></tr>
<tr><td>Novas Regressoes</td><td colspan='3' style='color:#dc2626;'>{len(diff_data['regressions'])} novas falhas</td></tr></tbody></table>"""

    content = template_str.replace("{{CONTEXT_TITLE}}", str(context_title))
    content = content.replace("{{GENERATION_DATE}}", datetime.now().strftime('%d/%m/%Y %H:%M:%S'))
    content = content.replace("{{TOTAL_LINES}}", f"{metrics['total_lines']:,}")
    content = content.replace("{{TOTAL_ERRORS}}", f"{metrics['total_errors']:,}")
    content = content.replace("{{TOTAL_WARNS}}", f"{metrics['total_warns']:,}")
    content = content.replace("{{UNIQUE_ERRORS}}", f"{len(metrics['error_counter'])}")
    content = content.replace("{{ERROR_TABLE_ROWS}}", error_rows_html or "<tr><td colspan='7'>Nenhum erro encontrado.</td></tr>")
    content = content.replace("{{BATCH_SECTION}}", batch_section_html)
    content = content.replace("{{DIFF_SECTION}}", diff_section_html)
    return content

def render_markdown_report(context_title: str, metrics: dict, diff_data: dict = None, batch_summary: list = None) -> str:
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    tot_err = max(metrics['total_errors'], 1)
    md = f"""# SA-AIC - Modelo de Documento para Distribuicao
# Relatorio de Auditoria de Logs — LogPulse AI

**Contexto Analisado:** {context_title}  
**Data de Emissao:** {now_str}  
**Linhas Totais:** {metrics['total_lines']:,} | **Erros:** {metrics['total_errors']:,} | **Avisos:** {metrics['total_warns']:,} | **Erros Unicos:** {len(metrics['error_counter'])}

---

## 1. Tabela de Erros Mais Frequentes (Clusterizacao Canonica)

| Rank | Severidade | Assinatura Canonica do Erro | Ocorrencias | % Total | Primeiro Visto | Ultimo Visto |
| :---: | :---: | :--- | :---: | :---: | :---: | :---: |
"""
    for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(15), start=1):
        prop = (count / tot_err) * 100
        sev = metrics['severities'].get(sig, "ERROR")
        first = metrics['first_seen'].get(sig, "N/A")
        last = metrics['last_seen'].get(sig, "N/A")
        md += f"| #{rank} | `{sev}` | `{sig}` | {count:,} | {prop:.1f}% | {first} | {last} |\n"

    if diff_data:
        md += f"""
---

## 2. Quadro Comparativo de Releases (Diff de Atualizacoes)
- **Variacao de Erros:** {diff_data['old_errors']:,} (v1) -> {diff_data['new_errors']:,} (v2) ({diff_data['diff_pct']:+.1f}%)
- **Erros Resolvidos com Sucesso:** {len(diff_data['resolved'])}
- **Novas Regressoes Detectadas:** {len(diff_data['regressions'])}
"""
    return md

# -----------------------------------------------------------------------------
# 4. INTERFACE STREAMLIT
# -----------------------------------------------------------------------------
st.title("🛡️ LogPulse AI — Analisador Inteligente & Gerador SA-AIC")
st.markdown("Motor agêntico para análise de logs nos formatos **.csv, .pdf, .txt, .log e .json** com exportação em **PDF, Markdown (.md) e HTML**.")

st.sidebar.header("⚙️ Modalidade de Analise")
mode = st.sidebar.radio(
    "Selecione a Operacao:",
    ["📊 Diagnostico de Log Unico", "📁 Analise Consolidada em Lote (Multiplos Arquivos)", "⚖️ Comparacao entre Versoes (Diff de Releases)"]
)

st.sidebar.divider()
with st.sidebar.expander("📄 Gerenciador de Template Dinamico", expanded=False):
    template_file = st.file_uploader("Subir novo Template (.html, .pdf, .md, .txt):", type=["html", "htm", "pdf", "md", "txt"])
    template_url = st.text_input("Ou URL direta do Template:", placeholder="https://raw.githubusercontent.com/.../report_template.html")

active_template = load_template(custom_url=template_url, uploaded_template=template_file)

# MODALIDADE 1: ÚNICO
if mode == "📊 Diagnostico de Log Unico":
    uploaded_file = st.sidebar.file_uploader("Envie seu arquivo de log:", type=["log", "txt", "csv", "pdf", "json"])
    if uploaded_file is not None:
        with st.spinner("Processando arquivo..."):
            raw_text = extract_content(uploaded_file)
            metrics = process_log(raw_text) if raw_text else None
            
        if metrics:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Linhas Analisadas", f"{metrics['total_lines']:,}")
            c2.metric("Erros Totais", f"{metrics['total_errors']:,}", delta_color="inverse")
            c3.metric("Avisos", f"{metrics['total_warns']:,}")
            c4.metric("Falhas Unicas", f"{len(metrics['error_counter'])}")
            
            st.divider()
            st.subheader("🔍 Padroes de Falhas Agrupados")
            if metrics['error_counter']:
                table_rows = []
                tot = max(metrics['total_errors'], 1)
                for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(20), start=1):
                    table_rows.append({
                        "Rank": f"#{rank}",
                        "Severidade": metrics['severities'].get(sig, "ERROR"),
                        "Assinatura Canonica": sig,
                        "Ocorrencias": count,
                        "Impacto (%)": f"{(count/tot)*100:.1f}%",
                        "Primeiro Visto": metrics['first_seen'].get(sig, "N/A"),
                        "Ultimo Visto": metrics['last_seen'].get(sig, "N/A"),
                    })
                st.dataframe(pd.DataFrame(table_rows), use_container_width=True)
            else:
                st.success("Nenhum erro encontrado no arquivo!")

            st.divider()
            st.subheader("📥 Exportacao do Relatorio Oficial (Modelo SA-AIC)")
            pdf_bytes = generate_pdf_report(uploaded_file.name, metrics)
            rep_md = render_markdown_report(uploaded_file.name, metrics)
            rep_html = render_html_report(active_template, uploaded_file.name, metrics)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.download_button("📑 Baixar Relatorio em PDF (.pdf)", data=pdf_bytes, file_name=f"relatorio_{uploaded_file.name}.pdf", mime="application/pdf", use_container_width=True)
            with col2:
                st.download_button("📄 Baixar Relatorio em Markdown (.md)", data=rep_md, file_name=f"relatorio_{uploaded_file.name}.md", mime="text/markdown", use_container_width=True)
            with col3:
                st.download_button("🌐 Baixar Relatorio em HTML (.html)", data=rep_html, file_name=f"relatorio_{uploaded_file.name}.html", mime="text/html", use_container_width=True)

# MODALIDADE 2: LOTE
elif mode == "📁 Analise Consolidada em Lote (Multiplos Arquivos)":
    uploaded_files = st.sidebar.file_uploader("Envie multiplos arquivos de log:", type=["log", "txt", "csv", "pdf", "json"], accept_multiple_files=True)
    if uploaded_files:
        batch_summary = []
        global_errors = Counter()
        global_warns = Counter()
        global_first = {}
        global_last = {}
        global_sev = {}
        tot_lines = 0
        
        with st.spinner("Processando lote..."):
            for f in uploaded_files:
                text = extract_content(f)
                m = process_log(text)
                tot_lines += m['total_lines']
                global_errors.update(m['error_counter'])
                global_warns.update(m['warn_counter'])
                for k, v in m['first_seen'].items():
                    if k not in global_first: global_first[k] = v
                for k, v in m['last_seen'].items(): global_last[k] = v
                for k, v in m['severities'].items(): global_sev[k] = v
                batch_summary.append({
                    "Arquivo": f.name,
                    "Linhas": m['total_lines'],
                    "Erros": m['total_errors'],
                    "Avisos": m['total_warns'],
                    "Erros Únicos": len(m['error_counter'])
                })
                
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Arquivos Processados", len(uploaded_files))
        c2.metric("Total de Linhas", f"{tot_lines:,}")
        c3.metric("Erros Globais", f"{sum(global_errors.values()):,}", delta_color="inverse")
        c4.metric("Padroes Unicos", len(global_errors))
        
        st.dataframe(pd.DataFrame(batch_summary), use_container_width=True)
        
        st.divider()
        st.subheader("📥 Exportacao do Relatorio Consolidado (Modelo SA-AIC)")
        global_metrics = {
            "total_lines": tot_lines,
            "total_errors": sum(global_errors.values()),
            "total_warns": sum(global_warns.values()),
            "error_counter": global_errors,
            "warn_counter": global_warns,
            "first_seen": global_first,
            "last_seen": global_last,
            "severities": global_sev
        }
        scope_title = f"Lote Consolidado ({len(uploaded_files)} Logs)"
        pdf_batch = generate_pdf_report(scope_title, global_metrics, batch_summary=batch_summary)
        rep_batch_md = render_markdown_report(scope_title, global_metrics, batch_summary=batch_summary)
        rep_batch_html = render_html_report(active_template, scope_title, global_metrics, batch_summary=batch_summary)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.download_button("📑 Baixar Relatorio Consolidado em PDF (.pdf)", data=pdf_batch, file_name="relatorio_lote_consolidado.pdf", mime="application/pdf", use_container_width=True)
        with col2:
            st.download_button("📄 Baixar Relatorio Consolidado em Markdown (.md)", data=rep_batch_md, file_name="relatorio_lote_consolidado.md", mime="text/markdown", use_container_width=True)
        with col3:
            st.download_button("🌐 Baixar Relatorio Consolidado em HTML (.html)", data=rep_batch_html, file_name="relatorio_lote_consolidado.html", mime="text/html", use_container_width=True)

# MODALIDADE 3: DIFF
else:
    file_old = st.sidebar.file_uploader("Versao Anterior (v1.x):", type=["log", "txt", "csv", "pdf", "json"], key="f_old")
    file_new = st.sidebar.file_uploader("Versao Atual (v2.x):", type=["log", "txt", "csv", "pdf", "json"], key="f_new")
    if file_old and file_new:
        with st.spinner("Comparando releases..."):
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

        c1, c2, c3 = st.columns(3)
        c1.metric("Erros Versao Anterior", f"{m_old['total_errors']:,}")
        c2.metric("Erros Versao Atual", f"{m_new['total_errors']:,}", f"{diff_pct:+.1f}%", delta_color="inverse")
        c3.metric("Erros Unicos", f"{len(keys_old)} -> {len(keys_new)}")

        st.divider()
        st.subheader("📥 Exportacao do Relatorio Comparativo (Diff Modelo SA-AIC)")
        scope_diff = f"{file_old.name} (v1) vs {file_new.name} (v2)"
        pdf_diff = generate_pdf_report(scope_diff, m_new, diff_data=diff_data)
        rep_diff_md = render_markdown_report(scope_diff, m_new, diff_data=diff_data)
        rep_diff_html = render_html_report(active_template, scope_diff, m_new, diff_data=diff_data)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.download_button("📑 Baixar Relatorio Diff em PDF (.pdf)", data=pdf_diff, file_name=f"relatorio_diff_{file_old.name}_vs_{file_new.name}.pdf", mime="application/pdf", use_container_width=True)
        with col2:
            st.download_button("📄 Baixar Relatorio Diff em Markdown (.md)", data=rep_diff_md, file_name=f"relatorio_diff_{file_old.name}_vs_{file_new.name}.md", mime="text/markdown", use_container_width=True)
        with col3:
            st.download_button("🌐 Baixar Relatorio Diff em HTML (.html)", data=rep_diff_html, file_name=f"relatorio_diff_{file_old.name}_vs_{file_new.name}.html", mime="text/html", use_container_width=True)
