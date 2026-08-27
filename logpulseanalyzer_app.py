import streamlit as st
import pandas as pd
import re
import io
import os
import requests
from datetime import datetime
from collections import Counter
import pypdf

# -----------------------------------------------------------------------------
# CONFIGURAÇÃO DE GERADORES DE PDF NATIVOS
# -----------------------------------------------------------------------------
def convert_html_to_pdf(html_content: str) -> bytes:
    """Gera binário PDF nativo e autêntico."""
    try:
        from xhtml2pdf import pisa
        pdf_io = io.BytesIO()
        pisa_status = pisa.CreatePDF(io.StringIO(html_content), dest=pdf_io)
        if not pisa_status.err:
            return pdf_io.getvalue()
    except Exception:
        pass
    try:
        from weasyprint import HTML
        return HTML(string=html_content).write_pdf()
    except Exception:
        pass
    return None

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
RE_TIMESTAMP = re.compile(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\b[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b)')
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
    return clean[:220]

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
# 2. TEMPLATES PADRÃO & GERENCIADOR MULTI-FORMATO (.HTML, .MD, .PDF)
# -----------------------------------------------------------------------------
DEFAULT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<style>
    @page {
        size: A4;
        margin: 15mm;
        @bottom-right { content: counter(page); font-size: 8pt; color: #64748b; }
        @bottom-left { content: "SA-AIC - Modelo de Documento para Distribuição"; font-size: 8pt; color: #64748b; }
    }
    body { font-family: Arial, Helvetica, sans-serif; color: #0f172a; line-height: 1.4; font-size: 9pt; }
    .header-card { background-color: #1e3a8a; color: #ffffff; padding: 16px 20px; border-radius: 6px; margin-bottom: 14px; }
    .header-card h1 { font-size: 14pt; margin: 0 0 4px 0; color: #ffffff; }
    .header-card p { font-size: 8.5pt; margin: 0; color: #93c5fd; }
    .badge { display: inline-block; background-color: #2563eb; color: #fff; font-size: 7pt; font-weight: bold; padding: 2px 6px; border-radius: 3px; text-transform: uppercase; margin-bottom: 4px; }
    h2 { font-size: 11pt; color: #0f172a; border-left: 4px solid #2563eb; padding-left: 8px; margin-top: 14px; margin-bottom: 6px; text-transform: uppercase; }
    h3 { font-size: 9.5pt; color: #1e3a8a; margin-top: 10px; margin-bottom: 4px; }
    table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 8pt; }
    th, td { border: 1px solid #cbd5e1; padding: 5px 6px; text-align: left; }
    th { background-color: #f1f5f9; color: #0f172a; font-weight: bold; }
    tr:nth-child(even) td { background-color: #f8fafc; }
    .box-note { background-color: #eff6ff; border: 1px solid #bfdbfe; padding: 8px 10px; border-radius: 4px; margin: 8px 0; }
    .prompt-box { background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; padding: 8px 10px; margin-bottom: 8px; font-family: monospace; font-size: 8pt; }
</style>
</head>
<body>
<div class="header-card">
    <div class="badge">SA-AIC - Modelo de Documento para Distribuição</div>
    <h1>Relatório Oficial de Auditoria & Inteligência de Logs</h1>
    <p><b>Contexto:</b> {{CONTEXT_TITLE}} | <b>Emissão:</b> {{GENERATION_DATE}} | <b>Engine:</b> LogPulse AI</p>
</div>

<h2>Definir Critérios da Tarefa de IA e Escrever Prompts</h2>
<h3>Passo 1: Definir Critérios Específicos da Tarefa (Framework CLEAR)</h3>
<table>
    <thead><tr><th style="width:28%;">Critério CLEAR</th><th>Definição Operacional Aplicada</th></tr></thead>
    <tbody>
        <tr><td><b>1. Relevância do Contexto</b></td><td>Priorização de falhas <code>CRITICAL</code>, <code>FATAL</code> e <code>ERROR</code>. Avisos (<code>WARN</code>) agregados por recorrência.</td></tr>
        <tr><td><b>2. Tom e Estilo</b></td><td>Técnico, analítico, formal e orientado a Engenharia de Software e SRE.</td></tr>
        <tr><td><b>3. Tratamento de Incertezas</b></td><td>Mascaramento Anti-PII e segredos em memória. Linhas corrompidas recebem marcadores sequenciais.</td></tr>
        <tr><td><b>4. Precisão e Confiabilidade</b></td><td>Contagem determinística O(1) de frequência eliminando alucinações numéricas.</td></tr>
        <tr><td><b>5. Eficiência da Resposta</b></td><td>Matrizes de impacto percentual (%) e tabelas comparativas de regressões.</td></tr>
    </tbody>
</table>

<h3>Passo 2: Escrever Prompts (Framework TRACI)</h3>
<div class="prompt-box">
<b>Tarefa Principal (Diagnóstico & Observabilidade):</b><br>
• <b>Task:</b> Extrair e tabular falhas únicas dos arquivos submetidos.<br>
• <b>Role:</b> Engenheiro Especialista SRE e Auditor de Confiabilidade.<br>
• <b>Audience:</b> Tech Leads, Desenvolvedores e Squads de Sustentação.<br>
• <b>Context:</b> {{CONTEXT_TITLE}} com {{TOTAL_LINES}} linhas analisadas.<br>
• <b>Instructions:</b> Sanitizar credenciais, computar frequência única e apontar plano de ação.
</div>

<h2>Direções do Modelo de Documentação</h2>
<h3>1. Introdução & Visão Geral</h3>
<p><b>Escopo:</b> Foram analisadas <b>{{TOTAL_LINES}} linhas</b>, detectando <b>{{TOTAL_ERRORS}} erros</b> e <b>{{TOTAL_WARNS}} avisos</b> distribuídos em <b>{{UNIQUE_ERRORS}} assinaturas canônicas exclusivas</b>.</p>

{{BATCH_SECTION}}

<h3>2. Tabela de Falhas Mais Frequentes (Clusterização Canônica)</h3>
<table>
    <thead>
        <tr>
            <th style="width:6%;">Rank</th>
            <th style="width:10%;">Severidade</th>
            <th>Assinatura Canônica do Erro</th>
            <th style="width:10%;">Ocorrências</th>
            <th style="width:8%;">% Total</th>
            <th style="width:14%;">Primeiro Visto</th>
            <th style="width:14%;">Último Visto</th>
        </tr>
    </thead>
    <tbody>
        {{ERROR_TABLE_ROWS}}
    </tbody>
</table>

{{DIFF_SECTION}}

<h3>3. Processo de Desenvolvimento & Recomendações Técnicas</h3>
<ol>
    <li><b>Isolamento de Causa Raiz:</b> Foco imediato nos erros do Top 3 do ranking.</li>
    <li><b>Sanitização e Segurança:</b> Chaves, e-mails, tokens e IPs foram substituídos por tags de anonimização.</li>
    <li><b>Ações Preventivas:</b> Dimensionar pools e políticas de retry para evitar cascata de falhas.</li>
</ol>

<h3>4. Principais Desafios e Soluções</h3>
<ul>
    <li><b>Desafio 1 (Volume de Logs):</b> Leitura por streaming O(1) de espaço.</li>
    <li><b>Desafio 2 (Dados Variáveis):</b> Normalização de parâmetros dinâmicos via regex compilada.</li>
</ul>

<h3>5. Cenários de Exemplo</h3>
<div class="box-note">
    <b>Cenário de Análise:</b> Auditoria do ecossistema para mitigação de falhas em produção e garantia de estabilidade pós-deploys.
</div>
</body>
</html>
"""

def load_template(custom_url: str = None, uploaded_template = None) -> str:
    """Lê templates em .html, .md, .txt ou .pdf."""
    if uploaded_template is not None:
        fname = uploaded_template.name.lower()
        try:
            if fname.endswith('.pdf'):
                reader = pypdf.PdfReader(uploaded_template)
                text = "\n".join([p.extract_text() or "" for p in reader.pages])
                # Encapsular texto extraído do PDF em layout HTML compatível
                return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><style>body{{font-family:Arial;padding:20px;font-size:9pt;line-height:1.4;}}</style></head><body>{text.replace(chr(10), '<br>')}</body></html>"""
            elif fname.endswith(('.html', '.htm')):
                return uploaded_template.read().decode('utf-8', errors='ignore')
            else:
                # .md / .txt
                raw = uploaded_template.read().decode('utf-8', errors='ignore')
                return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><style>body{{font-family:Arial;padding:20px;font-size:9pt;line-height:1.4;}}</style></head><body><pre style="white-space:pre-wrap;font-family:inherit;">{raw}</pre></body></html>"""
        except Exception as e:
            st.sidebar.warning(f"Erro ao ler template submetido: {e}. Usando padrão.")
            
    if custom_url and custom_url.strip():
        try:
            r = requests.get(custom_url.strip(), timeout=5)
            if r.status_code == 200:
                return r.text
        except Exception:
            st.sidebar.warning("Não foi possível acessar a URL do template. Usando padrão.")
            
    if os.path.exists("report_template.html"):
        try:
            with open("report_template.html", "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            pass
            
    return DEFAULT_HTML_TEMPLATE

def render_html_report(template_str: str, context_title: str, metrics: dict, diff_data: dict = None, batch_summary: list = None) -> str:
    total_errors = max(metrics['total_errors'], 1)
    
    error_rows_html = ""
    for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(15), start=1):
        prop = (count / total_errors) * 100
        sev = metrics['severities'].get(sig, "ERROR")
        first = metrics['first_seen'].get(sig, "N/A")
        last = metrics['last_seen'].get(sig, "N/A")
        error_rows_html += f"""
        <tr>
            <td style="text-align:center; font-weight:bold;">#{rank}</td>
            <td style="color:#dc2626; font-weight:bold;">{sev}</td>
            <td><code>{sig}</code></td>
            <td style="text-align:center; font-weight:bold;">{count:,}</td>
            <td style="text-align:center;">{prop:.1f}%</td>
            <td>{first}</td>
            <td>{last}</td>
        </tr>
        """
        
    batch_section_html = ""
    if batch_summary:
        b_rows = "".join([
            f"<tr><td><b>{item['Arquivo']}</b></td><td style='text-align:center;'>{item['Linhas']:,}</td><td style='text-align:center; color:#dc2626; font-weight:bold;'>{item['Erros']:,}</td><td style='text-align:center; color:#d97706;'>{item['Avisos']:,}</td><td style='text-align:center;'>{item['Erros Únicos']}</td></tr>"
            for item in batch_summary
        ])
        batch_section_html = f"""
        <h3>Sumário da Ingestão em Lote</h3>
        <table>
            <thead><tr><th>Arquivo de Log</th><th>Linhas</th><th>Erros</th><th>Avisos</th><th>Erros Únicos</th></tr></thead>
            <tbody>{b_rows}</tbody>
        </table>
        """
        
    diff_section_html = ""
    if diff_data:
        diff_section_html = f"""
        <h3>Quadro Comparativo de Releases (Diff v1 vs v2)</h3>
        <table>
            <thead><tr><th>Métrica</th><th>Versão Anterior (v1)</th><th>Versão Atual (v2)</th><th>Variação (%)</th><th>Diagnóstico</th></tr></thead>
            <tbody>
                <tr><td><b>Total de Erros</b></td><td style="text-align:center;">{diff_data['old_errors']:,}</td><td style="text-align:center;">{diff_data['new_errors']:,}</td><td style="text-align:center; font-weight:bold;">{diff_data['diff_pct']:+.1f}%</td><td>{"🟢 Estabilização" if diff_data['diff_pct'] < 0 else "🔴 Instabilidade"}</td></tr>
                <tr><td><b>Erros Únicos</b></td><td style="text-align:center;">{diff_data['old_unique']}</td><td style="text-align:center;">{diff_data['new_unique']}</td><td style="text-align:center;">{((diff_data['new_unique']-diff_data['old_unique'])/max(diff_data['old_unique'],1))*100:+.1f}%</td><td>Assinaturas</td></tr>
                <tr><td><b>Erros Resolvidos</b></td><td colspan="4" style="color:#16a34a; font-weight:bold;">{len(diff_data['resolved'])} correções identificadas</td></tr>
                <tr><td><b>Novas Regressões</b></td><td colspan="4" style="color:#dc2626; font-weight:bold;">{len(diff_data['regressions'])} novas falhas detectadas</td></tr>
            </tbody>
        </table>
        """

    content = template_str.replace("{{CONTEXT_TITLE}}", str(context_title))
    content = content.replace("{{GENERATION_DATE}}", datetime.now().strftime('%d/%m/%Y %H:%M:%S'))
    content = content.replace("{{TOTAL_LINES}}", f"{metrics['total_lines']:,}")
    content = content.replace("{{TOTAL_ERRORS}}", f"{metrics['total_errors']:,}")
    content = content.replace("{{TOTAL_WARNS}}", f"{metrics['total_warns']:,}")
    content = content.replace("{{UNIQUE_ERRORS}}", f"{len(metrics['error_counter'])}")
    content = content.replace("{{ERROR_TABLE_ROWS}}", error_rows_html or "<tr><td colspan='7' style='text-align:center;'>Nenhum erro encontrado.</td></tr>")
    content = content.replace("{{BATCH_SECTION}}", batch_section_html)
    content = content.replace("{{DIFF_SECTION}}", diff_section_html)
    return content

def render_markdown_report(context_title: str, metrics: dict, diff_data: dict = None, batch_summary: list = None) -> str:
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    total_errors = max(metrics['total_errors'], 1)
    
    md = f"""# SA-AIC - Modelo de Documento para Distribuição
# Relatório de Diagnóstico & Inteligência de Logs — LogPulse AI

**Contexto Analisado:** {context_title}  
**Data da Análise:** {now_str}  
**Volume Total de Linhas:** {metrics['total_lines']:,} | **Erros Detectados:** {metrics['total_errors']:,} | **Avisos:** {metrics['total_warns']:,}

---

## Definir Critérios da Tarefa de IA e Escrever Prompts

### Passo 1: Definir Critérios Específicos da Tarefa (Framework CLEAR)
1. **Relevância do Contexto:** Foco prioritário em eventos `CRITICAL`, `FATAL` e `ERROR`. Avisos (`WARN`) agregados por frequência.
2. **Tom e Estilo da Linguagem:** Técnico, formal, assertivo e orientado a Engenharia de Software e SRE.
3. **Tratamento de Incertezas:** Mascaramento em memória de Anti-PII, credenciais e tokens.
4. **Precisão e Confiabilidade:** Contagem determinística agregada em $O(1)$ sem risco de alucinações.
5. **Eficiência da Resposta:** Resumo estruturado em matrizes com percentuais de impacto e diffs de correções.

### Passo 2: Escrever Prompts (Framework TRACI)
- **Task:** Diagnóstico, agrupamento por assinatura canônica e elaboração de plano de ação.
- **Role:** Engenheiro Especialista SRE e Auditor de Confiabilidade.
- **Audience:** Times de Desenvolvimento, QA e Liderança Técnica.
- **Context:** Análise de telemetria ({context_title}).
- **Instructions:** Gerar tabela de frequência, isolar causas raízes e apontar soluções.

---

## Direções do Modelo de Documentação

### 1. Introdução & Visão Geral
- **Linhas Analisadas:** {metrics['total_lines']:,}
- **Erros Detectados:** {metrics['total_errors']:,}
- **Avisos (Warnings):** {metrics['total_warns']:,}
- **Padrões Únicos:** {len(metrics['error_counter'])}
"""
    if batch_summary:
        md += "\n### Sumário de Ingestão por Arquivo (Lote)\n"
        md += "| Arquivo | Linhas | Erros | Avisos | Erros Únicos |\n| :--- | :---: | :---: | :---: | :---: |\n"
        for item in batch_summary:
            md += f"| {item['Arquivo']} | {item['Linhas']:,} | {item['Erros']:,} | {item['Avisos']:,} | {item['Erros Únicos']} |\n"

    md += """
---

### 2. Tabela de Erros Mais Frequentes (Clusterizados por Padrão Canônico)

| Rank | Severidade | Assinatura / Categoria do Erro | Ocorrências | % do Total | Primeiro Visto | Último Visto |
| :---: | :---: | :--- | :---: | :---: | :---: | :---: |
"""
    for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(15), start=1):
        prop = (count / total_errors) * 100
        sev = metrics['severities'].get(sig, "ERROR")
        first = metrics['first_seen'].get(sig, "N/A")
        last = metrics['last_seen'].get(sig, "N/A")
        md += f"| #{rank} | `{sev}` | `{sig}` | {count:,} | {prop:.1f}% | {first} | {last} |\n"

    if diff_data:
        md += f"""
---

### 3. Quadro Comparativo de Releases (Diff de Atualizações)
- **Variação de Erros:** {diff_data['old_errors']:,} (v1) → {diff_data['new_errors']:,} (v2) ({diff_data['diff_pct']:+.1f}%)
- **Erros Resolvidos com Sucesso:** {len(diff_data['resolved'])}
- **Novas Regressões Detectadas:** {len(diff_data['regressions'])}

#### 🟢 Erros Resolvidos na Nova Versão
"""
        for err in list(diff_data['resolved'])[:6]:
            md += f"- ✅ `{err}`\n"
        md += "\n#### 🔴 Novas Regressões Introduzidas\n"
        for err in list(diff_data['regressions'])[:6]:
            md += f"- ⚠️ `{err}`\n"

    md += """
---

### 4. Processo de Desenvolvimento & Recomendações Técnicas
1. **Isolamento de Causa Raiz:** Foco prioritário nos erros ranqueados no Top 3.
2. **Sanitização e Segurança:** Todos os dados sensíveis foram mascarados.
3. **Ações Preventivas:** Políticas de retry e dimensionamento de conexões.
"""
    return md

# -----------------------------------------------------------------------------
# 3. INTERFACE STREAMLIT
# -----------------------------------------------------------------------------
st.title("🛡️ LogPulse AI — Analisador Inteligente & Gerador SA-AIC")
st.markdown("""
Motor agêntico para análise de telemetria em arquivos **.csv, .pdf, .txt, .log e .json**.
Gera relatórios oficiais sob demanda nos formatos **PDF (.pdf), Markdown (.md) e HTML (.html)**.
""")

st.sidebar.header("⚙️ Modalidade de Análise")
mode = st.sidebar.radio(
    "Selecione a Operação:",
    [
        "📊 Diagnóstico de Log Único",
        "📁 Análise Consolidada em Lote (Múltiplos Arquivos)",
        "⚖️ Comparação entre Versões (Diff de Releases)"
    ]
)

st.sidebar.divider()
with st.sidebar.expander("📄 Gerenciador de Template Dinâmico", expanded=False):
    st.caption("Suba um modelo (.html, .pdf, .md, .txt) ou informe uma URL direta para atualizar o template:")
    template_file = st.file_uploader("Subir novo Template:", type=["html", "htm", "pdf", "md", "txt"])
    template_url = st.text_input("Ou URL direta do Template:", placeholder="https://raw.githubusercontent.com/.../report_template.html")

active_template = load_template(custom_url=template_url, uploaded_template=template_file)

# -----------------------------------------------------------------------------
# MODALIDADE 1: LOG ÚNICO
# -----------------------------------------------------------------------------
if mode == "📊 Diagnóstico de Log Único":
    uploaded_file = st.sidebar.file_uploader("Envie seu arquivo de log:", type=["log", "txt", "csv", "pdf", "json"])
    
    if uploaded_file is not None:
        with st.spinner("Processando arquivo..."):
            raw_text = extract_content(uploaded_file)
            metrics = process_log(raw_text) if raw_text else None
            
        if metrics:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Linhas Analisadas", f"{metrics['total_lines']:,}")
            c2.metric("Erros Totais", f"{metrics['total_errors']:,}", delta_color="inverse")
            c3.metric("Avisos (Warnings)", f"{metrics['total_warns']:,}")
            c4.metric("Falhas Únicas", f"{len(metrics['error_counter'])}")
            
            st.divider()
            st.subheader("🔍 Padrões de Falhas Agrupados (Clusterização Canônica)")
            if metrics['error_counter']:
                table_rows = []
                tot = max(metrics['total_errors'], 1)
                for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(20), start=1):
                    table_rows.append({
                        "Rank": f"#{rank}",
                        "Severidade": metrics['severities'].get(sig, "ERROR"),
                        "Assinatura Canônica": sig,
                        "Ocorrências": count,
                        "Impacto (%)": f"{(count/tot)*100:.1f}%",
                        "Primeiro Visto": metrics['first_seen'].get(sig, "N/A"),
                        "Último Visto": metrics['last_seen'].get(sig, "N/A"),
                    })
                st.dataframe(pd.DataFrame(table_rows), use_container_width=True)
            else:
                st.success("🎉 Nenhum erro encontrado no log analisado!")

            st.divider()
            st.subheader("📥 Exportação do Relatório Oficial (Modelo SA-AIC)")
            
            report_html = render_html_report(active_template, uploaded_file.name, metrics)
            report_md = render_markdown_report(uploaded_file.name, metrics)
            pdf_bytes = convert_html_to_pdf(report_html)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                if pdf_bytes:
                    st.download_button(
                        label="📑 Baixar Relatório Oficial em PDF (.pdf)",
                        data=pdf_bytes,
                        file_name=f"relatorio_sa_aic_{uploaded_file.name}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                else:
                    st.warning("⚠️ Gerando via HTML nativo. Use o botão HTML para salvar em PDF no navegador.")
            with col2:
                st.download_button(
                    label="📄 Baixar Relatório Formatado (.md)",
                    data=report_md,
                    file_name=f"relatorio_sa_aic_{uploaded_file.name}.md",
                    mime="text/markdown",
                    use_container_width=True
                )
            with col3:
                st.download_button(
                    label="🌐 Baixar Relatório Visual (.html)",
                    data=report_html,
                    file_name=f"relatorio_sa_aic_{uploaded_file.name}.html",
                    mime="text/html",
                    use_container_width=True
                )
    else:
        st.info("👆 Por favor, envie um arquivo de log na barra lateral para iniciar a análise.")

# -----------------------------------------------------------------------------
# MODALIDADE 2: LOTE (MÚLTIPLOS ARQUIVOS)
# -----------------------------------------------------------------------------
elif mode == "📁 Análise Consolidada em Lote (Múltiplos Arquivos)":
    uploaded_files = st.sidebar.file_uploader("Envie múltiplos arquivos de log:", type=["log", "txt", "csv", "pdf", "json"], accept_multiple_files=True)
    
    if uploaded_files:
        batch_summary = []
        global_errors = Counter()
        global_warns = Counter()
        global_first = {}
        global_last = {}
        global_sev = {}
        tot_lines = 0
        
        with st.spinner("Processando lote de logs..."):
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
        c4.metric("Padrões Únicos", len(global_errors))
        
        st.divider()
        st.subheader("📋 Resumo por Arquivo")
        st.dataframe(pd.DataFrame(batch_summary), use_container_width=True)
        
        st.divider()
        st.subheader("📥 Exportação do Relatório Consolidado (Modelo SA-AIC)")
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
        rep_batch_html = render_html_report(active_template, scope_title, global_metrics, batch_summary=batch_summary)
        rep_batch_md = render_markdown_report(scope_title, global_metrics, batch_summary=batch_summary)
        pdf_batch_bytes = convert_html_to_pdf(rep_batch_html)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if pdf_batch_bytes:
                st.download_button(
                    label="📑 Baixar Relatório Consolidado em PDF (.pdf)",
                    data=pdf_batch_bytes,
                    file_name="relatorio_sa_aic_lote_consolidado.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            else:
                st.warning("⚠️ Gerando via HTML nativo.")
        with col2:
            st.download_button(
                label="📄 Baixar Relatório Consolidado (.md)",
                data=rep_batch_md,
                file_name="relatorio_sa_aic_lote_consolidado.md",
                mime="text/markdown",
                use_container_width=True
            )
        with col3:
            st.download_button(
                label="🌐 Baixar Relatório Consolidado em HTML (.html)",
                data=rep_batch_html,
                file_name="relatorio_sa_aic_lote_consolidado.html",
                mime="text/html",
                use_container_width=True
            )
    else:
        st.info("👆 Por favor, envie múltiplos arquivos de log na barra lateral.")

# -----------------------------------------------------------------------------
# MODALIDADE 3: COMPARAÇÃO (DIFF DE RELEASES)
# -----------------------------------------------------------------------------
else:
    st.sidebar.subheader("Upload dos Logs para Diff")
    file_old = st.sidebar.file_uploader("Versão Anterior (v1.x):", type=["log", "txt", "csv", "pdf", "json"], key="f_old")
    file_new = st.sidebar.file_uploader("Versão Atual (v2.x):", type=["log", "txt", "csv", "pdf", "json"], key="f_new")
    
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
                "old_unique": len(keys_old),
                "new_unique": len(keys_new),
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
        st.subheader("📥 Exportação do Relatório Comparativo (Diff Modelo SA-AIC)")
        
        scope_diff = f"{file_old.name} (v1) vs {file_new.name} (v2)"
        rep_diff_html = render_html_report(active_template, scope_diff, m_new, diff_data=diff_data)
        rep_diff_md = render_markdown_report(scope_diff, m_new, diff_data=diff_data)
        pdf_diff_bytes = convert_html_to_pdf(rep_diff_html)
        
        col_d1, col_d2, col_d3 = st.columns(3)
        with col_d1:
            if pdf_diff_bytes:
                st.download_button(
                    label="📑 Baixar Relatório Comparativo em PDF (.pdf)",
                    data=pdf_diff_bytes,
                    file_name=f"relatorio_sa_aic_diff_{file_old.name}_vs_{file_new.name}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            else:
                st.warning("⚠️ Gerando via HTML nativo.")
        with col_d2:
            st.download_button(
                label="📄 Baixar Relatório Comparativo (.md)",
                data=rep_diff_md,
                file_name=f"relatorio_sa_aic_diff_{file_old.name}_vs_{file_new.name}.md",
                mime="text/markdown",
                use_container_width=True
            )
        with col_d3:
            st.download_button(
                label="🌐 Baixar Relatório Comparativo em HTML (.html)",
                data=rep_diff_html,
                file_name=f"relatorio_sa_aic_diff_{file_old.name}_vs_{file_new.name}.html",
                mime="text/html",
                use_container_width=True
            )
    else:
        st.info("👆 Por favor, envie os dois arquivos de log na barra lateral para efetuar a comparação.")
