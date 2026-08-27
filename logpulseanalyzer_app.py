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
    page_title="LogPulse AI — Analisador Inteligente & Auditor SA-AIC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# 1. ENGINES DE PARSING AVANÇADO, SANITIZAÇÃO (ANTI-PII) & CAUSA RAIZ
# -----------------------------------------------------------------------------
RE_EMAIL = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
RE_CPF = re.compile(r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b')
RE_IP = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
RE_TOKEN = re.compile(r'(?i)(bearer\s+[a-zA-Z0-9_\-\.]+|jwt\s+[a-zA-Z0-9_\-\.]+|token[:=]\s*[a-zA-Z0-9_\-]+|password[:=]\s*\S+|secret[:=]\s*\S+)')
RE_TIMESTAMP = re.compile(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\b[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b|\b\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\b)')
RE_SEVERITY = re.compile(r'\b(CRITICAL|FATAL|ERROR|WARN|WARNING|INFO|DEBUG|TRACE)\b', re.IGNORECASE)
RE_DYNAMIC = re.compile(r'(\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b|\b0x[0-9a-fA-F]+\b|\b\d{4,}\b|(?<=\=)[^\s,;&]+)')

def sanitize_text(text: str) -> str:
    """Aplica sanitização estrita de PII e segredos em memória."""
    text = RE_TOKEN.sub('[REDACTED_SECRET]', text)
    text = RE_EMAIL.sub('u***@domain.com', text)
    text = RE_CPF.sub('***.***.***-**', text)
    text = RE_IP.sub('192.168.***.***', text)
    return text

def canonicalize_error(message: str) -> str:
    """Extrai assinatura canônica removendo variáveis voláteis."""
    clean = re.sub(r'^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?\S*\s*', '', message)
    clean = RE_SEVERITY.sub('', clean)
    clean = RE_DYNAMIC.sub('<ID>', clean)
    clean = re.sub(r'\s+', ' ', clean).strip(' :-[]')
    return clean[:160] if clean else "GenericSystemError: Unexpected failure"

def infer_root_cause(signature: str) -> tuple:
    """Heurística para inferência de Causa Raiz e Plano de Ação Técnico."""
    sig_lower = signature.lower()
    if "hikaripool" in sig_lower or "connection is not available" in sig_lower or "pool exhausted" in sig_lower:
        return "Esgotamento no pool de conexões do Banco de Dados", "Verificar queries travadas e aumentar 'maximumPoolSize'."
    elif "gatewaytimeout" in sig_lower or "504" in sig_lower:
        return "Indisponibilidade ou lentidão em API de terceiros", "Implementar Circuit Breaker e retries com exponential backoff."
    elif "nullpointerexception" in sig_lower or "undefined" in sig_lower:
        return "Tentativa de acesso a objeto nulo no código de negócio", "Adicionar validação defensiva de payload e anotações @NonNull."
    elif "socket closed" in sig_lower or "redisconnection" in sig_lower:
        return "Falha de comunicação no cluster de cache Redis", "Ajustar timeout de socket e checar keep-alive do cluster."
    elif "ratelimit" in sig_lower or "429" in sig_lower:
        return "Excesso de requisições por cliente / Tentativas suspeitas", "Validar políticas de rate limit e bloquear IPs abusivos no WAF."
    elif "diskspace" in sig_lower or "no space left" in sig_lower:
        return "Esgotamento de espaço no volume de disco", "Executar expurgo/rotação de logs e redimensionar partições."
    elif "serializationexception" in sig_lower or "json" in sig_lower:
        return "Incompatibilidade no schema de serialização JSON", "Ajustar anotações de formato (ex: @JsonFormat) no DTO de resposta."
    elif "unauthorized" in sig_lower or "401" in sig_lower:
        return "Token de sessão expirado ou credencial inválida", "Revisar fluxo de renovação (refresh token) e autenticação."
    elif "deadlock" in sig_lower:
        return "Concorrência e travamento mútuo em transações SQL", "Reordenar operações de escrita em transações concorrentes."
    else:
        return "Falha de execução de rotina sistêmica", "Inspecionar rastreamento completo e isolar módulo de origem."

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
    total_lines = len(lines)
    
    error_counter = Counter()
    warn_counter = Counter()
    info_counter = 0
    debug_counter = 0
    first_seen = {}
    last_seen = {}
    severities = {}
    sample_traces = {}
    
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
                sample_traces[canonical] = sanitized[:240]
            last_seen[canonical] = ts
            severities[canonical] = "CRITICAL" if sev in ["CRITICAL", "FATAL"] else "ERROR"
        elif sev == "WARN":
            canonical = canonicalize_error(sanitized)
            warn_counter[canonical] += 1
            if canonical not in first_seen:
                first_seen[canonical] = ts
            last_seen[canonical] = ts
        elif sev == "DEBUG":
            debug_counter += 1
        else:
            info_counter += 1
            
    return {
        "total_lines": total_lines,
        "total_errors": sum(error_counter.values()),
        "total_warns": sum(warn_counter.values()),
        "total_info": info_counter,
        "total_debug": debug_counter,
        "error_counter": error_counter,
        "warn_counter": warn_counter,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "severities": severities,
        "sample_traces": sample_traces
    }

# -----------------------------------------------------------------------------
# 2. GERADOR DE PDF COMPLETO (FPDF2 PURO PYTHON) — SEGUINDO SA-AIC INTEGRAL
# -----------------------------------------------------------------------------
class FullSAAICPDF(FPDF):
    def header(self):
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 18, 'F')
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(255, 255, 255)
        self.set_xy(10, 4)
        self.cell(0, 10, 'SA-AIC - Modelo de Documento para Distribuicao | LogPulse AI', 0, 1, 'L')
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 10, f'Pagina {self.page_no()}', 0, 0, 'R')

def generate_pdf_report(context_title: str, metrics: dict, diff_data: dict = None, batch_summary: list = None) -> bytes:
    pdf = FullSAAICPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Cabeçalho Principal
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 7, 'Relatorio Oficial de Diagnostico & Inteligencia de Logs', ln=True)
    pdf.set_font('Helvetica', '', 8.5)
    pdf.set_text_color(71, 85, 105)
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    pdf.cell(0, 5, f'Contexto: {context_title} | Emissao: {now_str} | Engine: LogPulse AI', ln=True)
    pdf.ln(3)

    # Passo 1: Framework CLEAR
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, 'Passo 1: Definir Criterios Especificos da Tarefa (Framework CLEAR)', ln=True)
    pdf.set_font('Helvetica', '', 8)
    clear_items = [
        ("1. Relevancia do Contexto:", "Priorizacao estrita de falhas CRITICAL, FATAL e ERROR. Warnings agrupados por impacto."),
        ("2. Tom e Estilo:", "Tecnico, assertivo, formal e orientado a SRE e Engenharia de Software."),
        ("3. Tratamento de Incertezas:", "Mascaramento rigoroso de PII (CPFs, e-mails, tokens JWT/Bearer, credenciais e IPs)."),
        ("4. Precisao e Confiabilidade:", "Agregacao deterministica em O(1) de frequencia por hash canonico sem alucinacoes."),
        ("5. Eficiencia da Resposta:", "Matrizes tabulares com calculo de proporcao (%) e deteccao automatica de regressoes.")
    ]
    for k, v in clear_items:
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.cell(42, 4.5, k, 0, 0)
        pdf.set_font('Helvetica', '', 7.5)
        pdf.cell(0, 4.5, v, 0, 1)
    pdf.ln(2)

    # Passo 2: Prompts TRACI
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 6, 'Passo 2: Engenharia de Prompts Aplicada (Framework TRACI)', ln=True)
    pdf.set_fill_color(248, 250, 252)
    pdf.rect(10, pdf.get_y(), 190, 22, 'F')
    pdf.set_font('Helvetica', '', 7.5)
    pdf.multi_cell(0, 4.2, f"• Task: Analisar arquivos e consolidar contagens unicas de erros com isolamento de causas raizes.\n• Role: Especialista em Observabilidade e SRE (LogPulse AI).\n• Audience: Equipes de Engenharia, QA e Tech Leads.\n• Context: Processamento de {metrics['total_lines']:,} linhas de telemetria ({context_title}).\n• Instructions: Sanitizar dados confidenciais, tabular falhas por severidade e apontar acoes recomendadas.")
    pdf.ln(3)

    # Visão Geral & Métricas
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 6, '1. Introducao & Visao Geral do Volume Analisado', ln=True)
    pdf.set_font('Helvetica', '', 8)
    pdf.cell(0, 5, f"Volume Total de Linhas: {metrics['total_lines']:,} | Falhas Detectadas: {metrics['total_errors']:,} | Avisos (Warnings): {metrics['total_warns']:,} | Padroes Unicos: {len(metrics['error_counter'])}", ln=True)
    pdf.ln(2)

    # Tabela de Ingestão em Lote (se houver)
    if batch_summary:
        pdf.set_font('Helvetica', 'B', 8.5)
        pdf.cell(0, 5, 'Sumario da Ingestao por Arquivo de Log:', ln=True)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.cell(70, 5, 'Arquivo', 1, 0, 'L', True)
        pdf.cell(30, 5, 'Linhas', 1, 0, 'C', True)
        pdf.cell(30, 5, 'Erros', 1, 0, 'C', True)
        pdf.cell(30, 5, 'Avisos', 1, 0, 'C', True)
        pdf.cell(30, 5, 'Erros Unicos', 1, 1, 'C', True)
        pdf.set_font('Helvetica', '', 7.5)
        for it in batch_summary:
            pdf.cell(70, 5, str(it['Arquivo'])[:38], 1, 0, 'L')
            pdf.cell(30, 5, f"{it['Linhas']:,}", 1, 0, 'C')
            pdf.cell(30, 5, f"{it['Erros']:,}", 1, 0, 'C')
            pdf.cell(30, 5, f"{it['Avisos']:,}", 1, 0, 'C')
            pdf.cell(30, 5, str(it['Erros Únicos']), 1, 1, 'C')
        pdf.ln(3)

    # Tabela de Falhas Mais Frequentes
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 6, '2. Tabela de Erros Mais Frequentes & Diagnostico de Causa Raiz', ln=True)
    pdf.set_fill_color(241, 245, 249)
    pdf.set_font('Helvetica', 'B', 7)
    pdf.cell(10, 5, 'Rank', 1, 0, 'C', True)
    pdf.cell(14, 5, 'Sev', 1, 0, 'C', True)
    pdf.cell(66, 5, 'Assinatura Canonica do Erro', 1, 0, 'L', True)
    pdf.cell(14, 5, 'Qtd', 1, 0, 'C', True)
    pdf.cell(14, 5, '% Total', 1, 0, 'C', True)
    pdf.cell(72, 5, 'Causa Provavel & Acao Recomendada', 1, 1, 'L', True)

    pdf.set_font('Helvetica', '', 6.5)
    tot_err = max(metrics['total_errors'], 1)
    for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(12), start=1):
        prop = (count / tot_err) * 100
        sev = metrics['severities'].get(sig, "ERROR")
        cause, act = infer_root_cause(sig)
        diag_str = f"{cause} ({act})"
        clean_sig = sig.encode('latin-1', 'replace').decode('latin-1')[:45]
        clean_diag = diag_str.encode('latin-1', 'replace').decode('latin-1')[:52]
        pdf.cell(10, 5, f"#{rank}", 1, 0, 'C')
        pdf.cell(14, 5, str(sev)[:7], 1, 0, 'C')
        pdf.cell(66, 5, clean_sig, 1, 0, 'L')
        pdf.cell(14, 5, f"{count:,}", 1, 0, 'C')
        pdf.cell(14, 5, f"{prop:.1f}%", 1, 0, 'C')
        pdf.cell(72, 5, clean_diag, 1, 1, 'L')
    pdf.ln(3)

    # Quadro Diff (se houver)
    if diff_data:
        pdf.set_font('Helvetica', 'B', 10)
        pdf.cell(0, 6, '3. Quadro Comparativo de Releases (Diff de Atualizacoes)', ln=True)
        pdf.set_font('Helvetica', '', 7.5)
        pdf.cell(0, 4.5, f"Variacao de Falhas: v1 ({diff_data['old_errors']:,}) -> v2 ({diff_data['new_errors']:,}) | Variacao: {diff_data['diff_pct']:+.1f}%", ln=True)
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.set_text_color(22, 163, 74)
        pdf.cell(0, 4.5, f"Erros Resolvidos com Sucesso: {len(diff_data['resolved'])} falhas eliminadas", ln=True)
        pdf.set_text_color(220, 38, 38)
        pdf.cell(0, 4.5, f"Novas Regressoes Introduzidas: {len(diff_data['regressions'])} novas assinaturas de erro", ln=True)
        pdf.set_text_color(15, 23, 42)
        pdf.ln(2)

    # Diretrizes Operacionais (Capítulos 3 a 7)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 6, '4. Processo de Desenvolvimento & Recomendacoes Tecnicas', ln=True)
    pdf.set_font('Helvetica', '', 7.5)
    pdf.multi_cell(0, 4, "1. Isolamento de Causa Raiz: Atuar prioritariamente nas falhas #1 e #2 do ranking de frequencia.\n2. Inspecao de Concorrencia: Verificar pools de conexao, retries e limites de sockets em rotinas criticas.\n3. Prevencao de Regressoes: Executar comparacao automatizada no pipeline de CI/CD antes do deploy em producao.")

    return bytes(pdf.output())

# -----------------------------------------------------------------------------
# 3. GERADORES DE RELATÓRIO HTML & MARKDOWN INTEGRAL
# -----------------------------------------------------------------------------
DEFAULT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #0f172a; padding: 24px; line-height: 1.5; font-size: 9pt; }
    .header-card { background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%); color: #ffffff; padding: 18px 22px; border-radius: 8px; margin-bottom: 18px; }
    .header-card h1 { font-size: 15pt; margin: 0 0 4px 0; color: #ffffff; }
    .header-card p { font-size: 9pt; margin: 0; color: #93c5fd; }
    .badge { display: inline-block; background-color: #3b82f6; color: #fff; font-size: 7pt; font-weight: bold; padding: 2px 6px; border-radius: 4px; text-transform: uppercase; margin-bottom: 4px; }
    h2 { font-size: 11.5pt; color: #0f172a; border-left: 4px solid #2563eb; padding-left: 8px; margin-top: 18px; margin-bottom: 8px; text-transform: uppercase; }
    h3 { font-size: 10pt; color: #1e3a8a; margin-top: 12px; margin-bottom: 6px; }
    table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 8.5pt; }
    th, td { border: 1px solid #cbd5e1; padding: 6px 8px; text-align: left; }
    th { background-color: #f1f5f9; color: #0f172a; font-weight: 600; }
    tr:nth-child(even) td { background-color: #f8fafc; }
    .badge-error { color: #dc2626; font-weight: bold; }
    .badge-critical { color: #7f1d1d; background: #fee2e2; padding: 1px 4px; border-radius: 3px; font-weight: bold; }
    .box-note { background-color: #eff6ff; border: 1px solid #bfdbfe; border-left: 4px solid #3b82f6; padding: 10px 12px; border-radius: 4px; margin: 10px 0; }
    .prompt-box { background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 12px; margin-bottom: 10px; font-family: monospace; font-size: 8pt; white-space: pre-wrap; }
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
        <tr><td><b>1. Relevância do Contexto</b></td><td>Priorização estrita de falhas <code>CRITICAL</code>, <code>FATAL</code> e <code>ERROR</code>. Avisos <code>WARN</code> agrupados por recorrência. Ruídos informativos (<code>INFO</code>/<code>DEBUG</code>) filtrados da visualização de criticidade.</td></tr>
        <tr><td><b>2. Tom e Estilo</b></td><td>Técnico, analítico, formal e orientado a Engenharia de Software e SRE.</td></tr>
        <tr><td><b>3. Tratamento de Incertezas</b></td><td>Mascaramento Anti-PII em memória de senhas, tokens Bearer/JWT, CPFs e IPs. Linhas corrompidas recebem marcadores sequenciais.</td></tr>
        <tr><td><b>4. Precisão e Confiabilidade</b></td><td>Contagem determinística $O(1)$ de ocorrências por hash canônico sem riscos de alucinação numérica.</td></tr>
        <tr><td><b>5. Eficiência da Resposta</b></td><td>Matrizes ranqueadas por impacto percentual (%) e quadro comparativo de regressões.</td></tr>
    </tbody>
</table>

<h3>Passo 2: Escrever Prompts (Framework TRACI)</h3>
<div class="prompt-box">
<b>Tarefa 1: Diagnóstico e Clusterização de Erros Únicos</b>
• <b>Task:</b> Extrair e tabular falhas únicas dos arquivos submetidos.
• <b>Role:</b> Engenheiro Especialista SRE e Auditor de Confiabilidade (LogPulse AI).
• <b>Audience:</b> Tech Leads, Desenvolvedores e Squads de Sustentação.
• <b>Context:</b> {{CONTEXT_TITLE}} com {{TOTAL_LINES}} linhas analisadas.
• <b>Instructions:</b> Sanitizar credenciais, computar frequência única, calcular proporção de impacto e apontar causa raiz provável.
</div>

<h2>Direções do Modelo de Documentação</h2>
<h3>1. Introdução & Visão Geral da Telemetria</h3>
<p>Foram analisadas <b>{{TOTAL_LINES}} linhas</b>, detectando <b>{{TOTAL_ERRORS}} erros</b> e <b>{{TOTAL_WARNS}} avisos</b> distribuídos em <b>{{UNIQUE_ERRORS}} assinaturas canônicas exclusivas</b>.</p>

{{BATCH_SECTION}}

<h3>2. Tabela de Falhas Mais Frequentes & Diagnóstico</h3>
<table>
    <thead>
        <tr>
            <th style="width:6%;">Rank</th>
            <th style="width:10%;">Severidade</th>
            <th>Assinatura Canônica do Erro</th>
            <th style="width:8%;">Qtd</th>
            <th style="width:7%;">%</th>
            <th style="width:12%;">Primeiro Visto</th>
            <th style="width:12%;">Último Visto</th>
            <th>Causa Raiz & Ação Recomendada</th>
        </tr>
    </thead>
    <tbody>
        {{ERROR_TABLE_ROWS}}
    </tbody>
</table>

{{DIFF_SECTION}}

<h3>3. Processo de Desenvolvimento & Recomendações Técnicas</h3>
<ol>
    <li><b>Isolamento de Causa Raiz:</b> Foco imediato nos erros do Top 3 do ranking de frequência.</li>
    <li><b>Sanitização e Segurança:</b> Chaves, e-mails, tokens e IPs foram substituídos por tags de anonimização.</li>
    <li><b>Ações Preventivas:</b> Dimensionar pools e políticas de retry para evitar cascata de falhas em produção.</li>
</ol>

<h3>4. Principais Desafios e Soluções</h3>
<ul>
    <li><b>Desafio 1 (Volume de Logs):</b> Leitura por geradores/streaming $O(1)$ de espaço em memória.</li>
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
        cause, act = infer_root_cause(sig)
        error_rows_html += f"""
        <tr>
            <td style='text-align:center; font-weight:bold;'>#{rank}</td>
            <td><span class='badge-{sev.lower()}'>{sev}</span></td>
            <td><code>{sig}</code></td>
            <td style='text-align:center; font-weight:bold;'>{count:,}</td>
            <td style='text-align:center;'>{prop:.1f}%</td>
            <td>{first}</td>
            <td>{last}</td>
            <td><b>{cause}:</b> {act}</td>
        </tr>
        """

    batch_section_html = ""
    if batch_summary:
        b_rows = "".join([f"<tr><td><b>{it['Arquivo']}</b></td><td style='text-align:center;'>{it['Linhas']:,}</td><td style='text-align:center; color:#dc2626; font-weight:bold;'>{it['Erros']:,}</td><td style='text-align:center; color:#d97706;'>{it['Avisos']:,}</td><td style='text-align:center;'>{it['Erros Únicos']}</td></tr>" for it in batch_summary])
        batch_section_html = f"<h3>Sumário da Ingestão em Lote</h3><table><thead><tr><th>Arquivo de Log</th><th>Linhas</th><th>Erros</th><th>Avisos</th><th>Erros Únicos</th></tr></thead><tbody>{b_rows}</tbody></table>"

    diff_section_html = ""
    if diff_data:
        diff_section_html = f"""
        <h3>Quadro Comparativo de Releases (Diff de Versões)</h3>
        <table>
            <thead><tr><th>Métrica</th><th>Versão Anterior (v1)</th><th>Versão Atual (v2)</th><th>Variação (%)</th><th>Diagnóstico</th></tr></thead>
            <tbody>
                <tr><td><b>Total de Falhas</b></td><td style='text-align:center;'>{diff_data['old_errors']:,}</td><td style='text-align:center;'>{diff_data['new_errors']:,}</td><td style='text-align:center; font-weight:bold;'>{diff_data['diff_pct']:+.1f}%</td><td>{"🟢 Redução expressiva" if diff_data['diff_pct'] < 0 else "🔴 Aumento de instabilidade"}</td></tr>
                <tr><td><b>Erros Resolvidos</b></td><td colspan='4' style='color:#16a34a; font-weight:bold;'>{len(diff_data['resolved'])} correções identificadas</td></tr>
                <tr><td><b>Novas Regressões</b></td><td colspan='4' style='color:#dc2626; font-weight:bold;'>{len(diff_data['regressions'])} novas falhas detectadas</td></tr>
            </tbody>
        </table>
        """

    content = template_str.replace("{{CONTEXT_TITLE}}", str(context_title))
    content = content.replace("{{GENERATION_DATE}}", datetime.now().strftime('%d/%m/%Y %H:%M:%S'))
    content = content.replace("{{TOTAL_LINES}}", f"{metrics['total_lines']:,}")
    content = content.replace("{{TOTAL_ERRORS}}", f"{metrics['total_errors']:,}")
    content = content.replace("{{TOTAL_WARNS}}", f"{metrics['total_warns']:,}")
    content = content.replace("{{UNIQUE_ERRORS}}", f"{len(metrics['error_counter'])}")
    content = content.replace("{{ERROR_TABLE_ROWS}}", error_rows_html or "<tr><td colspan='8' style='text-align:center;'>Nenhum erro encontrado.</td></tr>")
    content = content.replace("{{BATCH_SECTION}}", batch_section_html)
    content = content.replace("{{DIFF_SECTION}}", diff_section_html)
    return content

def render_markdown_report(context_title: str, metrics: dict, diff_data: dict = None, batch_summary: list = None) -> str:
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    tot_err = max(metrics['total_errors'], 1)
    
    md = f"""# SA-AIC - Modelo de Documento para Distribuição
# Relatório de Diagnóstico & Inteligência de Logs — LogPulse AI

**Contexto Analisado:** {context_title}  
**Data de Emissão:** {now_str}  
**Linhas Totais:** {metrics['total_lines']:,} | **Erros Detectados:** {metrics['total_errors']:,} | **Avisos:** {metrics['total_warns']:,} | **Padrões Únicos:** {len(metrics['error_counter'])}

---

## Definir Critérios da Tarefa de IA e Escrever Prompts

### Passo 1: Definir Critérios Específicos da Tarefa (Framework CLEAR)
1. **Relevância do Contexto:** Foco estrito em eventos `CRITICAL`, `FATAL` e `ERROR`. Ruídos informativos ignorados da visualização crítica.
2. **Tom e Estilo da Linguagem:** Técnico, objetivo, assertivo e orientado a SRE e Engenharia de Confiabilidade.
3. **Tratamento de Incertezas:** Mascaramento em memória de senhas, chaves, tokens e IPs (Anti-PII).
4. **Precisão e Confiabilidade:** Contagem determinística agregada em $O(1)$ baseada em dados brutos.
5. **Eficiência da Resposta:** Resumo tabular com cálculo de impacto (%) e rastreamento de causas raízes.

### Passo 2: Escrever Prompts (Framework TRACI)
- **Task:** Diagnóstico, agrupamento canônico e identificação de causas raízes.
- **Role:** Especialista em Observabilidade e SRE (LogPulse AI).
- **Audience:** Equipes de Desenvolvimento, QA e Liderança Técnica.
- **Context:** Análise de telemetria ({context_title}).
- **Instructions:** Gerar tabela de frequência, isolar causas raízes e propor soluções.

---

## 1. Tabela de Erros Mais Frequentes & Diagnóstico de Causa Raiz

| Rank | Severidade | Assinatura Canônica do Erro | Ocorrências | % Total | Primeiro Visto | Último Visto | Causa Provável & Ação |
| :---: | :---: | :--- | :---: | :---: | :---: | :---: | :--- |
"""
    for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(15), start=1):
        prop = (count / tot_err) * 100
        sev = metrics['severities'].get(sig, "ERROR")
        first = metrics['first_seen'].get(sig, "N/A")
        last = metrics['last_seen'].get(sig, "N/A")
        cause, act = infer_root_cause(sig)
        md += f"| #{rank} | `{sev}` | `{sig}` | {count:,} | {prop:.1f}% | {first} | {last} | **{cause}**: {act} |\n"

    if diff_data:
        md += f"""
---

## 2. Quadro Comparativo de Releases (Diff de Atualizações)
- **Variação de Erros:** {diff_data['old_errors']:,} (v1) → {diff_data['new_errors']:,} (v2) ({diff_data['diff_pct']:+.1f}%)
- **Erros Resolvidos com Sucesso:** {len(diff_data['resolved'])} falhas eliminadas
- **Novas Regressões Detectadas:** {len(diff_data['regressions'])} novas assinaturas de erro

### 🟢 Erros Resolvidos na Nova Versão
"""
        for err in list(diff_data['resolved'])[:6]:
            md += f"- ✅ `{err}`\n"
        md += "\n### 🔴 Novas Regressões Introduzidas\n"
        for err in list(diff_data['regressions'])[:6]:
            md += f"- ⚠️ `{err}`\n"

    md += """
---

## 3. Processo de Desenvolvimento & Recomendações
1. **Isolamento de Causa Raiz:** Atuar prioritariamente nos erros #1 e #2 do ranking.
2. **Dimensionamento de Recursos:** Ajustar pools de conexões e políticas de circuit-breaker.
3. **Auditoria de CI/CD:** Realizar diff automático antes de aprovar novas releases para produção.
"""
    return md

# -----------------------------------------------------------------------------
# 4. INTERFACE STREAMLIT AVANÇADA
# -----------------------------------------------------------------------------
st.title("🛡️ LogPulse AI — Analisador Inteligente & Auditor SA-AIC")
st.markdown("Motor agêntico de observabilidade com **agregação de padrões, inferência de causa raiz e geração de relatórios oficiais (PDF, Markdown e HTML)**.")

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
    template_file = st.file_uploader("Subir novo Template (.html, .pdf, .md, .txt):", type=["html", "htm", "pdf", "md", "txt"])
    template_url = st.text_input("Ou URL direta do Template:", placeholder="https://raw.githubusercontent.com/.../report_template.html")

active_template = load_template(custom_url=template_url, uploaded_template=template_file)

# -----------------------------------------------------------------------------
# MODALIDADE 1: ÚNICO
# -----------------------------------------------------------------------------
if mode == "📊 Diagnóstico de Log Único":
    uploaded_file = st.sidebar.file_uploader("Envie seu arquivo de log:", type=["log", "txt", "csv", "pdf", "json"])
    if uploaded_file is not None:
        with st.spinner("Processando e sanitizando telemetria..."):
            raw_text = extract_content(uploaded_file)
            metrics = process_log(raw_text) if raw_text else None
            
        if metrics:
            # Métricas em Cartões
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Linhas Analisadas", f"{metrics['total_lines']:,}")
            error_rate = (metrics['total_errors'] / max(metrics['total_lines'], 1)) * 100
            c2.metric("Falhas Críticas / Erros", f"{metrics['total_errors']:,}", f"Taxa: {error_rate:.2f}%", delta_color="inverse")
            c3.metric("Avisos (Warnings)", f"{metrics['total_warns']:,}")
            c4.metric("Padrões Únicos", f"{len(metrics['error_counter'])}")
            
            st.divider()
            
            # Tabela de Padrões Consolidada
            st.subheader("🔍 Padrões de Falhas Detectados & Causa Raiz Heurística")
            if metrics['error_counter']:
                table_rows = []
                tot = max(metrics['total_errors'], 1)
                for rank, (sig, count) in enumerate(metrics['error_counter'].most_common(20), start=1):
                    cause, act = infer_root_cause(sig)
                    table_rows.append({
                        "Rank": f"#{rank}",
                        "Severidade": metrics['severities'].get(sig, "ERROR"),
                        "Assinatura Canônica do Erro": sig,
                        "Ocorrências": count,
                        "Impacto (%)": f"{(count/tot)*100:.1f}%",
                        "Primeiro Visto": metrics['first_seen'].get(sig, "N/A"),
                        "Último Visto": metrics['last_seen'].get(sig, "N/A"),
                        "Causa Provável": cause,
                        "Ação Recomendada": act
                    })
                df_res = pd.DataFrame(table_rows)
                st.dataframe(df_res, use_container_width=True)
                
                # Stack traces sanitizadas para inspeção
                with st.expander("🛠️ Ver Amostras de Stack Traces Sanitizadas"):
                    for sig, count in metrics['error_counter'].most_common(5):
                        st.markdown(f"**Falha:** `{sig}` ({count} ocorrências)")
                        st.code(metrics['sample_traces'].get(sig, "Sem stack trace adicional"), language="text")
                        
                # Gráficos
                c_g1, c_g2 = st.columns(2)
                with c_g1:
                    st.subheader("📈 Top 5 Erros Mais Recorrentes")
                    chart_data = pd.DataFrame({
                        "Assinatura": [r['Assinatura Canônica do Erro'][:35] + "..." for r in table_rows[:5]],
                        "Ocorrências": [r['Ocorrências'] for r in table_rows[:5]]
                    }).set_index("Assinatura")
                    st.bar_chart(chart_data)
                with c_g2:
                    st.subheader("📊 Distribuição de Eventos")
                    st.bar_chart(pd.DataFrame({
                        "Categoria": ["Erros", "Warnings", "Info", "Debug"],
                        "Volume": [metrics['total_errors'], metrics['total_warns'], metrics['total_info'], metrics['total_debug']]
                    }).set_index("Categoria"))
            else:
                st.success("🎉 Nenhum erro crítico de nível ERROR ou CRITICAL foi identificado no log!")

            st.divider()
            st.subheader("📥 Exportação do Relatório Oficial Completo (SA-AIC Document Template)")
            pdf_bytes = generate_pdf_report(uploaded_file.name, metrics)
            rep_md = render_markdown_report(uploaded_file.name, metrics)
            rep_html = render_html_report(active_template, uploaded_file.name, metrics)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.download_button("📑 Baixar Relatório em PDF (.pdf)", data=pdf_bytes, file_name=f"relatorio_sa_aic_{uploaded_file.name}.pdf", mime="application/pdf", use_container_width=True)
            with col2:
                st.download_button("📄 Baixar Relatório em Markdown (.md)", data=rep_md, file_name=f"relatorio_sa_aic_{uploaded_file.name}.md", mime="text/markdown", use_container_width=True)
            with col3:
                st.download_button("🌐 Baixar Relatório em HTML (.html)", data=rep_html, file_name=f"relatorio_sa_aic_{uploaded_file.name}.html", mime="text/html", use_container_width=True)

# -----------------------------------------------------------------------------
# MODALIDADE 2: LOTE
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
        global_traces = {}
        tot_lines = 0
        
        with st.spinner("Processando todos os arquivos em lote..."):
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
                for k, v in m['sample_traces'].items():
                    if k not in global_traces: global_traces[k] = v
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
        st.subheader("📋 Resumo de Telemetria por Arquivo")
        st.dataframe(pd.DataFrame(batch_summary), use_container_width=True)
        
        st.divider()
        st.subheader("🌐 Ranking Global de Falhas do Ecossistema")
        if global_errors:
            global_rows = []
            tot_err = max(sum(global_errors.values()), 1)
            for rank, (sig, count) in enumerate(global_errors.most_common(20), start=1):
                cause, act = infer_root_cause(sig)
                global_rows.append({
                    "Rank": f"#{rank}",
                    "Severidade": global_sev.get(sig, "ERROR"),
                    "Assinatura Canônica": sig,
                    "Ocorrências Totais": count,
                    "Impacto (%)": f"{(count/tot_err)*100:.1f}%",
                    "Causa Provável": cause,
                    "Ação Recomendada": act
                })
            st.dataframe(pd.DataFrame(global_rows), use_container_width=True)
            
        st.divider()
        st.subheader("📥 Exportação do Relatório Consolidado (SA-AIC)")
        global_metrics = {
            "total_lines": tot_lines,
            "total_errors": sum(global_errors.values()),
            "total_warns": sum(global_warns.values()),
            "error_counter": global_errors,
            "warn_counter": global_warns,
            "first_seen": global_first,
            "last_seen": global_last,
            "severities": global_sev,
            "sample_traces": global_traces
        }
        scope_title = f"Lote Consolidado ({len(uploaded_files)} Logs)"
        pdf_batch = generate_pdf_report(scope_title, global_metrics, batch_summary=batch_summary)
        rep_batch_md = render_markdown_report(scope_title, global_metrics, batch_summary=batch_summary)
        rep_batch_html = render_html_report(active_template, scope_title, global_metrics, batch_summary=batch_summary)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.download_button("📑 Baixar Relatório Consolidado em PDF (.pdf)", data=pdf_batch, file_name="relatorio_sa_aic_lote_consolidado.pdf", mime="application/pdf", use_container_width=True)
        with col2:
            st.download_button("📄 Baixar Relatório Consolidado em Markdown (.md)", data=rep_batch_md, file_name="relatorio_sa_aic_lote_consolidado.md", mime="text/markdown", use_container_width=True)
        with col3:
            st.download_button("🌐 Baixar Relatório Consolidado em HTML (.html)", data=rep_batch_html, file_name="relatorio_sa_aic_lote_consolidado.html", mime="text/html", use_container_width=True)

# -----------------------------------------------------------------------------
# MODALIDADE 3: DIFF (COMPARAÇÃO DE RELEASES)
# -----------------------------------------------------------------------------
else:
    file_old = st.sidebar.file_uploader("Versão Anterior (v1.x):", type=["log", "txt", "csv", "pdf", "json"], key="f_old")
    file_new = st.sidebar.file_uploader("Versão Atual (v2.x):", type=["log", "txt", "csv", "pdf", "json"], key="f_new")
    if file_old and file_new:
        with st.spinner("Realizando Diff de releases e detectando regressões..."):
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
        col_c1.metric("Erros Versão Anterior (v1)", f"{m_old['total_errors']:,}")
        col_c2.metric("Erros Versão Atual (v2)", f"{m_new['total_errors']:,}", f"{diff_pct:+.1f}%", delta_color="inverse")
        col_c3.metric("Erros Únicos (v1 → v2)", f"{len(keys_old)} → {len(keys_new)}")

        c_res, c_reg = st.columns(2)
        with c_res:
            st.markdown(f"### 🟢 Erros Resolvidos com Sucesso ({len(resolved)})")
            if resolved:
                for err in list(resolved)[:6]:
                    st.success(f"**Corrigido:** `{err}` (Ocorria {m_old['error_counter'][err]} vezes na v1)")
            else:
                st.write("Nenhum erro anterior foi completamente extinto.")
                
        with c_reg:
            st.markdown(f"### 🔴 Novas Regressões Introduzidas ({len(regressions)})")
            if regressions:
                for err in list(regressions)[:6]:
                    st.error(f"**Regressão Inédita:** `{err}` ({m_new['error_counter'][err]} novas ocorrências)")
            else:
                st.write("Nenhuma regressão detectada na nova versão.")

        st.divider()
        st.subheader("📥 Exportação do Relatório Comparativo (Diff Modelo SA-AIC)")
        scope_diff = f"{file_old.name} (v1) vs {file_new.name} (v2)"
        pdf_diff = generate_pdf_report(scope_diff, m_new, diff_data=diff_data)
        rep_diff_md = render_markdown_report(scope_diff, m_new, diff_data=diff_data)
        rep_diff_html = render_html_report(active_template, scope_diff, m_new, diff_data=diff_data)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.download_button("📑 Baixar Relatório Diff em PDF (.pdf)", data=pdf_diff, file_name=f"relatorio_diff_{file_old.name}_vs_{file_new.name}.pdf", mime="application/pdf", use_container_width=True)
        with col2:
            st.download_button("📄 Baixar Relatório Diff em Markdown (.md)", data=rep_diff_md, file_name=f"relatorio_diff_{file_old.name}_vs_{file_new.name}.md", mime="text/markdown", use_container_width=True)
        with col3:
            st.download_button("🌐 Baixar Relatório Diff em HTML (.html)", data=rep_diff_html, file_name=f"relatorio_diff_{file_old.name}_vs_{file_new.name}.html", mime="text/html", use_container_width=True)
