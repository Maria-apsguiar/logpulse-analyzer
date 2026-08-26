# 🛡️ LogPulse AI — Analisador Inteligente de Logs & Gerador de Relatórios

Aplicação Web agêntica desenvolvida em Streamlit para ingestão de arquivos brutos de telemetria, detecção de anomalias, clusterização de erros, comparação de releases (*diff* entre versões) e exportação de relatórios formais no modelo **SA-AIC Document Template Handout (CLEAR & TRACI)**.

---

## 🚀 Principais Recursos
- **Ingestão Multi-Formato:** Suporte a arquivos `.log`, `.txt`, `.csv`, `.pdf` e `.json`.
- **Governança Anti-PII:** Mascaramento em memória de CPFs, e-mails, endereços IP e tokens/segredos (Bearer/JWT).
- **Clusterização Canônica:** Agrupamento de stack traces removendo variáveis dinâmicas em tempo real.
- **Diff de Versões (Releases):** Comparação entre logs da versão anterior vs. atual (Erros Resolvidos, Persistentes e Novas Regressões).
- **Gerador de Relatórios SA-AIC:** Exportação sob demanda com um clique nos formatos **PDF**, **Markdown (.md)** e **HTML**.

---

## 📋 Estrutura do Repositório
```txt
├── app.py              # Código principal da aplicação Streamlit
├── requirements.txt    # Dependências do projeto
└── README.md           # Documentação do projeto
