# SecurityGraph AI

A cybersecurity intelligence platform built on a Neo4j knowledge graph, powered by Google Gemini and the NVD/OWASP data sources. The system connects CVEs, weaknesses (CWEs), defenses, tools, and affected software through graph relationships — enabling natural language querying, autonomous vulnerability investigation, attack path analysis, and graph-powered analytics.

## Features

- **GraphRAG Q&A** — Ask natural language security questions; Gemini generates Cypher queries, runs them on Neo4j, and returns intelligent answers.
- **Autonomous CVE Investigator** — Enter a CVE ID and the agent auto-investigates it across 6 steps to produce a full security report.
- **Attack Path Analyzer** — Describe your tech stack in plain English and get a prioritized remediation plan with ranked defenses and detection tools.
- **Knowledge Graph Visualization** — Interactive pyvis graph showing a CVE's full attack surface: CWEs, defenses, tools, and affected software.
- **Graph Analytics** — PageRank on CVEs and community detection on CWEs to surface the most critical and interconnected vulnerabilities.
- **Live NVD Feed** — Automatically syncs new CVEs from the NVD API every 6 hours.
- **OWASP Defense Loader** — Scrapes OWASP cheat sheets and links defenses and tools to CWEs in the graph.
- **Evaluation Suite** — BLEU, ExactMatch, Faithfulness, and Relevance metrics across 20 test questions.

## Tech Stack

| Layer | Technology |
|---|---|
| Knowledge Graph | Neo4j AuraDB |
| LLM | Google Gemini 2.5 Flash |
| Backend | Python, Neo4j Python Driver |
| Frontend | Streamlit |
| Graph Viz | pyvis |
| Data Sources | NVD API, MITRE CWE, OWASP Cheat Sheets |

## Team

| Name | Role |
|---|---|
| Bhima Sai Kaushik | AI Integration & Graph RAG Agent |
| Panpan Lai | Data Engineering & ETL Pipeline |
| Hakhyunn Lee | Graph Analytics & Evaluation |

## Project Structure

```
SecurityGraphAI/
├── agents/
│   ├── graph_rag_agent.py       # GraphRAG Q&A pipeline
│   ├── autonomous_agent.py      # CVE investigation agent
│   └── attack_path_agent.py     # Attack path & stack analyzer
├── etl/
│   ├── load_to_neo4j.py         # CVE data loader
│   ├── load_owasp_defenses.py   # OWASP defense scraper
│   └── nvd_live_feed.py         # NVD live sync
├── utils/
│   ├── graph_visualizer.py      # pyvis CVE graph builder
│   └── graph_analytics.py       # PageRank & community detection
├── evaluate/
│   └── evaluate.py              # Evaluation suite
└── app.py                       # Streamlit UI
```

## Setup

1. Clone the repo and install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Create a `.env` file:
   ```
   NEO4J_URI=neo4j+s://your-instance.databases.neo4j.io
   NEO4J_USERNAME=neo4j
   NEO4J_PASSWORD=your_password
   GEMINI_API_KEY=your_gemini_api_key
   NVD_API_KEY=your_nvd_api_key
   ```

3. Load data into Neo4j:
   ```bash
   python etl/load_to_neo4j.py
   python etl/load_owasp_defenses.py
   ```

4. Run the app:
   ```bash
   streamlit run app.py
   ```
