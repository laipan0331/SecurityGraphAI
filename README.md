# 🔐 SecurityGraph AI

**Cybersecurity Knowledge Graph with GraphRAG**

DAMG 7374 - Generative AI for Data - Group Project

---

## 📘 Project Overview

SecurityGraph AI is a knowledge graph-based cybersecurity assistant that maps vulnerabilities, attacks, defenses, and tools — allowing developers and security professionals to ask natural language questions about security threats and how to mitigate them.

### Why This Project?

| Factor | Why It Matters |
|--------|----------------|
| **High Demand** | Every company needs security — it's a $200B+ industry |
| **Unique** | Almost no one builds security knowledge graphs |
| **Free Data** | CVE, NVD, OWASP — all free and structured! |
| **Portfolio Gold** | "I built a cybersecurity knowledge graph" = instant attention |
| **Practical** | You'll actually learn security concepts |

---

## 🎯 Current Project Status

**Week:** 2-3 (Data Engineering Complete → Graph Database Phase)  
**Overall Progress:** 30% Complete

### Team Progress

| Role | Team Member | Progress | Status |
|------|-------------|----------|--------|
| 🔧 **Data Engineer** | Panpan Lai | 100% | ✅ Complete |
| 🗄️ **Graph Engineer** | Hak Hyun Lee | 0% | 📋 Ready to Start |
| 🤖 **AI Engineer** | Sai Kaushik Bhima | 0% | 📋 Ready to Start |

---

## 📊 Data Engineering Progress (100% ✅)

**Responsible:** Panpan Lai

### ✅ Completed (Week 1)

1. **CVE Data Collection Pipeline** ✅
   - Built automated NVD API data collection
   - Collected 97 unique CVE records
   - 10 vulnerability categories covered
   - Files: [etl/01_collect_data.py](etl/01_collect_data.py)

2. **Data Preprocessing** ✅
   - Deduplication and cleaning
   - Missing value handling
   - Text preprocessing
   - Files: [etl/02_preprocess_data.py](etl/02_preprocess_data.py), [data/processed_cves.csv](data/processed_cves.csv)

3. **Statistical Analysis** ✅
   - Comprehensive data analysis
   - Severity and CVSS distribution
   - Files: [etl/03_generate_statistics.py](etl/03_generate_statistics.py), [data/statistics_report.txt](data/statistics_report.txt)

4. **Dataset Splitting** ✅
   - Train/Val/Test split (70/15/15)
   - Stratified by severity
   - Files: [etl/04_create_splits.py](etl/04_create_splits.py)

### ✅ Completed (Week 2)

5. **NER Framework Integration** ✅
   - Designed 7 entity types for CVE data
   - Created comprehensive annotation guidelines
   - Built complete training pipeline (BERT + DeBERTa)
   - Files: [NER_IMPLEMENTATION_PLAN.md](NER_IMPLEMENTATION_PLAN.md), [NER_ANNOTATION_GUIDE.md](NER_ANNOTATION_GUIDE.md)

6. **Supplemental Security Taxonomy Datasets** ✅
   - Added OWASP, vulnerability, defense, technology, tool, and CWE reference data
   - Added relationship CSVs for graph loading (vulnerability-defense, vulnerability-tool, vulnerability-CWE, vulnerability-OWASP, CVE-technology)
   - Files: [etl/05_generate_security_taxonomy.py](etl/05_generate_security_taxonomy.py), [data/vulnerabilities.csv](data/vulnerabilities.csv), [data/defenses.csv](data/defenses.csv)

📄 **Detailed Report:** See [DATA_ENGINEERING.md](DATA_ENGINEERING.md)

### 📝 To-Do (Week 3-5)

- [ ] Expand CVE collection (+50-70 records)
- [ ] Data validation

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USER INTERFACE                           │
│                  (Streamlit Web App)                        │
│  [Dashboard] [Vuln Explorer] [Q&A] [CVE Search] [Defense] │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                   GRAPHRAG LAYER                            │
│              (LangChain + Gemini 1.5)                       │
│  [Entity Extraction] → [Cypher Query] → [Answer Gen]      │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│              KNOWLEDGE GRAPH LAYER                          │
│                   (Neo4j AuraDB)                            │
│  (Vulnerability)─[:MITIGATED_BY]→(Defense)                 │
│        ├─[:AFFECTS]→(Technology)                           │
│        ├─[:HAS_CVE]→(CVE)                                  │
│        └─[:CATEGORY]→(OWASP_Category)                      │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    DATA LAYER                               │
│          (NVD API + OWASP + Manual CSVs)                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
SecurityGraphAI/
│
├── README.md                        # 📄 Main project documentation (this file)
├── DATA_ENGINEERING.md              # 🔧 Data engineering progress report
├── README_CVE_Pipeline.md           # 📊 Detailed CVE pipeline documentation
├── requirements.txt                 # 📦 Python dependencies
├── .env.example                     # 🔐 Environment variables template
├── .gitignore                       # 🚫 Git ignore rules
│
├── data/                            # 📊 Data files (current: CVE data)
│   ├── raw_cves.csv                 # ✅ 100 raw CVE records
│   ├── processed_cves.csv           # ✅ 97 cleaned CVE records
│   ├── train.csv                    # ✅ Training set (67 records)
│   ├── val.csv                      # ✅ Validation set (15 records)
│   ├── test.csv                     # ✅ Test set (15 records)
│   ├── statistics_report.txt        # ✅ Statistical analysis
│   │
│   ├── vulnerabilities.csv          # ✅ vulnerability reference table
│   ├── defenses.csv                 # ✅ defense reference table
│   ├── technologies.csv             # ✅ technology reference table
│   ├── tools.csv                    # ✅ security tools reference table
│   ├── cwes.csv                     # ✅ CWE reference table
│   ├── owasp_categories.csv         # ✅ OWASP Top 10 table
│   ├── vuln_defenses.csv            # ✅ vulnerability-defense relationships
│   ├── cve_technologies.csv         # ✅ CVE-technology relationships
│   ├── vuln_tools.csv               # ✅ vulnerability-tool relationships
│   ├── vuln_cwes.csv                # ✅ vulnerability-CWE relationships
│   └── vuln_owasp.csv               # ✅ vulnerability-OWASP relationships
│
├── etl/                             # 🔧 ETL scripts
│   ├── 01_collect_data.py           # ✅ NVD API data collection
│   ├── 02_preprocess_data.py        # ✅ Data preprocessing
│   ├── 03_generate_statistics.py    # ✅ Statistical analysis
│   ├── 04_create_splits.py          # ✅ Dataset splitting
│   │
│   ├── load_to_neo4j.py             # ✅ Neo4j data loader
│   └── 05_generate_security_taxonomy.py  # ✅ supplemental dataset generator
│
├── graphrag/                        # 🤖 GraphRAG components (Week 3-4)
│   ├── __init__.py
│   ├── entity_extractor.py          # 📝 Extract security entities
│   ├── cypher_generator.py          # 📝 Generate Cypher queries
│   ├── graph_retriever.py           # 📝 Graph traversal
│   └── answer_generator.py          # 📝 Generate answers
│
├── pages/                           # 🌐 Streamlit pages (Week 2-5)
│   ├── 1_Dashboard.py
│   ├── 2_Vulnerability_Explorer.py
│   ├── 3_CVE_Search.py
│   ├── 4_Ask_Question.py
│   ├── 5_Defense_Guide.py
│   └── 6_About.py
│
├── utils/                           # 🛠️ Utility modules
│   ├── __init__.py
│   ├── neo4j_connection.py
│   └── config.py
│
├── app.py                           # 🚀 Main Streamlit app (Week 3-5)
│
├── Assignment1_CVE_Data_Pipeline.ipynb  # 📓 Data pipeline notebook
├── Assignment1_Report.md            # 📄 Assignment 1 report
└── Assignment1_Report.html          # 📄 Assignment 1 HTML report
```

---

## 🚀 Quick Start Guide

### Prerequisites

```bash
# Python 3.11+
python --version

# Install dependencies
pip install -r requirements.txt
```

### Environment Setup

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Edit .env with your credentials:
#    - Neo4j AuraDB (free tier): https://neo4j.com/cloud/aura/
#    - Google Gemini API: https://ai.google.dev/
#    - NVD API Key (optional): https://nvd.nist.gov/developers
```

### Run Data Pipeline (Currently Available)

```bash
# Step 1: Collect CVE data from NVD
python etl/01_collect_data.py

# Step 2: Preprocess and clean data
python etl/02_preprocess_data.py

# Step 3: Generate statistics
python etl/03_generate_statistics.py

# Step 4: Create train/val/test splits
python etl/04_create_splits.py

# Step 5: Generate supplemental security taxonomy datasets
python etl/05_generate_security_taxonomy.py
```

---

## 👥 Team Collaboration Guide

### Getting Started

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd SecurityGraphAI
   ```

2. **Install Dependencies**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Mac/Linux
   venv\Scripts\activate     # Windows
   pip install -r requirements.txt
   ```

3. **Set Up Your Environment**
   ```bash
   cp .env.example .env
   # Add your API keys to .env
   ```

### Git Workflow

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes and commit
git add .
git commit -m "Add: description of changes"

# Push to GitHub
git push origin feature/your-feature-name

# Create Pull Request on GitHub
```

### Branching Strategy

- `main` - Production-ready code
- `develop` - Integration branch
- `feature/*` - Feature branches
- `fix/*` - Bug fix branches

### Who Works on What?

#### 🔧 Data Engineer (Panpan Lai)
**Focus:** Data collection, cleaning, CSV file creation

**Current Work:**
- ✅ CVE data pipeline complete
- 📝 Working on OWASP, defenses, tools data

**Your Folders:**
- `data/` - All CSV files
- `etl/` - Data collection & processing scripts

#### 🗄️ Graph Engineer (Person 2)
**Focus:** Neo4j setup, graph schema, data loading

**To Start:**
1. Review [DATA_ENGINEERING.md](DATA_ENGINEERING.md) to understand data
2. Set up Neo4j AuraDB (free tier)
3. Design graph schema
4. Write `etl/load_to_neo4j.py`

**Your Folders:**
- `etl/load_to_neo4j.py` - Data loading script
- `utils/neo4j_connection.py` - Neo4j utilities

#### 🤖 AI Engineer (Person 3)
**Focus:** Streamlit UI, LangChain, GraphRAG

**To Start:**
1. Set up basic Streamlit app structure
2. Get Gemini API key
3. Create placeholder pages
4. Start with Dashboard page

**Your Folders:**
- `app.py` - Main app
- `pages/` - All Streamlit pages
- `graphrag/` - GraphRAG components

---

## 📋 Week-by-Week Timeline

### ✅ Week 1 (Completed)
- [x] CVE data collection (Data Engineer)
- [x] Data preprocessing (Data Engineer)
- [x] Statistical analysis (Data Engineer)
- [x] Dataset splitting (Data Engineer)
- [x] GitHub repository setup

### 📍 Week 2 (Current - Feb 10-16)
- [ ] Collect OWASP vulnerability data (Data Engineer)
- [ ] Collect defense/mitigation data (Data Engineer)
- [ ] Set up Neo4j AuraDB (Graph Engineer)
- [ ] Design graph schema (Graph Engineer)
- [ ] Set up Streamlit skeleton (AI Engineer)
- [ ] Create Dashboard page (AI Engineer)

### Week 3 (Feb 17-23)
- [ ] Fetch more CVEs from NVD API (Data Engineer)
- [ ] Create relationship CSVs (Data Engineer)
- [ ] Load data to Neo4j (Graph Engineer)
- [ ] Create Cypher query templates (Graph Engineer)
- [ ] Implement GraphRAG pipeline (AI Engineer)
- [ ] Build Q&A page (AI Engineer)

### Week 4 (Feb 24-Mar 2)
- [ ] Data validation (Data Engineer)
- [ ] Graph visualization (Graph Engineer)
- [ ] Optimize Cypher queries (Graph Engineer)
- [ ] Build remaining pages (AI Engineer)
- [ ] Integration testing (All)

### Week 5 (Mar 3-9)
- [ ] Final testing (All)
- [ ] Bug fixes (All)
- [ ] Documentation (All)
- [ ] Demo video (All)
- [ ] Presentation preparation (All)

---

## 🎯 Key Features (To Be Implemented)

### 1. Dashboard
Overview of vulnerabilities, CVEs, and security statistics.

### 2. Vulnerability Explorer
Browse vulnerabilities by category, severity, technology.

### 3. CVE Search
Search and explore CVE database with filters.

### 4. Natural Language Q&A (GraphRAG) ⭐
**Example Questions:**
- "How do I prevent SQL injection in Django?"
- "What tools detect XSS vulnerabilities?"
- "What does CVE-2021-44228 affect?"
- "Difference between XSS and CSRF?"

### 5. Defense Guide
Step-by-step mitigation guides for each vulnerability.

### 6. Graph Visualization
Interactive graph showing vulnerability relationships.

---

## 📊 Target Data Metrics

| Data Type | Current | Target | Status |
|-----------|---------|--------|--------|
| CVE Records | 97 | 150+ | 🟡 65% |
| Vulnerabilities | 10 | 30-40 | 🔴 25% |
| Defense Strategies | 0 | 30-40 | 🔴 0% |
| Technologies | 0 | 40-50 | 🔴 0% |
| Security Tools | 0 | 20-25 | 🔴 0% |
| CWE Categories | 0 | 25-30 | 🔴 0% |
| Graph Nodes | ~100 | 200-250 | 🟡 40% |
| Graph Relationships | 0 | 300-400 | 🔴 0% |

🟢 Complete | 🟡 In Progress | 🔴 Not Started

---

## 📚 Learning Resources

### Security Basics (Required for All)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - 2 hours read
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/) - Reference
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Free course

### Technical Resources
- [Neo4j Cypher Basics](https://neo4j.com/developer/cypher/) - For Graph Engineer
- [LangChain Graph QA](https://python.langchain.com/docs/tutorials/graph/) - For AI Engineer
- [NVD API Documentation](https://nvd.nist.gov/developers) - For Data Engineer
- [Streamlit Documentation](https://docs.streamlit.io/) - For AI Engineer

---

## ⚠️ Important Notes

### For All Team Members

1. **Never commit sensitive data:**
   - API keys go in `.env` (already in .gitignore)
   - Large data files (>100MB) should be GitIgnored or use Git LFS

2. **Communication:**
   - Update your progress in respective documentation
   - Use pull requests for code review
   - Communicate blockers early

3. **Code Quality:**
   - Add comments for complex logic
   - Follow Python PEP 8 style guide
   - Test your code before committing

### Current Blockers

- 🔴 **Graph Engineer needs to start:** Set up Neo4j AuraDB
- 🔴 **AI Engineer needs to start:** Set up Streamlit skeleton
- 🟡 **Data Engineer needs more data:** OWASP, defenses, tools

---

## 📞 Contact & Support

### Data Questions
- Contact: Panpan Lai (Data Engineer)
- Documentation: [DATA_ENGINEERING.md](DATA_ENGINEERING.md)
- CVE Pipeline Details: [README_CVE_Pipeline.md](README_CVE_Pipeline.md)

### Graph Questions
- Contact: Hak Hyun Lee (Graph Engineer)
- Resources: Neo4j documentation, graph schema design

### AI/UI Questions
- Contact: Sai Kaushik Bhima (AI Engineer)
- Resources: LangChain docs, Streamlit tutorials

---

## 🔗 Important Links

- [NVD API](https://nvd.nist.gov/developers)
- [OWASP](https://owasp.org/)
- [CWE Database](https://cwe.mitre.org/)
- [Neo4j AuraDB](https://neo4j.com/cloud/aura/)
- [Google Gemini API](https://ai.google.dev/)
- [Streamlit](https://streamlit.io/)

---

## ⚖️ Disclaimer

```
╔══════════════════════════════════════════════════════════════╗
║                 EDUCATIONAL PURPOSE ONLY                     ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  This application is for EDUCATIONAL PURPOSES ONLY.         ║
║                                                              ║
║  • Not a replacement for professional security audits       ║
║  • CVE data may not be real-time                            ║
║  • Always consult security professionals for production     ║
║  • Do not use for actual penetration testing without        ║
║    proper authorization                                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 📄 License

This project is for educational and research purposes as part of DAMG 7374 - Generative AI for Data course.

---

Built with 🔐 by DAMG 7374 Group
