# SecurityGraph AI

Compact cybersecurity data engineering project for building a CVE-centered knowledge graph dataset and loading it into Neo4j.

## What This Repo Does

- Collects CVE records from the NVD API.
- Cleans and preprocesses CVE text data.
- Generates dataset statistics and visualizations.
- Splits data into train/val/test sets.
- Builds supplemental security taxonomy tables (OWASP, CWE, defenses, tools, technologies).
- Runs dataset quality checks and generates a validation report.
- Loads processed CVE data into Neo4j.

## Current Data Snapshot

Based on files currently in the data folder:

- raw_cves.csv: 244 rows
- processed_cves.csv: 244 rows
- enhanced_cves.csv: 244 rows
- train.csv: 172 rows
- val.csv: 36 rows
- test.csv: 36 rows
- vulnerabilities.csv: 36 rows
- defenses.csv: 35 rows
- technologies.csv: 45 rows
- tools.csv: 24 rows
- cwes.csv: 28 rows

## Project Structure

```text
SecurityGraphAI/
├── data/
│   ├── raw_cves.csv
│   ├── processed_cves.csv
│   ├── enhanced_cves.csv
│   ├── train.csv
│   ├── val.csv
│   ├── test.csv
│   ├── statistics_report.txt
│   ├── statistics_visualizations.png
│   ├── vulnerabilities.csv
│   ├── defenses.csv
│   ├── technologies.csv
│   ├── tools.csv
│   ├── cwes.csv
│   ├── owasp_categories.csv
│   ├── vuln_defenses.csv
│   ├── vuln_tools.csv
│   ├── vuln_cwes.csv
│   ├── vuln_owasp.csv
│   ├── cve_technologies.csv
│   └── data_quality_report.txt
├── etl/
│   ├── 01_collect_data.py
│   ├── 02_preprocess_data.py
│   ├── 02_preprocess_data_enhanced.py
│   ├── 03_generate_statistics.py
│   ├── 04_create_splits.py
│   ├── 05_generate_security_taxonomy.py
│   ├── 06_data_quality_check.py
│   └── load_to_neo4j.py
├── NER_ANNOTATION_GUIDE.md
├── NER_IMPLEMENTATION_PLAN.md
├── NEXT_STEPS.md
├── requirements.txt
└── README.md
```

## Setup

### 1. Create and activate virtual environment

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

Note: ETL scripts also use packages that may not be listed in requirements.txt in some environments. If needed, install:

```powershell
pip install nltk scikit-learn matplotlib seaborn
```

### 3. Download NLTK resources

```powershell
python -m nltk.downloader punkt stopwords
```

## Environment Variables

Create a .env file from .env.example and update values:

```env
NEO4J_URI=neo4j+s://xxxxx.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your-password-here
GOOGLE_API_KEY=your-gemini-api-key-here
NVD_API_KEY=your-nvd-api-key-here
```

Important:
- The loader script etl/load_to_neo4j.py reads NEO4J_USERNAME.
- It also supports legacy NEO4J_USER for backward compatibility.

## Run ETL Pipeline

From repository root:

```powershell
python etl/01_collect_data.py
python etl/02_preprocess_data.py
python etl/03_generate_statistics.py
python etl/04_create_splits.py
python etl/02_preprocess_data_enhanced.py
python etl/05_generate_security_taxonomy.py
python etl/06_data_quality_check.py
```

Outputs are written to the data folder.

## Load into Neo4j

```powershell
python etl/load_to_neo4j.py
```

This script loads from data/processed_cves.csv and creates:

- CVE nodes
- Severity nodes and HAS_SEVERITY relationships
- CWE nodes and MAPS_TO relationships
- Version nodes and AFFECTS_VERSION relationships
- Year nodes and PUBLISHED_IN relationships

## Key Notes

- This repository currently focuses on data/ETL and graph-loading foundations.
- NER planning artifacts are available in NER_IMPLEMENTATION_PLAN.md and NER_ANNOTATION_GUIDE.md.
- NEXT_STEPS.md tracks upcoming implementation work.

## License and Usage

This project is for educational and research use. Validate security recommendations before production use.
