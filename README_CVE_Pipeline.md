# SecurityGraph AI - CVE Data Processing Pipeline

A comprehensive data processing pipeline for analyzing CVE (Common Vulnerabilities and Exposures) data from the National Vulnerability Database (NVD) to build a security knowledge graph and GraphRAG system.

## 📊 Dataset Overview

### Dataset Selection Rationale

**Why CVE Data from NVD?**

1. **Authoritative Source**: The National Vulnerability Database (NVD) is the U.S. government repository of standards-based vulnerability management data, providing comprehensive and reliable information.

2. **Rich Security Context**: CVE data contains multiple dimensions of security information:
   - Detailed vulnerability descriptions in natural language
   - CVSS scores for severity assessment
   - CWE (Common Weakness Enumeration) classifications
   - Temporal metadata (publication dates, updates)
   - Attack vector information

3. **Real-world Applications**: Understanding and analyzing security vulnerabilities is crucial for:
   - Security risk assessment and management
   - Automated threat intelligence
   - Vulnerability prioritization
   - Security knowledge graph construction
   - GraphRAG-based security query systems

4. **Structured yet Complex**: CVE data provides an excellent balance:
   - Well-structured metadata for quantitative analysis
   - Rich text descriptions for NLP and graph extraction
   - Multiple relationships between vulnerabilities, weaknesses, and attack patterns

### Data Collection Strategy

The pipeline collects CVE data targeting **10 major vulnerability categories**:
- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Remote Code Execution (RCE)
- Authentication Bypass
- Path Traversal
- Command Injection
- XML External Entity (XXE)
- Insecure Deserialization
- Server-Side Request Forgery (SSRF)

**Collection Parameters**:
- 10 CVEs per vulnerability category
- Total target: ~100 CVE records
- API rate limiting: 6-second delay between requests
- Deduplication by CVE ID

---

## 🔧 Data Preprocessing Pipeline

### Step 1: Data Collection (`01_collect_data.py`)

**Process**:
1. Query NVD REST API with keyword-based search
2. Parse JSON responses to extract key fields
3. Handle CVSS scoring (v3.1 and v2 fallback)
4. Remove duplicate CVE entries
5. Export to `raw_cves.csv`

**Key Fields Extracted**:
- `cve_id`: Unique CVE identifier
- `description`: Natural language vulnerability description
- `cvss_score`: Numerical severity score (0-10)
- `severity`: Categorical severity (CRITICAL, HIGH, MEDIUM, LOW)
- `published_date`: Publication timestamp
- `cwe_ids`: Associated weakness classifications

---

### Step 2: Data Preprocessing (`02_preprocess_data.py`)

#### 2.1 Duplicate Removal
- **Method**: Drop duplicates based on `cve_id`
- **Purpose**: Ensure data integrity and avoid bias

#### 2.2 Missing Value Handling
- **Description**: Remove entries with empty descriptions (unusable for NLP)
- **Severity**: Fill missing values with 'UNKNOWN'
- **CVSS Score**: Fill missing values with 0.0
- **CWE IDs**: Fill missing values with 'Unknown'

#### 2.3 Text Cleaning
- **URL Replacement**: Replace URLs with `URL` token
- **Email Replacement**: Replace emails with `EMAIL` token
- **HTML Tag Removal**: Strip all HTML markup
- **Whitespace Normalization**: Remove excess spaces and newlines

#### 2.4 Security Entity Extraction
Extract structured information from unstructured text:
- CVE IDs referenced in descriptions
- CWE IDs for vulnerability classification
- IP addresses for network-related vulnerabilities
- Version numbers for affected software

#### 2.5 Text Tokenization
- **Method**: NLTK word tokenization
- **Processing**:
  - Convert to lowercase
  - Remove punctuation
  - Filter single-character tokens (except 'c', 'r' for programming contexts)
- **Output**: Token list and token count per CVE

#### 2.6 Sentence Segmentation
- **Purpose**: Enable sentence-level analysis for graph construction
- **Method**: NLTK sentence tokenization
- **Output**: Sentence list and sentence count per CVE

**Output**: `processed_cves.csv` with enriched features

---

### Step 3: Statistical Analysis (`03_generate_statistics.py`)

#### Key Statistics Generated

**Dataset Overview**:
- Total CVE count: 97 records
- Time range coverage
- Date distribution by year

**Text Features**:
- Average description length: ~XXX characters
- Token count distribution: mean, min, max
- Sentence count distribution
- Vocabulary size and richness

**Severity Distribution**:
```
CRITICAL: XX records (XX.X%)
HIGH:     XX records (XX.X%)
MEDIUM:   XX records (XX.X%)
LOW:      XX records (XX.X%)
```

**CVSS Score Analysis**:
- Mean CVSS score
- Median CVSS score
- Score range: 0.0 - 10.0
- Distribution across severity bands

**Vocabulary Analysis**:
- Total tokens processed
- Unique token count (vocabulary size)
- Vocabulary richness ratio
- Top 30 security terms by frequency

**CWE Coverage**:
- Percentage of CVEs with CWE labels
- Most common CWE types
- Vulnerability class distribution

#### Visualizations Generated

1. **Severity Distribution** (Pie Chart): Proportions of each severity level
2. **CVSS Score Distribution** (Histogram): Frequency distribution of scores
3. **Description Length Distribution** (Histogram): Text length patterns
4. **Token Count Distribution** (Histogram): Vocabulary usage patterns
5. **CVE Count by Year** (Bar Chart): Temporal distribution
6. **Top 15 Security Terms** (Horizontal Bar): Most frequent technical terms
7. **CVSS vs Description Length** (Scatter): Correlation analysis
8. **Severity by Year** (Stacked Bar): Temporal severity trends
9. **Sentence Count Distribution** (Histogram): Text complexity patterns

**Outputs**:
- `statistics_report.txt`: Comprehensive text report
- `statistics_visualizations.png`: 9-panel visualization

---

## 📂 Data Splitting Strategy

### Strategy Overview (`04_create_splits.py`)

**Split Ratios**:
- Training Set: **70%** (~68 records)
- Validation Set: **15%** (~15 records)
- Test Set: **15%** (~15 records)

### Stratification Approach

**Challenge**: Imbalanced severity distribution (e.g., only 1 LOW severity record)

**Solution**: Two-phase stratified split with special handling

#### Phase 1: Test Set Separation
- Use stratified sampling on severity levels
- Reserve 15% for testing
- Maintain severity distribution proportions

#### Phase 2: Validation Set Separation
- Apply stratified sampling to remaining data
- Calculate proportion: 15% of original = 17.6% of remaining
- Preserve severity balance

#### Special Case Handling
For severity levels with insufficient samples (n=1):
- Manually assign to training set
- Prevent stratification errors
- Document in split logs

### Distribution Verification

**Metrics Checked**:
1. **Size proportions**: Verify 70-15-15 split
2. **Severity distribution**: Compare proportions across splits
3. **CVSS score distribution**: Ensure balanced scoring ranges
4. **Token count distribution**: Check text complexity balance

**Validation Outputs**:
- Console summary with severity distribution tables
- CVSS statistics comparison across splits
- Visualization: `data_split_visualization.png`
  - Split size comparison (pie chart)
  - Severity distribution across splits (grouped bar chart)
  - CVSS score distribution (box plots)
  - Token count distribution (overlaid histograms)

---

## 🚀 Quick Start

### Prerequisites
```bash
pip install pandas scikit-learn nltk requests matplotlib seaborn
python -m nltk.downloader punkt stopwords
```

### Run the Complete Pipeline

```bash
# Step 1: Collect CVE data from NVD
python etl/01_collect_data.py

# Step 2: Preprocess and clean data
python etl/02_preprocess_data.py

# Step 3: Generate statistics and visualizations
python etl/03_generate_statistics.py

# Step 4: Create train/val/test splits
python etl/04_create_splits.py
```

**Alternative**: Use the simplified split script
```bash
python split.py
```

---

## 📁 Project Structure

```
SecurityGraphAI/
├── data/
│   ├── raw_cves.csv                      # Original CVE data (97 records)
│   ├── processed_cves.csv                # Cleaned and enriched data
│   ├── train.csv                         # Training set (70%)
│   ├── val.csv                           # Validation set (15%)
│   ├── test.csv                          # Test set (15%)
│   ├── statistics_report.txt             # Detailed analysis report
│   ├── statistics_visualizations.png     # 9-panel visualization
│   └── data_split_visualization.png      # Split quality assessment
├── etl/
│   ├── 01_collect_data.py               # NVD API data collection
│   ├── 02_preprocess_data.py            # Data cleaning pipeline
│   ├── 03_generate_statistics.py        # Statistical analysis
│   ├── 04_create_splits.py              # Dataset splitting (full)
│   └── 04_create_splits_simple.py       # Dataset splitting (simplified)
├── notebooks/                            # Jupyter notebooks for exploration
├── split.py                              # Standalone splitting script
└── README.md                             # This file
```

---

## 📊 Dataset Statistics Summary

| Metric | Value |
|--------|-------|
| Total CVEs | 97 |
| Average Description Length | ~XXX chars |
| Average Token Count | ~XX tokens |
| Average Sentence Count | ~X sentences |
| Vocabulary Size | ~XXX unique tokens |
| Date Range | YYYY-MM-DD to YYYY-MM-DD |
| CVSS Score Range | 0.0 - 10.0 |
| Severity Levels | 4 (CRITICAL, HIGH, MEDIUM, LOW) |

---

## 🎯 Next Steps

1. **Knowledge Graph Construction**
   - Extract entity relationships from CVE descriptions
   - Build graph schema for vulnerabilities, weaknesses, and attack patterns
   - Implement graph database (Neo4j/NetworkX)

2. **GraphRAG Implementation**
   - Integrate retrieval-augmented generation
   - Enable natural language queries over security knowledge
   - Build interactive security intelligence system

3. **Advanced Analytics**
   - Temporal vulnerability trend analysis
   - Predictive severity modeling
   - Automated vulnerability classification

---

## 📝 Data Quality Notes

- **Completeness**: 100% of records have non-empty descriptions
- **Consistency**: Standardized severity levels and CVSS scoring
- **Uniqueness**: Deduplicated by CVE ID
- **Balance**: Stratified splits maintain severity distribution
- **Coverage**: 10 major vulnerability categories represented

---

## 🔗 References

- [National Vulnerability Database](https://nvd.nist.gov/)
- [CVSS Specification](https://www.first.org/cvss/)
- [CWE List](https://cwe.mitre.org/)
- [CVE Program](https://www.cve.org/)

---

## 📄 License

This project is for educational and research purposes. CVE data is sourced from the National Vulnerability Database (NVD) maintained by NIST.

---

**Last Updated**: February 2, 2026
**Version**: 1.0
**Status**: Data preprocessing complete ✅
