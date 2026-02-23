# 🎯 NER Implementation Plan for SecurityGraphAI Project

## Overview

This document outlines the implementation of Named Entity Recognition (NER) for automated entity extraction from CVE vulnerability descriptions in the SecurityGraphAI knowledge graph project.

---

## Implementation Requirements ✅

- ✅ Use two transformer-based models for token classification
- ✅ Fine-tune on CVE security dataset  
- ✅ Evaluate with Precision, Recall, F1-score
- ✅ Compare model performance
- ✅ Analyze misclassified entities

---

## Project Integration Strategy

### 1. Dataset: CVE Vulnerability Descriptions

**Current Data:**
- 97 CVE records with detailed vulnerability descriptions
- Average description length: ~244 characters
- Rich security domain terminology
- Ideal for domain-specific NER

**Example:**
```
"SQL injection vulnerability in read.php3 and other scripts in Phorum 3.0.7 
allows remote attackers to execute arbitrary SQL queries via the sSQL parameter."
```

### 2. Entity Types to Extract

| Entity Type | Examples | Purpose for Knowledge Graph |
|-------------|----------|----------------------------|
| **SOFTWARE** | Phorum, phpBB, Oracle, Bugzilla | Software nodes |
| **VERSION** | 3.0.7, 1.4.2, 2.14 | Version tracking |
| **VULNERABILITY_TYPE** | SQL injection, XSS, buffer overflow | Vulnerability category nodes |
| **FILE** | read.php3, prefs.php, article.php | Affected file tracking |
| **ATTACK_VECTOR** | remote attackers, authenticated users | Attack method classification |
| **COMPONENT** | mod_sql, authentication modules | Component-level granularity |
| **IMPACT** | execute arbitrary SQL, bypass authentication | Impact assessment |

### 3. Data Annotation Strategy

**Option 1: Manual Annotation (Recommended)**
- Annotate 100-200 CVE descriptions manually
- Use tools like Label Studio or Doccano
- Create train/val/test splits (70/15/15)
- High quality, domain-specific labels

**Option 2: Semi-Automated Annotation**
- Use spaCy's EntityRuler with patterns
- Manual validation and correction
- Faster but requires careful validation

**Option 3: Use Existing Dataset + Custom Labels**
- Start with CoNLL-2003 or similar benchmark
- Add CVE data as domain adaptation
- Compare performance on general vs. security-specific entities

---

## Proposed Models

### Model 1: BERT-based (bert-base-cased)
**Advantages:**
- Strong baseline performance
- Good at general domain NER
- Well-documented

**Configuration:**
```python
model_checkpoint = "bert-base-cased"
learning_rate = 2e-5
batch_size = 16
epochs = 3
```

### Model 2: DeBERTa-v3-base
**Advantages:**
- More recent architecture
- Better performance on token classification
- Improved handling of long sequences

**Configuration:**
```python
model_checkpoint = "microsoft/deberta-v3-base"
learning_rate = 5e-6
batch_size = 8
epochs = 4
```

---

## Implementation Plan

### Week 1: Data Preparation
- [ ] Export CVE descriptions to annotation format
- [ ] Set up annotation tool (Label Studio/Doccano)
- [ ] Define annotation guidelines
- [ ] Annotate 50 samples for pilot

### Week 2: Annotation & Dataset Creation
- [ ] Complete annotating 100-200 CVE descriptions
- [ ] Create train/val/test splits
- [ ] Convert to HuggingFace dataset format
- [ ] Validate annotation quality

### Week 3: Model Training
- [ ] Fine-tune BERT model
- [ ] Fine-tune DeBERTa model
- [ ] Implement early stopping and checkpointing
- [ ] Track training metrics

### Week 4: Evaluation & Analysis
- [ ] Calculate Precision, Recall, F1 per entity type
- [ ] Generate confusion matrices
- [ ] Analyze misclassifications
- [ ] Compare model performance

### Week 5: Integration with Project
- [ ] Deploy best model for entity extraction
- [ ] Extract entities from all 97 CVE records
- [ ] Create entity CSV files for knowledge graph
- [ ] Update project documentation

---

## Evaluation Metrics

### 1. Token-Level Metrics
- Precision, Recall, F1 for each entity type
- Overall micro/macro averages

### 2. Entity-Level Metrics (Strict & Partial)
- Strict: Exact boundary match
- Partial: Overlapping boundaries

### 3. Confusion Analysis
```
Actual: SOFTWARE → Predicted: COMPONENT (common confusion)
Actual: VERSION → Predicted: O (missed entities)
```

### 4. Domain-Specific Analysis
- Performance on security terminology
- Rare entity recognition (CVE-specific terms)
- Multi-word entity handling

---

## Expected Outcomes

### For NER Implementation:
✅ Automated entity extraction with state-of-the-art models  
✅ Deep analysis of transformer models on security domain  
✅ Published results and model comparison  
✅ Reusable annotated dataset for security NER

### For SecurityGraphAI Project:
✅ Automated entity extraction from CVE descriptions  
✅ Enhanced knowledge graph with fine-grained entities  
✅ Foundation for relationship extraction  
✅ Improved data quality with ML-powered extraction

---

## Sample Annotation Format (BIO Tagging)

```
SQL         B-VULNERABILITY_TYPE
injection   I-VULNERABILITY_TYPE
vulnerability  O
in          O
read.php3   B-FILE
and         O
other       O
scripts     O
in          O
Phorum      B-SOFTWARE
3.0.7       B-VERSION
allows      O
remote      B-ATTACK_VECTOR
attackers   I-ATTACK_VECTOR
to          O
execute     B-IMPACT
arbitrary   I-IMPACT
SQL         I-IMPACT
queries     I-IMPACT
```

---

## Tools & Libraries

```python
# Required packages
transformers==4.35.0
datasets==2.14.0
seqeval==1.2.2
sklearn
wandb  # for experiment tracking
label-studio  # for annotation (optional)
```

---

## Project Structure

```
SecurityGraphAI/
├── ner/                          # NEW: NER Implementation
│   ├── data/
│   │   ├── annotated_cves.json   # Annotated dataset
│   │   ├── train.json
│   │   ├── val.json
│   │   └── test.json
│   ├── models/
│   │   ├── bert_ner/             # Fine-tuned BERT
│   │   └── deberta_ner/          # Fine-tuned DeBERTa
│   ├── notebooks/
│   │   ├── 01_data_annotation.ipynb
│   │   ├── 02_bert_training.ipynb
│   │   ├── 03_deberta_training.ipynb
│   │   └── 04_model_comparison.ipynb
│   ├── scripts/
│   │   ├── train_bert.py
│   │   ├── train_deberta.py
│   │   ├── evaluate.py
│   │   └── extract_entities.py
│   └── results/
│       ├── bert_metrics.json
│       ├── deberta_metrics.json
│       └── comparison_report.md
├── data/                         # Existing CVE data
└── etl/                          # Existing ETL scripts
```

---

## Timeline

| Week | Task | Deliverable |
|------|------|-------------|
| 1 | Data annotation setup | Annotation guidelines |
| 2 | Complete annotations | Labeled dataset (100-200) |
| 3 | Model training | 2 fine-tuned models |
| 4 | Evaluation | Comparison report |
| 5 | Integration | Entities extracted for all CVEs |

---

## Benefits

### Research Value:
1. Real-world security domain application
2. Meaningful comparison beyond toy datasets
3. Publishable results
4. Portfolio-worthy project

### Practical (Project):
1. Automated entity extraction pipeline
2. High-quality structured data for knowledge graph
3. Scalable to new CVE data
4. Foundation for relationship extraction

---

## Next Steps

1. **Decide on annotation strategy** (manual vs. semi-automated)
2. **Set up annotation environment**
3. **Create annotation guidelines document**
4. **Start pilot annotation (50 CVEs)**
5. **Evaluate pilot results and refine**
6. **Proceed with full annotation**

---

## References

- [HuggingFace Token Classification Tutorial](https://huggingface.co/docs/transformers/tasks/token_classification)
- [seqeval Documentation](https://github.com/chakki-works/seqeval)
- [Label Studio](https://labelstud.io/)
- [Security NER Research Papers]

---

**Author:** Panpan Lai  
**Project:** SecurityGraphAI  
**Date:** February 22, 2026  
**Status:** Proposal - Ready for Implementation
