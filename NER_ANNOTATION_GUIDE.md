# 🏷️ Quick Start: CVE NER Annotation Guide

## Entity Annotation Guidelines

### Entity Types & Examples

#### 1. SOFTWARE (Software/Library/Framework names)
```
Phorum, phpBB, Oracle, PostgreSQL, Bugzilla, Apache, MySQL
```

#### 2. VERSION (Version numbers)
```
3.0.7, 1.4.2, 2.14, 0.62
```

#### 3. VULNERABILITY_TYPE (Type of security vulnerability)
```
SQL injection, cross-site scripting (XSS), buffer overflow, 
authentication bypass, privilege escalation, remote code execution
```

#### 4. FILE (File or script names)
```
read.php3, prefs.php, article.php, reports.cgi
```

#### 5. ATTACK_VECTOR (How the attack is performed)
```
remote attackers, authenticated users, local users
```

#### 6. COMPONENT (System component or module)
```
mod_sql, authentication modules, query string
```

#### 7. IMPACT (What the attacker can achieve)
```
execute arbitrary SQL, bypass authentication, gain administrative access
```

---

## Annotation Example

**Original CVE:**
```
SQL injection vulnerability in read.php3 and other scripts in Phorum 3.0.7 
allows remote attackers to execute arbitrary SQL queries via the sSQL parameter.
```

**Annotated (BIO Format):**
```
Token              | Label
-------------------|----------------------
SQL                | B-VULNERABILITY_TYPE
injection          | I-VULNERABILITY_TYPE
vulnerability      | O
in                 | O
read.php3          | B-FILE
and                | O
other              | O
scripts            | O
in                 | O
Phorum             | B-SOFTWARE
3.0.7              | B-VERSION
allows             | O
remote             | B-ATTACK_VECTOR
attackers          | I-ATTACK_VECTOR
to                 | O
execute            | B-IMPACT
arbitrary          | I-IMPACT
SQL                | I-IMPACT
queries            | I-IMPACT
via                | O
the                | O
sSQL               | B-COMPONENT
parameter          | I-COMPONENT
.                  | O
```

---

## Sample Python Script to Export CVEs for Annotation

```python
import pandas as pd
import json

# Load CVE data
df = pd.read_csv('data/processed_cves.csv')

# Prepare for annotation
annotation_data = []
for idx, row in df.iterrows():
    annotation_data.append({
        'id': idx,
        'cve_id': row['cve_id'],
        'text': row['description'],
        'meta': {
            'severity': row['severity'],
            'cvss_score': row['cvss_score']
        }
    })

# Export to JSON for Label Studio or Doccano
with open('ner/data/cves_to_annotate.json', 'w') as f:
    json.dump(annotation_data, f, indent=2)

print(f"Exported {len(annotation_data)} CVEs for annotation")
```

---

## Recommended Annotation Tool Setup

### Option 1: Label Studio (Recommended)

1. **Install:**
```bash
pip install label-studio
```

2. **Start:**
```bash
label-studio start
```

3. **Configuration (XML):**
```xml
<View>
  <Labels name="label" toName="text">
    <Label value="SOFTWARE" background="blue"/>
    <Label value="VERSION" background="green"/>
    <Label value="VULNERABILITY_TYPE" background="red"/>
    <Label value="FILE" background="orange"/>
    <Label value="ATTACK_VECTOR" background="purple"/>
    <Label value="COMPONENT" background="cyan"/>
    <Label value="IMPACT" background="yellow"/>
  </Labels>
  <Text name="text" value="$text"/>
</View>
```

### Option 2: Doccano

1. **Install:**
```bash
pip install doccano
```

2. **Initialize:**
```bash
doccano init
doccano createuser --username admin --password pass
```

3. **Start:**
```bash
doccano webserver --port 8000
```

---

## Annotation Best Practices

1. **Be Consistent**
   - Always mark "SQL injection" as VULNERABILITY_TYPE
   - Always mark version numbers as VERSION

2. **Full Entity Span**
   - Correct: [SQL injection]_VULNERABILITY_TYPE
   - Incorrect: [SQL]_VULNERABILITY_TYPE injection

3. **Multi-word Entities**
   - "remote attackers" → B-ATTACK_VECTOR I-ATTACK_VECTOR
   - "cross-site scripting" → B-VULN I-VULN I-VULN

4. **Nested Entities - Choose Most Specific**
   - "Oracle Internet Application Server" → SOFTWARE (not separate)
   - "mod_auth_pgsql 0.9.5" → COMPONENT + VERSION (separate)

5. **Ambiguous Cases**
   - "PostgreSQL" alone → SOFTWARE
   - "PostgreSQL authentication modules" → COMPONENT

---

## Quality Checklist

Before submitting annotations:
- [ ] All software names tagged as SOFTWARE
- [ ] All version numbers tagged as VERSION  
- [ ] All vulnerability types identified
- [ ] File names properly tagged
- [ ] Attack vectors marked
- [ ] No overlapping entities
- [ ] Consistent multi-word entity handling

---

## Expected Annotation Time

- **Simple CVE** (1 sentence): ~2-3 minutes
- **Complex CVE** (multiple sentences): ~5-7 minutes
- **Target:** 100 CVEs = ~6-10 hours total

---

## After Annotation: Export Format

**Label Studio Export (JSON):**
```json
{
  "id": 1,
  "text": "SQL injection vulnerability in read.php3...",
  "labels": [
    {
      "start": 0,
      "end": 13,
      "text": "SQL injection",
      "label": "VULNERABILITY_TYPE"
    },
    {
      "start": 32,
      "end": 41,
      "text": "read.php3",
      "label": "FILE"
    }
  ]
}
```

**Convert to HuggingFace Format:**
```python
# See convert_annotations.py script in ner/scripts/
```

---

**Ready to start?** Follow the NER_ASSIGNMENT_PROPOSAL.md for full implementation plan.
