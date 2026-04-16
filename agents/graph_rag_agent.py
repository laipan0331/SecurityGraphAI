import os
from neo4j import GraphDatabase
from dotenv import load_dotenv
from google import genai

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))

NEO4J_URI      = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME") or os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

client       = genai.Client(api_key=GEMINI_API_KEY)
GEMINI_MODEL = "gemini-2.5-flash"

MAX_RETRIES = 3

# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA = """
Nodes:
  - CVE          { cve_id, description, cvss_score, published_date }
  - CWE          { cwe_id }
  - Severity     { level }             -- values: CRITICAL, HIGH, MEDIUM, LOW
  - Software     { name }
  - Version      { value }
  - VulnerabilityType { name }
  - AttackVector { name }              -- e.g. Remote, Local, Physical, Network
  - Year         { value }
  - Defense      { defense_id, name, description, source_url }
  - Tool         { name }              -- e.g. Burp Suite, sqlmap, OWASP ZAP

Relationships:
  (CVE)-[:HAS_SEVERITY]           ->(Severity)
  (CVE)-[:MAPS_TO]                ->(CWE)
  (CVE)-[:AFFECTS_SOFTWARE]       ->(Software)
  (CVE)-[:AFFECTS_VERSION]        ->(Version)
  (Software)-[:HAS_VERSION]       ->(Version)
  (CVE)-[:HAS_VULNERABILITY_TYPE] ->(VulnerabilityType)
  (CVE)-[:HAS_ATTACK_VECTOR]      ->(AttackVector)
  (CVE)-[:PUBLISHED_IN]           ->(Year)
  (CWE)-[:MITIGATED_BY]           ->(Defense)
  (CWE)-[:DETECTED_BY]            ->(Tool)
"""

# ── Few-shot examples ─────────────────────────────────────────────────────────
FEW_SHOT_EXAMPLES = """
Q: How many critical CVEs are there?
A: MATCH (c:CVE)-[:HAS_SEVERITY]->(s:Severity {level: 'CRITICAL'}) RETURN count(c) AS critical_count

Q: List CVEs affecting Apache software.
A: MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software) WHERE toLower(s.name) CONTAINS 'apache' RETURN c.cve_id, c.description LIMIT 20

Q: Which software has the most vulnerabilities?
A: MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software) RETURN s.name AS software, count(c) AS vuln_count ORDER BY vuln_count DESC LIMIT 10

Q: Show me CVEs with CVSS score above 9.
A: MATCH (c:CVE) WHERE c.cvss_score >= 9 RETURN c.cve_id, c.cvss_score, c.description ORDER BY c.cvss_score DESC LIMIT 20

Q: What are the most common CWE weaknesses?
A: MATCH (c:CVE)-[:MAPS_TO]->(w:CWE) RETURN w.cwe_id AS cwe, count(c) AS count ORDER BY count DESC LIMIT 10

Q: How many CVEs were published in 2023?
A: MATCH (c:CVE)-[:PUBLISHED_IN]->(y:Year {value: '2023'}) RETURN count(c) AS count

Q: Which CVEs use a network attack vector?
A: MATCH (c:CVE)-[:HAS_ATTACK_VECTOR]->(a:AttackVector) WHERE toLower(a.name) CONTAINS 'network' RETURN c.cve_id, c.description LIMIT 20

Q: What vulnerability types are most common?
A: MATCH (c:CVE)-[:HAS_VULNERABILITY_TYPE]->(v:VulnerabilityType) RETURN v.name AS type, count(c) AS count ORDER BY count DESC LIMIT 10

Q: Show critical CVEs affecting Linux.
A: MATCH (c:CVE)-[:HAS_SEVERITY]->(s:Severity {level: 'CRITICAL'}), (c)-[:AFFECTS_SOFTWARE]->(sw:Software) WHERE toLower(sw.name) CONTAINS 'linux' RETURN c.cve_id, c.description LIMIT 20

Q: Which CVEs are related to SQL injection?
A: MATCH (c:CVE)-[:HAS_VULNERABILITY_TYPE]->(v:VulnerabilityType) WHERE toLower(v.name) CONTAINS 'sql' RETURN c.cve_id, c.description LIMIT 20

Q: How do I prevent XSS attacks?
A: MATCH (w:CWE {cwe_id: 'CWE-79'})-[:MITIGATED_BY]->(d:Defense) RETURN d.name AS defense, d.description AS description

Q: What are the defenses for SQL injection?
A: MATCH (w:CWE {cwe_id: 'CWE-89'})-[:MITIGATED_BY]->(d:Defense) RETURN d.name AS defense, d.description AS description

Q: What tools can detect XSS?
A: MATCH (w:CWE {cwe_id: 'CWE-79'})-[:DETECTED_BY]->(t:Tool) RETURN t.name AS tool

Q: What tools detect SQL injection?
A: MATCH (w:CWE {cwe_id: 'CWE-89'})-[:DETECTED_BY]->(t:Tool) RETURN t.name AS tool

Q: How do I fix CSRF vulnerabilities?
A: MATCH (w:CWE {cwe_id: 'CWE-352'})-[:MITIGATED_BY]->(d:Defense) RETURN d.name AS defense, d.description AS description

Q: What defenses exist for authentication issues?
A: MATCH (w:CWE {cwe_id: 'CWE-287'})-[:MITIGATED_BY]->(d:Defense) RETURN d.name AS defense, d.description AS description

Q: What tools are available for security testing?
A: MATCH (t:Tool) RETURN t.name AS tool

Q: Which CWEs have the most defenses?
A: MATCH (w:CWE)-[:MITIGATED_BY]->(d:Defense) RETURN w.cwe_id AS cwe, count(d) AS defense_count ORDER BY defense_count DESC LIMIT 10

Q: Show me everything about CWE-79.
A: MATCH (w:CWE {cwe_id: 'CWE-79'}) OPTIONAL MATCH (w)-[:MITIGATED_BY]->(d:Defense) OPTIONAL MATCH (w)-[:DETECTED_BY]->(t:Tool) OPTIONAL MATCH (c:CVE)-[:MAPS_TO]->(w) RETURN w.cwe_id, collect(DISTINCT d.name) AS defenses, collect(DISTINCT t.name) AS tools, count(DISTINCT c) AS cve_count

Q: What tools should I use to secure my PHP application?
A: MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software) WHERE toLower(s.name) CONTAINS 'php' WITH c MATCH (c)-[:MAPS_TO]->(w:CWE)-[:DETECTED_BY]->(t:Tool) RETURN DISTINCT t.name AS tool, collect(DISTINCT w.cwe_id) AS covers_cwes

Q: What defenses should I apply to protect Apache from its known vulnerabilities?
A: MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software) WHERE toLower(s.name) CONTAINS 'apache' WITH c MATCH (c)-[:MAPS_TO]->(w:CWE)-[:MITIGATED_BY]->(d:Defense) RETURN DISTINCT d.name AS defense, d.description AS description, collect(DISTINCT w.cwe_id) AS related_cwes LIMIT 20

Q: Which critical CVEs can be detected by Burp Suite?
A: MATCH (c:CVE)-[:HAS_SEVERITY]->(s:Severity {level: 'CRITICAL'}) WITH c MATCH (c)-[:MAPS_TO]->(w:CWE)-[:DETECTED_BY]->(t:Tool {name: 'Burp Suite'}) RETURN DISTINCT c.cve_id AS cve, c.description AS description, w.cwe_id AS cwe

Q: What are the common weaknesses in Cisco products and how do I fix them?
A: MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software) WHERE toLower(s.name) CONTAINS 'cisco' WITH c MATCH (c)-[:MAPS_TO]->(w:CWE)-[:MITIGATED_BY]->(d:Defense) RETURN DISTINCT w.cwe_id AS cwe, collect(DISTINCT d.name) AS defenses LIMIT 20

Q: Which software has both critical CVEs and known defenses?
A: MATCH (c:CVE)-[:HAS_SEVERITY]->(s:Severity {level: 'CRITICAL'}) MATCH (c)-[:AFFECTS_SOFTWARE]->(sw:Software) MATCH (c)-[:MAPS_TO]->(w:CWE)-[:MITIGATED_BY]->(d:Defense) RETURN DISTINCT sw.name AS software, count(DISTINCT c) AS critical_cves, count(DISTINCT d) AS available_defenses ORDER BY critical_cves DESC LIMIT 10

Q: What is the full attack and defense profile of SQL injection?
A: MATCH (c:CVE)-[:HAS_VULNERABILITY_TYPE]->(v:VulnerabilityType) WHERE toLower(v.name) CONTAINS 'sql' WITH c MATCH (c)-[:MAPS_TO]->(w:CWE) OPTIONAL MATCH (w)-[:MITIGATED_BY]->(d:Defense) OPTIONAL MATCH (w)-[:DETECTED_BY]->(t:Tool) RETURN collect(DISTINCT c.cve_id) AS cves, collect(DISTINCT w.cwe_id) AS cwes, collect(DISTINCT d.name) AS defenses, collect(DISTINCT t.name) AS tools
"""

# ── Prompt templates ──────────────────────────────────────────────────────────
CYPHER_PROMPT_TEMPLATE = """You are an expert in Neo4j Cypher queries for a cybersecurity knowledge graph.

Graph Schema:
{schema}

Few-shot examples:
{examples}

Rules:
- Return ONLY the raw Cypher query — no explanation, no markdown, no code fences.
- Use LIMIT 20 unless the question asks for counts or aggregations.
- Use toLower() for case-insensitive string matching.
- Only use nodes and relationships defined in the schema above.
- For prevention/defense questions, traverse (CWE)-[:MITIGATED_BY]->(Defense).
- For detection/tool questions, traverse (CWE)-[:DETECTED_BY]->(Tool).
- For multi-hop questions, chain relationships like (CVE)-[:AFFECTS_SOFTWARE]->(Software) and (CVE)-[:MAPS_TO]->(CWE)-[:MITIGATED_BY]->(Defense).

Question: {question}
Cypher:"""

RETRY_PROMPT_TEMPLATE = """You are an expert in Neo4j Cypher queries. The previous query failed with an error.

Graph Schema:
{schema}

Original question: {question}
Failed Cypher query: {failed_cypher}
Error message: {error}

Fix the Cypher query. Return ONLY the corrected raw Cypher — no explanation, no markdown, no code fences.
Cypher:"""

ANSWER_PROMPT_TEMPLATE = """You are a cybersecurity expert. A user asked a question about a vulnerability knowledge graph.

Question: {question}

The database returned these results:
{results}

Provide a clear, concise natural language answer. If the results are empty, say no matching data was found.
"""

# ── Core functions ────────────────────────────────────────────────────────────

def clean_cypher(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = "\n".join(
            line for line in text.splitlines()
            if not line.startswith("```")
        ).strip()
    return text


def generate_cypher(question: str) -> str:
    prompt = CYPHER_PROMPT_TEMPLATE.format(
        schema=SCHEMA,
        examples=FEW_SHOT_EXAMPLES,
        question=question,
    )
    response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
    return clean_cypher(response.text)


def fix_cypher(question: str, failed_cypher: str, error: str) -> str:
    prompt = RETRY_PROMPT_TEMPLATE.format(
        schema=SCHEMA,
        question=question,
        failed_cypher=failed_cypher,
        error=error,
    )
    response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
    return clean_cypher(response.text)


def run_cypher(cypher: str) -> list[dict]:
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            result = session.run(cypher)
            return [dict(record) for record in result]
    finally:
        driver.close()


def generate_answer(question: str, results: list[dict]) -> str:
    results_text = "\n".join(str(r) for r in results) if results else "No results found."
    prompt = ANSWER_PROMPT_TEMPLATE.format(question=question, results=results_text)
    response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
    return response.text.strip()


# ── Main ask() with retry logic ───────────────────────────────────────────────

def ask(question: str) -> str:
    print(f"\nQuestion: {question}")

    cypher = generate_cypher(question)
    print(f"Generated Cypher:\n{cypher}\n")

    results = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            results = run_cypher(cypher)
            print(f"Raw results ({len(results)} records): {results[:3]}{'...' if len(results) > 3 else ''}\n")
            break
        except Exception as e:
            error_msg = str(e)
            print(f"  ⚠ Attempt {attempt} failed: {error_msg}")
            if attempt < MAX_RETRIES:
                print(f"  🔄 Asking Gemini to fix the query...")
                cypher = fix_cypher(question, cypher, error_msg)
                print(f"  Fixed Cypher:\n{cypher}\n")
            else:
                return (
                    f"Could not execute a valid Cypher query after {MAX_RETRIES} attempts.\n"
                    f"Last error: {error_msg}\n"
                    f"Last query:\n{cypher}"
                )

    if not results:
        return "No matching data found in the knowledge graph for your question."

    return generate_answer(question, results)


# ── Test ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    questions = [
        "How do I prevent XSS attacks?",
        "What tools should I use to secure my PHP application?",
        "What are the common weaknesses in Cisco products and how do I fix them?",
        "Which software has both critical CVEs and known defenses?",
        "What is the full attack and defense profile of SQL injection?",
    ]
    for q in questions:
        print("=" * 60)
        print(f"Answer: {ask(q)}")