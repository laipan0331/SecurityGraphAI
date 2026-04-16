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


# ── Neo4j helper ──────────────────────────────────────────────────────────────

def run_cypher(cypher: str, params: dict = {}) -> list[dict]:
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            result = session.run(cypher, **params)
            return [dict(record) for record in result]
    finally:
        driver.close()


# ── Investigation steps ───────────────────────────────────────────────────────

def step1_cve_details(cve_id: str) -> dict:
    """Get basic CVE info — description, CVSS score, severity, published date."""
    rows = run_cypher(
        """
        MATCH (c:CVE {cve_id: $cve_id})
        OPTIONAL MATCH (c)-[:HAS_SEVERITY]->(s:Severity)
        OPTIONAL MATCH (c)-[:PUBLISHED_IN]->(y:Year)
        RETURN c.description  AS description,
               c.cvss_score   AS cvss_score,
               s.level        AS severity,
               y.value        AS year
        """,
        {"cve_id": cve_id},
    )
    return rows[0] if rows else {}


def step2_cwe_mapping(cve_id: str) -> list[str]:
    """Find all CWEs this CVE maps to."""
    rows = run_cypher(
        """
        MATCH (c:CVE {cve_id: $cve_id})-[:MAPS_TO]->(w:CWE)
        RETURN w.cwe_id AS cwe_id
        """,
        {"cve_id": cve_id},
    )
    return [r["cwe_id"] for r in rows]


def step3_affected_software(cve_id: str) -> list[str]:
    """Find all software affected by this CVE."""
    rows = run_cypher(
        """
        MATCH (c:CVE {cve_id: $cve_id})-[:AFFECTS_SOFTWARE]->(s:Software)
        RETURN s.name AS software
        """,
        {"cve_id": cve_id},
    )
    return [r["software"] for r in rows]


def step4_defenses(cwe_ids: list[str]) -> list[dict]:
    """Find all defenses for the given CWEs."""
    if not cwe_ids:
        return []
    rows = run_cypher(
        """
        MATCH (w:CWE)-[:MITIGATED_BY]->(d:Defense)
        WHERE w.cwe_id IN $cwe_ids
        RETURN w.cwe_id AS cwe_id, d.name AS defense, d.description AS description
        ORDER BY w.cwe_id
        """,
        {"cwe_ids": cwe_ids},
    )
    return rows


def step5_tools(cwe_ids: list[str]) -> list[str]:
    """Find all detection tools for the given CWEs."""
    if not cwe_ids:
        return []
    rows = run_cypher(
        """
        MATCH (w:CWE)-[:DETECTED_BY]->(t:Tool)
        WHERE w.cwe_id IN $cwe_ids
        RETURN DISTINCT t.name AS tool
        """,
        {"cwe_ids": cwe_ids},
    )
    return [r["tool"] for r in rows]


def step6_multihop_profile(cve_id: str, cwe_ids: list[str]) -> dict:
    """
    Multi-hop: CVE → Software + CVE → CWE → Defense + CWE → Tool
    Gets the full attack/defense profile in one traversal.
    """
    if not cwe_ids:
        return {"software_defenses": [], "software_tools": []}

    # Which defenses apply to the software affected by this CVE via its CWEs
    software_defenses = run_cypher(
        """
        MATCH (c:CVE {cve_id: $cve_id})-[:AFFECTS_SOFTWARE]->(s:Software)
        MATCH (c)-[:MAPS_TO]->(w:CWE)-[:MITIGATED_BY]->(d:Defense)
        RETURN DISTINCT s.name AS software, w.cwe_id AS cwe, d.name AS defense
        LIMIT 10
        """,
        {"cve_id": cve_id},
    )

    # Which tools can detect issues in the affected software via its CWEs
    software_tools = run_cypher(
        """
        MATCH (c:CVE {cve_id: $cve_id})-[:AFFECTS_SOFTWARE]->(s:Software)
        MATCH (c)-[:MAPS_TO]->(w:CWE)-[:DETECTED_BY]->(t:Tool)
        RETURN DISTINCT s.name AS software, t.name AS tool
        """,
        {"cve_id": cve_id},
    )

    return {
        "software_defenses": software_defenses,
        "software_tools": software_tools,
    }


def step7_attack_vector(cve_id: str) -> str | None:
    """Get the attack vector for this CVE."""
    rows = run_cypher(
        """
        MATCH (c:CVE {cve_id: $cve_id})-[:HAS_ATTACK_VECTOR]->(a:AttackVector)
        RETURN a.name AS attack_vector
        """,
        {"cve_id": cve_id},
    )
    return rows[0]["attack_vector"] if rows else None


# ── Report generator ──────────────────────────────────────────────────────────

REPORT_PROMPT = """You are a senior cybersecurity analyst. Based on the investigation data below,
write a clear and structured security report for a developer audience.

CVE ID: {cve_id}

=== INVESTIGATION DATA ===

1. CVE Details:
{cve_details}

2. Weakness Categories (CWEs):
{cwes}

3. Affected Software:
{software}

4. Attack Vector:
{attack_vector}

5. Recommended Defenses:
{defenses}

6. Detection Tools:
{tools}

7. Multi-hop Profile (Software → CWE → Defense/Tool):
{multihop}

=== REPORT FORMAT ===
Write the report with these sections:
- Summary (2-3 sentences about what this CVE is)
- Severity Assessment (CVSS score, severity level, attack vector explanation)
- Affected Systems (what software/versions are at risk)
- Root Cause (which CWEs are involved and what they mean)
- How to Fix It (top 5 most important defenses, clearly explained)
- How to Detect It (which tools to use and how)
- Multi-hop Insight (what the graph reveals by connecting software → weakness → defense in one traversal)
- Recommended Action (1-2 sentence bottom line for developers)

Be concise, practical, and developer-friendly. No fluff.
"""

def generate_report(cve_id: str, data: dict) -> str:
    defenses_text = "\n".join(
        f"  [{d['cwe_id']}] {d['defense']}: {d['description'][:150]}..."
        for d in data["defenses"][:10]
    ) or "No defenses found in graph."

    prompt = REPORT_PROMPT.format(
        cve_id=cve_id,
        cve_details=data["cve_details"],
        cwes=", ".join(data["cwes"]) or "None found",
        software=", ".join(data["software"]) or "None found",
        attack_vector=data["attack_vector"] or "Unknown",
        defenses=defenses_text,
        tools=", ".join(data["tools"]) or "No tools found",
        multihop=str(data["multihop"]) if data["multihop"] else "No multi-hop data found.",
    )

    response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
    return response.text.strip()


# ── Main investigator ─────────────────────────────────────────────────────────

def investigate(cve_id: str) -> str:
    cve_id = cve_id.strip().upper()
    print(f"\n🔍 Investigating {cve_id}...")

    print("  Step 1/7 — Fetching CVE details...")
    cve_details = step1_cve_details(cve_id)
    if not cve_details:
        return f"❌ CVE '{cve_id}' not found in the knowledge graph."

    print("  Step 2/7 — Finding CWE mappings...")
    cwes = step2_cwe_mapping(cve_id)

    print("  Step 3/7 — Finding affected software...")
    software = step3_affected_software(cve_id)

    print("  Step 4/7 — Fetching defenses...")
    defenses = step4_defenses(cwes)

    print("  Step 5/7 — Finding detection tools...")
    tools = step5_tools(cwes)

    print("  Step 6/7 — Multi-hop profile (software + CWE + defense)...")
    multihop = step6_multihop_profile(cve_id, cwes)

    print("  Step 7/7 — Getting attack vector...")
    attack_vector = step7_attack_vector(cve_id)

    print("  📝 Generating security report...\n")

    data = {
        "cve_details": cve_details,
        "cwes": cwes,
        "software": software,
        "defenses": defenses,
        "tools": tools,
        "attack_vector": attack_vector,
        "multihop": multihop,
    }

    return generate_report(cve_id, data)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_cves = ["CVE-2019-11030", "CVE-2001-0537"]

    for cve_id in test_cves:
        print("=" * 65)
        report = investigate(cve_id)
        print(report)
        print()