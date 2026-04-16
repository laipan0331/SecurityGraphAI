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


# ── Step 1: Find CVEs for each technology in the stack ───────────────────────

def step1_stack_cves(technologies: list[str]) -> dict:
    """
    For each technology, find all CVEs affecting it.
    Returns: { "PHP": [cve_ids...], "Apache": [cve_ids...] }
    """
    stack_cves = {}
    for tech in technologies:
        rows = run_cypher(
            """
            MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software)
            WHERE toLower(s.name) CONTAINS toLower($tech)
            OPTIONAL MATCH (c)-[:HAS_SEVERITY]->(sev:Severity)
            RETURN c.cve_id AS cve_id,
                   c.cvss_score AS cvss_score,
                   sev.level AS severity
            ORDER BY c.cvss_score DESC
            """,
            {"tech": tech},
        )
        stack_cves[tech] = rows
    return stack_cves


# ── Step 2: Map CVEs to CWEs for each technology ─────────────────────────────

def step2_cwe_mapping(stack_cves: dict) -> dict:
    """
    For each technology, find all unique CWEs from its CVEs.
    Returns: { "PHP": ["CWE-89", "CWE-79", ...], ... }
    """
    stack_cwes = {}
    for tech, cves in stack_cves.items():
        cve_ids = [c["cve_id"] for c in cves]
        if not cve_ids:
            stack_cwes[tech] = []
            continue
        rows = run_cypher(
            """
            MATCH (c:CVE)-[:MAPS_TO]->(w:CWE)
            WHERE c.cve_id IN $cve_ids
            RETURN DISTINCT w.cwe_id AS cwe_id
            """,
            {"cve_ids": cve_ids},
        )
        stack_cwes[tech] = [r["cwe_id"] for r in rows]
    return stack_cwes


# ── Step 3: Find overlapping CWEs across the stack ───────────────────────────

def step3_overlapping_cwes(stack_cwes: dict) -> list[dict]:
    """
    Find CWEs that affect MULTIPLE technologies in the stack.
    These are the most dangerous — one weakness, multiple attack surfaces.
    """
    from collections import defaultdict
    cwe_to_techs = defaultdict(list)

    for tech, cwes in stack_cwes.items():
        for cwe in cwes:
            cwe_to_techs[cwe].append(tech)

    # Only keep CWEs that appear in 2+ technologies
    overlapping = [
        {"cwe_id": cwe, "affects_technologies": techs, "overlap_count": len(techs)}
        for cwe, techs in cwe_to_techs.items()
        if len(techs) >= 2
    ]

    return sorted(overlapping, key=lambda x: x["overlap_count"], reverse=True)


# ── Step 4: Find attack paths (multi-hop) ────────────────────────────────────

def step4_attack_paths(technologies: list[str]) -> list[dict]:
    """
    Multi-hop: Software → CVE → CWE → Defense
    Find the full attack path for each technology in the stack.
    """
    rows = run_cypher(
        """
        MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software)
        WHERE ANY(tech IN $technologies WHERE toLower(s.name) CONTAINS toLower(tech))
        MATCH (c)-[:MAPS_TO]->(w:CWE)
        OPTIONAL MATCH (c)-[:HAS_SEVERITY]->(sev:Severity)
        OPTIONAL MATCH (c)-[:HAS_ATTACK_VECTOR]->(av:AttackVector)
        RETURN s.name AS software,
               c.cve_id AS cve_id,
               c.cvss_score AS cvss_score,
               sev.level AS severity,
               av.name AS attack_vector,
               collect(DISTINCT w.cwe_id) AS cwes
        ORDER BY c.cvss_score DESC
        LIMIT 20
        """,
        {"technologies": technologies},
    )
    return rows


# ── Step 5: Prioritized defenses ─────────────────────────────────────────────

def step5_prioritized_defenses(stack_cwes: dict) -> list[dict]:
    """
    Find defenses that cover the MOST CWEs across the stack.
    Prioritize defenses by how many vulnerabilities they address.
    """
    all_cwes = list({cwe for cwes in stack_cwes.values() for cwe in cwes})
    if not all_cwes:
        return []

    rows = run_cypher(
        """
        MATCH (w:CWE)-[:MITIGATED_BY]->(d:Defense)
        WHERE w.cwe_id IN $all_cwes
        RETURN d.name AS defense,
               d.description AS description,
               collect(DISTINCT w.cwe_id) AS covers_cwes,
               count(DISTINCT w.cwe_id) AS coverage_count
        ORDER BY coverage_count DESC
        LIMIT 10
        """,
        {"all_cwes": all_cwes},
    )
    return rows


# ── Step 6: Recommended tools ─────────────────────────────────────────────────

def step6_recommended_tools(stack_cwes: dict) -> list[dict]:
    """
    Find tools that cover the most CWEs in the stack.
    """
    all_cwes = list({cwe for cwes in stack_cwes.values() for cwe in cwes})
    if not all_cwes:
        return []

    rows = run_cypher(
        """
        MATCH (w:CWE)-[:DETECTED_BY]->(t:Tool)
        WHERE w.cwe_id IN $all_cwes
        RETURN t.name AS tool,
               collect(DISTINCT w.cwe_id) AS covers_cwes,
               count(DISTINCT w.cwe_id) AS coverage_count
        ORDER BY coverage_count DESC
        """,
        {"all_cwes": all_cwes},
    )
    return rows


# ── Report generator ──────────────────────────────────────────────────────────

REPORT_PROMPT = """You are a senior cybersecurity architect. A developer has given you their tech stack
and you have analyzed it using a cybersecurity knowledge graph.

Tech Stack: {stack}

=== ANALYSIS DATA ===

1. CVEs per Technology:
{stack_cves_summary}

2. Overlapping Weaknesses (CWEs affecting multiple technologies — MOST DANGEROUS):
{overlapping_cwes}

3. Attack Paths (Software → CVE → CWE chain):
{attack_paths}

4. Prioritized Defenses (ranked by how many vulnerabilities they fix):
{defenses}

5. Recommended Security Tools:
{tools}

=== REPORT FORMAT ===
Write a remediation report with these sections:

🔴 Risk Summary
  - Total CVEs found across the stack
  - Most vulnerable technology
  - Highest severity found

⚠️  Shared Attack Surface
  - List CWEs that affect multiple technologies (these are the most critical)
  - Explain why overlapping weaknesses are dangerous

🛣️  Top Attack Paths
  - List the 3 most dangerous CVE → CWE chains in plain English
  - Include CVSS scores and attack vectors

✅ Fix Priority (ranked 1 to 5)
  - List top 5 defenses ordered by how many vulnerabilities they address
  - For each: what it fixes and how many CVEs it covers

🛠️  Security Tools to Run
  - List recommended tools and what they detect

🎯 Bottom Line
  - 2-3 sentence action plan for the developer

Be specific, practical, and prioritize by risk. No fluff.
"""

def generate_report(stack: list[str], data: dict) -> str:
    # Summarize CVEs per tech
    stack_cves_summary = "\n".join(
        f"  {tech}: {len(cves)} CVEs, "
        f"{sum(1 for c in cves if c.get('severity') == 'CRITICAL')} critical"
        for tech, cves in data["stack_cves"].items()
    )

    overlapping = "\n".join(
        f"  {o['cwe_id']} affects: {', '.join(o['affects_technologies'])} ({o['overlap_count']} technologies)"
        for o in data["overlapping_cwes"][:5]
    ) or "  No overlapping weaknesses found."

    attack_paths = "\n".join(
        f"  {r['software']} → {r['cve_id']} (CVSS {r['cvss_score']}, {r['severity']}) → {r['cwes']}"
        for r in data["attack_paths"][:5]
    ) or "  No attack paths found."

    defenses = "\n".join(
        f"  #{i+1} {d['defense']} — covers {d['coverage_count']} CWEs: {d['covers_cwes']}"
        for i, d in enumerate(data["defenses"][:5])
    ) or "  No defenses found."

    tools = "\n".join(
        f"  {t['tool']} — detects {t['coverage_count']} weakness types"
        for t in data["tools"]
    ) or "  No tools found."

    prompt = REPORT_PROMPT.format(
        stack=", ".join(stack),
        stack_cves_summary=stack_cves_summary,
        overlapping_cwes=overlapping,
        attack_paths=attack_paths,
        defenses=defenses,
        tools=tools,
    )

    response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
    return response.text.strip()


# ── Main entry point ──────────────────────────────────────────────────────────

def analyze_stack(technologies: list[str]) -> str:
    """
    Given a list of technologies, analyze the full attack surface
    and return a prioritized remediation report.
    """
    print(f"\n🔍 Analyzing stack: {', '.join(technologies)}")

    print("  Step 1/6 — Finding CVEs per technology...")
    stack_cves = step1_stack_cves(technologies)

    print("  Step 2/6 — Mapping CVEs to CWEs...")
    stack_cwes = step2_cwe_mapping(stack_cves)

    print("  Step 3/6 — Finding overlapping weaknesses...")
    overlapping_cwes = step3_overlapping_cwes(stack_cwes)

    print("  Step 4/6 — Tracing attack paths...")
    attack_paths = step4_attack_paths(technologies)

    print("  Step 5/6 — Prioritizing defenses...")
    defenses = step5_prioritized_defenses(stack_cwes)

    print("  Step 6/6 — Recommending tools...")
    tools = step6_recommended_tools(stack_cwes)

    print("  📝 Generating remediation report...\n")

    data = {
        "stack_cves": stack_cves,
        "stack_cwes": stack_cwes,
        "overlapping_cwes": overlapping_cwes,
        "attack_paths": attack_paths,
        "defenses": defenses,
        "tools": tools,
    }

    return generate_report(technologies, data)


# ── Natural Language Stack Extractor ─────────────────────────────────────────

EXTRACT_PROMPT = """You are a software stack parser. Extract only the technology names 
from the user's description. Return them as a comma-separated list with no explanation.

Examples:
Input: "I am building a web app using PHP on Apache with a MySQL database"
Output: PHP, Apache, MySQL

Input: "My app runs on Django with PostgreSQL and Redis caching"
Output: Django, PostgreSQL, Redis

Input: "We use Node.js with Express and MongoDB"
Output: Node.js, Express, MongoDB

Now extract from this:
Input: "{user_input}"
Output:"""

def extract_technologies(user_input: str) -> list[str]:
    """Use Gemini to extract technology names from natural language."""
    prompt = EXTRACT_PROMPT.format(user_input=user_input)
    response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
    raw = response.text.strip()
    technologies = [t.strip() for t in raw.split(",") if t.strip()]
    print(f"  🧠 Extracted technologies: {technologies}")
    return technologies


def analyze_stack_from_text(user_input: str) -> str:
    """
    Accept natural language description of a tech stack,
    extract technologies, then run full attack path analysis.
    """
    print(f"\n📝 Input: {user_input}")
    print("  Step 0 — Extracting technologies from text...")
    technologies = extract_technologies(user_input)

    if not technologies:
        return "❌ Could not extract any technologies from your description. Please try again."

    return analyze_stack(technologies)


# ── Test ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Test natural language input
    inputs = [
        "I am building a web app using PHP on Apache with a MySQL database",
        "My application runs on Cisco hardware with Linux servers",
    ]
    for user_input in inputs:
        print("=" * 65)
        report = analyze_stack_from_text(user_input)
        print(report)
        print()