import os
import time
import requests
from bs4 import BeautifulSoup
from neo4j import GraphDatabase
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME") or os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# ── CWE → OWASP Cheat Sheet mapping ──────────────────────────────────────────
# Each entry: cwe_id, cheat_sheet_url, fallback_defenses (used if scraping fails)
CWE_CHEATSHEET_MAP = [
    {
        "cwe_id": "CWE-79",
        "label": "Cross-Site Scripting (XSS)",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    },
    {
        "cwe_id": "CWE-89",
        "label": "SQL Injection",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    },
    {
        "cwe_id": "CWE-352",
        "label": "Cross-Site Request Forgery (CSRF)",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    },
    {
        "cwe_id": "CWE-287",
        "label": "Improper Authentication",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    },
    {
        "cwe_id": "CWE-284",
        "label": "Improper Access Control",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
    },
    {
        "cwe_id": "CWE-327",
        "label": "Broken Cryptography",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
    },
    {
        "cwe_id": "CWE-94",
        "label": "Code Injection",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
    },
    {
        "cwe_id": "CWE-611",
        "label": "XXE Injection",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    },
    {
        "cwe_id": "CWE-918",
        "label": "Server-Side Request Forgery (SSRF)",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    },
    {
        "cwe_id": "CWE-522",
        "label": "Insufficiently Protected Credentials",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    },
]

# ── Known security tools per CWE ─────────────────────────────────────────────
CWE_TOOLS_MAP = {
    "CWE-79":  ["Burp Suite", "OWASP ZAP", "DOMPurify", "CSP Evaluator"],
    "CWE-89":  ["Burp Suite", "sqlmap", "OWASP ZAP", "SonarQube"],
    "CWE-352": ["Burp Suite", "OWASP ZAP", "CSRFTester"],
    "CWE-287": ["OWASP ZAP", "Hydra", "Burp Suite"],
    "CWE-284": ["SonarQube", "Checkmarx", "OWASP ZAP"],
    "CWE-327": ["SSL Labs", "Nessus", "OpenSSL"],
    "CWE-94":  ["Burp Suite", "Semgrep", "SonarQube"],
    "CWE-611": ["Burp Suite", "OWASP ZAP", "XMLSec"],
    "CWE-918": ["Burp Suite", "OWASP ZAP", "Nessus"],
    "CWE-522": ["Hashcat", "John the Ripper", "Nessus"],
}

# ── Scraper ───────────────────────────────────────────────────────────────────

def scrape_cheatsheet(url: str, label: str) -> list[dict]:
    """
    Scrapes an OWASP cheat sheet page and returns a list of Defense dicts.
    Each h2/h3 section with meaningful content becomes one Defense node.
    """
    headers = {"User-Agent": "SecurityGraphAI-Scraper/1.0"}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        print(f"  ⚠  Could not fetch {url}: {e}")
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    defenses = []
    seen = set()

    # Walk all h2 / h3 headings — each is a distinct defense technique
    for heading in soup.find_all(["h2", "h3"]):
        title = heading.get_text(strip=True)

        # Skip nav/meta sections
        skip_keywords = ["table of content", "introduction", "references",
                         "authors", "related", "revision", "background",
                         "overview", "primary defense", "additional defense"]
        if any(k in title.lower() for k in skip_keywords):
            continue
        if len(title) < 5 or title.lower() in seen:
            continue
        seen.add(title.lower())

        # Grab the first paragraph after the heading as the description
        description = ""
        sibling = heading.find_next_sibling()
        while sibling:
            if sibling.name in ["h2", "h3"]:
                break
            if sibling.name == "p":
                text = sibling.get_text(strip=True)
                if len(text) > 30:
                    description = text[:500]   # cap at 500 chars
                    break
            sibling = sibling.find_next_sibling()

        if not description:
            continue

        defense_id = f"DEF-{label}-{len(defenses)+1:02d}"
        defenses.append({
            "defense_id": defense_id,
            "name": title,
            "description": description,
            "source_url": url,
        })

    print(f"  ✅ Scraped {len(defenses)} defenses from: {label}")
    return defenses


# ── Neo4j loaders ─────────────────────────────────────────────────────────────

def create_constraints(session):
    queries = [
        "CREATE CONSTRAINT defense_id_unique IF NOT EXISTS FOR (d:Defense) REQUIRE d.defense_id IS UNIQUE",
        "CREATE CONSTRAINT tool_name_unique   IF NOT EXISTS FOR (t:Tool)    REQUIRE t.name IS UNIQUE",
    ]
    for q in queries:
        session.run(q)
    print("✅ Constraints created for Defense and Tool nodes")


def load_defense_node(session, defense: dict):
    session.run(
        """
        MERGE (d:Defense {defense_id: $defense_id})
        SET d.name        = $name,
            d.description = $description,
            d.source_url  = $source_url
        """,
        **defense,
    )


def load_tool_node(session, tool_name: str):
    session.run(
        "MERGE (t:Tool {name: $name})",
        name=tool_name,
    )


def link_cwe_to_defense(session, cwe_id: str, defense_id: str):
    session.run(
        """
        MERGE (w:CWE {cwe_id: $cwe_id})
        WITH w
        MATCH (d:Defense {defense_id: $defense_id})
        MERGE (w)-[:MITIGATED_BY]->(d)
        """,
        cwe_id=cwe_id,
        defense_id=defense_id,
    )


def link_cwe_to_tool(session, cwe_id: str, tool_name: str):
    session.run(
        """
        MERGE (w:CWE {cwe_id: $cwe_id})
        WITH w
        MATCH (t:Tool {name: $tool_name})
        MERGE (w)-[:DETECTED_BY]->(t)
        """,
        cwe_id=cwe_id,
        tool_name=tool_name,
    )


def show_stats(session):
    result = session.run("""
        MATCH (d:Defense)        WITH count(d) AS defenses
        MATCH (t:Tool)           WITH defenses, count(t) AS tools
        MATCH ()-[:MITIGATED_BY]->() WITH defenses, tools, count(*) AS mit
        MATCH ()-[:DETECTED_BY]->()  RETURN defenses, tools, mit, count(*) AS det
    """)
    row = result.single()
    if row:
        print(f"\n📊 Stats: {row['defenses']} Defense nodes | {row['tools']} Tool nodes")
        print(f"         {row['mit']} MITIGATED_BY rels | {row['det']} DETECTED_BY rels")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if not (NEO4J_URI and NEO4J_USERNAME and NEO4J_PASSWORD):
        raise ValueError("Neo4j connection info missing. Check your .env file.")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
    driver.verify_connectivity()

    print("=" * 55)
    print("🔐 SecurityGraph AI — OWASP Defense & Tool Loader")
    print("=" * 55)

    with driver.session() as session:
        create_constraints(session)

        for entry in CWE_CHEATSHEET_MAP:
            cwe_id = entry["cwe_id"]
            label  = entry["label"]
            url    = entry["url"]

            print(f"\n[{cwe_id}] {label}")

            # 1. Scrape defenses from OWASP cheat sheet
            defenses = scrape_cheatsheet(url, label)
            for defense in defenses:
                load_defense_node(session, defense)
                link_cwe_to_defense(session, cwe_id, defense["defense_id"])

            # 2. Load tools and link to CWE
            tools = CWE_TOOLS_MAP.get(cwe_id, [])
            for tool_name in tools:
                load_tool_node(session, tool_name)
                link_cwe_to_tool(session, cwe_id, tool_name)
            print(f"  ✅ Linked {len(tools)} tools: {tools}")

            time.sleep(1)   # be polite to OWASP servers

        show_stats(session)

    driver.close()
    print("\n✅ OWASP Defense & Tool data successfully loaded!")


if __name__ == "__main__":
    main()