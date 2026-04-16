import os
import re
import time
import schedule
import requests
from datetime import datetime, timedelta, timezone
from neo4j import GraphDatabase
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))

NEO4J_URI      = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME") or os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NVD_API_KEY    = os.getenv("NVD_API_KEY", "")   # optional but recommended

NVD_API_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FETCH_INTERVAL = 6       # hours between each fetch
LOOKBACK_HOURS = 6       # how far back to look for new CVEs each run
MAX_RESULTS    = 100     # max CVEs to pull per run

# ── NVD API fetcher ───────────────────────────────────────────────────────────

def fetch_recent_cves(hours_back: int = LOOKBACK_HOURS) -> list[dict]:
    """Fetch CVEs published in the last N hours from NVD API."""
    now       = datetime.now(timezone.utc)
    start     = now - timedelta(hours=hours_back)

    # NVD requires this exact format
    pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {
        "pubStartDate": pub_start,
        "pubEndDate":   pub_end,
        "resultsPerPage": MAX_RESULTS,
    }

    try:
        resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        print(f"  📡 NVD returned {len(vulns)} new CVEs (last {hours_back}h)")
        return vulns
    except Exception as e:
        print(f"  ❌ NVD API error: {e}")
        return []


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_severity(metrics: dict) -> str | None:
    """Extract severity level from CVSS metrics."""
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        entries = metrics.get(version, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseSeverity") or _score_to_severity(data.get("baseScore"))
    return None

def _score_to_severity(score) -> str | None:
    if score is None:
        return None
    score = float(score)
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"

def parse_cvss_score(metrics: dict) -> float | None:
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        entries = metrics.get(version, [])
        if entries:
            return entries[0].get("cvssData", {}).get("baseScore")
    return None

def parse_attack_vector(metrics: dict) -> str | None:
    for version in ["cvssMetricV31", "cvssMetricV30"]:
        entries = metrics.get(version, [])
        if entries:
            av = entries[0].get("cvssData", {}).get("attackVector", "")
            return av.capitalize() if av else None
    return None

def parse_cwes(weaknesses: list) -> list[str]:
    cwe_ids = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
    return list(set(cwe_ids))

def parse_software(configurations: list) -> list[str]:
    software = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) >= 5:
                    product = parts[4].replace("_", " ").title()
                    if product and product not in software:
                        software.append(product)
    return software[:5]   # cap at 5 software per CVE

def parse_year(published: str) -> str | None:
    if published and len(published) >= 4:
        return published[:4]
    return None


# ── Neo4j loader ──────────────────────────────────────────────────────────────

def load_cve_to_neo4j(session, cve_data: dict) -> bool:
    """Parse one NVD vulnerability entry and load it into Neo4j."""
    try:
        cve       = cve_data.get("cve", {})
        cve_id    = cve.get("id")
        if not cve_id:
            return False

        # Description (English only)
        descriptions = cve.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        metrics       = cve.get("metrics", {})
        cvss_score    = parse_cvss_score(metrics)
        severity      = parse_severity(metrics)
        attack_vector = parse_attack_vector(metrics)
        published     = cve.get("published", "")
        year          = parse_year(published)
        cwes          = parse_cwes(cve.get("weaknesses", []))
        software_list = parse_software(cve.get("configurations", []))

        # Merge CVE node
        session.run(
            """
            MERGE (c:CVE {cve_id: $cve_id})
            SET c.description   = $description,
                c.cvss_score    = $cvss_score,
                c.published_date = $published
            """,
            cve_id=cve_id, description=description,
            cvss_score=cvss_score, published=published,
        )

        # Severity
        if severity:
            session.run(
                """
                MERGE (s:Severity {level: $level})
                WITH s MATCH (c:CVE {cve_id: $cve_id})
                MERGE (c)-[:HAS_SEVERITY]->(s)
                """,
                level=severity, cve_id=cve_id,
            )

        # CWEs
        for cwe_id in cwes:
            session.run(
                """
                MERGE (w:CWE {cwe_id: $cwe_id})
                WITH w MATCH (c:CVE {cve_id: $cve_id})
                MERGE (c)-[:MAPS_TO]->(w)
                """,
                cwe_id=cwe_id, cve_id=cve_id,
            )

        # Software
        for name in software_list:
            session.run(
                """
                MERGE (s:Software {name: $name})
                WITH s MATCH (c:CVE {cve_id: $cve_id})
                MERGE (c)-[:AFFECTS_SOFTWARE]->(s)
                """,
                name=name, cve_id=cve_id,
            )

        # Attack vector
        if attack_vector:
            session.run(
                """
                MERGE (a:AttackVector {name: $name})
                WITH a MATCH (c:CVE {cve_id: $cve_id})
                MERGE (c)-[:HAS_ATTACK_VECTOR]->(a)
                """,
                name=attack_vector, cve_id=cve_id,
            )

        # Year
        if year:
            session.run(
                """
                MERGE (y:Year {value: $value})
                WITH y MATCH (c:CVE {cve_id: $cve_id})
                MERGE (c)-[:PUBLISHED_IN]->(y)
                """,
                value=year, cve_id=cve_id,
            )

        return True

    except Exception as e:
        print(f"    ⚠ Failed to load {cve_data.get('cve', {}).get('id', '?')}: {e}")
        return False


# ── Main sync job ─────────────────────────────────────────────────────────────

def sync_nvd():
    """Fetch latest CVEs from NVD and load them into Neo4j."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'='*55}")
    print(f"🔄 NVD Sync started at {now}")
    print(f"{'='*55}")

    vulns = fetch_recent_cves(hours_back=LOOKBACK_HOURS)
    if not vulns:
        print("  ℹ No new CVEs found.")
        return

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
    loaded = 0
    skipped = 0

    with driver.session() as session:
        for vuln in vulns:
            success = load_cve_to_neo4j(session, vuln)
            if success:
                loaded += 1
            else:
                skipped += 1

    driver.close()
    print(f"\n✅ Sync complete — {loaded} CVEs loaded, {skipped} skipped")
    print(f"   Next sync in {FETCH_INTERVAL} hours")


# ── Scheduler ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🚀 SecurityGraph AI — NVD Live Feed")
    print(f"   Syncing every {FETCH_INTERVAL} hours")
    print(f"   Looking back {LOOKBACK_HOURS} hours per sync")
    if NVD_API_KEY:
        print("   ✅ NVD API key found — higher rate limits active")
    else:
        print("   ⚠  No NVD API key — limited to 5 requests/30s")

    # Run once immediately on startup
    sync_nvd()

    # Then schedule every N hours
    schedule.every(FETCH_INTERVAL).hours.do(sync_nvd)

    print(f"\n⏰ Scheduler running. Press Ctrl+C to stop.\n")
    while True:
        schedule.run_pending()
        time.sleep(60)   # check every minute