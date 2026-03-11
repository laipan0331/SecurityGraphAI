import os
import re
import pandas as pd
from neo4j import GraphDatabase
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))

CSV_PATH = os.path.join(BASE_DIR, "data", "enhanced_cves.csv")

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

def unique_clean(values):
    seen = set()
    result = []

    for value in values:
        if value is None:
            continue

        cleaned = str(value).strip()
        if cleaned == "":
            continue

        key = cleaned.lower()
        if key not in seen:
            seen.add(key)
            result.append(cleaned)

    return result


def normalize_text(value):
    if pd.isna(value):
        return None

    cleaned = str(value).strip()
    if cleaned == "" or cleaned.lower() in {"unknown", "nan", "none"}:
        return None

    return cleaned

def extract_cwe_ids(raw_cwe_value):
    text = normalize_text(raw_cwe_value)
    if text is None:
        return []

    parts = re.split(r"[;,|]", text)
    cwe_ids = []

    for part in parts:
        candidate = part.strip()
        if candidate:
            cwe_ids.append(candidate)

    return unique_clean(cwe_ids)

def extract_versions(raw_versions_value):
    text = normalize_text(raw_versions_value)
    if text is None:
        return []

    matches = re.findall(
        r"\b\d+(?:\.\d+){1,3}(?:\s*(?:alpha|beta|rc)\d*)?\b",
        text,
        flags=re.IGNORECASE,
    )

    return unique_clean(matches)

def extract_year(published_date_value):
    text = normalize_text(published_date_value)
    if text is None:
        return None

    if len(text) >= 4 and text[:4].isdigit():
        return text[:4]

    return None

def create_constraints(session):
    queries = [
        "CREATE CONSTRAINT cve_id_unique IF NOT EXISTS FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE",
        "CREATE CONSTRAINT severity_level_unique IF NOT EXISTS FOR (s:Severity) REQUIRE s.level IS UNIQUE",
        "CREATE CONSTRAINT cwe_id_unique IF NOT EXISTS FOR (w:CWE) REQUIRE w.cwe_id IS UNIQUE",
        "CREATE CONSTRAINT software_name_unique IF NOT EXISTS FOR (s:Software) REQUIRE s.name IS UNIQUE",
        "CREATE CONSTRAINT version_value_unique IF NOT EXISTS FOR (v:Version) REQUIRE v.value IS UNIQUE",
        "CREATE CONSTRAINT vuln_type_name_unique IF NOT EXISTS FOR (v:VulnerabilityType) REQUIRE v.name IS UNIQUE",
        "CREATE CONSTRAINT attack_vector_name_unique IF NOT EXISTS FOR (a:AttackVector) REQUIRE a.name IS UNIQUE",
        "CREATE CONSTRAINT year_value_unique IF NOT EXISTS FOR (y:Year) REQUIRE y.value IS UNIQUE",
    ]

    for query in queries:
        session.run(query)

def merge_cve(session, cve_id, description, cleaned_description, cvss_score, published_date):
    session.run(
        """
        MERGE (c:CVE {cve_id: $cve_id})
        SET c.description = $description,
            c.cleaned_description = $cleaned_description,
            c.cvss_score = $cvss_score,
            c.published_date = $published_date
        """,
        cve_id=cve_id,
        description=description,
        cleaned_description=cleaned_description,
        cvss_score=cvss_score,
        published_date=published_date,
    )

def main():
    if not (NEO4J_URI and NEO4J_USERNAME and NEO4J_PASSWORD):
        raise ValueError("Neo4j connection info missing. Check your .env file.")

    df = pd.read_csv(CSV_PATH)

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USERNAME, NEO4J_PASSWORD),
    )

    driver.verify_connectivity()

    with driver.session() as session:
        create_constraints(session)

        for _, row in df.iterrows():
            cve_id = normalize_text(row.get("cve_id"))
            if cve_id is None:
                continue

            description = normalize_text(row.get("description")) or ""
            cleaned_description = normalize_text(row.get("cleaned_description")) or description

            cvss_score = None
            if pd.notna(row.get("cvss_score")):
                cvss_score = float(row.get("cvss_score"))

            published_date = normalize_text(row.get("published_date"))
            severity = normalize_text(row.get("severity"))
            software_name = normalize_text(row.get("software_name"))
            vulnerability_type = normalize_text(row.get("vulnerability_type"))
            attack_vector = normalize_text(row.get("attack_vector"))
            year_value = extract_year(row.get("published_date"))
            cwe_ids = extract_cwe_ids(row.get("cwe_ids"))
            versions = extract_versions(row.get("affected_versions"))

            merge_cve(
                session,
                cve_id,
                description,
                cleaned_description,
                cvss_score,
                published_date,
            )

            if severity is not None:
                session.run(
                    """
                    MERGE (s:Severity {level: $level})
                    WITH s
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (c)-[:HAS_SEVERITY]->(s)
                    """,
                    cve_id=cve_id,
                    level=severity,
                )

            for cwe_id in cwe_ids:
                session.run(
                    """
                    MERGE (w:CWE {cwe_id: $cwe_id})
                    WITH w
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (c)-[:MAPS_TO]->(w)
                    """,
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                )

            if software_name is not None:
                session.run(
                    """
                    MERGE (s:Software {name: $name})
                    WITH s
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (c)-[:AFFECTS_SOFTWARE]->(s)
                    """,
                    cve_id=cve_id,
                    name=software_name,
                )

            for version_value in versions:
                session.run(
                    """
                    MERGE (v:Version {value: $value})
                    WITH v
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (c)-[:AFFECTS_VERSION]->(v)
                    """,
                    cve_id=cve_id,
                    value=version_value,
                )

                if software_name is not None:
                    session.run(
                        """
                        MATCH (s:Software {name: $software_name})
                        MERGE (v:Version {value: $value})
                        MERGE (s)-[:HAS_VERSION]->(v)
                        """,
                        software_name=software_name,
                        value=version_value,
                    )

            if vulnerability_type is not None:
                session.run(
                    """
                    MERGE (v:VulnerabilityType {name: $name})
                    WITH v
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (c)-[:HAS_VULNERABILITY_TYPE]->(v)
                    """,
                    cve_id=cve_id,
                    name=vulnerability_type,
                )

            if attack_vector is not None:
                session.run(
                    """
                    MERGE (a:AttackVector {name: $name})
                    WITH a
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (c)-[:HAS_ATTACK_VECTOR]->(a)
                    """,
                    cve_id=cve_id,
                    name=attack_vector,
                )

            if year_value is not None:
                session.run(
                    """
                    MERGE (y:Year {value: $value})
                    WITH y
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (c)-[:PUBLISHED_IN]->(y)
                    """,
                    cve_id=cve_id,
                    value=year_value,
                )

    driver.close()
    print("Successfully loaded enhanced graph into Neo4j.")

if __name__ == "__main__":
    main()