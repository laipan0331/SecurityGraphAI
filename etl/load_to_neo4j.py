import os
import ast
import re
import pandas as pd
from neo4j import GraphDatabase
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))

CSV_PATH = os.path.join(BASE_DIR, "data", "processed_cves.csv")

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME") or os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


def unique_clean(values):
    seen = set()
    cleaned_values = []

    for value in values:
        if value is None:
            continue

        cleaned = str(value).strip()
        if cleaned == "":
            continue

        lowered = cleaned.lower()
        if lowered not in seen:
            seen.add(lowered)
            cleaned_values.append(cleaned)

    return cleaned_values


def parse_extracted_entities(raw_value):
    if pd.isna(raw_value):
        return {}

    try:
        parsed = ast.literal_eval(str(raw_value))
        if isinstance(parsed, dict):
            return parsed
    except (ValueError, SyntaxError):
        pass

    return {}


def extract_versions(row):
    versions = []

    entities = parse_extracted_entities(row.get("extracted_entities"))
    extracted_versions = entities.get("version", [])

    if isinstance(extracted_versions, list):
        versions.extend(extracted_versions)

    return unique_clean(versions)


def extract_cwe_ids(raw_cwe_value):
    if pd.isna(raw_cwe_value):
        return []

    cwe_text = str(raw_cwe_value).strip()
    if cwe_text == "" or cwe_text.lower() == "unknown":
        return []

    # Handles values like:
    # "CWE-352"
    parts = re.split(r"[;,]", cwe_text)

    cwe_ids = []
    for part in parts:
        cleaned = part.strip()
        if cleaned != "" and cleaned.lower() != "unknown":
            cwe_ids.append(cleaned)

    return unique_clean(cwe_ids)


def extract_year(published_date_value):
    if pd.isna(published_date_value):
        return None

    text = str(published_date_value).strip()
    if len(text) >= 4 and text[:4].isdigit():
        return text[:4]

    return None


def create_constraints(session):
    constraint_queries = [
        "CREATE CONSTRAINT cve_id_unique IF NOT EXISTS FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE",
        "CREATE CONSTRAINT severity_level_unique IF NOT EXISTS FOR (s:Severity) REQUIRE s.level IS UNIQUE",
        "CREATE CONSTRAINT cwe_id_unique IF NOT EXISTS FOR (w:CWE) REQUIRE w.cwe_id IS UNIQUE",
        "CREATE CONSTRAINT version_value_unique IF NOT EXISTS FOR (v:Version) REQUIRE v.value IS UNIQUE",
        "CREATE CONSTRAINT year_value_unique IF NOT EXISTS FOR (y:Year) REQUIRE y.value IS UNIQUE"
    ]

    for query in constraint_queries:
        session.run(query)


def main():
    if not (NEO4J_URI and NEO4J_USERNAME and NEO4J_PASSWORD):
        raise ValueError("Neo4j connection info missing. Check your .env file.")

    df = pd.read_csv(CSV_PATH)

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
    )

    driver.verify_connectivity()

    with driver.session() as session:
        create_constraints(session)

        for _, row in df.iterrows():
            cve_id = str(row["cve_id"]).strip()
            description = str(row["description"]).strip()

            cvss_score = None
            if pd.notna(row.get("cvss_score")):
                cvss_score = float(row["cvss_score"])

            severity = str(row.get("severity", "")).strip()
            published_date = None
            if pd.notna(row.get("published_date")):
                published_date = str(row["published_date"]).strip()

            year_value = extract_year(row.get("published_date"))
            cwe_ids = extract_cwe_ids(row.get("cwe_ids"))
            versions = extract_versions(row)

            # CVE node
            session.run(
                """
                MERGE (c:CVE {cve_id: $cve_id})
                SET c.description = $description,
                    c.cvss_score = $cvss_score,
                    c.published_date = $published_date
                """,
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                published_date=published_date
            )

            # Severity node
            if severity != "":
                session.run(
                    """
                    MERGE (s:Severity {level: $level})
                    WITH s
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (c)-[:HAS_SEVERITY]->(s)
                    """,
                    cve_id=cve_id,
                    level=severity
                )

            # CWE nodes
            for one_cwe_id in cwe_ids:
                session.run(
                    """
                    MERGE (w:CWE {cwe_id: $cwe_id})
                    WITH w
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (c)-[:MAPS_TO]->(w)
                    """,
                    cve_id=cve_id,
                    cwe_id=one_cwe_id
                )

            # Version nodes
            for version_value in versions:
                session.run(
                    """
                    MERGE (v:Version {value: $value})
                    WITH v
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (c)-[:AFFECTS_VERSION]->(v)
                    """,
                    cve_id=cve_id,
                    value=version_value
                )

            # Year node
            if year_value is not None:
                session.run(
                    """
                    MERGE (y:Year {value: $value})
                    WITH y
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (c)-[:PUBLISHED_IN]->(y)
                    """,
                    cve_id=cve_id,
                    value=year_value
                )

    driver.close()
    print("Successfully loaded clean graph into Neo4j.")


if __name__ == "__main__":
    main()