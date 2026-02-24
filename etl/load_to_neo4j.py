import os
import pandas as pd
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CSV_PATH = os.path.join(BASE_DIR, "data", "processed_cves.csv")

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


def main():
    if not (NEO4J_URI and NEO4J_USERNAME and NEO4J_PASSWORD):
        raise ValueError("Neo4j connection info missing. Check your .env file.")

    # Read the cleaned CVE dataset
    df = pd.read_csv(CSV_PATH)

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
    )

    with driver.session() as session:
        for _, r in df.iterrows():
            cve_id = str(r["cve_id"]).strip()
            description = str(r["description"]).strip()

            cvss_score = None
            if pd.notna(r.get("cvss_score")):
                cvss_score = float(r["cvss_score"])

            published_date = None
            if pd.notna(r.get("published_date")):
                published_date = str(r["published_date"]).strip()

            severity = str(r["severity"]).strip()

            # 1) Create CVE node
            session.run("""
                MERGE (c:CVE {cve_id: $cve_id})
                SET c.description = $description,
                    c.cvss_score = $cvss_score,
                    c.published_date = $published_date
            """, cve_id=cve_id, description=description, cvss_score=cvss_score, published_date=published_date)

            # 2) Create Severity node and link
            session.run("""
                MERGE (s:Severity {level: $level})
                WITH s
                MATCH (c:CVE {cve_id: $cve_id})
                MERGE (c)-[:HAS_SEVERITY]->(s)
            """, cve_id=cve_id, level=severity)

            # 3) Create CWE nodes (if available) and link
            cwe_val = str(r.get("cwe_ids", "")).strip()
            if cwe_val and cwe_val.lower() != "unknown":
                for cwe_id in [x.strip() for x in cwe_val.split(";")]:
                    if cwe_id:
                        session.run("""
                            MERGE (w:CWE {cwe_id: $cwe_id})
                            WITH w
                            MATCH (c:CVE {cve_id: $cve_id})
                            MERGE (c)-[:MAPS_TO]->(w)
                        """, cve_id=cve_id, cwe_id=cwe_id)

    driver.close()
    print("Successfully Loaded CVE, Severity, and CWE into Neo4j.")


if __name__ == "__main__":
    main()
