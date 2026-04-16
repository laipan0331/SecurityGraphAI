import os
from neo4j import GraphDatabase
from dotenv import load_dotenv
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))

NEO4J_URI      = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME") or os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


def run_cypher(cypher: str, params: dict = {}) -> list[dict]:
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
    try:
        with driver.session() as session:
            result = session.run(cypher, **params)
            return [dict(record) for record in result]
    finally:
        driver.close()


# ── PageRank on CVEs ──────────────────────────────────────────────────────────

def get_cve_pagerank() -> pd.DataFrame:
    """
    Compute PageRank on CVEs using their connections to:
    - CWEs (MAPS_TO)
    - Software (AFFECTS_SOFTWARE)
    - Severity (HAS_SEVERITY)

    CVEs with more connections to critical CWEs and
    widely-used software score higher.

    Falls back to degree-based ranking if GDS not available.
    """
    # First try GDS PageRank (requires Neo4j GDS plugin)
    try:
        rows = run_cypher("""
            CALL gds.graph.project(
                'cve-graph',
                ['CVE', 'CWE', 'Software', 'Severity'],
                ['MAPS_TO', 'AFFECTS_SOFTWARE', 'HAS_SEVERITY']
            )
            YIELD graphName, nodeCount, relationshipCount
            RETURN graphName, nodeCount, relationshipCount
        """)

        rows = run_cypher("""
            CALL gds.pageRank.stream('cve-graph')
            YIELD nodeId, score
            WITH gds.util.asNode(nodeId) AS node, score
            WHERE node:CVE
            RETURN node.cve_id AS cve_id,
                   score AS pagerank_score
            ORDER BY score DESC
            LIMIT 15
        """)

        # Cleanup projection
        run_cypher("CALL gds.graph.drop('cve-graph') YIELD graphName")

        if rows:
            df = pd.DataFrame(rows)
            df["pagerank_score"] = df["pagerank_score"].round(4)
            df["rank"] = range(1, len(df) + 1)
            return df

    except Exception:
        pass  # GDS not available — use degree fallback

    # ── Degree-based fallback (no GDS needed) ────────────────────────────────
    rows = run_cypher("""
        MATCH (c:CVE)
        OPTIONAL MATCH (c)-[:MAPS_TO]->(w:CWE)
        OPTIONAL MATCH (c)-[:AFFECTS_SOFTWARE]->(s:Software)
        OPTIONAL MATCH (c)-[:HAS_SEVERITY]->(sev:Severity)
        WITH c,
             count(DISTINCT w) AS cwe_count,
             count(DISTINCT s) AS sw_count,
             sev.level AS severity
        WITH c,
             cwe_count,
             sw_count,
             severity,
             // Weight: critical CVEs with many CWEs and software score higher
             (cwe_count * 2.0 + sw_count * 1.5 +
              CASE severity
                WHEN 'CRITICAL' THEN 5.0
                WHEN 'HIGH'     THEN 3.0
                WHEN 'MEDIUM'   THEN 1.0
                ELSE 0.5
              END) AS pagerank_score
        ORDER BY pagerank_score DESC
        LIMIT 15
        RETURN c.cve_id AS cve_id,
               round(pagerank_score, 4) AS pagerank_score,
               cwe_count,
               sw_count,
               severity
    """)

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df["rank"] = range(1, len(df) + 1)
    return df


# ── Community Detection on CWEs ───────────────────────────────────────────────

def get_cwe_communities() -> pd.DataFrame:
    """
    Detect communities of CWEs that share the same defenses.
    CWEs in the same community can be fixed with similar strategies.

    Uses Louvain via GDS if available, otherwise groups by shared defenses.
    """
    # Try GDS Louvain first
    try:
        run_cypher("""
            CALL gds.graph.project(
                'cwe-defense-graph',
                ['CWE', 'Defense'],
                ['MITIGATED_BY']
            )
        """)

        rows = run_cypher("""
            CALL gds.louvain.stream('cwe-defense-graph')
            YIELD nodeId, communityId
            WITH gds.util.asNode(nodeId) AS node, communityId
            WHERE node:CWE
            RETURN node.cwe_id AS cwe_id,
                   communityId AS community_id
            ORDER BY community_id
        """)

        run_cypher("CALL gds.graph.drop('cwe-defense-graph') YIELD graphName")

        if rows:
            df = pd.DataFrame(rows)
            grouped = df.groupby("community_id")["cwe_id"].apply(list).reset_index()
            grouped.columns = ["community_id", "cwes"]
            grouped["size"] = grouped["cwes"].apply(len)
            grouped["cwes"] = grouped["cwes"].apply(lambda x: ", ".join(x))
            grouped = grouped[grouped["size"] > 1].sort_values("size", ascending=False)
            return grouped

    except Exception:
        pass  # GDS not available

    # ── Shared-defense fallback ───────────────────────────────────────────────
    rows = run_cypher("""
        MATCH (w:CWE)-[:MITIGATED_BY]->(d:Defense)
        WITH w.cwe_id AS cwe_id, collect(DISTINCT d.name) AS defenses
        RETURN cwe_id, defenses, size(defenses) AS defense_count
        ORDER BY defense_count DESC
    """)

    if not rows:
        return pd.DataFrame()

    from collections import defaultdict
    defense_to_cwes = defaultdict(list)
    for r in rows:
        for d in r["defenses"][:3]:
            defense_to_cwes[d].append(r["cwe_id"])

    communities = []
    seen_cwes = set()
    community_id = 1

    for defense, cwes in sorted(defense_to_cwes.items(), key=lambda x: -len(x[1])):
        new_cwes = [c for c in cwes if c not in seen_cwes]
        if len(new_cwes) >= 2:
            communities.append({
                "community_id": community_id,
                "shared_defense": defense,
                "cwes": ", ".join(new_cwes),
                "size": len(new_cwes),
            })
            seen_cwes.update(new_cwes)
            community_id += 1

    if not communities:
        return pd.DataFrame()

    return pd.DataFrame(communities).sort_values("size", ascending=False)


# ── CVE Risk Summary ──────────────────────────────────────────────────────────

def get_risk_summary() -> dict:
    """
    High-level risk metrics for the dashboard.
    """
    rows = run_cypher("""
        MATCH (c:CVE)
        OPTIONAL MATCH (c)-[:HAS_SEVERITY]->(s:Severity)
        RETURN s.level AS severity, count(c) AS count
        ORDER BY count DESC
    """)

    severity_counts = {r["severity"]: r["count"] for r in rows if r["severity"]}

    total = run_cypher("MATCH (c:CVE) RETURN count(c) AS count")[0]["count"]
    cwe_count = run_cypher("MATCH (w:CWE) RETURN count(w) AS count")[0]["count"]
    defense_count = run_cypher("MATCH (d:Defense) RETURN count(d) AS count")[0]["count"]
    tool_count = run_cypher("MATCH (t:Tool) RETURN count(t) AS count")[0]["count"]

    return {
        "total_cves": total,
        "total_cwes": cwe_count,
        "total_defenses": defense_count,
        "total_tools": tool_count,
        "critical": severity_counts.get("CRITICAL", 0),
        "high": severity_counts.get("HIGH", 0),
        "medium": severity_counts.get("MEDIUM", 0),
        "low": severity_counts.get("LOW", 0),
    }
