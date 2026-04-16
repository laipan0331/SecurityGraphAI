import os
from neo4j import GraphDatabase
from dotenv import load_dotenv
from pyvis.network import Network

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))

NEO4J_URI      = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME") or os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


def build_cve_graph(cve_id: str) -> str | None:
    """
    Build an interactive pyvis graph for a given CVE.
    Returns the HTML string or None if CVE not found.
    """
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))

    try:
        with driver.session() as session:
            # Check CVE exists
            result = session.run(
                "MATCH (c:CVE {cve_id: $cve_id}) RETURN c.cve_id AS id, c.description AS desc, c.cvss_score AS score",
                cve_id=cve_id.upper()
            )
            cve_row = result.single()
            if not cve_row:
                return None

            net = Network(height="550px", width="100%", bgcolor="#0d1b2a", font_color="#ffffff")
            net.set_options("""
            {
              "physics": {
                "barnesHut": {
                  "gravitationalConstant": -8000,
                  "springLength": 150
                },
                "stabilization": { "iterations": 150 }
              },
              "interaction": { "hover": true }
            }
            """)

            cve_label = cve_row["id"]
            score = cve_row["score"]
            cve_title = f"<b>{cve_label}</b><br>CVSS: {score}<br>{(cve_row['desc'] or '')[:120]}..."
            net.add_node(cve_label, label=cve_label, color="#e63946", size=28,
                         title=cve_title, font={"size": 14})

            # CWEs
            cwes = session.run(
                "MATCH (c:CVE {cve_id: $cve_id})-[:MAPS_TO]->(w:CWE) RETURN w.cwe_id AS cwe_id",
                cve_id=cve_id.upper()
            )
            for row in cwes:
                cwe = row["cwe_id"]
                net.add_node(cwe, label=cwe, color="#f4a261", size=20,
                             title=f"<b>{cwe}</b>", font={"size": 12})
                net.add_edge(cve_label, cwe, color="#f4a261", width=2)

                # Defenses linked to this CWE
                defenses = session.run(
                    "MATCH (w:CWE {cwe_id: $cwe_id})-[:MITIGATED_BY]->(d:Defense) "
                    "RETURN d.name AS name, d.defense_id AS did LIMIT 5",
                    cwe_id=cwe
                )
                for d in defenses:
                    did = d["did"]
                    dname = (d["name"] or "").replace("¶", "").strip()[:40]
                    node_id = f"DEF_{did}"
                    net.add_node(node_id, label=dname, color="#2a9d8f", size=14,
                                 title=f"<b>Defense</b><br>{dname}", font={"size": 10})
                    net.add_edge(cwe, node_id, color="#2a9d8f", dashes=True, width=1)

                # Tools linked to this CWE
                tools = session.run(
                    "MATCH (w:CWE {cwe_id: $cwe_id})-[:DETECTED_BY]->(t:Tool) RETURN t.name AS name",
                    cwe_id=cwe
                )
                for t in tools:
                    tname = t["name"]
                    node_id = f"TOOL_{tname}"
                    if not net.get_node(node_id):
                        net.add_node(node_id, label=tname, color="#457b9d", size=16,
                                     title=f"<b>Tool</b><br>{tname}", font={"size": 11})
                    net.add_edge(cwe, node_id, color="#457b9d", width=1)

            # Software
            software = session.run(
                "MATCH (c:CVE {cve_id: $cve_id})-[:AFFECTS_SOFTWARE]->(s:Software) RETURN s.name AS name",
                cve_id=cve_id.upper()
            )
            for row in software:
                sname = row["name"]
                node_id = f"SW_{sname}"
                net.add_node(node_id, label=sname, color="#7b2d8b", size=18,
                             title=f"<b>Software</b><br>{sname}", font={"size": 12})
                net.add_edge(cve_label, node_id, color="#7b2d8b", width=2)

            # Severity
            severity = session.run(
                "MATCH (c:CVE {cve_id: $cve_id})-[:HAS_SEVERITY]->(s:Severity) RETURN s.level AS level",
                cve_id=cve_id.upper()
            )
            sev_row = severity.single()
            if sev_row:
                level = sev_row["level"]
                sev_color = {"CRITICAL": "#e63946", "HIGH": "#f4a261",
                             "MEDIUM": "#e9c46a", "LOW": "#2a9d8f"}.get(level, "#aaa")
                node_id = f"SEV_{level}"
                net.add_node(node_id, label=level, color=sev_color, size=16,
                             title=f"<b>Severity</b>: {level}", font={"size": 11})
                net.add_edge(cve_label, node_id, color=sev_color, width=2)

        return net.generate_html()

    finally:
        driver.close()
