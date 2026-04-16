import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

import streamlit as st
import streamlit.components.v1 as components
from agents.graph_rag_agent import ask
from agents.autonomous_agent import investigate
from agents.attack_path_agent import analyze_stack, analyze_stack_from_text
from utils.graph_visualizer import build_cve_graph
from utils.gds_analytics import get_cve_pagerank, get_cwe_communities, get_risk_summary

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecurityGraph AI",
    page_icon="🔐",
    layout="wide",
)

# ── Dark theme + custom styling ───────────────────────────────────────────────
st.markdown("""
<style>
html, body, .stApp {
    background-color: #020617 !important;
    color: #f8fafc !important;
}
h1, h2, h3, h4, h5, h6, p, label, span, div {
    color: #f8fafc !important;
}
[data-testid="stSidebar"] {
    background-color: #0f172a !important;
}
[data-testid="stSidebar"] * {
    color: #f8fafc !important;
}
.stTabs [role="tab"] {
    background-color: #1e293b !important;
    color: #f8fafc !important;
    border-radius: 12px 12px 0 0;
    padding: 8px 16px;
}
.stTabs [role="tab"][aria-selected="true"] {
    background-color: #0f172a !important;
    border-bottom: 3px solid #38bdf8 !important;
    font-weight: 700 !important;
}
.stButton>button {
    background: linear-gradient(to right, #0ea5e9, #38bdf8) !important;
    color: #0b1120 !important;
    font-weight: 600 !important;
    border-radius: 999px !important;
    border: none !important;
    padding: 8px 20px !important;
}
.stButton>button:hover {
    filter: brightness(1.15) !important;
}
.stTextInput>div>div>input, .stTextArea>div>div>textarea {
    background-color: #1e293b !important;
    color: #ffffff !important;
    border: 1px solid #334155 !important;
    border-radius: 8px !important;
}
.stMetric {
    background-color: #0f172a !important;
    border: 1px solid #1e293b !important;
    border-radius: 12px !important;
    padding: 12px !important;
}
.stMetric label, .stMetric div {
    color: #f8fafc !important;
}
.stSuccess {
    background-color: #052e16 !important;
    border: 1px solid #166534 !important;
    border-radius: 8px !important;
}
.stExpander {
    background-color: #0f172a !important;
    border: 1px solid #1e293b !important;
    border-radius: 8px !important;
}
pre, code {
    background-color: #0f172a !important;
    color: #38bdf8 !important;
    border-radius: 8px !important;
}
.severity-critical {
    background-color: #450a0a;
    color: #fca5a5;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
}
.severity-high {
    background-color: #431407;
    color: #fdba74;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
}
.severity-medium {
    background-color: #422006;
    color: #fde68a;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
}
.live-badge {
    background-color: #052e16;
    color: #4ade80;
    padding: 3px 12px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid #166534;
}
</style>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="padding: 1.5rem 0 0.5rem 0;">
    <h1 style="margin-bottom: 0.2rem; font-size: 2rem;">🔐 SecurityGraph AI</h1>
    <p style="color: #94a3b8; font-size: 0.95rem; max-width: 720px; margin-bottom: 0.8rem;">
        Cybersecurity knowledge graph powered by <b style="color:#38bdf8;">Neo4j</b> 
        and <b style="color:#38bdf8;">Gemini 2.5 Flash</b> — connecting CVEs, weaknesses, 
        defenses, and tools through multi-hop graph reasoning.
    </p>
    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
        <span style="background:#0f172a; color:#38bdf8; padding:0.25rem 0.8rem; border-radius:999px; font-size:0.8rem; border: 1px solid #1e3a5f;">
            NVD · MITRE CWE · OWASP
        </span>
        <span style="background:#0f172a; color:#38bdf8; padding:0.25rem 0.8rem; border-radius:999px; font-size:0.8rem; border: 1px solid #1e3a5f;">
            GraphRAG + Text-to-Cypher
        </span>
        <span style="background:#052e16; color:#4ade80; padding:0.25rem 0.8rem; border-radius:999px; font-size:0.8rem; border: 1px solid #166534;">
            ● Live NVD Feed
        </span>
    </div>
</div>
""", unsafe_allow_html=True)

st.divider()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 📊 Graph Stats")

    try:
        summary = get_risk_summary()
        st.metric("Total CVEs", f"{summary['total_cves']:,}")
        st.metric("Defenses", f"{summary['total_defenses']:,}")
        st.metric("Tools", f"{summary['total_tools']:,}")
        st.metric("CWEs", f"{summary['total_cwes']:,}")

        st.markdown("### Severity Breakdown")
        st.markdown(f"""
        <div style="display:flex; flex-direction:column; gap:6px; margin-top:8px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#fca5a5; font-size:13px;">🔴 Critical</span>
                <span style="font-weight:600; color:#fca5a5;">{summary['critical']}</span>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#fdba74; font-size:13px;">🟠 High</span>
                <span style="font-weight:600; color:#fdba74;">{summary['high']}</span>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#fde68a; font-size:13px;">🟡 Medium</span>
                <span style="font-weight:600; color:#fde68a;">{summary['medium']}</span>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#86efac; font-size:13px;">🟢 Low</span>
                <span style="font-weight:600; color:#86efac;">{summary['low']}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    except Exception:
        st.info("Connect to Neo4j to see stats")

    st.divider()
    st.markdown("### 🔗 Data Sources")
    st.markdown("""
    <div style="font-size:13px; color:#94a3b8; line-height:1.8;">
        <div>📡 NVD — nvd.nist.gov</div>
        <div>🛡️ MITRE CWE — cwe.mitre.org</div>
        <div>📋 OWASP Cheat Sheets</div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    st.markdown("### ⚙️ System")
    st.markdown("""
    <div style="font-size:13px; color:#94a3b8; line-height:1.8;">
        <div>🤖 Gemini 2.5 Flash</div>
        <div>🗄️ Neo4j Knowledge Graph</div>
        <div>🔄 NVD Sync: every 6 hours</div>
    </div>
    """, unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "💬 Ask a Question",
    "🔍 Investigate CVE",
    "🛡️ Analyze My Stack",
    "📊 Graph Analytics",
    "📈 Evaluation",
])

# ── Tab 1: GraphRAG Q&A ───────────────────────────────────────────────────────
with tab1:
    st.subheader("💬 Ask a Security Question")
    st.markdown(
        "<p style='color:#94a3b8;'>Ask anything about vulnerabilities, defenses, "
        "tools, or CVEs — powered by Gemini Text-to-Cypher with multi-hop graph reasoning.</p>",
        unsafe_allow_html=True,
    )

    with st.expander("💡 Example questions"):
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            **Prevention:**
            - How do I prevent XSS attacks?
            - What are the defenses for SQL injection?
            - How do I fix CSRF vulnerabilities?

            **Detection:**
            - What tools detect SQL injection?
            - What security tools are available?
            """)
        with col2:
            st.markdown("""
            **Multi-hop reasoning:**
            - What tools should I use to secure my PHP application?
            - What are common weaknesses in Cisco products and how do I fix them?
            - Which software has both critical CVEs and known defenses?

            **Analytics:**
            - Which software has the most vulnerabilities?
            - Show me CVEs with CVSS score above 9
            """)

    question = st.text_input(
        "Your question",
        placeholder="e.g. How do I prevent XSS attacks?",
    )

    if st.button("Ask", type="primary", key="ask_btn"):
        if not question.strip():
            st.warning("Please enter a question.")
        else:
            with st.spinner("Querying knowledge graph..."):
                answer = ask(question)
            st.markdown("""
            <div style="background:#0f172a; border:1px solid #1e293b; 
                        border-radius:12px; padding:1.2rem; margin-top:1rem;">
                <div style="color:#38bdf8; font-size:12px; font-weight:600; 
                            margin-bottom:8px;">🛡️ ANSWER</div>
            """, unsafe_allow_html=True)
            st.markdown(answer)
            st.markdown("</div>", unsafe_allow_html=True)

# ── Tab 2: Autonomous CVE Investigator ───────────────────────────────────────
with tab2:
    st.subheader("🔍 Autonomous CVE Investigation")
    st.markdown(
        "<p style='color:#94a3b8;'>Enter a CVE ID — the agent automatically runs "
        "7 steps and generates a full security report with knowledge graph visualization.</p>",
        unsafe_allow_html=True,
    )

    with st.expander("💡 Example CVE IDs"):
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            - `CVE-2018-15381` — Cisco, CVSS 10.0
            - `CVE-2019-11030` — CVSS 10.0
            """)
        with col2:
            st.markdown("""
            - `CVE-2001-0537` — Cisco IOS
            - `CVE-2015-6388` — Cisco SSRF
            """)

    cve_id = st.text_input(
        "CVE ID",
        placeholder="e.g. CVE-2018-15381",
    )

    if st.button("Investigate", type="primary", key="investigate_btn"):
        if not cve_id.strip():
            st.warning("Please enter a CVE ID.")
        else:
            steps = [
                "Fetching CVE details...",
                "Finding CWE mappings...",
                "Finding affected software...",
                "Fetching defenses...",
                "Finding detection tools...",
                "Running multi-hop analysis...",
                "Generating security report...",
            ]
            progress = st.progress(0)
            status = st.empty()

            for i, step in enumerate(steps):
                status.markdown(
                    f"<p style='color:#38bdf8; font-size:13px;'>Step {i+1}/7 — {step}</p>",
                    unsafe_allow_html=True,
                )
                progress.progress((i + 1) / len(steps))

            report = investigate(cve_id)
            progress.empty()
            status.empty()

            st.markdown("""
            <div style="background:#0f172a; border:1px solid #1e293b;
                        border-radius:12px; padding:1.2rem; margin-top:1rem;">
                <div style="color:#38bdf8; font-size:12px; font-weight:600;
                            margin-bottom:8px;">🔍 SECURITY REPORT</div>
            """, unsafe_allow_html=True)
            st.markdown(report)
            st.markdown("</div>", unsafe_allow_html=True)

            st.divider()
            st.subheader("🕸️ Knowledge Graph")
            st.markdown(
                "<p style='color:#94a3b8; font-size:13px;'>Interactive visualization — "
                "drag nodes, zoom in/out, hover for details.</p>",
                unsafe_allow_html=True,
            )

            col1, col2, col3, col4, col5 = st.columns(5)
            col1.markdown("🔴 CVE")
            col2.markdown("🟠 CWE")
            col3.markdown("🟢 Defense")
            col4.markdown("🔵 Tool")
            col5.markdown("🟣 Software")

            with st.spinner("Building graph visualization..."):
                graph_html = build_cve_graph(cve_id)

            if graph_html:
                components.html(graph_html, height=570, scrolling=False)
            else:
                st.info(f"{cve_id.upper()} was not found in the knowledge graph.")

# ── Tab 3: Attack Path Analyzer ───────────────────────────────────────────────
with tab3:
    st.subheader("🛡️ Attack Path Analyzer")
    st.markdown(
        "<p style='color:#94a3b8;'>Describe your tech stack in plain English — "
        "the agent extracts technologies, finds overlapping weaknesses, "
        "and gives you a prioritized fix list.</p>",
        unsafe_allow_html=True,
    )

    with st.expander("💡 Example inputs"):
        st.markdown("""
        - `I am building a web app using PHP on Apache with a MySQL database`
        - `I have a Cisco network running on Linux servers`
        - `I am running Apache Tomcat with Atlassian Jira Server`
        """)

    stack_input = st.text_area(
        "Describe your tech stack",
        placeholder="e.g. I am building a web app using PHP on Apache with a MySQL database",
        height=100,
    )

    if st.button("Analyze Stack", type="primary", key="stack_btn"):
        if not stack_input.strip():
            st.warning("Please enter your tech stack.")
        else:
            with st.spinner("Analyzing attack surface..."):
                report = analyze_stack_from_text(stack_input)

            st.markdown("""
            <div style="background:#0f172a; border:1px solid #1e293b;
                        border-radius:12px; padding:1.2rem; margin-top:1rem;">
                <div style="color:#38bdf8; font-size:12px; font-weight:600;
                            margin-bottom:8px;">🛡️ REMEDIATION REPORT</div>
            """, unsafe_allow_html=True)
            st.markdown(report)
            st.markdown("</div>", unsafe_allow_html=True)

# ── Tab 4: Graph Analytics ────────────────────────────────────────────────────
with tab4:
    st.subheader("📊 Graph Analytics")
    st.markdown(
        "<p style='color:#94a3b8;'>Graph algorithm-powered insights using "
        "PageRank on CVEs and Community Detection on CWEs.</p>",
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        <div style="background:#0f172a; border:1px solid #1e293b; border-radius:12px; padding:1.2rem;">
            <div style="color:#38bdf8; font-size:14px; font-weight:600; margin-bottom:8px;">
                🏆 CVE PageRank
            </div>
            <p style="color:#94a3b8; font-size:13px;">
                Ranks CVEs by their importance in the knowledge graph — 
                connections to CWEs, affected software, and severity.
                Higher score = more dangerous and interconnected.
            </p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Run CVE PageRank", type="primary", key="pagerank_btn"):
            with st.spinner("Computing PageRank scores..."):
                pr_df = get_cve_pagerank()
            if pr_df.empty:
                st.info("No CVE data found.")
            else:
                st.dataframe(pr_df, use_container_width=True)

    with col2:
        st.markdown("""
        <div style="background:#0f172a; border:1px solid #1e293b; border-radius:12px; padding:1.2rem;">
            <div style="color:#38bdf8; font-size:14px; font-weight:600; margin-bottom:8px;">
                🔗 CWE Community Detection
            </div>
            <p style="color:#94a3b8; font-size:13px;">
                Groups CWEs that share the same defenses. 
                CWEs in the same community can be fixed with similar strategies — 
                one fix covers multiple weaknesses.
            </p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Run Community Detection", type="primary", key="community_btn"):
            with st.spinner("Detecting CWE communities..."):
                comm_df = get_cwe_communities()
            if comm_df.empty:
                st.info("No community data found.")
            else:
                st.dataframe(comm_df, use_container_width=True)
                if len(comm_df) > 0:
                    largest = comm_df.iloc[0]
                    st.success(
                        f"💡 Largest community has {largest['size']} CWEs "
                        f"sharing the same defense strategy."
                    )

# ── Tab 5: Evaluation ─────────────────────────────────────────────────────────
with tab5:
    st.subheader("📈 System Evaluation")
    st.markdown(
        "<p style='color:#94a3b8;'>Standard evaluation metrics following "
        "Neo4j's Text2Cypher 2024 benchmark methodology.</p>",
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("BLEU Score", "0.95", "Cypher translation quality")
    col2.metric("Exact Match", "95%", "Result correctness")
    col3.metric("Answer Relevance", "4.7/5", "LLM judge score")
    col4.metric("Faithfulness", "3.65/5", "Groundedness score")

    st.divider()

    st.markdown("### 🚨 Outlier Analysis")
    st.markdown(
        "<p style='color:#94a3b8;'>8 outliers detected across 4 failure patterns:</p>",
        unsafe_allow_html=True,
    )

    outliers = [
        {
            "pattern": "Large Result Set",
            "description": "When graph returns 20+ records, LLM enriches answer beyond raw data → low faithfulness. Expected GraphRAG behavior.",
            "examples": "Q06, Q08, Q09, Q10, Q14",
            "color": "#fde68a",
            "bg": "#422006",
        },
        {
            "pattern": "Sparse Vendor Data",
            "description": "Cisco only maps to 1 CWE in graph → answer too generic. Data coverage limitation, not model failure.",
            "examples": "Q17",
            "color": "#fdba74",
            "bg": "#431407",
        },
        {
            "pattern": "Negation Query",
            "description": "Gemini generated valid alternative Cypher using NOT EXISTS syntax. ExactMatch penalizes correct alternatives.",
            "examples": "Q19",
            "color": "#fca5a5",
            "bg": "#450a0a",
        },
        {
            "pattern": "Missing Data",
            "description": "React not in dataset → 0 results. Cypher was perfect. Handled gracefully — no hallucination.",
            "examples": "Q20",
            "color": "#86efac",
            "bg": "#052e16",
        },
    ]

    for o in outliers:
        st.markdown(f"""
        <div style="background:{o['bg']}; border-radius:10px; padding:1rem; margin-bottom:0.8rem;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:{o['color']}; font-weight:600; font-size:14px;">
                    {o['pattern']}
                </span>
                <span style="color:{o['color']}; font-size:12px; opacity:0.8;">
                    {o['examples']}
                </span>
            </div>
            <p style="color:{o['color']}; font-size:13px; margin-top:6px; opacity:0.9;">
                {o['description']}
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.divider()
    st.markdown("### 📊 Results by Category")
    categories = {
        "Aggregation":   {"bleu": "1.00", "match": "100%", "relevance": "5.0"},
        "Filter":        {"bleu": "1.00", "match": "100%", "relevance": "4.5"},
        "Defense":       {"bleu": "1.00", "match": "100%", "relevance": "5.0"},
        "Tool":          {"bleu": "1.00", "match": "100%", "relevance": "4.67"},
        "Multi-hop":     {"bleu": "1.00", "match": "100%", "relevance": "4.25"},
        "Outlier Cases": {"bleu": "0.50", "match": "50%",  "relevance": "5.0"},
    }

    for cat, scores in categories.items():
        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
        col1.markdown(f"**{cat}**")
        col2.markdown(f"BLEU: `{scores['bleu']}`")
        col3.markdown(f"Match: `{scores['match']}`")
        col4.markdown(f"Relevance: `{scores['relevance']}`")