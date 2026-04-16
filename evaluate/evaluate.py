import os
import sys
import json
import time
import math
from collections import Counter
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.graph_rag_agent import generate_cypher, run_cypher, generate_answer
from google import genai
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))

client       = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
GEMINI_MODEL = "gemini-2.5-flash"

# ── BLEU Score Implementation ─────────────────────────────────────────────────

def ngrams(tokens, n):
    return [tuple(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]

def bleu_score(reference: str, hypothesis: str) -> float:
    """
    Compute sentence-level BLEU score (1 to 4-gram).
    Standard metric used in Neo4j Text2Cypher benchmarking.
    """
    ref_tokens  = reference.lower().split()
    hyp_tokens  = hypothesis.lower().split()

    if len(hyp_tokens) == 0:
        return 0.0

    # Brevity penalty
    bp = 1.0 if len(hyp_tokens) >= len(ref_tokens) else \
         math.exp(1 - len(ref_tokens) / len(hyp_tokens))

    scores = []
    for n in range(1, 5):
        ref_ngrams  = Counter(ngrams(ref_tokens, n))
        hyp_ngrams  = Counter(ngrams(hyp_tokens, n))

        if not hyp_ngrams:
            scores.append(0.0)
            continue

        clipped = sum(min(count, ref_ngrams[gram]) for gram, count in hyp_ngrams.items())
        precision = clipped / sum(hyp_ngrams.values())
        scores.append(precision if precision > 0 else 1e-10)

    log_avg = sum(math.log(s) for s in scores) / 4
    return round(bp * math.exp(log_avg), 4)


# ── Execution ExactMatch ──────────────────────────────────────────────────────

def execution_exact_match(ground_truth_cypher: str, generated_cypher: str) -> tuple[bool, str]:
    """
    Run both Cypher queries on Neo4j and compare results.
    Returns (match: bool, reason: str)
    """
    try:
        gt_results  = run_cypher(ground_truth_cypher)
        gen_results = run_cypher(generated_cypher)

        # Convert to sorted string for comparison
        gt_str  = str(sorted([str(r) for r in gt_results]))
        gen_str = str(sorted([str(r) for r in gen_results]))

        match = gt_str == gen_str
        reason = "exact match" if match else \
                 f"GT returned {len(gt_results)} records, Generated returned {len(gen_results)} records"
        return match, reason

    except Exception as e:
        return False, f"Execution error: {str(e)[:80]}"


# ── LLM Judge ─────────────────────────────────────────────────────────────────

FAITHFULNESS_PROMPT = """You are an evaluator checking if an answer is grounded in retrieved data.

Retrieved Data from Graph:
{context}

Answer Given:
{answer}

Score faithfulness from 1 to 5:
5 = Completely grounded in retrieved data, no hallucination
4 = Mostly grounded with minor additions
3 = Some hallucination present
2 = Significant hallucination
1 = Answer ignores the data or makes up facts

Return ONLY a single integer (1-5). Nothing else."""

RELEVANCE_PROMPT = """You are an evaluator checking if an answer addresses the question.

Question: {question}
Answer: {answer}

Score answer relevance from 1 to 5:
5 = Perfectly answers the question with specific details
4 = Mostly answers with minor gaps
3 = Partially answers
2 = Barely addresses the question
1 = Does not answer the question at all

Return ONLY a single integer (1-5). Nothing else."""

def llm_score(prompt: str) -> int:
    try:
        response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        return max(1, min(5, int(response.text.strip())))
    except Exception:
        return 1


# ── Test Set ──────────────────────────────────────────────────────────────────

TEST_SET = [
    # ── Aggregation ──
    {
        "id": "Q01", "category": "aggregation",
        "question": "How many critical CVEs are there?",
        "ground_truth_cypher": "MATCH (c:CVE)-[:HAS_SEVERITY]->(s:Severity {level: 'CRITICAL'}) RETURN count(c) AS critical_count",
    },
    {
        "id": "Q02", "category": "aggregation",
        "question": "Which software has the most vulnerabilities?",
        "ground_truth_cypher": "MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software) RETURN s.name AS software, count(c) AS vuln_count ORDER BY vuln_count DESC LIMIT 10",
    },
    {
        "id": "Q03", "category": "aggregation",
        "question": "What are the most common CWE weaknesses?",
        "ground_truth_cypher": "MATCH (c:CVE)-[:MAPS_TO]->(w:CWE) RETURN w.cwe_id AS cwe, count(c) AS count ORDER BY count DESC LIMIT 10",
    },
    {
        "id": "Q04", "category": "aggregation",
        "question": "What vulnerability types are most common?",
        "ground_truth_cypher": "MATCH (c:CVE)-[:HAS_VULNERABILITY_TYPE]->(v:VulnerabilityType) RETURN v.name AS type, count(c) AS count ORDER BY count DESC LIMIT 10",
    },
    # ── Filter ──
    {
        "id": "Q05", "category": "filter",
        "question": "List CVEs affecting Apache.",
        "ground_truth_cypher": "MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software) WHERE toLower(s.name) CONTAINS 'apache' RETURN c.cve_id, c.description LIMIT 20",
    },
    {
        "id": "Q06", "category": "filter",
        "question": "Show me CVEs with CVSS score above 9.",
        "ground_truth_cypher": "MATCH (c:CVE) WHERE c.cvss_score >= 9 RETURN c.cve_id, c.cvss_score, c.description ORDER BY c.cvss_score DESC LIMIT 20",
    },
    {
        "id": "Q07", "category": "filter",
        "question": "How many CVEs were published in 2021?",
        "ground_truth_cypher": "MATCH (c:CVE)-[:PUBLISHED_IN]->(y:Year {value: '2021'}) RETURN count(c) AS count",
    },
    {
        "id": "Q08", "category": "filter",
        "question": "Which CVEs use a remote attack vector?",
        "ground_truth_cypher": "MATCH (c:CVE)-[:HAS_ATTACK_VECTOR]->(a:AttackVector) WHERE toLower(a.name) CONTAINS 'remote' RETURN c.cve_id, c.description LIMIT 20",
    },
    # ── Defense ──
    {
        "id": "Q09", "category": "defense",
        "question": "How do I prevent XSS attacks?",
        "ground_truth_cypher": "MATCH (w:CWE {cwe_id: 'CWE-79'})-[:MITIGATED_BY]->(d:Defense) RETURN d.name AS defense, d.description AS description",
    },
    {
        "id": "Q10", "category": "defense",
        "question": "What are the defenses for SQL injection?",
        "ground_truth_cypher": "MATCH (w:CWE {cwe_id: 'CWE-89'})-[:MITIGATED_BY]->(d:Defense) RETURN d.name AS defense, d.description AS description",
    },
    {
        "id": "Q11", "category": "defense",
        "question": "How do I fix CSRF vulnerabilities?",
        "ground_truth_cypher": "MATCH (w:CWE {cwe_id: 'CWE-352'})-[:MITIGATED_BY]->(d:Defense) RETURN d.name AS defense, d.description AS description",
    },
    # ── Tool ──
    {
        "id": "Q12", "category": "tool",
        "question": "What tools can detect XSS?",
        "ground_truth_cypher": "MATCH (w:CWE {cwe_id: 'CWE-79'})-[:DETECTED_BY]->(t:Tool) RETURN t.name AS tool",
    },
    {
        "id": "Q13", "category": "tool",
        "question": "What tools detect SQL injection?",
        "ground_truth_cypher": "MATCH (w:CWE {cwe_id: 'CWE-89'})-[:DETECTED_BY]->(t:Tool) RETURN t.name AS tool",
    },
    {
        "id": "Q14", "category": "tool",
        "question": "What security tools are available?",
        "ground_truth_cypher": "MATCH (t:Tool) RETURN t.name AS tool",
    },
    # ── Multi-hop ──
    {
        "id": "Q15", "category": "multihop",
        "question": "Which CWEs have the most defenses?",
        "ground_truth_cypher": "MATCH (w:CWE)-[:MITIGATED_BY]->(d:Defense) RETURN w.cwe_id AS cwe, count(d) AS defense_count ORDER BY defense_count DESC LIMIT 10",
    },
    {
        "id": "Q16", "category": "multihop",
        "question": "What tools should I use to secure my PHP application?",
        "ground_truth_cypher": "MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software) WHERE toLower(s.name) CONTAINS 'php' WITH c MATCH (c)-[:MAPS_TO]->(w:CWE)-[:DETECTED_BY]->(t:Tool) RETURN DISTINCT t.name AS tool, collect(DISTINCT w.cwe_id) AS covers_cwes",
    },
    {
        "id": "Q17", "category": "multihop",
        "question": "What are the common weaknesses in Cisco products and how do I fix them?",
        "ground_truth_cypher": "MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software) WHERE toLower(s.name) CONTAINS 'cisco' WITH c MATCH (c)-[:MAPS_TO]->(w:CWE)-[:MITIGATED_BY]->(d:Defense) RETURN DISTINCT w.cwe_id AS cwe, collect(DISTINCT d.name) AS defenses LIMIT 20",
    },
    {
        "id": "Q18", "category": "multihop",
        "question": "Which software has both critical CVEs and known defenses?",
        "ground_truth_cypher": "MATCH (c:CVE)-[:HAS_SEVERITY]->(s:Severity {level: 'CRITICAL'}) MATCH (c)-[:AFFECTS_SOFTWARE]->(sw:Software) MATCH (c)-[:MAPS_TO]->(w:CWE)-[:MITIGATED_BY]->(d:Defense) RETURN DISTINCT sw.name AS software, count(DISTINCT c) AS critical_cves, count(DISTINCT d) AS available_defenses ORDER BY critical_cves DESC LIMIT 10",
    },
    # ── Outlier candidates ──
    {
        "id": "Q19", "category": "outlier_candidate",
        "question": "Which software has no known defenses?",
        "ground_truth_cypher": "MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software) MATCH (c)-[:MAPS_TO]->(w:CWE) WHERE NOT (w)-[:MITIGATED_BY]->() RETURN DISTINCT s.name AS software LIMIT 20",
    },
    {
        "id": "Q20", "category": "outlier_candidate",
        "question": "What CVEs affect React?",
        "ground_truth_cypher": "MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s:Software) WHERE toLower(s.name) CONTAINS 'react' RETURN c.cve_id, c.description LIMIT 20",
    },
]


# ── Evaluate one ──────────────────────────────────────────────────────────────

def evaluate_one(test: dict) -> dict:
    result = {
        "id":                   test["id"],
        "question":             test["question"],
        "category":             test["category"],
        "cypher_generated":     None,
        "bleu_score":           0.0,    # Translation quality vs ground truth
        "execution_exact_match": False, # Result correctness
        "exact_match_reason":   None,
        "results_count":        0,
        "faithfulness_score":   0,      # 1-5 LLM judge
        "answer_relevance_score": 0,    # 1-5 LLM judge
        "answer":               None,
        "cypher_error":         None,
        "is_outlier":           False,
        "outlier_reasons":      [],
    }

    try:
        # ── Step 1: Generate Cypher ───────────────────────────────────────────
        cypher = generate_cypher(test["question"])
        result["cypher_generated"] = cypher

        # ── Step 2: BLEU Score (translation-based) ────────────────────────────
        result["bleu_score"] = bleu_score(test["ground_truth_cypher"], cypher)
        time.sleep(0.5)

        # ── Step 3: Execution ExactMatch ──────────────────────────────────────
        match, reason = execution_exact_match(test["ground_truth_cypher"], cypher)
        result["execution_exact_match"] = match
        result["exact_match_reason"]    = reason

        # ── Step 4: Run generated Cypher to get results ───────────────────────
        try:
            records = run_cypher(cypher)
            result["results_count"] = len(records)
        except Exception as e:
            result["cypher_error"] = str(e)
            records = []

        # ── Step 5: Generate answer ───────────────────────────────────────────
        answer = generate_answer(test["question"], records)
        result["answer"] = answer
        time.sleep(0.5)

        # ── Step 6: Faithfulness (LLM judge) ──────────────────────────────────
        context = "\n".join(str(r) for r in records[:5]) if records else "No data retrieved."
        result["faithfulness_score"] = llm_score(
            FAITHFULNESS_PROMPT.format(context=context, answer=answer)
        )
        time.sleep(0.5)

        # ── Step 7: Answer Relevance (LLM judge) ──────────────────────────────
        result["answer_relevance_score"] = llm_score(
            RELEVANCE_PROMPT.format(question=test["question"], answer=answer)
        )
        time.sleep(0.5)

    except Exception as e:
        result["cypher_error"] = str(e)

    # ── Outlier Detection ─────────────────────────────────────────────────────
    reasons = []
    if result["bleu_score"] < 0.3:
        reasons.append(f"Low BLEU ({result['bleu_score']:.2f}) — Cypher structure differs significantly")
    if not result["execution_exact_match"]:
        reasons.append(f"ExactMatch failed — {result['exact_match_reason']}")
    if result["faithfulness_score"] <= 2:
        reasons.append(f"Low Faithfulness ({result['faithfulness_score']}/5) — possible hallucination")
    if result["answer_relevance_score"] <= 2:
        reasons.append(f"Low Relevance ({result['answer_relevance_score']}/5) — answer off-topic")
    if result["results_count"] == 0 and not result["cypher_error"]:
        reasons.append("Query returned 0 results — data may not exist in graph")
    if result["cypher_error"]:
        reasons.append(f"Cypher execution error: {result['cypher_error'][:60]}")

    result["is_outlier"]    = len(reasons) > 0
    result["outlier_reasons"] = reasons

    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def run_evaluation():
    print("=" * 65)
    print("🧪 SecurityGraph AI — Standard Evaluation Suite")
    print("   Metrics: BLEU | ExactMatch | Faithfulness | Relevance")
    print(f"   {len(TEST_SET)} questions across 5 categories")
    print("=" * 65)

    results = []
    for test in TEST_SET:
        print(f"\n[{test['id']}] ({test['category']}) {test['question']}")
        r = evaluate_one(test)
        results.append(r)

        print(f"  BLEU Score       : {r['bleu_score']:.2f}")
        print(f"  ExactMatch       : {'✅' if r['execution_exact_match'] else '❌'} — {r['exact_match_reason']}")
        print(f"  Faithfulness     : {r['faithfulness_score']}/5")
        print(f"  Answer Relevance : {r['answer_relevance_score']}/5")
        print(f"  Results          : {r['results_count']} records")
        if r["is_outlier"]:
            print(f"  🚨 OUTLIER:")
            for reason in r["outlier_reasons"]:
                print(f"     - {reason}")

    # ── Aggregate metrics ─────────────────────────────────────────────────────
    total       = len(results)
    avg_bleu    = sum(r["bleu_score"] for r in results) / total
    exact_match = sum(1 for r in results if r["execution_exact_match"]) / total * 100
    avg_faith   = sum(r["faithfulness_score"] for r in results) / total
    avg_relev   = sum(r["answer_relevance_score"] for r in results) / total
    outliers    = [r for r in results if r["is_outlier"]]

    # Per category
    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(r)

    print("\n" + "=" * 65)
    print("📊 FINAL EVALUATION RESULTS")
    print("=" * 65)
    print(f"\n  BLEU Score (Cypher Translation) : {avg_bleu:.2f}  (1.0 = perfect)")
    print(f"  Execution ExactMatch            : {exact_match:.1f}%")
    print(f"  Faithfulness (LLM judge)        : {avg_faith:.2f}/5")
    print(f"  Answer Relevance (LLM judge)    : {avg_relev:.2f}/5")
    print(f"  Outliers Detected               : {len(outliers)}/{total}")

    print(f"\n  By Category:")
    for cat, cr in categories.items():
        b = sum(r["bleu_score"] for r in cr) / len(cr)
        e = sum(1 for r in cr if r["execution_exact_match"]) / len(cr) * 100
        f = sum(r["faithfulness_score"] for r in cr) / len(cr)
        rv = sum(r["answer_relevance_score"] for r in cr) / len(cr)
        print(f"  {cat:<20} BLEU:{b:.2f} ExactMatch:{e:.0f}% Faith:{f:.1f} Relev:{rv:.1f}")

    if outliers:
        print(f"\n  🚨 OUTLIER ANALYSIS ({len(outliers)} questions):")
        for r in outliers:
            print(f"\n  [{r['id']}] {r['question']}")
            for reason in r["outlier_reasons"]:
                print(f"     → {reason}")

    # Save
    output = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total": total,
            "avg_bleu_score": round(avg_bleu, 4),
            "execution_exact_match_rate": f"{exact_match:.1f}%",
            "avg_faithfulness": round(avg_faith, 2),
            "avg_answer_relevance": round(avg_relev, 2),
            "outlier_count": len(outliers),
        },
        "by_category": {
            cat: {
                "avg_bleu": round(sum(r["bleu_score"] for r in cr) / len(cr), 4),
                "exact_match_rate": f"{sum(1 for r in cr if r['execution_exact_match'])/len(cr)*100:.0f}%",
                "avg_faithfulness": round(sum(r["faithfulness_score"] for r in cr) / len(cr), 2),
                "avg_relevance": round(sum(r["answer_relevance_score"] for r in cr) / len(cr), 2),
            }
            for cat, cr in categories.items()
        },
        "outliers": [
            {
                "id": r["id"],
                "question": r["question"],
                "category": r["category"],
                "bleu_score": r["bleu_score"],
                "exact_match": r["execution_exact_match"],
                "faithfulness": r["faithfulness_score"],
                "relevance": r["answer_relevance_score"],
                "reasons": r["outlier_reasons"],
            }
            for r in outliers
        ],
        "detailed_results": results,
    }

    os.makedirs("evaluation", exist_ok=True)
    with open("evaluation/results.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n  📄 Saved to evaluation/results.json")
    print("=" * 65)
    return output


if __name__ == "__main__":
    run_evaluation()