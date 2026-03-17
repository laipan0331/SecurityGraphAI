from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
ENHANCED_CVES = DATA_DIR / "enhanced_cves.csv"


def make_df(rows, columns):
    return pd.DataFrame(rows, columns=columns)


def build_reference_tables():
    owasp = [
        ("OWASP-2021-A01", "Broken Access Control", "Authorization weaknesses", "Authorization"),
        ("OWASP-2021-A02", "Cryptographic Failures", "Weak or missing crypto", "Data Protection"),
        ("OWASP-2021-A03", "Injection", "Untrusted input interpreted as code", "Input Handling"),
        ("OWASP-2021-A04", "Insecure Design", "Missing security by design", "Architecture"),
        ("OWASP-2021-A05", "Security Misconfiguration", "Unsafe default settings", "Configuration"),
        ("OWASP-2021-A06", "Vulnerable Components", "Outdated vulnerable dependencies", "Supply Chain"),
        ("OWASP-2021-A07", "Auth Failures", "Identity/session weaknesses", "Identity"),
        ("OWASP-2021-A08", "Integrity Failures", "Code/data integrity issues", "Integrity"),
        ("OWASP-2021-A09", "Logging Failures", "Missing detection and monitoring", "Detection"),
        ("OWASP-2021-A10", "SSRF", "Server-side request forgery", "Networking"),
    ]

    vulnerabilities = [
        "SQL Injection", "Blind SQL Injection", "NoSQL Injection", "LDAP Injection", "Command Injection",
        "Cross-Site Scripting", "Stored XSS", "DOM XSS", "Cross-Site Request Forgery", "Server-Side Request Forgery",
        "XML External Entity", "Path Traversal", "Local File Inclusion", "Remote File Inclusion", "Insecure Deserialization",
        "Authentication Bypass", "Broken Access Control", "Privilege Escalation", "Session Fixation", "Credential Stuffing",
        "Security Misconfiguration", "Sensitive Data Exposure", "Information Disclosure", "Insecure Direct Object Reference", "Open Redirect",
        "Buffer Overflow", "Heap Overflow", "Race Condition", "Denial of Service", "Insecure File Upload",
        "Hardcoded Credentials", "Integer Overflow", "Use After Free", "Clickjacking", "Regex DoS", "Format String",
    ]

    defenses = [
        "Parameterized Queries", "Allowlist Input Validation", "Output Encoding", "Content Security Policy", "CSRF Tokens",
        "SameSite Cookies", "Least Privilege", "Role-Based Access Control", "Multi-Factor Authentication", "Secure Session Management",
        "Password Hashing", "Secrets Management", "Dependency Scanning", "SAST", "DAST",
        "Web Application Firewall", "Egress Filtering", "XML Parser Hardening", "File Upload Validation", "Path Normalization",
        "Sandboxing", "Rate Limiting", "Security Headers", "Patch Management", "Centralized Logging",
        "Encryption at Rest", "TLS Everywhere", "Secure Code Review", "Network Segmentation", "Backup and Recovery",
        "Deserialization Allowlist", "Memory-Safe Languages", "Binary Hardening", "Account Lockout", "Configuration Baselines",
    ]

    technologies = [
        "PHP", "Java", "Python", "JavaScript", "TypeScript", "C#", ".NET", "Spring Boot", "Django", "Flask",
        "Node.js", "Express.js", "React", "Angular", "Vue.js", "WordPress", "Drupal", "Joomla", "Apache HTTP Server", "Nginx",
        "Microsoft IIS", "Tomcat", "Oracle WebLogic", "Oracle Database", "MySQL", "PostgreSQL", "Microsoft SQL Server", "MongoDB", "Redis", "Docker",
        "Kubernetes", "Linux", "Windows Server", "OpenSSL", "Jenkins", "GitLab CI", "GitHub Actions", "Neo4j", "Apache Struts", "Log4j",
        "Bugzilla", "MediaWiki", "SquirrelMail", "Horde", "Citrix Presentation Server",
    ]

    tools = [
        "Burp Suite", "OWASP ZAP", "Nmap", "Nessus", "Nikto", "sqlmap", "Metasploit", "Wireshark",
        "Trivy", "Snyk", "SonarQube", "Semgrep", "GitGuardian", "HashiCorp Vault", "CrowdStrike Falcon", "Suricata",
        "Snort", "ModSecurity", "Falco", "OpenVAS", "OWASP Dependency-Check", "kube-bench", "Checkov", "Gitleaks",
    ]

    cwes = [
        ("CWE-20", "Improper Input Validation"), ("CWE-22", "Path Traversal"), ("CWE-79", "Cross-Site Scripting"), ("CWE-89", "SQL Injection"),
        ("CWE-94", "Code Injection"), ("CWE-134", "Format String"), ("CWE-190", "Integer Overflow"), ("CWE-200", "Information Exposure"),
        ("CWE-285", "Improper Authorization"), ("CWE-287", "Improper Authentication"), ("CWE-307", "Auth Attempt Limits"), ("CWE-352", "CSRF"),
        ("CWE-362", "Race Condition"), ("CWE-400", "Resource Consumption"), ("CWE-434", "Unrestricted File Upload"), ("CWE-416", "Use After Free"),
        ("CWE-476", "Null Pointer Dereference"), ("CWE-502", "Insecure Deserialization"), ("CWE-601", "Open Redirect"), ("CWE-611", "XXE"),
        ("CWE-639", "IDOR"), ("CWE-732", "Permission Assignment"), ("CWE-787", "Out-of-Bounds Write"), ("CWE-798", "Hardcoded Credentials"),
        ("CWE-863", "Authorization"), ("CWE-918", "SSRF"), ("CWE-1021", "Clickjacking"), ("CWE-119", "Buffer Overflow"),
    ]

    owasp_df = make_df(owasp, ["owasp_id", "name", "description", "focus_area"])

    vuln_rows = []
    for i, name in enumerate(vulnerabilities, start=1):
        severity = ["Medium", "High", "Critical"][i % 3]
        owasp_id = owasp[(i - 1) % len(owasp)][0]
        category = ["Injection", "Auth", "Access", "Memory", "Availability", "Configuration"][i % 6]
        vuln_rows.append((f"VULN-{i:03d}", name, f"{name} weakness in application stack.", severity, owasp_id, category))
    vuln_df = make_df(vuln_rows, ["id", "name", "description", "severity", "owasp_rank", "category"])

    def_rows = []
    for i, name in enumerate(defenses, start=1):
        def_rows.append((f"DEF-{i:03d}", name, f"Mitigation strategy: {name}", f"Implement {name} in SDLC and deployment."))
    def_df = make_df(def_rows, ["id", "name", "description", "implementation"])

    tech_rows = []
    for i, name in enumerate(technologies, start=1):
        tech_rows.append((f"TECH-{i:03d}", name, "Technology", "Various", f"Technology platform: {name}."))
    tech_df = make_df(tech_rows, ["id", "name", "category", "vendor", "description"])

    tool_rows = []
    for i, name in enumerate(tools, start=1):
        tool_rows.append((f"TOOL-{i:03d}", name, "Security Tool", "Various", f"Security tool: {name}."))
    tool_df = make_df(tool_rows, ["id", "name", "category", "vendor", "description"])

    cwe_rows = []
    for cwe_id, name in cwes:
        cwe_rows.append((cwe_id, name, f"{name} weakness class.", "Base"))
    cwe_df = make_df(cwe_rows, ["cwe_id", "name", "description", "abstraction"])

    return owasp_df, vuln_df, def_df, tech_df, tool_df, cwe_df


def build_relation_tables(vuln_df, def_df, tool_df, cwe_df, tech_df):
    vuln_ids = vuln_df["id"].tolist()
    def_ids = def_df["id"].tolist()
    tool_ids = tool_df["id"].tolist()
    cwe_ids = cwe_df["cwe_id"].tolist()

    vuln_def = []
    vuln_tool = []
    vuln_cwe = []
    vuln_owasp = []

    for i, row in enumerate(vuln_df.itertuples(index=False), start=0):
        vuln_id = row.id
        vuln_def.append((vuln_id, def_ids[i % len(def_ids)], "MITIGATED_BY"))
        vuln_def.append((vuln_id, def_ids[(i + 7) % len(def_ids)], "MITIGATED_BY"))

        vuln_tool.append((vuln_id, tool_ids[i % len(tool_ids)], "DETECTED_BY"))
        vuln_tool.append((vuln_id, tool_ids[(i + 3) % len(tool_ids)], "DETECTED_BY"))

        vuln_cwe.append((vuln_id, cwe_ids[i % len(cwe_ids)], "MAPPED_TO"))
        vuln_owasp.append((vuln_id, row.owasp_rank, "ALIGNS_WITH"))

    vuln_def_df = make_df(sorted(set(vuln_def)), ["vulnerability_id", "defense_id", "relationship"])
    vuln_tool_df = make_df(sorted(set(vuln_tool)), ["vulnerability_id", "tool_id", "relationship"])
    vuln_cwe_df = make_df(sorted(set(vuln_cwe)), ["vulnerability_id", "cwe_id", "relationship"])
    vuln_owasp_df = make_df(sorted(set(vuln_owasp)), ["vulnerability_id", "owasp_id", "relationship"])

    cve_tech_rows = []
    if ENHANCED_CVES.exists():
        cve_df = pd.read_csv(ENHANCED_CVES)
        tech_names = tech_df["name"].str.lower().tolist()
        tech_map = dict(zip(tech_df["name"].str.lower(), tech_df["id"]))

        for row in cve_df.itertuples(index=False):
            text = f"{getattr(row, 'software_name', '')} {getattr(row, 'description', '')}".lower()
            matches = [name for name in tech_names if name in text]
            for name in matches[:2]:
                cve_tech_rows.append((row.cve_id, tech_map[name], "AFFECTS", "text match"))

    cve_tech_df = make_df(sorted(set(cve_tech_rows)), ["cve_id", "technology_id", "relationship", "evidence"])
    return vuln_def_df, vuln_tool_df, vuln_cwe_df, vuln_owasp_df, cve_tech_df


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    owasp_df, vuln_df, def_df, tech_df, tool_df, cwe_df = build_reference_tables()
    vuln_def_df, vuln_tool_df, vuln_cwe_df, vuln_owasp_df, cve_tech_df = build_relation_tables(vuln_df, def_df, tool_df, cwe_df, tech_df)

    owasp_df.to_csv(DATA_DIR / "owasp_categories.csv", index=False)
    vuln_df.to_csv(DATA_DIR / "vulnerabilities.csv", index=False)
    def_df.to_csv(DATA_DIR / "defenses.csv", index=False)
    tech_df.to_csv(DATA_DIR / "technologies.csv", index=False)
    tool_df.to_csv(DATA_DIR / "tools.csv", index=False)
    cwe_df.to_csv(DATA_DIR / "cwes.csv", index=False)

    vuln_def_df.to_csv(DATA_DIR / "vuln_defenses.csv", index=False)
    cve_tech_df.to_csv(DATA_DIR / "cve_technologies.csv", index=False)
    vuln_tool_df.to_csv(DATA_DIR / "vuln_tools.csv", index=False)
    vuln_cwe_df.to_csv(DATA_DIR / "vuln_cwes.csv", index=False)
    vuln_owasp_df.to_csv(DATA_DIR / "vuln_owasp.csv", index=False)

    print("Generated supplemental files:")
    for name, df in [
        ("owasp_categories.csv", owasp_df),
        ("vulnerabilities.csv", vuln_df),
        ("defenses.csv", def_df),
        ("technologies.csv", tech_df),
        ("tools.csv", tool_df),
        ("cwes.csv", cwe_df),
        ("vuln_defenses.csv", vuln_def_df),
        ("cve_technologies.csv", cve_tech_df),
        ("vuln_tools.csv", vuln_tool_df),
        ("vuln_cwes.csv", vuln_cwe_df),
        ("vuln_owasp.csv", vuln_owasp_df),
    ]:
        print(f"- {name}: {len(df)} rows")


if __name__ == "__main__":
    main()
