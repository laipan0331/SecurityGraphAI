"""
SecurityGraph AI - Step 6: Data Quality Check
Validate key dataset quality rules and write a report to data/data_quality_report.txt.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORT_PATH = DATA_DIR / "data_quality_report.txt"


@dataclass
class CheckResult:
    name: str
    passed: bool
    details: str


def safe_read_csv(path: Path) -> pd.DataFrame:
    return pd.read_csv(path)


def missing_files(files: Iterable[str]) -> list[str]:
    return [name for name in files if not (DATA_DIR / name).exists()]


def check_primary_key(df: pd.DataFrame, key: str, label: str) -> list[CheckResult]:
    null_count = int(df[key].isna().sum())
    duplicate_count = int(df.duplicated(subset=[key]).sum())

    return [
        CheckResult(
            name=f"{label}: {key} has no nulls",
            passed=null_count == 0,
            details=f"null_count={null_count}",
        ),
        CheckResult(
            name=f"{label}: {key} is unique",
            passed=duplicate_count == 0,
            details=f"duplicate_count={duplicate_count}",
        ),
    ]


def check_fk(
    relation_df: pd.DataFrame,
    fk_col: str,
    parent_df: pd.DataFrame,
    parent_key: str,
    label: str,
) -> CheckResult:
    fk_values = set(relation_df[fk_col].dropna().astype(str))
    parent_values = set(parent_df[parent_key].dropna().astype(str))
    invalid = sorted(fk_values - parent_values)

    preview = ", ".join(invalid[:5]) if invalid else "none"
    return CheckResult(
        name=f"{label}: {fk_col} -> {parent_key}",
        passed=len(invalid) == 0,
        details=f"invalid_count={len(invalid)}; sample={preview}",
    )


def check_processed_cves(processed: pd.DataFrame) -> list[CheckResult]:
    results: list[CheckResult] = []

    results.extend(check_primary_key(processed, "cve_id", "processed_cves"))

    # CVSS range should be within [0, 10] when present.
    cvss = pd.to_numeric(processed["cvss_score"], errors="coerce")
    out_of_range = int(((cvss < 0) | (cvss > 10)).fillna(False).sum())
    results.append(
        CheckResult(
            name="processed_cves: cvss_score in [0,10]",
            passed=out_of_range == 0,
            details=f"out_of_range={out_of_range}",
        )
    )

    allowed_severity = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
    severity_values = set(processed["severity"].dropna().astype(str).str.upper())
    invalid_severity = sorted(severity_values - allowed_severity)
    results.append(
        CheckResult(
            name="processed_cves: severity values are valid",
            passed=len(invalid_severity) == 0,
            details=f"invalid_values={invalid_severity if invalid_severity else 'none'}",
        )
    )

    parsed_dates = pd.to_datetime(processed["published_date"], errors="coerce", utc=True)
    invalid_dates = int(parsed_dates.isna().sum())
    results.append(
        CheckResult(
            name="processed_cves: published_date parseable",
            passed=invalid_dates == 0,
            details=f"invalid_date_count={invalid_dates}",
        )
    )

    return results


def check_split_integrity(
    processed: pd.DataFrame, train: pd.DataFrame, val: pd.DataFrame, test: pd.DataFrame
) -> list[CheckResult]:
    results: list[CheckResult] = []

    pset = set(processed["cve_id"].astype(str))
    train_set = set(train["cve_id"].astype(str))
    val_set = set(val["cve_id"].astype(str))
    test_set = set(test["cve_id"].astype(str))

    inter_train_val = len(train_set & val_set)
    inter_train_test = len(train_set & test_set)
    inter_val_test = len(val_set & test_set)

    results.append(
        CheckResult(
            name="splits: train/val/test are mutually exclusive",
            passed=(inter_train_val == 0 and inter_train_test == 0 and inter_val_test == 0),
            details=(
                f"train_val_overlap={inter_train_val}, "
                f"train_test_overlap={inter_train_test}, "
                f"val_test_overlap={inter_val_test}"
            ),
        )
    )

    union_count = len(train_set | val_set | test_set)
    missing_in_splits = len(pset - (train_set | val_set | test_set))
    extra_in_splits = len((train_set | val_set | test_set) - pset)

    results.append(
        CheckResult(
            name="splits: union matches processed_cves",
            passed=(union_count == len(pset) and missing_in_splits == 0 and extra_in_splits == 0),
            details=(
                f"processed={len(pset)}, union={union_count}, "
                f"missing={missing_in_splits}, extra={extra_in_splits}"
            ),
        )
    )

    return results


def build_report(results: list[CheckResult], dataset_sizes: dict[str, int]) -> str:
    pass_count = sum(1 for r in results if r.passed)
    fail_count = len(results) - pass_count
    overall = "PASS" if fail_count == 0 else "FAIL"

    lines = []
    lines.append("=" * 78)
    lines.append("SECURITYGRAPH AI - DATA QUALITY REPORT")
    lines.append("=" * 78)
    lines.append("")
    lines.append("Dataset Sizes")
    lines.append("-" * 78)
    for name, size in dataset_sizes.items():
        lines.append(f"- {name}: {size}")

    lines.append("")
    lines.append("Quality Checks")
    lines.append("-" * 78)
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        lines.append(f"[{status}] {result.name}")
        lines.append(f"  {result.details}")

    lines.append("")
    lines.append("Summary")
    lines.append("-" * 78)
    lines.append(f"Overall: {overall}")
    lines.append(f"Passed: {pass_count}")
    lines.append(f"Failed: {fail_count}")
    lines.append("")

    if fail_count > 0:
        lines.append("Failed Checks")
        lines.append("-" * 78)
        for result in results:
            if not result.passed:
                lines.append(f"- {result.name}: {result.details}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    required = [
        "processed_cves.csv",
        "enhanced_cves.csv",
        "train.csv",
        "val.csv",
        "test.csv",
        "vulnerabilities.csv",
        "defenses.csv",
        "tools.csv",
        "cwes.csv",
        "owasp_categories.csv",
        "technologies.csv",
        "vuln_defenses.csv",
        "vuln_tools.csv",
        "vuln_cwes.csv",
        "vuln_owasp.csv",
        "cve_technologies.csv",
    ]

    missing = missing_files(required)
    if missing:
        raise FileNotFoundError(f"Missing required data files: {missing}")

    processed = safe_read_csv(DATA_DIR / "processed_cves.csv")
    enhanced = safe_read_csv(DATA_DIR / "enhanced_cves.csv")
    train = safe_read_csv(DATA_DIR / "train.csv")
    val = safe_read_csv(DATA_DIR / "val.csv")
    test = safe_read_csv(DATA_DIR / "test.csv")

    vulnerabilities = safe_read_csv(DATA_DIR / "vulnerabilities.csv")
    defenses = safe_read_csv(DATA_DIR / "defenses.csv")
    tools = safe_read_csv(DATA_DIR / "tools.csv")
    cwes = safe_read_csv(DATA_DIR / "cwes.csv")
    owasp = safe_read_csv(DATA_DIR / "owasp_categories.csv")
    technologies = safe_read_csv(DATA_DIR / "technologies.csv")

    vuln_def = safe_read_csv(DATA_DIR / "vuln_defenses.csv")
    vuln_tool = safe_read_csv(DATA_DIR / "vuln_tools.csv")
    vuln_cwe = safe_read_csv(DATA_DIR / "vuln_cwes.csv")
    vuln_owasp = safe_read_csv(DATA_DIR / "vuln_owasp.csv")
    cve_tech = safe_read_csv(DATA_DIR / "cve_technologies.csv")

    results: list[CheckResult] = []

    results.extend(check_processed_cves(processed))
    results.extend(check_primary_key(enhanced, "cve_id", "enhanced_cves"))
    results.extend(check_primary_key(vulnerabilities, "id", "vulnerabilities"))
    results.extend(check_primary_key(defenses, "id", "defenses"))
    results.extend(check_primary_key(tools, "id", "tools"))
    results.extend(check_primary_key(technologies, "id", "technologies"))
    results.extend(check_primary_key(cwes, "cwe_id", "cwes"))
    results.extend(check_primary_key(owasp, "owasp_id", "owasp_categories"))

    results.extend(check_split_integrity(processed, train, val, test))

    results.append(check_fk(vuln_def, "vulnerability_id", vulnerabilities, "id", "vuln_defenses"))
    results.append(check_fk(vuln_def, "defense_id", defenses, "id", "vuln_defenses"))

    results.append(check_fk(vuln_tool, "vulnerability_id", vulnerabilities, "id", "vuln_tools"))
    results.append(check_fk(vuln_tool, "tool_id", tools, "id", "vuln_tools"))

    results.append(check_fk(vuln_cwe, "vulnerability_id", vulnerabilities, "id", "vuln_cwes"))
    results.append(check_fk(vuln_cwe, "cwe_id", cwes, "cwe_id", "vuln_cwes"))

    results.append(check_fk(vuln_owasp, "vulnerability_id", vulnerabilities, "id", "vuln_owasp"))
    results.append(check_fk(vuln_owasp, "owasp_id", owasp, "owasp_id", "vuln_owasp"))

    results.append(check_fk(cve_tech, "technology_id", technologies, "id", "cve_technologies"))
    results.append(
        check_fk(cve_tech, "cve_id", processed, "cve_id", "cve_technologies")
    )

    dataset_sizes = {
        "processed_cves.csv": len(processed),
        "enhanced_cves.csv": len(enhanced),
        "train.csv": len(train),
        "val.csv": len(val),
        "test.csv": len(test),
        "vulnerabilities.csv": len(vulnerabilities),
        "defenses.csv": len(defenses),
        "tools.csv": len(tools),
        "technologies.csv": len(technologies),
        "cwes.csv": len(cwes),
        "owasp_categories.csv": len(owasp),
        "vuln_defenses.csv": len(vuln_def),
        "vuln_tools.csv": len(vuln_tool),
        "vuln_cwes.csv": len(vuln_cwe),
        "vuln_owasp.csv": len(vuln_owasp),
        "cve_technologies.csv": len(cve_tech),
    }

    report_text = build_report(results, dataset_sizes)
    REPORT_PATH.write_text(report_text, encoding="utf-8")

    print(report_text)
    print(f"Report saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()
