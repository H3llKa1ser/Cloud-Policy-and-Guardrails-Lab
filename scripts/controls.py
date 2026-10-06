#!/usr/bin/env python3
"""Compliance mapping for the guardrail policies.

Every rule in policies/aws carries an OPA METADATA annotation with its ID,
level, severity and control mappings. This tool reads those annotations
(via `opa inspect`) and:

  check                 validate the catalogue and its consistency with the
                        regression stack (exit 1 on any problem)
  catalogue             render docs/CONTROLS.md to stdout
  report <results.json> render a compliance report for one plan from
                        `conftest --output json` results
                        (--format markdown|json, default markdown)

Standard library only, so it runs anywhere OPA does.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICY_DIR = ROOT / "policies"
EXPECTED = ROOT / "examples" / "noncompliant" / "expected-violations.txt"

FRAMEWORKS = {
    "aws_fsbp": "AWS Foundational Security Best Practices",
    "cis_aws_v5": "CIS AWS Foundations Benchmark v5.0.0",
    "nist_800_53_r5": "NIST SP 800-53 Rev. 5",
}

NIST_FAMILIES = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "RA": "Risk Assessment",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

LEVELS = {"deny", "warn"}
SEVERITIES = ["critical", "high", "medium", "low"]
MAPPINGS = {"aws-security-hub", "author"}

ID_RE = re.compile(r"^[A-Z][A-Z0-9]*_\d{3}$")
FSBP_RE = re.compile(r"^[A-Za-z0-9]+\.\d+$")
CIS_RE = re.compile(r"^\d+(\.\d+)+$")
NIST_RE = re.compile(r"^[A-Z]{2}-\d+$")
FINDING_RE = re.compile(r"^\[(?P<id>[A-Z][A-Z0-9]*_\d{3})\] (?P<subject>[^:]+): (?P<text>.*)$")


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def load_rules() -> list[dict]:
    """Return one dict per annotated rule, sorted by ID."""
    out = subprocess.run(
        ["opa", "inspect", "--annotations", "--format", "json", str(POLICY_DIR)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    rules = []
    for entry in json.loads(out).get("annotations", []):
        ann = entry.get("annotations", {})
        custom = ann.get("custom") or {}
        if "id" not in custom:
            continue
        path = ".".join(str(p["value"]) for p in entry.get("path", []))
        location = entry.get("location", {})
        rules.append(
            {
                "id": custom["id"],
                "title": ann.get("title", ""),
                "description": ann.get("description", ""),
                "level": custom.get("level"),
                "severity": custom.get("severity"),
                "mapping": custom.get("mapping"),
                "controls": custom.get("controls") or {},
                "package": path.removeprefix("data.").rsplit(".", 1)[0],
                "file": Path(location.get("file", "")).name,
                "row": location.get("row"),
            }
        )
    return sorted(rules, key=lambda r: r["id"])


def load_expected() -> set[tuple[str, str]]:
    pairs = set()
    for line in EXPECTED.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            level, rule_id = line.split()
            pairs.add((level, rule_id))
    return pairs


# --------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------


def validate(rules: list[dict]) -> list[str]:
    errors = []
    seen: dict[str, str] = {}
    for r in rules:
        where = f"{r['id']} ({r['file']}:{r['row']})"
        if not ID_RE.match(r["id"]):
            errors.append(f"{where}: id must look like ABC_001")
        if r["id"] in seen:
            errors.append(f"{where}: duplicate id, also in {seen[r['id']]}")
        seen[r["id"]] = where
        if not r["title"]:
            errors.append(f"{where}: missing title")
        if r["level"] not in LEVELS:
            errors.append(f"{where}: level must be one of {sorted(LEVELS)}")
        # Convention: _0xx rules block, _1xx rules advise.
        number = int(r["id"].rsplit("_", 1)[-1])
        expected_level = "warn" if number >= 100 else "deny"
        if r["level"] in LEVELS and r["level"] != expected_level:
            errors.append(f"{where}: ids {'>=' if number >= 100 else '<'} 100 must be level {expected_level}")
        if r["severity"] not in SEVERITIES:
            errors.append(f"{where}: severity must be one of {SEVERITIES}")
        if r["mapping"] not in MAPPINGS:
            errors.append(f"{where}: mapping must be one of {sorted(MAPPINGS)}")
        controls = r["controls"]
        unknown = set(controls) - set(FRAMEWORKS)
        if unknown:
            errors.append(f"{where}: unknown frameworks {sorted(unknown)}")
        if not controls.get("nist_800_53_r5"):
            errors.append(f"{where}: every rule needs at least one NIST 800-53 control")
        if r["mapping"] == "aws-security-hub" and not controls.get("aws_fsbp"):
            errors.append(f"{where}: mapping aws-security-hub requires aws_fsbp controls")
        for framework, pattern in (("aws_fsbp", FSBP_RE), ("cis_aws_v5", CIS_RE), ("nist_800_53_r5", NIST_RE)):
            for c in controls.get(framework, []):
                if not pattern.match(str(c)):
                    errors.append(f"{where}: malformed {framework} control {c!r}")
    return errors


def check_regression_coverage(rules: list[dict]) -> list[str]:
    """Every resource rule must be proven against the real regression plan."""
    errors = []
    catalogue = {(r["level"], r["id"]) for r in rules}
    expected = load_expected()
    for level, rule_id in sorted(expected - catalogue):
        errors.append(f"expected-violations.txt lists '{level} {rule_id}' but no such rule exists")
    for level, rule_id in sorted(catalogue - expected):
        if not rule_id.startswith("GOV_"):  # data-driven, covered by unit tests
            errors.append(f"{rule_id} has no case in examples/noncompliant (add one and list '{level} {rule_id}')")
    return errors


def cmd_check(_args) -> int:
    rules = load_rules()
    errors = validate(rules) + check_regression_coverage(rules)
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"OK: {len(rules)} rules, metadata valid, all resource rules covered by the regression stack")
    return 0


# --------------------------------------------------------------------------
# Rendering helpers
# --------------------------------------------------------------------------


def fsbp_link(control: str) -> str:
    service, number = control.split(".")
    return (
        f"[{control}](https://docs.aws.amazon.com/securityhub/latest/userguide/"
        f"{service.lower()}-controls.html#{service.lower()}-{number})"
    )


def version_key(value: str):
    return [int(p) for p in value.split(".")]


def nist_key(value: str):
    family, number = value.split("-")
    return (family, int(number))


def sort_controls(framework: str, controls) -> list[str]:
    controls = [str(c) for c in controls]
    if framework == "cis_aws_v5":
        return sorted(set(controls), key=version_key)
    if framework == "nist_800_53_r5":
        return sorted(set(controls), key=nist_key)
    return sorted(set(controls), key=lambda c: (c.split(".")[0], int(c.split(".")[1])))


def render_controls(framework: str, controls) -> str:
    items = sort_controls(framework, controls)
    if not items:
        return "–"
    if framework == "aws_fsbp":
        return ", ".join(fsbp_link(c) for c in items)
    return ", ".join(items)


def reverse_index(rules: list[dict], framework: str) -> dict[str, list[dict]]:
    index = defaultdict(list)
    for r in rules:
        for c in r["controls"].get(framework, []):
            index[str(c)].append(r)
    return index


def code_list(ids) -> str:
    return ", ".join(f"`{i}`" for i in ids)


def level_icon(level: str) -> str:
    return "⛔ deny" if level == "deny" else "⚠️ warn"


# --------------------------------------------------------------------------
# catalogue
# --------------------------------------------------------------------------


def cmd_catalogue(_args) -> int:
    rules = load_rules()
    mapped = sum(1 for r in rules if r["mapping"] == "aws-security-hub")
    out = []
    w = out.append

    w("<!-- Generated by scripts/controls.py from policy METADATA. Do not edit; run `make controls`. -->")
    w("")
    w("# Control catalogue")
    w("")
    w(
        f"{len(rules)} guardrail rules, {mapped} mapped through an equivalent AWS Security Hub control "
        f"and {len(rules) - mapped} mapped by the author where no equivalent Security Hub control exists."
    )
    w("")
    w(
        "Mappings marked **aws-security-hub** take their CIS AWS Foundations v5.0.0 and NIST SP 800-53 Rev. 5 "
        "references from the [AWS Security Hub control reference]"
        "(https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html) "
        "for the listed FSBP control. NIST references are given at base-control level; the linked "
        "Security Hub control lists the specific enhancements. Mappings marked **author** are this "
        "project's own judgement and should be reviewed before being relied on for audit."
    )
    w("")
    w(
        "A guardrail is a *preventive, plan-time* control: it shows that infrastructure changed through "
        "Terraform is checked against a requirement, not that a running account meets it. Pair it with "
        "detective controls (Security Hub, AWS Config) for the runtime picture."
    )
    w("")

    w("## Rules")
    w("")
    w("| ID | Level | Severity | Rule | AWS FSBP | CIS v5.0.0 | NIST 800-53 r5 | Mapping |")
    w("|---|---|---|---|---|---|---|---|")
    for r in rules:
        c = r["controls"]
        w(
            f"| `{r['id']}` | {level_icon(r['level'])} | {r['severity']} | {r['title']} | "
            f"{render_controls('aws_fsbp', c.get('aws_fsbp', []))} | "
            f"{render_controls('cis_aws_v5', c.get('cis_aws_v5', []))} | "
            f"{render_controls('nist_800_53_r5', c.get('nist_800_53_r5', []))} | {r['mapping']} |"
        )
    w("")

    w("## CIS AWS Foundations Benchmark v5.0.0")
    w("")
    w("Requirements with at least one plan-time guardrail.")
    w("")
    w("| Requirement | Guardrails |")
    w("|---|---|")
    cis = reverse_index(rules, "cis_aws_v5")
    for req in sorted(cis, key=version_key):
        w(f"| {req} | {code_list(r['id'] for r in cis[req])} |")
    w("")

    w("## NIST SP 800-53 Rev. 5")
    w("")
    w("| Control | Guardrails |")
    w("|---|---|")
    nist = reverse_index(rules, "nist_800_53_r5")
    current_family = None
    for control in sorted(nist, key=nist_key):
        family = control.split("-")[0]
        if family != current_family:
            current_family = family
            w(f"| **{family}: {NIST_FAMILIES.get(family, family)}** | |")
        w(f"| {control} | {code_list(r['id'] for r in nist[control])} |")
    w("")

    w("## AWS Foundational Security Best Practices")
    w("")
    w("| Security Hub control | Guardrails |")
    w("|---|---|")
    fsbp = reverse_index(rules, "aws_fsbp")
    for control in sort_controls("aws_fsbp", fsbp):
        w(f"| {fsbp_link(control)} | {code_list(r['id'] for r in fsbp[control])} |")
    w("")

    print("\n".join(out))
    return 0


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------


def parse_results(path: Path) -> list[dict]:
    findings = []
    for namespace in json.loads(path.read_text()):
        for level, key in (("deny", "failures"), ("warn", "warnings")):
            for item in namespace.get(key) or []:
                m = FINDING_RE.match(item["msg"])
                if m:
                    findings.append({"level": level, **m.groupdict()})
    return findings


def build_report(rules: list[dict], findings: list[dict], plan: str) -> dict:
    by_id = {r["id"]: r for r in rules}
    by_rule = defaultdict(list)
    for f in findings:
        by_rule[f["id"]].append(f)

    def status(rule_ids: list[str]) -> str:
        levels = {f["level"] for rid in rule_ids for f in by_rule.get(rid, [])}
        if "deny" in levels:
            return "fail"
        if "warn" in levels:
            return "advisory"
        return "no-violations"

    frameworks = {}
    for framework in FRAMEWORKS:
        index = reverse_index(rules, framework)
        frameworks[framework] = [
            {
                "control": control,
                "status": status([r["id"] for r in index[control]]),
                "rules": [r["id"] for r in index[control]],
                "findings": sum(len(by_rule.get(r["id"], [])) for r in index[control]),
            }
            for control in sort_controls(framework, index)
        ]

    return {
        "plan": plan,
        "summary": {
            "rules_evaluated": len(rules),
            "blocking_findings": sum(1 for f in findings if f["level"] == "deny"),
            "advisory_findings": sum(1 for f in findings if f["level"] == "warn"),
        },
        "frameworks": frameworks,
        "findings": [
            {
                **f,
                "title": by_id.get(f["id"], {}).get("title", ""),
                "severity": by_id.get(f["id"], {}).get("severity", ""),
                "controls": by_id.get(f["id"], {}).get("controls", {}),
            }
            for f in sorted(
                findings,
                key=lambda f: (
                    f["level"] != "deny",
                    SEVERITIES.index(by_id.get(f["id"], {}).get("severity", "low")),
                    f["id"],
                    f["subject"],
                ),
            )
        ],
    }


STATUS_ICON = {"fail": "❌ fail", "advisory": "⚠️ advisory", "no-violations": "✅ no violations"}


def render_report_markdown(report: dict) -> str:
    out = []
    w = out.append
    s = report["summary"]
    w(f"### Compliance view: `{report['plan']}`")
    w("")
    w(
        f"{s['blocking_findings']} blocking and {s['advisory_findings']} advisory findings across "
        f"{s['rules_evaluated']} rules. Plan-time evidence only; see docs/CONTROLS.md for scope."
    )
    w("")
    for framework in ("cis_aws_v5", "nist_800_53_r5"):
        rows = report["frameworks"][framework]
        failing = sum(1 for r in rows if r["status"] == "fail")
        w(f"<details><summary><b>{FRAMEWORKS[framework]}</b>: {failing} of {len(rows)} mapped controls failing</summary>")
        w("")
        w("| Control | Status | Guardrails | Findings |")
        w("|---|---|---|---|")
        for r in rows:
            w(f"| {r['control']} | {STATUS_ICON[r['status']]} | {code_list(r['rules'])} | {r['findings']} |")
        w("")
        w("</details>")
        w("")
    if report["findings"]:
        w("| | Severity | Rule | Resource | Finding | CIS v5 | NIST |")
        w("|---|---|---|---|---|---|---|")
        for f in report["findings"]:
            c = f["controls"]
            icon = "⛔" if f["level"] == "deny" else "⚠️"
            text = f["text"].replace("|", "\\|")
            w(
                f"| {icon} | {f['severity']} | `{f['id']}` | `{f['subject']}` | {text} | "
                f"{render_controls('cis_aws_v5', c.get('cis_aws_v5', []))} | "
                f"{render_controls('nist_800_53_r5', c.get('nist_800_53_r5', []))} |"
            )
        w("")
    return "\n".join(out)


def cmd_report(args) -> int:
    rules = load_rules()
    findings = parse_results(Path(args.results))
    known = {r["id"] for r in rules}
    unknown = sorted({f["id"] for f in findings} - known)
    if unknown:
        print(f"ERROR: findings for rules without metadata: {unknown}", file=sys.stderr)
        return 1
    report = build_report(rules, findings, args.plan or args.results)
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render_report_markdown(report))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check").set_defaults(func=cmd_check)
    sub.add_parser("catalogue").set_defaults(func=cmd_catalogue)
    report = sub.add_parser("report")
    report.add_argument("results", help="conftest --output json results file")
    report.add_argument("--plan", help="label for the plan in the report")
    report.add_argument("--format", choices=["markdown", "json"], default="markdown")
    report.set_defaults(func=cmd_report)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
