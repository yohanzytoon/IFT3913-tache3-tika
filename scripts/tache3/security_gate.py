#!/usr/bin/env python3
"""Run the fixed Semgrep policy; fail on new findings or incomplete analysis."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
MODULES = [
    "tika-core",
    "tika-serialization",
    *[
        "tika-parsers/tika-parsers-standard/tika-parsers-standard-modules/"
        + "tika-parser-" + name + "-module"
        for name in ("ocr", "pdf", "microsoft")
    ],
]


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def commit(ref):
    return git("rev-parse", "--verify", ref + "^{commit}")


def resolve_baseline(event_name, event, explicit=None):
    """Return an existing ancestor, comparing every commit in a push/PR."""
    head = commit("HEAD")
    if explicit:
        base = commit(explicit)
        reason = "explicit"
    elif event_name == "pull_request":
        base = git("merge-base", head, commit(event["pull_request"]["base"]["sha"]))
        reason = "PR merge-base"
    elif event_name == "push" and event.get("before", "").strip("0"):
        # A force-push with an unrelated before SHA fails closed below.
        base = commit(event["before"])
        reason = "push before SHA"
    elif event_name in ("push", "workflow_dispatch", "local"):
        default_branch = event.get("repository", {}).get("default_branch", "main")
        base = None
        if event_name == "push":
            try:
                candidate = git("merge-base", head, commit("refs/remotes/origin/" + default_branch))
                if candidate != head:
                    base = candidate
            except subprocess.CalledProcessError:
                pass
        if base:
            reason = "new branch merge-base"
        else:
            base = commit((ROOT / ".semgrep/baseline.txt").read_text().strip())
            reason = "recorded source baseline"
    else:
        raise ValueError("Unsupported event: " + event_name)
    if base == head:
        raise ValueError("Baseline equals HEAD: refusing a scan that hides all changes")
    subprocess.run(["git", "merge-base", "--is-ancestor", base, head], cwd=ROOT, check=True)
    return base, reason


def classify(returncode, report):
    if returncode not in (0, 1) or report.get("errors"):
        return 2, "scanner_error"
    if not isinstance(report.get("results"), list):
        return 2, "invalid_report"
    if returncode == 1 and not report["results"]:
        return 2, "inconsistent_exit_code"
    if report["results"]:
        return 1, "new_findings"
    return 0, "no_new_findings"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--full", action="store_true", help="Inventory scan; findings are informational")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    metadata = {"status": "setup_error", "head": git("rev-parse", "HEAD")}
    code = 2
    try:
        if git("status", "--porcelain", "--untracked-files=no"):
            raise ValueError("Commit or stash tracked modifications before scanning")
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        event = json.loads(Path(event_path).read_text()) if event_path else {}
        if not args.full:
            base, reason = resolve_baseline(os.environ.get("GITHUB_EVENT_NAME", "local"), event, args.baseline)
            metadata.update(baseline=base, baseline_reason=reason)
        version = subprocess.check_output(["semgrep", "--version"], text=True).strip()
        if version != "1.140.0":
            raise ValueError("Expected Semgrep 1.140.0, got " + version)
        rules = sorted((ROOT / ".semgrep/rules").glob("*.yaml")) + sorted((ROOT / ".semgrep/rules").glob("*.yml"))
        if not rules:
            raise ValueError("No security rules found")
        metadata.update(semgrep=version, mode="full" if args.full else "differential",
                        rules={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in rules})
        targets = [module + "/src/main/java" for module in MODULES]
        for target in targets:
            if not (ROOT / target).is_dir():
                raise ValueError("Missing required scan target: " + target)
        metadata["targets"] = targets
        report_path = output / "semgrep.json"
        command = ["semgrep", "scan", "--config", ".semgrep/rules", "--strict",
                   "--metrics=off", "--disable-version-check", "--disable-nosem",
                   "--no-rewrite-rule-ids", "--json", "--output", str(report_path)]
        if not args.full:
            command += ["--error", "--baseline-commit", metadata["baseline"]]
        command += targets
        metadata["command"] = command
        with (output / "semgrep.log").open("w") as log:
            scan = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        report = json.loads(report_path.read_text())
        metadata.update(scanner_exit_code=scan.returncode, finding_count=len(report.get("results", [])),
                        error_count=len(report.get("errors", [])))
        code, status = classify(scan.returncode, report)
        if args.full and code == 1:
            code, status = 0, "inventory_with_findings"
        metadata["status"] = status
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        metadata["error"] = str(exc)
        print("Security analysis failed: " + str(exc), file=sys.stderr)
    metadata["gate_exit_code"] = code
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    summary = "Semgrep: {status}; {finding_count} finding(s); exit {gate_exit_code}".format(
        **dict({"finding_count": "unknown"}, **metadata))
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write("### Security gate\n\n" + summary + "\n\n")
            stream.write("Head: `" + metadata["head"] + "`\n\n")
            stream.write("Baseline: `" + metadata.get("baseline", "full inventory") + "`\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
