#!/usr/bin/env python3
"""Exercise the real pinned scanner in an isolated, disposable Git repository.

These Java fixtures test the gate, not the exploitability of Tika changes.
No branch or tracked file in the caller's checkout is changed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import security_gate


ROOT = Path(__file__).resolve().parents[2]
PERMISSIONS = '''import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
class Permissions {
    void write(Path file) throws Exception {
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-rw-rw-"));
    }
}
'''
XML = '''import javax.xml.parsers.DocumentBuilderFactory;
class Xml {
    void configure(DocumentBuilderFactory factory) throws Exception {
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
    }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    with tempfile.TemporaryDirectory(prefix="tache3-scanner-") as directory:
        repo = Path(directory)

        def git(*command):
            return subprocess.check_output(["git", *command], cwd=repo,
                                           stderr=subprocess.PIPE, text=True).strip()

        def save(message):
            git("add", ".")
            git("commit", "-m", message)
            return git("rev-parse", "HEAD")

        git("init", "-b", "main")
        git("config", "user.name", "Scanner validation")
        git("config", "user.email", "validation@example.invalid")
        shutil.copytree(ROOT / ".semgrep", repo / ".semgrep")
        scripts = repo / "scripts/tache3"
        scripts.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/tache3/security_gate.py", scripts)
        for module in security_gate.MODULES:
            target = repo / module / "src/main/java"
            target.mkdir(parents=True)
            (target / "Safe.java").write_text("class Safe {}\n")
        java = repo / "tika-core/src/main/java"
        clean = save("Clean Java fixtures and fixed policy")
        (repo / ".semgrep/baseline.txt").write_text(clean + "\n")
        baseline = save("Record clean reference")

        def scan(name, expected_code, expected_count, base=None, event=None, full=False):
            destination = output / name
            destination.mkdir(exist_ok=True)
            env = os.environ.copy()
            for key in ("GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "GITHUB_STEP_SUMMARY"):
                env.pop(key, None)
            env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
            env["SEMGREP_SEND_METRICS"] = "off"
            command = [sys.executable, str(scripts / "security_gate.py"),
                       "--output", str(destination)]
            if full:
                command.append("--full")
            elif base:
                command += ["--baseline", base]
            if event:
                kind, payload = event
                event_file = destination / "event.json"
                event_file.write_text(json.dumps(payload, indent=2) + "\n")
                env.update(GITHUB_EVENT_NAME=kind, GITHUB_EVENT_PATH=str(event_file))
            run = subprocess.run(command, cwd=repo, env=env, text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (destination / "gate.log").write_text(run.stdout)
            metadata = json.loads((destination / "metadata.json").read_text())
            count = metadata.get("finding_count")
            passed = run.returncode == expected_code and count == expected_count
            if event and event[0] == "push" and event[1].get("before", "").strip("0"):
                passed = passed and metadata.get("baseline") == event[1]["before"]
            cases.append(dict(name=name, expected_exit=expected_code,
                              actual_exit=run.returncode, expected_findings=expected_count,
                              actual_findings=count, passed=passed,
                              status=metadata["status"]))
            print(name + ": " + ("PASS" if passed else "FAIL"), flush=True)
            if not passed:
                raise RuntimeError(name + ": " + run.stdout)

        try:
            scan("clean-change", 0, 0, clean)
            (java / "Permissions.java").write_text(PERMISSIONS)
            legacy = save("Add one permissions finding")
            scan("new-finding-pr", 1, 1, event=("pull_request", {
                "pull_request": {"base": {"sha": baseline}}}))
            scan("before-replacement-full", 0, 1, full=True)
            (repo / "notes.txt").write_text("Harmless documentation change\n")
            save("Documentation only")
            scan("existing-finding-unchanged", 0, 0, legacy)
            (java / "Permissions.java").write_text("// Harmless line insertion\n\n" + PERMISSIONS)
            save("Move an existing finding down two lines")
            scan("existing-finding-moved", 0, 0, legacy)
            (java / "Permissions.java").write_text(PERMISSIONS.replace("rw-rw-rw-", "rw-------"))
            (java / "Xml.java").write_text(XML)
            save("Replace permissions finding with XXE finding")
            scan("same-count-new-finding", 1, 1, legacy)
            scan("after-replacement-full", 0, 1, full=True)
            (repo / "notes.txt").write_text("Second harmless commit after new XXE\n")
            save("A later harmless commit must not hide the previous finding")
            scan("multi-commit-push", 1, 1, event=("push", {"before": legacy}))
            git("update-ref", "refs/remotes/origin/main", baseline)
            scan("new-branch-push", 1, 1, event=("push", {
                "before": "0" * 40, "repository": {"default_branch": "main"}}))
            (java / "Xml.java").write_text(XML.replace(", true)", ", false)"))
            save("Repair all fixture findings")
            scan("repaired-against-clean", 0, 0, baseline)
            (repo / ".semgrep/rules/invalid.yaml").write_text("rules: [\n")
            save("Intentionally malformed rule must fail closed")
            scan("invalid-rules", 2, 0, baseline)
        finally:
            summary = {
                "scope": "Synthetic Java fixtures; real security_gate.py and Semgrep, not mocked",
                "source_head": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "gate_sha256": hashlib.sha256((scripts / "security_gate.py").read_bytes()).hexdigest(),
                "cases": cases,
            }
            (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
