"""Regression tests for baseline selection and fail-closed result handling."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("gate", Path(__file__).with_name("security_gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original_root = gate.ROOT
        gate.ROOT = Path(self.temp.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Gate test")
        self.git("config", "user.email", "gate@example.invalid")
        self.first = self.make_commit("first")
        (gate.ROOT / ".semgrep").mkdir()
        (gate.ROOT / ".semgrep/baseline.txt").write_text(self.first)
        self.second = self.make_commit("second")
        self.third = self.make_commit("third")

    def tearDown(self):
        gate.ROOT = self.original_root
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=gate.ROOT, stderr=subprocess.DEVNULL, text=True).strip()

    def make_commit(self, value):
        (gate.ROOT / "file").write_text(value)
        self.git("add", ".")
        self.git("commit", "-m", value)
        return self.git("rev-parse", "HEAD")

    def test_multi_commit_push_uses_before_not_head_parent(self):
        self.assertEqual(self.first, gate.resolve_baseline("push", {"before": self.first})[0])

    def test_pr_uses_merge_base_when_target_advanced(self):
        self.git("checkout", "-b", "target", self.second)
        (gate.ROOT / "target-only").write_text("target")
        self.git("add", ".")
        self.git("commit", "-m", "target advanced")
        target = self.git("rev-parse", "HEAD")
        self.git("checkout", "main")
        self.assertEqual(self.second, gate.resolve_baseline("pull_request", {"pull_request": {"base": {"sha": target}}})[0])

    def test_new_branch_falls_back_to_recorded_source(self):
        self.assertEqual(self.first, gate.resolve_baseline("push", {"before": "0" * 40})[0])

    def test_new_branch_uses_default_merge_base(self):
        self.git("update-ref", "refs/remotes/origin/main", self.second)
        self.assertEqual(self.second, gate.resolve_baseline("push", {"before": "0" * 40})[0])

    def test_self_baseline_rejected(self):
        with self.assertRaises(ValueError):
            gate.resolve_baseline("local", {}, self.third)

    def test_missing_baseline_rejected(self):
        with self.assertRaises(subprocess.CalledProcessError):
            gate.resolve_baseline("push", {"before": "f" * 40})

    def test_non_ancestor_rejected(self):
        self.git("checkout", "-b", "divergent", self.first)
        other = self.make_commit("different")
        self.git("checkout", "main")
        with self.assertRaises(subprocess.CalledProcessError):
            gate.resolve_baseline("push", {"before": other})


class ResultTests(unittest.TestCase):
    def test_clean_scan(self):
        self.assertEqual((0, "no_new_findings"), gate.classify(0, {"results": [], "errors": []}))

    def test_findings_fail_even_if_scanner_returns_zero(self):
        self.assertEqual(1, gate.classify(0, {"results": [{}]})[0])

    def test_partial_scan_errors_are_not_a_pass(self):
        self.assertEqual(2, gate.classify(0, {"results": [], "errors": [{}]})[0])

    def test_crash_is_not_a_security_finding(self):
        self.assertEqual(2, gate.classify(2, {"results": [{}]})[0])

    def test_missing_results_fail(self):
        self.assertEqual(2, gate.classify(0, {})[0])

    def test_malformed_json_shapes_fail_as_tooling_errors(self):
        for report in (None, [], {"results": None}, {"results": [], "errors": "broken"}):
            with self.subTest(report=report):
                self.assertEqual((2, "invalid_report"), gate.classify(0, report))

    def test_findings_exit_without_findings_is_a_tooling_error(self):
        self.assertEqual((2, "inconsistent_exit_code"), gate.classify(1, {"results": []}))


if __name__ == "__main__":
    unittest.main()
