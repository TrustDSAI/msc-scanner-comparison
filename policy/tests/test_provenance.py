"""Tests for provenance.py: tool version probing and bundle fingerprinting."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import provenance


def _completed(stdout: str):
    proc = MagicMock()
    proc.stdout = stdout
    return proc


def test_probe_trivy_parses_version():
    provenance._tool_versions_cache = None
    with patch("subprocess.run", return_value=_completed("Version: 0.69.3\nVulnerability DB:\n")):
        assert provenance._probe(["trivy", "--version"]) == "0.69.3"


def test_probe_grype_parses_version():
    with patch("subprocess.run", return_value=_completed("Application: grype\nVersion: 0.110.0\n")):
        assert provenance._probe(["grype", "version"]) == "0.110.0"


def test_probe_opa_parses_version():
    with patch("subprocess.run", return_value=_completed("Version: 1.17.0\nBuild Commit: abc\n")):
        assert provenance._probe(["opa", "version"]) == "1.17.0"


def test_probe_returns_none_on_malformed_output():
    with patch("subprocess.run", return_value=_completed("nonsense output, no version here")):
        assert provenance._probe(["trivy", "--version"]) is None


def test_probe_returns_none_on_subprocess_error():
    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, ["trivy"])):
        assert provenance._probe(["trivy", "--version"]) is None


def test_probe_returns_none_on_missing_binary():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert provenance._probe(["grype", "version"]) is None


def test_get_tool_versions_is_cached():
    provenance._tool_versions_cache = None
    call_count = {"n": 0}

    def fake_run(*args, **kwargs):
        call_count["n"] += 1
        return _completed("Version: 1.0.0\n")

    with patch("subprocess.run", side_effect=fake_run):
        first = provenance.get_tool_versions()
        second = provenance.get_tool_versions()
    assert first == second
    assert call_count["n"] == 3  # trivy, grype, opa probed once each


def test_fingerprint_stable_across_calls(tmp_path):
    rego_dir = tmp_path / "rego"
    rego_dir.mkdir()
    (rego_dir / "lib.rego").write_text("package vuln.lib\n")
    fp1 = provenance.fingerprint_rego_dir(rego_dir)
    fp2 = provenance.fingerprint_rego_dir(rego_dir)
    assert fp1 == fp2
    assert fp1.startswith("sha256:")


def test_fingerprint_changes_with_content(tmp_path):
    rego_dir = tmp_path / "rego"
    rego_dir.mkdir()
    f = rego_dir / "lib.rego"
    f.write_text("package vuln.lib\n")
    fp_before = provenance.fingerprint_rego_dir(rego_dir)
    f.write_text("package vuln.lib\n# changed\n")
    fp_after = provenance.fingerprint_rego_dir(rego_dir)
    assert fp_before != fp_after


def test_build_provenance_assembles_expected_keys(tmp_path):
    rego_dir = tmp_path / "rego"
    rego_dir.mkdir()
    (rego_dir / "p_gate.rego").write_text("package vuln.gate\n")
    with patch("subprocess.run", return_value=_completed("Version: 1.0.0\n")):
        provenance._tool_versions_cache = None
        prov = provenance.build_provenance(
            rego_dir=rego_dir, policy_package="vuln.gate",
            config={"block_epss_threshold": 0.5}, classifier="rule",
        )
    assert set(prov) == {
        "tool_versions", "policy_bundle_fingerprint", "policy_package",
        "rego_dir", "classifier", "config", "build_sha", "scan_timestamp",
    }
    assert prov["policy_package"] == "vuln.gate"
    assert prov["config"] == {"block_epss_threshold": 0.5}
