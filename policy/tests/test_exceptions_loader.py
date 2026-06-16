"""Tests for exceptions_loader.py: suppression YAML loading and validation."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from exceptions_loader import load_exceptions, validate_exception


VALID_YAML = """
exception:
  cve_id: CVE-2024-1234
  package: openssl
  expires: 2099-01-01
  approval:
    approver: alice@example.org
    approved_at: 2026-01-01
    reasoning: test exception
"""

MISSING_EXPIRY_YAML = """
exception:
  cve_id: CVE-2024-1234
  approval:
    approver: alice@example.org
    reasoning: no expiry set
"""

MISSING_APPROVAL_YAML = """
exception:
  cve_id: CVE-2024-1234
  expires: 2099-01-01
"""

BAD_CVE_YAML = """
exception:
  cve_id: not-a-cve
  expires: 2099-01-01
  approval:
    approver: alice@example.org
    reasoning: bad cve id
"""

MALFORMED_YAML = """
exception:
  cve_id: [this is not, valid: yaml structure
"""

NO_WRAPPER_YAML = """
cve_id: CVE-2024-1234
expires: 2099-01-01
"""


def test_valid_file_loads_and_unwraps(tmp_path):
    (tmp_path / "ex1.yaml").write_text(VALID_YAML)
    result = load_exceptions(tmp_path)
    assert len(result) == 1
    assert result[0]["cve_id"] == "CVE-2024-1234"
    assert result[0]["expires"] == "2099-01-01"  # stringified, not a date object
    assert "exception" not in result[0]  # wrapper unwrapped


def test_missing_expiry_is_skipped(tmp_path, capsys):
    (tmp_path / "bad.yaml").write_text(MISSING_EXPIRY_YAML)
    result = load_exceptions(tmp_path)
    assert result == []
    assert "skipping invalid exception" in capsys.readouterr().err


def test_missing_approval_is_skipped(tmp_path, capsys):
    (tmp_path / "bad.yaml").write_text(MISSING_APPROVAL_YAML)
    result = load_exceptions(tmp_path)
    assert result == []
    assert "skipping invalid exception" in capsys.readouterr().err


def test_bad_cve_format_is_skipped(tmp_path, capsys):
    (tmp_path / "bad.yaml").write_text(BAD_CVE_YAML)
    result = load_exceptions(tmp_path)
    assert result == []
    assert "skipping invalid exception" in capsys.readouterr().err


def test_malformed_yaml_is_skipped_not_raised(tmp_path, capsys):
    (tmp_path / "malformed.yaml").write_text(MALFORMED_YAML)
    result = load_exceptions(tmp_path)
    assert result == []
    assert "YAML parse error" in capsys.readouterr().err


def test_missing_exception_wrapper_is_skipped(tmp_path, capsys):
    (tmp_path / "nowrapper.yaml").write_text(NO_WRAPPER_YAML)
    result = load_exceptions(tmp_path)
    assert result == []
    assert "missing top-level 'exception:' key" in capsys.readouterr().err


def test_empty_directory_returns_empty_list(tmp_path):
    assert load_exceptions(tmp_path) == []


def test_missing_directory_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_exceptions(tmp_path / "does-not-exist")


def test_multiple_valid_files_all_load(tmp_path):
    (tmp_path / "a.yaml").write_text(VALID_YAML)
    (tmp_path / "b.yml").write_text(VALID_YAML.replace("CVE-2024-1234", "CVE-2024-5678"))
    result = load_exceptions(tmp_path)
    assert len(result) == 2


def test_one_bad_file_does_not_block_other_valid_files(tmp_path, capsys):
    (tmp_path / "good.yaml").write_text(VALID_YAML)
    (tmp_path / "bad.yaml").write_text(MALFORMED_YAML)
    result = load_exceptions(tmp_path)
    assert len(result) == 1
    assert result[0]["cve_id"] == "CVE-2024-1234"


def test_validate_exception_requires_expires_or_expires_when():
    errors = validate_exception(
        {"cve_id": "CVE-2024-1234", "approval": {"approver": "a", "reasoning": "r"}},
        source=Path("test.yaml"),
    )
    assert any("expires" in e for e in errors)


def test_validate_exception_accepts_expires_when():
    errors = validate_exception(
        {"cve_id": "CVE-2024-1234", "expires_when": "fix_available",
         "approval": {"approver": "a", "reasoning": "r"}},
        source=Path("test.yaml"),
    )
    assert errors == []
