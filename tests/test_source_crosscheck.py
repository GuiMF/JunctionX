"""CryptoScan comparison is optional metadata, never new assessment evidence."""

from copy import deepcopy
import json

import pytest

from adapters.source_crosscheck import cross_reference, load_report
from scripts.scan_source import main, scan_path


def report(*hits):
    return {"tool": {"name": "CryptoScan", "version": "1.4.0"}, "findings": list(hits)}


def hit(algorithm="MD5", line=2, **changes):
    return {"file": "example.py", "line": line, "algorithm": algorithm, **changes}


def scans(tmp_path, code="import hashlib\nhashlib.md5(data)\n"):
    (tmp_path / "example.py").write_text(code)
    return scan_path(tmp_path)["scans"]


def test_exact_algorithm_and_location_match_without_mutating_scan(tmp_path):
    values = scans(tmp_path)
    before = deepcopy(values)
    result = cross_reference(values, report(hit(), hit("RSA"), hit(line=3), hit()), tmp_path)
    assert len(result["matched"]) == 1 and len(result["unmatched"]) == 2
    assert result["matched"][0]["finding_id"] == values[0]["findings"][0]["id"]
    assert result["duplicate_hits"] == 1
    assert values == before


def test_two_same_algorithm_calls_are_ambiguous_and_unknown_never_corroborates(tmp_path):
    values = scans(tmp_path, "import hashlib\nhashlib.md5(a); hashlib.md5(b)\nhashlib.new(name)\n")
    result = cross_reference(values, report(hit(), hit("arbitrary-secret", line=3)), tmp_path)
    assert result["matched"] == []
    assert result["unmatched"][0]["reason"] == "ambiguous_occurrence"
    assert "arbitrary-secret" not in json.dumps(result)


def test_scanned_absolute_paths_supported_others_ignored_and_context_not_copied(tmp_path):
    result = cross_reference(scans(tmp_path), report(
        hit(file=str(tmp_path / "example.py"), context="literal-secret", id="secret-id"),
        hit(file="../example.py"), hit(file="/outside/example.py"),
        hit(file="not-scanned.py"), hit(category="Library Import"),
    ), tmp_path)
    assert len(result["matched"]) == 1 and result["ignored_hits"] == 4
    assert "secret" not in json.dumps(result)


def test_root_with_parent_segments_matches_absolute_report_paths(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    result = cross_reference(scans(tmp_path), report(hit(file=str(tmp_path / "example.py"))), nested / "..")
    assert len(result["matched"]) == 1


@pytest.mark.parametrize("invalid", [
    {}, {"tool": {"name": "CryptoScan", "version": "untrusted text"}, "findings": []},
    report(None), report(hit(line=True)), report(hit(line=-1)), report(hit(file=None)),
])
def test_malformed_reports_rejected(tmp_path, invalid):
    with pytest.raises(ValueError):
        cross_reference([], invalid, tmp_path)


def test_json_size_and_parse_errors_are_bounded_and_sanitized(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text('"secret-value"')
    with pytest.raises(ValueError, match="object"):
        load_report(path)
    path.write_text('{"secret-value":')
    with pytest.raises(ValueError, match="^Invalid CryptoScan JSON$"):
        load_report(path)
    monkeypatch.setattr("adapters.source_crosscheck.MAX_REPORT_BYTES", 5)
    with pytest.raises(ValueError, match="limited"):
        load_report(path)


def test_cli_optional_comparison_works_without_external_checkout_or_executable(tmp_path, monkeypatch):
    scans(tmp_path)
    cs = tmp_path / "cryptoscan.json"
    cs.write_text(json.dumps(report(hit())))
    output = tmp_path / "output.json"
    monkeypatch.setattr("sys.argv", ["scan_source", str(tmp_path), "--cryptoscan-json", str(cs), "--output", str(output)])
    assert main() == 0
    result = json.loads(output.read_text())
    assert result["cryptoscan"]["tool"]["version"] == "1.4.0"
    assert len(result["cryptoscan"]["matched"]) == 1
    assert result["scans"][0]["findings"][0]["evidence_kind"] == "declared"
