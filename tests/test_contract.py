import itertools

import pytest
from pydantic import ValidationError

from core.assessment import assess_finding
from core.identity import deduplicate_findings, stable_asset_id, stable_finding_id
from core.models import Finding, ScanRequest
from core.scoring import score_findings


def test_expanded_upload_byte_limits_count_utf8_bytes_and_combined_content():
    content = 'é' * (32 * 1024 * 1024)  # Exactly 64 MiB encoded, fewer characters.
    inputs = [dict(name=f'{i}.json', source_type='cloud', format='raw', content=content) for i in range(4)]
    assert len(ScanRequest(inputs=inputs).inputs) == 4  # Exactly 256 MiB combined.
    with pytest.raises(ValidationError, match='Each input must be at most 64 MiB'):
        ScanRequest(inputs=[dict(inputs[0], content=content + 'é')])
    with pytest.raises(ValidationError, match='Combined input contents must be at most 256 MiB'):
        ScanRequest(inputs=inputs + [dict(inputs[0], name='extra.json', content='x')])


def finding(**updates):
    data = dict(id="f-1", asset_id="a-1", source_type="source", algorithm="RSA",
                parameters={"key_bits": 1024}, usage="signature", evidence_kind="declared",
                evidence=[{"file": "crypto.py", "locator": "line 2", "detail": "RSA signing API"}],
                confidence="high")
    data.update(updates)
    return Finding.model_validate(data)


@pytest.mark.parametrize("updates", [
    {"evidence": []}, {"parameters": {"key_bits": 0}}, {"parameters": {"key_bits": True}},
    {"parameters": {"key_bits": "256"}}, {"observed_at": "2026-10-10T12:00:00"},
    {"source_type": "guess"}, {"algorithm": " "}, {"secret_key": "must not be accepted"},
])
def test_contract_rejects_ambiguous_or_unsupported_fields(updates):
    with pytest.raises(ValidationError):
        finding(**updates)


def test_identity_tracks_occurrence_not_mutable_crypto():
    asset = stable_asset_id("cloud", "arn:example:listener:123")
    assert asset == stable_asset_id("cloud", "arn:example:listener:123")
    assert asset != stable_asset_id("cloud", "arn:example:listener:124")
    assert asset != stable_asset_id("source", "arn:example:listener:123")
    original = stable_finding_id(asset, "key_establishment", "selected-group", "configured")
    assert original == stable_finding_id(asset, "key_establishment", "selected-group", "configured")
    assert original != stable_finding_id(asset, "key_establishment", "offered-group", "offered")


def test_duplicate_sightings_preserve_evidence_and_do_not_inflate_score():
    one = assess_finding(finding())
    two = one.model_copy(deep=True)
    two.evidence[0].locator = "line 4"
    merged = deduplicate_findings([two, one])
    assert len(merged) == 1
    assert len(merged[0].evidence) == 2
    assert deduplicate_findings([one, two]) == merged
    assert score_findings([one]) == score_findings([one, two] * 10)
    assert len(one.evidence) == 1


def test_different_assets_and_evidence_kinds_are_not_merged():
    items = [finding(), finding(id="f-2", asset_id="a-2"), finding(id="f-3", evidence_kind="offered")]
    assert len(deduplicate_findings(items)) == 3


def test_conflicting_facts_require_an_explicit_identity_fix():
    with pytest.raises(ValueError, match="Conflicting facts"):
        deduplicate_findings([finding(), finding(parameters={"key_bits": 2048})])


def test_conflicting_owners_rejected_even_after_null_in_every_order():
    for order in itertools.permutations([None, "team-a", "team-b"]):
        with pytest.raises(ValueError, match="Conflicting owners"):
            deduplicate_findings([finding(owner=owner) for owner in order])


def test_compatible_duplicate_owner_and_confidence_merge():
    result = deduplicate_findings([finding(), finding(owner="team-a", confidence="medium")])[0]
    assert result.owner == "team-a"
    assert result.confidence == "medium"


def test_unknown_and_offered_assets_cannot_improve_score():
    risky = assess_finding(finding())
    unknown = assess_finding(finding(id="f-2", asset_id="a-2", algorithm="unknown"))
    offered = assess_finding(finding(id="f-3", asset_id="a-3", algorithm="ML-DSA-65", evidence_kind="offered"))
    score = score_findings([risky, unknown, offered])
    assert score["value"] == 100
    assert score["assessed_assets"] == 1
    assert score["unknown_assets"] == score["offered_only_assets"] == 1
    assert score_findings([unknown])["value"] is None
    assert score_findings([])["value"] is None


def test_asset_uses_worst_tier_and_reports_unknown_authentication():
    aes = assess_finding(finding(id="f-aes", algorithm="AES", usage="encryption", parameters={"key_bits": 256}))
    rsa = assess_finding(finding())
    unknown = assess_finding(finding(id="f-unknown", algorithm="unknown"))
    score = score_findings([aes, rsa, unknown])
    assert score["value"] == 100
    assert score["assessed_assets"] == score["assets_with_unknowns"] == 1
    assert score["classical_issue_assets"] == 1


def test_not_applicable_is_not_unknown_or_safe():
    na = finding(quantum_status="not_applicable")
    score = score_findings([na])
    assert score["value"] is None
    assert score["not_applicable_assets"] == 1
    assert score["unknown_assets"] == score["assets_with_unknowns"] == 0


def test_request_requires_unique_input_names_and_aware_evaluation_time():
    item = {"name": "input", "source_type": "source", "format": "raw", "content": "pass"}
    with pytest.raises(ValidationError, match="unique"):
        ScanRequest(inputs=[item, item])
    with pytest.raises(ValidationError):
        ScanRequest(inputs=[item], evaluated_at="2026-10-10T00:00:00")


@pytest.mark.parametrize("field", ["id", "asset_id", "algorithm", "owner"])
def test_contract_rejects_unpaired_surrogates_before_json_export(field):
    with pytest.raises(ValidationError):
        finding(**{field: "invalid\ud800"})


def test_score_uses_equal_asset_weights_and_keeps_all_excluded_populations_visible():
    observations = [
        assess_finding(finding()),
        assess_finding(finding(id="aes128", asset_id="a-2", algorithm="AES", usage="encryption", parameters={"key_bits": 128})),
        assess_finding(finding(id="aes256", asset_id="a-3", algorithm="AES", usage="encryption", parameters={"key_bits": 256})),
        assess_finding(finding(id="unknown", asset_id="a-4", algorithm="unknown")),
        assess_finding(finding(id="offered-rsa", asset_id="a-5", evidence_kind="offered")),
        finding(id="na", asset_id="a-6", quantum_status="not_applicable"),
    ]
    score = score_findings(observations + [observations[0]] * 50)
    assert score["value"] == 50
    assert score["total_assets"] == 6
    assert score["assessed_assets"] == 3
    assert score["unknown_assets"] == score["offered_only_assets"] == score["not_applicable_assets"] == 1
    assert score["quantum_vulnerable_assets"] == 1
