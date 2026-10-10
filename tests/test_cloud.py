import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from adapters.cloud import scan_cloud
from adapters.cloud_demo import build_certificate_renewal_demo, build_demo


ROOT = Path(__file__).resolve().parents[1]
EVALUATED_AT = "2026-10-10T12:00:00Z"


class CloudTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        for source in (ROOT / "cloud-posture").glob("*.json"):
            (self.directory / source.name).write_bytes(source.read_bytes())

    def edit(self, filename, modify):
        path = self.directory / filename
        data = json.loads(path.read_text())
        modify(data)
        path.write_text(json.dumps(data))

    def scan(self):
        return scan_cloud(self.directory, evaluated_at=EVALUATED_AT)

    def test_supplied_inventory_and_evidence(self):
        report = self.scan()
        self.assertEqual(report["errors"], [])
        self.assertEqual(len(report["assets"]), 28)
        counts = {kind: sum(a["kind"] == kind for a in report["assets"])
                  for kind in ("kms_key", "load_balancer", "certificate", "listener")}
        self.assertEqual(counts, {"kms_key": 10, "load_balancer": 6, "certificate": 5, "listener": 7})
        links = [r for r in report["relationships"] if r["kind"] == "uses_certificate"]
        self.assertEqual(len(links), 5)
        self.assertTrue(all(r["resolved"] for r in links))
        self.assertEqual(len(report["findings"]), 25)
        for finding in report["findings"]:
            self.assertEqual(finding["evidence_kind"], "configured")
            self.assertIsNone(finding["observed_at"])
            for evidence in finding["evidence"]:
                value = json.loads(Path(evidence["file"]).read_text())
                for part in evidence["locator"].split("/")[1:]:
                    value = value[int(part)] if isinstance(value, list) else value[part]
                self.assertEqual(json.loads(evidence["detail"]), value)
        self.assertTrue(all(s["age_seconds"] > 0 for s in report["snapshots"]))
        json.dumps(report)

    def test_kms_usage_owner_and_symmetric_parameters(self):
        report = self.scan()
        by_alias = {a["configuration"]["AliasName"]: a for a in report["assets"] if a["kind"] == "kms_key"}
        signing = by_alias["alias/licensing-jwt-signing"]
        self.assertEqual(signing["owner"], "billing")
        findings = {f["asset_id"]: f for f in report["findings"] if f["asset_id"] in {a["asset_id"] for a in by_alias.values()}}
        self.assertEqual(findings[signing["asset_id"]]["usage"], "signature")
        decrypting = by_alias["alias/partner-feed-decrypt"]
        self.assertEqual(findings[decrypting["asset_id"]]["usage"], "encryption")
        symmetric = findings[by_alias["alias/s3-object-encryption"]["asset_id"]]
        self.assertEqual(symmetric["algorithm"], "AES")
        self.assertEqual(symmetric["parameters"], {"key_bits": 256, "mode": "GCM", "named_group": None})

    def test_operational_issues_are_separate_from_assessment(self):
        report = self.scan()
        issues = report["posture_issues"]
        codes = [i["code"] for i in issues]
        self.assertEqual(codes.count("rotation_disabled"), 2)
        self.assertEqual(codes.count("pending_deletion"), 1)
        self.assertEqual(codes.count("certificate_expired"), 1)
        self.assertEqual(codes.count("sha1_certificate_signature"), 1)
        self.assertEqual(codes.count("http_forwarding"), 1)
        forwarded = next(i for i in issues if i["code"] == "http_forwarding")
        self.assertIn("batch-internal-alb", forwarded["asset_id"])
        self.assertTrue(all(f["quantum_status"] == "unknown" for f in report["findings"]))
        self.assertEqual(report["coverage"]["cryptography"]["assessed"], 0)
        http = [a for a in report["assets"] if "http_actions" in a]
        redirect = next(a for a in http if "public-web-alb" in a["asset_id"])
        self.assertEqual(redirect["http_actions"][0]["type"], "redirect")
        self.assertEqual(redirect["http_actions"][0]["redirect_protocol"], "HTTPS")

    def test_unknown_algorithm_usage_and_policy(self):
        self.edit("kms_key_inventory.json", lambda d: d["Keys"][0].update(KeySpec="NEW_SPEC", KeyUsage="NEW_USAGE"))
        self.edit("load_balancer_listeners.json", lambda d: d["LoadBalancers"][0]["Listeners"][0].update(SslPolicy="Imaginary-PQ-2099"))
        report = self.scan()
        self.assertEqual(report["errors"], [])
        finding = next(f for f in report["findings"] if "/Keys/0/KeySpec" == f["evidence"][0]["locator"])
        self.assertEqual((finding["algorithm"], finding["usage"]), ("unknown", "unknown"))
        policy = next(a["tls_policy"] for a in report["assets"] if a.get("tls_policy", {}).get("name") == "Imaginary-PQ-2099")
        self.assertIsNone(policy["hybrid_pq_capable"])
        self.assertIsNone(policy["protocols"])
        self.assertEqual(report["coverage"]["tls_policies"]["unknown"], 1)
        self.assertEqual(report["coverage"]["tls_policies"]["mapped"], 4)

    def test_bad_file_keeps_other_inputs_and_unresolved_links(self):
        (self.directory / "acm_certificates.json").write_text("{broken")
        report = self.scan()
        self.assertEqual(len(report["assets"]), 23)
        self.assertTrue(report["coverage"]["certificate"]["file_failed"])
        links = [r for r in report["relationships"] if r["kind"] == "uses_certificate"]
        self.assertEqual(len(links), 5)
        self.assertTrue(all(not r["resolved"] for r in links))
        self.assertEqual(len(report["errors"]), 6)

    def test_malformed_resource_does_not_remove_valid_resources(self):
        self.edit("kms_key_inventory.json", lambda d: d["Keys"][0].update(KeySpec=[]))
        report = self.scan()
        self.assertEqual(report["coverage"]["kms_key"]["failed"], 1)
        self.assertEqual(report["coverage"]["kms_key"]["inventoried"], 9)
        self.assertEqual(len(report["assets"]), 27)
        self.assertEqual(len(report["errors"]), 1)

    def test_algorithm_names_are_specific_to_their_aws_service(self):
        self.edit("kms_key_inventory.json", lambda d: d["Keys"][0].update(KeySpec="EC_prime256v1"))
        self.edit("acm_certificates.json", lambda d: d["Certificates"][0].update(KeyAlgorithm="ECC_NIST_P256"))
        report = self.scan()
        for pointer in ("/Keys/0/KeySpec", "/Certificates/0/KeyAlgorithm"):
            finding = next(f for f in report["findings"] if f["evidence"][0]["locator"] == pointer)
            self.assertEqual(finding["algorithm"], "unknown")
            self.assertIsNone(finding["parameters"]["key_bits"])

    def test_malformed_posture_fields_do_not_silently_hide_issues(self):
        for field in ("KeyState", "KeyRotationStatus"):
            with self.subTest(field=field):
                self.edit("kms_key_inventory.json", lambda d: d["Keys"][0].update(
                    KeyState="Enabled", KeyRotationStatus="NOT_APPLICABLE"))
                self.edit("kms_key_inventory.json", lambda d: d["Keys"][0].update({field: []}))
                report = self.scan()
                self.assertEqual(report["coverage"]["kms_key"]["failed"], 1)
                self.assertEqual(report["coverage"]["kms_key"]["inventoried"], 9)

    def test_duplicate_resource_is_reported_once(self):
        self.edit("kms_key_inventory.json", lambda d: d["Keys"].append(copy.deepcopy(d["Keys"][0])))
        report = self.scan()
        self.assertEqual(report["coverage"]["kms_key"]["inventoried"], 10)
        self.assertEqual(report["coverage"]["kms_key"]["failed"], 1)
        self.assertEqual(len(report["assets"]), 28)

    def test_bad_listener_preserves_siblings(self):
        self.edit("load_balancer_listeners.json", lambda d: d["LoadBalancers"][0]["Listeners"][0].update(Certificates="invalid"))
        report = self.scan()
        self.assertEqual(report["coverage"]["listener"]["inventoried"], 6)
        self.assertEqual(report["coverage"]["listener"]["failed"], 1)
        self.assertEqual(report["coverage"]["load_balancer"]["inventoried"], 6)

    def test_non_object_listener_preserves_parent_and_siblings(self):
        self.edit("load_balancer_listeners.json", lambda d: d["LoadBalancers"][0]["Listeners"].append(None))
        report = self.scan()
        self.assertEqual(report["coverage"]["listener"]["inventoried"], 7)
        self.assertEqual(report["coverage"]["listener"]["failed"], 1)
        self.assertEqual(report["coverage"]["load_balancer"]["inventoried"], 6)

    def test_missing_crypto_fields_use_existing_resource_evidence(self):
        self.edit("kms_key_inventory.json", lambda d: d["Keys"][0].pop("KeySpec"))
        self.edit("kms_key_inventory.json", lambda d: d["Keys"][0].pop("KeyUsage"))
        report = self.scan()
        finding = next(f for f in report["findings"] if f["evidence"][0]["locator"] == "/Keys/0")
        self.assertEqual((finding["algorithm"], finding["usage"]), ("unknown", "unknown"))
        record = json.loads((self.directory / "kms_key_inventory.json").read_text())["Keys"][0]
        self.assertEqual(json.loads(finding["evidence"][0]["detail"]), record)

    def test_policy_mappings_preserve_cipher_capabilities_and_type(self):
        report = self.scan()
        policies = {a["tls_policy"]["name"]: a["tls_policy"] for a in report["assets"] if "tls_policy" in a}
        self.assertEqual(len(policies["ELBSecurityPolicy-2016-08"]["cipher_suites"]), 18)
        self.assertEqual(len(policies["ELBSecurityPolicy-TLS-1-2-2017-01"]["cipher_suites"]), 12)
        self.assertEqual(policies["ELBSecurityPolicy-FS-1-2-Res-2020-10"]["protocols"], ["TLSv1.2"])
        self.assertTrue(all(not p["hybrid_pq_capable"] for p in policies.values()))
        self.edit("load_balancer_listeners.json", lambda d: d["LoadBalancers"][4]["Listeners"][0].update(SslPolicy="ELBSecurityPolicy-FS-1-2-Res-2020-10"))
        report = self.scan()
        nlb = next(a for a in report["assets"] if a["kind"] == "listener" and "legacy-tcp-nlb" in a["asset_id"])
        self.assertEqual(nlb["tls_policy"]["protocols"], ["TLSv1.2"])
        self.assertEqual(len(nlb["tls_policy"]["cipher_suites"]), 4)
        self.assertIn("/network/", nlb["tls_policy"]["reference"])

    def test_policy_lists_are_isolated_between_resources_and_scans(self):
        self.edit("load_balancer_listeners.json", lambda d: d["LoadBalancers"][3]["Listeners"][0].update(
            SslPolicy="ELBSecurityPolicy-TLS-1-2-2017-01"))
        report = self.scan()
        matching = [a["tls_policy"] for a in report["assets"]
                    if a.get("tls_policy", {}).get("name") == "ELBSecurityPolicy-TLS-1-2-2017-01"]
        self.assertEqual(len(matching), 2)
        matching[0]["protocols"].append("BROKEN")
        matching[0]["cipher_suites"].clear()
        self.assertEqual(matching[1]["protocols"], ["TLSv1.2"])
        self.assertEqual(len(matching[1]["cipher_suites"]), 12)
        next_policy = next(a["tls_policy"] for a in self.scan()["assets"]
                           if a.get("tls_policy", {}).get("name") == matching[0]["name"])
        self.assertEqual(next_policy["protocols"], ["TLSv1.2"])
        self.assertEqual(len(next_policy["cipher_suites"]), 12)

    def test_out_of_range_dates_preserve_partial_results(self):
        for value in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
            with self.subTest(value=value):
                self.edit("kms_key_inventory.json", lambda d: d.update(GeneratedAt="2026-09-14T09:32:07Z"))
                with self.assertRaisesRegex(ValueError, "UTC range"):
                    scan_cloud(self.directory, evaluated_at=value)
                self.edit("acm_certificates.json", lambda d: d["Certificates"][0].update(NotAfter=value))
                report = self.scan()
                self.assertEqual(report["coverage"]["certificate"]["failed"], 1)
                self.assertEqual(len(report["assets"]), 27)
                self.edit("kms_key_inventory.json", lambda d: d.update(GeneratedAt=value))
                report = self.scan()
                self.assertTrue(report["coverage"]["kms_key"]["file_failed"])
                self.assertEqual(report["coverage"]["load_balancer"]["inventoried"], 6)

    def test_nonstandard_and_ambiguous_json_is_reported_as_file_failure(self):
        path = self.directory / "kms_key_inventory.json"
        original = path.read_text()
        for value in ("NaN", "Infinity", "-Infinity", "1e999", '"eu-west-1", "Region": "cn-north-1"'):
            with self.subTest(value=value):
                path.write_text(original.replace('"eu-west-1"', value, 1))
                report = self.scan()
                self.assertTrue(report["coverage"]["kms_key"]["file_failed"])
                self.assertEqual(len(report["assets"]), 18)
                json.dumps(report, allow_nan=False)

    def test_missing_certificate_reference_has_resolvable_evidence(self):
        self.edit("load_balancer_listeners.json", lambda d: d["LoadBalancers"][0]["Listeners"][0]["Certificates"][0].clear())
        report = self.scan()
        link = next(r for r in report["relationships"] if r["kind"] == "uses_certificate")
        self.assertFalse(link["resolved"])
        evidence = link["evidence"][0]
        value = json.loads(Path(evidence["file"]).read_text())
        for part in evidence["locator"].split("/")[1:]:
            value = value[int(part)] if isinstance(value, list) else value[part]
        self.assertEqual(value, json.loads(evidence["detail"]))
        self.assertEqual(report["errors"][0]["locator"], evidence["locator"])

    def test_malformed_certificate_reference_preserves_other_listeners(self):
        self.edit("load_balancer_listeners.json", lambda d: d["LoadBalancers"][0]["Listeners"][0]["Certificates"][0].update(CertificateArn=[]))
        report = self.scan()
        self.assertEqual(report["coverage"]["listener"]["failed"], 1)
        self.assertEqual(report["coverage"]["listener"]["inventoried"], 6)

    def test_cli_exit_codes_and_json_output(self):
        command = [sys.executable, "-B", "-m", "adapters.cloud", str(self.directory), "--evaluated-at"]
        success = subprocess.run(command + [EVALUATED_AT], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(json.loads(success.stdout)["errors"], [])
        (self.directory / "kms_key_inventory.json").write_text("{broken")
        partial = subprocess.run(command + [EVALUATED_AT], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(partial.returncode, 1, partial.stderr)
        self.assertEqual(len(json.loads(partial.stdout)["assets"]), 18)
        invalid = subprocess.run(command + ["0001-01-01T00:00:00+01:00"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 2)
        self.assertNotIn("Traceback", invalid.stderr)

    def test_dates_require_timezone_and_use_evaluation_time(self):
        with self.assertRaises(ValueError):
            scan_cloud(self.directory, evaluated_at="2026-10-10T12:00:00")
        before_expiry = scan_cloud(self.directory, evaluated_at="2026-07-01T00:00:00Z")
        self.assertNotIn("certificate_expired", [i["code"] for i in before_expiry["posture_issues"]])
        self.edit("acm_certificates.json", lambda d: d["Certificates"][0].update(NotAfter="invalid"))
        report = self.scan()
        self.assertEqual(report["coverage"]["certificate"]["failed"], 1)

    def test_unmapped_region_does_not_assume_aes(self):
        self.edit("kms_key_inventory.json", lambda d: d.update(Region="cn-north-1"))
        report = self.scan()
        symmetric = [f for f in report["findings"] if f["evidence"][0]["detail"] == '"SYMMETRIC_DEFAULT"']
        self.assertEqual(len(symmetric), 4)
        self.assertTrue(all(f["algorithm"] == "unknown" for f in symmetric))
        self.assertTrue(all(f["parameters"]["key_bits"] is None for f in symmetric))
        self.assertTrue(all(f["parameters"]["mode"] is None for f in symmetric))

    def test_demo_preserves_ids_and_does_not_claim_pq_negotiation(self):
        before = self.scan()
        modified = ROOT / "tests/fixtures/cloud-modified/load_balancer_listeners.json"
        (self.directory / modified.name).write_bytes(modified.read_bytes())
        after = self.scan()
        self.assertEqual(after["errors"], [])
        self.assertEqual([a["asset_id"] for a in before["assets"]], [a["asset_id"] for a in after["assets"]])
        self.assertEqual([f["id"] for f in before["findings"]], [f["id"] for f in after["findings"]])
        changed = [(old, new) for old, new in zip(before["assets"], after["assets"]) if old["configuration"] != new["configuration"]]
        self.assertEqual({a["kind"] for a, b in changed}, {"load_balancer", "listener"})
        listener = next(b for a, b in changed if b["kind"] == "listener")
        self.assertTrue(listener["tls_policy"]["hybrid_pq_capable"])
        self.assertIsNone(listener["tls_policy"]["negotiated_group"])
        self.assertTrue(all(f["observed_at"] is None for f in after["findings"]))

    def test_demo_fixture_changes_only_one_policy(self):
        original = json.loads((ROOT / "cloud-posture/load_balancer_listeners.json").read_text())
        modified_dir = ROOT / "tests/fixtures/cloud-modified"
        expected = copy.deepcopy(original)
        expected["LoadBalancers"][3]["Listeners"][0]["SslPolicy"] = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
        self.assertEqual(json.loads((modified_dir / "load_balancer_listeners.json").read_text()), expected)
        for name in ("kms_key_inventory.json", "acm_certificates.json"):
            self.assertEqual((modified_dir / name).read_bytes(), (ROOT / "cloud-posture" / name).read_bytes())

    def test_handoff_demo_has_linked_examples_and_known_limits(self):
        report = build_demo(evaluated_at=EVALUATED_AT)
        self.assertEqual(len(report["changes"]), 1)
        change = report["changes"][0]
        self.assertFalse(change["before"]["hybrid_pq_capable"])
        self.assertTrue(change["after"]["hybrid_pq_capable"])
        self.assertEqual(len(change["after"]["hybrid_groups"]), 3)
        self.assertIsNone(change["after"]["negotiated_group"])
        self.assertIsNone(report["observed_pq_negotiation"])
        self.assertTrue(report["certificate_unchanged"])
        self.assertEqual(len(report["examples"]["relationships"]), 1)
        self.assertEqual({a["owner"] for a in report["examples"]["assets"] if a["kind"] == "kms_key"}, {"billing", "platform"})
        self.assertEqual(len(report["examples"]["findings"]), 5)
        json.dumps(report)

    def test_certificate_renewal_preserves_identity_and_resolves_posture(self):
        demo = build_certificate_renewal_demo(evaluated_at=EVALUATED_AT)
        old, new = demo["before"], demo["after"]
        self.assertEqual(old["asset_id"], new["asset_id"])
        self.assertEqual(old["configuration"]["KeyAlgorithm"], new["configuration"]["KeyAlgorithm"])
        self.assertEqual(new["configuration"]["SignatureAlgorithm"], "SHA256WITHRSA")
        self.assertEqual(new["configuration"]["RenewalEligibility"], "INELIGIBLE")
        self.assertEqual({i["code"] for i in demo["resolved_posture_issues"]},
                         {"certificate_expired", "sha1_certificate_signature"})
        self.assertEqual(demo["remaining_certificate_issues"], [])
        self.assertEqual(len(demo["relationships"]), 1)
        self.assertTrue(demo["relationships"][0]["resolved"])
        self.assertFalse(demo["quantum_migration"])
        before = scan_cloud("cloud-posture", evaluated_at=EVALUATED_AT)
        after = scan_cloud(ROOT / "tests/fixtures/cloud-renewed", evaluated_at=EVALUATED_AT)
        self.assertEqual([f["id"] for f in before["findings"]], [f["id"] for f in after["findings"]])
        self.assertEqual([(r["source_id"], r["target_id"], r["kind"], r["resolved"]) for r in before["relationships"]],
                         [(r["source_id"], r["target_id"], r["kind"], r["resolved"]) for r in after["relationships"]])
        for name in ("kms_key_inventory.json", "load_balancer_listeners.json"):
            self.assertEqual((ROOT / "cloud-posture" / name).read_bytes(),
                             (ROOT / "tests/fixtures/cloud-renewed" / name).read_bytes())
        json.dumps(demo)

    def test_certificate_renewal_refuses_expired_or_unrelated_changes(self):
        with self.assertRaisesRegex(ValueError, "valid at the evaluation time"):
            build_certificate_renewal_demo(evaluated_at="2028-01-01T00:00:00Z")
        before = scan_cloud("cloud-posture", evaluated_at=EVALUATED_AT)
        after = scan_cloud(ROOT / "tests/fixtures/cloud-renewed", evaluated_at=EVALUATED_AT)
        changed = copy.deepcopy(after)
        changed["assets"][0]["configuration"]["KeyState"] = "Disabled"
        with patch("adapters.cloud_demo.scan_cloud", side_effect=[before, changed]):
            with self.assertRaisesRegex(ValueError, "exactly one certificate"):
                build_certificate_renewal_demo()
        changed = copy.deepcopy(after)
        certificate = next(a for a in changed["assets"] if a["kind"] == "certificate"
                           and a["configuration"]["DomainName"] == "legacy-tcp.internal.example.com")
        certificate["configuration"]["KeyAlgorithm"] = "RSA_4096"
        with patch("adapters.cloud_demo.scan_cloud", side_effect=[before, changed]):
            with self.assertRaisesRegex(ValueError, "key type/size"):
                build_certificate_renewal_demo()

    def test_demo_refuses_partial_scans_and_changed_certificates(self):
        before = scan_cloud("cloud-posture", evaluated_at=EVALUATED_AT)
        after = scan_cloud("tests/fixtures/cloud-modified", evaluated_at=EVALUATED_AT)
        partial = copy.deepcopy(after)
        partial["errors"].append({"message": "Invalid input"})
        with patch("adapters.cloud_demo.scan_cloud", side_effect=[before, partial]):
            with self.assertRaisesRegex(ValueError, "contain errors"):
                build_demo()
        changed = copy.deepcopy(after)
        certificate = next(a for a in changed["assets"] if a["kind"] == "certificate" and a["configuration"]["DomainName"] == "partner-api.example.com")
        certificate["configuration"]["KeyAlgorithm"] = "RSA_2048"
        with patch("adapters.cloud_demo.scan_cloud", side_effect=[before, changed]):
            with self.assertRaisesRegex(ValueError, "certificate must remain unchanged"):
                build_demo()

    def test_demo_refuses_unrelated_configuration_changes(self):
        before = scan_cloud("cloud-posture", evaluated_at=EVALUATED_AT)
        after = scan_cloud("tests/fixtures/cloud-modified", evaluated_at=EVALUATED_AT)
        for kind, field, value in (("kms_key", "KeyState", "Disabled"),
                                   ("certificate", "DomainName", "changed.example.com"),
                                   ("listener", "Port", 8443)):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(after)
                asset = next(a for a in changed["assets"] if a["kind"] == kind)
                asset["configuration"][field] = value
                with patch("adapters.cloud_demo.scan_cloud", side_effect=[before, changed]):
                    with self.assertRaisesRegex(ValueError, "only the listener policy"):
                        build_demo()


if __name__ == "__main__":
    unittest.main()
