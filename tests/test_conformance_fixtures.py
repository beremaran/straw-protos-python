import json
from pathlib import Path
import unittest

from straw_protos import _ed25519
from straw_protos.signing import registration_signing_payload, sign_registration, verify_registration_signature
from straw_protos.straw.v1 import straw_pb2 as pb


FIXTURES = Path(__file__).parents[1] / "conformance" / "fixtures" / "v1"


class ConformanceFixtureTests(unittest.TestCase):
    def load(self, name):
        return json.loads((FIXTURES / name).read_text())

    def test_registration_signing(self):
        fixture = self.load("registration-signing.json")
        request = fixture["request"]
        req = pb.RegisterRequest(
            worker_id=request["worker_id"], credential_id=request["credential_id"],
            executor_type=request["executor_type"], protocol_major=request["protocol_major"],
            protocol_minor=request["protocol_minor"], nonce=bytes.fromhex(request["nonce_hex"]),
            issued_at_unix_ms=request["issued_at_unix_ms"],
            supported_fingerprint_profiles=request["supported_fingerprint_profiles"],
        )
        seed = bytes.fromhex(fixture["seed_hex"])
        self.assertEqual(registration_signing_payload(req), bytes.fromhex(fixture["payload_hex"]))
        self.assertEqual(_ed25519.public_key(seed), bytes.fromhex(fixture["public_key_hex"]))
        signature = sign_registration(seed, req)
        self.assertEqual(signature, bytes.fromhex(fixture["signature_hex"]))
        self.assertTrue(verify_registration_signature(_ed25519.public_key(seed), req, signature))

    def test_envelope_unknown_field_and_enum(self):
        fixture = self.load("envelope.json")
        env = pb.Envelope(
            request_id=fixture["request_id"], deployment_id=fixture["deployment_id"],
            protocol_major=fixture["protocol_major"], protocol_minor=fixture["protocol_minor"],
            attempt=fixture["attempt"], assign_ack=pb.AssignAck(code=pb.ASSIGN_ACK_ACCEPTED),
        )
        self.assertEqual(env.SerializeToString(deterministic=True), bytes.fromhex(fixture["deterministic_wire_hex"]))
        decoded = pb.Envelope.FromString(bytes.fromhex(fixture["unknown_field_wire_hex"]))
        self.assertEqual(decoded.SerializeToString(deterministic=True), bytes.fromhex(fixture["unknown_field_wire_hex"]))
        unknown_ack = pb.AssignAck(code=fixture["unknown_enum_number"])
        self.assertEqual(unknown_ack.code, fixture["unknown_enum_number"])

    def test_request_start_direct_and_upstream_proxy(self):
        fixture = self.load("streaming.json")["request_start"]

        direct = pb.RequestStart.FromString(bytes.fromhex(fixture["direct"]["wire_hex"]))
        self.assertFalse(direct.HasField("upstream_proxy"))
        self.assertEqual(direct.destination_policy.resolution_mode, pb.DESTINATION_RESOLUTION_DIRECT_LOCAL)

        proxied = pb.RequestStart.FromString(bytes.fromhex(fixture["upstream_proxy"]["wire_hex"]))
        self.assertEqual(proxied.SerializeToString(deterministic=True),
                         bytes.fromhex(fixture["upstream_proxy"]["wire_hex"]))
        self.assertEqual(proxied.destination_policy.resolution_mode,
                         pb.DESTINATION_RESOLUTION_UPSTREAM_PROXY_REMOTE)
        want = fixture["upstream_proxy"]["upstream_proxy_instruction"]
        inst = proxied.upstream_proxy
        self.assertEqual(inst.upstream_proxy_id, want["upstream_proxy_id"])
        self.assertEqual(inst.provider_session_id, want["provider_session_id"])
        self.assertEqual(inst.country, want["country"])
        self.assertEqual(inst.region, want["region"])
        self.assertEqual(inst.ip_type, want["ip_type"])

    def test_old_decoder_ignores_upstream_proxy_instruction(self):
        # Emulate the previous tagged decoder by stripping field 16 (tag
        # 0x82 0x01, the trailing field in the deterministic encoding) from
        # the wire form: every known field must be retained and the new
        # decoder must accept the old wire form.
        fixture = self.load("streaming.json")["request_start"]
        wire = bytes.fromhex(fixture["upstream_proxy"]["wire_hex"])
        idx = wire.rfind(b"\x82\x01")
        self.assertGreaterEqual(idx, 0)
        old_form = wire[:idx]

        decoded = pb.RequestStart.FromString(old_form)
        self.assertFalse(decoded.HasField("upstream_proxy"))
        self.assertEqual(decoded.url, "https://www.coles.com.au/api/products")
        self.assertEqual(decoded.destination_policy.resolution_mode,
                         pb.DESTINATION_RESOLUTION_UPSTREAM_PROXY_REMOTE)


if __name__ == "__main__":
    unittest.main()
