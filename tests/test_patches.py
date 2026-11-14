"""Offline tests: discovery and patch generation (no Docker needed)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import prooflab  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class PatchTests(unittest.TestCase):
    def test_nginx_existing_curve_list_gets_pq_first(self):
        out, notes = prooflab.patch_nginx("server {\n  listen 443 ssl;\n  ssl_ecdh_curve X25519:prime256v1;\n  ssl_protocols TLSv1.2;\n}\n")
        self.assertIn("ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;", out)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", out)
        self.assertEqual(len(notes), 2)

    def test_nginx_without_curve_adds_line_after_key(self):
        src = "server {\n    listen 443 ssl;\n    ssl_certificate a.pem;\n    ssl_certificate_key k.pem;\n}\n"
        out, _ = prooflab.patch_nginx(src)
        self.assertIn("    ssl_certificate_key k.pem;\n    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;", out)

    def test_nginx_already_pq_is_unchanged(self):
        src = "server {\n listen 443 ssl;\n ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n"
        self.assertEqual(prooflab.patch_nginx(src), (src, []))

    def test_haproxy(self):
        out, _ = prooflab.patch_haproxy("global\n    ssl-default-bind-curves X25519:P-256\n")
        self.assertIn("ssl-default-bind-curves X25519MLKEM768:X25519:P-256", out)
        out, _ = prooflab.patch_haproxy("global\n    log stdout local0\nfrontend f\n    bind :443 ssl crt /x.pem\n")
        self.assertIn("global\n    ssl-default-bind-curves X25519MLKEM768:X25519:P-256\n", out)

    def test_caddy_curves_and_dockerfile_bump(self):
        out, _ = prooflab.patch_caddy("a.com {\n\ttls {\n\t\tcurves x25519 secp256r1\n\t}\n}\n")
        self.assertIn("curves x25519mlkem768 x25519 secp256r1", out)
        self.assertEqual(prooflab.patch_caddy("a.com {\n\trespond ok\n}\n")[1], [])
        df, notes = prooflab.bump_caddy_from("FROM caddy:2.8-alpine\n")
        self.assertEqual(df, "FROM caddy:2.10-alpine\n")
        self.assertEqual(prooflab.bump_caddy_from("FROM caddy:2.10.2\n")[1], [])

    def test_dockerfile_bump(self):
        out, notes = prooflab.bump_from("FROM nginx:1.27\nCOPY a b\n", "nginx", "nginx:1.27", "nginx:1.29-alpine")
        self.assertTrue(out.startswith("FROM nginx:1.29-alpine\n"))

    def test_discovery_on_examples(self):
        found = prooflab.discover(ROOT / "examples")
        self.assertEqual([p.name for p in found["nginx"]], ["nginx.conf"])
        self.assertEqual([p.name for p in found["caddy"]], ["Caddyfile"])
        self.assertEqual([p.name for p in found["haproxy"]], ["haproxy.cfg"])
        self.assertEqual(len(found["dockerfile"]), 3)
        df, image = prooflab.dockerfile_for(found["nginx"][0], found["dockerfile"], "nginx")
        self.assertEqual(image, "nginx:1.27")

    def test_caddy_prepare_rewrites_tls(self):
        text, port, sni = prooflab.Harness._prepare_caddy("example.com {\n\ttls {\n\t\tcurves x25519\n\t}\n\trespond ok\n}\n", [])
        self.assertIn("tls /prooflab/cert.pem /prooflab/key.pem {", text)
        self.assertEqual((port, sni), (443, "example.com"))
        text, port, _ = prooflab.Harness._prepare_caddy(":8443 {\n\trespond ok\n}\n", [])
        self.assertIn("\ttls /prooflab/cert.pem /prooflab/key.pem\n}", text)
        self.assertEqual(port, 8443)


if __name__ == "__main__":
    unittest.main()
