#!/usr/bin/env python3
"""Quantum Aether ProofLab (MVP): prove a post-quantum TLS change works before it reaches production.

1. Discover nginx / Caddy / HAProxy TLS configs and Dockerfile base images in a repository.
2. Propose a minimal change: X25519MLKEM768 hybrid key exchange first, classical groups kept as fallback.
3. Run the original and the patched config side by side in isolated Docker containers with a throwaway test cert.
4. Check: config valid, PQ-only client handshake, classical-only client handshake; measure handshake time and bytes.
5. Write a Markdown report (patch, pass/fail table, measurements, rollback steps) to the job summary.

Nothing is deployed. The only write to the repository is an optional pull request from a new branch.
Standard library only; needs `docker` and `git` on the runner.
"""
import argparse
import difflib
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

PQ_GROUP = "X25519MLKEM768"
NGINX_CURVES = "X25519MLKEM768:X25519:prime256v1"
HAPROXY_CURVES = "X25519MLKEM768:X25519:P-256"
CLIENT_PQ_GROUPS = "X25519MLKEM768"
CLIENT_CLASSIC_GROUPS = "X25519:prime256v1"
CLIENT_MODERN_GROUPS = "X25519MLKEM768:X25519:prime256v1"
# Images used when the patched config needs a newer TLS library than the repository's base image provides.
# Each choice is verified at run time: the report prints the OpenSSL / Go version actually found in the image.
RECOMMENDED = {
    "nginx": {"alpine": "nginx:1.29-alpine", "default": "nginx:1.29-alpine"},
    "haproxy": {"alpine": "haproxy:3.2-alpine", "default": "haproxy:3.2-alpine"},
    "caddy": {"alpine": "caddy:2.10-alpine", "default": "caddy:2.10-alpine"},
}
DEFAULT_ORIGINAL = {"nginx": "nginx:1.29-alpine", "haproxy": "haproxy:3.2-alpine", "caddy": "caddy:2.10-alpine"}
CLIENT_DOCKERFILE = "FROM alpine:3.22\nRUN apk add --no-cache openssl coreutils\n"
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build"}
MAX_CONFIGS = 6


# ----------------------------------------------------------------------------------------------- helpers
def run(cmd, timeout=120, check=False, input_text=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed ({p.returncode}): {p.stderr.strip()[-800:]}")
    return p


def log(msg):
    print(msg, flush=True)


def version_tuple(text):
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text or "")
    return tuple(int(x or 0) for x in m.groups()) if m else None


# ----------------------------------------------------------------------------------------------- discovery
def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def classify(path):
    name = path.name
    try:
        if path.stat().st_size > 512 * 1024:
            return None
        text = path.read_text(errors="replace")
    except OSError:
        return None
    if name.startswith("Caddyfile"):
        return "caddy"
    if name == "Dockerfile" or name.endswith(".Dockerfile") or name.startswith("Dockerfile."):
        return "dockerfile"
    if name.endswith(".cfg") or name == "haproxy.cfg":
        if re.search(r"^\s*(frontend|listen)\s+\S+", text, re.M) and re.search(r"^\s*bind\s+.*\bssl\b", text, re.M):
            return "haproxy"
    if name.endswith(".conf") or name == "nginx.conf" or name.endswith(".nginx"):
        if re.search(r"\bserver\s*\{", text) and (re.search(r"^\s*listen\s+[^;]*\bssl\b", text, re.M)
                                                 or re.search(r"^\s*ssl_certificate\s", text, re.M)):
            return "nginx"
    return None


def parse_from_lines(text):
    """Base images per stage; the last FROM is the runtime image."""
    images = []
    for line in text.splitlines():
        m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", line, re.I)
        if m:
            images.append(m.group(1))
    return images


def discover(root):
    found = {"nginx": [], "caddy": [], "haproxy": [], "dockerfile": []}
    for path in walk(root):
        kind = classify(path)
        if kind:
            found[kind].append(path)
    for k in found:
        found[k].sort()
    return found


def dockerfile_for(config_path, dockerfiles, server):
    """Closest Dockerfile (same directory first, then parents) whose runtime image is this server's official image."""
    best = None
    for df in dockerfiles:
        try:
            config_path.relative_to(df.parent)
        except ValueError:
            continue
        images = parse_from_lines(df.read_text(errors="replace"))
        runtime = images[-1] if images else ""
        repo = runtime.split("@")[0].split(":")[0].split("/")[-1]
        if repo == server and "$" not in runtime:
            depth = len(df.parent.parts)
            if best is None or depth > best[0]:
                best = (depth, df, runtime)
    return (best[1], best[2]) if best else (None, None)


# ----------------------------------------------------------------------------------------------- patches
def patch_nginx(text):
    """Put X25519MLKEM768 first in ssl_ecdh_curve (classical groups stay as fallback) and make sure TLS 1.3 is on."""
    notes, out = [], text
    if re.search(r"^\s*ssl_ecdh_curve\s", out, re.M):
        def fix(m):
            groups = [g for g in m.group(2).split(":") if g]
            if PQ_GROUP in groups:
                return m.group(0)
            if groups == ["auto"]:
                groups = []
            merged = [PQ_GROUP] + groups
            for g in ("X25519", "prime256v1"):
                if g not in merged and not (g == "prime256v1" and ("P-256" in merged or "secp256r1" in merged)):
                    merged.append(g)
            notes.append(f"ssl_ecdh_curve: {m.group(2)} -> {':'.join(merged)}")
            return f"{m.group(1)}{':'.join(merged)}{m.group(3)}"
        out = re.sub(r"^(\s*ssl_ecdh_curve\s+)([^;\s]+)(\s*;)", fix, out, flags=re.M)
    else:
        def add(m):
            indent = re.match(r"\s*", m.group(0)).group(0)
            notes.append(f"added ssl_ecdh_curve {NGINX_CURVES} (nginx's default 'auto' depends on the OpenSSL build)")
            return f"{m.group(0)}\n{indent}ssl_ecdh_curve {NGINX_CURVES};"
        out, n = re.subn(r"^[ \t]*ssl_certificate_key\s[^;]*;", add, out, flags=re.M)
        if n == 0:
            out, n = re.subn(r"^[ \t]*listen\s[^;]*\bssl\b[^;]*;", add, out, count=1, flags=re.M)

    def protocols(m):
        if "TLSv1.3" in m.group(2):
            return m.group(0)
        notes.append(f"ssl_protocols: added TLSv1.3 (hybrid ML-KEM key exchange exists only in TLS 1.3)")
        return f"{m.group(1)}{m.group(2).rstrip()} TLSv1.3{m.group(3)}"
    out = re.sub(r"^(\s*ssl_protocols\s+)([^;]+?)(\s*;)", protocols, out, flags=re.M)
    return out, notes


def patch_haproxy(text):
    notes, out = [], text
    def fix_curves(m):
        groups = [g for g in m.group(2).split(":") if g]
        if PQ_GROUP in groups:
            return m.group(0)
        merged = [PQ_GROUP] + groups
        if "X25519" not in merged:
            merged.append("X25519")
        notes.append(f"{m.group(1).strip()}: {m.group(2)} -> {':'.join(merged)}")
        return f"{m.group(1)}{':'.join(merged)}"
    if re.search(r"^\s*ssl-default-bind-curves\s", out, re.M):
        out = re.sub(r"^(\s*ssl-default-bind-curves\s+)(\S+)", fix_curves, out, flags=re.M)
    elif re.search(r"^\s*bind\s.*\bcurves\s", out, re.M):
        out = re.sub(r"(\bcurves\s+)(\S+)", fix_curves, out)
    else:
        out, n = re.subn(r"^(global[^\n]*\n)", lambda m: m.group(1) + f"    ssl-default-bind-curves {HAPROXY_CURVES}\n",
                         out, count=1, flags=re.M)
        if n:
            notes.append(f"global: added ssl-default-bind-curves {HAPROXY_CURVES}")
    return out, notes


def patch_caddy(text):
    """Caddy >= 2.10 offers X25519MLKEM768 by default; only an explicit `curves` list can switch it off."""
    notes = []
    def fix(m):
        groups = m.group(2).split()
        if "x25519mlkem768" in groups:
            return m.group(0)
        notes.append(f"tls curves: {' '.join(groups)} -> x25519mlkem768 {' '.join(groups)}")
        return f"{m.group(1)}x25519mlkem768 {' '.join(groups)}{m.group(3)}"
    out = re.sub(r"^(\s*curves\s+)([^\n#]+?)([ \t]*(?:#[^\n]*)?)$", fix, text, flags=re.M)
    return out, notes


def bump_caddy_from(text):
    notes = []
    def fix(m):
        tag = m.group(2)
        v = version_tuple(tag)
        if v and v[:2] < (2, 10):
            suffix = tag.split("-", 1)[1] if "-" in tag else ""
            new = "2.10" + (f"-{suffix}" if suffix else "")
            notes.append(f"Dockerfile: caddy:{tag} -> caddy:{new} (X25519MLKEM768 is on by default from Caddy 2.10)")
            return f"{m.group(1)}{new}"
        return m.group(0)
    out = re.sub(r"(?im)^(\s*FROM\s+(?:--platform=\S+\s+)?(?:docker\.io/)?(?:library/)?caddy:)(\S+)", fix, text)
    return out, notes


def bump_from(text, server, old_image, new_image):
    out, n = re.subn(r"(?im)^(\s*FROM\s+(?:--platform=\S+\s+)?)" + re.escape(old_image) + r"(\s|$)",
                     lambda m: m.group(1) + new_image + m.group(2), text)
    return out, ([f"Dockerfile: {old_image} -> {new_image} (needs OpenSSL >= 3.5 for X25519MLKEM768)"] if n else [])


# ----------------------------------------------------------------------------------------------- test harness
class Harness:
    def __init__(self, workdir, iterations):
        self.work = Path(workdir)
        self.iterations = iterations
        self.net = f"prooflab-{uuid.uuid4().hex[:8]}"
        self.client = "prooflab-client:local"
        self.containers = []

    def setup(self):
        run(["docker", "network", "create", self.net], check=True)
        ctx = self.work / "client"
        ctx.mkdir(exist_ok=True)
        (ctx / "Dockerfile").write_text(CLIENT_DOCKERFILE)
        run(["docker", "build", "-q", "-t", self.client, str(ctx)], timeout=600, check=True)
        self.client_openssl = run(["docker", "run", "--rm", self.client, "openssl", "version"]).stdout.strip()

    def cleanup(self):
        for c in self.containers:
            run(["docker", "rm", "-f", c])
        run(["docker", "network", "rm", self.net])

    def image_tls_library(self, server, image):
        if run(["docker", "pull", "-q", image], timeout=600).returncode != 0:
            return None, f"could not pull {image}"
        if server == "nginx":
            out = run(["docker", "run", "--rm", "--entrypoint", "nginx", image, "-V"]).stderr
            m = re.search(r"running with OpenSSL ([\d.]+\w*)", out) or re.search(r"built with OpenSSL ([\d.]+\w*)", out)
            return (("openssl", m.group(1)) if m else (None, out.strip()[:200])), out
        if server == "haproxy":
            out = run(["docker", "run", "--rm", "--entrypoint", "haproxy", image, "-vv"]).stdout
            m = re.search(r"Running on OpenSSL version\s*:\s*OpenSSL ([\d.]+\w*)", out) or re.search(r"Built with OpenSSL version\s*:\s*OpenSSL ([\d.]+\w*)", out)
            return (("openssl", m.group(1)) if m else (None, out.strip()[:200])), out
        if server == "caddy":
            out = run(["docker", "run", "--rm", "--entrypoint", "caddy", image, "version"]).stdout.strip()
            return ("caddy", out.split()[0] if out else "?"), out
        return (None, "?"), ""

    @staticmethod
    def supports_pq(server, lib):
        kind, ver = lib if lib else (None, None)
        v = version_tuple(ver or "")
        if not v:
            return False
        if kind == "openssl":
            return v >= (3, 5, 0)
        if kind == "caddy":
            return v[:2] >= (2, 10)
        return False

    # ---- per-server preparation: rewrite cert paths to the test cert, record what was rewritten
    def prepare(self, server, text):
        rewrites, hosts = [], set()
        if server == "nginx":
            def cert(m):
                rewrites.append(m.group(0).strip())
                target = "/prooflab/cert.pem" if m.group(1) == "ssl_certificate" else "/prooflab/key.pem"
                return f"{m.group(1)} {target};"
            text = re.sub(r"\b(ssl_certificate_key|ssl_certificate)\s+[^;]+;", cert, text)
            def drop(m):
                rewrites.append(m.group(0).strip() + "  (removed for the test run: file not in the test container)")
                return "# prooflab: removed for test: " + m.group(0).strip()
            text = re.sub(r"^[ \t]*(ssl_dhparam|ssl_trusted_certificate|ssl_client_certificate|ssl_stapling_file)\s[^;]*;", drop, text, flags=re.M)
            text = re.sub(r"^[ \t]*include\s+/etc/letsencrypt/[^;]*;", drop, text, flags=re.M)
            for m in re.finditer(r"proxy_pass\s+https?://([A-Za-z0-9_.-]+)", text):
                hosts.add(m.group(1))
            for m in re.finditer(r"^\s*server\s+([A-Za-z][A-Za-z0-9_.-]*)(?::\d+)?[^;]*;", text, re.M):
                hosts.add(m.group(1))
            listen = re.search(r"^\s*listen\s+(?:\[[^\]]*\]:|[\d.]+:)?(\d+)[^;]*\bssl\b", text, re.M)
            port = int(listen.group(1)) if listen else 443
            sn = re.search(r"^\s*server_name\s+([^;\s]+)", text, re.M)
            sni = sn.group(1) if sn and sn.group(1) not in ("_", "localhost", "") and "*" not in sn.group(1) else "localhost"
        elif server == "haproxy":
            def crt(m):
                rewrites.append(m.group(0).strip())
                return f"{m.group(1)}/prooflab/combined.pem"
            text = re.sub(r"(\bcrt\s+)(\S+)", crt, text)
            text = re.sub(r"(\bca-file\s+)(\S+)", lambda m: (rewrites.append(m.group(0) + " (removed)"), "")[1], text)
            b = re.search(r"^\s*bind\s+(?:[\d.*]*):(\d+)[^\n]*\bssl\b", text, re.M)
            port = int(b.group(1)) if b else 443
            sni = "localhost"
            for m in re.finditer(r"^\s*server\s+\S+\s+([A-Za-z][A-Za-z0-9_.-]*):\d+", text, re.M):
                hosts.add(m.group(1))
        else:  # caddy
            text, port, sni = self._prepare_caddy(text, rewrites)
        return text, rewrites, sorted(hosts), port, sni

    @staticmethod
    def _prepare_caddy(text, rewrites):
        lines, out, depth, port, sni, in_site, has_tls = text.splitlines(), [], 0, None, None, False, False
        for line in lines:
            stripped = line.strip()
            if depth == 0 and stripped.endswith("{") and stripped != "{" and not stripped.startswith("("):
                header = stripped[:-1].strip()
                addr = header.split(",")[0].split()[0]
                m = re.match(r"(?:https?://)?([^:/]*)(?::(\d+))?", addr)
                host, p = (m.group(1), m.group(2)) if m else ("", None)
                if port is None:
                    port = int(p) if p else 443
                    sni = host if host and host not in ("localhost",) and "*" not in host else "localhost"
                in_site, has_tls = True, False
                out.append(line)
                depth += 1
                continue
            if in_site and depth == 1 and re.match(r"tls(\s|$)", stripped):
                has_tls = True
                rewrites.append(stripped)
                indent = re.match(r"\s*", line).group(0)
                out.append(f"{indent}tls /prooflab/cert.pem /prooflab/key.pem" + (" {" if stripped.endswith("{") else ""))
                if stripped.endswith("{"):
                    depth += 1
                continue
            depth += line.count("{") - line.count("}")
            if in_site and depth == 0:
                if not has_tls:
                    out.append("\ttls /prooflab/cert.pem /prooflab/key.pem")
                    rewrites.append("(added) tls /prooflab/cert.pem /prooflab/key.pem")
                in_site = False
            out.append(line)
        return "\n".join(out) + "\n", port or 443, sni or "localhost"

    def make_cert(self, cert_dir, sni):
        """Throwaway self-signed test cert for this run (SAN = the site name), made in the client container."""
        cert_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(cert_dir, 0o777)
        san = ",".join(dict.fromkeys(f"DNS:{n}" for n in (sni, "localhost", "prooflab.test")))
        run(["docker", "run", "--rm", "-v", f"{cert_dir}:/out", self.client, "sh", "-c",
             "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=prooflab.test "
             f"-addext subjectAltName={san} -keyout /out/key.pem -out /out/cert.pem "
             "&& cat /out/cert.pem /out/key.pem > /out/combined.pem && chmod 644 /out/*.pem"], check=True)

    def mounts(self, server, conf_file, text, cert_dir):
        cert = ["-v", f"{cert_dir}:/prooflab:ro"]
        if server == "nginx":
            target = "/etc/nginx/nginx.conf" if re.search(r"^\s*http\s*\{", text, re.M) else "/etc/nginx/conf.d/default.conf"
            return cert + ["-v", f"{conf_file}:{target}:ro"], target
        if server == "haproxy":
            return cert + ["-v", f"{conf_file}:/usr/local/etc/haproxy/haproxy.cfg:ro"], "/usr/local/etc/haproxy/haproxy.cfg"
        return cert + ["-v", f"{conf_file}:/etc/caddy/Caddyfile:ro"], "/etc/caddy/Caddyfile"

    def validate_cmd(self, server, target):
        return {"nginx": ["nginx", "-t"], "haproxy": ["haproxy", "-c", "-f", target],
                "caddy": ["caddy", "validate", "--config", target, "--adapter", "caddyfile"]}[server]

    def handshake(self, host, port, sni, groups):
        p = run(["docker", "run", "--rm", "--network", self.net, self.client, "sh", "-c",
                 f"openssl s_client -connect {host}:{port} -servername {sni} -groups {groups} -tls1_3 </dev/null 2>&1"],
                timeout=60)
        out = p.stdout
        ok = p.returncode == 0 and "Cipher is (NONE)" not in out and ("TLSv1.3" in out)
        group = None
        m = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", out) or re.search(r"(?:Server|Peer) Temp Key:\s*([A-Za-z0-9_-]+)", out)
        if m:
            group = m.group(1).rstrip(",")
        rw = re.search(r"SSL handshake has read (\d+) bytes and written (\d+) bytes", out)
        return {"ok": ok, "group": group, "read": int(rw.group(1)) if rw else None,
                "written": int(rw.group(2)) if rw else None, "tail": out.strip()[-600:]}

    def timing(self, host, port, sni, groups):
        n = self.iterations
        script = (f"for i in $(seq {n}); do s=$(date +%s%N); "
                  f"openssl s_client -connect {host}:{port} -servername {sni} -groups {groups} -tls1_3 </dev/null >/dev/null 2>&1 "
                  f"&& e=$(date +%s%N) && echo $(( (e - s) / 1000 )); done")
        p = run(["docker", "run", "--rm", "--network", self.net, self.client, "sh", "-c", script], timeout=300)
        vals = [int(x) / 1000.0 for x in p.stdout.split() if x.isdigit()]
        return round(statistics.median(vals), 2) if vals else None

    def run_variant(self, server, label, image, text, filename):
        res = {"label": label, "image": image, "checks": {}, "measure": {}, "rewrites": []}
        lib, raw = self.image_tls_library(server, image)
        res["library"] = lib
        if lib is None:
            res["error"] = raw
            return res
        prepared, rewrites, hosts, port, sni = self.prepare(server, text)
        res["rewrites"], res["port"], res["sni"] = rewrites, port, sni
        vdir = self.work / f"{label}-{uuid.uuid4().hex[:6]}"
        vdir.mkdir()
        os.chmod(vdir, 0o755)
        conf = vdir / filename
        conf.write_text(prepared)
        os.chmod(conf, 0o644)
        self.make_cert(vdir / "cert", sni)
        mounts, target = self.mounts(server, conf, prepared, vdir / "cert")
        addhost = [a for h in hosts for a in ("--add-host", f"{h}:127.0.0.1")]
        v = run(["docker", "run", "--rm", *addhost, *mounts, "--entrypoint", self.validate_cmd(server, target)[0],
                 image, *self.validate_cmd(server, target)[1:]], timeout=120)
        res["checks"]["config_valid"] = v.returncode == 0
        res["validate_output"] = (v.stdout + v.stderr).strip()[-700:]
        if v.returncode != 0:
            return res
        name = f"prooflab-{label}-{uuid.uuid4().hex[:6]}"
        start = run(["docker", "run", "-d", "--name", name, "--network", self.net, *addhost, *mounts, image], timeout=120)
        self.containers.append(name)
        if start.returncode != 0:
            res["error"] = start.stderr.strip()[-400:]
            return res
        ready = run(["docker", "run", "--rm", "--network", self.net, self.client, "sh", "-c",
                     f"for i in $(seq 60); do nc -z {name} {port} && exit 0; sleep 0.5; done; exit 1"], timeout=60)
        if ready.returncode != 0:
            res["error"] = "server did not start listening: " + run(["docker", "logs", "--tail", "20", name]).stderr[-400:]
            return res
        pq = self.handshake(name, port, sni, CLIENT_PQ_GROUPS)
        classic = self.handshake(name, port, sni, CLIENT_CLASSIC_GROUPS)
        modern = self.handshake(name, port, sni, CLIENT_MODERN_GROUPS)
        res["checks"]["pq_client"] = pq["ok"]
        res["checks"]["classical_client"] = classic["ok"]
        res["checks"]["modern_client_gets_pq"] = modern["ok"] and (modern["group"] or "").upper() == PQ_GROUP.upper()
        res["handshakes"] = {"pq": pq, "classical": classic, "modern": modern}
        res["measure"] = {
            "pq_ms": self.timing(name, port, sni, CLIENT_PQ_GROUPS) if pq["ok"] else None,
            "classical_ms": self.timing(name, port, sni, CLIENT_CLASSIC_GROUPS) if classic["ok"] else None,
            "pq_bytes": (pq["read"], pq["written"]) if pq["ok"] else None,
            "classical_bytes": (classic["read"], classic["written"]) if classic["ok"] else None,
        }
        run(["docker", "rm", "-f", name])
        return res


# ----------------------------------------------------------------------------------------------- report
def mark(v):
    return "✅ pass" if v is True else ("❌ fail" if v is False else "—")


def fmt_bytes(b):
    return f"{b[0]} read / {b[1]} written" if b and b[0] is not None else "—"


def rollback_steps(server, rel_paths, notes):
    steps = ["Revert the pull request or commit (`git revert <commit>`), or restore these lines in "
             + ", ".join(f"`{p}`" for p in rel_paths) + ":"]
    steps += [f"   - {n}" for n in notes]
    reload_cmd = {"nginx": "`nginx -t && nginx -s reload`",
                  "haproxy": "`haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg` then reload (`systemctl reload haproxy` or send SIGUSR2 to the master)",
                  "caddy": "`caddy validate --config /etc/caddy/Caddyfile && caddy reload --config /etc/caddy/Caddyfile`"}[server]
    steps.append(f"Validate and reload: {reload_cmd}.")
    steps.append("If the image tag changed, redeploy the previous image tag.")
    steps.append("Check from outside: `openssl s_client -connect <host>:443 -groups X25519:prime256v1` must still succeed (classical clients).")
    return steps


def build_report(repo_root, items, client_openssl, harness_ran):
    lines = ["# ProofLab report: post-quantum TLS (X25519MLKEM768)", "",
             "Generated by [Quantum Aether ProofLab](https://ather-quantum.com/prooflab) (MVP). "
             "Nothing was deployed: the original and patched configs ran only in throwaway containers on this CI runner, "
             "with a self-signed test certificate.", ""]
    if harness_ran:
        lines += [f"Test client: `{client_openssl}` (alpine:3.22). PQ client offers only `{CLIENT_PQ_GROUPS}`; "
                  f"classical client offers only `{CLIENT_CLASSIC_GROUPS}`; modern client offers `{CLIENT_MODERN_GROUPS}`.", ""]
    if not items:
        lines += ["No nginx, Caddy or HAProxy TLS configuration was found. ProofLab MVP covers only these three servers."]
        return "\n".join(lines)
    for it in items:
        lines += [f"## {it['server']}: `{it['config']}`", ""]
        if it.get("dockerfile"):
            lines.append(f"Runtime image from `{it['dockerfile']}`: `{it['original_image']}`.")
        else:
            lines.append(f"No Dockerfile with an official {it['server']} image found; the original config was run on `{it['original_image']}`.")
        for v in it["variants"]:
            lib = v.get("library")
            if lib:
                lines.append(f"- {v['label']}: `{v['image']}` ships {lib[0]} `{lib[1]}`"
                             + (" (supports X25519MLKEM768)" if Harness.supports_pq(it['server'], lib) else " (no X25519MLKEM768 support)"))
        lines.append("")
        lines += ["### Proposed change", ""]
        if it["notes"]:
            lines += [f"- {n}" for n in it["notes"]] + [""]
        else:
            lines += ["- No change needed: the configuration already offers X25519MLKEM768." , ""]
        if it["diff"]:
            lines += ["```diff", it["diff"].rstrip(), "```", ""]
        lines += ["### Tests", "", "| Check | Original | Patched |", "|---|---|---|"]
        o, p = (it["variants"] + [{}, {}])[:2]
        labels = [("config_valid", "Config valid"), ("pq_client", f"Handshake, PQ-only client ({PQ_GROUP})"),
                  ("classical_client", "Handshake, classical-only client (fallback)"),
                  ("modern_client_gets_pq", f"Modern client negotiates {PQ_GROUP}")]
        for key, name in labels:
            lines.append(f"| {name} | {mark(o.get('checks', {}).get(key))} | {mark(p.get('checks', {}).get(key))} |")
        lines += ["", "### Measurements (median of runs, includes client process start)", "",
                  "| Metric | Original | Patched |", "|---|---|---|"]
        om, pm = o.get("measure", {}), p.get("measure", {})
        def ms(x):
            return f"{x} ms" if x is not None else "—"
        lines.append(f"| Handshake time, PQ client | {ms(om.get('pq_ms'))} | {ms(pm.get('pq_ms'))} |")
        lines.append(f"| Handshake time, classical client | {ms(om.get('classical_ms'))} | {ms(pm.get('classical_ms'))} |")
        lines.append(f"| Handshake bytes, PQ client | {fmt_bytes(om.get('pq_bytes'))} | {fmt_bytes(pm.get('pq_bytes'))} |")
        lines.append(f"| Handshake bytes, classical client | {fmt_bytes(om.get('classical_bytes'))} | {fmt_bytes(pm.get('classical_bytes'))} |")
        groups = [(v["label"], (v.get("handshakes", {}).get("modern") or {}).get("group")) for v in it["variants"]]
        lines += ["", "Group chosen for the modern client: " + ", ".join(f"{l}: `{g or '—'}`" for l, g in groups), ""]
        for v in it["variants"]:
            if v.get("error"):
                lines += [f"> ⚠ {v['label']}: {v['error']}", ""]
            if v.get("checks", {}).get("config_valid") is False:
                lines += [f"<details><summary>{v['label']}: config validation output</summary>", "", "```",
                          v.get("validate_output", ""), "```", "</details>", ""]
        rw = sorted({r for v in it["variants"] for r in v.get("rewrites", [])})
        if rw:
            lines += ["<details><summary>Test-only rewrites (not part of the patch)</summary>", ""]
            lines += [f"- `{r}` → test certificate" for r in rw] + ["", "</details>", ""]
        lines += ["### Rollback steps", ""]
        n = 0
        for step in rollback_steps(it["server"], it["changed_files"] or [it["config"]], it["rollback_notes"]):
            if step.startswith("   "):
                lines.append(step)
            else:
                n += 1
                lines.append(f"{n}. {step}")
        lines.append("")
        lines += [f"**Verdict:** {it['verdict']}", ""]
    lines += ["---", "Scope (MVP): nginx, Caddy and HAProxy configs only. The harness tests protocol behaviour, "
              "not your application, upstreams or real certificates. Review the patch before merging; nothing reaches "
              "production without your explicit approval."]
    return "\n".join(lines)


# ----------------------------------------------------------------------------------------------- main flow
def analyse(repo_root, scan_root, harness):
    found = discover(scan_root)
    log(f"Found: nginx={len(found['nginx'])} caddy={len(found['caddy'])} haproxy={len(found['haproxy'])} "
        f"dockerfiles={len(found['dockerfile'])}")
    items, patched_files = [], {}
    configs = [(s, p) for s in ("nginx", "caddy", "haproxy") for p in found[s]][:MAX_CONFIGS]
    for server, path in configs:
        rel = str(path.relative_to(repo_root))
        text = path.read_text(errors="replace")
        df, original_image = dockerfile_for(path, found["dockerfile"], server)
        original_image = original_image or DEFAULT_ORIGINAL[server]
        new_text, notes = {"nginx": patch_nginx, "haproxy": patch_haproxy, "caddy": patch_caddy}[server](text)
        rollback_notes = []
        for line_old, line_new in zip(text.splitlines(), new_text.splitlines()):
            if line_old != line_new:
                rollback_notes.append(f"`{line_old.strip()}`")
        if new_text.count("\n") > text.count("\n"):
            rollback_notes.append("remove the added line(s) shown in the diff")
        changes = {}
        if new_text != text:
            changes[path] = (text, new_text)
        # Decide the image for the patched run and, if needed, a Dockerfile change.
        patched_image = original_image
        lib, _ = harness.image_tls_library(server, original_image) if harness else (None, None)
        if harness and not Harness.supports_pq(server, lib):
            flavour = "alpine" if "alpine" in original_image else "default"
            patched_image = RECOMMENDED[server][flavour]
            if df:
                df_text = changes.get(df, (df.read_text(errors="replace"),) * 2)[1]
                if server == "caddy":
                    new_df, df_notes = bump_caddy_from(df_text)
                    m = re.findall(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S*caddy:\S+)", new_df)
                    patched_image = m[-1] if m else patched_image
                else:
                    new_df, df_notes = bump_from(df_text, server, original_image, patched_image)
                if new_df != df_text:
                    changes[df] = (df.read_text(errors="replace"), new_df)
                    notes += df_notes
                    rollback_notes.append(f"`FROM {original_image}` in `{df.relative_to(repo_root)}`")
            else:
                notes.append(f"Run this config on {server} built with OpenSSL >= 3.5 (tested here with `{patched_image}`); "
                             f"`{original_image}` does not support X25519MLKEM768.")
        diff = "".join("".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                                     f"a/{p.relative_to(repo_root)}", f"b/{p.relative_to(repo_root)}"))
                       for p, (old, new) in changes.items())
        item = {"server": server, "config": rel, "dockerfile": str(df.relative_to(repo_root)) if df else None,
                "original_image": original_image, "patched_image": patched_image, "notes": notes, "diff": diff,
                "changed_files": [str(p.relative_to(repo_root)) for p in changes], "rollback_notes": rollback_notes,
                "variants": []}
        if harness:
            item["variants"].append(harness.run_variant(server, "original", original_image, text, path.name))
            item["variants"].append(harness.run_variant(server, "patched", patched_image, new_text, path.name))
            pc = item["variants"][1].get("checks", {})
            oc = item["variants"][0].get("checks", {})
            passed = all(pc.get(k) is True for k in ("config_valid", "pq_client", "classical_client", "modern_client_gets_pq"))
            item["patched_pass"] = passed
            item["original_pq"] = oc.get("pq_client") is True
            if passed and not item["original_pq"]:
                item["verdict"] = "✅ The patch enables X25519MLKEM768 and keeps the classical fallback working."
            elif passed:
                item["verdict"] = "✅ Already post-quantum; the patched config passes all checks."
            else:
                item["verdict"] = "❌ The patched config did not pass every check. Do not merge; see the table above."
        else:
            item["patched_pass"], item["original_pq"], item["verdict"] = None, None, "Not tested (test-run: false)."
        for p, (_, new) in changes.items():
            patched_files[p] = new
        items.append(item)
    return items, patched_files


def open_pull_request(repo_root, patched_files, report_path, token):
    def git(*args, check=True):
        return run(["git", "-C", str(repo_root), *args], check=check)
    default = run(["gh", "repo", "view", "--json", "defaultBranchRef", "-q", ".defaultBranchRef.name"],
                  check=False).stdout.strip() or os.environ.get("GITHUB_BASE_REF") or "main"
    branch = f"prooflab/x25519mlkem768-{os.environ.get('GITHUB_RUN_ID', uuid.uuid4().hex[:8])}"
    if not branch.startswith("prooflab/") or branch == default:  # never push to the default branch
        raise RuntimeError("refusing to push: unsafe branch name")
    git("checkout", "-b", branch)
    for path, text in patched_files.items():
        Path(path).write_text(text)
        git("add", str(Path(path).relative_to(repo_root)))
    git("-c", "user.name=prooflab-action[bot]", "-c", "user.email=prooflab-action@users.noreply.github.com",
        "commit", "-m", "ProofLab: enable X25519MLKEM768 hybrid key exchange (classical fallback kept)")
    git("push", "origin", f"HEAD:refs/heads/{branch}")
    p = run(["gh", "pr", "create", "--base", default, "--head", branch,
             "--title", "ProofLab: enable post-quantum TLS (X25519MLKEM768) with classical fallback",
             "--body-file", str(report_path)], check=True)
    return p.stdout.strip().splitlines()[-1]


def set_output(name, value):
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"{name}={value}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--path", default=".")
    ap.add_argument("--repo-root", default=os.environ.get("GITHUB_WORKSPACE", "."))
    ap.add_argument("--test-run", default="true")
    ap.add_argument("--open-pr", default="false")
    ap.add_argument("--fail-on-error", default="true")
    ap.add_argument("--iterations", type=int, default=20)
    ap.add_argument("--report", default="prooflab-report.md")
    a = ap.parse_args(argv)
    repo_root = Path(a.repo_root).resolve()
    scan_root = (repo_root / a.path).resolve()
    if repo_root not in scan_root.parents and scan_root != repo_root:
        sys.exit("path must be inside the repository")
    test_run = a.test_run.lower() == "true"
    harness = None
    work = tempfile.mkdtemp(prefix="prooflab-")
    os.chmod(work, 0o755)  # non-root server images (haproxy) must read the mounted files
    try:
        if test_run:
            harness = Harness(work, max(1, min(a.iterations, 200)))
            harness.setup()
        items, patched_files = analyse(repo_root, scan_root, harness)
    finally:
        if harness:
            harness.cleanup()
    report = build_report(repo_root, items, harness.client_openssl if harness else "", bool(harness))
    report_path = Path(a.report).resolve()
    report_path.write_text(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(report + "\n")
    else:
        print(report)
    tested = [i for i in items if i["patched_pass"] is not None]
    all_pass = bool(tested) and all(i["patched_pass"] for i in tested)
    set_output("configs-found", len(items))
    set_output("patched-pass", "true" if all_pass else "false")
    set_output("original-post-quantum", "true" if tested and all(i["original_pq"] for i in tested) else "false")
    set_output("report-path", str(report_path))
    with open(Path(work) / "result.json", "w") as f:
        json.dump([{k: v for k, v in i.items() if k != "variants"} for i in items], f)
    pr_url = ""
    if a.open_pr.lower() == "true" and patched_files and all_pass:
        pr_url = open_pull_request(repo_root, patched_files, report_path, os.environ.get("GH_TOKEN", ""))
        log(f"Opened {pr_url}")
    elif a.open_pr.lower() == "true" and not all_pass:
        log("::warning::Pull request not opened: the patched config did not pass every check.")
    set_output("pr-url", pr_url)
    shutil.rmtree(work, ignore_errors=True)
    if tested and not all_pass and a.fail_on_error.lower() == "true":
        log("::error::ProofLab: the patched configuration failed at least one check (see the job summary).")
        return 1
    if not items:
        log("::warning::ProofLab: no nginx, Caddy or HAProxy TLS configuration found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
