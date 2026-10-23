"""Probe real TLS 1.3 negotiation for the standardized X25519MLKEM768 group.

The scanner uses the local OpenSSL CLI to report actual TLS 1.3 group
negotiation. It verifies the peer certificate and never sends application data.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PQC_GROUP = "X25519MLKEM768"
CLASSICAL_GROUPS = "X25519:P-256:P-384"
MAX_TARGETS = 500


def _target_name(host: str) -> tuple[str, str | None]:
    value = host.strip().rstrip(".")
    if not value or any(character.isspace() for character in value) or "/" in value or "@" in value:
        raise ValueError(f"invalid host name: {host!r}")
    try:
        address = ipaddress.ip_address(value)
        connect_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
        return connect_host, None
    except ValueError:
        try:
            ascii_host = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"invalid internationalized host name: {host!r}") from exc
        labels = ascii_host.split(".")
        label_pattern = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE)
        if len(ascii_host) > 253 or any(not label_pattern.fullmatch(label) for label in labels):
            raise ValueError(f"invalid host name: {host!r}")
        return ascii_host, ascii_host


def _last_diagnostic(output: str) -> str:
    ignored = ("CONNECTED(", "CONNECTION ESTABLISHED", "Protocol version:", "Ciphersuite:",
               "Peer certificate:", "Negotiated TLS1.3 group:", "Verification:", "DONE")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    useful = [line for line in lines if not line.startswith(ignored)]
    return " | ".join(useful[-3:])[:300] or "OpenSSL did not report a successful TLS 1.3 group negotiation."


class TLSPQCScanner:
    """Check whether a host negotiates one standardized hybrid TLS 1.3 group."""

    def __init__(self, timeout: float = 10.0, openssl: str = "openssl"):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        self.timeout = timeout
        self.openssl = shutil.which(openssl) or openssl
        self.openssl_version: str | None = None
        self.setup_error: str | None = None
        self._check_local_openssl()

    def _check_local_openssl(self) -> None:
        try:
            version = subprocess.run(
                [self.openssl, "version"], capture_output=True, text=True,
                timeout=min(self.timeout, 5.0), check=False,
            )
            if version.returncode != 0:
                self.setup_error = _last_diagnostic(version.stdout + "\n" + version.stderr)
                return
            self.openssl_version = (version.stdout or version.stderr).strip()

            groups = subprocess.run(
                [self.openssl, "list", "-tls1_3", "-tls-groups"], capture_output=True,
                text=True, timeout=min(self.timeout, 5.0), check=False,
            )
            if groups.returncode != 0 or PQC_GROUP not in (groups.stdout + groups.stderr):
                self.setup_error = (
                    f"{PQC_GROUP} is unavailable in the local OpenSSL build; "
                    "use OpenSSL 3.5 or newer with TLS ML-KEM group support."
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.setup_error = f"Could not inspect the local OpenSSL installation: {exc}"

    def _probe(self, host: str, port: int, groups: str) -> dict[str, Any]:
        connect_host, server_name = _target_name(host)
        endpoint = f"{connect_host}:{port}"
        command = [
            self.openssl, "s_client", "-connect", endpoint, "-tls1_3", "-groups", groups,
            "-brief", "-verify_return_error",
        ]
        if server_name is None:
            command.extend(["-verify_ip", connect_host.strip("[]")])
        else:
            command.extend(["-servername", server_name, "-verify_hostname", server_name])

        completed = subprocess.run(
            command,
            input="",
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        output = completed.stdout + "\n" + completed.stderr
        group_match = re.search(r"Negotiated TLS1\.3 group:\s*([^\s]+)", output, re.IGNORECASE)
        version_match = re.search(r"Protocol version:\s*([^\s]+)", output)
        cipher_match = re.search(r"Ciphersuite:\s*([^\s]+)", output)
        verified = bool(re.search(r"Verification:\s*OK|Verify return code:\s*0\s*\(ok\)", output, re.IGNORECASE))
        negotiated_group = group_match.group(1) if group_match else None
        return {
            "ok": completed.returncode == 0 and negotiated_group is not None and verified,
            "tls_version": version_match.group(1) if version_match else None,
            "cipher_suite": cipher_match.group(1) if cipher_match else None,
            "negotiated_group": negotiated_group,
            "certificate_verified": verified,
            "error": None if completed.returncode == 0 and negotiated_group and verified else _last_diagnostic(output),
        }

    def scan(self, hostname: str, port: int = 443) -> dict[str, Any]:
        """Attempt a PQ-only handshake, then a classical control if needed."""
        result: dict[str, Any] = {
            "host": hostname,
            "port": port,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "status": "inconclusive",
            "pqc_group_tested": PQC_GROUP,
            "pqc_hybrid_negotiated": None,
            "tls_version": None,
            "cipher_suite": None,
            "negotiated_group": None,
            "certificate_verified": None,
            "openssl_version": self.openssl_version,
            "error": None,
        }
        if self.setup_error:
            result["error"] = self.setup_error
            return result
        if not 1 <= port <= 65535:
            result["error"] = "port must be between 1 and 65535"
            return result

        try:
            _target_name(hostname)
            pq_probe = self._probe(hostname, port, PQC_GROUP)
            if pq_probe["ok"]:
                result.update({
                    "status": "pqc-hybrid-negotiated",
                    "pqc_hybrid_negotiated": True,
                    "tls_version": pq_probe["tls_version"],
                    "cipher_suite": pq_probe["cipher_suite"],
                    "negotiated_group": pq_probe["negotiated_group"],
                    "certificate_verified": True,
                })
                return result

            classical_probe = self._probe(hostname, port, CLASSICAL_GROUPS)
            if classical_probe["ok"]:
                result.update({
                    "status": "pqc-hybrid-not-observed",
                    "pqc_hybrid_negotiated": False,
                    "tls_version": classical_probe["tls_version"],
                    "cipher_suite": classical_probe["cipher_suite"],
                    "negotiated_group": classical_probe["negotiated_group"],
                    "certificate_verified": True,
                    "error": f"The classical control succeeded; the {PQC_GROUP} probe did not: {pq_probe['error']}",
                })
            else:
                result["error"] = (
                    f"PQC probe: {pq_probe['error']} Classical control: {classical_probe['error']}"
                )
        except subprocess.TimeoutExpired:
            result["error"] = f"OpenSSL probe timed out after {self.timeout:g} seconds"
        except OSError as exc:
            result["error"] = f"Could not run OpenSSL probe: {exc}"
        except ValueError as exc:
            result["error"] = str(exc)
        return result

    def scan_batch(self, domains: list[str], port: int = 443, delay: float = 1.0) -> list[dict[str, Any]]:
        """Scan an explicit, bounded list sequentially with a delay between hosts."""
        results = []
        if self.setup_error:
            return [self.scan(domain, port) for domain in domains]
        for index, domain in enumerate(domains):
            results.append(self.scan(domain, port))
            if index + 1 < len(domains) and delay:
                time.sleep(delay)
        return results


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _domains_from_file(path: Path) -> list[str]:
    domains = []
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            value = line.split("#", 1)[0].strip()
            if value:
                domains.append(value)
    if not domains:
        raise ValueError("domain file contains no hosts")

    if len(domains) > MAX_TARGETS:
        raise ValueError(f"domain file exceeds the {MAX_TARGETS}-host per-run limit")
    return list(dict.fromkeys(domains))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure a verified TLS 1.3 handshake using the X25519MLKEM768 hybrid group."
    )
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("--host", help="one hostname or IP address you are authorized to probe")
    targets.add_argument("--domains", type=Path, help="text file with one authorized hostname or IP per line")
    parser.add_argument("--port", type=_port, default=443, help="TLS port (default: 443)")
    parser.add_argument("--timeout", type=float, default=10.0, help="timeout per TLS handshake in seconds")
    parser.add_argument("--delay", type=float, default=1.0, help="pause between hosts in a domain file")
    parser.add_argument("--openssl", default="openssl", help="OpenSSL executable (requires TLS ML-KEM group support)")
    parser.add_argument("--output", type=Path, help="append JSONL results to this file; stdout is used otherwise")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be positive")
    if not math.isfinite(args.delay) or args.delay < 0:
        parser.error("delay cannot be negative")
    try:
        domains = [args.host] if args.host else _domains_from_file(args.domains.expanduser())
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    for domain in domains:
        try:
            _target_name(domain)
        except ValueError as exc:
            parser.error(str(exc))
    if len(domains) > MAX_TARGETS:
        parser.error(f"at most {MAX_TARGETS} hosts can be scanned in one run")

    scanner = TLSPQCScanner(timeout=args.timeout, openssl=args.openssl)
    results = scanner.scan_batch(domains, port=args.port, delay=args.delay)
    serialized = [json.dumps(result, sort_keys=True) for result in results]
    if args.output:
        output_path = args.output.expanduser()
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("a", encoding="utf-8") as destination:
                for line in serialized:
                    destination.write(line + "\n")
        except OSError as exc:
            parser.error(f"could not write output: {exc}")
    else:
        for line in serialized:
            print(line)

    if all(result["status"] != "inconclusive" for result in results):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
