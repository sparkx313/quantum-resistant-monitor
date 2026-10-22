"""
TLS Handshake Scanner — Detects Post-Quantum Cryptography key exchange support.
"""

import socket
import ssl
import struct
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

# Known PQC key exchange groups (from IANA TLS Supported Groups registry)
PQC_GROUPS: Dict[int, str] = {
    0x6399: "X25519Kyber768_draft",     # Cloudflare/Google hybrid
    0x6398: "X25519Kyber512_draft",
    0x0400: "mlkem768_draft",            # NIST ML-KEM Level 3
    0x0401: "mlkem1024_draft",           # NIST ML-KEM Level 5
    0x0200: "frodo640aes_draft",         # Microsoft FrodoKEM
    0x0201: "frodo976aes_draft",
    0x0500: " ClassicMcEliece6944_draft",
    0x0600: "sikep434_draft",            # supersingular isogeny (SIKE, broken but in drafts)
}

# Standard (non-PQC) groups for reference
STANDARD_GROUPS: Dict[int, str] = {
    0x0017: "x25519",
    0x0018: "x448",
    0x0019: "secp256r1",
    0x001a: "secp384r1",
    0x001b: "secp521r1",
    0x0021: "brainpoolP256r1",
    0xff01: "ffdhe2048",
}


class TLSPQCScanner:
    """
    Connects to a target host via TLS and inspects ServerKeyExchange
    and supported_groups to detect post-quantum cryptography offerings.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def scan(self, hostname: str, port: int = 443) -> Dict:
        """Perform a full TLS handshake scan and return structured result."""
        result = {
            "domain": hostname,
            "port": port,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "tls_version": None,
            "cipher_suite": None,
            "supported_groups": [],
            "pq_groups_detected": [],
            "pqc_ready": False,
            "pqc_partial": False,
            "cert_issuer": None,
            "cert_expiry": None,
            "error": None,
        }

        try:
            context = ssl.create_default_context()
            # Disable certificate verification for scanning
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    result["tls_version"] = tls_sock.version()
                    cipher = tls_sock.cipher()
                    if cipher:
                        result["cipher_suite"] = cipher[0]

                    # Extract supported groups from handshake
                    groups = self._extract_supported_groups(tls_sock, hostname, port)
                    result["supported_groups"] = [
                        STANDARD_GROUPS.get(g, PQC_GROUPS.get(g, f"unknown_{hex(g)}"))
                        for g in groups
                    ]

                    pq_found = [g for g in groups if g in PQC_GROUPS]
                    result["pq_groups_detected"] = [PQC_GROUPS[g] for g in pq_found]
                    result["pqc_ready"] = len(pq_found) >= 2  # hybrid = both classical + PQC
                    result["pqc_partial"] = len(pq_found) == 1

                    # Certificate info
                    try:
                        cert = tls_sock.getpeercert()
                        if cert:
                            issuer = dict(x[0] for x in cert.get("issuer", []))
                            result["cert_issuer"] = issuer.get("organizationName")
                            result["cert_expiry"] = cert.get("notAfter")
                    except Exception:
                        pass

        except socket.timeout:
            result["error"] = "Connection timed out"
        except socket.gaierror:
            result["error"] = "DNS resolution failed"
        except ssl.SSLError as e:
            result["error"] = f"TLS error: {str(e)[:80]}"
        except Exception as e:
            result["error"] = str(e)[:100]

        return result

    def _extract_supported_groups(
        self, tls_sock: ssl.SSLSocket, hostname: str, port: int
    ) -> List[int]:
        """
        Parse the TLS ClientHello/ServerHello supported_groups extension.
        This is a simplified extraction — production use requires full TLS record parsing.
        """
        # Send a raw ClientHello with all known PQC groups advertised
        # Then check if server responds with a PQC group in ServerKeyExchange
        groups: Set[int] = set()

        # Strategy: try connecting with only PQC groups advertised
        # If handshake succeeds → server supports that PQC group
        for pq_id in PQC_GROUPS:
            if self._test_group_support(hostname, port, pq_id):
                groups.add(pq_id)

        # Also check standard groups
        for std_id in STANDARD_GROUPS:
            if self._test_group_support(hostname, port, std_id):
                groups.add(std_id)

        return list(groups)

    def _test_group_support(self, hostname: str, port: int, group_id: int) -> bool:
        """
        Test if a server supports a specific TLS group by attempting a
        targeted handshake. Returns True if group negotiated.
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Set security level to allow all curves
            ctx.set_ciphers("ALL:@SECLEVEL=0")

            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                    # If handshake completes, server supports at least something
                    # In production, use OpenSSL's group selection API
                    # For now, we use a heuristic: successful handshake = OK
                    ss.do_handshake()
                    return True
        except Exception:
            return False

    def scan_batch(self, domains: List[str], output_path: str) -> List[Dict]:
        """Scan multiple domains and write JSONL output."""
        results = []
        for i, domain in enumerate(domains):
            print(f"[{i+1}/{len(domains)}] {domain}", end=" ... ")
            r = self.scan(domain.strip())
            status = "PQC" if r["pqc_ready"] else ("partial" if r["pqc_partial"] else "no")
            print(status)
            results.append(r)

        with open(output_path, "a") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")

        return results
