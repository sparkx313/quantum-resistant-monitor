# PQC TLS 1.3 Negotiation Monitor

This command-line monitor checks whether an explicitly supplied host negotiates the standardized `X25519MLKEM768` hybrid post-quantum key-exchange group during a real TLS 1.3 handshake. It uses the local OpenSSL executable to report the group selected by the server and verifies the server certificate and hostname.

The monitor records handshake observations. It does not crawl the public internet, infer a CDN or country, recommend server configuration, or claim complete post-quantum readiness. It tests one hybrid group per host; a negative result is scoped to that probe.

## Requirements

- Python 3.10 or newer
- OpenSSL 3.5 or newer, built with TLS ML-KEM group support
- A trusted CA bundle configured for OpenSSL
- Network access to the host you explicitly choose

Python runtime dependencies are empty; OpenSSL is an external executable. On Windows, install a compatible OpenSSL build and pass its path with `--openssl` if it is not available as `openssl` on `PATH`.

## Probe one host

```powershell
python -m src.tls_scanner --host example.com
```

The default port is `443`. The JSON result reports the negotiated group, TLS version, cipher suite, certificate-verification result, OpenSSL version, and scan timestamp.

## Probe an authorized list

Create a UTF-8 text file with one hostname or IP address per line. Lines may include comments after `#`.

```text
example.com
www.example.org
# internal service
api.example.net
```

Run a sequential scan with a one-second pause between hosts:

```powershell
python -m src.tls_scanner `
  --domains "targets.txt" `
  --delay 1.0 `
  --timeout 10 `
  --output "results/handshakes.jsonl"
```

At most 500 hosts are accepted per run. The JSONL output is appended so separate runs can be compared over time. Only scan hosts you are authorized to assess.

## Result meanings

- `pqc-hybrid-negotiated`: the verified TLS 1.3 handshake selected `X25519MLKEM768`.
- `pqc-hybrid-not-observed`: the PQ-only probe did not complete, while a verified TLS 1.3 classical control handshake did. This says nothing about other PQ groups.
- `inconclusive`: local OpenSSL support, certificate validation, DNS, connection, or both handshakes prevented a reliable comparison.

The PQ-only attempt offers only `X25519MLKEM768`. If it fails, the scanner performs a classical control using X25519, P-256, and P-384. Both probes use certificate and hostname verification; the scanner does not disable TLS verification or send application data.

## Standards and implementation references

- The [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters) lists `X25519MLKEM768` as a hybrid group.
- OpenSSL's [`s_client` documentation](https://docs.openssl.org/3.5/man1/openssl-s_client/) describes the TLS client command and its reporting options.
- OpenSSL's [group configuration documentation](https://docs.openssl.org/3.5/man3/SSL_CONF_cmd/) documents `-groups` and group negotiation. OpenSSL 3.5 added ML-KEM TLS support.

## Scope

A negotiated group is evidence for that specific handshake, host, port, time, client implementation, and network path. It does not establish organization-wide migration, certificate signature readiness, or the behavior of other clients and endpoints.
