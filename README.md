# Quantum-Resistant Traffic Migration Monitor

> Real-time scanner that analyzes TLS handshakes across the web to track post-quantum cryptography (PQC) adoption — building a live global migration dashboard.

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## The Problem

NIST finalized **CRYSTALS-Kyber (ML-KEM)** and **CRYSTALS-Dilithium (ML-DSA)** in 2024. But:

- **How many websites actually offer PQC key exchange?**
- **Which CDNs are prioritizing migration?**
- **Which industries are falling behind?**
- **"Q-Day"** (the date quantum computers break RSA/ECC) is estimated 2029–2035

No open tool tracks real-time PQC adoption across the public internet.

---

## What This Tool Does

1. **TLS Handshake Scanner**: Connects to target domains, parses `ServerKeyExchange` / `SupportedGroups` extension
2. **PQC Detection**: Identifies X25519Kyber768, mlkem768, and other hybrid post-quantum key exchange proposals
3. **Database Population**: Stores results with domain metadata (industry, CDN, country)
4. **Live Dashboard**: Streamlit/Grafana dashboard showing global PQC adoption heatmap
5. **Longitudinal Tracking**: Weekly scans → migration rate trends over time

---

## Detected Post-Quantum Algorithms

| Algorithm | OID / Code | Status |
|-----------|-----------|--------|
| X25519Kyber768 | `0x6399` | Cloudflare + Google enabled |
| mlkem768 | `0x0400` | NIST standardized 2024 |
| mldsa65 | `0x0804` | NIST standardized 2024 |
| Classic-McEliece-6688 | draft | TLS extension draft |
| FrodoKEM-640-AES | draft | Microsoft research |

---

## Usage

### Scan a List of Domains

```bash
python -m src.scanner \
    --domains data/top_100k.txt \
    --parallel 20 \
    --timeout 10 \
    --output data/scan_results.jsonl \
    --verbose
```

### Generate PQC Adoption Report

```bash
python -m src.report \
    --results data/scan_results.jsonl \
    --output reports/pqc_adoption_2024.html \
    --format html
```

### Run the Live Dashboard

```bash
streamlit run src/dashboard.py
```

---

## Project Structure

```
quantum-resistant-monitor/
├── src/
│   ├── tls_scanner.py   # TLS handshake parser + PQC detection
│   ├── algorithms.py    # PQC algorithm registry
│   ├── scanner.py       # Orchestrator
│   ├── report.py        # HTML/PDF report generation
│   ├── dashboard.py     # Streamlit live dashboard
│   └── database.py      # SQLite result store
├── data/
│   ├── top_100k.txt     # Domain list (Tranco or Majestic Million)
│   └── scan_results.jsonl
├── reports/
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

## Example Output

```json
{
  "domain": "example.com",
  "scan_date": "2024-11-15T03:22:10Z",
  "tls_version": "TLSv1.3",
  "supported_groups": ["x25519", "secp384r1"],
  "pq_groups_detected": [],
  "pqc_ready": false,
  "cdn": "Cloudflare",
  "country": "US",
  "cert_issuer": "Let's Encrypt",
  "recommendation": "Enable X25519Kyber768 via server config"
}
```

---

## How to Get Domain Lists

- **Tranco**: https://tranco-list.eu/ (top 1M domains)
- **Majestic Million**: https://majestic.com/reports/majestic-million
- **CrowdStrike Global Internet Test List**

---

## References

- NIST PQC Standards (FIPS 203, 204, 205) — August 2024
- TLS PQC Key Exchange Drafts (draft-cormio-tls-hybrid-*)
- Cloudflare PQC Blog (2022–2024)
- Google QUICHE Kyber Integration

---

## License

MIT © [sparkx313](https://github.com/sparkx313)
