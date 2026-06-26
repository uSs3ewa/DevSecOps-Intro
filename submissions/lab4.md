# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3069
- `juice-shop.cdx.json` size: 1834859 bytes
- `juice-shop.spdx.json` component count: 909

### Grype severity breakdown

| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 36 |
| Low | 5 |
| Negligible | 7 |
| **Total** | 106 |

### Top 10 CVEs

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | (won't fix) |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | (none) |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | (none) |

### Fix-available rate
Out of the top 10 CVEs, 6 out of 10 have a fix available. The remaining 4 (CVE-2026-5450 in libc6 marked "won't fix", GHSA-5mrr-rgp6-x4gr in marsdb, and GHSA-p6mc-m468-83gw in lodash.set) have no fix. Following Lecture 4's triage shortcut — sort by fix-available AND severity >= HIGH first — the priority should be jsonwebtoken (Critical, fix to 4.2.2), lodash (Critical, fix to 4.17.12), and crypto-js (Critical, fix to 4.2.0), since these are all critical-severity npm packages with known fixes. The "won't fix" libc6 CVE-2026-5450 requires either accepting the risk or upgrading the base image OS.

---

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 36 | 39 | +3 |
| Low | 5 | 22 | +17 |
| Negligible | 7 | 0 | -7 |
| **Total** | 106 | 109 | +3 |

### Why the difference?

**1. CVE-2026-48937 (Grype only, Trivy missed)**
This is a Node.js HTTP/2 GOAWAY frame vulnerability (Medium severity) affecting the `node` binary (v24.15.0). Grype found it via CPE-based matching against the NVD database, identifying the node binary as a CPE package. Trivy likely missed it because its vulnerability matching focuses on OS-level Debian packages and npm language-specific files, and may not have the same CPE mapping for the Node.js binary installed in the image. Different CVE database refresh cadence and CPE matching rules between the two tools explain this divergence.

**2. CVE-2026-23745 (Trivy only, Grype missed)**
This is a node-tar arbitrary file overwrite via symlink poisoning (High severity) affecting `tar@4.4.19`. Trivy found it via the GHSA/npm advisory database. Grype matched the same tar package but reported it under different advisory IDs (GHSA-83g3-92jg-28cx for tar, GHSA-r6q2-hw4h-h46w for tar) with different fix version ranges. The discrepancy stems from different package matching rules: Trivy matched against the npm ecosystem advisory for tar, while Grype used its own vulnerability namespace mapping. The tools agree the package is vulnerable, but they report different CVE identifiers and fix versions.

### When would you pick each?

**Syft+Grype's decoupled model** wins when you need SBOM-as-an-attestation for supply chain compliance. The SBOM is a static inventory artifact that can be signed (Lab 8 with Cosign), stored, and re-scanned over time without re-pulling the image. This is critical for incident response: when a new CVE drops, you re-run Grype on the existing SBOM to instantly know if you're affected — no image rebuild needed. It also separates concerns: Syft generates the inventory, Grype provides the vulnerability intelligence, and each can be updated independently.

**Trivy's all-in-one model** wins for simpler CI/CD pipelines where you want a single tool that covers vulnerabilities, secrets, misconfigurations, and IaC scanning in one pass. Its broader scope (including OS packages, language packages, and configuration issues) makes it ideal for a quick security gate in a pipeline. The tradeoff is tighter coupling — you can't swap the vulnerability DB without changing the tool — but for teams wanting "one command, full coverage," Trivy is the pragmatic choice.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: 1.6
- `bomFormat`: CycloneDX

### Image digest captured
- `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate (first 30 lines of juice-shop-attestation.json)

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.6",
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "...",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-26T09:07:41+03:00",
      "tools": [
        {
          "type": "application",
          "author": "anchore",
          "name": "syft",
          "version": "1.44.0"
        }
      ],
      ...
    },
    "components": [...]
  }
}
```

### What this enables in Lab 8

When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`, it cryptographically signs the SBOM attestation捆绑 with the container image's digest. The signed attestation proves that the CycloneDX SBOM (listing all 3069 components and their versions) was generated for this specific image (`bkimminich/juice-shop:v20.0.0` at `sha256:fd58bdc9...`). This creates a tamper-evident supply chain record: anyone can verify with `cosign verify-attestation` that the SBOM matches the image, and that it was produced by a trusted party. This is the operational implementation of Lecture 8 slide 9's claim that SBOM attestation answers "what's actually in this image?" with a cryptographically verifiable answer rather than just a text file.
