# Certificate revocation and CA intelligence

Phase 2 uses cryptographically validated OCSP and CRL evidence. An unavailable
responder is never converted into `GOOD`; aggregation returns `UNKNOWN` when a
source is unavailable or sources conflict.

## Persistent cache and refresh jobs

Revocation results are stored by certificate/issuer fingerprint in
`certificate_revocation_cache` for `CERTIFICATE_REVOCATION_CACHE_TTL_SECONDS`.
The endpoint below schedules a refresh without blocking the request:

```text
POST /api/scans/{scan_id}/certificate/revocation/refresh
GET  /api/certificate/revocation/jobs/{job_id}
```

The most recent result is available through:

```text
GET /api/scans/{scan_id}/certificate/revocation
```

## CA advisory feed

No CA incident or distrust record is fabricated. Configure an authoritative,
administrator-approved JSON feed using `CA_REPUTATION_FEED_URL`. The feed must
be HTTPS and have this shape:

```json
{
  "records": [
    {
      "fingerprint_sha256": "certificate-sha256",
      "status": "DISTRUSTED",
      "ca_reputation": "COMPROMISED_OR_DISTRUSTED",
      "effective_date": "2025-01-01T00:00:00Z",
      "evidence": ["advisory or authoritative record reference"]
    }
  ]
}
```

`CA_REPUTATION_FEED_TTL_SECONDS` controls persistent feed-result freshness.
`CERTIFICATE_DISTRUST_FINGERPRINTS` is a comma-separated emergency override for
explicitly approved SHA-256 certificate fingerprints. Feed failures and
non-matches remain visible as `UNAVAILABLE`, `UNKNOWN`, or `NO_MATCH`; they are
not treated as clean CA evidence.
