# Test data for WhichPGP

## Official Sample Keys

ASCII-armored PGP public keys taken from official specifications and minimal synthetic keys for testing.

1. `sample-v4-ed25519.asc`
    - Source: Draft IETF OpenPGP Crypto Refresh v6, Appendix A.1. "Sample v4 Ed25519 key".
    - URL: [https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-06.html#name-sample-v4-ed25519-key](https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-06.html#name-sample-v4-ed25519-key)

1. `sample-v4-ed25519-leg.asc`
    - Source: RFC 9580 OpenPGP, Appendix A.1. "Sample Version 4 Ed25519 Legacy Key".
    - URL: [https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-4-ed25519leg](https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-4-ed25519leg)

1. `sample-v5-certificate-trans.asc`
    - Source: Draft IETF OpenPGP Crypto Refresh v6, Appendix A.3. "Sample v5 Certificate (Transferable Public Key)".
    - URL: [https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-06.html#name-sample-v5-certificate-trans](https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-06.html#name-sample-v5-certificate-trans)

1. `sample-v6-certificat.asc`
    - Source: RFC 9580 OpenPGP, Appendix A.3. "Sample Version 6 Certificate (Transferable Public Key)".
    - URL: [https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-certificat](https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-certificat)

This folder contains tiny fixtures used by tests and examples.

## Minimal synthetic keys

The following files are intentionally minimal, synthetic fixtures used for golden tests:

- `openpgp_v6_pub.asc`
- `librepgp_v5_pub.asc`
- `librepgp_v4_pub.asc`

They are not intended for real-world use; they exist solely to exercise parsing and version detection paths.
