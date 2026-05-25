# vrt1-web-verifier

Browser-based independent verifier for VRT1 attestations. Zero install — paste an attestation and verify client-side.

## What it does

Verifies up to 5 binding layers of a VRT1 attestation:

1. **Schnorr signature** — BIP-340 over tagged hash of canonical payload
2. **Nostr event** — NIP-01 event id + signature binding
3. **Merkle inclusion** — SHA-256d proof against checkpoint root
4. **Checkpoint event** — Nostr kind-30079 with epoch/root/count
5. **Bitcoin anchor** — OP_RETURN payload in raw transaction

## Usage

Visit the deployed page or serve locally:

```
python3 -m http.server 8080
# open http://localhost:8080
```

Paste a signed attestation JSON, optionally with Nostr event, Merkle proof, checkpoint, or raw anchor tx. Click Verify.

## Self-test

On page load, the verifier runs all canonical test vectors from [vrt1-spec](https://github.com/Ifasola34/vrt1-spec). A green banner confirms cross-implementation correctness; red means something broke.

## Tech

- Pure HTML/CSS/JS — no build step
- [noble-secp256k1](https://github.com/paulmillr/noble-secp256k1) via CDN for BIP-340 Schnorr
- `crypto.subtle` for SHA-256
- Deploys as static site on Cloudflare Pages

## License

MIT
