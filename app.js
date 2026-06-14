// Cryptography: @noble/curves v1.8.1 (MIT), bundled and vendored locally as
// noble-secp256k1.bundle.mjs — NO runtime third-party fetch. It is loaded with
// error handling at the bottom of this script so a load failure shows a visible
// banner instead of a silently blank page.
import { REAL } from './real-vector.mjs';

let schnorr;

// ─── Utilities ───────────────────────────────────────────────────────────────

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`invalid hex: ${hex.slice(0, 20)}${hex.length > 20 ? '...' : ''}`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

function concatBytes(...arrays) {
  const len = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

async function sha256d(data) {
  return sha256(await sha256(data));
}

async function taggedHash(tag, msg) {
  const tagBytes = new TextEncoder().encode(tag);
  const tagHash = await sha256(tagBytes);
  return sha256(concatBytes(tagHash, tagHash, msg));
}

// ─── Input commitment (reveal-and-verify) ────────────────────────────────────
// Reproduces the Python oracle's normalize_input() exactly so a revealed
// record can be hashed here and matched against the committed input_hash:
//   norm = whitespace-collapse(lowercase(strip(text)))
//   input_hash = SHA256( utf8(norm + salt) )
// salt="" is the bare commitment (what the on-chain genesis used); a non-empty
// per-attestation secret salt closes the low-entropy guessing gap. Parity with
// Python is asserted in runSelfTest() against the real genesis + a salted
// vector. (ASCII / common-whitespace inputs match exactly; .toLowerCase() and
// \s diverge from Python only on exotic Unicode, which these inputs avoid.)
function normalizeInput(text) {
  return text.trim().toLowerCase().replace(/\s+/g, ' ');
}
async function inputHashHex(text, salt = '') {
  const data = new TextEncoder().encode(normalizeInput(text) + salt);
  return bytesToHex(await sha256(data));
}

// ─── Canonical JSON ──────────────────────────────────────────────────────────

function sortKeys(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sortKeys);
  const sorted = {};
  for (const k of Object.keys(obj).sort()) sorted[k] = sortKeys(obj[k]);
  return sorted;
}

function canonicalJson(obj) {
  return new TextEncoder().encode(JSON.stringify(sortKeys(obj)));
}

// ─── Number-literal-preserving canonical JSON ────────────────────────────────
// JSON.parse loses the int/float distinction (0.0 -> 0), so re-serializing a
// parsed attestation diverges from the Python signer for whole-number floats
// (e.g. a neutral score of 0.0). We parse the raw text preserving each number's
// literal, then canonicalize (sorted keys, compact) so the bytes match the
// signer exactly — letting ANY valid attestation verify, floats included.
function parsePreservingNumbers(text) {
  let i = 0;
  const ws = () => { while (i < text.length && /\s/.test(text[i])) i++; };
  function val() {
    ws(); const c = text[i];
    if (c === '{') return obj();
    if (c === '[') return arr();
    if (c === '"') return str();
    if (c === 't') { i += 4; return true; }
    if (c === 'f') { i += 5; return false; }
    if (c === 'n') { i += 4; return null; }
    return num();
  }
  function obj() {
    const o = {}; i++; ws();
    if (text[i] === '}') { i++; return o; }
    for (;;) {
      ws(); const k = str(); ws(); i++; // skip ':'
      o[k] = val(); ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === '}') { i++; break; }
      throw new Error('malformed object');
    }
    return o;
  }
  function arr() {
    const a = []; i++; ws();
    if (text[i] === ']') { i++; return a; }
    for (;;) {
      a.push(val()); ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === ']') { i++; break; }
      throw new Error('malformed array');
    }
    return a;
  }
  function str() {
    let s = ''; i++;
    while (text[i] !== '"') {
      if (text[i] === '\\') { s += text[i] + text[i + 1]; i += 2; }
      else { s += text[i]; i++; }
    }
    i++;
    return JSON.parse('"' + s + '"');
  }
  function num() {
    const st = i;
    while (i < text.length && /[-+0-9.eE]/.test(text[i])) i++;
    return { __num: text.slice(st, i) };
  }
  const r = val(); ws();
  return r;
}

function canonicalSerialize(node) {
  if (node === null || typeof node === 'boolean' || typeof node === 'string') return JSON.stringify(node);
  if (typeof node === 'object' && node.__num !== undefined) return node.__num;
  if (Array.isArray(node)) return '[' + node.map(canonicalSerialize).join(',') + ']';
  return '{' + Object.keys(node).sort().map(k => JSON.stringify(k) + ':' + canonicalSerialize(node[k])).join(',') + '}';
}

// Verify an attestation from its raw signed-attestation TEXT (preserves floats).
async function verifyAttestationFromText(signedText, sigHex, oraclePubkeyHex) {
  const parsed = parsePreservingNumbers(signedText);
  const canonical = new TextEncoder().encode(canonicalSerialize(parsed.attestation));
  const digest = await taggedHash('VRT1/attestation', canonical);
  const valid = await schnorr.verify(hexToBytes(sigHex), digest, hexToBytes(oraclePubkeyHex));
  return { valid, digest: bytesToHex(digest), canonicalHex: bytesToHex(canonical) };
}

// ─── Attestation Verification ────────────────────────────────────────────────

async function verifyAttestation(payload, sigHex, oraclePubkeyHex) {
  const canonical = canonicalJson(payload);
  const digest = await taggedHash('VRT1/attestation', canonical);
  const sig = hexToBytes(sigHex);
  const pubkey = hexToBytes(oraclePubkeyHex);
  const valid = await schnorr.verify(sig, digest, pubkey);
  return { valid, digest: bytesToHex(digest), canonicalHex: bytesToHex(canonical) };
}

// ─── Nostr Event Verification ────────────────────────────────────────────────

async function verifyNostrEvent(event) {
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]);
  const bytes = new TextEncoder().encode(serialized);
  const idBytes = await sha256(bytes);
  const computedId = bytesToHex(idBytes);
  if (computedId !== event.id) return { valid: false, reason: `id mismatch: computed ${computedId}` };
  const sigValid = await schnorr.verify(hexToBytes(event.sig), idBytes, hexToBytes(event.pubkey));
  if (!sigValid) return { valid: false, reason: 'signature invalid' };
  return { valid: true, computedId };
}

// ─── Merkle Proof Verification ───────────────────────────────────────────────

function expectedDepth(n) {
  if (n <= 1) return 0;
  let d = 0, m = n;
  while (m > 1) { m = Math.ceil(m / 2); d++; }
  return d;
}

async function verifyMerkleProof({ leaf, siblings, directions, root, size, index }) {
  if (size <= 0) return { valid: false, reason: 'size <= 0' };
  if (index < 0 || index >= size) return { valid: false, reason: 'index out of range' };
  if (leaf.length !== 32) return { valid: false, reason: 'leaf not 32 bytes' };
  if (siblings.length !== directions.length) return { valid: false, reason: 'siblings/directions length mismatch' };
  if (siblings.length !== expectedDepth(size)) return { valid: false, reason: `depth mismatch: got ${siblings.length}, expected ${expectedDepth(size)}` };

  let cur = await sha256d(concatBytes(new Uint8Array([0x00]), leaf));
  for (let i = 0; i < siblings.length; i++) {
    const sib = siblings[i];
    if (directions[i] === 0) {
      cur = await sha256d(concatBytes(new Uint8Array([0x01]), cur, sib));
    } else if (directions[i] === 1) {
      cur = await sha256d(concatBytes(new Uint8Array([0x01]), sib, cur));
    } else {
      return { valid: false, reason: `invalid direction: ${directions[i]}` };
    }
  }
  const valid = bytesToHex(cur) === bytesToHex(root);
  return { valid, computedRoot: bytesToHex(cur) };
}

// ─── OP_RETURN Parsing ───────────────────────────────────────────────────────

function parseOpReturn(payloadHex) {
  const bytes = hexToBytes(payloadHex);
  if (bytes.length !== 49) return { valid: false, reason: `payload length ${bytes.length} != 49` };
  const tag = String.fromCharCode(...bytes.slice(0, 4));
  if (tag !== 'VRT1') return { valid: false, reason: `unknown tag: ${tag}` };
  const version = bytes[4];
  if (version !== 1) return { valid: false, reason: `unsupported version: ${version}` };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const epochHi = view.getUint32(5);
  const epochLo = view.getUint32(9);
  const epoch = epochHi * 0x100000000 + epochLo;
  const leafCount = view.getUint32(13);
  const merkleRoot = bytes.slice(17, 49);
  return { valid: true, tag, version, epoch, leafCount, merkleRootHex: bytesToHex(merkleRoot) };
}

function extractOpReturnFromTx(rawHex) {
  const bytes = hexToBytes(rawHex);
  if (bytes.length < 10) return null;
  let pos = 4; // skip version (4 bytes LE)
  let segwit = false;
  if (bytes[pos] === 0x00 && bytes[pos + 1] !== 0x00) { segwit = true; pos += 2; }
  const readVarint = () => {
    const first = bytes[pos++];
    if (first < 0xfd) return first;
    if (first === 0xfd) { const v = bytes[pos] | (bytes[pos+1] << 8); pos += 2; return v; }
    if (first === 0xfe) { const v = bytes[pos] | (bytes[pos+1]<<8) | (bytes[pos+2]<<16) | (bytes[pos+3]<<24); pos += 4; return v >>> 0; }
    pos += 8; return Number(BigInt(bytes[pos-8]) | (BigInt(bytes[pos-7])<<8n) | (BigInt(bytes[pos-6])<<16n) | (BigInt(bytes[pos-5])<<24n) | (BigInt(bytes[pos-4])<<32n) | (BigInt(bytes[pos-3])<<40n) | (BigInt(bytes[pos-2])<<48n) | (BigInt(bytes[pos-1])<<56n));
  };
  const inputCount = readVarint();
  for (let i = 0; i < inputCount; i++) {
    pos += 36; // prev_out (32 txid + 4 vout)
    const scriptLen = readVarint();
    pos += scriptLen + 4; // script + sequence
  }
  const outputCount = readVarint();
  for (let i = 0; i < outputCount; i++) {
    pos += 8; // value (8 bytes LE)
    const scriptLen = readVarint();
    const script = bytes.slice(pos, pos + scriptLen);
    pos += scriptLen;
    if (script.length >= 2 && script[0] === 0x6a) {
      let dataStart, dataLen;
      if (script[1] <= 0x4b) { dataLen = script[1]; dataStart = 2; }
      else if (script[1] === 0x4c) { dataLen = script[2]; dataStart = 3; }
      else if (script[1] === 0x4d) { dataLen = script[2] | (script[3] << 8); dataStart = 4; }
      else continue;
      if (dataStart + dataLen <= script.length) {
        const payload = script.slice(dataStart, dataStart + dataLen);
        if (payload.length === 49 && String.fromCharCode(...payload.slice(0, 4)) === 'VRT1') {
          return bytesToHex(payload);
        }
      }
    }
  }
  return null;
}

// ─── Full Verification Pipeline ──────────────────────────────────────────────

async function verifyFull({ signedAttestation, attestationText, nostrEvent, merkleProof, checkpointEvent, anchorRawTxHex }) {
  const result = { ok: true, schnorrOk: null, nostrEventOk: null, merkleOk: null, checkpointOk: null, anchorOk: null, notes: [] };

  // Layer 1: Schnorr. Prefer the raw-text path (preserves number literals like
  // a 0.0 score) when the caller supplies it; fall back to the object path.
  const att = signedAttestation.attestation;
  const attResult = attestationText
    ? await verifyAttestationFromText(attestationText, signedAttestation.sig, att.oracle)
    : await verifyAttestation(att, signedAttestation.sig, att.oracle);
  result.schnorrOk = attResult.valid;
  if (!attResult.valid) { result.ok = false; result.notes.push('Attestation Schnorr signature FAILED'); }

  // Layer 2: Nostr event
  if (nostrEvent) {
    const evResult = await verifyNostrEvent(nostrEvent);
    if (!evResult.valid) { result.nostrEventOk = false; result.notes.push(`Nostr event: ${evResult.reason}`); }
    else if (nostrEvent.pubkey !== att.oracle) { result.nostrEventOk = false; result.notes.push('Nostr event pubkey != attestation oracle'); }
    else { result.nostrEventOk = true; }
    if (result.nostrEventOk === false) result.ok = false;
  }

  // Layer 3: Merkle proof
  if (merkleProof) {
    const expectedLeaf = attResult.digest;
    if (merkleProof.leaf_hex && merkleProof.leaf_hex !== expectedLeaf) {
      result.merkleOk = false;
      result.notes.push(`Merkle leaf != attestation digest`);
    } else {
      const mResult = await verifyMerkleProof({
        leaf: hexToBytes(expectedLeaf),
        siblings: merkleProof.siblings_hex.map(hexToBytes),
        directions: merkleProof.directions,
        root: hexToBytes(merkleProof.root_hex),
        size: merkleProof.size,
        index: merkleProof.index
      });
      result.merkleOk = mResult.valid;
      if (!mResult.valid) result.notes.push(`Merkle proof: ${mResult.reason}`);
    }
    if (result.merkleOk === false) result.ok = false;
  }

  // Layer 4: Checkpoint event
  if (checkpointEvent) {
    if (!merkleProof || result.merkleOk !== true) {
      result.checkpointOk = false;
      result.notes.push('Checkpoint requires a valid Merkle proof');
    } else {
      const cpResult = await verifyNostrEvent(checkpointEvent);
      if (!cpResult.valid) { result.checkpointOk = false; result.notes.push(`Checkpoint event: ${cpResult.reason}`); }
      else if (checkpointEvent.pubkey !== att.oracle) { result.checkpointOk = false; result.notes.push('Checkpoint pubkey != oracle'); }
      else {
        const content = JSON.parse(checkpointEvent.content);
        if (content.epoch !== att.epoch) { result.checkpointOk = false; result.notes.push('Checkpoint epoch mismatch'); }
        else if (content.root !== merkleProof.root_hex) { result.checkpointOk = false; result.notes.push('Checkpoint root != proof root'); }
        else if (content.count !== merkleProof.size) { result.checkpointOk = false; result.notes.push('Checkpoint count != proof size'); }
        else { result.checkpointOk = true; }
      }
    }
    if (result.checkpointOk === false) result.ok = false;
  }

  // Layer 5: Anchor tx
  if (anchorRawTxHex) {
    if (!merkleProof) {
      result.anchorOk = false;
      result.notes.push('Anchor requires a Merkle proof');
    } else {
      const payloadHex = extractOpReturnFromTx(anchorRawTxHex);
      if (!payloadHex) { result.anchorOk = false; result.notes.push('No VRT1 OP_RETURN found in tx'); }
      else {
        const parsed = parseOpReturn(payloadHex);
        if (!parsed.valid) { result.anchorOk = false; result.notes.push(`Anchor: ${parsed.reason}`); }
        else if (parsed.epoch !== att.epoch) { result.anchorOk = false; result.notes.push('Anchor epoch mismatch'); }
        else if (parsed.merkleRootHex !== merkleProof.root_hex) { result.anchorOk = false; result.notes.push('Anchor root != proof root'); }
        else if (parsed.leafCount !== merkleProof.size) { result.anchorOk = false; result.notes.push('Anchor leaf_count != proof size'); }
        else { result.anchorOk = true; }
      }
    }
    if (result.anchorOk === false) result.ok = false;
  }

  return result;
}

// ─── Test Vectors ────────────────────────────────────────────────────────────

const VECTORS = {
  attestation: {
    attestation: {"epoch":7,"input_hash":"abababababababababababababababababababababababababababababababab","model":"veritas.sentiment.keyword.v1","oracle":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","output":{"label":"bullish","score":0.42},"ts":1700000000,"v":1},
    sig: "42dd9019c75df7b978cac9e4bea55c8fa6ef6b1603a0c93c0136c2c2387b3c4bbbbfeac25c351781201a50335eccd4bb30764a85d3f0637b990dce550325a5d5",
    canonical_bytes_hex: "7b2265706f6368223a372c22696e7075745f68617368223a2261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162222c226d6f64656c223a22766572697461732e73656e74696d656e742e6b6579776f72642e7631222c226f7261636c65223a2234663335356264636237636330616637323865663363636562393631356439303638346262356232636135663835396162306630623730343037353837316161222c226f7574707574223a7b226c6162656c223a2262756c6c697368222c2273636f7265223a302e34327d2c227473223a313730303030303030302c2276223a317d",
    digest_hex: "e4b104bf63081162695785b88ce0a947b78a7a7e3cc264004472052f22f2b5d7"
  },
  nostrAttestationEvent: {"content":"eyJhdHRlc3RhdGlvbiI6eyJlcG9jaCI6NywiaW5wdXRfaGFzaCI6ImFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIiLCJtb2RlbCI6InZlcml0YXMuc2VudGltZW50LmtleXdvcmQudjEiLCJvcmFjbGUiOiI0ZjM1NWJkY2I3Y2MwYWY3MjhlZjNjY2ViOTYxNWQ5MDY4NGJiNWIyY2E1Zjg1OWFiMGYwYjcwNDA3NTg3MWFhIiwib3V0cHV0Ijp7ImxhYmVsIjoiYnVsbGlzaCIsInNjb3JlIjowLjQyfSwidHMiOjE3MDAwMDAwMDAsInYiOjF9LCJzaWciOiI0MmRkOTAxOWM3NWRmN2I5NzhjYWM5ZTRiZWE1NWM4ZmE2ZWY2YjE2MDNhMGM5M2MwMTM2YzJjMjM4N2IzYzRiYmJiZmVhYzI1YzM1MTc4MTIwMWE1MDMzNWVjY2Q0YmIzMDc2NGE4NWQzZjA2MzdiOTkwZGNlNTUwMzI1YTVkNSJ9","created_at":1700000000,"id":"0c0904b4feabdb7c2d448401b30ee848222727d5bef0e369f4eb995b193beca2","kind":30078,"pubkey":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","sig":"9d5011dd9d35c48a20a44e804f08ce6756402a584eb43ffbee597b62e0a4415a31aecac636dfa43055ae810edbaf1c59329323a62bc1685eabebb6a998562f1b","tags":[["d","7:0"],["model","veritas.sentiment.keyword.v1"],["v","VRT1.1"],["epoch","7"],["input","abababababababababababababababababababababababababababababababab"]]},
  nostrCheckpointEvent: {"content":"{\"anchor_txid\":\"abababababababababababababababababababababababababababababababab\",\"count\":5,\"epoch\":7,\"root\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\"}","created_at":1700000060,"id":"b75428fe7d815ef3bbd1984feedffebfaab4abdac3c85eb14b749517b138b646","kind":30079,"pubkey":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","sig":"b43f54ec6fb61f6f059d75ba0b93433d55c58f86d5bd8b75f7d68c46c9f657f2b24ad8b5af653d54c9b788cf30ef4d7b05dad46e7c97f6593a3c77588280bb2a","tags":[["d","checkpoint:7"],["v","VRT1.1"],["root","cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"],["anchor","abababababababababababababababababababababababababababababababab"]]},
  opReturn: {
    payload_hex: "5652543101000000000000000700000005cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
    epoch: 7, leaf_count: 5,
    merkle_root_hex: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
  },
  // Reveal-and-verify parity: this salted (content, salt) -> input_hash triple
  // is produced by the Python oracle (tests/test_reveal.py asserts the same
  // values), so a green self-test here proves the browser and the signer agree.
  reveal: {
    content: "approved",
    salt: "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
    salted_hash: "5089006b47fda34d47aedbb75b7cc4cc2ac93b722912557c38ead4422d6bc7d5"
  },
  fullChain: {"signedAttestation":{"attestation":{"epoch":0,"input_hash":"d6cf1f66f2a7c130a3fb02b30c7d1716566ef1373e293a90e253e387b2f1cb5a","model":"veritas.sentiment.keyword.v1","oracle":"b49888ece95ca22c6c0641e9388b01d41f15c471762b047f3453e7eff938ddfb","output":{"label":"bullish","neg_hits":1,"pos_hits":5,"score":0.6667,"token_count":8},"ts":1780305707,"v":1},"sig":"922164e5b843fbd1357b75cef210dcf2bde4e6cc258e52c6f9ef2017861aec499c7fa3c55adda3815b9175124ef1716ae579f000968f8cce449dafb17aaea6bc"},"nostrEvent":{"pubkey":"b49888ece95ca22c6c0641e9388b01d41f15c471762b047f3453e7eff938ddfb","created_at":1780305707,"kind":30078,"tags":[["d","0:0"],["model","veritas.sentiment.keyword.v1"],["v","VRT1.1"],["epoch","0"],["input","d6cf1f66f2a7c130a3fb02b30c7d1716566ef1373e293a90e253e387b2f1cb5a"]],"content":"eyJhdHRlc3RhdGlvbiI6eyJlcG9jaCI6MCwiaW5wdXRfaGFzaCI6ImQ2Y2YxZjY2ZjJhN2MxMzBhM2ZiMDJiMzBjN2QxNzE2NTY2ZWYxMzczZTI5M2E5MGUyNTNlMzg3YjJmMWNiNWEiLCJtb2RlbCI6InZlcml0YXMuc2VudGltZW50LmtleXdvcmQudjEiLCJvcmFjbGUiOiJiNDk4ODhlY2U5NWNhMjJjNmMwNjQxZTkzODhiMDFkNDFmMTVjNDcxNzYyYjA0N2YzNDUzZTdlZmY5MzhkZGZiIiwib3V0cHV0Ijp7ImxhYmVsIjoiYnVsbGlzaCIsIm5lZ19oaXRzIjoxLCJwb3NfaGl0cyI6NSwic2NvcmUiOjAuNjY2NywidG9rZW5fY291bnQiOjh9LCJ0cyI6MTc4MDMwNTcwNywidiI6MX0sInNpZyI6IjkyMjE2NGU1Yjg0M2ZiZDEzNTdiNzVjZWYyMTBkY2YyYmRlNGU2Y2MyNThlNTJjNmY5ZWYyMDE3ODYxYWVjNDk5YzdmYTNjNTVhZGRhMzgxNWI5MTc1MTI0ZWYxNzE2YWU1NzlmMDAwOTY4ZjhjY2U0NDlkYWZiMTdhYWVhNmJjIn0=","id":"6e3c22e44a241ed2619e9ca20a0332edee461f4064fc843965c9ae56cd033fea","sig":"ad76e85b67d7480ca5db02656005842afb61257d50a8fe76aa1a89f92e5a5b41f014268e9737c41e0dc96e0a9537e236a101022700c6a620b8a7753e776a9451"},"merkleProof":{"leaf_hex":"4136233aa4162d1c5366d1fd82191c959f5a72e8593f2f936327692db62e3e39","siblings_hex":[],"directions":[],"root_hex":"9923549d8bbc16fda8e9b583b0be9e8bf2ee1bbd35a78215d30e815d3d24318d","size":1,"index":0},"checkpointEvent":{"pubkey":"b49888ece95ca22c6c0641e9388b01d41f15c471762b047f3453e7eff938ddfb","created_at":1780305707,"kind":30079,"tags":[["d","checkpoint:0"],["v","VRT1.1"],["root","9923549d8bbc16fda8e9b583b0be9e8bf2ee1bbd35a78215d30e815d3d24318d"],["anchor","69501d1dd218aeb5024e6f1c1d659df4877dd2477a17b1cf0078b30d65dc596f"]],"content":"{\"anchor_txid\":\"69501d1dd218aeb5024e6f1c1d659df4877dd2477a17b1cf0078b30d65dc596f\",\"count\":1,\"epoch\":0,\"root\":\"9923549d8bbc16fda8e9b583b0be9e8bf2ee1bbd35a78215d30e815d3d24318d\"}","id":"8f27799ebe84a86503fcf4abecd0a19c1b63ae40c0540b932a595d82853cf73d","sig":"0a8b97a985b62f6cefb2d6ed10d80e3dff22c51f54565215f993386047e2a6788921b9ba9af410c84b457842209908b9ed232b03db1ee10da313d5bbff9c4c6e"}},
  merkle: {"1":{"leaves_hex":["df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"],"root_hex":"7b31761fed08f425cee7654ab202310c05fc2d63a88199c803e1751d43cbff4c","size":1,"proofs":[{"index":0,"leaf_hex":"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","siblings_hex":[],"directions":[]}]},"2":{"leaves_hex":["df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d"],"root_hex":"d8edbd842b6648ec1c73facd9cf8c9071c535da8677bad4fe4cedb721f272542","size":2,"proofs":[{"index":0,"leaf_hex":"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","siblings_hex":["b21f7661530e31a2746ad6f338d7cf1397af439c15319baf9d4bd70eaf9faea3"],"directions":[0]},{"index":1,"leaf_hex":"b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d","siblings_hex":["7b31761fed08f425cee7654ab202310c05fc2d63a88199c803e1751d43cbff4c"],"directions":[1]}]},"3":{"leaves_hex":["df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d","433ebf5bc03dffa38536673207a21281612cef5faa9bc7a4d5b9be2fdb12cf1a"],"root_hex":"25a6f214c54178f9e2d4a5f9d9cfc49c92d5a5155cab1d1ed7c75c22a25ba444","size":3,"proofs":[{"index":0,"leaf_hex":"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","siblings_hex":["b21f7661530e31a2746ad6f338d7cf1397af439c15319baf9d4bd70eaf9faea3","a356f1ac61cd76b49aba7eb0716a40011093608a16091b5445045ebec9e25acf"],"directions":[0,0]},{"index":1,"leaf_hex":"b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d","siblings_hex":["7b31761fed08f425cee7654ab202310c05fc2d63a88199c803e1751d43cbff4c","a356f1ac61cd76b49aba7eb0716a40011093608a16091b5445045ebec9e25acf"],"directions":[1,0]},{"index":2,"leaf_hex":"433ebf5bc03dffa38536673207a21281612cef5faa9bc7a4d5b9be2fdb12cf1a","siblings_hex":["9a603b3cef54685788855553fc5d7377fd93713e870a754248d93830177e2566","d8edbd842b6648ec1c73facd9cf8c9071c535da8677bad4fe4cedb721f272542"],"directions":[0,1]}]},"4":{"leaves_hex":["df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d","433ebf5bc03dffa38536673207a21281612cef5faa9bc7a4d5b9be2fdb12cf1a","88185d128d9922e0e6bcd32b07b6c7f20f27968eab447a1d8d1cdf250f79f7d3"],"root_hex":"362d16d1ac54ff5b3d34415544965662dbea8c4fb7ac9c0ba72ec05d2f390a06","size":4,"proofs":[{"index":0,"leaf_hex":"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","siblings_hex":["b21f7661530e31a2746ad6f338d7cf1397af439c15319baf9d4bd70eaf9faea3","2a7325a68ef7110c878f74c3f974bc75da91da28420b0d0ee820fc5df58967bb"],"directions":[0,0]},{"index":1,"leaf_hex":"b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d","siblings_hex":["7b31761fed08f425cee7654ab202310c05fc2d63a88199c803e1751d43cbff4c","2a7325a68ef7110c878f74c3f974bc75da91da28420b0d0ee820fc5df58967bb"],"directions":[1,0]},{"index":2,"leaf_hex":"433ebf5bc03dffa38536673207a21281612cef5faa9bc7a4d5b9be2fdb12cf1a","siblings_hex":["26d89eb54048a281a4ca9091a3dd947d9cf30cccdce8c4f781ae966442ad89f8","d8edbd842b6648ec1c73facd9cf8c9071c535da8677bad4fe4cedb721f272542"],"directions":[0,1]},{"index":3,"leaf_hex":"88185d128d9922e0e6bcd32b07b6c7f20f27968eab447a1d8d1cdf250f79f7d3","siblings_hex":["9a603b3cef54685788855553fc5d7377fd93713e870a754248d93830177e2566","d8edbd842b6648ec1c73facd9cf8c9071c535da8677bad4fe4cedb721f272542"],"directions":[1,1]}]},"5":{"leaves_hex":["df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d","433ebf5bc03dffa38536673207a21281612cef5faa9bc7a4d5b9be2fdb12cf1a","88185d128d9922e0e6bcd32b07b6c7f20f27968eab447a1d8d1cdf250f79f7d3","1bc5d0e3df0ea12c4d0078668d14924f95106bbe173e196de50fe13a900b0937"],"root_hex":"0a43a456e88501a76c7cb37eb988d371f37200b197d2fa3921532469d9894dbd","size":5,"proofs":[{"index":0,"leaf_hex":"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","siblings_hex":["b21f7661530e31a2746ad6f338d7cf1397af439c15319baf9d4bd70eaf9faea3","2a7325a68ef7110c878f74c3f974bc75da91da28420b0d0ee820fc5df58967bb","e1109607046bdf86d52c0229733766abb8ca1269d7f381c285132c49bd082d2a"],"directions":[0,0,0]},{"index":1,"leaf_hex":"b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d","siblings_hex":["7b31761fed08f425cee7654ab202310c05fc2d63a88199c803e1751d43cbff4c","2a7325a68ef7110c878f74c3f974bc75da91da28420b0d0ee820fc5df58967bb","e1109607046bdf86d52c0229733766abb8ca1269d7f381c285132c49bd082d2a"],"directions":[1,0,0]},{"index":2,"leaf_hex":"433ebf5bc03dffa38536673207a21281612cef5faa9bc7a4d5b9be2fdb12cf1a","siblings_hex":["26d89eb54048a281a4ca9091a3dd947d9cf30cccdce8c4f781ae966442ad89f8","d8edbd842b6648ec1c73facd9cf8c9071c535da8677bad4fe4cedb721f272542","e1109607046bdf86d52c0229733766abb8ca1269d7f381c285132c49bd082d2a"],"directions":[0,1,0]},{"index":3,"leaf_hex":"88185d128d9922e0e6bcd32b07b6c7f20f27968eab447a1d8d1cdf250f79f7d3","siblings_hex":["9a603b3cef54685788855553fc5d7377fd93713e870a754248d93830177e2566","d8edbd842b6648ec1c73facd9cf8c9071c535da8677bad4fe4cedb721f272542","e1109607046bdf86d52c0229733766abb8ca1269d7f381c285132c49bd082d2a"],"directions":[1,1,0]},{"index":4,"leaf_hex":"1bc5d0e3df0ea12c4d0078668d14924f95106bbe173e196de50fe13a900b0937","siblings_hex":["7e1dc632195d5cbe210fe36ddd562ae5d0bd6c8a3296737f565baea92191bbf9","ced3cc912785dd4a88edefbf133b0759e83d633e378497b52cc2987deb205d60","362d16d1ac54ff5b3d34415544965662dbea8c4fb7ac9c0ba72ec05d2f390a06"],"directions":[0,0,1]}]},"7":{"leaves_hex":["df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d","433ebf5bc03dffa38536673207a21281612cef5faa9bc7a4d5b9be2fdb12cf1a","88185d128d9922e0e6bcd32b07b6c7f20f27968eab447a1d8d1cdf250f79f7d3","1bc5d0e3df0ea12c4d0078668d14924f95106bbe173e196de50fe13a900b0937","221f8af2372a95064f2ef7d7712216a9ab46e7ef98482fd237e106f83eaa7569","b253668f6b59f1ff28522831931e4d3c5a3de533965af22e961735437c0172cb"],"root_hex":"784668408010eb34562e133347eac57bdd0a16f076040685b2a96e74716655d9","size":7,"proofs":[{"index":0,"leaf_hex":"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","siblings_hex":["b21f7661530e31a2746ad6f338d7cf1397af439c15319baf9d4bd70eaf9faea3","2a7325a68ef7110c878f74c3f974bc75da91da28420b0d0ee820fc5df58967bb","94c3c1413e08489a4d9a40d3679fc7220010bc7aadd47cf2b758cad5149857c4"],"directions":[0,0,0]},{"index":1,"leaf_hex":"b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d","siblings_hex":["7b31761fed08f425cee7654ab202310c05fc2d63a88199c803e1751d43cbff4c","2a7325a68ef7110c878f74c3f974bc75da91da28420b0d0ee820fc5df58967bb","94c3c1413e08489a4d9a40d3679fc7220010bc7aadd47cf2b758cad5149857c4"],"directions":[1,0,0]},{"index":2,"leaf_hex":"433ebf5bc03dffa38536673207a21281612cef5faa9bc7a4d5b9be2fdb12cf1a","siblings_hex":["26d89eb54048a281a4ca9091a3dd947d9cf30cccdce8c4f781ae966442ad89f8","d8edbd842b6648ec1c73facd9cf8c9071c535da8677bad4fe4cedb721f272542","94c3c1413e08489a4d9a40d3679fc7220010bc7aadd47cf2b758cad5149857c4"],"directions":[0,1,0]},{"index":3,"leaf_hex":"88185d128d9922e0e6bcd32b07b6c7f20f27968eab447a1d8d1cdf250f79f7d3","siblings_hex":["9a603b3cef54685788855553fc5d7377fd93713e870a754248d93830177e2566","d8edbd842b6648ec1c73facd9cf8c9071c535da8677bad4fe4cedb721f272542","94c3c1413e08489a4d9a40d3679fc7220010bc7aadd47cf2b758cad5149857c4"],"directions":[1,1,0]},{"index":4,"leaf_hex":"1bc5d0e3df0ea12c4d0078668d14924f95106bbe173e196de50fe13a900b0937","siblings_hex":["96c6f5c62951a8c346d99654d9f077cc75aa1fcc76ad46b74b326b7e442d3df9","cd840e4d4c3793ccc0144169c7c376bc9a6e3bd6c65aa6ad20d48a722b726c0f","362d16d1ac54ff5b3d34415544965662dbea8c4fb7ac9c0ba72ec05d2f390a06"],"directions":[0,0,1]},{"index":5,"leaf_hex":"221f8af2372a95064f2ef7d7712216a9ab46e7ef98482fd237e106f83eaa7569","siblings_hex":["7e1dc632195d5cbe210fe36ddd562ae5d0bd6c8a3296737f565baea92191bbf9","cd840e4d4c3793ccc0144169c7c376bc9a6e3bd6c65aa6ad20d48a722b726c0f","362d16d1ac54ff5b3d34415544965662dbea8c4fb7ac9c0ba72ec05d2f390a06"],"directions":[1,0,1]},{"index":6,"leaf_hex":"b253668f6b59f1ff28522831931e4d3c5a3de533965af22e961735437c0172cb","siblings_hex":["189994f100193baa09544c33a3a61cd652d582884e2ca3cc829a8ec5d2dbe73e","8012c28e463b28a4b97d3ef749a3a14d88fa025c9483741c7aa8840ba20fc0ea","362d16d1ac54ff5b3d34415544965662dbea8c4fb7ac9c0ba72ec05d2f390a06"],"directions":[0,1,1]}]},"8":{"leaves_hex":["df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d","433ebf5bc03dffa38536673207a21281612cef5faa9bc7a4d5b9be2fdb12cf1a","88185d128d9922e0e6bcd32b07b6c7f20f27968eab447a1d8d1cdf250f79f7d3","1bc5d0e3df0ea12c4d0078668d14924f95106bbe173e196de50fe13a900b0937","221f8af2372a95064f2ef7d7712216a9ab46e7ef98482fd237e106f83eaa7569","b253668f6b59f1ff28522831931e4d3c5a3de533965af22e961735437c0172cb","1561ade0621c5acf44b780521f95a1e0b19b4e5032945b860c4032fc28a3a23b"],"root_hex":"9bdcd25ecd7b1a7b57391b0310599dc35df54aced423de90a47935405d00b730","size":8,"proofs":[{"index":0,"leaf_hex":"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119","siblings_hex":["b21f7661530e31a2746ad6f338d7cf1397af439c15319baf9d4bd70eaf9faea3","2a7325a68ef7110c878f74c3f974bc75da91da28420b0d0ee820fc5df58967bb","6069c0642abb3686824b78551cb5a7b6c5fa1b42c5fea5b3fb97fafc190372d6"],"directions":[0,0,0]},{"index":1,"leaf_hex":"b40711a88c7039756fb8a73827eabe2c0fe5a0346ca7e0a104adc0fc764f528d","siblings_hex":["7b31761fed08f425cee7654ab202310c05fc2d63a88199c803e1751d43cbff4c","2a7325a68ef7110c878f74c3f974bc75da91da28420b0d0ee820fc5df58967bb","6069c0642abb3686824b78551cb5a7b6c5fa1b42c5fea5b3fb97fafc190372d6"],"directions":[1,0,0]},{"index":2,"leaf_hex":"433ebf5bc03dffa38536673207a21281612cef5faa9bc7a4d5b9be2fdb12cf1a","siblings_hex":["26d89eb54048a281a4ca9091a3dd947d9cf30cccdce8c4f781ae966442ad89f8","d8edbd842b6648ec1c73facd9cf8c9071c535da8677bad4fe4cedb721f272542","6069c0642abb3686824b78551cb5a7b6c5fa1b42c5fea5b3fb97fafc190372d6"],"directions":[0,1,0]},{"index":3,"leaf_hex":"88185d128d9922e0e6bcd32b07b6c7f20f27968eab447a1d8d1cdf250f79f7d3","siblings_hex":["9a603b3cef54685788855553fc5d7377fd93713e870a754248d93830177e2566","d8edbd842b6648ec1c73facd9cf8c9071c535da8677bad4fe4cedb721f272542","6069c0642abb3686824b78551cb5a7b6c5fa1b42c5fea5b3fb97fafc190372d6"],"directions":[1,1,0]},{"index":4,"leaf_hex":"1bc5d0e3df0ea12c4d0078668d14924f95106bbe173e196de50fe13a900b0937","siblings_hex":["96c6f5c62951a8c346d99654d9f077cc75aa1fcc76ad46b74b326b7e442d3df9","4b3211dc187edafa87256466e3df2ddf05da5c97a1b09934ef68a818154c5907","362d16d1ac54ff5b3d34415544965662dbea8c4fb7ac9c0ba72ec05d2f390a06"],"directions":[0,0,1]},{"index":5,"leaf_hex":"221f8af2372a95064f2ef7d7712216a9ab46e7ef98482fd237e106f83eaa7569","siblings_hex":["7e1dc632195d5cbe210fe36ddd562ae5d0bd6c8a3296737f565baea92191bbf9","4b3211dc187edafa87256466e3df2ddf05da5c97a1b09934ef68a818154c5907","362d16d1ac54ff5b3d34415544965662dbea8c4fb7ac9c0ba72ec05d2f390a06"],"directions":[1,0,1]},{"index":6,"leaf_hex":"b253668f6b59f1ff28522831931e4d3c5a3de533965af22e961735437c0172cb","siblings_hex":["ba05f2e66a17b5943c2bda11ded24a8d85e363a6931cda884ac5b014ba2be303","8012c28e463b28a4b97d3ef749a3a14d88fa025c9483741c7aa8840ba20fc0ea","362d16d1ac54ff5b3d34415544965662dbea8c4fb7ac9c0ba72ec05d2f390a06"],"directions":[0,1,1]},{"index":7,"leaf_hex":"1561ade0621c5acf44b780521f95a1e0b19b4e5032945b860c4032fc28a3a23b","siblings_hex":["189994f100193baa09544c33a3a61cd652d582884e2ca3cc829a8ec5d2dbe73e","8012c28e463b28a4b97d3ef749a3a14d88fa025c9483741c7aa8840ba20fc0ea","362d16d1ac54ff5b3d34415544965662dbea8c4fb7ac9c0ba72ec05d2f390a06"],"directions":[1,1,1]}]}}
};

// ─── Self-Test ───────────────────────────────────────────────────────────────

async function runSelfTest() {
  const failures = [];
  let totalTests = 0;

  // 1. Canonical JSON + tagged hash
  totalTests++;
  const canonical = canonicalJson(VECTORS.attestation.attestation);
  const canonicalHex = bytesToHex(canonical);
  if (canonicalHex !== VECTORS.attestation.canonical_bytes_hex) {
    failures.push(`canonical JSON mismatch`);
  }

  totalTests++;
  const digest = await taggedHash('VRT1/attestation', canonical);
  if (bytesToHex(digest) !== VECTORS.attestation.digest_hex) {
    failures.push(`tagged hash mismatch`);
  }

  // 2. Attestation Schnorr
  totalTests++;
  const attResult = await verifyAttestation(VECTORS.attestation.attestation, VECTORS.attestation.sig, VECTORS.attestation.attestation.oracle);
  if (!attResult.valid) failures.push('attestation Schnorr failed');

  // 3. Nostr attestation event
  totalTests++;
  const nostrResult = await verifyNostrEvent(VECTORS.nostrAttestationEvent);
  if (!nostrResult.valid) failures.push(`nostr attestation event: ${nostrResult.reason}`);

  // 4. Nostr checkpoint event
  totalTests++;
  const cpResult = await verifyNostrEvent(VECTORS.nostrCheckpointEvent);
  if (!cpResult.valid) failures.push(`nostr checkpoint event: ${cpResult.reason}`);

  // 5. Merkle proofs (all trees)
  for (const [treeSize, tree] of Object.entries(VECTORS.merkle)) {
    for (const proof of tree.proofs) {
      totalTests++;
      const mResult = await verifyMerkleProof({
        leaf: hexToBytes(proof.leaf_hex),
        siblings: proof.siblings_hex.map(hexToBytes),
        directions: proof.directions,
        root: hexToBytes(tree.root_hex),
        size: tree.size,
        index: proof.index
      });
      if (!mResult.valid) failures.push(`merkle tree=${treeSize} idx=${proof.index}: ${mResult.reason}`);
    }
  }

  // 6. OP_RETURN roundtrip
  totalTests++;
  const opResult = parseOpReturn(VECTORS.opReturn.payload_hex);
  if (!opResult.valid) failures.push(`OP_RETURN parse: ${opResult.reason}`);
  else {
    if (opResult.epoch !== VECTORS.opReturn.epoch) failures.push('OP_RETURN epoch mismatch');
    if (opResult.leafCount !== VECTORS.opReturn.leaf_count) failures.push('OP_RETURN leaf_count mismatch');
    if (opResult.merkleRootHex !== VECTORS.opReturn.merkle_root_hex) failures.push('OP_RETURN root mismatch');
  }

  // 7. Negative Schnorr — detects a compromised schnorr.verify that always returns true
  totalTests++;
  const tamperedAtt = { ...VECTORS.attestation.attestation, epoch: 999 };
  const negResult = await verifyAttestation(tamperedAtt, VECTORS.attestation.sig, tamperedAtt.oracle);
  if (negResult.valid) failures.push('negative Schnorr test: tampered attestation should FAIL');

  // 8. hexToBytes rejects invalid hex
  totalTests++;
  try { hexToBytes('zz'); failures.push('hexToBytes accepted invalid hex'); } catch (e) { /* expected */ }

  // Helper: flip the first hex nibble so a value is provably corrupted but stays valid hex.
  const flip = (hex) => (hex[0] === '0' ? '1' : '0') + hex.slice(1);

  // 9. Negative Schnorr — a corrupted signature must FAIL (proves the sig bytes are checked)
  totalTests++;
  const badSigResult = await verifyAttestation(
    VECTORS.attestation.attestation, flip(VECTORS.attestation.sig), VECTORS.attestation.attestation.oracle);
  if (badSigResult.valid) failures.push('negative test: corrupted signature should FAIL');

  // 10. Negative Schnorr — verifying against the wrong (but valid) pubkey must FAIL
  totalTests++;
  const wrongPubkey = VECTORS.fullChain.signedAttestation.attestation.oracle; // a real key, not this signer
  const wrongKeyResult = await verifyAttestation(
    VECTORS.attestation.attestation, VECTORS.attestation.sig, wrongPubkey);
  if (wrongKeyResult.valid) failures.push('negative test: wrong oracle pubkey should FAIL');

  // 11. Negative Merkle — a tampered sibling must break the proof (proves the path is walked)
  totalTests++;
  const goodProof = VECTORS.merkle['4'].proofs[0];
  const sibs = goodProof.siblings_hex.map(hexToBytes);
  sibs[0] = hexToBytes(flip(goodProof.siblings_hex[0]));
  const tamperedMerkle = await verifyMerkleProof({
    leaf: hexToBytes(goodProof.leaf_hex),
    siblings: sibs,
    directions: goodProof.directions,
    root: hexToBytes(VECTORS.merkle['4'].root_hex),
    size: VECTORS.merkle['4'].size,
    index: goodProof.index
  });
  if (tamperedMerkle.valid) failures.push('negative test: tampered Merkle sibling should FAIL');

  // 12. Reveal parity — the REAL on-chain genesis plaintext must hash to the
  // input_hash inside its anchored attestation (proves our normalize+hash
  // reproduces the Python signer for the real, Bitcoin-stamped record).
  totalTests++;
  const genHash = await inputHashHex(REAL.inputText);
  if (genHash !== REAL.signedAttestation.attestation.input_hash) {
    failures.push('reveal parity: genesis plaintext does not reproduce on-chain input_hash');
  }

  // 13. Reveal parity — a SALTED commitment matches the Python-produced vector.
  totalTests++;
  const saltedHash = await inputHashHex(VECTORS.reveal.content, VECTORS.reveal.salt);
  if (saltedHash !== VECTORS.reveal.salted_hash) {
    failures.push('reveal parity: salted commitment mismatch vs Python vector');
  }

  // 14. Negative reveal — the wrong salt must NOT reproduce the commitment.
  totalTests++;
  const wrongSalt = await inputHashHex(VECTORS.reveal.content, flip(VECTORS.reveal.salt));
  if (wrongSalt === VECTORS.reveal.salted_hash) {
    failures.push('negative reveal: wrong salt should not match the commitment');
  }

  const banner = document.getElementById('self-test-banner');
  if (failures.length === 0) {
    banner.className = 'pass';
    banner.textContent = `Self-test PASSED: ${totalTests} tests across all vectors`;
  } else {
    banner.className = 'fail';
    banner.textContent = `Self-test FAILED (${failures.length}/${totalTests}): ${failures.join('; ')}`;
  }
}

// ─── UI Logic ────────────────────────────────────────────────────────────────

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function showResults(result, attestation) {
  const container = document.getElementById('results');
  const tbody = document.getElementById('result-body');
  const notes = document.getElementById('notes');
  const details = document.getElementById('details-content');

  const icon = (val) => {
    if (val === true) return '<span class="pass-icon">PASS</span>';
    if (val === false) return '<span class="fail-icon">FAIL</span>';
    return '<span class="skip-icon">SKIP</span>';
  };

  tbody.innerHTML = `
    <tr><td>Schnorr Signature</td><td>${icon(result.schnorrOk)}</td><td>BIP-340 over tagged hash</td></tr>
    <tr><td>Nostr Event</td><td>${icon(result.nostrEventOk)}</td><td>NIP-01 id + sig + pubkey binding</td></tr>
    <tr><td>Merkle Inclusion</td><td>${icon(result.merkleOk)}</td><td>SHA-256d proof against root</td></tr>
    <tr><td>Checkpoint</td><td>${icon(result.checkpointOk)}</td><td>Epoch + root + count binding</td></tr>
    <tr><td>Anchor TX</td><td>${icon(result.anchorOk)}</td><td>Bitcoin OP_RETURN payload</td></tr>
    <tr class="row-total"><td><strong>Overall</strong></td><td><strong>${icon(result.ok)}</strong></td><td></td></tr>
  `;

  notes.innerHTML = result.notes.map(n => `<li>${esc(n)}</li>`).join('');

  if (attestation) {
    details.textContent = JSON.stringify(attestation, null, 2);
  }

  container.classList.add('visible');
}

const handleVerify = async function() {
  const btn = document.getElementById('verify-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Verifying...';

  try {
    const attText = document.getElementById('input-attestation').value.trim();
    if (!attText) { alert('Signed attestation is required'); return; }
    const signedAttestation = JSON.parse(attText);

    const nostrText = document.getElementById('input-nostr').value.trim();
    const nostrEvent = nostrText ? JSON.parse(nostrText) : undefined;

    const merkleText = document.getElementById('input-merkle').value.trim();
    const merkleProof = merkleText ? JSON.parse(merkleText) : undefined;

    const cpText = document.getElementById('input-checkpoint').value.trim();
    const checkpointEvent = cpText ? JSON.parse(cpText) : undefined;

    const anchorText = document.getElementById('input-anchor').value.trim();
    const anchorRawTxHex = anchorText || undefined;

    const result = await verifyFull({ signedAttestation, attestationText: attText, nostrEvent, merkleProof, checkpointEvent, anchorRawTxHex });
    showResults(result, signedAttestation.attestation);
  } catch (e) {
    alert(`Error: ${e.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify';
  }
};

const runDemo = async function(mode) {
  const signed = { attestation: VECTORS.attestation.attestation, sig: VECTORS.attestation.sig };

  if (mode === 'attestation') {
    const result = await verifyFull({ signedAttestation: signed });
    showResults(result, signed.attestation);
  } else if (mode === 'attestation+nostr') {
    const result = await verifyFull({ signedAttestation: signed, nostrEvent: VECTORS.nostrAttestationEvent });
    showResults(result, signed.attestation);
  } else if (mode === 'attestation+merkle') {
    // Standalone Merkle proof verification (uses test vector leaf, not attestation digest)
    const tree = VECTORS.merkle['4'];
    const proof = tree.proofs[0];
    const mResult = await verifyMerkleProof({
      leaf: hexToBytes(proof.leaf_hex),
      siblings: proof.siblings_hex.map(hexToBytes),
      directions: proof.directions,
      root: hexToBytes(tree.root_hex),
      size: tree.size,
      index: proof.index
    });
    const result = { ok: mResult.valid, schnorrOk: null, nostrEventOk: null, merkleOk: mResult.valid, checkpointOk: null, anchorOk: null, notes: [] };
    if (!mResult.valid) result.notes.push(`Merkle: ${mResult.reason}`);
    else result.notes.push('Standalone Merkle proof (tree size 4, index 0)');
    // Also verify attestation sig
    const attResult = await verifyAttestation(signed.attestation, signed.sig, signed.attestation.oracle);
    result.schnorrOk = attResult.valid;
    result.ok = result.ok && attResult.valid;
    showResults(result, signed.attestation);
  } else if (mode === 'full') {
    const fc = VECTORS.fullChain;
    const result = await verifyFull({
      signedAttestation: fc.signedAttestation,
      nostrEvent: fc.nostrEvent,
      merkleProof: fc.merkleProof,
      checkpointEvent: fc.checkpointEvent
    });
    showResults(result, fc.signedAttestation.attestation);
  } else if (mode === 'real') {
    const result = await verifyFull({
      signedAttestation: REAL.signedAttestation,
      attestationText: REAL.signedAttestationText,
      nostrEvent: REAL.nostrEvent,
      merkleProof: REAL.merkleProof,
      checkpointEvent: REAL.checkpointEvent,
      anchorRawTxHex: REAL.anchorRawTxHex
    });
    showResults(result, REAL.signedAttestation.attestation);
  } else if (mode === 'invalid-sig') {
    const tampered = { ...VECTORS.attestation.attestation, epoch: 999 };
    const result = await verifyFull({ signedAttestation: { attestation: tampered, sig: VECTORS.attestation.sig } });
    showResults(result, tampered);
  }
};

const toggleDetails = function() {
  document.getElementById('details-content').classList.toggle('open');
};

// Sample attestation (kept in sync with the test vector) for the one-click demo + paste box.
// The real, on-chain attestation as raw text (preserves "score":0.0 so it verifies).
const SAMPLE_ATTESTATION = REAL.signedAttestationText;
const runHeroDemo = function() {
  document.getElementById('verifier').scrollIntoView({ behavior: 'smooth' });
  runDemo('real');
};
const loadSample = function() {
  const tab = document.querySelector('.tab[data-panel="paste"]');
  if (tab) tab.click();
  document.getElementById('input-attestation').value = SAMPLE_ATTESTATION;
  document.getElementById('input-nostr').value = JSON.stringify(REAL.nostrEvent);
  document.getElementById('input-merkle').value = JSON.stringify(REAL.merkleProof);
  document.getElementById('input-checkpoint').value = JSON.stringify(REAL.checkpointEvent);
  document.getElementById('input-anchor').value = REAL.anchorRawTxHex;
  document.getElementById('verifier').scrollIntoView({ behavior: 'smooth' });
};

// ─── Reveal & verify the original record (commit-and-reveal) ──
// Prefill the real, on-chain genesis as the public worked example (it is
// unsalted on purpose — its plaintext is public, so anyone can recompute it).
const loadRevealGenesis = function() {
  document.getElementById('reveal-content').value = REAL.inputText;
  document.getElementById('reveal-salt').value = '';
  document.getElementById('reveal-target').value = REAL.signedAttestation.attestation.input_hash;
  const box = document.getElementById('reveal-result');
  if (box) box.hidden = true;
  document.getElementById('reveal').scrollIntoView({ behavior: 'smooth' });
};

const handleReveal = async function() {
  const content = document.getElementById('reveal-content').value;
  const salt = document.getElementById('reveal-salt').value.trim();
  let target = document.getElementById('reveal-target').value.trim().toLowerCase();
  const box = document.getElementById('reveal-result');

  // If the fingerprint field is empty, lift it from a signed attestation
  // pasted into the verifier box above — so "load sample, then reveal" works.
  if (!target) {
    const attText = document.getElementById('input-attestation').value.trim();
    if (attText) {
      try { target = String(JSON.parse(attText)?.attestation?.input_hash || '').toLowerCase(); } catch (e) { /* ignore */ }
    }
  }

  // CSP-safe DOM builders (no innerHTML with user-supplied content).
  const p = (txt, cls) => { const el = document.createElement('p'); if (cls) el.className = cls; el.textContent = txt; return el; };
  const codeLine = (label, val) => {
    const el = document.createElement('p'); el.className = 'reveal-hash';
    const s = document.createElement('span'); s.textContent = label + ' ';
    const c = document.createElement('code'); c.textContent = val;
    el.append(s, c); return el;
  };
  const render = (kind, nodes) => { box.hidden = false; box.className = 'reveal-result ' + kind; box.replaceChildren(...nodes); };

  if (!content.trim()) { render('mismatch', [p('Paste the original record first.')]); return; }
  if (!/^[0-9a-f]{64}$/.test(target)) {
    render('mismatch', [p('Provide the committed fingerprint (the 64-character input_hash from the signed attestation), or click “Load the real genesis example”.')]);
    return;
  }

  const computed = await inputHashHex(content, salt);
  if (computed === target) {
    const nodes = [
      p('✓ MATCH — this exact record is what was committed.', 'reveal-headline'),
      codeLine('fingerprint', computed),
    ];
    if (target === REAL.signedAttestation.attestation.input_hash) {
      const note = document.createElement('p');
      note.append(document.createTextNode('That fingerprint sits inside the genesis attestation anchored to Bitcoin on 13 Jun 2026 — '));
      const a = document.createElement('a');
      a.href = `https://mempool.space/tx/${REAL.txid}`; a.target = '_blank'; a.rel = 'noopener';
      a.textContent = 'see the transaction';
      note.append(a, document.createTextNode('. Verify the full receipt chain above.'));
      nodes.push(note);
    } else if (salt) {
      nodes.push(p('Verified against a salted (private) commitment using the secret salt you supplied.'));
    }
    render('match', nodes);
  } else {
    render('mismatch', [
      p('✗ NO MATCH — this record (or salt) is not what was committed.', 'reveal-headline'),
      codeLine('you provided', computed),
      codeLine('committed   ', target),
      p(salt
        ? 'Check the record text and the secret salt — a single changed character breaks the match.'
        : 'Check the record text. If the receipt was private (salted), you also need its secret salt.'),
    ]);
  }
};

// Tabs
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.panel).classList.add('active');
  });
});

// Load the vendored crypto library, then run the self-test — with error handling
// so any failure shows a red banner rather than a silently blank page.
(async () => {
  const banner = document.getElementById('self-test-banner');
  try {
    ({ schnorr } = await import('./noble-secp256k1.bundle.mjs'));
  } catch (e) {
    banner.className = 'fail';
    banner.textContent = `Could not load the cryptography library (${e.message}). Verification is unavailable — please reload.`;
    return;
  }
  try {
    await runSelfTest();
  } catch (e) {
    banner.className = 'fail';
    banner.textContent = `Self-test crashed: ${e.message}`;
  }
})();

// ─── Event wiring (replaces inline onclick= so the CSP needs no 'unsafe-inline') ──
document.querySelectorAll('[data-action]').forEach((el) => {
  el.addEventListener('click', () => {
    switch (el.dataset.action) {
      case 'hero-demo': runHeroDemo(); break;
      case 'load-sample': loadSample(); break;
      case 'verify': handleVerify(); break;
      case 'demo': runDemo(el.dataset.mode); break;
      case 'toggle-details': toggleDetails(); break;
      case 'reveal': handleReveal(); break;
      case 'load-reveal-genesis': loadRevealGenesis(); break;
    }
  });
});

// ─── Live anchor: render the real look-it-up links (DOM, CSP-safe) ──
function renderRealAnchor() {
  const el = document.getElementById('real-anchor-banner');
  if (!el || typeof REAL === 'undefined') return;
  const mk = (href, text) => {
    const a = document.createElement('a');
    a.href = href; a.target = '_blank'; a.rel = 'noopener';
    a.textContent = text;
    return a;
  };
  el.replaceChildren(
    mk(`https://mempool.space/tx/${REAL.txid}`, '\u{1F50D} View the Bitcoin transaction'),
    mk(`https://njump.me/${REAL.attNote}`, '\u{1FAAA} View the attestation on Nostr')
  );
}
renderRealAnchor();

// ─── Service worker registration (moved out of an inline <script>) ──
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  });
}
