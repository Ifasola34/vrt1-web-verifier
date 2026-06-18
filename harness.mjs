// Pre-deploy harness: runs the verifier functions (with the canonicalization
// FIX) against the real broadcast bundle + real noble crypto, in Node. If this
// prints all-green, the browser will too. Throwaway.
import { schnorr } from './noble-secp256k1.bundle.mjs';
import { REAL } from './real-vector.mjs';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

function hexToBytes(h){const b=new Uint8Array(h.length/2);for(let i=0;i<b.length;i++)b[i]=parseInt(h.substr(i*2,2),16);return b;}
function bytesToHex(b){let s='';for(const x of b)s+=x.toString(16).padStart(2,'0');return s;}
function concatBytes(...a){const n=a.reduce((s,x)=>s+x.length,0);const o=new Uint8Array(n);let k=0;for(const x of a){o.set(x,k);k+=x.length;}return o;}
async function sha256(d){return new Uint8Array(await crypto.subtle.digest('SHA-256',d));}
async function sha256d(d){return sha256(await sha256(d));}
function normalizeInput(t){return t.trim().toLowerCase().replace(/\s+/g,' ');}
async function inputHashHex(text,salt=''){return bytesToHex(await sha256(new TextEncoder().encode(normalizeInput(text)+salt)));}
async function taggedHash(tag,msg){const t=new TextEncoder().encode(tag);const th=await sha256(t);return sha256(concatBytes(th,th,msg));}

// --- canonicalization FIX (number-literal-preserving) ---
function parsePreservingNumbers(text){
  let i=0; const ws=()=>{while(i<text.length&&/\s/.test(text[i]))i++;};
  function val(){ws();const c=text[i];
    if(c==='{')return obj(); if(c==='[')return arr(); if(c==='"')return str();
    if(c==='t'){i+=4;return true;} if(c==='f'){i+=5;return false;} if(c==='n'){i+=4;return null;}
    return num();}
  function obj(){const o={};i++;ws();if(text[i]==='}'){i++;return o;}
    for(;;){ws();const k=str();ws();i++;o[k]=val();ws();
      if(text[i]===','){i++;continue;} if(text[i]==='}'){i++;break;} throw new Error('bad obj');}return o;}
  function arr(){const a=[];i++;ws();if(text[i]===']'){i++;return a;}
    for(;;){a.push(val());ws();if(text[i]===','){i++;continue;} if(text[i]===']'){i++;break;} throw new Error('bad arr');}return a;}
  function str(){let s='';i++;while(text[i]!=='"'){if(text[i]==='\\'){s+=text[i]+text[i+1];i+=2;}else{s+=text[i];i++;}}i++;return JSON.parse('"'+s+'"');}
  function num(){const st=i;while(i<text.length&&/[-+0-9.eE]/.test(text[i]))i++;return {__num:text.slice(st,i)};}
  const r=val();ws();return r;}
function canonicalSerialize(node){
  if(node===null||typeof node==='boolean'||typeof node==='string')return JSON.stringify(node);
  if(typeof node==='object'&&node.__num!==undefined)return node.__num;
  if(Array.isArray(node))return '['+node.map(canonicalSerialize).join(',')+']';
  return '{'+Object.keys(node).sort().map(k=>JSON.stringify(k)+':'+canonicalSerialize(node[k])).join(',')+'}';}

async function verifyAttestationFromText(signedText, sigHex, oracleHex){
  const parsed = parsePreservingNumbers(signedText);
  const canonical = new TextEncoder().encode(canonicalSerialize(parsed.attestation));
  const digest = await taggedHash('VRT1/attestation', canonical);
  const valid = await schnorr.verify(hexToBytes(sigHex), digest, hexToBytes(oracleHex));
  return { valid, digest: bytesToHex(digest) };
}
async function verifyNostrEvent(event){
  const serialized=JSON.stringify([0,event.pubkey,event.created_at,event.kind,event.tags,event.content]);
  const idBytes=await sha256(new TextEncoder().encode(serialized));
  if(bytesToHex(idBytes)!==event.id)return{valid:false,reason:'id mismatch'};
  if(!await schnorr.verify(hexToBytes(event.sig),idBytes,hexToBytes(event.pubkey)))return{valid:false,reason:'sig invalid'};
  return{valid:true};
}
function expectedDepth(n){if(n<=1)return 0;let d=0,m=n;while(m>1){m=Math.ceil(m/2);d++;}return d;}
async function verifyMerkleProof({leaf,siblings,directions,root,size,index}){
  if(size<=0)return{valid:false,reason:'size<=0'};
  if(siblings.length!==expectedDepth(size))return{valid:false,reason:'depth'};
  let cur=await sha256d(concatBytes(new Uint8Array([0x00]),leaf));
  for(let i=0;i<siblings.length;i++){
    if(directions[i]===0)cur=await sha256d(concatBytes(new Uint8Array([0x01]),cur,siblings[i]));
    else cur=await sha256d(concatBytes(new Uint8Array([0x01]),siblings[i],cur));}
  return{valid:bytesToHex(cur)===bytesToHex(root)};
}
function parseOpReturn(h){const b=hexToBytes(h);if(b.length!==49)return{valid:false};
  if(String.fromCharCode(...b.slice(0,4))!=='VRT1')return{valid:false};
  const v=new DataView(b.buffer,b.byteOffset,b.byteLength);
  return{valid:true,epoch:v.getUint32(5)*0x100000000+v.getUint32(9),leafCount:v.getUint32(13),merkleRootHex:bytesToHex(b.slice(17,49))};}
function extractOpReturnFromTx(rawHex){const bytes=hexToBytes(rawHex);let pos=4;
  if(bytes[pos]===0x00&&bytes[pos+1]!==0x00)pos+=2;
  const rv=()=>{const f=bytes[pos++];if(f<0xfd)return f;if(f===0xfd){const v=bytes[pos]|(bytes[pos+1]<<8);pos+=2;return v;}if(f===0xfe){const v=bytes[pos]|(bytes[pos+1]<<8)|(bytes[pos+2]<<16)|(bytes[pos+3]<<24);pos+=4;return v>>>0;}pos+=8;return 0;};
  const nin=rv();for(let i=0;i<nin;i++){pos+=36;const sl=rv();pos+=sl+4;}
  const nout=rv();for(let i=0;i<nout;i++){pos+=8;const sl=rv();const s=bytes.slice(pos,pos+sl);pos+=sl;
    if(s.length>=2&&s[0]===0x6a){let ds,dl;if(s[1]<=0x4b){dl=s[1];ds=2;}else if(s[1]===0x4c){dl=s[2];ds=3;}else continue;
      if(ds+dl<=s.length){const p=s.slice(ds,ds+dl);if(p.length===49&&String.fromCharCode(...p.slice(0,4))==='VRT1')return bytesToHex(p);}}}
  return null;}

async function verifyRealFull(){
  const att=REAL.signedAttestation.attestation;
  const r={schnorrOk:null,nostrOk:null,merkleOk:null,cpOk:null,anchorOk:null};
  const ar=await verifyAttestationFromText(REAL.signedAttestationText, REAL.signedAttestation.sig, att.oracle);
  r.schnorrOk=ar.valid;
  const nr=await verifyNostrEvent(REAL.nostrEvent); r.nostrOk=nr.valid && REAL.nostrEvent.pubkey===att.oracle;
  const mr=await verifyMerkleProof({leaf:hexToBytes(ar.digest),siblings:REAL.merkleProof.siblings_hex.map(hexToBytes),directions:REAL.merkleProof.directions,root:hexToBytes(REAL.merkleProof.root_hex),size:REAL.merkleProof.size,index:REAL.merkleProof.index});
  r.merkleOk=(REAL.merkleProof.leaf_hex===ar.digest)&&mr.valid;
  const cr=await verifyNostrEvent(REAL.checkpointEvent); const cc=JSON.parse(REAL.checkpointEvent.content);
  r.cpOk=cr.valid&&REAL.checkpointEvent.pubkey===att.oracle&&cc.epoch===att.epoch&&cc.root===REAL.merkleProof.root_hex&&cc.count===REAL.merkleProof.size;
  const ph=extractOpReturnFromTx(REAL.anchorRawTxHex); const op=ph?parseOpReturn(ph):{valid:false};
  r.anchorOk=op.valid&&op.epoch===att.epoch&&op.merkleRootHex===REAL.merkleProof.root_hex&&op.leafCount===REAL.merkleProof.size;
  return r;}

const r=await verifyRealFull();
console.log(JSON.stringify(r,null,2));

// Reveal-and-verify parity: the genesis plaintext must reproduce its on-chain
// input_hash, and a salted vector must match the Python signer (tests/test_reveal.py).
const genHash=await inputHashHex(REAL.inputText);
const revealGenesisOk=genHash===REAL.signedAttestation.attestation.input_hash;
const saltedOk=(await inputHashHex('approved','9f8e7d6c5b4a39281706f5e4d3c2b1a0'))==='5089006b47fda34d47aedbb75b7cc4cc2ac93b722912557c38ead4422d6bc7d5';
console.log('revealGenesisOk:',revealGenesisOk,' saltedParityOk:',saltedOk);

// "Paste a whole bundle.json" path: a real bundle file embeds the signed
// attestation as raw text with "score":0.0. The split must preserve that float
// (via canonicalSerialize) or the Schnorr check fails. Mirrors handleBundle().
const bundleText=`{
  "signedAttestation": ${REAL.signedAttestationText},
  "nostrEvent": ${JSON.stringify(REAL.nostrEvent)},
  "merkleProof": ${JSON.stringify(REAL.merkleProof)},
  "checkpointEvent": ${JSON.stringify(REAL.checkpointEvent)},
  "anchorRawTxHex": ${JSON.stringify(REAL.anchorRawTxHex)},
  "_meta": {"network":"mainnet"}
}`;
const bTree=parsePreservingNumbers(bundleText);
const bAttText=canonicalSerialize(bTree.signedAttestation);
const bAtt=await verifyAttestationFromText(bAttText, JSON.parse(bundleText).signedAttestation.sig, REAL.signedAttestation.attestation.oracle);
const bundleSplitOk=bAttText.includes('"score":0.0') && bAtt.valid && bAtt.digest===REAL.merkleProof.leaf_hex;
console.log('bundleSplitOk:',bundleSplitOk,'(float preserved + sig valid + digest==leaf)');

const allGreen=r.schnorrOk&&r.nostrOk&&r.merkleOk&&r.cpOk&&r.anchorOk&&revealGenesisOk&&saltedOk&&bundleSplitOk;
console.log(allGreen?'\nALL FIVE LAYERS GREEN + REVEAL PARITY + BUNDLE SPLIT — safe to deploy':'\n*** NOT all green — do NOT deploy ***');
