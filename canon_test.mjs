// Prove the canonicalization fix: a number-literal-preserving canonical JSON
// that reproduces Python's bytes (incl. "0.0"), so the real on-chain
// attestation (score 0.0) verifies. Throwaway test.
import { schnorr } from './noble-secp256k1.bundle.mjs';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

function hexToBytes(h){const b=new Uint8Array(h.length/2);for(let i=0;i<b.length;i++)b[i]=parseInt(h.substr(i*2,2),16);return b;}
function bytesToHex(b){let s='';for(const x of b)s+=x.toString(16).padStart(2,'0');return s;}
function concatBytes(...a){const n=a.reduce((s,x)=>s+x.length,0);const o=new Uint8Array(n);let k=0;for(const x of a){o.set(x,k);k+=x.length;}return o;}
async function sha256(d){return new Uint8Array(await crypto.subtle.digest('SHA-256',d));}
async function taggedHash(tag,msg){const t=new TextEncoder().encode(tag);const th=await sha256(t);return sha256(concatBytes(th,th,msg));}

// --- number-literal-preserving JSON canonicalization ---
function parsePreservingNumbers(text){
  let i=0;
  const ws=()=>{while(i<text.length&&/\s/.test(text[i]))i++;};
  function val(){ws();const c=text[i];
    if(c==='{')return obj(); if(c==='[')return arr(); if(c==='"')return str();
    if(c==='t'){i+=4;return true;} if(c==='f'){i+=5;return false;} if(c==='n'){i+=4;return null;}
    return num();}
  function obj(){const o={};i++;ws();if(text[i]==='}'){i++;return o;}
    for(;;){ws();const k=str();ws();i++;/*:*/o[k]=val();ws();
      if(text[i]===','){i++;continue;} if(text[i]==='}'){i++;break;} throw new Error('bad obj@'+i);}return o;}
  function arr(){const a=[];i++;ws();if(text[i]===']'){i++;return a;}
    for(;;){a.push(val());ws();if(text[i]===','){i++;continue;} if(text[i]===']'){i++;break;} throw new Error('bad arr@'+i);}return a;}
  function str(){let s='';i++;while(text[i]!=='"'){if(text[i]==='\\'){s+=text[i]+text[i+1];i+=2;}else{s+=text[i];i++;}}i++;return JSON.parse('"'+s+'"');}
  function num(){const st=i;while(i<text.length&&/[-+0-9.eE]/.test(text[i]))i++;return {__num:text.slice(st,i)};}
  const r=val();ws();return r;}
function canonicalSerialize(node){
  if(node===null||typeof node==='boolean'||typeof node==='string')return JSON.stringify(node);
  if(typeof node==='object'&&node.__num!==undefined)return node.__num;
  if(Array.isArray(node))return '['+node.map(canonicalSerialize).join(',')+']';
  const keys=Object.keys(node).sort();
  return '{'+keys.map(k=>JSON.stringify(k)+':'+canonicalSerialize(node[k])).join(',')+'}';}
function canonicalBytesFromText(text){return new TextEncoder().encode(canonicalSerialize(parsePreservingNumbers(text)));}

// The real on-chain attestation PAYLOAD as Python serialized it (score 0.0 preserved):
const attText='{"epoch":0,"input_hash":"f16e4f7f799732b01c2f19d87309c1d87bff140491818cb3ecb2aacef2c74f1d","model":"veritas.sentiment.keyword.v1","oracle":"5de21ccf78953bf2079280932b21020ec1050c205d6e683b63001d9bb69d5836","output":{"label":"neutral","neg_hits":0,"pos_hits":0,"score":0.0,"token_count":9},"ts":1781407635,"v":1}';
const sig='eab9c70613afeffa0a2efe4e27374966ab877d59a9c3480c5d7e2d9ba9f4018651ef3ce9b26104f89bb1d85d7c163787a15fc9783fbc0c33517b22f0b3d433a0';
const oracle='5de21ccf78953bf2079280932b21020ec1050c205d6e683b63001d9bb69d5836';
const expectedLeaf='7540d06012f9caf3da13ea4db67edaa85ee684d16e6cb04fd897fd3ecb64b701'; // merkleProof.leaf_hex

const canonical=canonicalBytesFromText(attText);
console.log('canonical bytes:', new TextDecoder().decode(canonical));
const digest=await taggedHash('VRT1/attestation',canonical);
console.log('digest:', bytesToHex(digest));
console.log('matches merkle leaf:', bytesToHex(digest)===expectedLeaf);
const ok=await schnorr.verify(hexToBytes(sig),digest,hexToBytes(oracle));
console.log('schnorr.verify:', ok);
console.log(ok && bytesToHex(digest)===expectedLeaf ? '\nFIX WORKS' : '\n*** fix incomplete ***');
