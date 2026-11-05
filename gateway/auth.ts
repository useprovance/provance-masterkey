import { createPublicKey, verify, type KeyObject } from 'node:crypto';

export type Claims = {sub:string;scope:'catalog:read'|'call:execute'|'call:reconcile'|'free:execute';callId?:string;requestHash?:string};
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function verifyToken(header:string|undefined,options:{publicKey:string|KeyObject;issuer:string;audience:string;now?:number}):Claims {
  if(!header?.startsWith('Bearer ')||header.length>4096)throw Error('Unauthorized');
  const token=header.slice(7);const parts=token.split('.');
  if(parts.length!==3||parts.some(p=>!p||!/^[A-Za-z0-9_-]+$/.test(p)))throw Error('Unauthorized');
  const [h,p,s]=parts;
  const metadata=JSON.parse(Buffer.from(h,'base64url').toString());
  if(metadata.alg!=='EdDSA'||metadata.typ!=='JWT'||metadata.kid!=='provance-gateway-v1')throw Error('Unauthorized');
  const key=typeof options.publicKey==='string'?createPublicKey(options.publicKey.replace(/\\n/g,'\n')):options.publicKey;
  if(!verify(null,Buffer.from(`${h}.${p}`),key,Buffer.from(s,'base64url')))throw Error('Unauthorized');
  const c=JSON.parse(Buffer.from(p,'base64url').toString());const now=options.now??Math.floor(Date.now()/1000);
  if(c.iss!==options.issuer||c.aud!==options.audience||!uuid.test(c.sub??'')||!uuid.test(c.jti??'')||!Number.isInteger(c.iat)||!Number.isInteger(c.exp)||c.exp<=now||c.iat>now+5||c.exp-c.iat>120||c.exp<=c.iat)throw Error('Unauthorized');
  if(!['catalog:read','call:execute','call:reconcile','free:execute'].includes(c.scope))throw Error('Unauthorized');
  if(c.scope!=='catalog:read'&&(!uuid.test(c.callId??'')||!/^[a-f0-9]{64}$/.test(c.requestHash??'')))throw Error('Unauthorized');
  return c as Claims;
}
