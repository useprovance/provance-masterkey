import test from 'node:test';import assert from 'node:assert/strict';import {verifyToken} from '../auth';import {generateKeyPairSync,sign,randomUUID} from 'node:crypto';
test('ordinary execution cannot grant itself operator reconciliation scope',()=>{
 const keys=generateKeyPairSync('ed25519'),encode=(v:unknown)=>Buffer.from(JSON.stringify(v)).toString('base64url');const now=Math.floor(Date.now()/1000);
 const header=encode({alg:'EdDSA',typ:'JWT',kid:'provance-gateway-v1'});const payload=encode({iss:'api',aud:'gateway',sub:randomUUID(),jti:randomUUID(),iat:now,exp:now+120,scope:'call:reconcile',callId:randomUUID(),requestHash:'a'.repeat(64)});const unsigned=header+'.'+payload;
 const token='Bearer '+unsigned+'.'+sign(null,Buffer.from(unsigned),keys.privateKey).toString('base64url');assert.equal(verifyToken(token,{issuer:'api',audience:'gateway',publicKey:keys.publicKey}).scope,'call:reconcile');
 assert.throws(()=>verifyToken(token.replace(payload,encode({...JSON.parse(Buffer.from(payload,'base64url').toString()),callId:randomUUID()})),{issuer:'api',audience:'gateway',publicKey:keys.publicKey}));
});
