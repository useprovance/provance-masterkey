import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { once } from 'node:events';
import { createGateway } from '../server';
import { verifyToken } from '../auth';
import { hashRequest, validateResult, type CertifiedAdapter, type ServiceRequest } from '../payment';
import type { Ledger, Claim } from '../ledger';
import { providerPolicy } from '../x402';
import {freePolicy} from '../free';

const keys=generateKeyPairSync('ed25519');const publicKey=keys.publicKey.export({type:'spki',format:'pem'}).toString();
const owner=randomUUID(),callId=randomUUID(),audience='http://127.0.0.1:4010';
const revision='b6aa0b1696a649a8644929ab1d1e9d641edf2904';
const policy=providerPolicy({serviceId:'fixture',registryRevision:revision,url:'https://provider.example/search',payTo:'0x1111111111111111111111111111111111111111',maxFeeUsd:'0.25',inputSchema:{type:'object'},risk:'read',enabled:true,reviewedAt:'2026-11-02'});
const request:ServiceRequest={runId:randomUUID(),serviceId:'fixture',registryRevision:revision,input:{b:2,a:1},maxCostUsd:'0.25',callKey:'node:0',idempotencyKey:'provance:fixture:node:0',providerPolicy:policy,policyHash:hashRequest(policy)};
const requestHash=hashRequest(request);
function token(overrides:Record<string,unknown>={},metadata:Record<string,unknown>={}){
  const now=Math.floor(Date.now()/1000);const encode=(v:unknown)=>Buffer.from(JSON.stringify(v)).toString('base64url');
  const body=`${encode({alg:'EdDSA',typ:'JWT',kid:'provance-gateway-v1',...metadata})}.${encode({iss:'provance-api',aud:audience,sub:owner,jti:randomUUID(),iat:now,exp:now+120,scope:'catalog:read',...overrides})}`;
  return `Bearer ${body}.${sign(null,Buffer.from(body),keys.privateKey).toString('base64url')}`;
}
const executeToken=()=>token({scope:'call:execute',callId,requestHash});
async function server<T>(options:{ledger?:Ledger;adapters?:readonly CertifiedAdapter[]},run:(base:string)=>Promise<T>){
  const s=createGateway({publicKey,issuer:'provance-api',audience,...options});s.listen(0,'127.0.0.1');await once(s,'listening');
  try{return await run(`http://127.0.0.1:${(s.address() as any).port}`);}finally{s.closeAllConnections();await new Promise<void>(r=>s.close(()=>r()));}
}
function fixture(){
  let claims=0,completions=0,unknown=0;let state:Claim={execute:false,status:'pending',request};
  const ledger:Ledger={status:async()=>state,claim:async()=>{claims++;if(state.status!=='pending')return{execute:false,...state};state={execute:false,status:'dispatched'};return{execute:true,status:'dispatched',request};},complete:async(_o,_c,_h,result)=>{completions++;state={execute:false,status:result.status,result};},unknown:async()=>{unknown++;state={execute:false,status:'unknown'};}};
  return{ledger,count:()=>({claims,completions,unknown})};
}
const adapter:CertifiedAdapter={serviceId:'fixture',registryRevision:revision,policy,execute:async()=>({status:'succeeded',totalFeeUsd:'0.10',receiptId:randomUUID(),result:{ok:true}})};
const post=(base:string,auth=executeToken(),body:unknown={callId,requestHash})=>fetch(`${base}/v1/calls`,{method:'POST',headers:{Authorization:auth,'Content-Type':'application/json'},body:JSON.stringify(body)});

test('authorization binds issuer, audience, owner, scope, lifetime and algorithm',()=>{
  assert.equal(verifyToken(token(),{publicKey,issuer:'provance-api',audience}).sub,owner);
  for(const patch of [{iss:'evil'},{aud:'wrong'},{sub:'not-a-uuid'},{exp:1},{iat:9999999999},{exp:Math.floor(Date.now()/1000)+121},{scope:'wallet:transfer'},{scope:'call:execute'}])assert.throws(()=>verifyToken(token(patch),{publicKey,issuer:'provance-api',audience}));
  assert.throws(()=>verifyToken(token({}, {alg:'none'}),{publicKey,issuer:'provance-api',audience}));
  assert.throws(()=>verifyToken(token().slice(0,-3)+'abc',{publicKey,issuer:'provance-api',audience}));
});
test('catalog works without CDP, MongoDB or a wallet; paid calls fail before claiming',async()=>{
  const f=fixture();await server({ledger:f.ledger},async base=>{
    assert.equal((await fetch(`${base}/v1/services`)).status,401);
    const r=await fetch(`${base}/v1/services?q=image`,{headers:{Authorization:token()}});assert.equal(r.status,200);const d=await r.json();assert(d.total>0);assert(d.services.length<=50);assert(d.services.every((s:any)=>s.status!=='hidden'&&s.availability==='catalog_only'));
    const capabilities=await (await fetch(`${base}/v1/capabilities`,{headers:{Authorization:token()}})).json();assert.equal(capabilities.serviceCount,1803);assert.equal(capabilities.paymentsEnabled,false);
    assert.equal((await post(base)).status,409);assert.equal(f.count().claims,0);
  });
});
test('call identity and scope cannot be replaced by request input',async()=>{
  const f=fixture();await server({ledger:f.ledger,adapters:[adapter]},async base=>{
    assert.equal((await post(base,token())).status,403);
    assert.equal((await post(base,executeToken(),{callId:randomUUID(),requestHash})).status,403);
    assert.equal((await post(base,executeToken(),{callId,requestHash,input:{steal:true}})).status,403);
    assert.equal(f.count().claims,0);
  });
});
test('duplicate calls replay a persisted result and never execute payment twice',async()=>{
  const f=fixture();let invocations=0;await server({ledger:f.ledger,adapters:[{...adapter,execute:async(r)=>{invocations++;return adapter.execute(r);}}]},async base=>{
    const first=await (await post(base)).json();const second=await (await post(base)).json();assert.deepEqual(second,first);assert.equal(invocations,1);assert.equal(f.count().completions,1);
  });
});
test('uncertified operation is refused before financial dispatch',async()=>{
  const f=fixture();await server({ledger:f.ledger,adapters:[{...adapter,serviceId:'other'}]},async base=>{assert.equal((await post(base)).status,409);assert.equal(f.count().claims,0);});
});
test('a dispatched provider timeout keeps an unknown hold and cannot execute again',async()=>{
  const f=fixture();let calls=0;await server({ledger:f.ledger,adapters:[{...adapter,execute:async()=>{calls++;throw Error('Timeout');}}]},async base=>{
    assert.equal((await post(base)).status,502);assert.equal((await post(base)).status,202);assert.equal(calls,1);assert.equal(f.count().unknown,1);assert.equal(f.count().completions,0);
  });
});
test('an invalid receipt or above-ceiling result cannot settle a call',()=>{
  assert.throws(()=>validateResult({status:'succeeded',totalFeeUsd:'0.26',receiptId:'receipt',result:{}},'0.25'));
  assert.throws(()=>validateResult({status:'succeeded',totalFeeUsd:'0.1',receiptId:null,result:{}},'0.25'));
  assert.throws(()=>validateResult({status:'failed_no_charge',totalFeeUsd:'0.1',receiptId:'r',result:{}},'0.25'));
});
test('canonical hashes bind exact inputs while ignoring JSON property order',()=>{
  assert.equal(hashRequest(request),hashRequest({...request,input:{a:1,b:2}}));
  assert.notEqual(hashRequest(request),hashRequest({...request,maxCostUsd:'0.26'}));
});
test('a changed payee, network, asset, endpoint, schema, review or provider ceiling invalidates old consent before dispatch',async()=>{
  for(const patch of [{payTo:'0x2222222222222222222222222222222222222222'},{network:'eip155:1'},{asset:'0x'+'3'.repeat(40)},{url:'https://other.example/search'},{inputSchema:{type:'object',required:['secret']}},{reviewedAt:'2026-11-03'},{maxFeeUsd:'0.26'}]) {
    const f=fixture();await server({ledger:f.ledger,adapters:[{...adapter,policy:{...policy,...patch} as typeof policy}]},async base=>{
      assert.equal((await post(base)).status,409);assert.equal(f.count().claims,0);
    });
  }
});
test('capabilities expose immutable policy identity and paused operation status',async()=>{
 const f=fixture();f.ledger.health=async()=>({enabled:false,dailyLimit:'0'});
 await server({ledger:f.ledger,adapters:[adapter]},async base=>{
  const response=await fetch(`${base}/v1/capabilities?serviceId=fixture`,{headers:{Authorization:token()}});const data=await response.json();
  assert.equal(data.executable,false);assert.equal(data.operations[0].state,'temporarily_unavailable');assert.equal(data.policyHash,request.policyHash);assert.deepEqual(data.policy,policy);
 });
});
test('free capability and dispatch work with payments paused and replay once',async()=>{
 const p=freePolicy({...policy,version:2,network:null,asset:null,scheme:'free',payTo:null,maxFeeUsd:'0',method:'GET',adapter:'blockrun-json-v1',enabled:true,inputExample:{},note:''});
 const input={...request,maxCostUsd:'0',providerPolicy:p,policyHash:hashRequest(p),lease:randomUUID()};let calls=0;let result:any;
 const f=fixture();f.ledger.health=async()=>({enabled:false,dailyLimit:'0',freeExecutionVersion:1});
 f.ledger.claimFree=async()=>result?{execute:false,status:'succeeded',result}:{execute:true,status:'dispatched'};
 f.ledger.completeFree=async(_o,_h,_r,value)=>{result=value;};
 const free={...adapter,policy:p,execute:async()=>{calls++;return{status:'succeeded' as const,totalFeeUsd:'0',receiptId:null,result:{answer:'from free provider'}};}};
 await server({ledger:f.ledger,adapters:[free]},async base=>{
  const cap=await(await fetch(`${base}/v1/capabilities?serviceId=fixture`,{headers:{Authorization:token()}})).json();assert.equal(cap.paymentsEnabled,false);assert.equal(cap.executable,true);assert.equal(cap.operations[0].billing,'free');
  const auth=token({scope:'free:execute',callId:input.runId,requestHash:hashRequest(input)});
  const send=(body:any=input,authorization=auth)=>fetch(`${base}/v1/free`,{method:'POST',headers:{Authorization:authorization,'Content-Type':'application/json'},body:JSON.stringify(body)});
  assert.equal((await send({...input,maxCostUsd:'1'})).status,403);
  assert.equal((await send(input,executeToken())).status,403);
  const first=await(await send()).json();assert.equal(first.result.answer,'from free provider');assert.deepEqual(await(await send()).json(),first);assert.equal(calls,1);assert.equal(f.count().claims,0);
 });
});
