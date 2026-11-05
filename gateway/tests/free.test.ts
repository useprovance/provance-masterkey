import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createFreeAdapter,freePolicy,loadFreeAdapters,type FreeProvider} from '../free';
import {hashRequest,type ServiceRequest} from '../payment';

const configs=JSON.parse(readFileSync('gateway/free-providers.json','utf8')) as FreeProvider[];
const config=configs.find(p=>p.serviceId==='crypto-price')!;
function request(p=config,input:Record<string,unknown>={symbol:'BTC-USD'}):ServiceRequest {const policy=freePolicy(p);return{runId:'00000000-0000-4000-8000-000000000001',serviceId:p.serviceId,registryRevision:p.registryRevision,input,maxCostUsd:'0',callKey:'n:0',idempotencyKey:'test',providerPolicy:policy,policyHash:hashRequest(policy)};}
const response=(data:Record<string,any>,status=200)=>({status,headers:{},data});
test('all reviewed free routes load without any payer key or RPC',()=>{assert.equal(loadFreeAdapters().length,12);assert(loadFreeAdapters().every(a=>a.policy.scheme==='free'&&a.policy.network===null&&a.policy.payTo===null));});
test('free price executes a bounded GET and returns zero with no receipt',async()=>{
 const adapter=createFreeAdapter(config,async(url,options)=>{assert.equal(url,'https://blockrun.ai/api/v1/crypto/price/BTC-USD');assert.deepEqual(options,{method:'GET'});return response({symbol:'BTC-USD',price:123,free:true,timestamp:'2026-11-03T00:00:00Z',realtime:false});});
 const result=await adapter.execute(request());assert.equal(result.status,'succeeded');assert.equal(result.totalFeeUsd,'0');assert.equal(result.receiptId,null);assert.equal(result.result.price,123);
});
test('zero-fee route cannot accept a positive cap, transplanted policy or invalid input',async()=>{
 let calls=0;const adapter=createFreeAdapter(config,async()=>{calls++;return response({});});
 for(const input of [{...request(),maxCostUsd:'0.01'},{...request(),input:{symbol:'../../wallet'}},{...request(),providerPolicy:{...request().providerPolicy,url:'https://other.example'}}])assert.equal((await adapter.execute(input)).status,'failed_no_charge');
 assert.equal(calls,0);
});
test('a 402 challenge, redirect or provider error never causes payment or a retry',async()=>{
 for(const status of [402,302,500]){let calls=0;const result=await createFreeAdapter(config,async()=>{calls++;return response({accepts:[{amount:'10000'}]},status);}).execute(request());assert.equal(calls,1);assert.equal(result.status,'failed_no_charge');assert.equal(result.totalFeeUsd,'0');}
});
test('unusable prices and empty/invalid history fail instead of becoming successful node output',async()=>{
 const result=await createFreeAdapter(config,async()=>response({symbol:'WRONG',price:0,free:true})).execute(request());assert.equal(result.status,'failed_no_charge');
 const history=configs.find(p=>p.serviceId==='crypto-history')!;
 const result2=await createFreeAdapter(history,async()=>response({symbol:'BTC-USD',free:true,bars:[]})).execute(request(history,{symbol:'BTC-USD',days:14}));assert.equal(result2.status,'failed_no_charge');
});
test('symbol lists normalize provider identifiers before exposing workflow outputs',async()=>{
 const list=configs.find(p=>p.serviceId==='crypto-symbols')!;
 const result=await createFreeAdapter(list,async()=>response({symbols:[{symbol:'BTC/USD-USD'}]})).execute(request(list,{limit:3}));
 assert.equal((result.result.outputs as any[])[0].symbol,'BTC-USD');assert.equal((result.result.outputs as any[])[0].providerSymbol,'BTC/USD-USD');
});
test('Exa MCP is restricted to free search and never signs an identity/payment challenge',async()=>{
 const exa=configs.find(p=>p.serviceId==='exa')!;const methods:string[]=[];
 const result=await createFreeAdapter(exa,async(_url,options)=>{const body=options.body!;methods.push(String(body.method));assert(!Object.keys(options.headers??{}).some(k=>/payment|authorization/i.test(k)));if(body.method==='initialize')return response({result:{serverInfo:{name:'exa'},protocolVersion:'2025-03-26'}});if(body.method==='notifications/initialized')return response({},202);assert.equal((body.params as any).name,'web_search_exa');return response({result:{content:[{type:'text',text:'Stellar docs https://developers.stellar.org/docs'}]}});}).execute(request(exa,{query:'Stellar docs',numResults:2,type:'fast'}));
 assert.equal(result.status,'succeeded');assert.deepEqual(methods,['initialize','notifications/initialized','tools/call']);assert.match(String(result.result.text),/developers.stellar.org/);
});
test('minimal Exa input gets bounded defaults, without inventing a paid route',async()=>{
 const exa=configs.find(p=>p.serviceId==='exa')!;
 const result=await createFreeAdapter(exa,async(_url,options)=>{
  const body=options.body!;
  if(body.method==='initialize')return response({result:{serverInfo:{name:'exa'},protocolVersion:'2025-03-26'}});
  if(body.method==='notifications/initialized')return response({},202);
  assert.deepEqual((body.params as any).arguments,{query:'dev',numResults:2,type:'fast'});
  return response({result:{content:[{type:'text',text:'DEV Community https://dev.to/'}]}});
 }).execute(request(exa,{query:'dev'}));
 assert.equal(result.status,'succeeded');assert.equal(result.totalFeeUsd,'0');
});
test('Exa tool failures expose a safe actionable category and never retry or pay',async()=>{
 const exa=configs.find(p=>p.serviceId==='exa')!;
 for(const [detail,code] of [['Rate limit exceeded. secret=should-not-be-forwarded','EXA_RATE_LIMITED'],['Temporarily unavailable','EXA_UNAVAILABLE'],['Invalid API key','EXA_ACCESS_DENIED'],['Unknown failure with private query data','EXA_SEARCH_FAILED']]){
  let searches=0;const result=await createFreeAdapter(exa,async(_url,options)=>{
   const body=options.body!;
   if(body.method==='initialize')return response({result:{serverInfo:{name:'exa'},protocolVersion:'2025-03-26'}});
   if(body.method==='notifications/initialized')return response({},202);
   searches++;return response({result:{isError:true,content:[{type:'text',text:detail}]}});
  }).execute(request(exa,{query:'dev'}));
  assert.equal(result.status,'failed_no_charge');assert.equal(result.result.errorCode,code);assert.equal(result.totalFeeUsd,'0');assert.equal(searches,1);
  assert.match(String(result.result.error),/Exa/);assert(!String(result.result.error).includes('should-not-be-forwarded'));assert(!String(result.result.error).includes('private query'));
 }
});
