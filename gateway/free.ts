import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import Ajv from 'ajv';
import {hashRequest, type CertifiedAdapter, type FreeProviderPolicy, type ServiceRequest, type VerifiedResult} from './payment';
import {safeRequest} from './network';

export interface FreeProvider extends FreeProviderPolicy {enabled:boolean;inputExample:Record<string,unknown>;note:string}
export function freePolicy(p:FreeProvider):FreeProviderPolicy {
 return {version:2,serviceId:p.serviceId,...(p.operation?{operation:p.operation}:{}),registryRevision:p.registryRevision,network:null,asset:null,scheme:'free',payTo:null,maxFeeUsd:'0',url:p.url,method:p.method,adapter:p.adapter,inputSchema:p.inputSchema,risk:p.risk,reviewedAt:p.reviewedAt};
}
export function validateFreeProvider(p:FreeProvider){
 if(p.version!==2||p.scheme!=='free'||p.network!==null||p.asset!==null||p.payTo!==null||p.maxFeeUsd!=='0'||p.risk!=='read'||!Number.isFinite(Date.parse(p.reviewedAt)))throw Error('Invalid free provider policy');
 const u=new URL(p.url);if(u.username||u.password||u.port||u.search||u.hash||u.protocol!=='https:')throw Error('Invalid free endpoint');
 const allowed=p.adapter==='blockrun-json-v1'&&p.method==='GET'&&u.hostname==='blockrun.ai'&&/^\/api\/v1\/(?:(?:crypto|fx|commodity)\/(?:list|price\/\{symbol\})|crypto\/history\/\{symbol\}|usstock\/list|stocks\/us\/list|audio\/voices)$/.test(decodeURIComponent(u.pathname))
  ||p.adapter==='exa-mcp-search-v1'&&p.method==='POST'&&p.url==='https://mcp.exa.ai/mcp'
  ||p.adapter==='guardrail-json-v1'&&p.method==='POST'&&p.url==='https://brack-hive.tail4f568d.ts.net/output-risk';
 if(!allowed)throw Error('Unreviewed free route');
}
function ok(response:Awaited<ReturnType<typeof safeRequest>>){
 if(response.status===402)throw Error('Free access now requires payment or identity; no signature or paid fallback was attempted');
 if(response.status<200||response.status>=300)throw Error(`Free provider returned HTTP ${response.status}; no payment was attempted`);
 if(response.data.error||response.data.errors||response.data.isError)throw Error('Free provider returned an error');
 return response.data;
}
class ExaSearchError extends Error {
 constructor(message:string,readonly code:string,readonly retryable:boolean,readonly providerStatus?:number){super(message);}
}
function exaFailure(detail:unknown,status?:number):ExaSearchError {
 const text=typeof detail==='string'?detail:JSON.stringify(detail??{});
 if(status===402)return new ExaSearchError('Exa free access now requires payment. No payment or paid fallback was attempted.','EXA_PAYMENT_REQUIRED',false,status);
 if(status===429||/rate.?limit|too many requests|quota.{0,30}(?:exceed|limit|reach)|(?:status|code)\D{0,10}429/i.test(text))return new ExaSearchError('Exa free search is rate limited. Wait a moment, then run the block again. No payment was attempted.','EXA_RATE_LIMITED',true,status);
 if(status===401||status===403||/unauthorized|authentication required|invalid api key|(?:status|code)\D{0,10}(?:401|403)/i.test(text))return new ExaSearchError('Exa rejected free access. Try again later or contact the operator; no payment was attempted.','EXA_ACCESS_DENIED',false,status);
 if(status&&status>=500||/temporar|unavailable|overloaded|internal server|timed? ?out/i.test(text))return new ExaSearchError('Exa free search is temporarily unavailable. Try running the block again later. No payment was attempted.','EXA_UNAVAILABLE',true,status);
 return new ExaSearchError('Exa could not complete this free search. Try a more specific query or run the block again later. No payment was attempted.','EXA_SEARCH_FAILED',false,status);
}
const normalizeSymbol=(symbol:string)=>symbol.includes('/')?symbol.replace(/-USD$/,'').replace('/','-'):symbol;
export function createFreeAdapter(config:FreeProvider,fetchProvider:typeof safeRequest=safeRequest):CertifiedAdapter {
 validateFreeProvider(config);const policy=freePolicy(config);const validate=new Ajv({strict:true,validateFormats:false}).compile(config.inputSchema);
 return {serviceId:config.serviceId,operation:config.operation,registryRevision:config.registryRevision,policy,execute:async(request:ServiceRequest):Promise<VerifiedResult>=>{
  try{
   if(request.maxCostUsd!=='0'||request.policyHash!==hashRequest(policy)||hashRequest(request.providerPolicy)!==request.policyHash)throw Error('Free input or approved policy changed');
   if(!validate(request.input))throw Error('Input does not match the reviewed free-service schema');
   let data:Record<string,any>;
   if(config.adapter==='exa-mcp-search-v1'){
    const rpc=async(body:Record<string,unknown>,headers:Record<string,string>={})=>{
     let response:Awaited<ReturnType<typeof fetchProvider>>;
     try{response=await fetchProvider(config.url,{method:'POST',body,headers,sse:true});}catch(error){throw exaFailure(error instanceof Error?error.message:undefined);}
     if(response.status<200||response.status>=300||response.data.error||response.data.errors||response.data.isError)throw exaFailure(response.data,response.status);
     return response;
    };
    const init=await rpc({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'provance',version:'1.0'}}});
    const initialized=ok(init);if(!initialized.result?.serverInfo)throw new ExaSearchError('Exa could not initialize free search. Try again later. No payment was attempted.','EXA_PROTOCOL_ERROR',true);
    const headers:Record<string,string>={'mcp-protocol-version':initialized.result.protocolVersion};
    if(init.headers['mcp-session-id'])headers['mcp-session-id']=init.headers['mcp-session-id'];
    ok(await rpc({jsonrpc:'2.0',method:'notifications/initialized'},headers));
    const response=ok(await rpc({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'web_search_exa',arguments:{...request.input,numResults:request.input.numResults??2,type:request.input.type??'fast'}}},headers));
    if(response.result?.isError)throw exaFailure(response.result.content);
    if(!Array.isArray(response.result?.content))throw new ExaSearchError('Exa returned an invalid search response. Try again later. No payment was attempted.','EXA_PROTOCOL_ERROR',true);
    const text=response.result.content.filter((c:any)=>c.type==='text'&&typeof c.text==='string').map((c:any)=>c.text).join('\n');
    if(!text.trim())throw new ExaSearchError('Exa returned no search text. Try a more specific query. No payment was attempted.','EXA_EMPTY_RESULT',false);
    data={text,content:response.result.content,free:true,source:'exa-official-mcp'};
   }else if(config.adapter==='guardrail-json-v1'){
    data=ok(await fetchProvider(config.url,{method:'POST',body:request.input,headers:{'X-Free-Tier':'AGENTFAST'}}));
    if(!['low','medium','high'].includes(data.risk)||!['allow','block'].includes(data.recommended_action)||!Array.isArray(data.patterns))throw Error('Invalid guardrail response');
    data={...data,advisory:true};
   }else{
    const u=new URL(config.url.replace('{symbol}',encodeURIComponent(String(request.input.symbol??''))));
    if(config.url.endsWith('/list')){u.searchParams.set('limit',String(request.input.limit??3));if(request.input.q)u.searchParams.set('q',String(request.input.q));}
    if(config.url.includes('/history/')){const to=Math.floor(Date.now()/1000)-300;u.searchParams.set('resolution','D');u.searchParams.set('from',String(to-Number(request.input.days??14)*86400));u.searchParams.set('to',String(to));}
    data=ok(await fetchProvider(u.toString(),{method:'GET'}));
    if(config.url.includes('/price/')){
     if(data.symbol!==request.input.symbol||!Number.isFinite(data.price)||data.price<=0||data.free!==true||!Number.isFinite(Date.parse(data.timestamp)))throw Error('Invalid free price response');
    }else if(config.url.includes('/history/')){
     if(data.symbol!==request.input.symbol||data.free!==true||!Array.isArray(data.bars)||!data.bars.length||!data.bars.every((b:any,i:number)=>['t','o','h','l','c'].every(k=>Number.isFinite(b[k]))&&b.c>0&&b.h>=Math.max(b.o,b.c)&&b.l<=Math.min(b.o,b.c)&&(i===0||b.t>data.bars[i-1].t)&&b.t>=data.from&&b.t<=data.to))throw Error('Invalid free history response');
     data={...data,outputs:data.bars};
    }else if(config.url.endsWith('/voices')){
     if(!Array.isArray(data.data)||!data.data.length||!data.data.every((v:any)=>typeof v.voice_id==='string'&&typeof v.name==='string'))throw Error('Invalid voice list');
     data={...data,outputs:data.data};
    }else{
     if(!Array.isArray(data.symbols)||!data.symbols.length||data.symbols.length>20||!data.symbols.every((s:any)=>typeof s.symbol==='string'))throw Error('Invalid symbol list');
     const symbols=data.symbols.map((s:any)=>({...s,providerSymbol:s.symbol,symbol:normalizeSymbol(s.symbol)}));
     data={...data,symbols,outputs:symbols,coverageNote:'Price availability varies by symbol; free prices are delayed daily-close data.'};
    }
   }
   return {status:'succeeded',totalFeeUsd:'0',receiptId:null,result:data};
  }catch(error){return {status:'failed_no_charge',totalFeeUsd:'0',receiptId:null,result:{error:error instanceof Error?error.message:'Free service failed',...(error instanceof ExaSearchError?{errorCode:error.code,retryable:error.retryable,...(error.providerStatus?{providerStatus:error.providerStatus}:{})}:{})}};}
 }};
}
export function loadFreeAdapters():CertifiedAdapter[]{
 const rows=JSON.parse(readFileSync(join(process.cwd(),'gateway/free-providers.json'),'utf8')) as FreeProvider[];
 if(!Array.isArray(rows))throw Error('Invalid free-provider manifest');
 const index=JSON.parse(readFileSync(join(process.cwd(),'data/registry/index.json'),'utf8'));const seen=new Set<string>();
 return rows.filter(p=>p.enabled).map(p=>{
  const id=p.serviceId+':'+(p.operation??'');
  if(seen.has(id)||p.registryRevision!=='b6aa0b1696a649a8644929ab1d1e9d641edf2904'||!index.entries.some((e:any)=>e.id===p.serviceId&&e.status!=='hidden'))throw Error('Unknown free operation');seen.add(id);
  return createFreeAdapter(p);
 });
}
