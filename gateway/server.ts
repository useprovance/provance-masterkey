import { createServer, type IncomingMessage, type Server } from 'node:http';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyToken } from './auth';
import { certifiedAdapters, hashRequest, matchesPolicy, validateResult, type CertifiedAdapter } from './payment';
import {reconcileEvidence} from './x402';
import type { Ledger } from './ledger';

interface Options {publicKey:string;issuer:string;audience:string;ledger?:Ledger;adapters?:readonly CertifiedAdapter[]}
const revision='b6aa0b1696a649a8644929ab1d1e9d641edf2904';
export const reason='Catalog access is ready. Paid execution is disabled until a payment adapter enforces the per-call ceiling.';
async function body(req:IncomingMessage){
  let size=0;const parts:Buffer[]=[];
  for await(const part of req){size+=part.length;if(size>16384)throw Error('Request too large');parts.push(part);}
  return JSON.parse(Buffer.concat(parts).toString());
}
export function createGateway(options:Options):Server {
  // This process never starts upstream Next/CDP/OAuth/agent routes or imports its wallet.
  const index=JSON.parse(readFileSync(join(process.cwd(),'data/registry/index.json'),'utf8')) as {syncedAt:string;entries:{id:string;name:string;description?:string;category:string;status:string}[]};
  const entries=index.entries.filter(s=>s.status!=='hidden');
  const adapters=options.adapters??certifiedAdapters;
  const paidAdapters=adapters.filter(a=>a.policy.scheme!=='free');
  return createServer(async(req,res)=>{
    const send=(status:number,data:unknown)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(data));};
    let url:URL;try{url=new URL(req.url??'/', 'http://gateway.internal');}catch{send(400,{error:'Invalid URL'});return;}
    if(req.method==='GET'&&url.pathname==='/health'){send(200,{status:'ok',service:'provance-masterkey-gateway',paymentsConfigured:paidAdapters.length>0,freeOperations:adapters.length-paidAdapters.length,ledgerConfigured:!!options.ledger});return;}
    if(req.method==='GET'&&url.pathname==='/ready'){try{if(!options.ledger?.health)throw Error();await options.ledger.health();send(200,{ready:true});}catch{send(503,{ready:false});}return;}
    let identity;
    try{identity=verifyToken(req.headers.authorization,{publicKey:options.publicKey,issuer:options.issuer,audience:options.audience});}catch{send(401,{error:'Unauthorized'});return;}
    try{
      if(req.method==='GET'&&url.pathname==='/v1/capabilities'&&identity.scope==='catalog:read'){
        const service=url.searchParams.get('serviceId');const operation=url.searchParams.get('operation')??undefined;
        const operating=options.ledger?.health?await options.ledger.health():{enabled:true,freeExecutionVersion:undefined};
        const adapter=adapters.find(a=>a.serviceId===service&&a.operation===operation&&a.registryRevision===revision);
        const ready=(a:CertifiedAdapter)=>a.policy.scheme==='free'?operating.freeExecutionVersion===1:operating.enabled;
        const executable=!!adapter&&ready(adapter);
        const operations=adapters.map(a=>({serviceId:a.serviceId,...(a.operation?{operation:a.operation}:{}),registryRevision:a.registryRevision,policyHash:hashRequest(a.policy),billing:a.policy.scheme==='free'?'free':'paid',executable:ready(a),state:ready(a)?'certified':'temporarily_unavailable',reason:ready(a)?a.policy.scheme==='free'?'Free service ready for input approval':'Reviewed operation ready for approval':a.policy.scheme==='free'?'Free-service database setup is required':'Provider payments are paused'}));
        send(200,{protocol:'provance-gateway-v1',serviceCount:entries.length,registryRevision:revision,enabledOperations:operations.filter(a=>a.executable).length,paymentsEnabled:operating.enabled&&adapters.some(a=>a.policy.scheme!=='free'),executable,operations,...(adapter?{policy:adapter.policy,policyHash:hashRequest(adapter.policy)}:{}),reason:adapter?operations.find(a=>a.serviceId===adapter.serviceId&&a.operation===adapter.operation)?.reason:operations.some(a=>a.executable)?'Reviewed free services are available; paid services remain paused':!operating.enabled?'Provider payments are paused':'This operation is catalog-only until its provider is reviewed and enabled'});return;
      }
      if(req.method==='GET'&&url.pathname==='/v1/services'&&identity.scope==='catalog:read'){
        const q=(url.searchParams.get('q')??'').toLowerCase().slice(0,200);
        const offset=Math.max(0,Math.min(entries.length,Number(url.searchParams.get('offset'))||0));
        const matching=entries.filter(e=>`${e.name} ${e.description??''} ${e.category}`.toLowerCase().includes(q));
        send(200,{total:matching.length,revision,services:matching.slice(offset,offset+50).map(e=>({...e,availability:'catalog_only'}))});return;
      }
      if(req.method==='POST'&&url.pathname==='/v1/reconcile'&&identity.scope==='call:reconcile'){
        if(!options.ledger){send(503,{error:'Reconciliation is not configured'});return;}
        const input=await body(req);if(input.callId!==identity.callId||input.requestHash!==identity.requestHash||Object.keys(input).some(k=>!['callId','requestHash','transactionHash'].includes(k))||input.transactionHash&&!/^0x[0-9a-fA-F]{64}$/.test(input.transactionHash)){send(403,{error:'Call authorization mismatch'});return;}
        const current=await options.ledger.status(identity.sub,input.callId,input.requestHash);if(current.result){send(200,current.result);return;}
        if(!current.evidence){if(!options.ledger.closeUnsent){send(409,{error:'Unsent-dispatch recovery is unavailable'});return;}send(200,await options.ledger.closeUnsent(identity.sub,input.callId,input.requestHash));return;}
        if(!process.env.BASE_RPC_URL){send(503,{error:'Settlement RPC is not configured; hold retained'});return;}
        const result=await reconcileEvidence(current.evidence,process.env.BASE_RPC_URL,input.transactionHash);
        if(!result){send(202,{status:'unknown',message:'Settlement is not yet proven; hold retained'});return;}
        await options.ledger.complete(identity.sub,input.callId,input.requestHash,result);send(200,result);return;
      }
      if(url.pathname==='/v1/free'&&identity.scope!=='free:execute'){send(403,{error:'Free execution scope required'});return;}
      if(req.method==='POST'&&url.pathname==='/v1/free'&&identity.scope==='free:execute'){
        const input=await body(req);
        if(input.runId!==identity.callId||hashRequest(input)!==identity.requestHash||input.maxCostUsd!=='0'||input.providerPolicy?.scheme!=='free'){send(403,{error:'Free call authorization mismatch'});return;}
        const adapter=adapters.find(a=>a.policy.scheme==='free'&&matchesPolicy(a,input));
        if(!adapter){send(409,{error:'Reviewed free operation changed or is unavailable'});return;}
        if(!options.ledger?.claimFree||!options.ledger.completeFree){send(503,{error:'Free-call persistence is unavailable'});return;}
        const claim=await options.ledger.claimFree(identity.sub,identity.requestHash!,input);
        if(claim.result){send(200,claim.result);return;}
        if(!claim.execute){send(202,{status:claim.status});return;}
        const result=validateResult(await adapter.execute(input),'0');
        if(result.receiptId!==null||result.totalFeeUsd!=='0'||result.status==='charged_error')throw Error('Free adapter violated its zero-fee policy');
        await options.ledger.completeFree(identity.sub,identity.requestHash!,input,result);send(200,result);return;
      }
      if(identity.scope!=='call:execute'){send(403,{error:'Scope not permitted'});return;}
      if(req.method==='GET'&&url.pathname===`/v1/calls/${identity.callId}`){
        if(!options.ledger){send(503,{error:'Ledger unavailable'});return;}
        send(200,await options.ledger.status(identity.sub,identity.callId!,identity.requestHash!));return;
      }
      if(req.method!=='POST'||url.pathname!=='/v1/calls'){send(404,{error:'Not found'});return;}
      const input=await body(req);
      if(!input||Object.keys(input).sort().join(',')!=='callId,requestHash'||input.callId!==identity.callId||input.requestHash!==identity.requestHash){send(403,{error:'Call authorization mismatch'});return;}
      if(!options.ledger){send(503,{error:'Ledger unavailable'});return;}
      // Refuse BEFORE claiming/dispatching a reservation when this release has no bounded adapters.
      if(paidAdapters.length===0){send(409,{error:reason});return;}
      const prior=await options.ledger.status(identity.sub,input.callId,input.requestHash);
      if(prior.result){send(200,prior.result);return;}
      const pending=prior.request;
      if(prior.status==='pending'&&(!pending||hashRequest(pending)!==input.requestHash||!paidAdapters.some(a=>matchesPolicy(a,pending)))){send(409,{error:'Approved provider policy changed or operation is unavailable. Start a new run for a new approval.'});return;}
      const claim=await options.ledger.claim(identity.sub,input.callId,input.requestHash);
      if(!claim.execute){send(202,{status:claim.status,result:claim.result});return;}
      const request=claim.request!;
      try{
        if(hashRequest(request)!==input.requestHash)throw Error('Persisted input hash mismatch');
        const adapter=paidAdapters.find(a=>matchesPolicy(a,request));
        if(!adapter)throw Error('Operation is not certified');
        const result=validateResult(await adapter.execute(request,{evidence:async value=>{if(!options.ledger?.evidence)throw Error('Durable payment evidence storage unavailable');await options.ledger.evidence(identity.sub,input.callId,input.requestHash,value);}}),request.maxCostUsd);
        await options.ledger.complete(identity.sub,input.callId,input.requestHash,result);
        send(200,result);
      }catch{
        const final=await options.ledger.status(identity.sub,input.callId,input.requestHash).catch(()=>null);
        if(final?.result){send(200,final.result);return;}
        await options.ledger.unknown(identity.sub,input.callId,input.requestHash).catch(()=>{});
        send(502,{error:'Dispatched call outcome is uncertain. Reservation retained; do not retry payment.'});
      }
    }catch{send(503,{error:'Gateway request could not be processed safely. No automatic retry was performed.'});}
  });
}
