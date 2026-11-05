import test from 'node:test';import assert from 'node:assert/strict';
import {generatePrivateKey,privateKeyToAccount} from 'viem/accounts';import {encodeEventTopics,encodeAbiParameters,parseAbi,recoverTypedDataAddress} from 'viem';
import {createEvmAdapter,chooseRequirement,providerPolicy,USDC,types,verifiedTransfer,type Provider,type Evidence} from '../x402';import {publicAddress} from '../network';import {hashRequest} from '../payment';
const key=generatePrivateKey();const account=privateKeyToAccount(key);const payTo='0x1111111111111111111111111111111111111111' as const;
const provider:Provider={serviceId:'fixture',registryRevision:'revision',url:'https://provider.example/search',payTo,maxFeeUsd:'0.1',risk:'read',enabled:true,reviewedAt:'2026-11-02',inputSchema:{type:'object',properties:{query:{type:'string'}},required:['query'],additionalProperties:false}};
const quote={scheme:'exact',network:'eip155:8453',amount:'10000',asset:USDC,payTo,maxTimeoutSeconds:60,extra:{name:'USD Coin',version:'2'}};
const challenge=(requirement:any=quote)=>({x402Version:2,resource:{url:provider.url},accepts:[requirement]});
const request={runId:'run',callKey:'node:0',idempotencyKey:'provance:run:node:0',serviceId:'fixture',registryRevision:'revision',input:{query:'Stellar'},maxCostUsd:'0.05',providerPolicy:providerPolicy(provider),policyHash:hashRequest(providerPolicy(provider))};
const abi=parseAbi(['event Transfer(address indexed from,address indexed to,uint256 value)','event AuthorizationUsed(address indexed authorizer,bytes32 indexed nonce)']);
function receipt(e:Evidence){return{status:'success',logs:[{address:USDC,topics:encodeEventTopics({abi,eventName:'Transfer',args:{from:e.from,to:e.to}}),data:encodeAbiParameters([{type:'uint256'}],[BigInt(e.value)])},{address:USDC,topics:encodeEventTopics({abi,eventName:'AuthorizationUsed',args:{authorizer:e.from,nonce:e.nonce}}),data:'0x'}]};}
function fixture(required:any=challenge(),responseError=false){
 let calls=0,signed:any;let evidence:Evidence|undefined;const saved:Evidence[]=[];
 const client={getChainId:async()=>8453,readContract:async()=>1000000n,waitForTransactionReceipt:async()=>receipt(evidence!)};
 const fetch=async(_url:string,_body:any,headers:any={})=>{calls++;if(!headers['PAYMENT-SIGNATURE'])return{status:402,headers:{'payment-required':Buffer.from(JSON.stringify(required)).toString('base64')},data:{}};signed=JSON.parse(Buffer.from(headers['PAYMENT-SIGNATURE'],'base64').toString());if(responseError)throw Error('Provider timed out');return{status:200,headers:{'payment-response':Buffer.from(JSON.stringify({network:'eip155:8453',transaction:'0x'+'a'.repeat(64)})).toString('base64')},data:{answer:'ok'}};};
 const adapter=createEvmAdapter(provider,key,'https://rpc.example',{client,fetch:fetch as any});
 return{adapter,context:{evidence:async(e:any)=>{evidence=e;saved.push({...e});}},stats:()=>({calls,signed,saved}),client};
}
test('signed transfer is exact, one-use, recipient-bound and below both fee ceilings',async()=>{
 const f=fixture();const result=await f.adapter.execute(request,f.context);assert.equal(result.totalFeeUsd,'0.010000');assert.equal(result.status,'succeeded');assert.equal(f.stats().calls,2);assert.equal(f.stats().saved.length,2);
 const auth=f.stats().signed.payload.authorization;assert.equal(auth.value,'10000');assert.equal(auth.to,payTo);assert(Number(auth.validBefore)-Number(auth.validAfter)<=65);
 const signer=await recoverTypedDataAddress({domain:{name:'USD Coin',version:'2',chainId:8453,verifyingContract:USDC},types,primaryType:'TransferWithAuthorization',message:{...auth,value:BigInt(auth.value),validAfter:BigInt(auth.validAfter),validBefore:BigInt(auth.validBefore)},signature:f.stats().signed.payload.signature});assert.equal(signer.toLowerCase(),account.address.toLowerCase());
});
test('changed quote or recipient never sends a signed payment',async()=>{
 for(const change of [{amount:'50001'},{payTo:'0x2222222222222222222222222222222222222222'},{network:'eip155:1'},{asset:'0x'+'3'.repeat(40)},{extra:{name:'USD Coin',version:'2',assetTransferMethod:'permit2'}}]){const f=fixture(challenge({...quote,...change}));const r=await f.adapter.execute(request,f.context);assert.equal(r.totalFeeUsd,'0');assert.equal(r.status,'failed_no_charge');assert.equal(f.stats().calls,1);assert.equal(f.stats().saved.length,0);}
});
test('a timeout after transmitting authorization never retries or pretends the call was free',async()=>{
 const f=fixture(challenge(),true);await assert.rejects(f.adapter.execute(request,f.context),/timed out/);assert.equal(f.stats().calls,2);assert.equal(f.stats().saved.length,1);
});
test('schema rejection happens before any provider request',async()=>{const f=fixture();const r=await f.adapter.execute({...request,input:{query:'x',secret:'do not send'}},f.context);assert.equal(r.status,'failed_no_charge');assert.equal(f.stats().calls,0);});
test('the signer refuses a transplanted policy before contacting the provider',async()=>{const f=fixture();const result=await f.adapter.execute({...request,providerPolicy:{...request.providerPolicy,payTo:'0x2222222222222222222222222222222222222222'}},f.context);assert.equal(result.status,'failed_no_charge');assert.equal(f.stats().calls,0);assert.equal(f.stats().saved.length,0);});
test('only explicitly reviewed optional discovery/identity hints may be ignored',()=>{
 const config={...provider,ignoredExtensions:['bazaar','agentkit'] as ('bazaar'|'agentkit')[]};
 assert.equal(chooseRequirement({...challenge(),extensions:{bazaar:{info:{}},agentkit:{info:{statement:'ignore me'}}}},config,'0.05').amount,'10000');
 assert.throws(()=>chooseRequirement({...challenge(),extensions:{delegation:{}}},config,'0.05'));
 assert.throws(()=>chooseRequirement({...challenge(),extensions:{agentkit:{required:true}}},config,'0.05'));
 assert.throws(()=>chooseRequirement({...challenge(),extensions:{bazaar:{}}},provider,'0.05'));
});
test('settlement requires matching authorization nonce and exact recipient transfer',()=>{
 const e={network:'eip155:8453',asset:USDC,from:account.address,to:payTo,value:'10000',nonce:'0x'+'4'.repeat(64),validAfter:'1',validBefore:'2'} as Evidence;assert(verifiedTransfer(receipt(e),e));assert(!verifiedTransfer(receipt(e),{...e,value:'20000'}));assert(!verifiedTransfer(receipt(e),{...e,nonce:('0x'+'5'.repeat(64)) as any}));
});
test('SSRF filter refuses internal, mapped, link-local, loopback and reserved addresses',()=>{
 for(const ip of ['127.0.0.1','10.0.0.1','169.254.169.254','172.31.0.1','192.168.0.1','100.100.1.1','0.0.0.0','::1','::ffff:127.0.0.1','fc00::1','fe80::1','2002:7f00:1::','2001:db8::1'])assert.equal(publicAddress(ip),false,ip);
 assert(publicAddress('8.8.8.8'));assert(publicAddress('2606:4700::1111'));
});
