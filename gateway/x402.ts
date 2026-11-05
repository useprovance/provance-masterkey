import {randomBytes} from 'node:crypto';
import {createPublicClient,http,parseAbi,decodeEventLog,type Hex} from 'viem';
import {privateKeyToAccount} from 'viem/accounts';
import {base} from 'viem/chains';
import Ajv from 'ajv';
import {micros,hashRequest,type PaidProviderPolicy,type CertifiedAdapter,type ServiceRequest,type VerifiedResult} from './payment';
import {safeJson} from './network';
export const USDC='0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' as const;
export const types={TransferWithAuthorization:[{name:'from',type:'address'},{name:'to',type:'address'},{name:'value',type:'uint256'},{name:'validAfter',type:'uint256'},{name:'validBefore',type:'uint256'},{name:'nonce',type:'bytes32'}]} as const;
export interface Provider {serviceId:string;operation?:string;registryRevision:string;url:string;payTo:Hex;maxFeeUsd:string;inputSchema:object;risk:'read';enabled:boolean;reviewedAt:string;ignoredExtensions?:('bazaar'|'agentkit')[]}
export function providerPolicy(config: Provider): PaidProviderPolicy {
 return {version:1,serviceId:config.serviceId,...(config.operation?{operation:config.operation}:{}),registryRevision:config.registryRevision,
  network:'eip155:8453',asset:USDC.toLowerCase(),scheme:'exact',url:config.url,method:'POST',payTo:config.payTo.toLowerCase(),
  maxFeeUsd:config.maxFeeUsd,inputSchema:config.inputSchema,risk:config.risk,reviewedAt:config.reviewedAt,ignoredExtensions:config.ignoredExtensions??[]};
}
export type Evidence={network:'eip155:8453';asset:typeof USDC;from:Hex;to:Hex;value:string;validAfter:string;validBefore:string;nonce:Hex;transaction?:Hex};
const abi=parseAbi(['function balanceOf(address) view returns (uint256)','function authorizationState(address,bytes32) view returns (bool)','event Transfer(address indexed from,address indexed to,uint256 value)','event AuthorizationUsed(address indexed authorizer,bytes32 indexed nonce)']);
const domain={name:'USD Coin',version:'2',chainId:8453,verifyingContract:USDC} as const;
export function chooseRequirement(data:any,config:Provider,maximum:string){
 if(data.x402Version!==2||data.resource?.url!==config.url)throw Error('Unsupported payment challenge');
 if(data.extensions){
  if(typeof data.extensions!=='object'||Array.isArray(data.extensions)||Object.entries(data.extensions).some(([key,value]:[string,any])=>!(config.ignoredExtensions??[]).includes(key as any)||!value||typeof value!=='object'||Array.isArray(value)||value.required===true))throw Error('Unsupported payment extension');
  // Explicitly ignore discovery and optional human-identity discounts. Never sign,
  // follow, register or forward their instructions; use the standard exact quote.
 }
 const matches=(Array.isArray(data.accepts)?data.accepts:[]).filter((r:any)=>r.scheme==='exact'&&r.network==='eip155:8453'&&String(r.asset).toLowerCase()===USDC.toLowerCase()&&String(r.payTo).toLowerCase()===config.payTo.toLowerCase()&&/^\d{1,30}$/.test(r.amount)&&r.extra?.name==='USD Coin'&&r.extra?.version==='2'&&(!r.extra?.assetTransferMethod||r.extra.assetTransferMethod==='eip3009'));
 matches.sort((a:any,b:any)=>BigInt(a.amount)<BigInt(b.amount)?-1:1);
 const quote=matches[0];if(!quote||BigInt(quote.amount)<=0n||BigInt(quote.amount)>micros(maximum)||BigInt(quote.amount)>micros(config.maxFeeUsd)||!Number.isInteger(quote.maxTimeoutSeconds)||quote.maxTimeoutSeconds<1||quote.maxTimeoutSeconds>120)throw Error('Payment requirement exceeds policy');
 return quote;
}
export function verifiedTransfer(receipt:any,evidence:Evidence){
 if(receipt.status!=='success')return false;let nonce=false,transfer=false;
 for(const log of receipt.logs??[]){if(String(log.address).toLowerCase()!==USDC.toLowerCase())continue;try{const event=decodeEventLog({abi,data:log.data,topics:log.topics}) as any;if(event.eventName==='AuthorizationUsed'&&event.args.authorizer.toLowerCase()===evidence.from.toLowerCase()&&event.args.nonce.toLowerCase()===evidence.nonce.toLowerCase())nonce=true;if(event.eventName==='Transfer'&&event.args.from.toLowerCase()===evidence.from.toLowerCase()&&event.args.to.toLowerCase()===evidence.to.toLowerCase()&&event.args.value===BigInt(evidence.value))transfer=true;}catch{}}
 return nonce&&transfer;
}
export const amountUsd=(amount:bigint)=>`${amount/1000000n}.${String(amount%1000000n).padStart(6,'0')}`;
export function createEvmAdapter(config:Provider,key:Hex,rpcUrl:string,dependencies?:{fetch?:typeof safeJson;client?:any;account?:any}):CertifiedAdapter{
 const rpc=new URL(rpcUrl);if(rpc.protocol!=='https:')throw Error('Payment RPC must use HTTPS');
 const account=dependencies?.account??privateKeyToAccount(key);const client=dependencies?.client??createPublicClient({chain:base,transport:http(rpcUrl,{retryCount:0,timeout:8000})});const fetchProvider=dependencies?.fetch??safeJson;
 const ajv=new Ajv({strict:true,allErrors:false,validateFormats:false});const validate=ajv.compile(config.inputSchema);
 const policy=providerPolicy(config);
 return {...config,policy,execute:async(request:ServiceRequest,context)=>{
  let sent=false;
  try{
   if(request.policyHash!==hashRequest(policy)||hashRequest(request.providerPolicy)!==request.policyHash)throw Error('Approved provider policy changed');
   if(!validate(request.input))throw Error('Input does not match the reviewed provider schema');
   if(await client.getChainId()!==8453)throw Error('Wrong payment network');
   const unpaid=await fetchProvider(config.url,request.input);
   if(unpaid.status!==402)throw Error('Expected a payment challenge; refusing automatic fallback');
   const required=unpaid.headers['payment-required'];if(!required||required.length>20000)throw Error('Missing bounded payment challenge');
   const challenge=JSON.parse(Buffer.from(required,'base64').toString());const quote=chooseRequirement(challenge,config,request.maxCostUsd);
   if(await client.readContract({address:USDC,abi,functionName:'balanceOf',args:[account.address]})<BigInt(quote.amount))throw Error('Platform fee wallet has insufficient USDC');
   const now=Math.floor(Date.now()/1000);const authorization:Evidence={network:'eip155:8453',asset:USDC,from:account.address,to:config.payTo,value:quote.amount,validAfter:String(now-5),validBefore:String(now+Math.min(60,quote.maxTimeoutSeconds)),nonce:`0x${randomBytes(32).toString('hex')}`};
   const signature=await account.signTypedData({domain,types,primaryType:'TransferWithAuthorization',message:{from:authorization.from,to:authorization.to,value:BigInt(authorization.value),validAfter:BigInt(authorization.validAfter),validBefore:BigInt(authorization.validBefore),nonce:authorization.nonce}});
   if(!context)throw Error('Durable evidence persistence required');await context.evidence({...authorization});
   const payload={x402Version:2,resource:challenge.resource,accepted:quote,payload:{signature,authorization:{from:authorization.from,to:authorization.to,value:authorization.value,validAfter:authorization.validAfter,validBefore:authorization.validBefore,nonce:authorization.nonce}}};
   // One signed authorization, one HTTP attempt. No price negotiation or payment retry.
   sent=true;const response=await fetchProvider(config.url,request.input,{'PAYMENT-SIGNATURE':Buffer.from(JSON.stringify(payload)).toString('base64')});
   const encoded=response.headers['payment-response'];if(!encoded||encoded.length>20000)throw Error('Missing settlement evidence');const settlement=JSON.parse(Buffer.from(encoded,'base64').toString());
   if(settlement.network!=='eip155:8453'||!/^0x[0-9a-fA-F]{64}$/.test(settlement.transaction))throw Error('Invalid settlement reference');
   authorization.transaction=settlement.transaction;await context.evidence({...authorization});
   const receipt=await client.waitForTransactionReceipt({hash:settlement.transaction,confirmations:2,timeout:15000});if(!verifiedTransfer(receipt,authorization))throw Error('Settlement did not match authorization');
   return{status:response.status>=200&&response.status<300?'succeeded':'charged_error',totalFeeUsd:amountUsd(BigInt(quote.amount)),receiptId:`eip155:8453:${settlement.transaction}:${authorization.nonce}`,result:response.data};
  }catch(error){if(sent)throw error;return{status:'failed_no_charge',totalFeeUsd:'0',receiptId:null,result:{error:'Provider preflight failed before payment; check the input and service configuration'}};}
 }};
}
export async function reconcileEvidence(evidence:Evidence,rpcUrl:string,transaction?:Hex):Promise<VerifiedResult|null>{
 const client=createPublicClient({chain:base,transport:http(rpcUrl,{retryCount:0,timeout:8000})});if(await client.getChainId()!==8453)throw Error('Wrong payment network');
 const hash=transaction??evidence.transaction;
 if(hash){const r=await client.getTransactionReceipt({hash});const final=await client.getBlock({blockTag:'finalized'});if(r.blockNumber<=final.number&&verifiedTransfer(r,evidence))return{status:'charged_error',totalFeeUsd:amountUsd(BigInt(evidence.value)),receiptId:`eip155:8453:${hash}:${evidence.nonce}`,result:{error:'Payment confirmed during reconciliation; provider response was not recovered'}};}
 const final=await client.getBlock({blockTag:'finalized'});
 if(final.timestamp>BigInt(evidence.validBefore)&&!await client.readContract({address:USDC,abi,functionName:'authorizationState',args:[evidence.from,evidence.nonce],blockNumber:final.number}))return{status:'failed_no_charge',totalFeeUsd:'0',receiptId:null,result:{error:'Authorization expired unused at a finalized block'}};
 return null;
}
