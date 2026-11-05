import { createHash } from 'node:crypto';

export interface ServiceRequest {
  runId:string;serviceId:string;operation?:string;registryRevision:string;input:Record<string,unknown>;maxCostUsd:string;callKey:string;idempotencyKey:string;
  policyHash: string; providerPolicy: ProviderPolicy;
}
export interface PaidProviderPolicy {
  version: 1; serviceId: string; operation?: string; registryRevision: string;
  network: 'eip155:8453'; asset: string; scheme: 'exact'; url: string; method: 'POST';
  payTo: string; maxFeeUsd: string; inputSchema: object; risk: 'read'; reviewedAt: string;
  ignoredExtensions: ('bazaar'|'agentkit')[];
}
export interface FreeProviderPolicy {
  version: 2; serviceId: string; operation?: string; registryRevision: string;
  network: null; asset: null; scheme: 'free'; payTo: null; maxFeeUsd: '0';
  url: string; method: 'GET'|'POST'; adapter: 'blockrun-json-v1'|'exa-mcp-search-v1'|'guardrail-json-v1';
  inputSchema: object; risk: 'read'; reviewedAt: string;
}
export type ProviderPolicy = PaidProviderPolicy | FreeProviderPolicy;
export function canonical(value:unknown):string {
  if(value===null||typeof value!=='object')return JSON.stringify(value);
  if(Array.isArray(value))return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical((value as Record<string,unknown>)[key])}`).join(',')}}`;
}
export const hashRequest=(value:unknown)=>createHash('sha256').update(canonical(value)).digest('hex');
export function micros(value:string):bigint {
  if(!/^(?:0|[1-9]\d{0,13})(?:\.\d{1,6})?$/.test(value))throw Error('Invalid exact fee');
  const [whole,fraction='']=value.split('.');return BigInt(whole)*1000000n+BigInt(fraction.padEnd(6,'0'));
}
export interface VerifiedResult {status:'succeeded'|'charged_error'|'failed_no_charge';totalFeeUsd:string;receiptId:string|null;result:Record<string,unknown>}
export interface CertifiedAdapter {
  serviceId:string;operation?:string;registryRevision:string;
  policy: ProviderPolicy;
  // Implementations must enforce the ceiling at authorization, not only inspect a quote.
  execute(request:ServiceRequest,context?:{evidence(value:Record<string,unknown>):Promise<void>}):Promise<VerifiedResult>;
}
// No environment variable can silently certify an unbounded paidFetch adapter.
export const certifiedAdapters: readonly CertifiedAdapter[] = Object.freeze([]);
export function matchesPolicy(adapter: CertifiedAdapter, request: ServiceRequest): boolean {
  return adapter.serviceId === request.serviceId && adapter.operation === request.operation
    && adapter.registryRevision === request.registryRevision && !!request.providerPolicy
    && hashRequest(adapter.policy) === request.policyHash && hashRequest(request.providerPolicy) === request.policyHash;
}
export function validateResult(result:VerifiedResult,maximum:string){
  const actual=micros(result.totalFeeUsd);
  if(actual>micros(maximum))throw Error('Provider exceeded the authorized ceiling; reconciliation required');
  if(actual>0&&!result.receiptId)throw Error('Missing payment receipt');
  if(!['succeeded','charged_error','failed_no_charge'].includes(result.status)||(result.status==='failed_no_charge'&&actual!==0n))throw Error('Invalid payment outcome');
  if(!result.result||Array.isArray(result.result)||typeof result.result!=='object'||Buffer.byteLength(JSON.stringify(result))>250000)throw Error('Invalid service result');
  return result;
}
