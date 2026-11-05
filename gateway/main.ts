import { createPublicKey } from 'node:crypto';
import { createGateway } from './server';
import {loadAdapters} from './providers';
import {loadFreeAdapters} from './free';
import {reconcileEvidence} from './x402';
import { postgresLedger } from './ledger';
const publicKey=process.env.MASTERKEY_GATEWAY_PUBLIC_KEY;
if(!publicKey)throw Error('MASTERKEY_GATEWAY_PUBLIC_KEY is required');
if(createPublicKey(publicKey.replace(/\\n/g,'\n')).asymmetricKeyType!=='ed25519')throw Error('An Ed25519 gateway public key is required');
const audience=(process.env.MASTERKEY_GATEWAY_URL??'http://127.0.0.1:4010').replace(/\/+$/,'');
const parsedOrigin=new URL(audience);
if(parsedOrigin.origin!==audience||(process.env.NODE_ENV==='production'&&parsedOrigin.protocol!=='https:'))throw Error('Configure a canonical HTTPS gateway audience in production');
const ledger=process.env.MASTERKEY_GATEWAY_DATABASE_URL?postgresLedger(process.env.MASTERKEY_GATEWAY_DATABASE_URL):undefined;
async function main(){
  if(ledger)await ledger.check();
  if(process.env.NODE_ENV==='production'&&!ledger)throw Error('A restricted gateway database connection is required in production');
  const server=createGateway({publicKey:publicKey!,issuer:process.env.MASTERKEY_GATEWAY_ISSUER??'provance-api',audience,ledger,adapters:[...loadAdapters(),...loadFreeAdapters()]});
  server.requestTimeout=15000;server.headersTimeout=10000;
  const port=Number(process.env.MASTERKEY_GATEWAY_PORT??4010);
  server.listen(port,process.env.MASTERKEY_GATEWAY_HOST??'127.0.0.1',()=>console.log(`Provance Masterkey gateway listening on ${port}; bounded payment policy enforced`));
  let reconciling=false;const reconcileTimer=setInterval(()=>{if(reconciling||!ledger)return;reconciling=true;void(async()=>{for(const call of await ledger.pending!()){try{if(call.payment_evidence&&!process.env.BASE_RPC_URL)continue;const result=call.payment_evidence?await reconcileEvidence(call.payment_evidence,process.env.BASE_RPC_URL!):await ledger.closeUnsent!(call.owner_id,call.id,call.request_hash);if(result)await ledger.complete(call.owner_id,call.id,call.request_hash,result);}catch{/* Keep uncertain holds; never retry payment. */}}})().catch(()=>{}).finally(()=>{reconciling=false;});},30000);
  for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{clearInterval(reconcileTimer);server.close(()=>{void ledger?.close().finally(()=>process.exit(0));if(!ledger)process.exit(0);});});
}
void main().catch(()=>{console.error('Gateway startup failed. Check restricted database access and configuration.');process.exitCode=1;});
