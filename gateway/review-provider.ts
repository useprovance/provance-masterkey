/** Unpaid quote review only. This entry point never loads a wallet or sends authorization. */
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {safeJson} from './network';
import {chooseRequirement,amountUsd,type Provider} from './x402';
import {hashRequest} from './payment';
import Ajv from 'ajv';

async function main() {
 const args=process.argv.slice(2);const options:Record<string,string>={};
 for(let i=0;i<args.length;i+=2){if(!['--manifest','--service','--input','--output'].includes(args[i])||!args[i+1])throw Error('Use --manifest file --service id --input file [--output file]');options[args[i]]=args[i+1];}
 if(!options['--manifest']||!options['--service']||!options['--input'])throw Error('An explicit manifest, service and input file are required');
 const providers=JSON.parse(readFileSync(resolve(options['--manifest']),'utf8')) as Provider[];
 const provider=providers.find(p=>p.serviceId===options['--service']);
 if(!provider||provider.risk!=='read')throw Error('Only an explicitly reviewed read-only candidate can be quoted');
 const input=JSON.parse(readFileSync(resolve(options['--input']),'utf8'));
 if(!input||typeof input!=='object'||Array.isArray(input)||Buffer.byteLength(JSON.stringify(input))>256000)throw Error('Input must be an object under 256KB');
 if(!new Ajv({strict:true,validateFormats:false}).compile(provider.inputSchema)(input))throw Error('Input does not match the candidate schema');
 const response=await safeJson(provider.url,input as Record<string,unknown>);
 if(response.status!==402||!response.headers['payment-required']||response.headers['payment-required'].length>20000)throw Error('Provider did not return a supported unpaid x402 quote');
 const challenge=JSON.parse(Buffer.from(response.headers['payment-required'],'base64').toString());
 const quote=chooseRequirement(challenge,provider,provider.maxFeeUsd);
 const report={status:'unpaid_quote_verified',observedAt:new Date().toISOString(),serviceId:provider.serviceId,url:provider.url,inputHash:hashRequest(input),network:quote.network,asset:quote.asset,payTo:quote.payTo,amountUsd:amountUsd(BigInt(quote.amount)),maximumUsd:provider.maxFeeUsd,maxTimeoutSeconds:quote.maxTimeoutSeconds,ignoredExtensions:Object.keys(challenge.extensions??{}),paidSettlementVerified:false};
 const output=JSON.stringify(report,null,2)+'\n';if(options['--output'])writeFileSync(resolve(options['--output']),output);process.stdout.write(output);
}
void main().catch(error=>{console.error(error instanceof Error?error.message:'Quote review failed');process.exitCode=1;});
