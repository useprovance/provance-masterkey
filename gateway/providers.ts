import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {createEvmAdapter,type Provider} from './x402';
import {micros,type CertifiedAdapter} from './payment';
export function loadAdapters():CertifiedAdapter[]{
 const configs=JSON.parse(readFileSync(join(process.cwd(),'gateway/providers.json'),'utf8')) as Provider[];
 if(!Array.isArray(configs))throw Error('Invalid provider manifest');
 const enabled=configs.filter(p=>p.enabled);
 if(configs.some(p=>p.ignoredExtensions!==undefined&&(!Array.isArray(p.ignoredExtensions)||p.ignoredExtensions.some(e=>!['bazaar','agentkit'].includes(e)))))throw Error('Unreviewed payment extension policy');
 if(!enabled.length)return[];
 if(!/^0x[0-9a-fA-F]{64}$/.test(process.env.MASTERKEY_FEE_PRIVATE_KEY??'')||!process.env.BASE_RPC_URL)throw Error('Configure the dedicated fee payer and Base RPC before enabling providers');
 const seen=new Set();const index=JSON.parse(readFileSync(join(process.cwd(),'data/registry/index.json'),'utf8'));
 for(const p of enabled){const url=new URL(p.url);const id=p.serviceId+':'+(p.operation??'');if(p.risk!=='read'||!/^0x[0-9a-fA-F]{40}$/.test(p.payTo)||url.protocol!=='https:'||url.username||url.password||url.hash||url.port||!p.inputSchema||!Number.isFinite(Date.parse(p.reviewedAt))||!index.entries.some((e:any)=>e.id===p.serviceId&&e.status!=='hidden')||p.registryRevision!=='b6aa0b1696a649a8644929ab1d1e9d641edf2904'||seen.has(id)||micros(p.maxFeeUsd)<=0n)throw Error('Provider manifest is not reviewed/valid');seen.add(id);}
 return enabled.map(p=>createEvmAdapter(p,process.env.MASTERKEY_FEE_PRIVATE_KEY as `0x${string}`,process.env.BASE_RPC_URL!));
}
