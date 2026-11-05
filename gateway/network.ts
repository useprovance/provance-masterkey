import {lookup} from 'node:dns/promises';
import {request} from 'node:https';
import {isIP} from 'node:net';
export function publicAddress(ip:string){
 if(isIP(ip)===4){const[a,b]=ip.split('.').map(Number);return !(a===0||a===10||a===127||a>=224||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&(b===168||b===0)||a===100&&b>=64&&b<=127||a===198&&(b===18||b===19)||a===192&&b===2||a===198&&b===51||a===203&&b===0);}
 return isIP(ip)===6&&/^[23]/i.test(ip)&&!/^2001:(?:0*:|db8:)/i.test(ip)&&!/^2002:|^3fff:/i.test(ip);
}
export interface JsonRequest {method:'GET'|'POST';body?:Record<string,unknown>;headers?:Record<string,string>;sse?:boolean}
export async function safeRequest(url:string,options:JsonRequest){
 const u=new URL(url);if(u.protocol!=='https:'||u.username||u.password||u.hash||u.port&&u.port!=='443'||isIP(u.hostname))throw Error('HTTPS provider hostname required');
 const addresses=await lookup(u.hostname,{all:true});if(!addresses.length||addresses.some(a=>!publicAddress(a.address)))throw Error('Provider resolved to a non-public address');
 return new Promise<{status:number;headers:Record<string,string>;data:Record<string,any>}>((resolve,reject)=>{
  const first=addresses.find(a=>a.family===4)??addresses[0];const data=options.body===undefined?undefined:Buffer.from(JSON.stringify(options.body));
  const req=request(u,{method:options.method,headers:{Accept:options.sse?'application/json, text/event-stream':'application/json',...(data?{'Content-Type':'application/json','Content-Length':String(data.length)}:{}),...options.headers},lookup:((_h:any,o:any,cb:any)=>o.all?cb(null,[first]):cb(null,first.address,first.family)) as any},res=>{
   let size=0;const parts:Buffer[]=[];res.on('data',chunk=>{size+=chunk.length;if(size>250000){res.destroy(Error('Result too large'));return;}parts.push(chunk);});res.on('error',reject);
   res.on('end',()=>{try{const raw=Buffer.concat(parts).toString();let result;try{result=raw?JSON.parse(raw):{};}catch(error){if(!options.sse)throw error;const frames=raw.split(/\r?\n\r?\n/).map(frame=>frame.split(/\r?\n/).filter(line=>line.startsWith('data:')).map(line=>line.slice(5).trimStart()).join('\n')).filter(Boolean);if(frames.length!==1)throw Error('Expected one MCP result');result=JSON.parse(frames[0]);}if(!result||typeof result!=='object'||Array.isArray(result))throw Error('Expected JSON object');const h:Record<string,string>={};for(const[k,v]of Object.entries(res.headers))if(typeof v==='string')h[k]=v;resolve({status:res.statusCode??500,headers:h,data:result});}catch(e){reject(e);}});
  });const timer=setTimeout(()=>req.destroy(Error('Provider timed out')),30000);req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end(data);
 });
}
export const safeJson=(url:string,body:Record<string,unknown>,headers:Record<string,string>={})=>safeRequest(url,{method:'POST',body,headers});
