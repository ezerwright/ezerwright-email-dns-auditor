import test from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import {once} from 'node:events';
import {Resolver} from 'node:dns/promises';
import {auditEmailDns} from '../scripts/auditor.mjs';

// No upstream forwarding. All packets stay on loopback; fixture names never resolve publicly.
async function withDns(answer,run) {
  const server=dgram.createSocket('udp4');
  const asked=[];
  server.on('message',(request,peer)=>{
    let pos=12;const labels=[];
    while(request[pos]) {const len=request[pos++];labels.push(request.subarray(pos,pos+len).toString('ascii'));pos+=len;}
    pos++;const type=request.readUInt16BE(pos);const question=request.subarray(12,pos+4);
    const name=labels.join('.');asked.push([type,name]);
    const reply=answer(type,name);
    if(reply===null) return; // deliberate dropped packet for cancellation test
    const header=Buffer.alloc(12);request.copy(header,0,0,2);header.writeUInt16BE(0x8180|(reply.rcode??0),2);header.writeUInt16BE(1,4);header.writeUInt16BE(reply.body?1:0,6);
    let record=Buffer.alloc(0);
    if(reply.body) {record=Buffer.alloc(12);record.writeUInt16BE(0xc00c,0);record.writeUInt16BE(type,2);record.writeUInt16BE(1,4);record.writeUInt32BE(60,6);record.writeUInt16BE(reply.body.length,10);record=Buffer.concat([record,reply.body]);}
    server.send(Buffer.concat([header,question,record]),peer.port,peer.address);
  });
  server.bind(0,'127.0.0.1');await once(server,'listening');
  const resolver=new Resolver({timeout:1000,tries:1});resolver.setServers([`127.0.0.1:${server.address().port}`]);
  try {await run(resolver,asked);} finally {resolver.cancel();await new Promise(resolve=>server.close(resolve));}
}
const txt=(...chunks)=>({body:Buffer.concat(chunks.map(s=>{const b=Buffer.from(s);return Buffer.concat([Buffer.from([b.length]),b]);}))});

test('real Node DNS: split TXT, null MX, explicit selector and exact query budget',async()=>{
  await withDns((type,name)=>type===15?{body:Buffer.from([0,0,0])}:name==='_dmarc.example.com'?txt('v=DMARC1; p=reject; pct=0'):name==='s.one._domainkey.example.com'?txt('v=DKIM1; p='):txt('v=spf1 ','-all'),async(resolver,asked)=>{
    const a=await auditEmailDns('example.com',{authorized:true,selectors:['s.one'],resolver});
    assert.equal(a.checks.mx.status,'null-mx');assert.equal(a.checks.spf.record,'v=spf1 -all');assert.equal(a.checks.dmarc.percentage,0);assert.equal(a.checks.dkim.selectors[0].status,'revoked');
    assert.deepEqual(asked,[[15,'example.com'],[16,'example.com'],[16,'_dmarc.example.com'],[16,'s.one._domainkey.example.com']]);
  });
});
for(const [rcode,want] of [[0,'absent'],[3,'absent'],[2,'inconclusive'],[5,'inconclusive']])test('real Node DNS RCODE '+rcode+' retains absence/error distinction',async()=>{
  await withDns(()=>({rcode}),async resolver=>assert.equal((await auditEmailDns('example.com',{authorized:true,resolver})).checks.spf.status,want));
});
test('real Node DNS dropped packets cancel and audit finishes',async()=>{
  await withDns(()=>null,async resolver=>{
    const start=Date.now();const a=await auditEmailDns('example.com',{authorized:true,resolver,timeoutMs:100});
    assert.equal(a.checks.mx.status,'inconclusive');assert.equal(a.checks.spf.status,'inconclusive');assert.equal(a.checks.dmarc.status,'inconclusive');assert.ok(Date.now()-start<3000);
  });
});
