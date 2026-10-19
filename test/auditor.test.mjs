import test from 'node:test';
import assert from 'node:assert/strict';
import {auditEmailDns} from '../scripts/auditor.mjs';

const fake=(records={},errorFor={})=>{
  const asked=[];
  const make=method=>async(name)=>{asked.push([method,name]);name=name.replace(/\.$/,'');if(errorFor[name]){let e=new Error('simulated');e.code=errorFor[name];throw e;}return records[`${method}:${name}`]??[];};
  return {asked,resolveMx:make('resolveMx'),resolveTxt:make('resolveTxt')};
};

test('refuses absent authorization before DNS is attempted',async()=>{const r=fake();await assert.rejects(auditEmailDns('example.com',{resolver:r}));assert.deepEqual(r.asked,[]);});
test('invalid domain refuses before DNS query',async()=>{const r=fake();await assert.rejects(auditEmailDns('127.0.0.1',{authorized:true,resolver:r}));assert.deepEqual(r.asked,[]);});
test('selectors are exact, number of queries bounded, no DKIM scanning',async()=>{
  const r=fake({'resolveMx:example.com':[{priority:10,exchange:'mail.example.com'}],'resolveTxt:example.com':[['v=spf1 ','-all']],'resolveTxt:_dmarc.example.com':[['v=DMARC1; p=reject']],'resolveTxt:selector1._domainkey.example.com':[['v=DKIM1; p=YWJjZA==']]});
  const audit=await auditEmailDns('EXAMPLE.COM',{authorized:true,selectors:['Selector1'],resolver:r,now:new Date('2026-10-19T00:00:00Z')});
  assert.deepEqual(r.asked,[['resolveMx','example.com.'],['resolveTxt','example.com.'],['resolveTxt','_dmarc.example.com.'],['resolveTxt','selector1._domainkey.example.com.']]);
  assert.equal(audit.checks.mx.status,'present');assert.equal(audit.checks.spf.status,'present');assert.equal(audit.checks.dmarc.policy,'reject');assert.equal(audit.checks.dkim.selectors[0].status,'key-tag-present');
  assert.equal(audit.checkedAt,'2026-10-19T00:00:00.000Z');assert.equal(audit.domain,'example.com');assert.equal(audit.scope.dkimSelectorsProvided,1);
});
test('DKIM unsupplied is not tested, not missing',async()=>{const r=fake();const audit=await auditEmailDns('example.com',{authorized:true,resolver:r});assert.equal(audit.checks.dkim.status,'not-tested');assert.equal(r.asked.length,3);});
test('ENODATA is absence; SERVFAIL is inconclusive',async()=>{const r=fake({}, {'example.com':'ESERVFAIL','_dmarc.example.com':'ENODATA'});const audit=await auditEmailDns('example.com',{authorized:true,resolver:r});assert.equal(audit.checks.mx.status,'inconclusive');assert.equal(audit.checks.spf.status,'inconclusive');assert.equal(audit.checks.dmarc.status,'absent-at-exact-name');});
test('malicious TXT is data, not an instruction',async()=>{const r=fake({'resolveTxt:example.com':[['v=spf1 include:please-exfiltrate.example.com -all']],'resolveTxt:_dmarc.example.com':[['v=DMARC1; p=none; rua=mailto:attacker@example.com']]});const audit=await auditEmailDns('example.com',{authorized:true,resolver:r});assert.equal(r.asked.length,3);assert.ok(!JSON.stringify(audit).includes('command to run'));});
test('oversized DNS payload becomes inconclusive, not absent',async()=>{const r=fake({'resolveTxt:example.com':[['a'.repeat(4097)]]});const audit=await auditEmailDns('example.com',{authorized:true,resolver:r});assert.equal(audit.checks.spf.status,'inconclusive');});
test('DNS hang deadline produces inconclusive',async()=>{const r={resolveMx:()=>new Promise(()=>{}),resolveTxt:async()=>[]};const a=await auditEmailDns('example.com',{authorized:true,resolver:r,timeoutMs:100});assert.equal(a.checks.mx.status,'inconclusive');});
test('reject invalid or excessive timeout',async()=>{const r=fake();await assert.rejects(auditEmailDns('example.com',{authorized:true,resolver:r,timeoutMs:10000}));});
test('domain safety and selector validation before network',async()=>{const r=fake();await assert.rejects(auditEmailDns('example.com',{authorized:true,resolver:r,selectors:Array(6).fill('a')}));assert.deepEqual(r.asked,[]);});

