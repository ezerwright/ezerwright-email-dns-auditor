import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeDomain,normalizeSelectors} from '../scripts/safety.mjs';
import {assessMx,assessSpf,assessDmarc,assessDkim,txtRows,parseTags} from '../scripts/records.mjs';
import {auditEmailDns} from '../scripts/auditor.mjs';
import {run} from '../scripts/audit.mjs';
const data=records=>({status:'ok',records});

test('RFC6376 dotted selector supported',()=>assert.deepEqual(normalizeSelectors(['March.Reykjavik']),['march.reykjavik']));
test('short valid public domain is accepted',()=>assert.equal(normalizeDomain('a.de'),'a.de'));
test('malformed A-label is rejected before DNS',()=>assert.throws(()=>normalizeDomain('xn--a.com')));
test('mixed null MX requires review',()=>assert.equal(assessMx(data([{priority:0,exchange:'.'},{priority:10,exchange:'mx.example.com'}])).status,'needs-review'));
test('combined DKIM owner too long rejects before any query',async()=>{
  let calls=0;const r={resolveMx:async()=>{calls++;return []},resolveTxt:async()=>{calls++;return []}};
  const domain=['a'.repeat(63),'b'.repeat(63),'c'.repeat(63),'d'.repeat(50),'com'].join('.');
  await assert.rejects(auditEmailDns(domain,{authorized:true,selectors:['longselector'],resolver:r}));assert.equal(calls,0);
});
test('query names are absolute, bounded and not derived from TXT',async()=>{
  const asked=[];const r={resolveMx:async n=>{asked.push(['MX',n]);return []},resolveTxt:async n=>{asked.push(['TXT',n]);return [['v=spf1 include:attacker.com -all']]}};
  await auditEmailDns('example.com',{authorized:true,selectors:['s.one'],resolver:r});
  assert.deepEqual(asked,[['MX','example.com.'],['TXT','example.com.'],['TXT','_dmarc.example.com.'],['TXT','s.one._domainkey.example.com.']]);
});
for(const code of ['ENOENT','DNS_ENOTFOUND','EAI_AGAIN','ECANCELLED'])test('non-DNS-negative error '+code+' is inconclusive',async()=>{
  const fail=async()=>{throw Object.assign(Error('untrusted'),{code})};
  const a=await auditEmailDns('example.com',{authorized:true,resolver:{resolveTxt:fail,resolveMx:fail}});
  assert.equal(a.checks.spf.status,'inconclusive');
});
test('DNS timeout cancels pending resolver work',async()=>{
  let cancelled=0;const r={resolveMx:()=>new Promise(()=>{}),resolveTxt:async()=>[],cancel:()=>{cancelled++}};
  const a=await auditEmailDns('example.com',{authorized:true,resolver:r,timeoutMs:100});
  assert.equal(a.checks.mx.status,'inconclusive');assert.equal(cancelled,1);
});
test('invalid MX hostname is not echoed into output',async()=>{
  const a=await auditEmailDns('example.com',{authorized:true,resolver:{resolveMx:async()=>[{priority:0,exchange:'<script>alert(1)</script>'}],resolveTxt:async()=>[]}});
  assert.equal(a.checks.mx.status,'inconclusive');assert.ok(!JSON.stringify(a).includes('<script>'));
});
test('TXT chunk count checked before join allocation',()=>assert.throws(()=>txtRows([Array(10000).fill('')])));
test('TXT aggregate response bound',()=>assert.throws(()=>txtRows(Array.from({length:100},()=>['a'.repeat(4000)]))));
test('tag parser supports extension underscores and case-sensitive DKIM names',()=>{
  const x=parseTags('p=YWJj; X_ext=a; P=ignored');assert.equal(x.malformed,false);assert.equal(x.tags.P,'ignored');
});
for(const raw of ['v=DKIM1;;p=YWJj','v=DKIM1; p=YWJj;\u001b[31m=red'])test('malformed tag list rejected '+JSON.stringify(raw),()=>assert.equal(assessDkim(data([raw]),'s').status,'needs-review'));
for(const raw of ['p=YWJj; v=DKIM1','v=dkim1; p=YWJj','v=DKIM1; k=RSA; p=YWJj','v=DKIM1; p=A','v=DKIM1; p=YWJj='])test('DKIM invalid ordering/case/base64 '+raw,()=>assert.equal(assessDkim(data([raw]),'s').status,'needs-review'));
test('DKIM base64 folding whitespace accepted',()=>assert.equal(assessDkim(data(['v=DKIM1; p=YW Jj\r\n ZA==']),'s').status,'key-tag-present'));
for(const records of [['v=DKIM1; p=YWJjZA==','unrelated TXT'],['v=DKIM1; p=','v=OTHER; p=YWJjZA==']])test('DKIM whole TXT RRset must be unique '+records[1],()=>assert.equal(assessDkim(data(records),'s').status,'multiple'));
test('SPF unreachable lookups and redirect ignored after all',()=>{
  const x=assessSpf(data(['v=spf1 -all '+Array(11).fill('include:a.com').join(' ')+' redirect=b.com']));
  assert.equal(x.directLookupTerms,0);assert.ok(!x.findings.some(f=>f.code==='spf-direct-lookups'));
});
test('SPF direct count is potential, not proof of limit failure',()=>{
  const x=assessSpf(data(['v=spf1 '+Array(11).fill('include:a.com').join(' ')]));
  assert.ok(x.findings.some(f=>f.code==='spf-direct-lookups'));assert.doesNotMatch(x.findings.map(f=>f.message).join(' '),/exceeding the 10-lookup limit even/);
});
for(const raw of ['v=spf1 wat -all','v=spf1 ip4:999.1.1.1 -all','v=spf1 ip6:abcd/129 -all','v=spf1 a/33 -all','v=spf1 redirect=a.com redirect=b.com','v=spf1\t-all'])test('SPF malformed grammar needs review '+raw,()=>assert.equal(assessSpf(data([raw])).status,'needs-review'));
test('SPF unknown modifier not unknown mechanism',()=>assert.equal(assessSpf(data(['v=spf1 x_ext=anything -all'])).status,'present'));
test('RFC7208 unknown modifiers may repeat and are ignored',()=>assert.equal(assessSpf(data(['v=spf1 x_ext=a x_ext=b -all'])).status,'present'));
for(const mechanism of ['a','mx'])test('SPF slash inside macro is not a CIDR delimiter: '+mechanism,()=>assert.equal(assessSpf(data([`v=spf1 ${mechanism}:%{l1r/}.example.com -all`])).status,'present'));
for(const term of ['ip4:192.0.2.0/01','a/01','mx//064'])test('SPF CIDR length disallows leading zero: '+term,()=>assert.equal(assessSpf(data(['v=spf1 '+term+' -all'])).status,'needs-review'));
test('SPF macros remain unevaluated and explicitly partial',()=>assert.equal(assessSpf(data(['v=spf1 exists:%{i}.a.com -all'])).syntaxScope,'partial-static'));
for(const raw of ['v=DMARC1; p=reject; sp=garbage','v=DMARC1; rua=mailto:a@example.com; p=reject'])test('DMARC invalid subpolicy or order '+raw,()=>assert.equal(assessDmarc(data([raw])).status,'needs-review'));
test('DMARC pct three-digit leading zeros allowed by ABNF',()=>assert.equal(assessDmarc(data(['v=DMARC1; p=reject; pct=001'])).status,'present'));
test('DMARC reports requested percentage and unresolved inheritance',()=>{
  const x=assessDmarc(data(['v=DMARC1; p=reject; sp=none; pct=0']));assert.equal(x.percentage,0);assert.equal(x.subdomainPolicy,'none');assert.equal(x.effectivePolicyStatus,'not-evaluated');
});
test('DMARC bogus reporting address is not called configured',()=>assert.equal(assessDmarc(data(['v=DMARC1; p=none; rua=not-a-uri'])).reportingConfigured,false));
test('CLI attacker-controlled errors cannot emit terminal escapes',async()=>{
  let err='';const api={err:{write:s=>err+=s},out:{write:()=>{}},auditEmailDns:async()=>{throw Error('oops\u001b[31m\nFORGED')}};
  assert.equal(await run(['example.com','--authorized'],api),1);assert.ok(!err.includes('\u001b'));assert.equal(err.split('\n').length,2);
});
test('CLI C1 controls and Unicode line separators are escaped in reports and errors',async()=>{
  for(const fail of [false,true]) {
    let output='';const api={err:{write:s=>output+=s},out:{write:s=>output+=s},auditEmailDns:async()=>{if(fail)throw Error('bad\u009b31m\u2028line');return {value:'bad\u009b31m\u2028line'}}};
    await run(['example.com','--authorized'],api);assert.ok(!/[\u009b\u2028]/.test(output));
    if(!fail) assert.equal(JSON.parse(output).value,'bad\u009b31m\u2028line');
  }
});
