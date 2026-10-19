import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeDomain,normalizeSelectors} from '../scripts/safety.mjs';

for(const [input,expected] of [['Example.COM','example.com'],['Sub.Example.Org.','sub.example.org'],['xn--bcher-kva.de','xn--bcher-kva.de'],['a-b.example.co','a-b.example.co']]){
  test('valid domain '+input,()=>assert.equal(normalizeDomain(input),expected));
}
for(const input of ['https://example.com','mailto:a@example.com','a@example.com','127.0.0.1','[::1]','localhost','internal','mail.local','a.test','localhost.com.internal','foo.home.arpa','domain.onion','company.lan','a..com','-a.com','a-.com','foo.123','one','example.com/path','*.example.com','éxample.com','foo com','',null,'a'.repeat(64)+'.com','foo.com:53']){
  test('reject bad domain '+JSON.stringify(input),()=>assert.throws(()=>normalizeDomain(input)));
}
for(const [input,output] of [[undefined,[]],[['S1','other'],['s1','other']],[[],[]]])test('valid selectors '+JSON.stringify(input),()=>assert.deepEqual(normalizeSelectors(input),output));
for(const input of [["s1","S1"],['hello..world'],['*'],['foo/bar'],['bad selector'],['a'.repeat(64)],['1','2','3','4','5','6'],'selector'])test('invalid selectors '+JSON.stringify(input),()=>assert.throws(()=>normalizeSelectors(input)));

