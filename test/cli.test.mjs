import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {parseArgs,run} from '../scripts/audit.mjs';
const report={tool:'ezerwright-email-dns-auditor'};
const fakeApi=(extra={})=>{let output='',errors='',called=0;return {api:{auditEmailDns:async(...args)=>{called++;return report;},writeFile:extra.writeFile??(async()=>{}),out:{write:s=>{output+=s;}},err:{write:s=>{errors+=s;}}},get:()=>({output,errors,called})};};
test('parse required domain and authorization',()=>assert.deepEqual(parseArgs(['example.com','--authorized','--selector','S1']),{selectors:['S1'],domain:'example.com',authorized:true}));
for(const argv of [[],['example.com'],['a.com','b.com','--authorized'],['a.com','--authorized','--authorized'],['a.com','--authorized','--out','../evil.json'],['a.com','--authorized','--out','c:\\evil.json'],['a.com','--authorized','--out','NUL.json'],['a.com','--authorized','--out','a.txt'],['a.com','--authorized','--selector'],['a.com','--authorized','--unknown'],['a.com','--authorized','--out','one.json','--out','two.json']])test('CLI rejects '+JSON.stringify(argv),()=>assert.throws(()=>parseArgs(argv)));
test('CLI help no network',async()=>{const {api,get}=fakeApi();assert.equal(await run(['--help'],api),0);assert.equal(get().called,0)});
test('CLI normal stdout JSON',async()=>{const {api,get}=fakeApi();assert.equal(await run(['example.com','--authorized'],api),0);assert.deepEqual(JSON.parse(get().output),report);assert.equal(get().called,1)});
test('CLI argument failure no audit',async()=>{const {api,get}=fakeApi();assert.equal(await run(['example.com'],api),1);assert.equal(get().called,0)});
test('report write exclusively creates, never overwrites',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'dns-audit-test-'));
  try{
    const {writeFile}=await import('node:fs/promises');
    const path=join(dir,'report.json');
    let output='',errors='';
    const api={auditEmailDns:async()=>report,writeFile:async(name,data,opts)=>writeFile(path,data,opts),out:{write:s=>output+=s},err:{write:s=>errors+=s}};
    assert.equal(await run(['example.com','--authorized','--out','report.json'],api),0);
    assert.deepEqual(JSON.parse(await readFile(path,'utf8')),report);
    assert.equal(await run(['example.com','--authorized','--out','report.json'],api),1);
    assert.deepEqual(JSON.parse(await readFile(path,'utf8')),report);
    assert.match(errors,/EEXIST/);
  }finally{await rm(dir,{recursive:true,force:true});}
});
