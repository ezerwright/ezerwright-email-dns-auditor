#!/usr/bin/env node
import {writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {auditEmailDns} from './auditor.mjs';

function safeJson(value,space) {
  return JSON.stringify(value,null,space).replace(/[\u007f-\u009f\u2028-\u202e\u2066-\u2069]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
}

export function parseArgs(argv) {
  const args={selectors:[]};
  for(let i=0;i<argv.length;i++) {
    const arg=argv[i];
    if(arg==='--help'||arg==='-h') return {help:true};
    if(arg==='--authorized') {if(args.authorized)throw Error('Duplicate --authorized.'); args.authorized=true;}
    else if(arg==='--selector') {if(!argv[i+1]||argv[i+1].startsWith('--'))throw Error('--selector requires an explicit DNS label.');args.selectors.push(argv[++i]);}
    else if(arg==='--out') {if(args.out)throw Error('Duplicate --out.');if(!argv[i+1]||argv[i+1].startsWith('--'))throw Error('--out requires a JSON basename.');args.out=argv[++i];}
    else if(arg.startsWith('-')) throw Error(`Unknown option: ${arg}`);
    else if(args.domain) throw Error('Only one exact DNS domain is permitted.');
    else args.domain=arg;
  }
  if(!args.domain)throw Error('A public DNS domain is required.');
  if(!args.authorized)throw Error('Explicit user authorization required: --authorized');
  if(args.out && (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\.json$/.test(args.out) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(args.out)))throw Error('Report name must be a simple JSON basename, not a path.');
  return args;
}

export const USAGE=`Usage:\n  node scripts/audit.mjs example.com --authorized [--selector sel1] [--out report.json]\n\nOnly exact, explicitly authorized public DNS domains. At most five known DKIM selectors.\nNo SMTP, mail send, credentials, or DNS modifications. Output files must not exist.\n`;

export async function run(argv,api={auditEmailDns,writeFile,out:process.stdout,err:process.stderr}) {
  try {
    const args=parseArgs(argv);
    if(args.help) {api.out.write(USAGE);return 0;}
    const report=await api.auditEmailDns(args.domain,{authorized:true,selectors:args.selectors});
    const json=safeJson(report,2)+'\n';
    if(args.out) {
      await api.writeFile(args.out,json,{flag:'wx',mode:0o600,encoding:'utf8'});
      api.out.write(`Created ${args.out}\n`);
    } else api.out.write(json);
    return 0;
  } catch(e) {
    // JSON quoting neutralizes terminal control characters and forged log lines.
    api.err.write(`Email DNS Auditor: ${safeJson(String(e?.message||'Unknown error').slice(0,512))}\n`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const code=await run(process.argv.slice(2));
  process.exitCode=code;
}
