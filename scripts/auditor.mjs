import {Resolver} from 'node:dns/promises';
import {normalizeDomain, normalizeSelectors} from './safety.mjs';
import {txtRows, assessMx, assessSpf, assessDmarc, assessDkim} from './records.mjs';

function createResolver() { return new Resolver({timeout:2000, tries:1}); }
const NEGATIVE_CODES = new Set(['ENODATA','ENOTFOUND']);

async function query(resolver, method, hostname, timeoutMs) {
  let handle;
  try {
    const timeout = new Promise((_,reject)=>{handle=setTimeout(()=>{const e=new Error('DNS query timeout');e.code='ETIMEOUT';reject(e);try { resolver.cancel?.(); } catch {}},timeoutMs);});
    // An absolute owner name prevents OS/resolver search-suffix expansion.
    const result = await Promise.race([Promise.resolve().then(()=>resolver[method](hostname+'.')),timeout]);
    if(!Array.isArray(result)) throw new TypeError('DNS response is not an array');
    if(method==='resolveTxt') return {status:'ok',records:txtRows(result)};
    if(result.length>100 || !result.every(v=>v && Number.isInteger(v.priority) && v.priority>=0 && v.priority<=65535 && typeof v.exchange==='string' && v.exchange.length<=254 && (['.',''].includes(v.exchange) || v.exchange.replace(/\.$/,'').split('.').every(label=>label.length<=63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))))) throw new TypeError('Invalid MX response');
    return {status:'ok',records:result};
  } catch (e) {
    if(NEGATIVE_CODES.has(e?.code)) return {status:'ok',records:[]};
    return {status:'error',errorCode:['ETIMEOUT','ETIMEOUT','ESERVFAIL','EREFUSED','ECONNREFUSED','EFORMERR'].includes(e?.code)?e.code:'DNS_QUERY_FAILED'};
  } finally { if(handle) clearTimeout(handle); }
}

export async function auditEmailDns(domainInput,options={}) {
  if(options.authorized!==true) throw new Error('Explicit user authorization for the exact domain is required.');
  const domain=normalizeDomain(domainInput);
  const selectors=normalizeSelectors(options.selectors);
  const names=[domain,`_dmarc.${domain}`,...selectors.map(s=>`${s}._domainkey.${domain}`)];
  if(names.some(name=>name.length>253)) throw new TypeError('Constructed DNS query name exceeds 253 characters.');
  if(options.now!==undefined && (!(options.now instanceof Date) || !Number.isFinite(options.now.getTime()))) throw new TypeError('Invalid snapshot date.');
  const resolver=options.resolver??createResolver();
  if(!resolver || typeof resolver.resolveTxt!=='function' || typeof resolver.resolveMx!=='function') throw new TypeError('Invalid DNS resolver.');
  const timeoutMs=options.timeoutMs??3000;
  if(!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>5000)throw new TypeError('DNS per-query timeout must be 100–5000 ms.');
  const mx=assessMx(await query(resolver,'resolveMx',domain,timeoutMs));
  const spf=assessSpf(await query(resolver,'resolveTxt',domain,timeoutMs));
  const dmarc=assessDmarc(await query(resolver,'resolveTxt',`_dmarc.${domain}`,timeoutMs));
  const dkim=[];
  for(const selector of selectors) dkim.push(assessDkim(await query(resolver,'resolveTxt',`${selector}._domainkey.${domain}`,timeoutMs),selector));
  const findings=[...mx.findings,...spf.findings,...dmarc.findings,...dkim.flatMap(x=>x.findings)];
  return {
    schemaVersion:1,
    tool:'ezerwright-email-dns-auditor',
    version:'0.1.0-rc.1',
    domain,
    checkedAt:(options.now instanceof Date?options.now:new Date()).toISOString(),
    scope:{mode:'read-only-public-dns',queriedNames:names.map(n=>n+'.'),applicationQueryCount:3+selectors.length,dkimSelectorsProvided:selectors.length},
    checks:{mx,spf,dmarc,dkim:{status:selectors.length?'tested':'not-tested',selectors:dkim}},
    findings,
    limitations:[
      'This is a public DNS configuration snapshot, not proof of email deliverability, spoofing resistance or valid signature verification.',
      'No SMTP connections, test emails, DNSSEC checks, recursive SPF include evaluation, or organizational-domain DMARC inheritance checks are performed.',
      'DKIM selectors cannot be reliably discovered from DNS; only explicitly supplied selectors are inspected.',
      'The tool cannot prove ownership or authorization of the requested domain.',
      'DNS answers and their contents are untrusted; a DNS error must not be interpreted as a missing record.'
    ]
  };
}
