import {isIP} from 'node:net';
// Only TXT/MX DNS data is inspected. Parsed text remains untrusted input.
export function joinTxt(chunks) {
  if (!Array.isArray(chunks) || chunks.length > 4096 || !chunks.every(s => typeof s === 'string') || chunks.reduce((n,s)=>n+s.length,0)>4096) throw new TypeError('Invalid or oversized DNS TXT chunks.');
  return chunks.join(''); // TXT chunks are not separate TXT records.
}

export function txtRows(data) {
  if (!Array.isArray(data) || data.length > 100) throw new TypeError('Unexpectedly large DNS TXT response.');
  const rows = data.map(joinTxt);
  if (rows.reduce((n,row)=>n+row.length,0)>65536) throw new TypeError('Oversized DNS TXT response');
  return rows;
}

export function parseTags(value) {
  const tags = Object.create(null);
  const duplicates = [];
  const parts=value.split(';');
  if(parts.at(-1).trim()==='') parts.pop();
  for (const part of parts) {
    const match = /^[ \t]*([a-z][a-z0-9_]*)[ \t]*=[ \t]*([\x20-\x3a\x3c-\x7e\t]*?)[ \t]*$/i.exec(part.replace(/\r\n(?=[ \t])/g,''));
    if (!match) return {tags, duplicates, malformed: true};
    const [, rawKey, val] = match;
    const key = rawKey;
    if (Object.hasOwn(tags, key)) duplicates.push(key);
    else tags[key] = val.trim();
  }
  return {tags, duplicates, malformed: false};
}

function finding(code, level, message, advice) { return {code, level, message, advice}; }

export function assessMx(mx) {
  if (mx.status === 'error') return {status:'inconclusive', findings:[finding('mx-query-error','warning','MX lookup failed; mail routing could not be determined.','Verify DNS reachability and retry.')]};
  if (!mx.records.length) return {status:'no-explicit-mx', records:[], findings:[finding('mx-absent','info','No explicit MX records were published. This is not sufficient to prove inbound mail is broken.','Confirm whether this domain is intended to receive email; SMTP may use an implicit address fallback.')]};
  const records=mx.records.map(r=>({priority:r.priority,exchange:r.exchange})).sort((a,b)=>a.priority-b.priority || a.exchange.localeCompare(b.exchange));
  const isNull = records.length === 1 && records[0].priority === 0 && ['.',''].includes(records[0].exchange);
  if(!isNull && records.some(r=>['.',''].includes(r.exchange))) return {status:'needs-review',records,findings:[finding('mx-invalid-null','warning','A null MX target is mixed with other MX records or has a nonzero priority.','Review the null MX configuration against RFC 7505.')]};
  return {status:isNull?'null-mx':'present',records,findings:isNull?[finding('mx-null','info','Null MX explicitly indicates this domain does not accept email.','No action needed if inbound email is intentionally disabled.')]:[]};
}

// Partial static screening: never expands macros or follows DNS targets.
function cidrValid(value,max) {
  return value===undefined || (/^(?:0|[1-9][0-9]{0,2})$/.test(value) && Number(value)<=max);
}

function spfTermValid(term) {
  if (/^[a-z][a-z0-9_.-]*=/i.test(term)) return !/^(?:redirect|exp)=$/i.test(term);
  const t=term.replace(/^[+?~-]/,'');
  if (/^all$/i.test(t)) return true;
  if (/^(?:include|exists):[^ ]+$/i.test(t)) return true;
  if (/^ptr(?::[^ ]+)?$/i.test(t)) return true;
  const ip=/^ip([46]):([^/]+)(?:\/(\d+))?$/i.exec(t);
  if(ip) return isIP(ip[2])===Number(ip[1]) && cidrValid(ip[3],ip[1]==='4'?32:128);
  // A slash can be part of a macro delimiter set, not a CIDR suffix.
  const host=/^(a|mx)(?::([^/]+))?(?:\/(\d{1,3}))?(?:\/\/(\d{1,3}))?$/i.exec(t.replace(/%\{[^}]*\}/g,'macro'));
  return !!host && cidrValid(host[3],32) && cidrValid(host[4],128);
}

export function assessSpf(txt) {
  if (txt.status === 'error') return {status:'inconclusive',findings:[finding('spf-query-error','warning','SPF lookup failed, so publication cannot be determined.','Retry after resolving the DNS error.')]};
  const rows=txt.records.filter(x=>/^v=spf1(?: |$)/i.test(x));
  if(!rows.length && txt.records.some(x=>/^\s*v=spf1(?:\s|$)/i.test(x))) return {status:'needs-review',findings:[finding('spf-syntax-review','warning','SPF-like text does not have a valid version boundary.','Check record whitespace and grammar.')]};
  if(rows.length===0) return {status:'absent',findings:[finding('spf-absent','info','No SPF v=spf1 record was found at this exact domain.','If this domain sends email, review its SPF and DKIM/DMARC setup.')]};
  if(rows.length>1) return {status:'multiple',count:rows.length,findings:[finding('spf-multiple','warning','Multiple SPF records were published for this domain.','Consolidate SPF policies into one record after reviewing all legitimate senders.')]};
  const raw=rows[0], terms=raw.split(/ +/).slice(1).filter(Boolean);
  const modifiers=terms.filter(t=>/^(?:redirect|exp)=/i.test(t)).map(t=>t.split('=')[0].toLowerCase());
  const malformed=/[^\x20-\x7e]/.test(raw) || terms.some(t=>!spfTermValid(t)) || new Set(modifiers).size!==modifiers.length;
  const allIndex=terms.findIndex(t=>/^[+?~-]?all$/i.test(t));
  const reachable=allIndex<0?terms:terms.slice(0,allIndex);
  const lookupTerms=reachable.filter(t=>/^[+?~-]?(?:include:|a(?:$|[:/])|mx(?:$|[:/])|ptr(?:$|:)|exists:)/i.test(t));
  if(allIndex<0 && terms.some(t=>/^redirect=/i.test(t))) lookupTerms.push('redirect');
  const findings=[];
  if(malformed) findings.push(finding('spf-syntax-review','warning','SPF contains unusually long or malformed terms.','Check SPF syntax with your email administrator.'));
  if(lookupTerms.length>10) findings.push(finding('spf-direct-lookups','warning',`SPF contains ${lookupTerms.length} potentially reachable direct DNS terms; some evaluation paths may exceed ten.`, 'The limit applies during evaluation including nested lookups; earlier matches may stop evaluation.'));
  else if(lookupTerms.length>0) findings.push(finding('spf-recursion-unchecked','info',`There are ${lookupTerms.length} direct DNS-lookup terms; nested include/redirect lookups were not evaluated.`, 'Evaluate recursive SPF DNS lookups separately before concluding compliance.'));
  return {status:malformed?'needs-review':'present',record:raw,untrustedRecord:true,syntaxScope:'partial-static',lookupLimitStatus:'not-evaluated',directLookupTerms:lookupTerms.length,findings};
}

export function assessDmarc(txt) {
  if(txt.status==='error') return {status:'inconclusive',findings:[finding('dmarc-query-error','warning','DMARC DNS lookup failed.','Retry when DNS resolution is available.')]};
  const rows=txt.records.filter(x=>/^[ \t]*v[ \t]*=[ \t]*DMARC1(?:[ \t]*;|[ \t]*$)/.test(x));
  if(!rows.length) return {status:'absent-at-exact-name',findings:[finding('dmarc-absent-exact','info','No DMARC record was found at the exact queried _dmarc hostname.','For subdomains, inherited organizational-domain policy may apply; review the parent using a public-suffix-aware tool.')]};
  if(rows.length>1) return {status:'multiple',count:rows.length,findings:[finding('dmarc-multiple','warning','Multiple DMARC records found at this _dmarc name.','Keep one valid DMARC policy at this hostname.')]};
  const raw=rows[0], tagData=parseTags(raw), policy=tagData.tags.p?.toLowerCase();
  const pct=tagData.tags.pct;
  const keys=Object.keys(tagData.tags);
  const invalid=tagData.malformed || tagData.duplicates.length>0 || keys[0]!=='v' || keys[1]!=='p' || !['none','quarantine','reject'].includes(policy) || tagData.tags.v!=='DMARC1'
    || (tagData.tags.sp!==undefined && !['none','quarantine','reject'].includes(tagData.tags.sp.toLowerCase()))
    || (tagData.tags.adkim!==undefined && !['r','s'].includes(tagData.tags.adkim.toLowerCase()))
    || (tagData.tags.aspf!==undefined && !['r','s'].includes(tagData.tags.aspf.toLowerCase()))
    || (pct!==undefined && (!/^\d{1,3}$/.test(pct) || Number(pct)>100));
  if(invalid) return {status:'needs-review',effectivePolicyStatus:'not-evaluated',findings:[finding('dmarc-invalid','warning','DMARC record has malformed/duplicate tags, invalid tag order, or an invalid policy parameter.','Review full syntax. RFC 7489 section 6.6.3 allows a monitoring fallback for invalid p/sp with a valid rua; this tool does not determine receiver behavior.')]};
  const findings=policy==='none'?[finding('dmarc-monitoring','info','DMARC p=none requests monitoring; it does not request quarantine or rejection.','After monitoring and validating authorized senders, consider an enforcement policy if appropriate.')]:[];
  const reportingConfigured=(tagData.tags.rua??'').split(',').some(uri=>/^mailto:[^\s@!,]+@[^\s@!,]+(?:!\d+[kmgt]?)?$/i.test(uri.trim()));
  if(tagData.tags.rua!==undefined && !reportingConfigured) findings.push(finding('dmarc-report-uri-review','info','No supported mailto aggregate-report URI was recognized.','Review reporting URI syntax and external destination authorization; no reports are sent.'));
  return {status:'present',syntaxScope:'partial-static',effectivePolicyStatus:'not-evaluated',policy,subdomainPolicy:tagData.tags.sp?.toLowerCase()??null,percentage:Number(pct??100),alignment:{adkim:tagData.tags.adkim?.toLowerCase()??'r',aspf:tagData.tags.aspf?.toLowerCase()??'r'},reportingConfigured,reportingAuthorization:'not-checked', findings};
}

export function assessDkim(txt,selector) {
  if(txt.status==='error') return {selector,status:'inconclusive',findings:[finding('dkim-query-error','warning',`DNS lookup failed for DKIM selector ${selector}.`,'Check DNS reachability and the selector name.')]};
  if(txt.records.length>1) return {selector,status:'multiple',findings:[finding('dkim-multiple','warning',`Multiple TXT records found for DKIM selector ${selector}; results are undefined under RFC 6376.`, 'Publish a unique TXT record at the selector; chunks within one TXT record are permitted.')]};
  // v=DKIM1 is optional. Recognize records with p= and no v= too.
  const rows=txt.records.map(raw=>({raw,parsed:parseTags(raw)})).filter(({parsed})=>
    Object.hasOwn(parsed.tags,'p') && (parsed.tags.v === undefined || parsed.tags.v?.toUpperCase()==='DKIM1'));
  if(rows.length===0) return txt.records.length>0?{selector,status:'needs-review',findings:[finding('dkim-unrecognized','info',`TXT data exists for selector ${selector} but no recognized DKIM key record was identified.`,'Confirm selector and inspect record grammar manually.')]}:{selector,status:'no-txt-at-selector',findings:[finding('dkim-not-found','info',`No TXT record found for supplied selector ${selector}.`,'Confirm the selector from your sending provider; other selectors may be active.')]};
  const record=rows[0].parsed;
  if(record.malformed || record.duplicates.length || (record.tags.v!==undefined && (record.tags.v!=='DKIM1' || Object.keys(record.tags)[0]!=='v')) || !Object.hasOwn(record.tags,'p') || (record.tags.k!==undefined && !['rsa','ed25519'].includes(record.tags.k))) return {selector,status:'needs-review',findings:[finding('dkim-syntax-review','warning',`DKIM selector ${selector} has malformed, repeated, or unsupported key tags.`,'Review key syntax and algorithm with the signing provider.')]};
  if(record.tags.p==='') return {selector,status:'revoked',keyType:record.tags.k?.toLowerCase()??'rsa',findings:[finding('dkim-revoked','info',`DKIM selector ${selector} publishes an empty p= tag (revoked key).`,'Verify the service no longer signs with this selector.')]};
  const key=record.tags.p.replace(/[ \t\r\n]/g,'');
  if(!/^[A-Za-z0-9+/]+={0,2}$/.test(key) || (key.includes('=') && key.length%4!==0) || key.length%4===1 || Buffer.from(key,'base64').toString('base64').replace(/=+$/,'')!==key.replace(/=+$/,'')) return {selector,status:'needs-review',findings:[finding('dkim-key-syntax','warning',`DKIM selector ${selector} has public-key text requiring review.`,'Check base64 public-key encoding and the provider configuration.')]};
  return {selector,status:'key-tag-present',keyType:record.tags.k?.toLowerCase()??'rsa',findings:[finding('dkim-not-cryptographically-verified','info',`A DKIM p= public-key tag exists for selector ${selector}, but no signature was verified.`,'Confirm valid signatures and domain alignment with an authorized real message.')]};
}
