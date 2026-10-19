import {domainToASCII,domainToUnicode} from 'node:url';
// Strict user-target validation. We intentionally do not accept hostnames,
// IP addresses, e-mail addresses, URLs, or internal/reserved suffixes as a domain.
const BLOCKED_ENDINGS = ['localhost', 'local', 'internal', 'test', 'invalid', 'example', 'onion', 'lan', 'corp', 'intranet', 'arpa', 'alt'];

export function normalizeDomain(input) {
  if (typeof input !== 'string' || input.length > 254 || input.length < 4) throw new TypeError('Enter a public DNS domain name, not a URL or email address.');
  const domain = input.endsWith('.') ? input.slice(0, -1).toLowerCase() : input.toLowerCase();
  if (domain.length > 253 || !/^[a-z0-9.-]+$/.test(domain)) throw new TypeError('Only ASCII DNS domain names are supported; use punycode for IDNs.');
  if(domainToASCII(domain)!==domain) throw new TypeError('Invalid IDNA A-label.');
  const labels = domain.split('.');
  // Some Node builds leave malformed ASCII A-labels unchanged; reject undecodable labels too.
  if(labels.some(label=>label.startsWith('xn--') && domainToUnicode(label)===label)) throw new TypeError('Invalid IDNA A-label.');
  if (labels.length < 2 || labels.some(part => !part || part.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part))) throw new TypeError('Invalid public domain syntax.');
  const tld = labels.at(-1);
  if (!(/^[a-z]{2,63}$/.test(tld) || /^xn--[a-z0-9-]{2,59}$/.test(tld))) throw new TypeError('Invalid public DNS top-level domain.');
  if (BLOCKED_ENDINGS.some(suffix => domain === suffix || domain.endsWith('.' + suffix))) throw new TypeError('Internal, special-use and reserved DNS suffixes are not supported.');
  return domain;
}

export function normalizeSelectors(input) {
  if (input === undefined) return [];
  if (!Array.isArray(input) || input.length > 5) throw new TypeError('Supply no more than five explicit DKIM selectors.');
  const selectors = input.map(s => {
    if (typeof s !== 'string' || s.length < 1 || s.length > 253 || s.split('.').some(label => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))) throw new TypeError('Invalid DKIM selector; specify DNS labels separated by dots.');
    return s.toLowerCase();
  });
  if (new Set(selectors).size !== selectors.length) throw new TypeError('Duplicate DKIM selector.');
  return selectors;
}
