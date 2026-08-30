// c24 stubbed-fetch harness: extracts CORE + NET blocks from receipt.html and
// unit-tests collectReceipts/loadFleet with a stubbed fetch + minimal DOM.
// Run: node t-net.mjs <repo-dir>  (from inside the ethers install dir)
import fs from 'fs';
import nodeCrypto from 'node:crypto';

import path from 'node:path';
import { verifyMessage, Wallet } from 'ethers';
if (!globalThis.crypto) globalThis.crypto = nodeCrypto.webcrypto;

const REPO = process.argv[2];
const html = fs.readFileSync(REPO + '/receipt.html', 'utf8');
const core = html.match(/\/\/ ---- CORE BEGIN ----[^\n]*\n([\s\S]*?)\/\/ ---- CORE END ----/);
const net = html.match(/\/\/ ---- NET BEGIN ----[^\n]*\n([\s\S]*?)\/\/ ---- NET END ----/);
if (!core || !net) { console.error('CORE/NET block not found in receipt.html'); process.exit(1); }

// pin: CORE must stay fetch-free (that's WHY NET is a separate block)
const coreIsPure = !core[1].includes('fetch(');
let fails = 0;
const T = (n, c, d) => { console.log((c ? 'PASS' : 'FAIL') + ' | ' + n + (d && !c ? ' | ' + d : '')); if (!c) fails++; };
T('NET: CORE block contains no fetch( call', coreIsPure);
T('NET: block holds collectReceipts + loadFleet', net[1].includes('async function collectReceipts') && net[1].includes('async function loadFleet'));

globalThis.ethers = { verifyMessage };
// The RENDER block (everything between CORE END and NET BEGIN) defines
// renderReceiptInto, which loadFleet calls — run it against the stub DOM so
// the emitted HTML (summary + failure cards) is asserted, not a stubbed call.
const render = html.match(/\/\/ ---- CORE END ----([\s\S]*?)\/\/ ---- NET BEGIN ----/);
if (!render) { console.error('RENDER block not found'); process.exit(1); }
const mod = new Function(core[1] + render[1] + net[1] +
  '; return { collectReceipts, loadFleet, verifyReceipt, FLEET, renderReceiptInto };')();

// ---- test-key fixtures (public well-known test vectors, NOT real wallets) ----
const PK1 = '0x' + '46'.repeat(32);            // published test key (CI's ETHKEY_PK)
const PK3 = '0x0000000000000000000000000000000000000000000000000000000000000003'; // c18 throwaway
const w1 = new Wallet(PK1), w3 = new Wallet(PK3);

// Build a receipt markdown exactly as ethkey.py make_proof lays it out, but
// signed by ethers — the JS->Python half of gap #10 parity.
async function makeReceipt(payloadStr, wallet, note) {
  const created = '2026-08-30T00:00:00Z';
  const sha = nodeCrypto.createHash('sha256').update(Buffer.from(payloadStr)).digest('hex');
  const sig = await wallet.signMessage('ethkey-lite-proof v1\ncreated:' + created + '\nsha256:' + sha);
  const b64 = Buffer.from(payloadStr).toString('base64');
  const body = b64.match(/.{1,76}/g).join('\n');
  return ['# ethkey-lite-proof v1', 'created: ' + created,
    'signer: ' + wallet.address, 'sha256: ' + sha, 'note: ' + note,
    'signature: ' + sig, '', '-----BEGIN PAYLOAD-----', body, '-----END PAYLOAD-----', ''].join('\n');
}
const rcC = await makeReceipt('c24 receipt for signer 1', w1, 'harness fixture, not a release receipt');
const rc3 = await makeReceipt('c24 receipt for signer 3', w3, 'harness fixture, not a release receipt');

// ---- fetch stub: ordered [regex -> handler(url)] ----
let ROUTES = [], CALLS = [];
globalThis.fetch = async (url) => {
  CALLS.push(url);
  for (const [re, h] of ROUTES) {
    const m = url.match(re);
    if (m) {
      const out = await h(url, m);
      if (out === 404) return { ok: false, status: 404, json: async () => { throw new Error('HTTP 404'); }, text: async () => { throw new Error('HTTP 404'); } };
      return { ok: true, status: 200, json: async () => out, text: async () => out };
    }
  }
  return { ok: false, status: 404, json: async () => { throw new Error('HTTP 404'); }, text: async () => { throw new Error('HTTP 404'); } };
};
const tags = (names) => names.map(n => ({ name: n }));
const files = (names) => names.map(n => ({ name: n }));

// E1+E2: tag-pinned route picks newest tag, verifies EVERY same-version receipt,
// skips other versions, and requests the tag ref (never HEAD).
{
  CALLS = [];
  ROUTES = [
    [/\/tags\?/, () => tags(['v0.9', 'v0.7', 'v0.6'])],
    [/\/contents\/proofs\?ref=v0\.9$/, () => files(['c-fixture.md', 'README-ish.txt'])], // no receipt names
    [/\/contents\/proofs\?ref=v0\.7$/, () => files(['v0.7-alpha.md', 'v0.7-beta.md', 'v0.6-old.md'])],
    [/\/v0\.7\/proofs\/v0\.7-alpha\.md$/, () => rcC],
    [/\/v0\.7\/proofs\/v0\.7-beta\.md$/, () => rcC],
  ];
  mod.FLEET.length = 0; mod.FLEET.push({ repo: 'ethkey-lite', signer: w1.address });
  const hit = await mod.collectReceipts('ethkey-lite');
  T('E1: walk-down v0.9 (no receipts) -> loads at v0.7', hit.results.length === 2 &&
    hit.results.every(r => r.ok && /@ tag v0\.7/.test(r.checks[0].detail)), hit.results.map(r => r.checks[0].detail).join(' | '));
  T('E1: required pinned signer honored on every result',
    hit.results.every(r => r.checks.some(c => c.name === 'require' && c.ok)));
  T('E2: multi-receipt release: both same-version receipts fetched',
    CALLS.some(u => /v0\.7-alpha\.md/.test(u)) && CALLS.some(u => /v0\.7-beta\.md/.test(u)));
  T('E2: other-version receipt (v0.6-old) NOT fetched', !CALLS.some(u => /v0\.6-old\.md/.test(u)));
  T('E1: tag-pinned route used, no HEAD request made',
    CALLS.some(u => /contents\/proofs\?ref=v0\.7/.test(u)) && !CALLS.some(u => /\/HEAD\//.test(u) || /ref=HEAD/.test(u)));
}

// E3: tags endpoint dies -> HEAD fallback, result LABELED as HEAD
{
  CALLS = [];
  ROUTES = [
    [/\/tags\?/, () => 404],
    [/\/contents\/proofs$/, () => files(['v0.8-only-on-main.md'])],
    [/\/HEAD\/proofs\/v0\.8-only-on-main\.md$/, () => rcC],
  ];
  const hit = await mod.collectReceipts('ethkey-lite');
  T('E3: HEAD fallback loads + labeled "tag route unavailable"',
    hit.results.length === 1 && /from HEAD \(tag route unavailable\)/.test(hit.results[0].checks[0].detail), hit.results[0] && hit.results[0].checks[0].detail);
  T('E3: failure trail names the tags route', hit.tried.some(t => /tags \(/.test(t)), hit.tried.join('; '));
}

// E4: everything remote dead -> committed same-origin fallback for ethkey-lite
{
  ROUTES = [[/^proofs\/v0\.4-source\.md$/, () => fs.readFileSync(REPO + '/proofs/v0.4-source.md', 'utf8')]];
  mod.FLEET.length = 0; mod.FLEET.push({ repo: 'ethkey-lite', signer: '0xf232dcdc177b53981b4d805a48c79f239db8d0f9' });
  const hit = await mod.collectReceipts('ethkey-lite');
  T('E4: committed v0.4 fallback works when API is down',
    hit.results.length === 1 && /API route unavailable/.test(hit.results[0].checks[0].detail) && hit.results[0].ok,
    hit.results.map(r => r.checks[0].detail).join(' | '));
}

// E5: non-fallback repo with every route dead -> empty results, populated trail
{
  ROUTES = [];
  mod.FLEET.length = 0; mod.FLEET.push({ repo: 'secretgate', signer: w1.address });
  const hit = await mod.collectReceipts('secretgate');
  T('E5: dead remote = zero results + tried trail (no crash)',
    hit.results.length === 0 && hit.tried.length >= 2, hit.tried.join('; '));
}

// ---- minimal DOM stub for loadFleet ----
// The REAL renderReceiptInto (render layer between CORE and NET) runs against
// this stub DOM — asserting the actual rendered HTML, not a stubbed call.
function makeDom() {
  globalThis.RENDERED_HTML = [];
  const mkEl = () => ({ className: '', innerHTML: '', appendChild() {} });
  const root = { innerHTML: '', children: [], appendChild(c) { this.children.push(c); globalThis.RENDERED_HTML.push((c.innerHTML || '') + (c.children || []).map(x => x.innerHTML).join('\n')); } };
  globalThis.document = { getElementById: () => root, createElement: mkEl };
  return root;
}

// F1: every fleet repo resolves -> ALL VALID summary with count
{
  mod.FLEET.length = 0;
  mod.FLEET.push({ repo: 'ethkey-lite', signer: w1.address }, { repo: 'secretgate', signer: w3.address });
  ROUTES = [
    [/tianzhicdev\/ethkey-lite\/tags\?/, () => tags(['v1.0'])],
    [/tianzhicdev\/secretgate\/tags\?/, () => tags(['v2.0'])],
    [/tianzhicdev\/ethkey-lite\/contents\/proofs\?ref=v1\.0$/, () => files(['v1.0-a.md'])],
    [/tianzhicdev\/secretgate\/contents\/proofs\?ref=v2\.0$/, () => files(['v2.0-a.md'])],
    [/tianzhicdev\/ethkey-lite\/v1\.0\/proofs\/v1\.0-a\.md$/, () => rcC],
    [/tianzhicdev\/secretgate\/v2\.0\/proofs\/v2\.0-a\.md$/, () => rc3],
  ];
  const root = makeDom();
  await mod.loadFleet();
  const sum = root.children[root.children.length - 1].innerHTML;
  T('F1: all-reachable fleet -> ALL FLEET RECEIPTS VALID 2/2',
    /ALL FLEET RECEIPTS VALID/.test(sum) && /2\/2 receipts valid/.test(sum), sum);
}

// F2: one repo unreachable -> INCOMPLETE summary, failure card, never a fake PASS
{
  ROUTES = [
    [/tianzhicdev\/ethkey-lite\/tags\?/, () => tags(['v1.0'])],
    [/tianzhicdev\/ethkey-lite\/contents\/proofs\?ref=v1\.0$/, () => files(['v1.0-a.md'])],
    [/tianzhicdev\/ethkey-lite\/v1\.0\/proofs\/v1\.0-a\.md$/, () => rcC],
    // secretgate: every route 404s (default fallthrough)
  ];
  const root = makeDom();
  await mod.loadFleet();
  const sum = root.children[root.children.length - 1].innerHTML;
  T('F2: unreachable repo -> FLEET CHECK INCOMPLETE 1/2, no fake PASS',
    /FLEET CHECK INCOMPLETE/.test(sum) && /1\/2 receipts valid/.test(sum) && !/ALL FLEET RECEIPTS VALID/.test(sum), sum);
  const emitted = globalThis.RENDERED_HTML.join('\n');
  T('F2: the outage surfaces as a rendered fetch-failure card (FAIL badge + trail)',
    /could not load any receipt/.test(emitted) && /badge fail/.test(emitted), emitted.slice(0, 200));
}

// P2: JS-built receipt (ethers signature) verifies under the page's own
// verifier; written to tmp for the bash step to re-verify via the PYTHON CLI.
{
  const r = await mod.verifyReceipt(rcC, w1.address);
  T('P2: ethers-signed receipt verifies under page CORE (sig+payload+signer+require)',
    r.ok, JSON.stringify(r.checks));
  const outp = path.join(REPO, 'js-proof-parity.md');
  fs.writeFileSync(outp, rcC);
  console.log('JS_PROOF_WRITTEN ' + outp);
}

// FLEET pin (c16/c25): the trust-anchor table the page hardcodes must stay
// byte-equal to these values (copied from the team LEDGER). A silent swap in
// receipt.html turns CI red instead of shipping a stealth trust change.
{
  const PINNED = {
    'ethkey-lite': '0xf232dcdc177b53981b4d805a48c79f239db8d0f9',
    'secretgate': '0xfd4090e27c1f946ff01a265caa7d4aca662acc15',
    'hookpack': '0xfd4090e27c1f946ff01a265caa7d4aca662acc15',
    'secretgate-action': '0xfd4090e27c1f946ff01a265caa7d4aca662acc15',
  };
  // read from the COMMITTED page (mod.FLEET above has been mutated by E-cases)
  const fleetSrc = html.match(/const FLEET = \[([\s\S]*?)\];/);
  const pairs = [...(fleetSrc ? fleetSrc[1] : '').matchAll(/repo:\s*'([^']+)',\s*signer:\s*'(0x[0-9a-fA-F]{40})'/g)]
    .map(m => [m[1], m[2].toLowerCase()]);
  T('PIN: FLEET table == LEDGER-pinned repo->signer pairs (no extra, no drift)',
    pairs.length === Object.keys(PINNED).length &&
    pairs.every(([r, s]) => PINNED[r] === s),
    JSON.stringify(pairs));
}

// ---- BOOT matrix (c26, audit gap #21) ----
// The BOOT block (click wiring + the deep-link boot() IIFE) is extracted
// VERBATIM from the page and executed against a capturing stub DOM + the
// ROUTES fetch stub. The ONLY harness seam is prefixing the IIFE with an
// assignment (globalThis.__BOOTP = ...) so it can be awaited, and injecting
// the FLEET pin seam BEFORE the boot block (boot reads FLEET synchronously,
// so mutating mod.FLEET after evaluation is too late).
const boot = html.match(/\/\/ ---- BOOT BEGIN ----[^\n]*\n([\s\S]*?)\/\/ ---- BOOT END ----/);
if (!boot) { console.error('BOOT block not found in receipt.html'); process.exit(1); }
const bootPatched = boot[1].replace('(async function boot()', 'globalThis.__BOOTP = (async function boot()');
T('BOOT: block holds the click wiring + boot() IIFE',
  boot[1].includes("getElementById('rp_btn').addEventListener") && boot[1].includes('(async function boot()'));

// rich stub DOM: per-id elements, capture rendered cards + click wiring
function makeBootDom() {
  globalThis.RENDERED_HTML = [];
  const clicks = {};
  const root = { innerHTML: '', children: [], appendChild(c) { this.children.push(c); globalThis.RENDERED_HTML.push(c.innerHTML || ''); } };
  const mk = (id) => ({ id, className: '', innerHTML: '', value: '', children: [],
    appendChild(c) { this.children.push(c); globalThis.RENDERED_HTML.push(c.innerHTML || ''); },
    addEventListener(_ev, fn) { clicks[id] = fn; } });
  const els = {};
  for (const id of ['rp_btn', 'rp_load', 'rp_fleet', 'rp_input', 'rp_require', 'rp_output']) els[id] = mk(id);
  els.rp_output.appendChild = root.appendChild.bind(root);
  els.rp_output.children = root.children;
  globalThis.document = { getElementById: (id) => els[id], createElement: () => ({ className: '', innerHTML: '', appendChild() {} }) };
  return { els, clicks };
}

async function runBoot(qs, fleetSeam) {
  globalThis.location = { search: qs };
  CALLS = [];
  const { els, clicks } = makeBootDom();
  await new Function(core[1] + render[1] + net[1] + fleetSeam + bootPatched)();
  await globalThis.__BOOTP;
  return { els, clicks, out: globalThis.RENDERED_HTML.join('\n') };
}
const SEAM = "FLEET.length = 0; FLEET.push({ repo: 'ethkey-lite', signer: '" + w1.address + "' }, { repo: 'secretgate', signer: '" + w3.address + "' });";

// G1: no params -> zero auto-render, zero fetches, empty prefill, ALL THREE click handlers wired
{
  const r = await runBoot('', SEAM);
  T('G1: no params -> nothing rendered, nothing fetched, require field empty',
    r.out === '' && CALLS.length === 0 && r.els.rp_require.value === '', r.out.slice(0, 120));
  T('G1: click wiring registered (btn/load/fleet)',
    ['rp_btn', 'rp_load', 'rp_fleet'].every((id) => typeof r.clicks[id] === 'function'), JSON.stringify(Object.keys(r.clicks)));
}

// G2: ?require=<valid> alone -> field prefilled + honest 'paste to verify' card, ZERO fetches
{
  const r = await runBoot('?require=' + w1.address.toLowerCase(), SEAM);
  T('G2: valid require-only prefills field verbatim', r.els.rp_require.value === w1.address.toLowerCase(), r.els.rp_require.value);
  T('G2: renders PASS require-param card, fetches NOTHING',
    /required signer prefilled/.test(r.out) && /badge pass/.test(r.out) && CALLS.length === 0, r.out.slice(0, 160));
}

// G3: ?require=<malformed> -> refusal card, field STAYS EMPTY, zero fetches
{
  const r = await runBoot('?require=not-an-address', SEAM);
  T('G3: malformed require -> refusal card + empty field + zero fetches',
    /URL param refused/.test(r.out) && r.els.rp_require.value === '' && CALLS.length === 0, r.out.slice(0, 160));
}

// G4: honored pair ?load=latest&require=<pinned> -> auto-runs loader against pinned signer, RECEIPT VALID
{
  ROUTES = [
    [/tianzhicdev\/ethkey-lite\/tags\?/, () => tags(['v0.7'])],
    [/tianzhicdev\/ethkey-lite\/contents\/proofs\?ref=v0\.7$/, () => files(['v0.7-a.md'])],
    [/tianzhicdev\/ethkey-lite\/v0\.7\/proofs\/v0\.7-a\.md$/, () => rcC],
  ];
  const r = await runBoot('?load=latest&require=' + w1.address.toLowerCase(), SEAM);
  T('G4: honored pair auto-loads + renders RECEIPT VALID against pinned signer',
    /RECEIPT VALID/.test(r.out) && CALLS.some(u => /ref=v0\.7/.test(u)), r.out.slice(0, 200));
}

// G5: mismatched pair (require != pinned for that repo) -> refusal names pinned signer, ZERO fetches, empty field
{
  const r = await runBoot('?repo=secretgate&require=' + w1.address.toLowerCase(), SEAM);
  T('G5: mismatch pair -> refusal names the pinned signer, zero fetches, no prefill',
    /the pair disagrees with the pinned FLEET table/.test(r.out) &&
    r.out.includes(w3.address) && CALLS.length === 0 && r.els.rp_require.value === '', r.out.slice(0, 200));
}

// G6: ?repo=<allowed> alone (no load) -> 'noted' card, zero fetches
{
  const r = await runBoot('?repo=secretgate', SEAM);
  T('G6: repo-only -> noted card, add-&load hint, zero fetches',
    /\?repo=secretgate noted/.test(r.out) && CALLS.length === 0, r.out.slice(0, 160));
}

console.log(fails ? fails + ' FAILURES' : 'net-harness OK');
process.exit(fails ? 1 : 0);
