import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const reportsDir = path.resolve(__dirname, '..', 'reports');
const audits = new Map();

const localAgentOrder = [
  'Scope Agent',
  'Recon Agent',
  'Route Agent',
  'Scanner Agent',
  'CORS Agent',
  'Exploit Agent',
  'PoC Agent',
  'Duplicate Agent',
  'Report Agent'
];

const externalProgramAgentOrder = [
  'Scope Agent',
  'Recon Agent',
  'Scanner Agent',
  'Report Agent'
];

const EXTERNAL_PROGRAM_MODE = 'external-program-passive';
const EXTERNAL_BOUNDED_MODE = 'external-program-bounded';
const EXTERNAL_REQUESTS_PER_SECOND = 1;
const INTIGRITI_PWN_PROFILE_ID = 'intigriti-pwn';
const INTIGRITI_PWN_PROOF_PROFILE_ID = 'intigriti-pwn-proof';
const INTIGRITI_PWN_POLICY_URL = 'https://app.intigriti.com/programs/intigriti/intigriti/detail';
const INTIGRITI_PWN_HOST_SUFFIX = '.pwn.intigriti.rocks';
const INTIGRITI_PWN_REQUESTS_PER_SECOND = 2;
const INTIGRITI_PWN_REQUEST_BUDGET = 24;

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function nowTime() {
  return new Date().toLocaleTimeString([], { hour12: false });
}

function pushEvent(audit, agent, message, state = 'done') {
  audit.timeline.unshift({ time: nowTime(), agent, message, state });
}

function normalizeTarget(rawTarget) {
  const value = String(rawTarget || '').trim();
  if (!value) throw new Error('Target is required.');

  const withProtocol = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  const url = new URL(withProtocol);

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Only HTTP and HTTPS targets are supported.');
  }

  url.hash = '';
  return {
    input: value,
    url: url.toString(),
    origin: url.origin,
    hostname: url.hostname,
    protocol: url.protocol
  };
}

function isExternalProgramMode(mode) {
  return mode === EXTERNAL_PROGRAM_MODE || mode === EXTERNAL_BOUNDED_MODE;
}

function isPrivateOrReservedIp(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const octets = address.split('.').map(Number);
    const [first, second] = octets;
    return (
      first === 0 ||
      first === 10 ||
      first === 127 ||
      first >= 224 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && (second === 0 || second === 168)) ||
      (first === 198 && (second === 18 || second === 19 || second === 51)) ||
      (first === 203 && second === 0)
    );
  }

  if (family === 6) {
    const normalized = address.toLowerCase();
    return (
      normalized === '::' ||
      normalized === '::1' ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('fe80:') ||
      normalized.startsWith('2001:db8:') ||
      normalized.startsWith('::ffff:127.')
    );
  }

  return true;
}

function buildExternalProgramPlan({ target, authorized, programProfile }) {
  if (!authorized) {
    throw new Error('Confirm that you are authorized to test this target before running agents.');
  }

  const normalized = normalizeTarget(target);
  if (normalized.protocol !== 'https:') {
    throw new Error('External Program mode requires one exact HTTPS URL.');
  }
  if (net.isIP(normalized.hostname) || normalized.hostname === 'localhost' || normalized.hostname.endsWith('.localhost')) {
    throw new Error('External Program mode requires a public program hostname, not an IP address or localhost.');
  }

  const profile = programProfile || {};
  const platform = String(profile.platform || '').trim();
  const programName = String(profile.programName || '').trim();
  const policyUrl = String(profile.policyUrl || '').trim();
  const exactScopeUrl = String(profile.exactScopeUrl || normalized.url).trim();
  const profileId = String(profile.profileId || 'custom-passive').trim();

  if (profileId === INTIGRITI_PWN_PROOF_PROFILE_ID) {
    throw new Error('Controlled-proof receipts never execute automatic target traffic in the Safe Web engine.');
  }

  if (!['HackerOne', 'Bugcrowd', 'Intigriti'].includes(platform)) {
    throw new Error('External Program mode requires HackerOne, Bugcrowd, or Intigriti as the program platform.');
  }
  if (!programName) {
    throw new Error('Record the program name before running External Program mode.');
  }
  if (!policyUrl || !/^https:\/\//i.test(policyUrl)) {
    throw new Error('Record the current HTTPS policy URL before running External Program mode.');
  }
  if (!profile.automationAcknowledged) {
    throw new Error('Confirm that the current program policy permits this low-rate read-only check.');
  }
  if (!profile.humanReviewAcknowledged) {
    throw new Error('Confirm that you will manually validate any observation before reporting it.');
  }

  const normalizedScope = normalizeTarget(exactScopeUrl);
  if (normalizedScope.url !== normalized.url) {
    throw new Error('External Program mode only contacts the exact in-scope URL recorded in the policy receipt.');
  }

  if (profileId === INTIGRITI_PWN_PROFILE_ID) {
    const researcherUsername = String(profile.researcherUsername || '').trim();
    if (platform !== 'Intigriti') {
      throw new Error('The Intigriti PWN profile must use the Intigriti platform.');
    }
    if (normalized.hostname !== 'pwn.intigriti.rocks' && !normalized.hostname.endsWith(INTIGRITI_PWN_HOST_SUFFIX)) {
      throw new Error('The Intigriti PWN profile only permits an exact host under *.pwn.intigriti.rocks.');
    }
    if (policyUrl.replace(/\/$/, '') !== INTIGRITI_PWN_POLICY_URL) {
      throw new Error('The Intigriti PWN profile must use its pinned official policy URL.');
    }
    if (!/^[A-Za-z0-9_.-]{2,64}$/.test(researcherUsername)) {
      throw new Error('Enter your real Intigriti username for the required attribution header.');
    }

    return {
      profileId: INTIGRITI_PWN_PROFILE_ID,
      platform: 'Intigriti',
      programName: 'Intigriti',
      policyUrl: INTIGRITI_PWN_POLICY_URL,
      policySnapshotDate: profile.policySnapshotDate || '2026-07-21',
      exactScopeUrl: normalized.url,
      allowedHostSuffix: INTIGRITI_PWN_HOST_SUFFIX,
      researcherUsername,
      attributionHeaders: ['X-Intigriti-Username', 'User-Agent'],
      requestRatePerSecond: INTIGRITI_PWN_REQUESTS_PER_SECOND,
      publishedRequestRatePerSecond: 10,
      requestBudget: INTIGRITI_PWN_REQUEST_BUDGET,
      allowedMethods: ['GET', 'HEAD'],
      redirectPolicy: 'same-origin-only; maximum 2',
      discoveryPolicy: 'root, standard policy files, and same-origin links/assets found in retrieved pages',
      prohibitedActions: [
        'cross-origin discovery',
        'subdomain enumeration',
        'credential attacks',
        'form submission',
        'state-changing requests',
        'payload mutation',
        'denial of service',
        "access to other users' data"
      ],
      automationAcknowledged: true,
      humanReviewAcknowledged: true,
      recordedAt: profile.recordedAt || new Date().toISOString()
    };
  }

  return {
    profileId: 'custom-passive',
    platform,
    programName,
    policyUrl,
    exactScopeUrl: normalized.url,
    requestRatePerSecond: EXTERNAL_REQUESTS_PER_SECOND,
    requestBudget: 1,
    allowedMethods: ['GET'],
    redirectPolicy: 'do-not-follow',
    prohibitedActions: [
      'path discovery',
      'route guessing',
      'CORS origin manipulation',
      'authentication',
      'payload mutation',
      'active exploitation',
      'reproduction traffic'
    ],
    automationAcknowledged: true,
    humanReviewAcknowledged: true,
    recordedAt: new Date().toISOString()
  };
}

function createRequestPacer(requestsPerSecond) {
  const intervalMs = Math.ceil(1000 / requestsPerSecond);
  let nextAllowedAt = 0;

  return {
    async wait() {
      const now = Date.now();
      const scheduledAt = Math.max(now, nextAllowedAt);
      nextAllowedAt = scheduledAt + intervalMs;
      const waitMs = Math.max(0, scheduledAt - now);
      if (waitMs) await delay(waitMs);
      return { scheduledAt, waitMs, intervalMs };
    }
  };
}

async function assertExternalTargetResolvesPublic(audit) {
  const addresses = await dns.lookup(audit.target.hostname, { all: true });
  if (!addresses.length || addresses.some((entry) => isPrivateOrReservedIp(entry.address))) {
    throw new Error('External Program mode blocked a hostname that resolves to a private or reserved address.');
  }
  audit.evidence.dns = addresses.map((entry) => `${entry.family === 6 ? 'AAAA' : 'A'} ${entry.address}`);
  return addresses;
}

function createAudit({ target, scopeRules = '', mode = 'standard', authorized, programProfile }) {
  if (!authorized) {
    throw new Error('Confirm that you are authorized to test this target before running agents.');
  }

  const id = crypto.randomUUID();
  const normalized = normalizeTarget(target);
  const externalProgram = isExternalProgramMode(mode);
  const policyReceipt = externalProgram
    ? buildExternalProgramPlan({ target: normalized.url, authorized, programProfile })
    : null;
  const audit = {
    id,
    target: normalized,
    mode,
    scopeRules,
    policyReceipt,
    status: 'queued',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    agents: (externalProgram ? externalProgramAgentOrder : localAgentOrder).map((name) => ({
      name,
      role: roleForAgent(name),
      status: 'queued',
      progress: 0,
      summary: 'Waiting for orchestrator',
      evidence: []
    })),
    findings: [],
    evidence: {},
    timeline: [],
    report: null,
    error: null,
    requestPacer: externalProgram ? createRequestPacer(policyReceipt.requestRatePerSecond) : null,
    requestLog: []
  };

  audits.set(id, audit);
  runAudit(audit).catch((error) => {
    audit.status = 'failed';
    audit.error = error.message;
    audit.updatedAt = new Date().toISOString();
    pushEvent(audit, 'Orchestrator', error.message, 'error');
  });

  return audit;
}

function listAudits() {
  return [...audits.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

function getAudit(id) {
  return audits.get(id);
}

function roleForAgent(name) {
  return {
    'Scope Agent': 'Confirms rules and normalizes target',
    'Recon Agent': 'Captures bounded live Web evidence',
    'Route Agent': 'Safely probes common app endpoints',
    'Scanner Agent': 'Records response posture and metadata',
    'CORS Agent': 'Checks browser trust boundaries',
    'Exploit Agent': 'Validates safely reproducible impact',
    'PoC Agent': 'Creates copyable repro commands',
    'Duplicate Agent': 'Builds public duplicate search leads',
    'Report Agent': 'Packages evidence into markdown'
  }[name];
}

function getAgent(audit, name) {
  return audit.agents.find((agent) => agent.name === name);
}

async function runAgent(audit, name, fn) {
  const agent = getAgent(audit, name);
  agent.status = 'running';
  agent.progress = Math.max(agent.progress, 12);
  agent.summary = 'Running';
  audit.status = 'running';
  audit.updatedAt = new Date().toISOString();
  pushEvent(audit, name, 'Started');

  await delay(250);
  const result = await fn(audit, agent);
  agent.status = 'complete';
  agent.progress = 100;
  agent.summary = result?.summary || 'Complete';
  agent.evidence = result?.evidence || agent.evidence;
  audit.updatedAt = new Date().toISOString();
  pushEvent(audit, name, agent.summary);
}

async function runAudit(audit) {
  if (isExternalProgramMode(audit.mode)) {
    await runAgent(audit, 'Scope Agent', runExternalProgramScopeAgent);
    await runAgent(audit, 'Recon Agent', runExternalProgramReconAgent);
    await runAgent(audit, 'Scanner Agent', runExternalProgramObservationAgent);
    await runAgent(audit, 'Report Agent', runReportAgent);
    audit.status = 'complete';
    audit.updatedAt = new Date().toISOString();
    pushEvent(
      audit,
      'Orchestrator',
      audit.policyReceipt?.profileId === INTIGRITI_PWN_PROFILE_ID
        ? 'External Program bounded live map complete'
        : 'External Program passive observation complete'
    );
    return;
  }

  await runAgent(audit, 'Scope Agent', runScopeAgent);
  await runAgent(audit, 'Recon Agent', runReconAgent);
  await runAgent(audit, 'Route Agent', runRouteAgent);
  await runAgent(audit, 'Scanner Agent', runScannerAgent);
  await runAgent(audit, 'CORS Agent', runCorsAgent);
  await runAgent(audit, 'Exploit Agent', runExploitAgent);
  await runAgent(audit, 'PoC Agent', runPocAgent);
  await runAgent(audit, 'Duplicate Agent', runDuplicateAgent);
  await runAgent(audit, 'Report Agent', runReportAgent);
  audit.status = 'complete';
  audit.updatedAt = new Date().toISOString();
  pushEvent(audit, 'Orchestrator', `Audit complete with ${audit.findings.length} findings`);
}

async function runRouteAgent(audit) {
  const probes = [
    '/',
    '/robots.txt',
    '/sitemap.xml',
    '/.well-known/security.txt',
    '/api',
    '/graphql',
    '/admin',
    '/login',
    '/debug',
    '/health',
    '/status',
    '/.env'
  ];
  const routes = [];

  for (const route of probes) {
    const url = new URL(route, audit.target.origin).toString();
    try {
      const { response } = await fetchText(url, { method: 'HEAD', timeoutMs: 3500 });
      routes.push({ route, url, status: response.status, contentType: response.headers.get('content-type') || '' });
    } catch (error) {
      routes.push({ route, url, status: 'error', error: error.message });
    }
  }

  audit.evidence.routes = routes;
  return {
    summary: `${routes.length} routes probed safely`,
    evidence: routes.map((route) => `${route.route}: ${route.status}`)
  };
}

async function runScopeAgent(audit) {
  const evidence = [
    `Target normalized to ${audit.target.url}`,
    `Allowed origin: ${audit.target.origin}`,
    audit.scopeRules ? `Scope notes recorded: ${audit.scopeRules.slice(0, 180)}` : 'No extra scope notes supplied'
  ];
  audit.evidence.scope = evidence;
  return { summary: 'Authorized scope locked', evidence };
}

async function runExternalProgramScopeAgent(audit) {
  await assertExternalTargetResolvesPublic(audit);
  const receipt = audit.policyReceipt;
  const bounded = receipt.profileId === INTIGRITI_PWN_PROFILE_ID;
  const evidence = [
    `Platform: ${receipt.platform}`,
    `Program: ${receipt.programName}`,
    `Policy: ${receipt.policyUrl}`,
    `Exact in-scope URL: ${receipt.exactScopeUrl}`,
    `HTTP ceiling: ${receipt.requestRatePerSecond} request/second; budget ${receipt.requestBudget} requests`,
    `Redirects: ${receipt.redirectPolicy}`,
    bounded ? `Attribution headers: ${receipt.attributionHeaders.join(', ')}` : 'Attribution headers: none recorded',
    bounded
      ? 'Discovery: retrieved same-origin public links/assets only; no subdomain or parameter enumeration.'
      : 'Discovery: disabled; one response only.',
    'Output: evidence and hypotheses only; deterministic manual proof is required before any report.'
  ];
  audit.evidence.scope = evidence;
  audit.evidence.policyReceipt = receipt;
  return { summary: 'Program policy receipt locked', evidence };
}

async function readLimitedText(response, maxBytes) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let received = 0;
  let text = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      await reader.cancel('Bug Bunny response-size limit reached');
      throw new Error(`Response exceeded the ${maxBytes}-byte safety limit`);
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

async function fetchText(rawUrl, options = {}) {
  const method = options.method || 'GET';
  const timeoutMs = options.timeoutMs || 8000;
  const maxBytes = options.maxBytes || 524_288;
  const allowedOrigin = options.allowedOrigin || new URL(rawUrl).origin;
  const maxRedirects = options.maxRedirects ?? 4;
  let currentUrl = new URL(rawUrl);

  for (let redirectCount = 0; redirectCount <= maxRedirects; redirectCount += 1) {
    if (!['http:', 'https:'].includes(currentUrl.protocol)) {
      throw new Error(`Blocked non-HTTP protocol: ${currentUrl.protocol}`);
    }
    if (currentUrl.origin !== allowedOrigin) {
      throw new Error(`Blocked cross-origin redirect to ${currentUrl.origin}`);
    }
    if (options.requestBudget && (options.requestLog?.length || 0) >= options.requestBudget) {
      throw new Error(`Request budget of ${options.requestBudget} exhausted before ${method} ${currentUrl}`);
    }

    const pacing = await options.pacer?.wait();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(currentUrl, {
        method,
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'user-agent': 'BugBunnyLocal/0.2 authorized-safe-web-audit',
          ...(options.headers || {})
        }
      });

      if ([301, 302, 303, 307, 308].includes(response.status)) {
        options.requestLog?.push({
          method,
          url: currentUrl.toString(),
          status: response.status,
          time: new Date().toISOString(),
          waitMs: pacing?.waitMs || 0,
          redirect: 'not-followed'
        });
        if (maxRedirects === 0) {
          return { response, text: '', redirectBlocked: true };
        }
        const location = response.headers.get('location');
        if (!location) return { response, text: '' };
        currentUrl = new URL(location, currentUrl);
        continue;
      }

      const text = method === 'HEAD' ? '' : await readLimitedText(response, maxBytes);
      options.requestLog?.push({
        method,
        url: currentUrl.toString(),
        status: response.status,
        time: new Date().toISOString(),
        waitMs: pacing?.waitMs || 0
      });
      return { response, text };
    } catch (error) {
      options.requestLog?.push({
        method,
        url: currentUrl.toString(),
        status: 'error',
        error: error.message,
        time: new Date().toISOString(),
        waitMs: pacing?.waitMs || 0
      });
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  throw new Error('Redirect limit exceeded');
}

async function runExternalProgramReconAgent(audit) {
  if (audit.policyReceipt.profileId === INTIGRITI_PWN_PROFILE_ID) {
    return runBoundedExternalProgramReconAgent(audit);
  }
  const page = await fetchText(audit.target.url, {
    method: 'GET',
    timeoutMs: 8000,
    maxBytes: 262_144,
    maxRedirects: 0,
    allowedOrigin: audit.target.origin,
    pacer: audit.requestPacer,
    requestLog: audit.requestLog,
    requestBudget: audit.policyReceipt.requestBudget
  });
  const headers = Object.fromEntries(page.response.headers.entries());
  const title = page.text.match(/<title[^>]*>(.*?)<\/title>/is)?.[1]?.replace(/\s+/g, ' ').trim() || 'No title found';
  const forms = [...page.text.matchAll(/<form\b[^>]*>/gi)].length;

  audit.evidence.http = {
    status: page.response.status,
    finalUrl: page.response.url,
    headers,
    title,
    forms,
    links: [],
    redirectBlocked: Boolean(page.redirectBlocked)
  };
  audit.evidence.requestLog = audit.requestLog;

  const evidence = [
    `GET ${audit.target.url}`,
    `HTTP ${page.response.status}`,
    `Title: ${title}`,
    `${forms} forms observed without interaction`,
    page.redirectBlocked ? 'Redirect response recorded but not followed.' : 'No redirects or discovered links were followed.'
  ];
  return { summary: 'One exact URL observed with no discovery', evidence };
}

function externalRequestHeaders(audit) {
  if (audit.policyReceipt.profileId !== INTIGRITI_PWN_PROFILE_ID) return {};
  const username = audit.policyReceipt.researcherUsername;
  return {
    'user-agent': `BugBunny/0.3 Intigriti-${username} evidence-mapper`,
    'x-intigriti-username': username
  };
}

function safeDiscoveredUrl(rawUrl, origin) {
  try {
    const url = new URL(rawUrl, origin);
    if (url.origin !== origin || url.protocol !== 'https:') return null;
    if (url.username || url.password) return null;
    url.hash = '';
    url.search = '';
    const lowerPath = url.pathname.toLowerCase();
    if (/\/(?:logout|log-out|signout|sign-out|delete|remove|unsubscribe|terminate)(?:\/|$)/.test(lowerPath)) return null;
    if (/\.(?:png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|mp4|webm|zip|pdf)$/i.test(lowerPath)) return null;
    return url.toString();
  } catch {
    return null;
  }
}

function extractClientEndpoints(source, origin) {
  const endpoints = new Set();
  const endpointPattern = /["'`](\/(?:api|graphql|auth|oauth|v\d+|admin|internal)(?:\/[A-Za-z0-9_.~:{}-]+){0,8})["'`]/gi;
  for (const match of source.matchAll(endpointPattern)) {
    const safe = safeDiscoveredUrl(match[1], origin);
    if (safe) endpoints.add(safe);
    if (endpoints.size >= 40) break;
  }
  return [...endpoints];
}

async function runBoundedExternalProgramReconAgent(audit) {
  const receipt = audit.policyReceipt;
  const requestOptions = {
    timeoutMs: 8000,
    maxBytes: 524_288,
    maxRedirects: 2,
    allowedOrigin: audit.target.origin,
    pacer: audit.requestPacer,
    requestLog: audit.requestLog,
    requestBudget: receipt.requestBudget,
    headers: externalRequestHeaders(audit)
  };
  const page = await fetchText(audit.target.url, { ...requestOptions, method: 'GET' });
  const headers = Object.fromEntries(page.response.headers.entries());
  const title = page.text.match(/<title[^>]*>(.*?)<\/title>/is)?.[1]?.replace(/\s+/g, ' ').trim() || 'No title found';
  const forms = [...page.text.matchAll(/<form\b[^>]*>/gi)].length;
  const discovered = collectLinks(page.text, audit.target.origin)
    .map((url) => safeDiscoveredUrl(url, audit.target.origin))
    .filter(Boolean)
    .filter((url) => url !== audit.target.url);
  const uniqueDiscovered = [...new Set(discovered)].slice(0, 30);
  const standardUrls = [
    new URL('/robots.txt', audit.target.origin).toString(),
    new URL('/.well-known/security.txt', audit.target.origin).toString()
  ];
  const javascriptUrls = uniqueDiscovered.filter((url) => /\.m?js$/i.test(new URL(url).pathname)).slice(0, 8);
  const publicPageUrls = uniqueDiscovered
    .filter((url) => !/\.(?:m?js|css|map|json|txt)$/i.test(new URL(url).pathname))
    .slice(0, 10);
  const artifacts = [];
  const clientEndpoints = new Set(extractClientEndpoints(page.text, audit.target.origin));

  for (const url of standardUrls) {
    if (audit.requestLog.length >= receipt.requestBudget) break;
    try {
      const result = await fetchText(url, { ...requestOptions, method: 'GET', maxBytes: 131_072 });
      artifacts.push({
        kind: 'standard-policy',
        url,
        method: 'GET',
        status: result.response.status,
        contentType: result.response.headers.get('content-type') || '',
        bytes: Buffer.byteLength(result.text)
      });
    } catch (error) {
      artifacts.push({ kind: 'standard-policy', url, method: 'GET', status: 'error', error: error.message });
    }
  }

  for (const url of javascriptUrls) {
    if (audit.requestLog.length >= receipt.requestBudget) break;
    try {
      const result = await fetchText(url, { ...requestOptions, method: 'GET' });
      artifacts.push({
        kind: 'javascript',
        url,
        method: 'GET',
        status: result.response.status,
        contentType: result.response.headers.get('content-type') || '',
        bytes: Buffer.byteLength(result.text)
      });
      for (const endpoint of extractClientEndpoints(result.text, audit.target.origin)) clientEndpoints.add(endpoint);
    } catch (error) {
      artifacts.push({ kind: 'javascript', url, method: 'GET', status: 'error', error: error.message });
    }
  }

  for (const url of publicPageUrls) {
    if (audit.requestLog.length >= receipt.requestBudget) break;
    try {
      const result = await fetchText(url, { ...requestOptions, method: 'HEAD', maxBytes: 1 });
      artifacts.push({
        kind: 'linked-route',
        url,
        method: 'HEAD',
        status: result.response.status,
        contentType: result.response.headers.get('content-type') || ''
      });
    } catch (error) {
      artifacts.push({ kind: 'linked-route', url, method: 'HEAD', status: 'error', error: error.message });
    }
  }

  audit.evidence.http = {
    status: page.response.status,
    finalUrl: page.response.url,
    headers,
    title,
    forms,
    links: uniqueDiscovered,
    redirectBlocked: Boolean(page.redirectBlocked)
  };
  audit.evidence.publicArtifacts = artifacts;
  audit.evidence.clientEndpoints = [...clientEndpoints];
  audit.evidence.requestLog = audit.requestLog;

  const evidence = [
    `GET ${audit.target.url} returned HTTP ${page.response.status}`,
    `Title: ${title}`,
    `${forms} forms observed without interaction`,
    `${uniqueDiscovered.length} same-origin public links/assets collected`,
    `${artifacts.length} linked or standard resources checked`,
    `${clientEndpoints.size} client-side endpoint candidates extracted`,
    `${audit.requestLog.length} of ${receipt.requestBudget} requests used at ≤${receipt.requestRatePerSecond}/second`
  ];
  return { summary: `Mapped ${uniqueDiscovered.length} public assets within a ${receipt.requestBudget}-request budget`, evidence };
}

async function runExternalProgramObservationAgent(audit) {
  if (audit.policyReceipt.profileId === INTIGRITI_PWN_PROFILE_ID) {
    const requestCount = audit.evidence.requestLog?.length || 0;
    const artifactCount = audit.evidence.publicArtifacts?.length || 0;
    const endpointCount = audit.evidence.clientEndpoints?.length || 0;
    const evidence = [
      `${requestCount} attributed requests stayed inside the ${audit.policyReceipt.requestBudget}-request budget`,
      `${artifactCount} public linked or standard resources were recorded`,
      `${endpointCount} client-side endpoint candidates were extracted without probing them`,
      'No forms were submitted and no state-changing methods or payload mutations were used.'
    ];
    audit.findings.push({
      id: crypto.randomUUID(),
      severity: 'Info',
      path: audit.target.url,
      title: 'Bounded live attack surface captured',
      hypothesis: 'The collected public routes and client-side endpoint candidates are leads for manual, in-scope testing—not vulnerability claims.',
      confidence: 100,
      status: 'Evidence captured — manual validation required',
      time: 'just now',
      evidence,
      remediation: 'Review the mapped authentication and data boundaries, then choose one victim-centered hypothesis for manual proof.',
      poc: ''
    });
    audit.evidence.observationBoundary = {
      reportable: false,
      reason: 'A bounded attack-surface map does not establish exploitability, victim harm, or uniqueness.'
    };
    return { summary: 'Live attack surface recorded; no vulnerability asserted', evidence };
  }

  const headers = audit.evidence.http?.headers || {};
  const present = (name) => Boolean(headers[name]);
  const evidence = [
    `content-security-policy: ${present('content-security-policy') ? 'present' : 'absent'}`,
    `strict-transport-security: ${present('strict-transport-security') ? 'present' : 'absent'}`,
    `x-frame-options: ${present('x-frame-options') ? 'present' : 'absent'}`,
    `referrer-policy: ${present('referrer-policy') ? 'present' : 'absent'}`,
    `set-cookie: ${present('set-cookie') ? 'present' : 'absent'}`
  ];
  const observation = {
    id: crypto.randomUUID(),
    severity: 'Info',
    path: audit.target.url,
    title: 'Response security posture captured',
    hypothesis: 'This is a passive header inventory, not a vulnerability determination.',
    confidence: 100,
    status: 'Observed — manual validation required',
    time: 'just now',
    evidence,
    remediation: 'Do not submit this observation. Use it only to prioritize manual, in-scope research.',
    poc: ''
  };
  audit.findings.push(observation);
  audit.evidence.observationBoundary = {
    reportable: false,
    reason: 'External Program mode performs one passive GET request and does not validate exploitability.'
  };
  return { summary: 'Passive posture recorded; no finding asserted', evidence };
}

async function runReconAgent(audit) {
  const evidence = [];
  try {
    const addresses = await dns.lookup(audit.target.hostname, { all: true });
    audit.evidence.dns = addresses.map((entry) => `${entry.family === 6 ? 'AAAA' : 'A'} ${entry.address}`);
    evidence.push(`${addresses.length} DNS addresses resolved`);
  } catch (error) {
    audit.evidence.dns = [`DNS lookup failed: ${error.message}`];
    evidence.push('DNS lookup failed');
  }

  const page = await fetchText(audit.target.url);
  const headers = Object.fromEntries(page.response.headers.entries());
  const title = page.text.match(/<title[^>]*>(.*?)<\/title>/is)?.[1]?.replace(/\s+/g, ' ').trim() || 'No title found';
  const links = collectLinks(page.text, audit.target.origin).slice(0, 24);
  const forms = [...page.text.matchAll(/<form\b[^>]*>/gi)].length;

  audit.evidence.http = {
    status: page.response.status,
    finalUrl: page.response.url,
    headers,
    title,
    forms,
    links
  };
  evidence.push(`HTTP ${page.response.status} from ${page.response.url}`);
  evidence.push(`Title: ${title}`);
  evidence.push(`${links.length} same-origin links collected`);
  evidence.push(`${forms} forms detected`);

  try {
    const robots = await fetchText(new URL('/robots.txt', audit.target.origin).toString(), { timeoutMs: 4000 });
    audit.evidence.robots = robots.response.ok ? robots.text.slice(0, 2000) : `robots.txt returned HTTP ${robots.response.status}`;
    evidence.push(`robots.txt returned HTTP ${robots.response.status}`);
  } catch (error) {
    audit.evidence.robots = `robots.txt probe failed: ${error.message}`;
  }

  return { summary: `Mapped ${links.length} links and ${forms} forms`, evidence };
}

function collectLinks(html, origin) {
  const links = new Set();
  const re = /\b(?:href|src)=["']([^"'#\s]+)["']/gi;
  for (const match of html.matchAll(re)) {
    try {
      const url = new URL(match[1], origin);
      if (url.origin === origin) {
        url.hash = '';
        links.add(url.toString());
      }
    } catch {
      // Ignore malformed references.
    }
  }
  return [...links];
}

async function runScannerAgent(audit) {
  const headers = audit.evidence.http?.headers || {};
  const evidence = [];
  const add = (finding) => {
    audit.findings.push({ id: crypto.randomUUID(), status: 'Observed', time: 'just now', ...finding });
    evidence.push(`${finding.severity}: ${finding.title}`);
  };

  if (!headers['content-security-policy']) {
    add({
      severity: 'Info',
      path: audit.target.origin,
      title: 'Missing Content-Security-Policy header',
      hypothesis: 'Browsers have no CSP policy to reduce XSS impact or script injection blast radius.',
      confidence: 82,
      evidence: ['content-security-policy header was absent on the target response.'],
      remediation: 'Define a restrictive Content-Security-Policy and tighten script/style sources.'
    });
  }

  if (audit.target.protocol === 'https:' && !headers['strict-transport-security']) {
    add({
      severity: 'Low',
      path: audit.target.origin,
      title: 'Missing HSTS header',
      hypothesis: 'Users can be exposed to downgrade or first-request interception risk.',
      confidence: 78,
      evidence: ['strict-transport-security header was absent over HTTPS.'],
      remediation: 'Send Strict-Transport-Security with an appropriate max-age and includeSubDomains when safe.'
    });
  }

  if (!headers['x-frame-options'] && !frameAncestors(headers['content-security-policy'])) {
    add({
      severity: 'Info',
      path: audit.target.origin,
      title: 'No clickjacking frame control detected',
      hypothesis: 'Pages may be embeddable in hostile frames unless application logic blocks it.',
      confidence: 70,
      evidence: ['Neither x-frame-options nor CSP frame-ancestors was present.'],
      remediation: 'Add CSP frame-ancestors or X-Frame-Options according to app requirements.'
    });
  }

  if (!headers['referrer-policy']) {
    add({
      severity: 'Info',
      path: audit.target.origin,
      title: 'Missing Referrer-Policy header',
      hypothesis: 'Sensitive URL path or query data may leak through the Referer header.',
      confidence: 68,
      evidence: ['referrer-policy header was absent.'],
      remediation: 'Set Referrer-Policy, commonly strict-origin-when-cross-origin.'
    });
  }

  const setCookie = headers['set-cookie'] || '';
  if (setCookie && /session|auth|token/i.test(setCookie) && !/;\s*secure/i.test(setCookie)) {
    add({
      severity: 'Medium',
      path: audit.target.origin,
      title: 'Sensitive cookie missing Secure flag',
      hypothesis: 'Authentication-related cookies may be sent over plaintext requests.',
      confidence: 88,
      evidence: ['set-cookie contained auth-like cookie name without a Secure attribute.'],
      remediation: 'Mark authentication cookies Secure, HttpOnly, and SameSite where compatible.'
    });
  }

  const server = headers.server || headers['x-powered-by'];
  if (server) {
    add({
      severity: 'Info',
      path: audit.target.origin,
      title: 'Technology fingerprint exposed',
      hypothesis: 'Server or framework headers reveal implementation details useful for targeted testing.',
      confidence: 65,
      evidence: [`Observed header: ${headers.server ? `server=${headers.server}` : `x-powered-by=${headers['x-powered-by']}`}`],
      remediation: 'Remove or minimize framework/version banners where operationally practical.'
    });
  }

  if (audit.findings.length === 0) {
    evidence.push('No baseline web misconfiguration findings detected.');
  }

  const exposedEnv = audit.evidence.routes?.find((route) => route.route === '/.env' && Number(route.status) < 400);
  if (exposedEnv) {
    try {
      const envProbe = await fetchText(exposedEnv.url, { timeoutMs: 3500 });
      const contentType = envProbe.response.headers.get('content-type') || '';
      const looksLikeEnv = /(^|\n)[A-Z0-9_]{3,}\s*=\s*[^=\n]{3,}/.test(envProbe.text) && !/text\/html/i.test(contentType);
      audit.evidence.envProbe = {
        status: envProbe.response.status,
        contentType,
        matchedSecretPattern: looksLikeEnv
      };
      if (looksLikeEnv) {
        add({
          severity: 'Critical',
          path: exposedEnv.url,
          title: 'Readable environment file exposed',
          hypothesis: 'The environment file route returned secret-like key/value content.',
          confidence: 92,
          status: 'Verified',
          evidence: [`GET ${exposedEnv.url} returned non-HTML content matching environment variable patterns.`],
          remediation: 'Block dotfiles at the web server and rotate any exposed credentials.'
        });
      } else {
        evidence.push('/.env route did not return readable secret-like content');
      }
    } catch (error) {
      evidence.push(`/.env validation failed safely: ${error.message}`);
    }
  }

  const securityTxt = audit.evidence.routes?.find((route) => route.route === '/.well-known/security.txt');
  if (securityTxt && Number(securityTxt.status) === 404) {
    add({
      severity: 'Info',
      path: securityTxt.url,
      title: 'security.txt not published',
      hypothesis: 'Researchers may not have a standard disclosure contact path.',
      confidence: 55,
      evidence: [`${securityTxt.url} returned HTTP 404.`],
      remediation: 'Publish /.well-known/security.txt with disclosure policy and contact details.'
    });
  }

  return { summary: `${audit.findings.length} findings produced`, evidence };
}

async function runCorsAgent(audit) {
  const evidence = [];
  try {
    const { response } = await fetchText(audit.target.url, {
      method: 'GET',
      timeoutMs: 5000,
      headers: { origin: 'https://attacker.example' }
    });
    const acao = response.headers.get('access-control-allow-origin') || '';
    const acac = response.headers.get('access-control-allow-credentials') || '';
    audit.evidence.cors = { acao, acac };
    evidence.push(`access-control-allow-origin: ${acao || 'absent'}`);
    evidence.push(`access-control-allow-credentials: ${acac || 'absent'}`);
    if (acao === 'https://attacker.example' && /true/i.test(acac)) {
      audit.findings.push({
        id: crypto.randomUUID(),
        severity: 'Medium',
        path: audit.target.origin,
        title: 'Attacker origin reflected with credentials',
        hypothesis: 'A hostile origin is explicitly trusted with credentials; impact depends on whether the response contains authenticated sensitive data.',
        confidence: 84,
        status: 'Candidate',
        time: 'just now',
        evidence: [`Attacker origin reflected with credentials: ACAO=${acao}, ACAC=${acac}.`],
        remediation: 'Allowlist trusted origins exactly and validate authenticated response exposure before assigning impact.'
      });
    } else if (acao === '*' && /true/i.test(acac)) {
      evidence.push('Wildcard ACAO with credentials observed; browsers block credentialed reads, so no vulnerability was filed.');
    }
  } catch (error) {
    audit.evidence.cors = { error: error.message };
    evidence.push(`CORS probe failed: ${error.message}`);
  }
  return { summary: 'CORS boundary checked', evidence };
}

function frameAncestors(csp = '') {
  return /frame-ancestors/i.test(csp);
}

async function runExploitAgent(audit) {
  const evidence = audit.findings.map((finding) => {
    finding.validation = `Non-invasive validation: observed live response/evidence supports ${finding.title}.`;
    return `${finding.title}: validation attached`;
  });

  if (audit.evidence.http?.links?.some((link) => /graphql/i.test(link))) {
    audit.findings.push({
      id: crypto.randomUUID(),
      severity: 'Info',
      path: new URL('/graphql', audit.target.origin).toString(),
      title: 'GraphQL-like endpoint discovered',
      hypothesis: 'A GraphQL endpoint path appeared in same-origin references and may merit authorized introspection testing.',
      confidence: 58,
      status: 'Candidate',
      time: 'just now',
      evidence: ['Same-origin link included a graphql path.'],
      remediation: 'Confirm production GraphQL introspection, auth, and resolver authorization controls.'
    });
    evidence.push('GraphQL candidate added from recon links');
  }

  return { summary: 'Safe validation completed', evidence: evidence.length ? evidence : ['No exploit validation needed'] };
}

async function runPocAgent(audit) {
  const evidence = audit.findings.map((finding) => {
    finding.poc = buildPoc(audit, finding);
    return `${finding.title}: PoC command generated`;
  });
  return { summary: `${evidence.length} PoCs generated`, evidence };
}

function buildPoc(audit, finding) {
  if (/header|fingerprint|clickjacking|hsts|referrer|csp/i.test(finding.title)) {
    return `curl -I ${JSON.stringify(audit.target.url)}`;
  }
  return `curl -sS ${JSON.stringify(finding.path || audit.target.url)}`;
}

async function runDuplicateAgent(audit) {
  const evidence = audit.findings.slice(0, 5).map((finding) => {
    finding.duplicateSearch = [
      `${audit.target.hostname} ${finding.title}`,
      `"${finding.title}" bug bounty`,
      `"${finding.title}" CVE`
    ];
    return `${finding.title}: duplicate search leads generated`;
  });
  return { summary: 'Duplicate leads prepared', evidence: evidence.length ? evidence : ['No findings to cross-check'] };
}

async function runReportAgent(audit) {
  await fs.mkdir(reportsDir, { recursive: true });
  const report = renderReport(audit);
  const filename = `${audit.id}.md`;
  const filepath = path.join(reportsDir, filename);
  await fs.writeFile(filepath, report, 'utf8');
  audit.report = {
    filename,
    path: filepath,
    markdown: report
  };
  return { summary: 'Markdown report written', evidence: [`Report saved to ${filepath}`] };
}

function renderReport(audit) {
  const externalProgram = isExternalProgramMode(audit.mode);
  const boundedExternal = audit.policyReceipt?.profileId === INTIGRITI_PWN_PROFILE_ID;
  const lines = [
    externalProgram ? `# Bug Bunny External Program Observation Ledger` : `# Bug Bunny.ai Local Audit Report`,
    ``,
    `Target: ${audit.target.url}`,
    `Mode: ${audit.mode}`,
    `Generated: ${new Date().toISOString()}`,
    ``,
    `## Scope`,
    ...(audit.evidence.scope || []).map((item) => `- ${item}`),
    ``,
    externalProgram ? (boundedExternal ? `## Bounded Live Evidence` : `## Passive Observation Evidence`) : `## Recon Evidence`,
    `- HTTP status: ${audit.evidence.http?.status ?? 'n/a'}`,
    `- Final URL: ${audit.evidence.http?.finalUrl ?? 'n/a'}`,
    `- Page title: ${audit.evidence.http?.title ?? 'n/a'}`,
    `- Forms detected: ${audit.evidence.http?.forms ?? 0}`,
    `- Same-origin links collected: ${audit.evidence.http?.links?.length ?? 0}`,
    externalProgram
      ? `- Outbound HTTP requests: ${audit.evidence.requestLog?.length ?? 0} of ${audit.policyReceipt?.requestBudget ?? 0}`
      : `- Route probes: ${audit.evidence.routes?.length ?? 0}`,
    ``,
    externalProgram ? `## Observations — Not Submission Ready` : `## Findings`
  ];

  if (!audit.findings.length) {
    lines.push(`No findings were produced by the baseline agent run.`);
  }

  for (const finding of audit.findings) {
    lines.push(
      ``,
      `### ${finding.severity}: ${finding.title}`,
      `- Path: ${finding.path}`,
      `- Confidence: ${finding.confidence}%`,
      `- Status: ${finding.status}`,
      `- Hypothesis: ${finding.hypothesis}`,
      `- Evidence: ${(finding.evidence || []).join(' ') || 'n/a'}`,
      `- Validation: ${finding.validation || 'n/a'}`,
      `- PoC: \`${finding.poc || 'n/a'}\``,
      `- Remediation: ${finding.remediation || 'n/a'}`
    );
  }

  lines.push(
    ``,
    externalProgram ? `## Submission Gate` : `## Timeline`,
    ...(externalProgram
      ? [
          `This ledger is not a vulnerability report and must not be submitted as one.`,
          boundedExternal
            ? `It records a bounded, attributed public attack-surface map. Manually validate scope, impact, duplicate status, and a victim-centered proof before creating any report.`
            : `It records one passive response only. Manually validate scope, impact, duplicate status, and a victim-centered proof before creating any report.`
        ]
      : audit.timeline.slice().reverse().map((event) => `- ${event.time} [${event.agent}] ${event.message}`)),
    ``,
    `## Safety Boundary`,
    externalProgram
      ? boundedExternal
        ? `One exact in-scope host; ${audit.policyReceipt.requestBudget}-request budget at ≤${audit.policyReceipt.requestRatePerSecond}/second; required attribution headers; same-origin public links/assets only; no subdomain discovery, form submission, credential attacks, state changes, payload mutation, or access to other users' data.`
        : `Exact HTTPS URL only; one rate-limited GET; redirects, path discovery, CORS probes, authentication, payload mutation, active exploitation, and reproduction traffic are disabled.`
      : `Local/owned-target mode may use bounded GET/HEAD checks with same-origin redirect limits. Active exploitation remains disabled.`
  );

  return `${lines.join('\n')}\n`;
}

export {
  EXTERNAL_BOUNDED_MODE,
  EXTERNAL_PROGRAM_MODE,
  buildExternalProgramPlan,
  createAudit,
  createRequestPacer,
  fetchText,
  getAudit,
  listAudits
};
