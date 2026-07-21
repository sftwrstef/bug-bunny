import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, rename, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { chromium } from 'playwright';

const projectRoot = resolve(process.env.CONTROLX_PROJECT_ROOT || process.cwd());
const appUrl = new URL(process.env.CONTROLX_DEMO_URL || 'http://127.0.0.1:5173');
const fixtureUrl = new URL(process.env.CONTROLX_REPLAY_FIXTURE_URL || 'http://127.0.0.1:8899');
const suppliedRunId = process.env.CONTROLX_REPLAY_RUN_ID || '';
const outputPath = resolve(
  projectRoot,
  process.env.CONTROLX_REPLAY_DEMO_OUTPUT || 'evidence/dev-week/controlx-authenticated-replay-demo.webm'
);
const screenshotPath = resolve(
  projectRoot,
  process.env.CONTROLX_REPLAY_SCREENSHOT_OUTPUT || 'evidence/dev-week/controlx-authenticated-replay-verified.png'
);
const videoScratchDir = resolve(projectRoot, 'output', 'playwright', 'authenticated-replay-demo');

const FIXTURE_ACCOUNT_A_TOKEN = 'controlx-fixture-account-a';
const FIXTURE_ACCOUNT_B_TOKEN = 'controlx-fixture-account-b';
const FIXTURE_MARKER_A = 'CONTROLX_FIXTURE_OBJECT_A_7F3A';
const FIXTURE_MARKER_B = 'CONTROLX_FIXTURE_OBJECT_B_91C2';
const fixtureOrigin = fixtureUrl.origin;
const accountACurl = `curl --silent --show-error -H 'Authorization: Bearer ${FIXTURE_ACCOUNT_A_TOKEN}' '${fixtureOrigin}/api/objects/A'`;
const accountBCurl = `curl --silent --show-error -H 'Authorization: Bearer ${FIXTURE_ACCOUNT_B_TOKEN}' '${fixtureOrigin}/api/objects/B'`;
const genericProfileExample = {
  target: 'https://api.example.test/',
  program: 'Synthetic reviewed-program setup · no traffic',
  policy: 'https://example.test/security-policy',
  hostname: 'api.example.test',
  hypothesis: "Account B can read Account A's known controlled object."
};

const pause = (milliseconds) => new Promise((resolvePause) => setTimeout(resolvePause, milliseconds));
const managedChildren = [];
let shuttingDown = false;

if (!existsSync(resolve(projectRoot, 'package.json'))) {
  throw new Error(`Run this script from the ControlX repository or set CONTROLX_PROJECT_ROOT. Missing package.json under ${projectRoot}`);
}

function childOutputTail(child) {
  return child.output.slice(-20).join('\n');
}

function startManagedProcess(label, command, args) {
  const child = spawn(command, args, {
    cwd: projectRoot,
    detached: process.platform !== 'win32',
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.label = label;
  child.output = [];
  for (const stream of [child.stdout, child.stderr]) {
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      child.output.push(...chunk.trimEnd().split('\n').filter(Boolean));
      child.output = child.output.slice(-40);
    });
  }
  managedChildren.push(child);
  return child;
}

async function stopManagedProcess(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolveExit) => child.once('exit', resolveExit));
  try {
    if (process.platform === 'win32') child.kill('SIGTERM');
    else process.kill(-child.pid, 'SIGTERM');
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
  }
  await Promise.race([exited, pause(3000)]);
  if (child.exitCode === null && child.signalCode === null) {
    try {
      if (process.platform === 'win32') child.kill('SIGKILL');
      else process.kill(-child.pid, 'SIGKILL');
    } catch (error) {
      if (error.code !== 'ESRCH') throw error;
    }
  }
}

async function cleanup() {
  if (shuttingDown) return;
  shuttingDown = true;
  await Promise.all([...managedChildren].reverse().map(stopManagedProcess));
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    cleanup().finally(() => process.exit(128 + (signal === 'SIGINT' ? 2 : 15)));
  });
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = Array.isArray(body.detail)
      ? body.detail.map((item) => item.msg || item.message || 'invalid request').join(' ')
      : body.detail;
    throw new Error(`${options.method || 'GET'} ${url} failed with HTTP ${response.status}: ${body.error || detail || 'unknown error'}`);
  }
  return body;
}

async function endpointReady(url, predicate = () => true) {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(1200) });
    if (!response.ok) return false;
    const body = await response.json().catch(() => null);
    return Boolean(body && predicate(body));
  } catch {
    return false;
  }
}

async function waitForEndpoint(url, predicate, child, timeoutMs = 30000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (await endpointReady(url, predicate)) return;
    if (child && child.exitCode !== null) {
      throw new Error(`${child.label} exited with code ${child.exitCode}.\n${childOutputTail(child)}`);
    }
    await pause(300);
  }
  const processDetail = child ? `\n${childOutputTail(child)}` : '';
  throw new Error(`Timed out waiting for ${url}.${processDetail}`);
}

async function ensureFixture() {
  const healthUrl = new URL('/health', fixtureUrl).href;
  const fixtureReady = await endpointReady(
    healthUrl,
    (body) => body.fixture === 'authenticated-replay' && body.mode === 'vulnerable'
  );
  if (fixtureReady) return;
  if (fixtureUrl.hostname !== '127.0.0.1' || fixtureUrl.protocol !== 'http:' || fixtureUrl.port !== '8899') {
    throw new Error(`The configured fixture is unavailable: ${fixtureUrl.origin}. Start it in vulnerable mode before recording.`);
  }

  const python = existsSync(resolve(projectRoot, '.venv', 'bin', 'python'))
    ? resolve(projectRoot, '.venv', 'bin', 'python')
    : 'python3';
  const child = startManagedProcess(
    'authenticated replay fixture',
    python,
    ['-m', 'proofs.authenticated_replay_demo', '--mode', 'vulnerable', '--port', '8899']
  );
  await waitForEndpoint(
    healthUrl,
    (body) => body.fixture === 'authenticated-replay' && body.mode === 'vulnerable',
    child
  );
}

async function ensureApp() {
  const auditsUrl = new URL('/api/audits', appUrl).href;
  if (await endpointReady(auditsUrl, (body) => Array.isArray(body.audits))) return;
  if (appUrl.origin !== 'http://127.0.0.1:5173') {
    throw new Error(`The configured ControlX app is unavailable: ${appUrl.origin}. Start it before recording.`);
  }

  const child = startManagedProcess('ControlX dev stack', 'node', ['server/dev.js']);
  await waitForEndpoint(auditsUrl, (body) => Array.isArray(body.audits), child, 45000);
}

async function validateSuppliedRun() {
  if (!suppliedRunId) return '';
  const response = await fetchJson(new URL(`/api/audits/${suppliedRunId}`, appUrl).href);
  if (response.audit?.target !== `${fixtureOrigin}/`) {
    throw new Error(`CONTROLX_REPLAY_RUN_ID must target the exact localhost fixture origin ${fixtureOrigin}/.`);
  }
  if (!['created', 'proof_scope_recorded'].includes(response.audit?.status)) {
    throw new Error(`CONTROLX_REPLAY_RUN_ID must be fresh; current status is ${response.audit?.status || 'unknown'}.`);
  }
  return suppliedRunId;
}

async function demonstrateReusableProfileBoundary(page) {
  await page.getByRole('button', { name: 'Live bounty target', exact: true }).click();
  await page.getByLabel('Target profile').selectOption('authenticated-replay');
  await page.getByLabel('Platform').selectOption('Bugcrowd');
  await page.getByLabel('Exact in-scope HTTPS URL').fill(genericProfileExample.target);
  await page.getByLabel('Scope notes').fill('Illustrative setup only. A real run requires the current program policy, explicit hosts, two self-controlled accounts, and two harmless controlled objects.');
  await page.getByLabel('Program name').fill(genericProfileExample.program);
  await page.getByLabel('Current policy URL').fill(genericProfileExample.policy);
  await page.getByLabel(/Explicit hostnames/).fill(genericProfileExample.hostname);
  await page.getByLabel('One victim-centered hypothesis').fill(genericProfileExample.hypothesis);
  await page.getByLabel('Account A and Account B will both be self-created accounts that I control.').check();
  await page.getByLabel(/I will replay only Account A's known object ID/).check();
  await page.getByLabel(/The current policy permits this controlled validation/).check();
  await page.getByLabel('I will manually validate scope, impact, and duplicates before reporting anything.').check();
  await page.getByLabel('I am authorized to test this target.').check();
  await page.getByRole('button', { name: /^Prepare authenticated replay/ }).scrollIntoViewIfNeeded();
  await pause(6500);

  // The public-program values above are intentionally illustrative. The recorded
  // proof switches to the bundled localhost fixture before any run is created.
  await page.getByRole('button', { name: 'Local / owned target', exact: true }).click();
  await page.getByTestId('choose-local-replay').click();
  await page.getByLabel('Owned or localhost target URL').fill(`${fixtureOrigin}/`);
  await page.getByLabel('Scope notes').fill('Synthetic localhost fixture only. Two controlled accounts; GET-only replay; four-request maximum; stop immediately on exposure.');
  await page.getByLabel('I am authorized to test this target.').check();
  await pause(3500);
}

async function pasteIntoSecureZone(locator, text) {
  await locator.scrollIntoViewIfNeeded();
  await locator.focus();
  const accepted = await locator.evaluate((element, clipboardText) => {
    const clipboardData = { getData: (type) => type === 'text' || type === 'text/plain' ? clipboardText : '' };
    const event = new Event('paste', { bubbles: true, cancelable: true });
    Object.defineProperty(event, 'clipboardData', { value: clipboardData });
    return !element.dispatchEvent(event);
  }, text);
  if (!accepted) throw new Error(`Secure paste zone ${await locator.getAttribute('data-testid')} did not consume the synthetic paste event.`);
}

async function assertFixtureSecretsAreNotRendered(page) {
  for (const secret of [FIXTURE_ACCOUNT_A_TOKEN, FIXTURE_ACCOUNT_B_TOKEN, FIXTURE_MARKER_A, FIXTURE_MARKER_B]) {
    if (await page.getByText(secret, { exact: false }).count()) {
      throw new Error('A secure paste value was rendered in the page instead of remaining ephemeral.');
    }
  }
}

function formatObservedErrors(observedErrors) {
  return observedErrors.map(({ kind, detail }) => `[${kind}] ${detail}`).join('\n');
}

await rm(videoScratchDir, { recursive: true, force: true });
await mkdir(videoScratchDir, { recursive: true });
await mkdir(dirname(outputPath), { recursive: true });
await mkdir(dirname(screenshotPath), { recursive: true });

let browser;
let context;
let video;
let successful = false;
const observedErrors = [];

try {
  await ensureFixture();
  await ensureApp();
  let runId = await validateSuppliedRun();

  browser = await chromium.launch({ headless: true });
  context = await browser.newContext({
    colorScheme: 'dark',
    deviceScaleFactor: 1,
    recordVideo: {
      dir: videoScratchDir,
      size: { width: 1440, height: 900 }
    },
    viewport: { width: 1440, height: 900 }
  });
  const page = await context.newPage();
  video = page.video();

  page.on('console', (message) => {
    if (message.type() === 'error') observedErrors.push({ kind: 'console.error', detail: message.text() });
  });
  page.on('pageerror', (error) => {
    observedErrors.push({ kind: 'pageerror', detail: error.stack || error.message });
  });
  page.on('response', (response) => {
    if (response.url().startsWith(appUrl.origin) && response.url().includes('/api/') && response.status() >= 400) {
      observedErrors.push({ kind: 'api-response', detail: `${response.status()} ${response.request().method()} ${response.url()}` });
    }
  });

  await page.goto(appUrl.href, { waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: 'Hunts', exact: true }).waitFor();
  await pause(3500);
  await demonstrateReusableProfileBoundary(page);

  if (runId) {
    await page.getByRole('button', { name: new RegExp(runId) }).click();
    await page.getByText(`${fixtureOrigin}/`, { exact: true }).first().waitFor({ timeout: 15000 });
    await pause(2500);
    await page.getByRole('button', { name: 'Proof Lab', exact: true }).click();
  } else {
    const createResponse = page.waitForResponse((response) => (
      response.url() === new URL('/api/audits/create', appUrl).href
      && response.request().method() === 'POST'
    ));
    await page.getByRole('button', { name: /^Prepare authenticated replay/ }).click();
    const created = await (await createResponse).json();
    runId = created.audit?.run_id || '';
    if (!runId) throw new Error('The visible scope-gate action did not return an audit run ID.');
  }

  const workbench = page.getByTestId('replay-workbench');
  try {
    await workbench.waitFor({ timeout: 10000 });
  } catch {
    throw new Error(
      'Authenticated replay workbench is not available for a fresh localhost run. '
      + 'Required assumption: local_lab runs with no prior Web-engine evidence must route Proof Lab to AuthenticatedReplayWorkbench.'
    );
  }
  await pause(2500);

  await pasteIntoSecureZone(page.getByTestId('curl-account-a'), accountACurl);
  await pause(2500);
  await pasteIntoSecureZone(page.getByTestId('curl-account-b'), accountBCurl);
  await assertFixtureSecretsAreNotRendered(page);
  await pause(2500);

  await page.getByTestId('preview-redaction').click();
  const preview = page.getByTestId('redaction-preview');
  try {
    await preview.waitFor({ timeout: 15000 });
  } catch (error) {
    const uiError = await page.locator('.replay-error, .error-line').last().textContent().catch(() => 'no UI error rendered');
    const browserErrors = observedErrors.length ? `\n${formatObservedErrors(observedErrors)}` : '';
    throw new Error(`Redaction preview did not open: ${uiError || error.message}${browserErrors}`);
  }
  await preview.getByText('Distinct session confirmed', { exact: true }).waitFor();
  await preview.getByTestId('replay-budget').filter({ hasText: '0 / 4 requests' }).waitFor();
  await pause(7000);

  await pasteIntoSecureZone(page.getByTestId('marker-account-a'), FIXTURE_MARKER_A);
  await pause(2000);
  await pasteIntoSecureZone(page.getByTestId('marker-account-b'), FIXTURE_MARKER_B);
  await assertFixtureSecretsAreNotRendered(page);
  await pause(2000);

  await page.getByLabel('Object kind · non-secret label').fill('controlled fixture object');
  await pause(1500);
  await page.getByLabel('A and B are isolated live sessions.').check();
  await pause(1500);
  await page.getByLabel('Both objects and both accounts are controlled by me.').check();
  await pause(1500);
  await page.getByLabel('No third-party data is expected; stop on unexpected exposure.').check();
  await pause(4000);

  const replayButton = page.getByTestId('run-bounded-replay');
  if (await replayButton.isDisabled()) throw new Error('Bounded replay remained disabled after every preview and attestation passed.');
  await replayButton.click();

  const result = page.getByTestId('replay-workbench');
  await result.getByTestId('replay-verdict').getByText(/VERIFIED REPLAY/).waitFor({ timeout: 20000 });
  await result.getByTestId('replay-budget').filter({ hasText: '3 / 4 requests' }).waitFor();
  const receipt = await result.getByTestId('replay-receipt-hash').textContent();
  if (!receipt || !/^SHA-256 [a-f0-9]{64}$/.test(receipt.trim())) {
    throw new Error(`Replay receipt hash was not a complete SHA-256 value: ${receipt || 'missing'}`);
  }
  const savedRun = await fetchJson(new URL(`/api/audits/${runId}`, appUrl).href);
  const savedRunJson = JSON.stringify(savedRun);
  for (const forbidden of [accountACurl, accountBCurl, FIXTURE_ACCOUNT_A_TOKEN, FIXTURE_ACCOUNT_B_TOKEN, FIXTURE_MARKER_A, FIXTURE_MARKER_B]) {
    if (savedRunJson.includes(forbidden)) {
      throw new Error('The saved run API returned raw capture material; refusing to preserve the recording.');
    }
  }
  await pause(10000);

  await result.getByTestId('replay-matrix').scrollIntoViewIfNeeded();
  await page.screenshot({ path: screenshotPath, fullPage: false });
  await pause(8000);

  await page.getByRole('button', { name: 'Findings', exact: true }).click();
  await page.getByRole('button', { name: 'Surface Map', exact: true }).click();
  await page.locator('.map-panel').scrollIntoViewIfNeeded();
  await pause(8000);

  await page.getByRole('button', { name: 'Proof Lab', exact: true }).click();
  await page.getByTestId('replay-receipt-hash').scrollIntoViewIfNeeded();
  await pause(7000);

  if (observedErrors.length) {
    throw new Error(`Browser or API errors occurred during capture:\n${formatObservedErrors(observedErrors)}`);
  }
  successful = true;
} finally {
  if (context) await context.close();
  if (browser) await browser.close();
  await cleanup();
}

if (!successful) throw new Error('Authenticated replay demo did not complete.');
if (!video) throw new Error('Playwright did not create a video for the authenticated replay demo.');

await rm(outputPath, { force: true });
await rename(await video.path(), outputPath);
console.log(outputPath);
console.log(screenshotPath);
