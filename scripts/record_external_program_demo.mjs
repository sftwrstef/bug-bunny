import { mkdir, rename } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';

const appUrl = process.env.BUG_BUNNY_DEMO_URL || 'http://127.0.0.1:5173';
const targetUrl = 'https://portswigger.net/';
const policyUrl = 'https://portswigger.net/blog/portswigger-bug-bounty-program';
const replayRunId = process.env.BUG_BUNNY_EXTERNAL_RUN_ID || '';
const outputDir = resolve(process.cwd(), 'output', 'demo');
const outputPath = resolve(outputDir, 'bug-bunny-external-program-demo.webm');
const pause = (milliseconds) => new Promise((resolvePause) => setTimeout(resolvePause, milliseconds));

await mkdir(outputDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  colorScheme: 'dark',
  deviceScaleFactor: 1,
  recordVideo: {
    dir: outputDir,
    size: { width: 1440, height: 900 }
  },
  viewport: { width: 1440, height: 900 }
});
const page = await context.newPage();
const consoleErrors = [];
page.on('console', (message) => {
  if (message.type() === 'error') consoleErrors.push(message.text());
});

await page.goto(appUrl, { waitUntil: 'networkidle' });
await page.getByRole('heading', { name: 'Signal Console' }).waitFor();
if (replayRunId) {
  await page.getByRole('button', { name: new RegExp(replayRunId) }).click();
  await page.getByText('Response security posture captured').waitFor({ timeout: 15000 });
} else {
  await page.getByRole('button', { name: 'External program (passive)' }).click();
  await pause(1200);

  await page.getByLabel('Exact in-scope HTTPS URL').fill(targetUrl);
  await page.getByLabel('Scope notes').fill(
    'HackerOne / PortSwigger: exact root URL only. One passive GET at no more than one HTTP request per second; no subdomains, discovery, CORS, auth, payloads, or proof traffic.'
  );
  await page.getByLabel('Program name').fill('PortSwigger');
  await page.getByLabel('Current policy URL').fill(policyUrl);
  await page.getByLabel('The current policy explicitly permits this low-rate, read-only check.').check();
  await page.getByLabel('I will manually validate scope, impact, and duplicates before reporting anything.').check();
  await page.getByLabel('I am authorized to test this target.').check();
  await pause(1600);

  await page.getByRole('button', { name: /Run passive program check/ }).click();
  await page.getByText('Response security posture captured').waitFor({ timeout: 30000 });
}
await pause(3000);

await page.getByRole('button', { name: 'Surface Map' }).click();
await page.locator('.map-panel').scrollIntoViewIfNeeded();
await pause(4500);

await page.getByRole('button', { name: 'Report Draft' }).click();
await page.locator('.report-panel').scrollIntoViewIfNeeded();
await page.getByRole('heading', { name: 'Observation Ledger', exact: true }).waitFor({ timeout: 10000 });
await pause(6500);

const video = page.video();
await context.close();
await browser.close();

if (consoleErrors.length) {
  throw new Error(`Browser console errors during external program capture:\n${consoleErrors.join('\n')}`);
}

await rename(await video.path(), outputPath);
console.log(outputPath);
