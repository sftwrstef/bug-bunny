import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { chromium } from 'playwright';

const appUrl = process.env.BUG_BUNNY_DEMO_URL || 'http://127.0.0.1:5173';
const runId = process.env.BUG_BUNNY_CONTROLLED_RUN_ID;
const outputPath = resolve(
  process.cwd(),
  process.env.BUG_BUNNY_PROOF_SCREENSHOT || 'evidence/dev-week/controlled-proof-closed.png'
);

if (!runId) {
  throw new Error('Set BUG_BUNNY_CONTROLLED_RUN_ID to the saved controlled-proof run.');
}

await mkdir(dirname(outputPath), { recursive: true });

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  colorScheme: 'dark',
  deviceScaleFactor: 1,
  viewport: { width: 1440, height: 900 }
});
const page = await context.newPage();
const consoleErrors = [];
page.on('console', (message) => {
  if (message.type() === 'error') consoleErrors.push(message.text());
});

try {
  await page.goto(appUrl, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: new RegExp(runId) }).click();
  await page.getByRole('button', { name: 'Proof Lab', exact: true }).click();

  let panel = page.locator('.proof-closed');
  await panel.getByText('hypothesis closed', { exact: true }).waitFor();
  await panel.getByText('INVALID · NO IDOR', { exact: true }).waitFor();
  await panel.getByText('DENIED · 2 of 2 isolated replays', { exact: true }).waitFor();

  const stalePlanCopy = [
    'FIRST MANUAL MILESTONE',
    'expected 403/404',
    'potential proof only if',
    'scope recorded'
  ];
  for (const text of stalePlanCopy) {
    if (await panel.getByText(text, { exact: false }).count()) {
      throw new Error(`Closed proof panel still contains stale plan copy: ${text}`);
    }
  }

  await page.getByRole('button', { name: 'Findings', exact: true }).click();
  await page.getByRole('button', { name: 'Submission gate closed', exact: true }).waitFor();
  if (await page.getByText('No reproduction command: passive mode permits no follow-up traffic.', { exact: true }).count()) {
    throw new Error('Controlled Findings view fell through to passive-mode copy.');
  }

  await page.getByRole('button', { name: 'Reports', exact: true }).click();
  await page.getByRole('heading', { name: 'Observation Ledger', exact: true }).waitFor();
  if (await page.getByText(/Collect the passive receipt/).count()) {
    throw new Error('Controlled Reports view fell through to passive-mode copy.');
  }

  await page.getByRole('button', { name: 'Proof Lab', exact: true }).click();
  panel = page.locator('.proof-closed');
  await panel.getByText('submission gate closed', { exact: true }).waitFor();
  await panel.screenshot({ path: outputPath });
} finally {
  await context.close();
  await browser.close();
}

if (consoleErrors.length) {
  throw new Error(`Browser console errors during controlled-proof capture:\n${consoleErrors.join('\n')}`);
}

console.log(outputPath);
