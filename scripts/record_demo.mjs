import { mkdir, rename } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';

const appUrl = process.env.CONTROLX_DEMO_URL || 'http://127.0.0.1:5173';
const outputDir = resolve(process.cwd(), 'output', 'demo');
const outputPath = resolve(outputDir, 'controlx-demo.webm');
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
await pause(4500);

await page.getByRole('button', { name: 'Run safe Web audit' }).click();
await page.getByText('Safe Web audit ready').waitFor({ timeout: 30000 });
await pause(5500);

await page.getByRole('button', { name: 'Surface Map' }).click();
await page.locator('.map-panel').scrollIntoViewIfNeeded();
await pause(6000);

await page.getByRole('button', { name: 'Triage' }).click();
await page.locator('.verified-proof').scrollIntoViewIfNeeded();
await pause(2500);
await page.getByRole('button', { name: 'Run real proof' }).click();
await page.getByText('VERIFIED EXECUTION').waitFor({ timeout: 30000 });
await pause(6500);

await page.getByRole('button', { name: 'Report Draft' }).click();
await page.locator('.report-panel').scrollIntoViewIfNeeded();
await pause(7000);

const video = page.video();
await context.close();
await browser.close();

if (consoleErrors.length) {
  throw new Error(`Browser console errors during demo capture:\n${consoleErrors.join('\n')}`);
}

await rename(await video.path(), outputPath);
console.log(outputPath);
