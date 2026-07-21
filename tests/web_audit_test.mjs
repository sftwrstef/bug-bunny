import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import {
  EXTERNAL_BOUNDED_MODE,
  EXTERNAL_PROGRAM_MODE,
  buildExternalProgramPlan,
  createAudit,
  createRequestPacer,
  fetchText
} from '../server/auditEngine.js';

function waitForAudit(audit, timeoutMs = 10_000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const poll = () => {
      if (audit.status === 'complete') return resolve(audit);
      if (audit.status === 'failed') return reject(new Error(audit.error || 'audit failed'));
      if (Date.now() - started > timeoutMs) return reject(new Error('audit timed out'));
      setTimeout(poll, 25);
    };
    poll();
  });
}

test('authorized safe Web audit captures live evidence and bounded findings', async () => {
  const fixture = http.createServer((request, response) => {
    if (request.url === '/.well-known/security.txt' || request.url === '/.env') {
      response.writeHead(404, { 'content-type': 'text/plain' });
      response.end('not found');
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html', 'x-fixture-request-method': request.method });
    response.end('<html><head><title>ControlX Fixture</title></head><body><a href="/api">API</a><form></form></body></html>');
  });

  await new Promise((resolve) => fixture.listen(0, '127.0.0.1', resolve));
  const address = fixture.address();
  const target = `http://127.0.0.1:${address.port}/`;

  try {
    assert.throws(() => createAudit({ target, scopeRules: 'local fixture', authorized: false }), /authorized/i);
    const audit = createAudit({ target, scopeRules: 'Local deterministic fixture only.', authorized: true, mode: 'authorized-safe-web' });
    await waitForAudit(audit);
    assert.equal(audit.status, 'complete');
    assert.equal(audit.target.origin, `http://127.0.0.1:${address.port}`);
    assert.equal(audit.evidence.http.status, 200);
    assert.equal(audit.evidence.http.title, 'ControlX Fixture');
    assert.equal(audit.evidence.http.forms, 1);
    assert.ok(audit.evidence.routes.length >= 10);
    assert.ok(audit.evidence.cors);
    assert.ok(audit.findings.some((finding) => finding.title === 'Missing Content-Security-Policy header'));
    assert.ok(audit.findings.every((finding) => finding.poc));
    assert.match(audit.report.markdown, /authorized-safe-web/);
  } finally {
    fixture.closeAllConnections();
    await new Promise((resolve, reject) => fixture.close((error) => error ? reject(error) : resolve()));
  }
});

test('safe fetch blocks cross-origin redirects and oversized bodies', async () => {
  const destination = http.createServer((_request, response) => response.end('outside scope'));
  await new Promise((resolve) => destination.listen(0, '127.0.0.1', resolve));
  const destinationAddress = destination.address();

  const source = http.createServer((request, response) => {
    if (request.url === '/redirect') {
      response.writeHead(302, { location: `http://127.0.0.1:${destinationAddress.port}/` });
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('x'.repeat(1024));
  });
  await new Promise((resolve) => source.listen(0, '127.0.0.1', resolve));
  const sourceAddress = source.address();

  try {
    await assert.rejects(
      fetchText(`http://127.0.0.1:${sourceAddress.port}/redirect`),
      /cross-origin redirect/i
    );
    await assert.rejects(
      fetchText(`http://127.0.0.1:${sourceAddress.port}/large`, { maxBytes: 128 }),
      /response exceeded/i
    );
  } finally {
    source.closeAllConnections();
    destination.closeAllConnections();
    await Promise.all([
      new Promise((resolve, reject) => source.close((error) => error ? reject(error) : resolve())),
      new Promise((resolve, reject) => destination.close((error) => error ? reject(error) : resolve()))
    ]);
  }
});

test('external program plan locks one exact HTTPS URL and observations-only limits', async () => {
  const target = 'https://portswigger.net/';
  const profile = {
    platform: 'HackerOne',
    programName: 'PortSwigger',
    policyUrl: 'https://portswigger.net/blog/portswigger-bug-bounty-program',
    exactScopeUrl: target,
    automationAcknowledged: true,
    humanReviewAcknowledged: true
  };

  const plan = buildExternalProgramPlan({ target, authorized: true, programProfile: profile });
  assert.equal(EXTERNAL_PROGRAM_MODE, 'external-program-passive');
  assert.equal(plan.exactScopeUrl, target);
  assert.equal(plan.requestRatePerSecond, 1);
  assert.equal(plan.requestBudget, 1);
  assert.deepEqual(plan.allowedMethods, ['GET']);
  assert.equal(plan.redirectPolicy, 'do-not-follow');
  assert.ok(plan.prohibitedActions.includes('path discovery'));
  assert.ok(plan.prohibitedActions.includes('active exploitation'));

  assert.throws(
    () => buildExternalProgramPlan({ target: 'http://portswigger.net/', authorized: true, programProfile: profile }),
    /HTTPS/i
  );
  assert.throws(
    () => buildExternalProgramPlan({ target: 'https://127.0.0.1/', authorized: true, programProfile: { ...profile, exactScopeUrl: 'https://127.0.0.1/' } }),
    /public program hostname/i
  );
  assert.throws(
    () => buildExternalProgramPlan({ target, authorized: true, programProfile: { ...profile, exactScopeUrl: 'https://portswigger.net/login' } }),
    /exact in-scope URL/i
  );

  const pacer = createRequestPacer(1);
  await pacer.wait();
  const started = Date.now();
  await pacer.wait();
  assert.ok(Date.now() - started >= 900, 'one-request-per-second pacing is enforced');
});

test('Intigriti PWN profile enforces scope, attribution, rate, and request budget', async () => {
  const target = 'https://app.pwn.intigriti.rocks/';
  const profile = {
    profileId: 'intigriti-pwn',
    platform: 'Intigriti',
    programName: 'Intigriti',
    policyUrl: 'https://app.intigriti.com/programs/intigriti/intigriti/detail',
    exactScopeUrl: target,
    researcherUsername: 'researcher_test',
    automationAcknowledged: true,
    humanReviewAcknowledged: true
  };

  const plan = buildExternalProgramPlan({ target, authorized: true, programProfile: profile });
  assert.equal(EXTERNAL_BOUNDED_MODE, 'external-program-bounded');
  assert.equal(plan.profileId, 'intigriti-pwn');
  assert.equal(plan.requestRatePerSecond, 2);
  assert.equal(plan.publishedRequestRatePerSecond, 10);
  assert.equal(plan.requestBudget, 24);
  assert.deepEqual(plan.allowedMethods, ['GET', 'HEAD']);
  assert.equal(plan.researcherUsername, 'researcher_test');
  assert.ok(plan.attributionHeaders.includes('X-Intigriti-Username'));

  assert.throws(
    () => buildExternalProgramPlan({
      target: 'https://example.com/',
      authorized: true,
      programProfile: { ...profile, exactScopeUrl: 'https://example.com/' }
    }),
    /pwn\.intigriti\.rocks/i
  );
  assert.throws(
    () => buildExternalProgramPlan({
      target,
      authorized: true,
      programProfile: { ...profile, researcherUsername: '<username>' }
    }),
    /real Intigriti username/i
  );
});

test('controlled-proof receipt cannot execute through the automatic Web engine', () => {
  const target = 'https://app.pwn.intigriti.rocks/';
  assert.throws(
    () => buildExternalProgramPlan({
      target,
      authorized: true,
      programProfile: {
        profileId: 'intigriti-pwn-proof',
        platform: 'Intigriti',
        programName: 'Intigriti',
        policyUrl: 'https://app.intigriti.com/programs/intigriti/intigriti/detail',
        exactScopeUrl: target,
        researcherUsername: 'researcher_test',
        automationAcknowledged: true,
        humanReviewAcknowledged: true
      }
    }),
    /never execute automatic target traffic/i
  );
});

test('safe fetch refuses a request beyond the recorded budget', async () => {
  let received = 0;
  const fixture = http.createServer((_request, response) => {
    received += 1;
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('ok');
  });
  await new Promise((resolve) => fixture.listen(0, '127.0.0.1', resolve));
  const address = fixture.address();
  const url = `http://127.0.0.1:${address.port}/`;
  const requestLog = [];

  try {
    await fetchText(url, { requestLog, requestBudget: 1 });
    await assert.rejects(fetchText(url, { requestLog, requestBudget: 1 }), /budget of 1 exhausted/i);
    assert.equal(received, 1);
    assert.equal(requestLog.length, 1);
  } finally {
    fixture.closeAllConnections();
    await new Promise((resolve, reject) => fixture.close((error) => error ? reject(error) : resolve()));
  }
});
