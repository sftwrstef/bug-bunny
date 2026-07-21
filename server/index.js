import express from 'express';
import { createAudit, getAudit, listAudits } from './auditEngine.js';

const app = express();
const port = Number(process.env.CONTROLX_API_PORT || 8787);

app.use(express.json({ limit: '1mb' }));

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, name: 'controlx-safe-web-engine', mode: 'authorized-read-only' });
});

app.get('/api/audits', (_req, res) => {
  res.json({ audits: listAudits() });
});

app.post('/api/audits', (req, res) => {
  try {
    const audit = createAudit(req.body);
    res.status(202).json({ audit });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/audits/:id', (req, res) => {
  const audit = getAudit(req.params.id);
  if (!audit) {
    res.status(404).json({ error: 'Audit not found' });
    return;
  }
  res.json({ audit });
});

app.get('/api/audits/:id/report', (req, res) => {
  const audit = getAudit(req.params.id);
  if (!audit?.report?.markdown) {
    res.status(404).send('Report not ready');
    return;
  }
  res.type('text/markdown').send(audit.report.markdown);
});

app.listen(port, '127.0.0.1', () => {
  console.log(`ControlX API listening on http://127.0.0.1:${port}`);
});
