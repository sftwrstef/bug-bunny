import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Bell,
  Bug,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clipboard,
  Code2,
  Command,
  Copy,
  Crosshair,
  DatabaseZap,
  FileText,
  Flag,
  GitBranch,
  Globe2,
  Layers3,
  Link,
  Plus,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  Radar,
  Route,
  TerminalSquare,
  Upload,
  Zap
} from 'lucide-react';
import './styles.css';

const navItems = [
  { label: 'Hunts', icon: Crosshair },
  { label: 'Scope', icon: Globe2 },
  { label: 'Findings', icon: Bug },
  { label: 'PoCs', icon: Code2 },
  { label: 'Reports', icon: FileText },
  { label: 'Settings', icon: Settings }
];

const demoFindings = [
  {
    severity: 'Critical',
    path: '/api/user/update',
    title: 'IDOR in user object reference',
    hypothesis: "User can access or modify other users' profiles via predictable user_id",
    confidence: 92,
    status: 'Analyzed',
    time: '2m ago',
    accent: '#ef4444'
  },
  {
    severity: 'High',
    path: '/graphql',
    title: 'GraphQL introspection enabled',
    hypothesis: 'Introspection exposes schema, object relations, and admin mutations',
    confidence: 86,
    status: 'Analyzed',
    time: '5m ago',
    accent: '#f97316'
  },
  {
    severity: 'Medium',
    path: '/static/js/app.js',
    title: 'Hardcoded cloud access key',
    hypothesis: 'AWS key found in client-side bundle can enable unauthorized access',
    confidence: 74,
    status: 'In progress',
    time: '1m ago',
    accent: '#eab308'
  }
];

const agentCatalog = [
  {
    name: 'Recon Agent',
    role: 'Maps attack surface',
    icon: Radar,
    progress: 94,
    status: 'Found 142 endpoints',
    detail: 'Subdomains, routes, auth walls'
  },
  {
    name: 'Scope Agent',
    role: 'Keeps bounty rules aligned',
    icon: Crosshair,
    progress: 88,
    status: '2 paths excluded',
    detail: 'Program scope and safe testing'
  },
  {
    name: 'Route Agent',
    role: 'Safely probes common app endpoints',
    icon: Route,
    progress: 66,
    status: 'Endpoint probes ready',
    detail: 'robots, sitemap, api, graphql'
  },
  {
    name: 'Exploit Agent',
    role: 'Turns hints into proof',
    icon: Zap,
    progress: 76,
    status: 'IDOR PoC ready',
    detail: 'Request mutation + response diff'
  },
  {
    name: 'Scanner Agent',
    role: 'Checks headers and metadata',
    icon: ShieldCheck,
    progress: 72,
    status: 'Baseline scanner ready',
    detail: 'Headers, cookies, dotfiles'
  },
  {
    name: 'CORS Agent',
    role: 'Checks browser trust boundaries',
    icon: Globe2,
    progress: 64,
    status: 'Origin probe ready',
    detail: 'ACAO, ACAC, reflection'
  },
  {
    name: 'PoC Agent',
    role: 'Builds repro commands',
    icon: Code2,
    progress: 69,
    status: 'cURL chain drafted',
    detail: 'Headers, payloads, assertions'
  },
  {
    name: 'Duplicate Agent',
    role: 'Checks known reports',
    icon: Search,
    progress: 61,
    status: 'No public dupes',
    detail: 'CVE, H1, blog, changelog search'
  },
  {
    name: 'Report Agent',
    role: 'Packages submission',
    icon: FileText,
    progress: 83,
    status: 'Impact section queued',
    detail: 'Severity, root cause, fix'
  }
];

const agentIcons = Object.fromEntries(agentCatalog.map((agent) => [agent.name, agent.icon]));

const backendAgentOrder = [
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

async function api(path, options) {
  const response = await fetch(path, {
    headers: { 'content-type': 'application/json', ...(options?.headers || {}) },
    ...options
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Request failed with HTTP ${response.status}`);
  }
  return data;
}

function severityRank(severity) {
  return { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 }[severity] ?? 0;
}

function formatStatus(status) {
  return String(status || 'created').replaceAll('_', ' ');
}

function normalizeFinding(finding) {
  return {
    id: finding.finding_id,
    severity: finding.severity,
    path: finding.location,
    title: finding.title,
    hypothesis: finding.hypothesis,
    confidence: finding.confidence,
    status: formatStatus(finding.status),
    time: 'stored in SQLite',
    evidence: Object.entries(finding.evidence || {}).map(([key, value]) => `${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`),
    remediation: finding.remediation,
    poc: finding.poc,
    duplicateSearch: [
      `${finding.location} ${finding.title}`,
      `"${finding.title}" bug bounty`,
      `"${finding.title}" CVE`
    ]
  };
}

function buildAgents(audit, findings = []) {
  const status = audit?.status || 'created';
  const hasScan = ['web_audit_complete', 'mock_scan_complete', 'report_generated'].includes(status);
  const hasReport = status === 'report_generated';
  return backendAgentOrder.map((name) => {
    const complete =
      name === 'Scope Agent' ||
      (hasScan && ['Recon Agent', 'Route Agent', 'Scanner Agent', 'CORS Agent', 'Exploit Agent', 'PoC Agent', 'Duplicate Agent'].includes(name)) ||
      (hasReport && name === 'Report Agent');
    const running =
      (status === 'created' && name === 'Scope Agent') ||
      (status === 'scanning' && ['Recon Agent', 'Route Agent', 'Scanner Agent'].includes(name));
    const progress = complete ? 100 : running ? 45 : 0;
    const summaries = {
      'Scope Agent': audit ? 'SQLite run created' : 'Waiting for target',
      'Recon Agent': hasScan ? 'Live DNS and HTTP profile captured' : 'Waiting for safe Web engine',
      'Route Agent': hasScan ? 'Bounded GET/HEAD route checks captured' : 'Waiting for safe Web engine',
      'Scanner Agent': hasScan ? `${findings.length} observed findings stored in SQLite` : 'Waiting for safe Web engine',
      'CORS Agent': hasScan ? 'Browser trust boundary observed live' : 'Waiting for safe Web engine',
      'Exploit Agent': hasScan ? 'No active exploitation performed' : 'Disabled until scan',
      'PoC Agent': hasScan ? `${findings.length} safe PoCs generated` : 'Waiting for findings',
      'Duplicate Agent': hasScan ? 'Duplicate leads derived locally' : 'Waiting for findings',
      'Report Agent': hasReport ? 'Report written to /runs' : 'Waiting for report generation'
    };
    return {
      name,
      role: agentCatalog.find((agent) => agent.name === name)?.role || 'Local audit worker',
      status: complete ? 'complete' : running ? 'running' : 'queued',
      progress,
      summary: summaries[name],
      detail: audit ? 'FastAPI + SQLite backend' : 'Local MVP worker'
    };
  });
}

function normalizeAuditResponse(data) {
  const rawAudit = data.audit;
  if (!rawAudit) return null;
  const findings = (data.findings || []).map(normalizeFinding).sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const engineAudit = data.engine_audit;
  return {
    id: rawAudit.run_id,
    run_id: rawAudit.run_id,
    status: rawAudit.status,
    target: { url: rawAudit.target, type: rawAudit.target_type },
    scopeRules: rawAudit.scope_notes,
    runDir: rawAudit.run_dir,
    rawDir: rawAudit.raw_dir,
    reportsDir: rawAudit.reports_dir,
    report: rawAudit.report_path ? {
      path: rawAudit.report_path,
      markdown: data.markdown || ''
    } : null,
    evidence: {
      ...(engineAudit?.evidence || {}),
      run_id: rawAudit.run_id,
      target_type: rawAudit.target_type,
      run_dir: rawAudit.run_dir,
      raw_dir: rawAudit.raw_dir,
      reports_dir: rawAudit.reports_dir,
      report_path: rawAudit.report_path,
      scanner_mode: engineAudit ? 'authorized-read-only' : 'not-run'
    },
    findings,
    timeline: engineAudit?.timeline?.length ? engineAudit.timeline : buildTimeline(rawAudit, findings),
    agents: engineAudit?.agents?.length ? engineAudit.agents : buildAgents(rawAudit, findings)
  };
}

function buildTimeline(audit, findings) {
  if (!audit) return [];
  const items = [
    { time: new Date(audit.created_at).toLocaleTimeString([], { hour12: false }), agent: 'Scope Agent', message: 'AuditRun row created in SQLite', state: 'done' }
  ];
  if (['web_audit_complete', 'mock_scan_complete', 'report_generated'].includes(audit.status)) {
    items.push(
      { time: new Date(audit.updated_at).toLocaleTimeString([], { hour12: false }), agent: 'Scanner Agent', message: `web_audit.json parsed into ${findings.length} findings`, state: 'done' },
      { time: new Date(audit.updated_at).toLocaleTimeString([], { hour12: false }), agent: 'PoC Agent', message: `${findings.length} safe repro commands generated`, state: 'done' }
    );
  }
  if (audit.status === 'report_generated') {
    items.push({ time: new Date(audit.updated_at).toLocaleTimeString([], { hour12: false }), agent: 'Report Agent', message: 'report.md written to run folder', state: 'done' });
  }
  return items.reverse();
}

const codeLines = [
  ['41', 'def update'],
  ['42', "  user = User.find(params[:user_id])"],
  ['43', '  user.email = params[:email]'],
  ['44', '  user.name = params[:name] if params[:name].present?'],
  ['45', '  user.update!(user_params)'],
  ['46', '  render json: user'],
  ['47', 'rescue ActiveRecord::RecordNotFound'],
  ['48', "  render json: { error: 'Not found' }, status: :not_found"],
  ['49', 'end'],
  ['50', ''],
  ['51', 'private']
];

const timeline = [
  ['10:24:11', 'Scope ingested', 'api.acme.app (142 endpoints)', 'by you', 'done'],
  ['10:24:18', 'Repo scanned', '112 commits analyzed', 'by AI', 'done'],
  ['10:25:03', 'IDOR in /api/user/update', 'Confidence: 92%', 'Critical', 'hot'],
  ['10:25:47', 'GraphQL introspection', 'Confidence: 86%', 'High', 'high'],
  ['10:26:22', 'Hardcoded AWS key', 'Confidence: 74%', 'Medium', 'open']
];

function BrandMark() {
  return (
    <div className="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 36 42" role="img">
        <path className="ear left" d="M12 2 4 13l7 6 7-10Z" />
        <path className="ear right" d="M24 2 18 9l7 10 7-6Z" />
        <path className="shield" d="M18 10 5 17v14l13 8 13-8V17Z" />
        <path className="core" d="M18 15 10 20v8l8 5 8-5v-8Z" />
      </svg>
    </div>
  );
}

function IconButton({ children, label, onClick }) {
  return (
    <button className="icon-button" aria-label={label} title={label} onClick={onClick}>
      {children}
    </button>
  );
}

function Sidebar({ activeNav, setActiveNav, setTab, notify }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <BrandMark />
        <span>Bug<span> Bunny</span></span>
      </div>
      <nav className="nav">
        {navItems.map(({ label, icon: Icon }) => (
          <button
            className={`nav-item ${activeNav === label ? 'active' : ''}`}
            key={label}
            onClick={() => {
              setActiveNav(label);
              if (label === 'Findings') setTab('Triage');
              if (label === 'PoCs') setTab('Surface Map');
              if (label === 'Reports') setTab('Report Draft');
              notify(`${label} view selected`);
            }}
          >
            <Icon size={21} strokeWidth={2} />
            <span>{label}</span>
          </button>
        ))}
      </nav>
      <div className="sidebar-bottom">
        <button className="workspace-card" onClick={() => notify('Workspace selector is local-only for this MVP')}>
          <div className="workspace-icon"><ShieldCheck size={18} /></div>
          <div>
            <strong>Local Workspace</strong>
            <span>SQLite MVP</span>
          </div>
          <ChevronDown size={18} />
        </button>
        <div className="credits">
          <div className="credits-head">
            <span>Safe Web Mode</span>
            <button className="tiny-icon" onClick={() => notify('Bounded authorized GET/HEAD checks only. Deep proofs use localhost fixtures.')} aria-label="Safe mode help">
              <CircleHelp size={15} />
            </button>
          </div>
          <strong>Read-only HTTP checks</strong>
          <div className="meter"><span style={{ width: '78%' }} /></div>
          <small>Evidence stored locally</small>
        </div>
      </div>
    </aside>
  );
}

function Topbar({ search, setSearch, onNewHunt, notify }) {
  return (
    <header className="topbar">
      <label className="command-search">
        <Search size={18} />
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search findings, agents, paths... or run a command"
        />
        <kbd><Command size={13} /> K</kbd>
      </label>
      <button className="new-hunt" onClick={onNewHunt}>
        <Plus size={19} />
        New hunt
        <ChevronDown size={17} />
      </button>
      <IconButton label="Notifications" onClick={() => notify('No unread agent alerts')}><Bell size={20} /></IconButton>
      <IconButton label="Help" onClick={() => notify('Authorize a target, run the safe Web audit, then open Report Draft')}><CircleHelp size={21} /></IconButton>
      <button className="profile" onClick={() => notify('Operator profile active')}>OS <ChevronDown size={17} /></button>
    </header>
  );
}

function Composer({
  target,
  setTarget,
  scopeRules,
  setScopeRules,
  authorized,
  setAuthorized,
  onRun,
  running,
  error
}) {
  return (
    <section className="composer">
      <div className="target-area">
        <div>
          <p className="eyebrow"><span />Scope gate</p>
          <h2>Authorize a target</h2>
          <p>Every run starts with a recorded boundary and your explicit approval.</p>
        </div>
        <div className="target-fields">
          <input
            aria-label="Target URL or repo path"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="Target URL or repo path, e.g. https://example.com or /path/to/repo"
          />
          <textarea
            aria-label="Scope notes"
            value={scopeRules}
            onChange={(event) => setScopeRules(event.target.value)}
            placeholder="Optional scope notes, exclusions, bounty rules, safe-test limits..."
          />
          <label className="auth-check">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(event) => setAuthorized(event.target.checked)}
            />
            I am authorized to test this target.
          </label>
          {error && <p className="error-line">{error}</p>}
        </div>
      </div>
      <div className="action-grid">
        {[
          ['Run safe Web audit', 'Recon, observe, validate, report', GitBranch, 'full'],
          ['Check duplicate', 'Public leads from findings', Sparkles, 'duplicate'],
          ['Draft report', 'Markdown from evidence', Clipboard, 'report']
        ].map(([title, subtitle, Icon, mode]) => (
          <button className="action-card" key={title} onClick={() => onRun(mode)} disabled={running}>
            <span><Icon size={22} /></span>
            <span>
              <strong>{title}</strong>
              <small>{subtitle}</small>
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}

function AgentSwarm({ onRun, audit, running }) {
  const visibleAgents = audit?.agents?.length ? audit.agents : buildAgents(null, []);
  return (
    <section className="panel agent-swarm">
      <div className="panel-title swarm-title">
        <h3><Sparkles size={18} /> Audit Pipeline</h3>
        <button onClick={() => onRun('full')} disabled={running}>
          <Route size={17} />
          {running ? 'Running' : 'Run pipeline'}
        </button>
      </div>
      <div className="agent-grid">
        {visibleAgents.map(({ name, role, progress, status, summary, detail }) => {
          const Icon = agentIcons[name] || ShieldCheck;
          const isRunning = status === 'running';
          return (
          <article className={`agent-card ${isRunning ? 'running' : ''}`} key={name}>
            <div className="agent-head">
              <span><Icon size={19} /></span>
              <strong>{name}</strong>
            </div>
            <p>{role}</p>
            <div className="agent-progress">
              <i><b style={{ width: `${progress || 0}%` }} /></i>
              <em>{status || `${progress || 0}%`}</em>
            </div>
            <small>{summary || 'Waiting for orchestrator'}</small>
            <span className="agent-detail">{detail || 'Live backend worker'}</span>
          </article>
        )})}
      </div>
    </section>
  );
}

function FindingsTable({ findings, selected, setSelected, onViewAll }) {
  return (
    <section className="panel findings-panel">
      <div className="table-head">
        <span>Severity</span>
        <span>Finding</span>
        <span>Hypothesis</span>
        <span>Confidence</span>
        <span>Status</span>
      </div>
      {findings.length === 0 && (
        <div className="empty-findings">
          <ShieldCheck size={20} />
          <strong>No findings yet</strong>
          <span>Run the swarm to produce live evidence.</span>
        </div>
      )}
      {findings.map((finding, index) => (
        <button
          className={`finding-row ${selected === index ? 'selected' : ''}`}
          key={finding.id || `${finding.path}-${finding.title}-${index}`}
          onClick={() => setSelected(index)}
        >
          <span className={`severity ${(finding.severity || 'info').toLowerCase()}`}>
            <ShieldCheck size={15} />
            {finding.severity}
          </span>
          <span className="finding-title">
              <strong>{finding.path}</strong>
              <small>{finding.title}</small>
            </span>
          <span className="hypothesis">{finding.hypothesis}</span>
          <span className="confidence">
            <strong>{finding.confidence}%</strong>
            <i><b style={{ width: `${finding.confidence}%` }} /></i>
          </span>
          <span className="status">
            <em className={finding.status === 'Analyzed' ? 'green' : 'blue'} />
            <span>{finding.status}<small>{finding.time || 'just now'}</small></span>
            <ChevronRight size={17} />
          </span>
        </button>
      ))}
      <button className="view-all" onClick={onViewAll}>View all findings <ChevronRight size={17} /></button>
    </section>
  );
}

function CodeExcerpt({ finding, onCopy }) {
  const lines = finding?.poc
    ? finding.poc.split('\n').map((line, index) => [String(index + 1).padStart(2, '0'), line])
    : [['01', 'Run a safe Web audit to generate a stored reproduction command.']];
  return (
    <section className="panel code-panel">
      <div className="panel-title">
        <h3>{finding?.poc ? 'Generated PoC' : 'Code excerpt'}</h3>
      </div>
      <div className="code-file">
        <span>{finding?.path || 'app/controllers/user_controller.rb'}</span>
        <button onClick={() => onCopy(finding?.poc || lines.map(([, code]) => code).join('\n'))}>{finding?.poc ? 'Command' : 'Copy'}</button>
        <button className="copy-button" onClick={() => onCopy(finding?.poc || lines.map(([, code]) => code).join('\n'))} aria-label="Copy PoC">
          <Copy size={17} />
        </button>
      </div>
      <pre>
        {lines.map(([line, code]) => (
          <div className={line === '45' ? 'hotline' : ''} key={line}>
            <span>{line}</span>
            <code>{code}</code>
          </div>
        ))}
      </pre>
    </section>
  );
}

function Timeline({ audit, expanded, setExpanded }) {
  const events = audit?.timeline?.length
    ? audit.timeline.map((item) => [item.time, item.agent, item.message, item.state === 'error' ? 'error' : 'by AI', item.state || 'done'])
    : [['--:--:--', 'Console', 'Create a hunt to write SQLite and /runs artifacts', 'local', 'open']];
  const visibleEvents = expanded ? events : events.slice(0, 12);
  return (
    <section className="panel timeline-panel">
      <div className="panel-title">
        <h3>Findings timeline</h3>
      </div>
      <div className="timeline">
        {visibleEvents.map(([time, title, detail, actor, state], index) => (
          <div className={`timeline-item ${state}`} key={`${time}-${title}-${detail}-${index}`}>
            <span className="timeline-dot">
              {state === 'done' ? <Check size={12} /> : state === 'open' ? '' : '!'}
            </span>
            <time>{time}</time>
            <div>
              <strong>{title}</strong>
              <small>{detail}</small>
            </div>
            <em>{actor}</em>
          </div>
        ))}
      </div>
      <button className="view-all timeline-link" onClick={() => setExpanded(!expanded)}>
        {expanded ? 'Collapse timeline' : 'View full timeline'} <ChevronRight size={17} />
      </button>
    </section>
  );
}

function EvidencePanel({ finding, audit, onReport, onCopy, notify }) {
  const [stackOpen, setStackOpen] = useState(true);
  const defaultCommand = finding?.poc || `curl -I ${audit?.target?.url || 'https://example.com'}`;
  const [commandDraft, setCommandDraft] = useState(defaultCommand);

  useEffect(() => {
    setCommandDraft(defaultCommand);
  }, [defaultCommand]);

  const checklist = useMemo(() => {
    if (!audit) return ['Target pending', 'Agents waiting', 'Report not generated'];
    return [
      `Audit ${audit.status}`,
      `${audit.findings?.length || 0} findings recorded`,
      audit.report ? 'Report draft generated' : 'Report pending'
    ];
  }, [audit]);

  const selected = finding || audit?.findings?.[0];

  return (
    <aside className="evidence">
      <section className="panel stack-panel">
        <div className="panel-title stack-title">
          <h3><Layers3 size={18} /> Evidence Stack</h3>
          <button className="copy-button" onClick={() => setStackOpen(!stackOpen)} aria-label={stackOpen ? 'Collapse evidence stack' : 'Expand evidence stack'}>
            <ChevronDown size={18} />
          </button>
        </div>
        {stackOpen && (
          <div className="evidence-card command-card">
            <div className="evidence-head">
              <h4><Command size={18} /> Editable command</h4>
              <button className="copy-button" onClick={() => onCopy(commandDraft)} aria-label="Copy repro command">
                <Copy size={17} />
              </button>
            </div>
            <textarea
              aria-label="Editable repro command"
              className="command-editor"
              value={commandDraft}
              onChange={(event) => setCommandDraft(event.target.value)}
              spellCheck="false"
            />
            <strong>{selected ? selected.status : 'Waiting'}</strong>
          </div>
        )}
      </section>
      <section className="panel evidence-card">
        <div className="evidence-head">
          <h4><DatabaseZap size={18} /> Signal snapshot</h4>
          <button className="copy-button" onClick={() => onCopy(JSON.stringify(audit?.evidence || {}, null, 2))} aria-label="Copy impact snapshot">
            <Link size={16} />
          </button>
        </div>
        <pre className="json">{JSON.stringify({
          target: audit?.target?.url || 'not set',
          status: audit?.status || 'idle',
          title: audit?.evidence?.http?.title,
          httpStatus: audit?.evidence?.http?.status,
          links: audit?.evidence?.http?.links?.length || 0,
          forms: audit?.evidence?.http?.forms || 0
        }, null, 2)}</pre>
      </section>
      <section className="panel refs-card">
        <h4><Link size={17} /> Evidence refs</h4>
        <ul>
          {(selected?.evidence?.length ? selected.evidence : audit?.evidence?.scope || ['No evidence yet']).slice(0, 4).map((item, index) => (
            <li key={`${item}-${index}`}>{item}</li>
          ))}
        </ul>
        <button onClick={() => {
          if (selected?.duplicateSearch?.[0]) {
            onCopy(selected.duplicateSearch.join('\n'));
          } else {
            notify('Duplicate leads pending');
          }
        }}>{selected?.duplicateSearch?.[0] || 'Duplicate leads pending'}</button>
      </section>
      <section className="ready-panel">
        <h3><Check size={20} /> Run integrity</h3>
        {checklist.map((item) => (
          <p key={item}><Check size={16} /> {item}</p>
        ))}
        <button onClick={onReport} disabled={!audit?.report}><FileText size={18} /> Open final report</button>
      </section>
    </aside>
  );
}

function AuditRunsPanel({ runs, onLoadRun, onRefreshRuns }) {
  return (
    <section className="panel runs-panel">
      <div className="panel-title">
        <h3><Crosshair size={18} /> Hunt Runs</h3>
        <button className="mini-action" onClick={onRefreshRuns}>Refresh</button>
      </div>
      <div className="runs-list">
        {runs.length === 0 && <p>No saved runs yet. Create a hunt to write SQLite and `/runs` artifacts.</p>}
        {runs.map((run) => (
          <button key={run.run_id} onClick={() => onLoadRun(run.run_id)}>
            <strong>{run.target}</strong>
            <span>{run.status} · {run.target_type}</span>
            <small>{run.run_id}</small>
          </button>
        ))}
      </div>
    </section>
  );
}

function VerifiedIdorProof({ proof, running, onRun }) {
  const control = proof?.control;
  const exploit = proof?.exploit;
  const confirmed = proof?.verdict === 'confirmed';

  return (
    <section className={`panel verified-proof ${confirmed ? 'confirmed' : ''}`}>
      <div className="panel-title proof-title">
        <div>
          <h3><ShieldCheck size={18} /> Verified IDOR Replay</h3>
          <p>Executes a real same-state control and attack against an ephemeral local fixture.</p>
        </div>
        <button className="mini-action" onClick={onRun} disabled={running}>
          <Zap size={16} /> {running ? 'Running proof…' : 'Run real proof'}
        </button>
      </div>
      {!proof && (
        <div className="proof-empty">
          <strong>Safe recon observes. Verified replay proves the authorization harm.</strong>
          <span>No external target is contacted; the vulnerable fixture binds to localhost on a random port.</span>
        </div>
      )}
      {proof && (
        <>
          <div className="proof-matrix">
            <article>
              <span>Truthful control</span>
              <strong>Attacker → own profile</strong>
              <code>{control.response.status} · owner={control.response.body.id}</code>
              <em className="proof-ok"><Check size={14} /> legitimate access works</em>
            </article>
            <article className="proof-harm">
              <span>Exploit</span>
              <strong>Attacker → victim profile</strong>
              <code>{exploit.response.status} · owner={exploit.response.body.id}</code>
              <em><Bug size={14} /> victim private data exposed</em>
            </article>
          </div>
          <div className="proof-verdict">
            <span><Check size={16} /> VERIFIED EXECUTION</span>
            <strong>Unauthenticated access is rejected; the same authenticated actor can still retrieve the victim record.</strong>
            <code>seed {proof.fixture.seed_sha256.slice(0, 12)}…</code>
          </div>
        </>
      )}
    </section>
  );
}

function ScopePanel({ target, setTarget, scopeRules, setScopeRules, authorized, setAuthorized, audit }) {
  return (
    <section className="panel scope-panel">
      <div className="panel-title">
        <h3><Globe2 size={18} /> Scope</h3>
      </div>
      <div className="scope-grid">
        <label>
          <span>Target URL or repo path</span>
          <input value={target} onChange={(event) => setTarget(event.target.value)} />
        </label>
        <label>
          <span>Scope notes</span>
          <textarea value={scopeRules} onChange={(event) => setScopeRules(event.target.value)} />
        </label>
        <label className="auth-check scope-check">
          <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
          I am authorized to test this target.
        </label>
        <div className="scope-artifacts">
          <strong>Current artifacts</strong>
          <span>Run: {audit?.run_id || 'none'}</span>
          <span>Raw: {audit?.rawDir || 'not created'}</span>
          <span>Report: {audit?.report?.path || 'not generated'}</span>
        </div>
      </div>
    </section>
  );
}

function SettingsPanel({ notify }) {
  return (
    <section className="panel settings-panel">
      <div className="panel-title">
        <h3><Settings size={18} /> Settings</h3>
      </div>
      <div className="settings-grid">
        <button onClick={() => notify('Safe Web mode uses bounded GET/HEAD requests and same-origin redirects only')}>Safe Web mode: on</button>
        <button onClick={() => notify('OpenAI API disabled by design')}>OpenAI API: disabled</button>
        <button onClick={() => notify('Google APIs disabled by design')}>Google APIs: disabled</button>
        <button onClick={() => notify('Active exploitation disabled')}>Active exploitation: disabled</button>
      </div>
    </section>
  );
}

function ExploitMap({ audit, findings, onCopy }) {
  const routes = audit?.evidence?.routes || [];
  return (
    <section className="panel map-panel">
      <div className="panel-title">
        <h3><TerminalSquare size={18} /> Surface Map</h3>
        <button className="mini-action" onClick={() => onCopy(JSON.stringify(routes, null, 2))}>Copy routes</button>
      </div>
      <div className="map-grid">
        <article>
          <strong>Target</strong>
          <span>{audit?.target?.url || 'No live audit yet'}</span>
        </article>
        <article>
          <strong>Routes</strong>
          <span>{routes.length} safe probes</span>
        </article>
        <article>
          <strong>Findings</strong>
          <span>{findings.length} candidates</span>
        </article>
      </div>
      <div className="route-list">
        {(routes.length ? routes : [{ route: '/', status: 'waiting', url: 'Run an audit to map routes' }]).map((route, index) => (
          <button key={`${route.route}-${index}`} onClick={() => route.url && onCopy(route.url)}>
            <span>{route.route}</span>
            <strong>{route.status}</strong>
            <small>{route.url}</small>
          </button>
        ))}
      </div>
    </section>
  );
}

function ReportDraft({ audit, onCopy, onReport }) {
  const markdown = audit?.report?.markdown || '# Report not ready\n\nRun a full audit to generate a markdown report.';
  return (
    <section className="panel report-panel">
      <div className="panel-title">
        <h3><FileText size={18} /> Report Draft</h3>
        <div className="report-actions">
          <button className="mini-action" onClick={() => onCopy(markdown)}>Copy markdown</button>
          <button className="mini-action" onClick={onReport} disabled={!audit?.report}>Open report</button>
        </div>
      </div>
      <pre>{markdown}</pre>
    </section>
  );
}

function App() {
  const [tab, setTab] = useState('Triage');
  const [selectedFinding, setSelectedFinding] = useState(0);
  const [lastAction, setLastAction] = useState('');
  const [activeNav, setActiveNav] = useState('Hunts');
  const [notice, setNotice] = useState('');
  const [search, setSearch] = useState('');
  const [timelineExpanded, setTimelineExpanded] = useState(false);
  const [target, setTarget] = useState('http://127.0.0.1:5173/');
  const [scopeRules, setScopeRules] = useState('Local authorized test target.');
  const [authorized, setAuthorized] = useState(true);
  const [audit, setAudit] = useState(null);
  const [runs, setRuns] = useState([]);
  const [error, setError] = useState('');
  const [idorProof, setIdorProof] = useState(null);
  const [proofRunning, setProofRunning] = useState(false);
  const tabs = ['Triage', 'Surface Map', 'Report Draft'];
  const running = audit?.status === 'scanning';
  const rawFindings = audit?.findings || [];
  const liveFindings = rawFindings.filter((finding) => {
    const q = search.trim().toLowerCase();
    if (!q) return true;
    return [finding.severity, finding.path, finding.title, finding.hypothesis, finding.status]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(q));
  });

  function notify(message) {
    setNotice(message);
    setTimeout(() => setNotice(''), 2400);
  }

  async function refreshRuns() {
    try {
      const data = await api('/api/audits');
      setRuns(data.audits || []);
      notify(`${data.audits?.length || 0} runs loaded`);
    } catch (loadError) {
      notify(loadError.message);
    }
  }

  async function loadRun(runId) {
    try {
      const data = await api(`/api/audits/${runId}`);
      setAudit(normalizeAuditResponse(data));
      setTab('Triage');
      setActiveNav('Findings');
      notify('Run loaded from SQLite');
    } catch (loadError) {
      notify(loadError.message);
    }
  }

  useEffect(() => {
    refreshRuns();
  }, []);

  async function startAudit(mode) {
    setError('');
    setSelectedFinding(0);
    setActiveNav('Findings');
    setTab('Triage');
    setLastAction('Creating hunt');
    try {
      const created = await api('/api/audits/create', {
        method: 'POST',
        body: JSON.stringify({ target, scope_notes: scopeRules, authorized })
      });
      setAudit(normalizeAuditResponse(created));
      notify('AuditRun created in SQLite');

      const scanned = await api(`/api/audits/${created.audit.run_id}/run-web-audit`, { method: 'POST' });
      setAudit(normalizeAuditResponse(scanned));
      notify('Live safe Web evidence captured');

      const reported = await api(`/api/audits/${created.audit.run_id}/generate-report`, { method: 'POST' });
      setAudit(normalizeAuditResponse(reported));
      await refreshRuns();
      notify(`${mode === 'report' ? 'Report draft' : mode === 'duplicate' ? 'Duplicate leads' : 'Safe Web audit'} ready`);
    } catch (runError) {
      setError(runError.message);
      notify(runError.message);
    }
  }

  async function runIdorProof() {
    setProofRunning(true);
    try {
      const data = await api('/api/proofs/idor/run', { method: 'POST' });
      setIdorProof(data.proof);
      notify('Victim-centered IDOR proof confirmed');
    } catch (proofError) {
      notify(proofError.message);
    } finally {
      setProofRunning(false);
    }
  }

  function openReport() {
    if (audit?.id && audit?.report) {
      window.open(`/api/audits/${audit.id}/report`, '_blank', 'noopener,noreferrer');
    } else {
      notify('Report is not ready yet');
    }
  }

  async function copyText(text) {
    const value = String(text || '');
    try {
      await navigator.clipboard.writeText(value);
      notify('Copied to clipboard');
    } catch {
      const fallback = document.createElement('textarea');
      fallback.value = value;
      fallback.setAttribute('readonly', '');
      fallback.style.position = 'fixed';
      fallback.style.left = '-9999px';
      document.body.appendChild(fallback);
      fallback.select();
      const copied = document.execCommand('copy');
      document.body.removeChild(fallback);
      notify(copied ? 'Copied to clipboard' : 'Copy blocked by browser');
    }
  }

  function newHunt() {
    setAudit(null);
    setSelectedFinding(0);
    setLastAction('');
    setSearch('');
    setTab('Triage');
    setActiveNav('Hunts');
    notify('New hunt ready');
  }

  return (
    <div className="app-shell">
      <Sidebar activeNav={activeNav} setActiveNav={setActiveNav} setTab={setTab} notify={notify} />
      <main className="main">
        <Topbar search={search} setSearch={setSearch} onNewHunt={newHunt} notify={notify} />
        <div className="workspace">
          <section className="console">
            <div className="title-row">
              <div>
                <p className="eyebrow"><span />Authorized research workspace</p>
                <h1>Signal Console</h1>
                <p className="title-subtitle">Bounded Web reconnaissance, evidence-first triage, and proof-ready reports.</p>
                <div className="tabs">
                  {tabs.map((name) => (
                    <button className={tab === name ? 'active' : ''} onClick={() => setTab(name)} key={name}>
                      {name}
                    </button>
                  ))}
                </div>
              </div>
              {(notice || lastAction || audit) && <span className="toast"><Zap size={15} /> {notice || (audit ? `Audit ${audit.status}` : `${lastAction} queued`)}</span>}
            </div>
            <Composer
              target={target}
              setTarget={setTarget}
              scopeRules={scopeRules}
              setScopeRules={setScopeRules}
              authorized={authorized}
              setAuthorized={setAuthorized}
              onRun={startAudit}
              running={running}
              error={error}
            />
            <AgentSwarm onRun={startAudit} audit={audit} running={running} />
            <VerifiedIdorProof proof={idorProof} running={proofRunning} onRun={runIdorProof} />
            {activeNav === 'Hunts' && <AuditRunsPanel runs={runs} onLoadRun={loadRun} onRefreshRuns={refreshRuns} />}
            {activeNav === 'Scope' && (
              <ScopePanel
                target={target}
                setTarget={setTarget}
                scopeRules={scopeRules}
                setScopeRules={setScopeRules}
                authorized={authorized}
                setAuthorized={setAuthorized}
                audit={audit}
              />
            )}
            {activeNav === 'Settings' && <SettingsPanel notify={notify} />}
            {tab === 'Triage' && !['Hunts', 'Scope', 'Settings'].includes(activeNav) && (
              <>
                <FindingsTable findings={liveFindings} selected={selectedFinding} setSelected={setSelectedFinding} onViewAll={() => { setSearch(''); notify(`${rawFindings.length} findings visible`); }} />
                <div className="lower-grid">
                  <CodeExcerpt finding={liveFindings[selectedFinding]} onCopy={copyText} />
                  <Timeline audit={audit} expanded={timelineExpanded} setExpanded={setTimelineExpanded} />
                </div>
              </>
            )}
            {tab === 'Surface Map' && !['Hunts', 'Scope', 'Settings'].includes(activeNav) && <ExploitMap audit={audit} findings={liveFindings} onCopy={copyText} />}
            {tab === 'Report Draft' && !['Hunts', 'Scope', 'Settings'].includes(activeNav) && <ReportDraft audit={audit} onCopy={copyText} onReport={openReport} />}
          </section>
          <EvidencePanel finding={liveFindings[selectedFinding]} audit={audit} onReport={openReport} onCopy={copyText} notify={notify} />
        </div>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
