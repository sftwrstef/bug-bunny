import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Bug,
  Check,
  ChevronDown,
  ChevronRight,
  Clipboard,
  Code2,
  Command,
  Copy,
  Crosshair,
  DatabaseZap,
  FileText,
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
  Zap
} from 'lucide-react';
import './styles.css';

const navItems = [
  { label: 'Hunts', icon: Crosshair },
  { label: 'Scope', icon: Globe2 },
  { label: 'Findings', icon: Bug },
  { label: 'Proof Lab', icon: Code2 },
  { label: 'Reports', icon: FileText },
  { label: 'Settings', icon: Settings }
];

const agentCatalog = [
  {
    name: 'Scope Gate',
    role: 'Records authorization and limits',
    icon: Crosshair,
    progress: 0,
    status: 'Waiting for a hunt',
    detail: 'Target and policy receipt'
  },
  {
    name: 'Evidence Collector',
    role: 'Runs bounded deterministic checks',
    icon: Radar,
    progress: 0,
    status: 'Waiting for scope',
    detail: 'DNS and HTTP receipts'
  },
  {
    name: 'AI Reviewer',
    role: 'Separates evidence from claims',
    icon: Sparkles,
    progress: 0,
    status: 'Waiting for evidence',
    detail: 'Model-configurable · tool access denied'
  },
  {
    name: 'Report Builder',
    role: 'Packages evidence and AI verdict',
    icon: FileText,
    progress: 0,
    status: 'Waiting for AI review',
    detail: 'Markdown plus provenance'
  }
];

const agentIcons = Object.fromEntries(agentCatalog.map((agent) => [agent.name, agent.icon]));

const INTIGRITI_PWN_POLICY_URL = 'https://app.intigriti.com/programs/intigriti/intigriti/detail';
const INTIGRITI_PWN_TARGET = 'https://app.pwn.intigriti.rocks/';
const INTIGRITI_PWN_SCOPE = 'Intigriti public PWN environment only. Exact host; attributed GET/HEAD traffic at ≤2 requests/second with a 24-request budget. No subdomain discovery, credential attacks, form submission, state changes, payload mutation, denial of service, or access to other users\' data.';
const INTIGRITI_PWN_PROOF_PROFILE_ID = 'intigriti-pwn-proof';
const AUTHENTICATED_REPLAY_PROFILE_ID = 'authenticated-replay';
const INTIGRITI_PWN_PROOF_HOSTS = ['app.pwn.intigriti.rocks', 'login.pwn.intigriti.rocks'];
const INTIGRITI_PWN_PROOF_HYPOTHESIS = 'Account B can access an object owned by Account A when supplied with Account A\'s known object identifier.';
const INTIGRITI_PWN_PROOF_SCOPE = 'Authorized testing of explicitly listed Intigriti PWN-environment hosts only. Two self-created controlled accounts may be used as attacker and victim. Manual browser and narrowly replayed API validation is permitted. Scripted requests remain below 2 requests per second and include X-Intigriti-Username: sftwr. No third-party accounts or data, mass identifier enumeration, credential attacks, brute force, denial of service, cross-scope traffic, destructive actions, or persistence. Stop after the minimum deterministic proof is captured.';
const AUTHENTICATED_REPLAY_SCOPE = 'Authorized testing of explicitly listed in-scope HTTPS hosts only. Two self-controlled accounts and two harmless self-controlled objects may be used for a GET-only authorization differential. No enumeration, state changes, third-party data, credential attacks, redirects, destructive actions, persistence, or denial of service. Stop immediately on exposure; otherwise stop after the fourth bounded control request.';

function isAuthenticatedReplayProfile(profileId) {
  return profileId === INTIGRITI_PWN_PROOF_PROFILE_ID || profileId === AUTHENTICATED_REPLAY_PROFILE_ID;
}

function hostnameFromUrl(value) {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return '';
  }
}

const externalProgramDefaults = {
  profileId: 'intigriti-pwn',
  platform: 'Intigriti',
  researcherUsername: '',
  programName: 'Intigriti',
  policyUrl: INTIGRITI_PWN_POLICY_URL,
  allowedHosts: [],
  proofHypothesis: '',
  controlledAccountsAcknowledged: false,
  minimumProofAcknowledged: false,
  automationAcknowledged: false,
  humanReviewAcknowledged: false
};

async function api(path, options) {
  const { headers: optionHeaders = {}, ...requestOptions } = options || {};
  const response = await fetch(path, {
    ...requestOptions,
    headers: { 'content-type': 'application/json', ...optionHeaders }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = Array.isArray(data.detail)
      ? data.detail.map((issue) => issue.msg || issue.message || 'Invalid request').join(' ')
      : data.detail;
    throw new Error(data.error || detail || `Request failed with HTTP ${response.status}`);
  }
  return data;
}

function severityRank(severity) {
  return { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 }[severity] ?? 0;
}

function formatStatus(status) {
  if (status === 'proof_closed_invalid') return 'Hypothesis closed · no IDOR';
  if (status === 'authenticated_replay_verified') return 'Authenticated replay verified · review required';
  if (status === 'authenticated_replay_closed_invalid') return 'Authenticated replay closed · authorization held';
  if (status === 'authenticated_replay_inconclusive') return 'Authenticated replay inconclusive';
  if (status === 'authenticated_replay_report_generated') return 'Authenticated replay report generated';
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

function buildAgents(audit, findings = [], requestedMode = 'local_lab', requestedProfile = null) {
  const status = audit?.status || 'created';
  const controlledProofResult = audit?.controlledProofResult;
  const authenticatedReplayResult = audit?.authenticatedReplayResult;
  const hasEvidence = Boolean(audit?.evidenceCollected) || ['web_audit_complete', 'mock_scan_complete', 'proof_closed_invalid', 'report_generated'].includes(status) || status.startsWith('authenticated_replay_');
  const hasAnalysis = Boolean(audit?.aiAnalysis);
  const hasReport = Boolean(audit?.report) || status === 'report_generated';
  const externalProgram = (audit?.mode || requestedMode) === 'external_program';
  const profileId = audit?.policyReceipt?.profileId || requestedProfile?.profileId;
  const boundedExternal = externalProgram && profileId === 'intigriti-pwn';
  const controlledProof = externalProgram && isAuthenticatedReplayProfile(profileId);
  return agentCatalog.map((stage) => {
    const name = stage.name;
    const complete =
      (Boolean(audit) && name === 'Scope Gate') ||
      (hasEvidence && name === 'Evidence Collector') ||
      (hasAnalysis && name === 'AI Reviewer') ||
      (hasReport && name === 'Report Builder');
    const running = status === 'scanning' && name === 'Evidence Collector';
    const progress = complete ? 100 : running ? 45 : 0;
    const summaries = {
      'Scope Gate': audit ? (controlledProof ? 'Controlled proof scope and status stored locally' : externalProgram ? 'Program policy receipt stored in SQLite' : 'Authorization receipt stored in SQLite') : 'Waiting for target',
      'Evidence Collector': hasEvidence ? (authenticatedReplayResult ? `${authenticatedReplayResult.requestBudgetUsed}/${authenticatedReplayResult.requestBudgetMax} bounded requests · ${authenticatedReplayResult.classification}` : controlledProofResult ? 'Owner control passed · 2/2 cross-account replays denied' : boundedExternal ? `${audit.evidence?.requestLog?.length || 0} attributed requests mapped the public surface` : externalProgram ? 'One exact GET stored; no discovery' : `${findings.length} bounded observations stored`) : controlledProof ? 'Waiting for two ephemeral authenticated captures' : 'Waiting for a scoped collection',
      'AI Reviewer': hasAnalysis ? `${audit.aiAnalysis.analysis?.verdict || 'Analysis'} · ${audit.aiAnalysis.model_ref}` : 'Waiting for saved evidence',
      'Report Builder': hasReport ? (externalProgram ? 'Observation ledger written to /runs' : 'Evidence report written to /runs') : 'Waiting for AI review'
    };
    return {
      name,
      role: stage.role,
      status: complete ? 'complete' : running ? 'running' : 'queued',
      progress,
      summary: summaries[name],
      detail: name === 'AI Reviewer'
        ? 'Evidence-only OpenCode session · tools blocked'
        : externalProgram
          ? controlledProof ? (authenticatedReplayResult ? 'GET only · distinct sessions · same-state A/B controls · sanitized receipt' : 'Explicit hosts, two controlled accounts, known-ID replay, and stop condition enforced') : boundedExternal ? 'Intigriti allowlist, identity, rate, and budget enforced' : 'External passive boundary enforced'
          : stage.detail
    };
  });
}

function normalizeAuditResponse(data) {
  const rawAudit = data.audit;
  if (!rawAudit) return null;
  const findings = (data.findings || []).map(normalizeFinding).sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const engineAudit = data.engine_audit;
  const aiAnalysis = data.ai_analysis || null;
  const controlledProofResult = data.controlled_proof_result || null;
  const authenticatedReplayResult = data.authenticated_replay_result || null;
  const authenticatedReplayReceiptSha256 = data.authenticated_replay_receipt_sha256 || null;
  const authenticatedReplayTimeline = authenticatedReplayResult ? [
    {
      time: new Date(authenticatedReplayResult.recordedAt).toLocaleTimeString([], { hour12: false }),
      agent: 'Evidence Collector',
      message: `${authenticatedReplayResult.verdict} · ${authenticatedReplayResult.classification} · ${authenticatedReplayResult.requestBudgetUsed}/${authenticatedReplayResult.requestBudgetMax} bounded requests.`,
      actor: 'authenticated replay',
      state: authenticatedReplayResult.verdict === 'INCONCLUSIVE' ? 'warning' : 'done'
    },
    {
      time: new Date(rawAudit.created_at).toLocaleTimeString([], { hour12: false }),
      agent: 'Scope Gate',
      message: 'Two controlled accounts, two controlled objects, explicit hosts, and the minimum-proof stop condition were enforced.',
      actor: 'system',
      state: 'done'
    }
  ] : controlledProofResult ? [
    {
      time: new Date(controlledProofResult.recordedAt).toLocaleTimeString([], { hour12: false }),
      agent: 'Evidence Collector',
      message: 'Owner control passed; Account B was denied on both isolated known-object replays.',
      actor: 'manual proof',
      state: 'done'
    },
    {
      time: new Date(rawAudit.created_at).toLocaleTimeString([], { hour12: false }),
      agent: 'Scope Gate',
      message: 'Two controlled accounts, one known draft, and the minimum-proof stop condition were enforced.',
      actor: 'system',
      state: 'done'
    }
  ] : null;
  const baseTimeline = engineAudit?.timeline?.length ? engineAudit.timeline : authenticatedReplayTimeline || buildTimeline(rawAudit, findings);
  const timeline = aiAnalysis
    ? [{
        time: new Date(aiAnalysis.analyzed_at).toLocaleTimeString([], { hour12: false }),
        agent: 'AI Reviewer',
        message: `${aiAnalysis.analysis?.verdict}: ${aiAnalysis.analysis?.summary || 'Evidence analyzed'}`,
        actor: 'AI',
        state: 'done'
      }, ...baseTimeline]
    : baseTimeline;
  const normalized = {
    id: rawAudit.run_id,
    run_id: rawAudit.run_id,
    status: rawAudit.status,
    mode: rawAudit.mode || 'local_lab',
    target: { url: rawAudit.target, type: rawAudit.target_type },
    scopeRules: rawAudit.scope_notes,
    policyReceipt: rawAudit.policy_receipt || {},
    runDir: rawAudit.run_dir,
    rawDir: rawAudit.raw_dir,
    reportsDir: rawAudit.reports_dir,
    aiAnalysis,
    controlledProofResult,
    authenticatedReplayResult,
    authenticatedReplayReceiptSha256,
    evidenceCollected: Boolean(engineAudit || controlledProofResult || authenticatedReplayResult),
    report: rawAudit.report_path ? {
      path: rawAudit.report_path,
      markdown: data.markdown || ''
    } : null,
    evidence: {
      ...(engineAudit?.evidence || {}),
      ...(authenticatedReplayResult ? { authenticated_replay: authenticatedReplayResult } : {}),
      run_id: rawAudit.run_id,
      target_type: rawAudit.target_type,
      run_dir: rawAudit.run_dir,
      raw_dir: rawAudit.raw_dir,
      reports_dir: rawAudit.reports_dir,
      report_path: rawAudit.report_path,
      scanner_mode: authenticatedReplayResult
        ? 'authenticated-capture-replay'
        : engineAudit
        ? (rawAudit.mode === 'external_program' ? (rawAudit.policy_receipt?.profileId === 'intigriti-pwn' ? 'external-program-bounded' : 'external-program-passive') : 'authorized-read-only')
        : isAuthenticatedReplayProfile(rawAudit.policy_receipt?.profileId) ? 'authenticated-capture-replay' : 'not-run'
    },
    findings,
    timeline
  };
  normalized.agents = buildAgents(normalized, findings);
  return normalized;
}

function buildTimeline(audit, findings) {
  if (!audit) return [];
  const items = [
    {
      time: new Date(audit.created_at).toLocaleTimeString([], { hour12: false }),
      agent: 'Scope Gate',
      message: isAuthenticatedReplayProfile(audit.policy_receipt?.profileId)
        ? 'Controlled proof boundary stored; zero target requests sent'
        : 'Authorization boundary stored in SQLite',
      actor: 'system',
      state: 'done'
    }
  ];
  if (['web_audit_complete', 'mock_scan_complete', 'report_generated'].includes(audit.status)) {
    items.push({
      time: new Date(audit.updated_at).toLocaleTimeString([], { hour12: false }),
      agent: 'Evidence Collector',
      message: audit.mode === 'external_program' ? (audit.policy_receipt?.profileId === 'intigriti-pwn' ? 'Bounded attributed surface map stored; no vulnerability asserted' : 'Passive response posture stored; no finding asserted') : `web_audit.json parsed into ${findings.length} observations`,
      actor: 'system',
      state: 'done'
    });
  }
  if (audit.status === 'report_generated') {
    items.push({ time: new Date(audit.updated_at).toLocaleTimeString([], { hour12: false }), agent: 'Report Builder', message: 'Markdown report written to run folder', actor: 'system', state: 'done' });
  }
  return items.reverse();
}

function BrandMark() {
  return (
    <div className="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 42 42" role="img">
        <rect className="frame" x="3" y="3" width="36" height="36" rx="11" />
        <path className="slash slash-one" d="M13 12 29 30" />
        <path className="slash slash-two" d="M29 12 13 30" />
        <path className="pulse" d="M7 21h6m16 0h6" />
      </svg>
    </div>
  );
}

function Sidebar({ activeNav, setActiveNav, setTab }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <BrandMark />
        <span>CTRL<span>/X</span></span>
      </div>
      <nav className="nav">
        {navItems.map(({ label, icon: Icon }) => (
          <button
            className={`nav-item ${activeNav === label ? 'active' : ''}`}
            key={label}
            onClick={() => {
              setActiveNav(label);
              if (label === 'Findings') setTab('Triage');
              if (label === 'Reports') setTab('Report Draft');
            }}
          >
            <Icon size={21} strokeWidth={2} />
            <span>{label}</span>
          </button>
        ))}
      </nav>
      <div className="sidebar-bottom">
        <div className="workspace-card">
          <div className="workspace-icon"><ShieldCheck size={18} /></div>
          <div>
            <strong>Local Workspace</strong>
            <span>SQLite evidence store</span>
          </div>
        </div>
        <div className="credits">
          <div className="credits-head">
            <span>Safe Web Mode</span>
          </div>
          <strong>Read-only HTTP checks</strong>
          <div className="meter"><span style={{ width: '78%' }} /></div>
          <small>Evidence stored locally</small>
        </div>
      </div>
    </aside>
  );
}

function Topbar({ search, setSearch, onNewHunt }) {
  return (
    <header className="topbar">
      <label className="command-search">
        <Search size={18} />
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Filter observations by severity, path, title, or status"
        />
      </label>
      <button className="new-hunt" onClick={onNewHunt}>
        <Plus size={19} />
        New hunt
      </button>
    </header>
  );
}

function Composer({
  auditMode,
  setAuditMode,
  localWorkflow,
  setLocalWorkflow,
  target,
  setTarget,
  scopeRules,
  setScopeRules,
  authorized,
  setAuthorized,
  programProfile,
  setProgramProfile,
  onApplyProgramPreset,
  audit,
  onCollect,
  onAnalyze,
  onGenerateReport,
  busyAction,
  error
}) {
  const externalProgram = auditMode === 'external_program';
  const localReplay = !externalProgram && localWorkflow === 'authenticated-replay';
  const boundedExternal = externalProgram && programProfile.profileId === 'intigriti-pwn';
  const controlledProof = externalProgram && isAuthenticatedReplayProfile(programProfile.profileId);
  const replayWorkflow = localReplay || controlledProof;
  const pwnProof = programProfile.profileId === INTIGRITI_PWN_PROOF_PROFILE_ID;
  const pwnProfile = boundedExternal || pwnProof;
  const genericReplay = programProfile.profileId === AUTHENTICATED_REPLAY_PROFILE_ID;
  const updateProgramProfile = (field, value) => setProgramProfile((current) => ({ ...current, [field]: value }));
  const controlledResult = audit?.authenticatedReplayResult || audit?.controlledProofResult;
  const controlledProofReady = !replayWorkflow || Boolean(controlledResult);
  const controlledProofClosed = replayWorkflow && Boolean(controlledResult);
  const controlledAnalysisSaved = replayWorkflow && Boolean(audit?.aiAnalysis);
  const canAnalyze = Boolean(audit?.evidenceCollected) && controlledProofReady && !controlledAnalysisSaved;
  const canReport = Boolean(audit?.aiAnalysis) && controlledProofReady;
  const targetHostname = hostnameFromUrl(target);
  const explicitProofHostsReady = !controlledProof || (
    programProfile.allowedHosts.length > 0
    && programProfile.allowedHosts.every((host) => (
      pwnProof
        ? /^[a-z0-9.-]+\.pwn\.intigriti\.rocks$/i.test(host)
        : /^[a-z0-9.-]+$/i.test(host) && !host.includes('*') && !host.startsWith('.')
    ))
    && Boolean(targetHostname)
    && programProfile.allowedHosts.includes(targetHostname)
  );
  const profileReady = !externalProgram || (
    programProfile.programName.trim()
    && /^https:\/\//i.test(programProfile.policyUrl)
    && programProfile.automationAcknowledged
    && programProfile.humanReviewAcknowledged
    && (!pwnProfile || /^[A-Za-z0-9_.-]{2,64}$/.test(programProfile.researcherUsername.trim()))
    && explicitProofHostsReady
    && (!controlledProof || (
      programProfile.proofHypothesis.trim()
      && programProfile.controlledAccountsAcknowledged
      && programProfile.minimumProofAcknowledged
    ))
  );
  const canCollect = Boolean(target.trim() && scopeRules.trim() && authorized && profileReady);
  const actionCards = [
    {
      title: controlledProofClosed ? 'Authenticated replay complete' : replayWorkflow ? 'Prepare authenticated replay' : boundedExternal ? 'Map bounded live surface' : externalProgram ? 'Collect one passive response' : 'Collect bounded evidence',
      subtitle: controlledProofClosed
        ? (audit?.authenticatedReplayResult ? `${audit.authenticatedReplayResult.verdict} · ${audit.authenticatedReplayResult.classification}` : 'Owner control passed · 2/2 peer replays denied')
        : !canCollect
        ? (pwnProfile ? 'Enter identity and confirm every scope check' : 'Complete the scope and authorization gate')
        : replayWorkflow ? 'SQLite scope receipt only · zero target traffic until you paste both captures' : boundedExternal ? 'Attributed GET/HEAD · 24-request hard budget' : externalProgram ? 'One exact GET · no discovery or follow-ups' : 'Authorized DNS and read-only HTTP checks',
      Icon: externalProgram ? ShieldCheck : GitBranch,
      action: onCollect,
      disabled: Boolean(busyAction) || !canCollect || controlledProofClosed
    },
    {
      title: controlledAnalysisSaved ? 'AI review saved' : busyAction === 'analyze' ? 'AI is reviewing…' : 'Review current run with AI',
      subtitle: controlledAnalysisSaved ? 'Write-once session preserved with the run' : canAnalyze ? 'Redacted receipt → structured proof requirements' : 'Collect evidence first',
      Icon: Sparkles,
      action: onAnalyze,
      disabled: Boolean(busyAction) || !canAnalyze
    },
    {
      title: busyAction === 'report' ? 'Writing report…' : 'Generate evidence report',
      subtitle: canReport ? (replayWorkflow ? 'Redacted proof receipt + AI verdict + provenance' : 'Deterministic receipts + AI verdict + provenance') : 'Run AI review first',
      Icon: Clipboard,
      action: onGenerateReport,
      disabled: Boolean(busyAction) || !canReport
    }
  ];

  return (
    <section className="composer">
      <div className="target-area">
        <div>
          <p className="eyebrow"><span />Scope gate</p>
          <h2>{replayWorkflow ? 'Authenticated replay boundary' : boundedExternal ? 'Live program boundary' : externalProgram ? 'External program boundary' : 'Authorize a target'}</h2>
          <p>{replayWorkflow ? `A reusable A-versus-B proof boundary with explicit ${localReplay ? 'localhost or owned-target' : pwnProof ? 'PWN' : 'program'} hosts, two self-controlled accounts, equivalent objects, and a four-request hard stop. Recording scope sends zero traffic.` : boundedExternal ? 'A real paid-program target with a pinned allowlist, researcher attribution, rate ceiling, and request budget.' : externalProgram ? 'A single, policy-recorded public URL. This mode observes once and never asserts a bounty finding.' : 'Every local or owned-target run starts with a recorded boundary and your explicit approval.'}</p>
        </div>
        <div className="target-fields">
          <div className="mode-switch" role="group" aria-label="Audit mode">
            <button className={auditMode === 'local_lab' ? 'active' : ''} onClick={() => setAuditMode('local_lab')} type="button">Local / owned target</button>
            <button className={externalProgram ? 'active' : ''} onClick={() => setAuditMode('external_program')} type="button">Live bounty target</button>
          </div>
          {!externalProgram && (
            <div className="mode-switch workflow-switch" role="group" aria-label="Local evidence workflow">
              <button className={localWorkflow === 'bounded-audit' ? 'active' : ''} onClick={() => { setLocalWorkflow('bounded-audit'); setAuthorized(true); }} type="button">Bounded recon</button>
              <button data-testid="choose-local-replay" className={localReplay ? 'active' : ''} onClick={() => { setLocalWorkflow('authenticated-replay'); setAuthorized(true); }} type="button">Authenticated replay</button>
            </div>
          )}
          <input
            aria-label={externalProgram ? 'Exact in-scope HTTPS URL' : 'Owned or localhost target URL'}
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder={externalProgram ? 'Exact in-scope HTTPS URL' : 'Owned or localhost URL, e.g. http://127.0.0.1:3000/'}
          />
          <textarea
            aria-label="Scope notes"
            value={scopeRules}
            onChange={(event) => setScopeRules(event.target.value)}
            placeholder={externalProgram ? 'Record the current scope rule, exclusions, attribution headers, and any tighter rate limit…' : 'Optional scope notes, exclusions, bounty rules, safe-test limits...'}
          />
          {externalProgram && (
            <div className="policy-profile">
              <div className="policy-profile-head">
                <strong>Policy receipt</strong>
                <span>stored with the run</span>
              </div>
              <p>{controlledProof ? `${pwnProof ? 'Intigriti PWN' : 'Cross-platform'} authenticated replay · explicit hosts only · two self-controlled accounts and objects · GET only · no automatic traffic while recording scope, enumeration, third-party data, redirects, writes, or persistence.` : boundedExternal ? 'Intigriti PWN environment · 24 attributed GET/HEAD requests at ≤2/second · same-origin public assets only · no writes, credential attacks, subdomain discovery, or payload mutation.' : 'Exactly one public HTTPS URL · one GET at ≤1 HTTP request/second · no redirects, route guessing, CORS probes, auth, payloads, or proof traffic.'}</p>
              <label>
                <span>Target profile</span>
                <select value={programProfile.profileId} onChange={(event) => onApplyProgramPreset(event.target.value)}>
                  <option value="intigriti-pwn">Intigriti PWN environment — bounded live map</option>
                  <option value={INTIGRITI_PWN_PROOF_PROFILE_ID}>Intigriti PWN — controlled A↔B proof scope</option>
                  <option value={AUTHENTICATED_REPLAY_PROFILE_ID}>Authenticated replay — any reviewed program</option>
                  <option value="custom-passive">Custom program — one passive response</option>
                </select>
              </label>
              <div className="policy-profile-fields">
                <label>
                  <span>Platform</span>
                  <select value={programProfile.platform} disabled={pwnProfile} onChange={(event) => updateProgramProfile('platform', event.target.value)}>
                    <option>HackerOne</option>
                    <option>Bugcrowd</option>
                    <option>Intigriti</option>
                  </select>
                </label>
                <label>
                  <span>Program name</span>
                  <input value={programProfile.programName} readOnly={pwnProfile} onChange={(event) => updateProgramProfile('programName', event.target.value)} placeholder="e.g. PortSwigger" />
                </label>
              </div>
              {pwnProfile && <label>
                <span>Your Intigriti username — sent in the required attribution header</span>
                <input value={programProfile.researcherUsername} onChange={(event) => updateProgramProfile('researcherUsername', event.target.value)} placeholder="your Intigriti username" autoComplete="off" />
              </label>}
              <label>
                <span>Current policy URL</span>
                <input value={programProfile.policyUrl} readOnly={pwnProfile} onChange={(event) => updateProgramProfile('policyUrl', event.target.value)} placeholder="https://…" />
              </label>
              {controlledProof && <>
                <label>
                  <span>Explicit {pwnProof ? 'PWN ' : ''}hostnames — comma separated; no wildcards</span>
                  <input
                    value={programProfile.allowedHosts.join(', ')}
                    onChange={(event) => updateProgramProfile('allowedHosts', event.target.value.split(',').map((host) => host.trim().toLowerCase()).filter(Boolean))}
                    placeholder={pwnProof ? 'app.pwn.intigriti.rocks, login.pwn.intigriti.rocks' : 'api.example.com, app.example.com'}
                    autoComplete="off"
                  />
                </label>
                <label>
                  <span>One victim-centered hypothesis</span>
                  <textarea
                    value={programProfile.proofHypothesis}
                    onChange={(event) => updateProgramProfile('proofHypothesis', event.target.value)}
                    placeholder="Account B can access Account A's known object identifier…"
                  />
                </label>
                <label className="auth-check">
                  <input type="checkbox" checked={programProfile.controlledAccountsAcknowledged} onChange={(event) => updateProgramProfile('controlledAccountsAcknowledged', event.target.checked)} />
                  Account A and Account B will both be self-created accounts that I control.
                </label>
                <label className="auth-check">
                  <input type="checkbox" checked={programProfile.minimumProofAcknowledged} onChange={(event) => updateProgramProfile('minimumProofAcknowledged', event.target.checked)} />
                  I will replay only Account A's known object ID under B, repeat once for cache/session control, then stop.
                </label>
              </>}
              <label className="auth-check">
                <input type="checkbox" checked={programProfile.automationAcknowledged} onChange={(event) => updateProgramProfile('automationAcknowledged', event.target.checked)} />
                {controlledProof ? `The current policy permits this controlled validation; the engine will use no more than four GET requests${genericReplay ? ' at one request per second' : ' at or below two requests per second'}.` : 'The current policy explicitly permits this low-rate, read-only check.'}
              </label>
              <label className="auth-check">
                <input type="checkbox" checked={programProfile.humanReviewAcknowledged} onChange={(event) => updateProgramProfile('humanReviewAcknowledged', event.target.checked)} />
                I will manually validate scope, impact, and duplicates before reporting anything.
              </label>
            </div>
          )}
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
        {actionCards.map(({ title, subtitle, Icon, action, disabled }) => (
          <button className="action-card" key={title} onClick={action} disabled={disabled}>
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

function AgentSwarm({ audit, requestedMode, requestedProfile }) {
  const externalProgram = (audit?.mode || requestedMode) === 'external_program';
  const profileId = audit?.policyReceipt?.profileId || requestedProfile?.profileId;
  const boundedExternal = externalProgram && profileId === 'intigriti-pwn';
  const controlledProof = externalProgram && isAuthenticatedReplayProfile(profileId);
  const visibleAgents = audit?.agents?.length ? audit.agents : buildAgents(null, [], requestedMode, requestedProfile);
  return (
    <section className="panel agent-swarm">
      <div className="panel-title swarm-title">
        <h3><Route size={18} /> {controlledProof ? 'Controlled Proof Pipeline' : boundedExternal ? 'Live Program Pipeline' : externalProgram ? 'Passive Program Pipeline' : 'Evidence Pipeline'}</h3>
        <span className="provider-chip"><Sparkles size={14} /> Optional AI review · model-configurable</span>
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
          <span>Observation</span>
        <span>Hypothesis</span>
        <span>Confidence</span>
        <span>Status</span>
      </div>
      {findings.length === 0 && (
        <div className="empty-findings">
          <ShieldCheck size={20} />
          <strong>No observations yet</strong>
          <span>Run the selected pipeline to produce stored evidence.</span>
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

function CodeExcerpt({ finding, onCopy, externalProgram }) {
  const lines = finding?.poc
    ? finding.poc.split('\n').map((line, index) => [String(index + 1).padStart(2, '0'), line])
    : [['01', externalProgram ? 'External Program mode creates no reproduction commands or follow-up traffic.' : 'Run a safe Web audit to generate a stored reproduction command.']];
  return (
    <section className="panel code-panel">
      <div className="panel-title">
        <h3>{finding?.poc ? 'Generated PoC' : 'Code excerpt'}</h3>
      </div>
      <div className="code-file">
        <span>{finding?.path || 'app/controllers/user_controller.rb'}</span>
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
    ? audit.timeline.map((item) => [item.time, item.agent, item.message, item.actor || (item.agent === 'AI Reviewer' ? 'AI' : 'system'), item.state || 'done'])
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

function EvidencePanel({ finding, audit, requestedMode, onReport, onCopy, notify }) {
  const [stackOpen, setStackOpen] = useState(true);
  const externalProgram = audit?.mode === 'external_program' || requestedMode === 'external_program';
  const boundedExternal = externalProgram && audit?.policyReceipt?.profileId === 'intigriti-pwn';
  const authenticatedReplay = audit?.authenticatedReplayResult;
  const controlledProof = Boolean(authenticatedReplay) || (externalProgram && isAuthenticatedReplayProfile(audit?.policyReceipt?.profileId));
  const defaultCommand = externalProgram
    ? controlledProof
      ? authenticatedReplay || audit?.controlledProofResult
        ? 'Replay receipt is write-once. Create a new scoped run for different captures or another object flow.'
        : 'Open Proof Lab and paste two ephemeral DevTools cURL captures. Raw credentials are never retained.'
      : boundedExternal
      ? 'No automatic exploit command: review the mapped surface and authorize one manual hypothesis first.'
      : 'No reproduction command: passive mode permits no follow-up traffic.'
    : finding?.poc || `curl -I ${audit?.target?.url || 'https://example.com'}`;
  const [commandDraft, setCommandDraft] = useState(defaultCommand);

  useEffect(() => {
    setCommandDraft(defaultCommand);
  }, [defaultCommand]);

  const checklist = useMemo(() => {
    if (!audit) return ['Target pending', 'Agents waiting', 'Report not generated'];
    return [
      formatStatus(audit.status),
      authenticatedReplay ? `${authenticatedReplay.verdict} · ${authenticatedReplay.classification} · submission ready: no` : controlledProof && audit.controlledProofResult ? 'Tested draft hypothesis closed as INVALID · NO IDOR' : `${audit.findings?.length || 0} ${externalProgram ? 'observations' : 'findings'} recorded`,
      authenticatedReplay ? `A→A and B→B controls · ${authenticatedReplay.requestBudgetUsed}/${authenticatedReplay.requestBudgetMax} bounded requests` : controlledProof ? 'Two-account known-ID boundary and stop condition enforced' : boundedExternal ? `${audit.policyReceipt.requestBudget}-request attributed live-target boundary enforced` : externalProgram ? 'One-GET passive boundary enforced' : 'Local / owned-target safety boundary',
      audit.aiAnalysis ? `AI verdict: ${audit.aiAnalysis.analysis?.verdict}` : 'AI review pending',
      audit.report ? (externalProgram ? 'Observation ledger generated' : 'Report draft generated') : 'Report pending'
    ];
  }, [audit, externalProgram, boundedExternal, controlledProof, authenticatedReplay]);

  const selected = finding || audit?.findings?.[0];
  const signalSnapshot = authenticatedReplay ? {
    target: audit.target?.url,
    status: formatStatus(audit.status),
    verdict: authenticatedReplay.verdict,
    classification: authenticatedReplay.classification,
    controls: authenticatedReplay.attempts?.filter((attempt) => attempt.branch.endsWith('_control')).length || 0,
    requestBudget: `${authenticatedReplay.requestBudgetUsed}/${authenticatedReplay.requestBudgetMax}`,
    submissionReady: authenticatedReplay.submissionReady
  } : controlledProof && audit?.controlledProofResult ? {
    target: audit.target?.url,
    status: formatStatus(audit.status),
    classification: audit.controlledProofResult.classification,
    testedScope: audit.controlledProofResult.testedScope,
    replayAttempts: audit.controlledProofResult.authorizationBranch?.attempts,
    submissionReady: audit.controlledProofResult.submissionReady
  } : {
    target: audit?.target?.url || 'not set',
    status: audit?.status || 'idle',
    title: audit?.evidence?.http?.title,
    httpStatus: audit?.evidence?.http?.status,
    links: audit?.evidence?.http?.links?.length || 0,
    forms: audit?.evidence?.http?.forms || 0
  };
  const evidenceRefs = authenticatedReplay ? [
    `Receipt SHA-256: ${audit.authenticatedReplayReceiptSha256 || 'not recorded'}`,
    `Capture SHA-256: ${authenticatedReplay.captureSha256}`,
    `Endpoint: ${authenticatedReplay.method} ${authenticatedReplay.hostname} · ${authenticatedReplay.endpointShape?.locatorKind}`,
    `Redaction: raw cURL, credentials, markers, locators, and bodies absent`
  ] : controlledProof && audit?.controlledProofResult ? [
    `Program: ${audit?.policyReceipt?.programName || 'not recorded'}`,
    `Tested scope: ${audit.controlledProofResult.testedScope}`,
    `Classification: ${audit.controlledProofResult.verdict} · ${audit.controlledProofResult.classification}`,
    'Submission gate: closed'
  ] : externalProgram ? [
    `Program: ${audit?.policyReceipt?.programName || 'not recorded'}`,
    `Policy: ${audit?.policyReceipt?.policyUrl || 'not recorded'}`,
    `Exact scope: ${audit?.policyReceipt?.exactScopeUrl || audit?.target?.url || 'not recorded'}`,
    'Submission gate: manual validation required'
  ] : selected?.evidence?.length ? selected.evidence : audit?.evidence?.scope;

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
              <h4><Command size={18} /> {externalProgram ? 'Follow-up boundary' : 'Editable command'}</h4>
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
        <pre className="json">{JSON.stringify(signalSnapshot, null, 2)}</pre>
      </section>
      <section className={`panel evidence-card ai-card ${audit?.aiAnalysis ? 'complete' : ''}`}>
        <div className="evidence-head">
          <h4><Sparkles size={18} /> AI evidence review</h4>
          <span>{audit?.aiAnalysis?.model_ref || 'Model selected at runtime'}</span>
        </div>
        {audit?.aiAnalysis ? (
          <>
            <strong>{audit.aiAnalysis.analysis?.verdict}</strong>
            <p>{audit.aiAnalysis.analysis?.summary}</p>
            <small>Session {audit.aiAnalysis.session_id || 'not recorded'} · input {audit.aiAnalysis.input_sha256?.slice(0, 12)}…</small>
          </>
        ) : (
          <p>Collect evidence, then run an optional AI review. The configured model receives a redacted receipt and has no OpenCode tool permissions.</p>
        )}
      </section>
      <section className="panel refs-card">
        <h4><Link size={17} /> Evidence refs</h4>
        <ul>
          {(evidenceRefs || ['No evidence yet']).slice(0, 4).map((item, index) => (
            <li key={`${item}-${index}`}>{item}</li>
          ))}
        </ul>
        <button onClick={() => {
          if (authenticatedReplay) {
            notify(authenticatedReplay.verdict === 'VERIFIED'
              ? 'Verified replay still requires human scope, impact, and duplicate review before reporting.'
              : authenticatedReplay.verdict === 'INVALID'
                ? 'Submission gate closed — authorization held in the tested branch.'
                : 'No conclusion: create a new run after repairing both truthful controls.');
            return;
          }
          if (controlledProof) {
            notify('Submission gate closed — the tested draft hypothesis is INVALID.');
            return;
          }
          if (externalProgram) {
            notify('External Program mode does not generate duplicate leads. Validate manually before any report.');
            return;
          }
          if (selected?.duplicateSearch?.[0]) {
            onCopy(selected.duplicateSearch.join('\n'));
          } else {
            notify('Duplicate leads pending');
          }
        }}>{authenticatedReplay ? (authenticatedReplay.verdict === 'VERIFIED' ? 'Human review required' : authenticatedReplay.verdict === 'INVALID' ? 'Submission gate closed' : 'Controls must be repaired') : controlledProof ? 'Submission gate closed' : externalProgram ? 'Manual validation required' : selected?.duplicateSearch?.[0] ? 'Copy duplicate-search queries' : 'Duplicate queries pending'}</button>
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
            <span>{formatStatus(run.status)} · {run.target_type}</span>
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
          <h3><ShieldCheck size={18} /> Local Proof Lab · IDOR replay</h3>
          <p>IDOR is the first deterministic proof template—not the scanner's only capability. It executes a same-state control and attack against an ephemeral localhost fixture.</p>
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

function SecretPasteCapture({ label, detail, byteCount, onCapture, onClear, testId }) {
  return (
    <article className={`capture-zone ${byteCount ? 'captured' : ''}`}>
      <span>{label}</span>
      <strong>{byteCount ? 'Captured in volatile memory' : 'Paste from DevTools'}</strong>
      <textarea
        aria-label={label}
        data-testid={testId}
        className="command-editor secret-paste-zone"
        value=""
        onChange={() => {}}
        onPaste={(event) => {
          event.preventDefault();
          onCapture(event.clipboardData.getData('text'));
        }}
        placeholder={byteCount ? `${byteCount} bytes held locally · value hidden` : detail}
        spellCheck="false"
        autoComplete="off"
      />
      <em className={byteCount ? 'proof-ok' : ''}>
        {byteCount ? <><Check size={14} /> {byteCount} bytes · never rendered</> : <><Clipboard size={14} /> Focus here and paste</>}
      </em>
      {byteCount > 0 && <button className="mini-action" type="button" onClick={onClear}>Clear capture</button>}
    </article>
  );
}

function AuthenticatedReplayResult({ audit, onAnalyze, busyAction }) {
  const result = audit.authenticatedReplayResult;
  const attempts = result?.attempts || [];
  const ownerControl = attempts.find((attempt) => attempt.branch === 'owner_control');
  const peerControl = attempts.find((attempt) => attempt.branch === 'peer_control');
  const replayAttempts = attempts.filter((attempt) => attempt.branch.startsWith('cross_account_replay'));
  const verified = result?.verdict === 'VERIFIED';
  const invalid = result?.verdict === 'INVALID';
  const controlFailed = result?.classification === 'CONTROL_FAILED';
  const replayRan = replayAttempts.length > 0;
  const verdictLabel = verified
    ? 'VERIFIED REPLAY · HUMAN REVIEW REQUIRED'
    : invalid
      ? 'INVALID · AUTHORIZATION HELD'
      : `INCONCLUSIVE · ${String(result?.classification || 'UNKNOWN').replaceAll('_', ' ')}`;
  const resultSummary = verified || invalid
    ? 'Two isolated sessions completed their same-account controls and the bounded cross-account replay.'
    : controlFailed
      ? 'At least one same-account control failed, so the cross-account branch was not executed.'
      : replayRan
        ? 'Both same-account controls passed, but the cross-account replay was incomplete or inconsistent.'
        : 'The bounded replay stopped before a valid cross-account conclusion could be reached.';
  const attemptLine = (attempt) => attempt
    ? `${attempt.status ?? 'no status'} · ${attempt.outcome} · marker ${attempt.markerObserved ? 'observed' : 'absent'}`
    : 'not executed · stop condition reached';
  const controlLabel = (attempt, actor) => attempt?.markerObserved
    ? `${actor} session and marker passed`
    : attempt
      ? `${actor} control did not pass`
      : `${actor} control not executed`;

  return (
    <section
      className={`panel verified-proof authenticated-replay-result ${invalid ? 'proof-closed' : ''} ${verified ? 'confirmed' : ''}`}
      data-testid="replay-workbench"
    >
      <div className="panel-title proof-title">
        <div>
          <h3><ShieldCheck size={18} /> Authenticated replay · A versus B</h3>
          <p>{resultSummary} Only the sanitized write-once receipt remains.</p>
        </div>
        <span className="provider-chip"><Check size={14} /> {result.verdict}</span>
      </div>
      <div className="proof-empty">
        <strong>{result.reason}</strong>
        <span>GET only · DNS pinned · redirects blocked · fresh connection per attempt · raw captures and response bodies discarded</span>
      </div>
      <div className="proof-matrix replay-result-grid" data-testid="replay-matrix">
        <article>
          <span>Account A control</span>
          <strong>A → A's controlled {result.objectKind}</strong>
          <code>{attemptLine(ownerControl)}</code>
          <em className={ownerControl?.markerObserved ? 'proof-ok' : ''}>{ownerControl?.markerObserved ? <Check size={14} /> : <Bug size={14} />} {controlLabel(ownerControl, 'owner')}</em>
        </article>
        <article>
          <span>Account B control</span>
          <strong>B → B's controlled {result.objectKind}</strong>
          <code>{attemptLine(peerControl)}</code>
          <em className={peerControl?.markerObserved ? 'proof-ok' : ''}>{peerControl?.markerObserved ? <Check size={14} /> : <Bug size={14} />} {controlLabel(peerControl, 'peer')}</em>
        </article>
        <article className={verified ? 'proof-harm' : invalid ? 'proof-denied' : ''}>
          <span>Cross-account branch</span>
          <strong>B session → A's controlled object</strong>
          <code>{replayAttempts.length ? replayAttempts.map(attemptLine).join(' / ') : 'not executed because a truthful control failed'}</code>
          <em className={invalid ? 'proof-ok' : ''}>{verified ? <Bug size={14} /> : <ShieldCheck size={14} />} {verified ? 'owner-only marker exposed' : invalid ? 'owner-only marker withheld twice' : replayRan ? 'unstable replay · no valid conclusion' : 'not executed · no valid conclusion'}</em>
        </article>
      </div>
      <div className="proof-verdict" data-testid="replay-verdict">
        <span><ShieldCheck size={16} /> {verdictLabel}</span>
        <strong>{verified ? 'The deterministic branch crossed the authorization boundary, but scope, impact, and duplicates still require human review.' : result.reason}</strong>
        <code data-testid="replay-budget">{result.requestBudgetUsed} / {result.requestBudgetMax} requests</code>
      </div>
      <div className="proof-verdict replay-receipt">
        <span>IMMUTABLE RECEIPT</span>
        <strong data-testid="replay-receipt-hash">SHA-256 {audit.authenticatedReplayReceiptSha256 || 'unavailable'}</strong>
        {audit.aiAnalysis
          ? <code>AI {audit.aiAnalysis.analysis?.verdict} · session {audit.aiAnalysis.session_id || 'recorded'}</code>
          : <button className="mini-action" type="button" onClick={onAnalyze} disabled={Boolean(busyAction)}><Sparkles size={15} /> {busyAction === 'analyze' ? 'AI is reviewing…' : 'Review with AI'}</button>}
      </div>
    </section>
  );
}

function AuthenticatedReplayWorkbench({ audit, onComplete, onAnalyze, busyAction, notify }) {
  const rawSecrets = useRef({ ownerCurl: '', peerCurl: '', ownerMarker: '', peerMarker: '' });
  const [captureBytes, setCaptureBytes] = useState({ ownerCurl: 0, peerCurl: 0, ownerMarker: 0, peerMarker: 0 });
  const [preview, setPreview] = useState(null);
  const [objectKind, setObjectKind] = useState('controlled object');
  const [sessionsIsolated, setSessionsIsolated] = useState(false);
  const [controlledObjects, setControlledObjects] = useState(false);
  const [noThirdPartyData, setNoThirdPartyData] = useState(false);
  const [working, setWorking] = useState('');
  const [error, setError] = useState('');

  useEffect(() => () => {
    rawSecrets.current = { ownerCurl: '', peerCurl: '', ownerMarker: '', peerMarker: '' };
  }, []);

  function bytes(value) {
    return new TextEncoder().encode(value).length;
  }

  function capture(field, rawValue) {
    const value = String(rawValue || '');
    if (!value.trim()) {
      setError('The pasted value was empty. Copy it again and paste into the matching secure zone.');
      return;
    }
    rawSecrets.current[field] = value;
    setCaptureBytes((current) => ({ ...current, [field]: bytes(value) }));
    if (field === 'ownerCurl' || field === 'peerCurl') setPreview(null);
    setError('');
  }

  function clear(field) {
    rawSecrets.current[field] = '';
    setCaptureBytes((current) => ({ ...current, [field]: 0 }));
    if (field === 'ownerCurl' || field === 'peerCurl') setPreview(null);
  }

  function clearAllSecrets() {
    rawSecrets.current = { ownerCurl: '', peerCurl: '', ownerMarker: '', peerMarker: '' };
    setCaptureBytes({ ownerCurl: 0, peerCurl: 0, ownerMarker: 0, peerMarker: 0 });
  }

  async function previewReplay() {
    if (!captureBytes.ownerCurl || !captureBytes.peerCurl) {
      setError('Paste both authenticated cURL captures before previewing redaction.');
      return;
    }
    setWorking('preview');
    setError('');
    try {
      const data = await api(`/api/audits/${audit.id}/authenticated-replay/preview`, {
        method: 'POST',
        headers: { 'X-ControlX-Intent': 'authenticated-replay-v1' },
        body: JSON.stringify({ owner_curl: rawSecrets.current.ownerCurl, peer_curl: rawSecrets.current.peerCurl })
      });
      setPreview(data.preview);
      notify('Redaction preview passed — no target requests sent');
    } catch (previewError) {
      setPreview(null);
      setError(previewError.message);
      notify(previewError.message);
    } finally {
      setWorking('');
    }
  }

  const readyToExecute = Boolean(
    preview
    && captureBytes.ownerCurl
    && captureBytes.peerCurl
    && captureBytes.ownerMarker
    && captureBytes.peerMarker
    && objectKind.trim()
    && sessionsIsolated
    && controlledObjects
    && noThirdPartyData
  );

  async function executeReplay() {
    if (!readyToExecute) {
      setError('Complete the redaction preview, paste both benign markers, and confirm every control.');
      return;
    }
    setWorking('execute');
    setError('');
    try {
      const data = await api(`/api/audits/${audit.id}/authenticated-replay/execute`, {
        method: 'POST',
        headers: { 'X-ControlX-Intent': 'authenticated-replay-v1' },
        body: JSON.stringify({
          owner_curl: rawSecrets.current.ownerCurl,
          peer_curl: rawSecrets.current.peerCurl,
          object_kind: objectKind.trim(),
          owner_marker: rawSecrets.current.ownerMarker,
          peer_marker: rawSecrets.current.peerMarker,
          preview_sha256: preview.captureSha256,
          sessions_isolated: true,
          controlled_objects_acknowledged: true,
          third_party_data_expected: false
        })
      });
      clearAllSecrets();
      setPreview(null);
      await onComplete(data);
      notify(`Authenticated replay: ${data.authenticated_replay_result?.verdict || 'receipt saved'}`);
    } catch (executeError) {
      clearAllSecrets();
      setPreview(null);
      setError(`${executeError.message} Raw captures and markers were cleared; paste fresh values before retrying.`);
      notify(executeError.message);
    } finally {
      setWorking('');
    }
  }

  return (
    <section className="panel verified-proof authenticated-replay" data-testid="replay-workbench">
      <div className="panel-title proof-title">
        <div>
          <h3><ShieldCheck size={18} /> Authenticated replay · A versus B</h3>
          <p>Paste two DevTools “Copy as cURL” requests for equivalent objects owned by isolated accounts you control. ControlX validates and redacts before sending anything.</p>
        </div>
        <span className="provider-chip"><ShieldCheck size={14} /> local secrets · ephemeral</span>
      </div>
      <div className="proof-empty">
        <strong>Nothing pasted below is rendered, logged, or written to SQLite. Replace a capture by pasting again.</strong>
        <span>Preview parses only · execution is GET-only · exact allowlisted origin · four-request maximum · redirects blocked</span>
      </div>
      <div className="proof-matrix capture-grid">
        <SecretPasteCapture
          label="Account A · owner control"
          detail="Paste A's authenticated cURL for A's controlled object"
          byteCount={captureBytes.ownerCurl}
          onCapture={(value) => capture('ownerCurl', value)}
          onClear={() => clear('ownerCurl')}
          testId="curl-account-a"
        />
        <SecretPasteCapture
          label="Account B · peer control"
          detail="Paste B's authenticated cURL for B's equivalent controlled object"
          byteCount={captureBytes.peerCurl}
          onCapture={(value) => capture('peerCurl', value)}
          onClear={() => clear('peerCurl')}
          testId="curl-account-b"
        />
      </div>
      <div className="proof-verdict replay-preview-action">
        <span>STEP 1 · CAPTURE</span>
        <strong>The two URLs must share one endpoint shape and differ by exactly one controlled object locator.</strong>
        <button data-testid="preview-redaction" className="mini-action" type="button" onClick={previewReplay} disabled={working === 'preview' || !captureBytes.ownerCurl || !captureBytes.peerCurl}>
          <ShieldCheck size={15} /> {working === 'preview' ? 'Validating…' : 'Preview redaction'}
        </button>
      </div>
      {preview && (
        <div className="redaction-preview" data-testid="redaction-preview">
          <div className="proof-empty">
            <strong>{preview.method} {preview.origin} · {preview.endpointShape.locatorKind.replaceAll('_', ' ')} mutation</strong>
            <span>Path depth {preview.endpointShape.pathDepth} · query names {preview.endpointShape.queryNames.join(', ') || 'none'} · redirects {preview.redirectPolicy}</span>
          </div>
          <div className="proof-matrix">
            <article>
              <span>Account A sanitized</span>
              <strong>Session headers: {preview.credentialHeaderNames.join(', ')}</strong>
              <code>fingerprint {preview.ownerSessionFingerprint}…</code>
              <em className="proof-ok"><Check size={14} /> values redacted</em>
            </article>
            <article>
              <span>Account B sanitized</span>
              <strong>Distinct session confirmed</strong>
              <code>fingerprint {preview.peerSessionFingerprint}…</code>
              <em className="proof-ok"><Check size={14} /> values redacted</em>
            </article>
          </div>
          <div className="proof-verdict">
            <span>STEP 2 · REDACTED</span>
            <strong>{preview.persistence}</strong>
            <code data-testid="replay-budget">0 / {preview.requestBudgetMax} requests</code>
          </div>
        </div>
      )}
      <div className="replay-controls">
        <label>
          <span>Object kind · non-secret label</span>
          <input value={objectKind} onChange={(event) => setObjectKind(event.target.value)} maxLength={80} autoComplete="off" />
        </label>
        <div className="proof-matrix marker-grid">
          <SecretPasteCapture
            label="Account A · benign response marker"
            detail="Paste the unique marker visible only in A's controlled object"
            byteCount={captureBytes.ownerMarker}
            onCapture={(value) => capture('ownerMarker', value)}
            onClear={() => clear('ownerMarker')}
            testId="marker-account-a"
          />
          <SecretPasteCapture
            label="Account B · benign response marker"
            detail="Paste the unique marker visible only in B's controlled object"
            byteCount={captureBytes.peerMarker}
            onCapture={(value) => capture('peerMarker', value)}
            onClear={() => clear('peerMarker')}
            testId="marker-account-b"
          />
        </div>
        <div className="replay-acknowledgements">
          <label className="auth-check"><input type="checkbox" checked={sessionsIsolated} onChange={(event) => setSessionsIsolated(event.target.checked)} /> A and B are isolated live sessions.</label>
          <label className="auth-check"><input type="checkbox" checked={controlledObjects} onChange={(event) => setControlledObjects(event.target.checked)} /> Both objects and both accounts are controlled by me.</label>
          <label className="auth-check"><input type="checkbox" checked={noThirdPartyData} onChange={(event) => setNoThirdPartyData(event.target.checked)} /> No third-party data is expected; stop on unexpected exposure.</label>
        </div>
      </div>
      {error && <p className="error-line replay-error">{error}</p>}
      <div className="proof-verdict replay-run-action">
        <span>STEP 3 · REPLAY</span>
        <strong>A→A and B→B must pass before B→A. A denial is repeated once; a positive marker stops immediately.</strong>
        <button data-testid="run-bounded-replay" className="mini-action" type="button" onClick={executeReplay} disabled={!readyToExecute || Boolean(working)}>
          <Zap size={15} /> {working === 'execute' ? 'Running bounded replay…' : 'Run bounded replay'}
        </button>
      </div>
    </section>
  );
}

function ControlledExternalProofPlan({ audit, onReplayComplete, onAnalyze, busyAction, notify }) {
  const result = audit?.controlledProofResult;

  if (audit?.authenticatedReplayResult) {
    return <AuthenticatedReplayResult audit={audit} onAnalyze={onAnalyze} busyAction={busyAction} />;
  }

  if (result) {
    const owner = result.actors?.owner || 'Account A';
    const peer = result.actors?.peer || 'Account B';
    const attempts = result.authorizationBranch?.attempts || 0;
    return (
      <section className="panel verified-proof controlled-proof proof-closed">
        <div className="panel-title proof-title">
          <div>
            <h3><ShieldCheck size={18} /> Controlled external proof · A versus B</h3>
            <p>One owner control and two isolated known-object replays were recorded as a redacted, API write-once receipt. No raw object ID, response body, credentials, cookies, or tokens were stored.</p>
          </div>
          <span className="provider-chip"><Check size={14} /> hypothesis closed</span>
        </div>
        <div className="proof-empty">
          <strong>{result.reason}</strong>
          <span>Classification is limited to this tested submission draft; it does not claim the entire application is IDOR-free.</span>
        </div>
        <div className="proof-matrix">
          <article>
            <span>Truthful control</span>
            <strong>Account A ({owner}) → own marked draft</strong>
            <code>SUCCEEDED · owner marker observed</code>
            <em className="proof-ok"><Check size={14} /> ownership path works</em>
          </article>
          <article className="proof-denied">
            <span>Authorization branch</span>
            <strong>Account B ({peer}) → A's known draft</strong>
            <code>DENIED · {attempts} of {attempts} isolated replays</code>
            <em className="proof-ok"><ShieldCheck size={14} /> authorization held</em>
          </article>
        </div>
        <div className="proof-verdict">
          <span><ShieldCheck size={16} /> INVALID · NO IDOR</span>
          <strong>No IDOR observed in the tested draft flow. Owner access succeeded; Account B was denied on both controlled replays. Hypothesis closed.</strong>
          <code>submission gate closed</code>
        </div>
      </section>
    );
  }

  return <AuthenticatedReplayWorkbench audit={audit} onComplete={onReplayComplete} onAnalyze={onAnalyze} busyAction={busyAction} notify={notify} />;
}

function ScopePanel({ target, setTarget, scopeRules, setScopeRules, authorized, setAuthorized, audit }) {
  const externalProgram = audit?.mode === 'external_program';
  const boundedExternal = externalProgram && audit?.policyReceipt?.profileId === 'intigriti-pwn';
  const authenticatedReplay = audit?.authenticatedReplayResult;
  const controlledProof = Boolean(authenticatedReplay) || (externalProgram && isAuthenticatedReplayProfile(audit?.policyReceipt?.profileId));
  return (
    <section className="panel scope-panel">
      <div className="panel-title">
        <h3><Globe2 size={18} /> Scope</h3>
      </div>
      <div className="scope-grid">
        <label>
          <span>HTTP(S) target URL</span>
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
          {externalProgram && <span>{controlledProof ? 'Controlled proof policy' : boundedExternal ? 'Live program policy' : 'External passive policy'}: {audit.policyReceipt?.programName || 'recorded'}</span>}
          {externalProgram && <span>Exact URL: {audit.policyReceipt?.exactScopeUrl || audit.target?.url}</span>}
          {controlledProof && <span>Explicit hosts: {(audit.policyReceipt?.allowedHosts || []).join(', ')}</span>}
          {externalProgram && <span>Boundary: {controlledProof ? (authenticatedReplay ? `authenticated GET replay / ${authenticatedReplay.requestBudgetUsed} of ${authenticatedReplay.requestBudgetMax} requests / raw secrets discarded` : 'ephemeral A↔B capture / two truthful controls / four-request maximum') : boundedExternal ? `${audit.policyReceipt.requestBudget} GET/HEAD requests / ≤${audit.policyReceipt.requestRatePerSecond} per second / attributed` : 'one GET / ≤1 HTTP request per second / no follow-ups'}</span>}
          {authenticatedReplay && <span>Replay receipt: {audit.authenticatedReplayReceiptSha256 || 'not recorded'}</span>}
          <span>Run: {audit?.run_id || 'none'}</span>
          <span>Raw: {audit?.rawDir || 'not created'}</span>
          <span>Report: {audit?.report?.path || 'not generated'}</span>
        </div>
      </div>
    </section>
  );
}

function SettingsPanel({ providerStatus, onRefreshProvider, providerChecking }) {
  return (
    <section className="panel settings-panel">
      <div className="panel-title">
        <h3><Settings size={18} /> Settings</h3>
      </div>
      <div className="settings-grid">
        <article>
          <span className={`status-dot ${providerStatus?.ready ? 'ready' : 'offline'}`} />
          <div>
            <strong>AI provider</strong>
            <p>{providerStatus?.model || 'Not configured'}</p>
            <small>{providerStatus?.detail || 'Status has not been checked yet.'}</small>
          </div>
          <button className="mini-action" onClick={onRefreshProvider} disabled={providerChecking}>
            {providerChecking ? 'Checking…' : 'Refresh status'}
          </button>
        </article>
        <article>
          <ShieldCheck size={19} />
          <div>
            <strong>Execution boundary</strong>
            <p>Model tools denied · evidence redacted · deterministic verification required</p>
            <small>Live-target profiles enforce their own host allowlist, required identity headers, rate ceiling, request budget, and prohibited actions.</small>
          </div>
        </article>
      </div>
    </section>
  );
}

function ExploitMap({ audit, findings, onCopy }) {
  const routes = audit?.evidence?.routes || [];
  const externalProgram = audit?.mode === 'external_program';
  const boundedExternal = externalProgram && audit?.policyReceipt?.profileId === 'intigriti-pwn';
  const authenticatedReplay = audit?.authenticatedReplayResult;
  const controlledProof = Boolean(authenticatedReplay) || (externalProgram && isAuthenticatedReplayProfile(audit?.policyReceipt?.profileId));
  const controlledRoutes = authenticatedReplay ? authenticatedReplay.attempts.map((attempt) => ({
    route: attempt.branch.replaceAll('_', ' ').toUpperCase(),
    status: attempt.status ?? attempt.outcome,
    url: `${attempt.outcome} · marker ${attempt.markerObserved ? 'observed' : 'absent'} · ${attempt.elapsedMs} ms`
  })) : audit?.controlledProofResult ? [
    { route: 'CONTROL', status: 'succeeded', url: 'Account A owner marker observed' },
    { route: 'REPLAY 1', status: 'forbidden', url: 'Account B denied; owner marker absent' },
    { route: 'REPLAY 2', status: 'forbidden', url: 'Account B denied; owner marker absent' }
  ] : [];
  return (
    <section className="panel map-panel">
      <div className="panel-title">
        <h3><TerminalSquare size={18} /> {controlledProof ? 'Controlled Proof Ledger' : boundedExternal ? 'Live Request Ledger' : externalProgram ? 'Passive Request Ledger' : 'Surface Map'}</h3>
        <button className="mini-action" onClick={() => onCopy(JSON.stringify(controlledProof ? authenticatedReplay || audit?.controlledProofResult || {} : externalProgram ? audit?.evidence?.requestLog || [] : routes, null, 2))}>Copy {externalProgram ? 'ledger' : 'routes'}</button>
      </div>
      <div className="map-grid">
        <article>
          <strong>Target</strong>
          <span>{audit?.target?.url || 'No live audit yet'}</span>
        </article>
        <article>
          <strong>{controlledProof ? 'Proof branches' : externalProgram ? 'HTTP budget' : 'Routes'}</strong>
          <span>{controlledProof ? (authenticatedReplay ? `2 truthful controls · ${authenticatedReplay.requestBudgetUsed - 2} cross-account replay${authenticatedReplay.requestBudgetUsed - 2 === 1 ? '' : 's'}` : '1 owner control · 2 isolated replays') : externalProgram ? `${audit?.evidence?.requestLog?.length || 0} of ${audit?.policyReceipt?.requestBudget || 1} request` : `${routes.length} safe probes`}</span>
        </article>
        <article>
          <strong>{externalProgram ? 'Output' : 'Findings'}</strong>
          <span>{controlledProof ? (authenticatedReplay ? `${authenticatedReplay.verdict} · ${authenticatedReplay.classification} · human review required` : 'INVALID · NO IDOR · submission gate closed') : externalProgram ? (boundedExternal ? `${audit?.evidence?.clientEndpoints?.length || 0} endpoint leads · no vulnerability asserted` : 'observations only') : `${findings.length} candidates`}</span>
        </article>
      </div>
      <div className="route-list">
        {(controlledProof
          ? controlledRoutes
          : externalProgram
          ? (audit?.evidence?.requestLog?.length ? audit.evidence.requestLog.map((request) => ({ route: request.method, status: request.status, url: request.url })) : [{ route: 'GET', status: 'waiting', url: boundedExternal ? 'Run the bounded mapper to create an attributed request ledger' : 'Run the passive check to record the one allowed URL' }])
          : (routes.length ? routes : [{ route: '/', status: 'waiting', url: 'Run an audit to map routes' }])
        ).map((route, index) => (
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
  const externalProgram = audit?.mode === 'external_program';
  const boundedExternal = externalProgram && audit?.policyReceipt?.profileId === 'intigriti-pwn';
  const controlledProof = Boolean(audit?.authenticatedReplayResult) || (externalProgram && isAuthenticatedReplayProfile(audit?.policyReceipt?.profileId));
  const markdown = audit?.report?.markdown || (controlledProof ? '# Authenticated replay ledger not ready\n\nCapture two controlled sessions in Proof Lab, preview redaction, run the bounded replay, then let an optional AI reviewer challenge the saved receipt.' : externalProgram ? `# Observation ledger not ready\n\nCollect the ${boundedExternal ? 'bounded live map' : 'passive receipt'}, run AI review, then generate the ledger.` : '# Report not ready\n\nCollect evidence, run AI review, then generate the report.');
  return (
    <section className="panel report-panel">
      <div className="panel-title">
        <h3><FileText size={18} /> {externalProgram ? 'Observation Ledger' : 'Report Draft'}</h3>
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
  const [activeNav, setActiveNav] = useState('Hunts');
  const [notice, setNotice] = useState('');
  const [search, setSearch] = useState('');
  const [timelineExpanded, setTimelineExpanded] = useState(false);
  const [auditMode, setAuditMode] = useState('local_lab');
  const [localWorkflow, setLocalWorkflow] = useState('bounded-audit');
  const [target, setTarget] = useState('http://127.0.0.1:5173/');
  const [scopeRules, setScopeRules] = useState('Local authorized test target.');
  const [authorized, setAuthorized] = useState(true);
  const [programProfile, setProgramProfile] = useState(externalProgramDefaults);
  const [audit, setAudit] = useState(null);
  const [runs, setRuns] = useState([]);
  const [error, setError] = useState('');
  const [busyAction, setBusyAction] = useState('');
  const [providerStatus, setProviderStatus] = useState(null);
  const [providerChecking, setProviderChecking] = useState(false);
  const [idorProof, setIdorProof] = useState(null);
  const [proofRunning, setProofRunning] = useState(false);
  const tabs = ['Triage', 'Surface Map'];
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

  function chooseAuditMode(nextMode) {
    if (nextMode === auditMode) return;
    setAuditMode(nextMode);
    setAudit(null);
    setError('');
    if (nextMode === 'external_program') {
      setAuthorized(false);
      setTarget(INTIGRITI_PWN_TARGET);
      setScopeRules(INTIGRITI_PWN_SCOPE);
      setProgramProfile((current) => ({
        ...externalProgramDefaults,
        researcherUsername: current.researcherUsername || ''
      }));
    } else {
      setLocalWorkflow('bounded-audit');
      setAuthorized(true);
      setTarget('http://127.0.0.1:5173/');
      setScopeRules('Local authorized test target.');
    }
  }

  function applyProgramPreset(profileId) {
    setAudit(null);
    setError('');
    setAuthorized(false);
    if (profileId === 'intigriti-pwn') {
      setTarget(INTIGRITI_PWN_TARGET);
      setScopeRules(INTIGRITI_PWN_SCOPE);
      setProgramProfile((current) => ({
        ...externalProgramDefaults,
        researcherUsername: current.researcherUsername || ''
      }));
      return;
    }
    if (profileId === INTIGRITI_PWN_PROOF_PROFILE_ID) {
      setTarget(INTIGRITI_PWN_TARGET);
      setScopeRules(INTIGRITI_PWN_PROOF_SCOPE);
      setProgramProfile((current) => ({
        ...externalProgramDefaults,
        profileId: INTIGRITI_PWN_PROOF_PROFILE_ID,
        researcherUsername: current.researcherUsername || 'sftwr',
        allowedHosts: INTIGRITI_PWN_PROOF_HOSTS,
        proofHypothesis: INTIGRITI_PWN_PROOF_HYPOTHESIS,
        controlledAccountsAcknowledged: false,
        minimumProofAcknowledged: false
      }));
      return;
    }
    if (profileId === AUTHENTICATED_REPLAY_PROFILE_ID) {
      setTarget('');
      setScopeRules(AUTHENTICATED_REPLAY_SCOPE);
      setProgramProfile({
        profileId: AUTHENTICATED_REPLAY_PROFILE_ID,
        platform: 'HackerOne',
        researcherUsername: '',
        programName: '',
        policyUrl: '',
        allowedHosts: [],
        proofHypothesis: '',
        controlledAccountsAcknowledged: false,
        minimumProofAcknowledged: false,
        automationAcknowledged: false,
        humanReviewAcknowledged: false
      });
      return;
    }
    setTarget('');
    setScopeRules('');
    setProgramProfile({
      profileId: 'custom-passive',
      platform: 'HackerOne',
      researcherUsername: '',
      programName: '',
      policyUrl: '',
      automationAcknowledged: false,
      humanReviewAcknowledged: false
    });
  }

  async function refreshRuns(silent = false) {
    try {
      const data = await api('/api/audits');
      setRuns(data.audits || []);
      if (!silent) notify(`${data.audits?.length || 0} runs loaded`);
    } catch (loadError) {
      notify(loadError.message);
    }
  }

  async function refreshProviderStatus(silent = false) {
    setProviderChecking(true);
    try {
      const data = await api('/api/ai/status');
      setProviderStatus(data);
      if (!silent) notify(data.ready ? `${data.model} is ready` : data.detail);
    } catch (statusError) {
      setProviderStatus({ ready: false, model: 'Unavailable', detail: statusError.message });
      if (!silent) notify(statusError.message);
    } finally {
      setProviderChecking(false);
    }
  }

  async function loadRun(runId) {
    try {
      const data = await api(`/api/audits/${runId}`);
      const loaded = normalizeAuditResponse(data);
      setAudit(loaded);
      setAuditMode(loaded.mode);
      setLocalWorkflow(loaded.mode === 'local_lab' && loaded.status === 'created' && !loaded.evidenceCollected ? 'authenticated-replay' : 'bounded-audit');
      setTarget(loaded.target.url);
      setScopeRules(loaded.scopeRules);
      setAuthorized(true);
      if (loaded.mode === 'external_program') {
        setProgramProfile({
          profileId: loaded.policyReceipt.profileId || 'custom-passive',
          platform: loaded.policyReceipt.platform || 'HackerOne',
          researcherUsername: loaded.policyReceipt.researcherUsername || '',
          programName: loaded.policyReceipt.programName || '',
          policyUrl: loaded.policyReceipt.policyUrl || '',
          allowedHosts: loaded.policyReceipt.allowedHosts || [],
          proofHypothesis: loaded.policyReceipt.proofHypothesis || '',
          controlledAccountsAcknowledged: Boolean(loaded.policyReceipt.controlledAccountsAcknowledged),
          minimumProofAcknowledged: Boolean(loaded.policyReceipt.minimumProofAcknowledged),
          automationAcknowledged: Boolean(loaded.policyReceipt.automationAcknowledged),
          humanReviewAcknowledged: Boolean(loaded.policyReceipt.humanReviewAcknowledged)
        });
      }
      setTab('Triage');
      setActiveNav('Hunts');
      notify('Run loaded from SQLite');
    } catch (loadError) {
      notify(loadError.message);
    }
  }

  useEffect(() => {
    refreshRuns(true);
    refreshProviderStatus(true);
  }, []);

  async function collectEvidence() {
    setError('');
    setSelectedFinding(0);
    setActiveNav('Hunts');
    setBusyAction('collect');
    try {
      const created = await api('/api/audits/create', {
        method: 'POST',
        body: JSON.stringify({
          target,
          scope_notes: scopeRules,
          authorized,
          mode: auditMode,
          program_profile: auditMode === 'external_program' ? {
            profile_id: programProfile.profileId,
            platform: programProfile.platform,
            researcher_username: programProfile.researcherUsername,
            program_name: programProfile.programName,
            policy_url: programProfile.policyUrl,
            allowed_hosts: programProfile.allowedHosts || [],
            proof_hypothesis: programProfile.proofHypothesis || '',
            controlled_accounts_acknowledged: Boolean(programProfile.controlledAccountsAcknowledged),
            minimum_proof_acknowledged: Boolean(programProfile.minimumProofAcknowledged),
            automation_acknowledged: programProfile.automationAcknowledged,
            human_review_acknowledged: programProfile.humanReviewAcknowledged
          } : null
        })
      });
      setAudit(normalizeAuditResponse(created));
      notify('AuditRun created in SQLite');

      if (
        (auditMode === 'external_program' && isAuthenticatedReplayProfile(programProfile.profileId))
        || (auditMode === 'local_lab' && localWorkflow === 'authenticated-replay')
      ) {
        await refreshRuns(true);
        setActiveNav('Proof Lab');
        notify('Authenticated replay scope saved — zero target requests sent');
        return;
      }

      const scanned = await api(`/api/audits/${created.audit.run_id}/run-web-audit`, { method: 'POST' });
      setAudit(normalizeAuditResponse(scanned));
      await refreshRuns(true);
      notify(auditMode === 'external_program' ? (programProfile.profileId === 'intigriti-pwn' ? 'Live surface map saved — ready for AI review' : 'Passive receipt saved — ready for AI review') : 'Bounded evidence saved — ready for AI review');
    } catch (runError) {
      setError(runError.message);
      notify(runError.message);
    } finally {
      setBusyAction('');
    }
  }

  async function analyzeCurrentAudit() {
    if (!audit?.id) {
      notify('Collect or load a run first');
      return;
    }
    setBusyAction('analyze');
    setError('');
    try {
      const analyzed = await api(`/api/audits/${audit.id}/analyze`, { method: 'POST' });
      setAudit(normalizeAuditResponse(analyzed));
      await refreshRuns(true);
      notify(`AI verdict: ${analyzed.ai_analysis?.analysis?.verdict || 'analysis complete'}`);
    } catch (analysisError) {
      setError(analysisError.message);
      notify(analysisError.message);
    } finally {
      setBusyAction('');
    }
  }

  async function generateAuditReport() {
    if (!audit?.id) {
      notify('Collect or load a run first');
      return;
    }
    setBusyAction('report');
    setError('');
    try {
      const reported = await api(`/api/audits/${audit.id}/generate-report`, { method: 'POST' });
      setAudit(normalizeAuditResponse(reported));
      setActiveNav('Reports');
      await refreshRuns(true);
      notify(audit.mode === 'external_program' ? 'Observation ledger generated' : 'Evidence report generated');
    } catch (reportError) {
      setError(reportError.message);
      notify(reportError.message);
    } finally {
      setBusyAction('');
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

  async function completeAuthenticatedReplay(data) {
    const normalized = normalizeAuditResponse(data);
    setAudit(normalized);
    setSelectedFinding(0);
    await refreshRuns(true);
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
    setBusyAction('');
    setSearch('');
    setTab('Triage');
    setActiveNav('Hunts');
    notify('New hunt ready');
  }

  const showEvidence = ['Findings', 'Reports'].includes(activeNav);

  return (
    <div className="app-shell">
      <Sidebar activeNav={activeNav} setActiveNav={setActiveNav} setTab={setTab} />
      <main className="main">
        <Topbar search={search} setSearch={setSearch} onNewHunt={newHunt} />
        <div className={`workspace ${showEvidence ? '' : 'single-column'}`}>
          <section className="console">
            <div className="title-row">
              <div>
                <p className="eyebrow"><span />Authorized research workspace</p>
                <h1>{activeNav === 'Proof Lab' ? 'Proof Lab' : activeNav}</h1>
                <p className="title-subtitle">Find the delta. Prove the impact. Bounded replay, control paths, and evidence receipts for authorized research.</p>
                {activeNav === 'Findings' && <div className="tabs">
                  {tabs.map((name) => (
                    <button className={tab === name ? 'active' : ''} onClick={() => setTab(name)} key={name}>
                      {name}
                    </button>
                  ))}
                </div>}
              </div>
              {(notice || busyAction || audit) && <span className="toast"><Zap size={15} /> {notice || (busyAction ? `${busyAction} running` : formatStatus(audit.status))}</span>}
            </div>
            {activeNav === 'Hunts' && (
              <>
                <Composer
                  auditMode={auditMode}
                  setAuditMode={chooseAuditMode}
                  localWorkflow={localWorkflow}
                  setLocalWorkflow={setLocalWorkflow}
                  target={target}
                  setTarget={setTarget}
                  scopeRules={scopeRules}
                  setScopeRules={setScopeRules}
                  authorized={authorized}
                  setAuthorized={setAuthorized}
                  programProfile={programProfile}
                  setProgramProfile={setProgramProfile}
                  onApplyProgramPreset={applyProgramPreset}
                  audit={audit}
                  onCollect={collectEvidence}
                  onAnalyze={analyzeCurrentAudit}
                  onGenerateReport={generateAuditReport}
                  busyAction={busyAction}
                  error={error}
                />
                <AgentSwarm audit={audit} requestedMode={auditMode} requestedProfile={programProfile} />
                <AuditRunsPanel runs={runs} onLoadRun={loadRun} onRefreshRuns={() => refreshRuns(false)} />
              </>
            )}
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
            {activeNav === 'Proof Lab' && (
              (Boolean(audit?.authenticatedReplayResult)
                || isAuthenticatedReplayProfile(audit?.policyReceipt?.profileId)
                || (audit?.mode === 'local_lab' && audit?.status === 'created' && !audit?.evidenceCollected))
                ? <ControlledExternalProofPlan
                    audit={audit}
                    onReplayComplete={completeAuthenticatedReplay}
                    onAnalyze={analyzeCurrentAudit}
                    busyAction={busyAction}
                    notify={notify}
                  />
                : <VerifiedIdorProof proof={idorProof} running={proofRunning} onRun={runIdorProof} />
            )}
            {activeNav === 'Settings' && (
              <SettingsPanel
                providerStatus={providerStatus}
                onRefreshProvider={() => refreshProviderStatus(false)}
                providerChecking={providerChecking}
              />
            )}
            {activeNav === 'Findings' && tab === 'Triage' && (
              <>
                <FindingsTable findings={liveFindings} selected={selectedFinding} setSelected={setSelectedFinding} onViewAll={() => { setSearch(''); notify(`${rawFindings.length} findings visible`); }} />
                <div className="lower-grid">
                  <CodeExcerpt finding={liveFindings[selectedFinding]} onCopy={copyText} externalProgram={(audit?.mode || auditMode) === 'external_program'} />
                  <Timeline audit={audit} expanded={timelineExpanded} setExpanded={setTimelineExpanded} />
                </div>
              </>
            )}
            {activeNav === 'Findings' && tab === 'Surface Map' && <ExploitMap audit={audit} findings={liveFindings} onCopy={copyText} />}
            {activeNav === 'Reports' && <ReportDraft audit={audit} onCopy={copyText} onReport={openReport} />}
          </section>
          {showEvidence && <EvidencePanel finding={liveFindings[selectedFinding]} audit={audit} requestedMode={auditMode} onReport={openReport} onCopy={copyText} notify={notify} />}
        </div>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
