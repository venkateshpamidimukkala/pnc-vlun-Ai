import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable, defer, filter, race, shareReplay, switchMap, take, tap, timeout, timer, throwError } from 'rxjs';

export interface Vulnerability { id: string; tenant_id: string; mnemonic: string; application: string; repository: string; title: string; category: string; severity: string; status: string; cve?: string; cwe?: string; cvss?: number; ai_confidence?: string; created_at?: string; file_name?: string; line_number?: number; description?: string; risk_score?: number; vulnerable_code?: string; recommended_fix?: string; }
export interface MvpScan { scan_id: string; application: { id: string; name: string; repo_path: string; total_vulnerabilities: number; critical_issues: number }; findings: Vulnerability[]; scanner: string; status: string; }
interface BackgroundJob { job_id: string; scan_id?: string; status: string; result?: MvpScan; error?: string; }
interface WorkflowJob { job_id: string; status: string; result?: EngineWorkflow; error?: string; queued_at?: string; started_at?: string; completed_at?: string; timeline?: { duration_ms?: number }; }
export interface MvpFix { id: string; finding_id: string; original_code: string; fixed_code: string; explanation: string; status: string; }
export interface DashboardMetrics { total: number; critical: number; high: number; medium: number; low: number; open: number; remediated: number; risk_reduction_percent: number; ai_success_rate_percent: number; applications_scanned?: number; remediations_generated?: number; jira_tickets_created?: number; pull_requests_generated?: number; branches_created?: number; security_score?: number; }
export interface MvpApplication { id: string; name: string; repo_path: string; technology_stack: string[]; total_vulnerabilities: number; critical_issues: number; last_scan_date: string; }
export interface ApplicationInventoryRepository { name: string; total_findings: number; critical_findings: number; }
export interface ApplicationInventoryApplication { name: string; repo_path: string; total_findings: number; critical_findings: number; repositories: ApplicationInventoryRepository[]; }
export interface ApplicationInventoryGroup { mnemonic: string; total_findings: number; critical_findings: number; applications: ApplicationInventoryApplication[]; }
export interface MvpRemediation { id: string; finding_id: string; original_code: string; fixed_code: string; explanation: string; cwe?: string; confidence: string; status: string; created_at: string; }
export interface MvpRecord { id: string; ticket_number?: string; pr_number?: string; branch_name?: string; summary?: string; title?: string; vulnerability_pattern?: string; description?: string; cwe?: string; status: string; application?: string; repository?: string; files_changed?: string[]; created_date?: string; }
export interface RemediationResponse { workflow_id: string; status: string; matched_vulnerabilities: number; branch_pattern: string; confidence: string; next_step: string; }
export interface ApprovalItem { id: string; mnemonic: string; application: string; repository: string; title: string; level: string; status: string; due_at: string; }
export interface CopilotResponse { answer: string; evidence: string[]; confidence: string; }
export interface ApprovalDecisionResponse extends ApprovalItem { }
export interface EngineWorkflow { workflow_id: string; tenant_id: string; requested_by: string; project: string; repository_path: string; status: string; created_at: string; finding_ids: string[]; evidence: Record<string, unknown>; }
export interface WorkflowEvidence { status?: string; [key: string]: unknown; }

// Background jobs are already asynchronous; polling at 20 requests/second
// creates unnecessary API and browser load without making scans complete faster.
const JOB_POLL_INTERVAL_MS = 500;

@Injectable({providedIn:'root'})
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1';
  private readonly vulnerabilityCache = new Map<string, Observable<Vulnerability[]>>();
  private inventoryCache?: Observable<ApplicationInventoryGroup[]>;
  private applicationsCache?: Observable<MvpApplication[]>;
  private readonly cacheTtlMs = 60_000;
  private workflowsCache?: Observable<EngineWorkflow[]>;
  private integrationsCache?: Observable<{ provider: string; enabled: boolean; reason: string }[]>;
  vulnerabilities(filters: Record<string, string> = {}): Observable<Vulnerability[]> { const key = JSON.stringify(Object.keys(filters).sort().map(name => [name, filters[name]])); const cached = this.vulnerabilityCache.get(key); if (cached) return cached; let params = new HttpParams(); Object.entries(filters).forEach(([key,value]) => params = params.set(key,value)); const request = this.http.get<Vulnerability[]>(`${this.baseUrl}/vulnerabilities`, {params}).pipe(shareReplay({bufferSize: 1, refCount: false})); this.vulnerabilityCache.set(key, request); return request; }
  metrics(): Observable<DashboardMetrics> { return this.http.get<DashboardMetrics>(`${this.baseUrl}/dashboard/metrics`); }
  remediation(payload: Record<string, unknown>): Observable<RemediationResponse> { return this.http.post<RemediationResponse>(`${this.baseUrl}/remediation/bulk`, payload).pipe(tap(() => this.invalidateVulnerabilities())); }
  approvals(): Observable<ApprovalItem[]> { return this.http.get<ApprovalItem[]>(`${this.baseUrl}/approvals`); }
  decideApproval(id: string, decision: 'APPROVE' | 'REJECT', comment = ''): Observable<ApprovalDecisionResponse> { return this.http.post<ApprovalDecisionResponse>(`${this.baseUrl}/approvals/${id}/decision`, { decision, comment }).pipe(tap(() => this.invalidateVulnerabilities())); }
  auditEvents(): Observable<{ event_type: string; aggregate_id: string; occurred_at: string }[]> { return this.http.get<{ event_type: string; aggregate_id: string; occurred_at: string }[]>(`${this.baseUrl}/audit/events`); }
  copilot(question: string, tenantId: string): Observable<CopilotResponse> { return this.http.post<CopilotResponse>(`${this.baseUrl}/copilot/query`, {question, tenant_id: tenantId}); }
  private timedRequest<T>(name: string, request: Observable<T>): Observable<T> { return defer(() => { const started = performance.now(); console.info(`[${new Date().toISOString()}] ${name} started`); return request.pipe(tap({ next: () => console.info(`[${new Date().toISOString()}] ${name} completed (${(performance.now() - started).toFixed(2)} ms)`), error: error => console.error(`[${new Date().toISOString()}] ${name} failed (${(performance.now() - started).toFixed(2)} ms)`, error) })); }); }
  createEngineWorkflow(payload: { project: string; repository_path: string; finding_ids?: string[] }): Observable<EngineWorkflow> { let polls = 0; return this.timedRequest('POST /engine/workflows', this.http.post<WorkflowJob>(`${this.baseUrl}/engine/workflows`, payload)).pipe(switchMap(initial => { console.info(`[${new Date().toISOString()}] Workflow accepted (job ${initial.job_id})`); const polling = timer(0, JOB_POLL_INTERVAL_MS).pipe(switchMap(tick => { if (tick === 0) return [initial]; polls += 1; return this.timedRequest(`GET /engine/workflow-jobs/${initial.job_id} poll #${polls}`, this.http.get<WorkflowJob>(`${this.baseUrl}/engine/workflow-jobs/${initial.job_id}`)); }), tap(current => console.info(`[${new Date().toISOString()}] Workflow job ${current.status} (poll #${polls})`)), filter(current => current.status === 'COMPLETED' || current.status === 'FAILED'), take(1), switchMap(current => { console.info(`[${new Date().toISOString()}] Workflow job ${current.status} after ${polls} poll(s)`); return current.status === 'FAILED' ? throwError(() => new Error(current.error || 'Workflow failed')) : current.result ? [current.result] : throwError(() => new Error('Workflow completed without a result')); })); const deadline = timer(120000).pipe(switchMap(() => throwError(() => new Error(`Workflow job ${initial.job_id} timed out after ${polls} poll(s)`)))); return race(polling, deadline); }), tap(() => this.invalidateWorkflows())); }
  engineWorkflow(id: string): Observable<EngineWorkflow> { return this.http.get<EngineWorkflow>(`${this.baseUrl}/engine/workflows/${id}`); }
  engineWorkflows(): Observable<EngineWorkflow[]> { if (!this.workflowsCache) this.workflowsCache = this.http.get<EngineWorkflow[]>(`${this.baseUrl}/engine/workflows`).pipe(shareReplay({bufferSize: 1, refCount: false})); return this.workflowsCache; }
  engineIntegrations(): Observable<{ provider: string; enabled: boolean; reason: string }[]> { if (!this.integrationsCache) this.integrationsCache = this.http.get<{ provider: string; enabled: boolean; reason: string }[]>(`${this.baseUrl}/engine/integrations`).pipe(shareReplay({bufferSize: 1, refCount: false})); return this.integrationsCache; }
  invalidateVulnerabilities(): void { this.vulnerabilityCache.clear(); }
  invalidateWorkflows(): void { this.workflowsCache = undefined; }
  private waitForScan(job: Observable<BackgroundJob>): Observable<MvpScan> { let polls = 0; return this.timedRequest('POST /mvp/scans', job).pipe(switchMap(initial => { console.info(`[${new Date().toISOString()}] Scan accepted (job ${initial.job_id})`); return timer(0, JOB_POLL_INTERVAL_MS).pipe(switchMap(tick => { if (tick === 0) return [initial]; polls += 1; return this.timedRequest(`GET /mvp/jobs/${initial.job_id} poll #${polls}`, this.http.get<BackgroundJob>(`${this.baseUrl}/mvp/jobs/${initial.job_id}`)); }), filter(current => current.status === 'COMPLETED' || current.status === 'FAILED'), take(1), switchMap(current => { console.info(`[${new Date().toISOString()}] Scan job ${current.status} after ${polls} poll(s)`); if (current.status === 'FAILED') return throwError(() => new Error(current.error || 'Scan failed')); return current.result ? [current.result] : throwError(() => new Error('Scan completed without a result')); })); }), timeout(120000), tap(() => this.invalidateVulnerabilities())); }
  scanRepository(repository_path: string): Observable<MvpScan> { return this.waitForScan(this.http.post<BackgroundJob>(`${this.baseUrl}/mvp/scans`, { repository_path })); }
  scanGitRepository(repository_url: string): Observable<MvpScan> { return this.waitForScan(this.http.post<BackgroundJob>(`${this.baseUrl}/mvp/scans/git`, { repository_url })); }
  scanUploadedRepository(file: File): Observable<MvpScan> { const body = new FormData(); body.append('file', file, file.name); return this.waitForScan(this.http.post<BackgroundJob>(`${this.baseUrl}/mvp/scans/upload`, body)); }
  generateFix(id: string, repository_path: string): Observable<MvpFix> { return this.http.post<MvpFix>(`${this.baseUrl}/mvp/vulnerabilities/${id}/fix`, { repository_path }); }
  createJira(id: string): Observable<Record<string, unknown>> { return this.http.post<Record<string, unknown>>(`${this.baseUrl}/mvp/vulnerabilities/${id}/jira`, {}); }
  createBranch(id: string, repository_path: string): Observable<Record<string, unknown>> { return this.http.post<Record<string, unknown>>(`${this.baseUrl}/mvp/vulnerabilities/${id}/branch`, { repository_path }); }
  createPullRequest(id: string): Observable<Record<string, unknown>> { return this.http.post<Record<string, unknown>>(`${this.baseUrl}/mvp/vulnerabilities/${id}/pull-request`, {}); }
  applications(): Observable<MvpApplication[]> { if (!this.applicationsCache) this.applicationsCache = this.cached(this.http.get<MvpApplication[]>(`${this.baseUrl}/mvp/applications`), () => this.applicationsCache = undefined); return this.applicationsCache; }
  applicationInventory(): Observable<ApplicationInventoryGroup[]> { if (!this.inventoryCache) this.inventoryCache = this.cached(this.http.get<ApplicationInventoryGroup[]>(`${this.baseUrl}/mvp/application-inventory`), () => this.inventoryCache = undefined); return this.inventoryCache; }
  remediations(): Observable<MvpRemediation[]> { return this.http.get<MvpRemediation[]>(`${this.baseUrl}/mvp/remediations`); }
  jiraTickets(): Observable<MvpRecord[]> { return this.http.get<MvpRecord[]>(`${this.baseUrl}/mvp/jira`); }
  branches(): Observable<MvpRecord[]> { return this.http.get<MvpRecord[]>(`${this.baseUrl}/mvp/branches`); }
  pullRequests(): Observable<MvpRecord[]> { return this.http.get<MvpRecord[]>(`${this.baseUrl}/mvp/pull-requests`); }
  knowledge(): Observable<MvpRecord[]> { return this.http.get<MvpRecord[]>(`${this.baseUrl}/mvp/knowledge`); }
  invalidateReadModels(): void { this.inventoryCache = undefined; this.applicationsCache = undefined; this.invalidateVulnerabilities(); this.invalidateWorkflows(); }
  private cached<T>(source: Observable<T>, clear: () => void): Observable<T> { return source.pipe(shareReplay({bufferSize: 1, refCount: false}), tap({ complete: () => window.setTimeout(clear, this.cacheTtlMs), error: clear })); }
}
