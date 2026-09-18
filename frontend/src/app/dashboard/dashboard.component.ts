import { Component, OnInit, inject } from '@angular/core';
import { Router } from '@angular/router';
import { DashboardMetrics, ApiService, EngineWorkflow } from '../core/api.service';

@Component({
  standalone: true,
  template: `
    <div class="page security-dashboard">
      <div class="page-header">
        <div>
          <p class="eyebrow">Dashboard</p>
          <h1>Security dashboard</h1>
          <p class="subtitle">Security posture, active gates, and unresolved risk across the tenant.</p>
        </div>
        <button class="btn btn-secondary" (click)="load()" [disabled]="loading">{{ loading ? 'Refreshing…' : 'Refresh dashboard' }}</button>
      </div>
      @if (loading) {
        <section class="panel empty-state">Loading security dashboard…</section>
      } @else if (error) {
        <section class="panel empty-state">Security dashboard data is temporarily unavailable. <button class="btn btn-ghost" (click)="load()">Try again</button></section>
      } @else {
        <section class="metric-grid">
          <article class="metric-card"><span class="metric-label">Security posture</span><strong class="metric-value">{{ metrics?.security_score ?? 0 }}</strong><span class="metric-note">Current security score</span></article>
          <article class="metric-card"><span class="metric-label">Active gates</span><strong class="metric-value">{{ activeGates }}</strong><span class="metric-note">Governed checks in progress</span></article>
          <article class="metric-card"><span class="metric-label">Unresolved risk</span><strong class="metric-value">{{ metrics?.open ?? 0 }}</strong><span class="metric-note">Findings requiring action</span></article>
          <article class="metric-card"><span class="metric-label">Critical risk</span><strong class="metric-value">{{ metrics?.critical ?? 0 }}</strong><span class="metric-note">Priority review</span></article>
        </section>
        <section class="panel workflow-panel">
          <div class="panel-title"><div><h2>Security operations</h2><p class="subtitle">Classification, remediation, validation, and approval evidence are retained for every engine workflow.</p></div><span class="badge badge-success">Governed</span></div>
          <div class="workflow-summary"><strong>{{ workflows.length }} workflow(s) tracked</strong><span>{{ workflowStatus }}</span></div>
          @if (workflows.length) { <ul class="list-reset workflow-list">@for (workflow of workflows; track workflow.workflow_id) {<li class="list-row"><span><strong>{{ workflow.project }}</strong><small>{{ workflow.repository_path }}</small></span><span class="badge" [class.badge-success]="workflow.status === 'READY'" [class.badge-neutral]="workflow.status !== 'READY'">{{ workflow.status }}</span></li>}</ul> }
        </section>
        <section class="panel quick-actions"><div class="panel-title"><h2>Quick actions</h2></div><div class="action-row"><button class="btn btn-primary" (click)="goTo('execute')">Scan code base</button><button class="btn btn-secondary" (click)="goTo('remediation')">Review remediation</button></div></section>
      }
    </div>
  `,
  styles: [`.workflow-panel{margin-bottom:1rem}.workflow-summary{display:flex;justify-content:space-between;gap:1rem;padding:1rem;background:#f8fafc;border:1px solid var(--line);border-radius:9px}.workflow-summary span,.workflow-list small{color:var(--muted);font-size:.75rem}.workflow-list{margin-top:.75rem}.workflow-list .list-row>span:first-child{display:flex;flex-direction:column;gap:.25rem}.quick-actions{margin-top:1rem}.action-row{display:flex;flex-wrap:wrap;gap:.7rem}@media(max-width:600px){.workflow-summary{align-items:flex-start;flex-direction:column}.action-row .btn{width:100%}}`]
})
export class DashboardComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  metrics: DashboardMetrics | null = null;
  workflows: EngineWorkflow[] = [];
  loading = false;
  error = false;
  get activeGates(): number { return this.workflows.filter(workflow => workflow.status !== 'COMPLETED').length; }
  get workflowStatus(): string { return this.workflows.length ? 'Evidence retained for every tracked workflow' : 'No active engine workflows'; }
  ngOnInit(): void { this.load(); }
  load(): void { this.loading = true; this.error = false; this.api.metrics().subscribe({ next: value => { this.metrics = value; this.loadWorkflows(); }, error: () => { this.loading = false; this.error = true; } }); }
  goTo(path: string): void { void this.router.navigate([path]); }
  private loadWorkflows(): void { this.api.engineWorkflows().subscribe({ next: value => { this.workflows = value; this.loading = false; }, error: () => { this.workflows = []; this.loading = false; } }); }
}