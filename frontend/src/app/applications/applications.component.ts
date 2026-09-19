import { CommonModule, DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApplicationInventoryApplication, ApplicationInventoryGroup, ApiService } from '../core/api.service';

type RiskStatus = 'Critical' | 'High' | 'Medium' | 'Healthy';
type SortKey = 'name' | 'repositories' | 'findings' | 'critical' | 'risk';

interface ApplicationRow extends ApplicationInventoryApplication {
  mnemonic: string;
  repositoryCount: number;
  risk: RiskStatus;
}

@Component({
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, DatePipe],
  styleUrls: ['./applications.component.scss'],
  template: `
    <div class="applications-page" [class.dark-mode]="darkMode">
      <header class="page-header">
        <div>
          <p class="eyebrow">Management / Inventory</p>
          <div class="title-row"><h1>Applications</h1><span class="status-chip"><span class="status-dot healthy"></span>Live inventory</span></div>
          <p class="subtitle">Security posture and repository coverage across your application portfolio.</p>
        </div>
        <div class="header-actions">
          <button class="icon-button" type="button" (click)="darkMode = !darkMode" [attr.aria-label]="darkMode ? 'Use light mode' : 'Use dark mode'" title="Toggle theme"><span class="material-icons">{{ darkMode ? 'light_mode' : 'dark_mode' }}</span></button>
          <button class="btn btn-secondary" type="button" (click)="refresh()"><span class="material-icons" [class.spin]="loading">refresh</span>Refresh</button>
          <a class="btn btn-primary" routerLink="/execute"><span class="material-icons">qr_code_scanner</span>Scan application</a>
        </div>
      </header>

      <section class="kpi-grid" aria-label="Application inventory summary">
        <article class="kpi-card"><span class="kpi-icon blue"><span class="material-icons">apps</span></span><div><span class="kpi-label">Applications</span><strong>{{ rows.length }}</strong><small>In current inventory</small></div></article>
        <article class="kpi-card"><span class="kpi-icon purple"><span class="material-icons">account_tree</span></span><div><span class="kpi-label">Repositories</span><strong>{{ repositoryTotal }}</strong><small>Connected codebases</small></div></article>
        <article class="kpi-card"><span class="kpi-icon orange"><span class="material-icons">bug_report</span></span><div><span class="kpi-label">Total findings</span><strong>{{ findingsTotal }}</strong><small>{{ criticalTotal }} critical findings</small></div></article>
        <article class="kpi-card"><span class="kpi-icon red"><span class="material-icons">gpp_maybe</span></span><div><span class="kpi-label">At risk</span><strong>{{ atRiskTotal }}</strong><small>Critical or high risk</small></div></article>
      </section>

      <section class="inventory-panel">
        <div class="panel-heading"><div><h2>Application inventory</h2><p>{{ filteredRows.length }} of {{ rows.length }} applications</p></div><span class="last-updated">Updated {{ lastUpdated | date:'MMM d, y, h:mm a' }}</span></div>
        <div class="toolbar" role="search">
          <label class="search-box"><span class="material-icons">search</span><input type="search" [(ngModel)]="query" (ngModelChange)="applyFilters()" placeholder="Search applications, mnemonics, repositories..." aria-label="Search applications" /></label>
          <select class="field" [(ngModel)]="riskFilter" (ngModelChange)="applyFilters()" aria-label="Filter by risk"><option value="All">All risk statuses</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Healthy">Healthy</option></select>
          <select class="field" [(ngModel)]="sortKey" (ngModelChange)="applyFilters()" aria-label="Sort applications"><option value="risk">Sort: Risk</option><option value="name">Sort: Name</option><option value="repositories">Sort: Repositories</option><option value="findings">Sort: Findings</option><option value="critical">Sort: Critical findings</option></select>
          <button class="filter-button" type="button" (click)="clearFilters()" [disabled]="!query && riskFilter === 'All'">Clear filters</button>
        </div>

        @if (loading) { <div class="empty-state"><span class="material-icons spin">refresh</span><p>Loading application inventory…</p></div> }
        @else if (error) { <div class="empty-state"><span class="material-icons">error_outline</span><p>{{ error }}</p><button class="btn btn-secondary" type="button" (click)="refresh()">Try again</button></div> }
        @else if (!filteredRows.length) { <div class="empty-state"><span class="material-icons">search_off</span><p>No applications match the current filters.</p></div> }
        @else {
          <div class="table-wrap"><table class="inventory-table"><thead><tr><th>Application</th><th>Mnemonic</th><th>Repositories</th><th>Total findings</th><th>Critical findings</th><th>Risk status</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>
            @for (app of filteredRows; track app.name + app.mnemonic) { <tr><td><div class="app-name"><span class="app-avatar">{{ initials(app.name) }}</span><div><strong>{{ app.name }}</strong><small>{{ app.repo_path }}</small></div></div></td><td><span class="mnemonic">{{ app.mnemonic }}</span></td><td>{{ app.repositoryCount }}</td><td><strong>{{ app.total_findings }}</strong></td><td><span [class.finding-critical]="app.critical_findings > 0">{{ app.critical_findings }}</span></td><td><span [class]="'risk-pill ' + riskClass(app.risk)"><span class="status-dot"></span>{{ app.risk }}</span></td><td><div class="row-actions"><button type="button" (click)="openDrawer(app)">View</button><a [routerLink]="['/vulnerabilities']" [queryParams]="{ application: app.name }">Findings</a><a routerLink="/remediation">Remediate</a><a routerLink="/execute">Scan</a></div></td></tr> }
          </tbody></table></div>
          <div class="card-grid">@for (app of filteredRows; track app.name + app.mnemonic) { <article class="application-card"><div class="card-top"><div class="app-name"><span class="app-avatar">{{ initials(app.name) }}</span><div><strong>{{ app.name }}</strong><small>{{ app.mnemonic }}</small></div></div><span [class]="'risk-pill ' + riskClass(app.risk)"><span class="status-dot"></span>{{ app.risk }}</span></div><div class="card-stats"><span><small>Repositories</small><strong>{{ app.repositoryCount }}</strong></span><span><small>Findings</small><strong>{{ app.total_findings }}</strong></span><span><small>Critical</small><strong>{{ app.critical_findings }}</strong></span></div><div class="card-actions"><button type="button" (click)="openDrawer(app)">View</button><a routerLink="/vulnerabilities">Findings</a><a routerLink="/remediation">Remediate</a><a routerLink="/execute">Scan</a></div></article> }</div>
        }
      </section>

      @if (selectedApplication) { <div class="drawer-backdrop" (click)="closeDrawer()"></div><aside class="drawer" aria-label="Repository details"><div class="drawer-header"><div><p class="eyebrow">Application details</p><h2>{{ selectedApplication.name }}</h2><p>{{ selectedApplication.mnemonic }} · {{ selectedApplication.repo_path }}</p></div><button class="icon-button" type="button" (click)="closeDrawer()" aria-label="Close repository details"><span class="material-icons">close</span></button></div><div class="drawer-summary"><div><span>Total findings</span><strong>{{ selectedApplication.total_findings }}</strong></div><div><span>Critical</span><strong class="critical-text">{{ selectedApplication.critical_findings }}</strong></div></div><h3>Repositories <span>{{ selectedApplication.repositories.length }}</span></h3><div class="repository-list">@for (repo of selectedApplication.repositories; track repo.name) { <div class="repository-row"><span class="repo-icon material-icons">source</span><div><strong>{{ repo.name }}</strong><small>{{ repo.total_findings }} findings · {{ repo.critical_findings }} critical</small></div><span class="repository-risk" [class.critical-text]="repo.critical_findings > 0">{{ repo.critical_findings > 0 ? 'Review' : 'Healthy' }}</span></div> } @empty { <p class="muted">No repository details available.</p> }</div></aside> }
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ApplicationsComponent {
  private readonly api = inject(ApiService);
  rows: ApplicationRow[] = [];
  filteredRows: ApplicationRow[] = [];
  selectedApplication: ApplicationRow | null = null;
  query = '';
  riskFilter: RiskStatus | 'All' = 'All';
  sortKey: SortKey = 'risk';
  loading = true;
  error = '';
  darkMode = false;
  lastUpdated = new Date();

  constructor() { this.refresh(); }

  get repositoryTotal(): number { return this.rows.reduce((sum, app) => sum + app.repositoryCount, 0); }
  get findingsTotal(): number { return this.rows.reduce((sum, app) => sum + app.total_findings, 0); }
  get criticalTotal(): number { return this.rows.reduce((sum, app) => sum + app.critical_findings, 0); }
  get atRiskTotal(): number { return this.rows.filter(app => app.risk === 'Critical' || app.risk === 'High').length; }

  refresh(): void {
    this.loading = true; this.error = '';
    this.api.applicationInventory().subscribe({
      next: groups => { this.rows = this.flatten(groups); this.lastUpdated = new Date(); this.applyFilters(); this.loading = false; },
      error: () => { this.error = 'Unable to load application inventory.'; this.loading = false; },
    });
  }

  applyFilters(): void {
    const search = this.query.trim().toLowerCase();
    const riskRank: Record<RiskStatus, number> = { Critical: 0, High: 1, Medium: 2, Healthy: 3 };
    this.filteredRows = this.rows.filter(app => (!search || `${app.name} ${app.mnemonic} ${app.repo_path} ${app.repositories.map(repo => repo.name).join(' ')}`.toLowerCase().includes(search)) && (this.riskFilter === 'All' || app.risk === this.riskFilter));
    this.filteredRows.sort((a, b) => this.sortKey === 'name' ? a.name.localeCompare(b.name) : this.sortKey === 'repositories' ? b.repositoryCount - a.repositoryCount : this.sortKey === 'findings' ? b.total_findings - a.total_findings : this.sortKey === 'critical' ? b.critical_findings - a.critical_findings : riskRank[a.risk] - riskRank[b.risk]);
  }

  clearFilters(): void { this.query = ''; this.riskFilter = 'All'; this.applyFilters(); }
  openDrawer(app: ApplicationRow): void { this.selectedApplication = app; }
  closeDrawer(): void { this.selectedApplication = null; }
  initials(name: string): string { return name.split(/\s+/).map(part => part[0]).join('').slice(0, 2).toUpperCase(); }
  riskClass(risk: RiskStatus): string { return `risk-${risk.toLowerCase()}`; }

  private flatten(groups: ApplicationInventoryGroup[]): ApplicationRow[] {
    return groups.flatMap(group => group.applications.map(app => ({ ...app, mnemonic: group.mnemonic, repositoryCount: app.repositories.length, risk: this.riskFor(app) })));
  }

  private riskFor(app: ApplicationInventoryApplication): RiskStatus {
    if (app.critical_findings > 0) return 'Critical';
    if (app.total_findings >= 10) return 'High';
    if (app.total_findings > 0) return 'Medium';
    return 'Healthy';
  }
}