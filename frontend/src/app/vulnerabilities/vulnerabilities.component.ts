import { Component, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, Vulnerability } from '../core/api.service';

@Component({
  standalone: true,
  imports: [FormsModule],
  template: `
    <div class="page"><div class="page-header"><div><p class="eyebrow">Risk intelligence</p><h1>Vulnerability inventory</h1><p class="subtitle">Search, filter, cluster, and review tenant-scoped findings before remediation.</p></div><button class="btn btn-primary" (click)="exportRows()">Export view</button></div>
      <section class="panel"><div class="toolbar"><input class="field search-field" [(ngModel)]="search" (ngModelChange)="filterRows()" placeholder="Search title, CVE, application or repository" aria-label="Search vulnerabilities"><select class="field" [(ngModel)]="severity" (ngModelChange)="filterRows()"><option value="">All severities</option><option value="CRITICAL">CRITICAL</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option></select><select class="field" [(ngModel)]="status" (ngModelChange)="filterRows()"><option value="">All statuses</option><option value="OPEN">OPEN</option><option value="IN_REVIEW">IN_REVIEW</option><option value="REMEDIATED">REMEDIATED</option><option value="ACCEPTED_RISK">ACCEPTED_RISK</option></select><button class="btn btn-ghost" (click)="reset()">Reset</button></div>
        @if (loading) { <div class="empty-state">Loading inventory...</div> } @else if (error) { <div class="empty-state">Unable to load findings. <button class="btn btn-ghost" (click)="load()">Try again</button></div> } @else if (!rows.length) { <div class="empty-state"><strong>No findings match this view</strong><p>Adjust your filters or search terms to continue.</p></div> } @else { <div class="table-wrap"><table class="data-table"><thead><tr><th>Severity</th><th>Finding</th><th>Scope</th><th>CVSS</th><th>Status</th><th>Confidence</th></tr></thead><tbody>@for (row of rows; track row.id) { <tr><td><span class="badge" [class.badge-critical]="row.severity === 'CRITICAL'" [class.badge-high]="row.severity === 'HIGH'" [class.badge-medium]="row.severity === 'MEDIUM'" [class.badge-low]="row.severity === 'LOW'">{{ row.severity }}</span></td><td><strong>{{ row.title }}</strong><small class="muted">{{ row.cve || row.category }}</small></td><td><strong>{{ row.mnemonic }}</strong><small class="muted">{{ row.application }} / {{ row.repository }}</small></td><td>{{ row.cvss ?? '-' }}</td><td><span class="badge badge-neutral">{{ formatStatus(row.status) }}</span></td><td>{{ row.ai_confidence || 'MEDIUM' }}</td></tr> }</tbody></table></div><p class="result-count">Showing {{ rows.length }} of {{ allRows.length }} findings</p> }
      </section></div>
  `,
  styles: [`.muted{display:block;margin-top:.25rem;color:var(--muted);font-size:.73rem}.result-count{margin:1rem 0 0;color:var(--muted);font-size:.75rem}`],
})
export class VulnerabilitiesComponent implements OnInit {
  private readonly api = inject(ApiService);
  allRows: Vulnerability[] = [];
  rows: Vulnerability[] = [];
  search = '';
  severity = '';
  status = '';
  loading = false;
  error = false;

  ngOnInit(): void { this.load(); }
  load(): void { this.loading = true; this.error = false; this.api.vulnerabilities().subscribe({ next: (rows) => { this.allRows = rows; this.filterRows(); this.loading = false; }, error: () => { this.error = true; this.loading = false; } }); }
  filterRows(): void { const query = this.search.toLowerCase(); this.rows = this.allRows.filter((row) => (!query || [row.title, row.cve, row.category, row.mnemonic, row.application, row.repository].some((value) => (value || '').toLowerCase().includes(query))) && (!this.severity || row.severity === this.severity) && (!this.status || row.status === this.status)); }
  reset(): void { this.search = ''; this.severity = ''; this.status = ''; this.filterRows(); }
  formatStatus(value: string): string { return value.replaceAll('_', ' '); }
  exportRows(): void { const body = this.rows.map((row) => `${row.severity},"${row.title.replaceAll('"', '""')}",${row.mnemonic},${row.status}`).join('\n'); const blob = new Blob([`severity,title,mnemonic,status\n${body}`], { type: 'text/csv' }); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'pnc-vulnerability-inventory.csv'; link.click(); URL.revokeObjectURL(link.href); }
}
