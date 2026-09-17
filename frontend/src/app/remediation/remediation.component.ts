import { TitleCasePipe } from '@angular/common';
import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, RemediationResponse } from '../core/api.service';

type RemediationScope = 'ENTERPRISE' | 'MNEMONIC' | 'APPLICATION' | 'REPOSITORY';
type Severity = '' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

@Component({
  standalone: true,
  imports: [FormsModule, TitleCasePipe],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <p class="eyebrow">Governed automation</p>
          <h1>AI remediation center</h1>
          <p class="subtitle">Prepare validated remediation workflows. No merge occurs without the required approval gate.</p>
        </div>
        <span class="badge badge-success">Approval protected</span>
      </div>
      <div class="two-column">
        <section class="panel">
          <div class="panel-title"><h2>Start a remediation workflow</h2><span class="badge badge-neutral">Step 1 of 3</span></div>
          <label class="form-label">Remediation scope
            <select class="field full" [(ngModel)]="scope">
              <option value="ENTERPRISE">Entire enterprise</option><option value="MNEMONIC">Mnemonic</option>
              <option value="APPLICATION">Application</option><option value="REPOSITORY">Repository</option>
            </select>
          </label>
          @if (scope !== 'ENTERPRISE') {
            <label class="form-label">{{ scope | titlecase }} name
              <input class="field full" [(ngModel)]="scopeValue" placeholder="Enter scope name" />
            </label>
          }
          <label class="form-label">Severity threshold
            <select class="field full" [(ngModel)]="severity">
              <option value="">All severities</option><option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option>
            </select>
          </label>
          <button class="btn btn-primary full-button" [disabled]="submitting" (click)="submit()">
            {{ submitting ? 'Preparing workflow…' : 'Analyze and request remediation' }}
          </button>
          @if (error) { <p class="error">{{ error }}</p> }
        </section>
        <section class="panel">
          <div class="panel-title"><h2>What happens next</h2></div>
          <ol class="steps">
            <li><strong>Discover and classify</strong><span>Findings are matched to the selected scope and prioritized.</span></li>
            <li><strong>Validate proposed changes</strong><span>Automated checks run before a pull request can be created.</span></li>
            <li><strong>Route for approval</strong><span>Security and application owners review evidence before merge.</span></li>
          </ol>
        </section>
      </div>
      @if (result) {
        <section class="panel result">
          <p class="eyebrow">Workflow created</p><h2>{{ statusLabel }}</h2>
          <div class="result-grid">
            <div><small>Matched findings</small><strong>{{ result.matched_vulnerabilities }}</strong></div>
            <div><small>Confidence</small><strong>{{ result.confidence }}</strong></div>
            <div><small>Branch pattern</small><strong>{{ result.branch_pattern }}</strong></div>
          </div>
          <p class="subtitle">{{ result.next_step }}</p>
        </section>
      }
    </div>
  `,
  styles: [`
    .form-label{display:block;margin:1.1rem 0;color:var(--ink);font-weight:600;font-size:.8rem}.full{display:block;width:100%;margin-top:.45rem}.full-button{width:100%;margin-top:.8rem}.error{margin:1rem 0 0;color:var(--danger)}.steps{padding:0;margin:0;list-style:none}.steps li{position:relative;padding:0 0 1.5rem 2rem;border-left:2px solid #dce6ee}.steps li:last-child{border-left-color:transparent}.steps li::before{content:'';position:absolute;left:-7px;top:0;width:12px;height:12px;background:var(--orange);border:3px solid #fff;border-radius:50%;box-shadow:0 0 0 1px var(--orange)}.steps strong,.steps span{display:block}.steps span{margin-top:.35rem;color:var(--muted);font-size:.78rem;line-height:1.5}.result{margin-top:1rem}.result-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}.result-grid div{padding:1rem;background:#f8fafc;border-radius:8px}.result-grid small,.result-grid strong{display:block}.result-grid small{color:var(--muted);font-size:.72rem}.result-grid strong{margin-top:.4rem;font-size:.95rem}@media(max-width:600px){.result-grid{grid-template-columns:1fr}}
  `],
})
export class RemediationComponent {
  private readonly api = inject(ApiService);
  scope: RemediationScope = 'ENTERPRISE';
  scopeValue = '';
  severity: Severity = '';
  submitting = false;
  error = '';
  result: RemediationResponse | null = null;

  get statusLabel(): string { return this.result?.status.replaceAll('_', ' ') ?? ''; }

  submit(): void {
    this.submitting = true;
    this.error = '';
    const payload: Record<string, unknown> = {
      tenant_id: localStorage.getItem('pnc.tenantId') || '00000000-0000-0000-0000-000000000001',
      requested_by: localStorage.getItem('pnc.userId') || '00000000-0000-0000-0000-000000000001',
      scope: this.scope,
    };
    if (this.scope !== 'ENTERPRISE') {
      const fieldByScope: Record<Exclude<RemediationScope, 'ENTERPRISE'>, string> = {
        MNEMONIC: 'mnemonic', APPLICATION: 'application', REPOSITORY: 'repository',
      };
      payload[fieldByScope[this.scope]] = this.scopeValue.trim();
    }
    if (this.severity) payload['severity'] = this.severity;
    this.api.remediation(payload).subscribe({
      next: (value) => { this.result = value; this.submitting = false; },
      error: (err: { error?: { detail?: string } }) => {
        this.error = err?.error?.detail || 'The remediation request could not be submitted.';
        this.submitting = false;
      },
    });
  }
}