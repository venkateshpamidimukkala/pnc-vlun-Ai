import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, CopilotResponse } from '../core/api.service';

@Component({
  standalone: true,
  imports: [FormsModule],
  template: `
    <div class="page">
      <div class="page-header"><div><p class="eyebrow">Analyst assistant</p><h1>Security Copilot</h1><p class="subtitle">Ask questions about tenant-scoped vulnerabilities, remediation, and evidence.</p></div><span class="badge badge-success">Knowledge base online</span></div>
      <section class="copilot panel">
        <div class="welcome"><div class="copilot-icon">*</div><div><h2>How can I help with your security posture?</h2><p class="subtitle">Responses are grounded in the current inventory and audit evidence.</p></div></div>
        <div class="suggestions">@for (suggestion of suggestions; track suggestion) { <button class="suggestion" (click)="question = suggestion">{{ suggestion }}</button> }</div>
        <div class="conversation">@if (!response && !loading) { <div class="empty-state">Your conversation will appear here.</div> } @if (loading) { <div class="empty-state">Reviewing tenant evidence...</div> } @if (response) { <div class="answer"><strong>Copilot</strong><p>{{ response.answer }}</p><div class="evidence">@for (item of response.evidence; track item) { <span class="badge badge-neutral">{{ item }}</span> }<span class="badge badge-success">{{ response.confidence }} confidence</span></div></div> }</div>
        <div class="prompt"><textarea [(ngModel)]="question" (keydown.enter)="ask($event)" rows="2" placeholder="Ask about open critical findings, remediation progress, or audit evidence..."></textarea><button class="btn btn-primary" [disabled]="loading || question.trim().length < 3" (click)="ask()">{{ loading ? 'Thinking...' : 'Ask Copilot' }}</button></div>
        @if (error) { <p class="error">{{ error }}</p> }
      </section>
    </div>
  `,
  styles: [`.copilot{max-width:980px}.welcome{display:flex;gap:1rem;align-items:center;padding-bottom:1.25rem;border-bottom:1px solid var(--line)}.copilot-icon{display:grid;place-items:center;width:46px;height:46px;color:#fff;background:var(--orange);border-radius:12px;font-size:1.5rem}.welcome h2{margin-bottom:.35rem}.suggestions{display:flex;flex-wrap:wrap;gap:.5rem;margin:1rem 0}.suggestion{padding:.55rem .75rem;color:var(--navy-2);background:#f3f7fa;border:1px solid var(--line);border-radius:999px;font-size:.75rem}.conversation{min-height:230px;border:1px solid var(--line);border-radius:8px}.answer{padding:1.25rem;line-height:1.7}.answer strong{color:var(--orange-dark)}.evidence{display:flex;flex-wrap:wrap;gap:.5rem}.prompt{display:flex;gap:.75rem;margin-top:1rem}.prompt textarea{flex:1;padding:.8rem;resize:vertical;border:1px solid #cbd6e2;border-radius:7px;outline:0}.prompt textarea:focus{border-color:var(--orange)}.error{color:var(--danger)}`],
})
export class CopilotComponent {
  private readonly api = inject(ApiService);
  question = '';
  loading = false;
  error = '';
  response: CopilotResponse | null = null;
  readonly suggestions = ['What are my highest-risk open findings?', 'Which applications need remediation?', 'Summarize recent audit activity.'];

  ask(event?: Event): void {
    event?.preventDefault();
    const question = this.question.trim();
    if (question.length < 3 || this.loading) return;
    this.loading = true;
    this.error = '';
    const tenantId = localStorage.getItem('pnc.tenantId') || '00000000-0000-0000-0000-000000000001';
    this.api.copilot(question, tenantId).subscribe({
      next: (value) => { this.response = value; this.loading = false; },
      error: () => { this.error = 'Copilot is temporarily unavailable.'; this.loading = false; },
    });
  }
}
