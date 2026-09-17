import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Vulnerability { id: string; tenant_id: string; mnemonic: string; application: string; repository: string; title: string; category: string; severity: string; status: string; cve?: string; cwe?: string; cvss?: number; ai_confidence?: string; created_at?: string; }
export interface DashboardMetrics { total: number; critical: number; high: number; medium: number; low: number; open: number; remediated: number; risk_reduction_percent: number; ai_success_rate_percent: number; }
export interface RemediationResponse { workflow_id: string; status: string; matched_vulnerabilities: number; branch_pattern: string; confidence: string; next_step: string; }
export interface ApprovalItem { id: string; mnemonic: string; application: string; repository: string; title: string; level: string; status: string; due_at: string; }
export interface CopilotResponse { answer: string; evidence: string[]; confidence: string; }
export interface ApprovalDecisionResponse extends ApprovalItem { }

@Injectable({providedIn:'root'})
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1';
  vulnerabilities(filters: Record<string, string> = {}): Observable<Vulnerability[]> { let params = new HttpParams(); Object.entries(filters).forEach(([key,value]) => params = params.set(key,value)); return this.http.get<Vulnerability[]>(`${this.baseUrl}/vulnerabilities`, {params}); }
  metrics(): Observable<DashboardMetrics> { return this.http.get<DashboardMetrics>(`${this.baseUrl}/dashboard/metrics`); }
  remediation(payload: Record<string, unknown>): Observable<RemediationResponse> { return this.http.post<RemediationResponse>(`${this.baseUrl}/remediation/bulk`, payload); }
  approvals(): Observable<ApprovalItem[]> { return this.http.get<ApprovalItem[]>(`${this.baseUrl}/approvals`); }
  decideApproval(id: string, decision: 'APPROVE' | 'REJECT', comment = ''): Observable<ApprovalDecisionResponse> { return this.http.post<ApprovalDecisionResponse>(`${this.baseUrl}/approvals/${id}/decision`, { decision, comment }); }
  auditEvents(): Observable<{ event_type: string; aggregate_id: string; occurred_at: string }[]> { return this.http.get<{ event_type: string; aggregate_id: string; occurred_at: string }[]>(`${this.baseUrl}/audit/events`); }
  copilot(question: string, tenantId: string): Observable<CopilotResponse> { return this.http.post<CopilotResponse>(`${this.baseUrl}/copilot/query`, {question, tenant_id: tenantId}); }
}
