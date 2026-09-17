import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs';

export type Role = 'SECURITY_ANALYST' | 'SECURITY_REVIEWER' | 'PLATFORM_ADMIN';
export interface AuthUser { user_id: string; tenant_id: string; name: string; email: string; role: Role; }

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly key = 'pnc.auth';
  login(email: string, password: string): Observable<AuthUser> { return this.http.post<AuthUser>('/api/v1/auth/login', { email, password }).pipe(tap(user => this.save(user))); }
  register(name: string, email: string, password: string, role: Role): Observable<AuthUser> { return this.http.post<AuthUser>('/api/v1/auth/register', { name, email, password, role }).pipe(tap(user => this.save(user))); }
  user(): AuthUser | null { const value = localStorage.getItem(this.key); return value ? JSON.parse(value) as AuthUser : null; }
  isAuthenticated(): boolean { return this.user() !== null; }
  hasRole(roles: Role[]): boolean { const user = this.user(); return !!user && roles.includes(user.role); }
  logout(): void { localStorage.removeItem(this.key); localStorage.removeItem('pnc.userId'); localStorage.removeItem('pnc.tenantId'); localStorage.removeItem('pnc.role'); }
  private save(user: AuthUser): void { localStorage.setItem(this.key, JSON.stringify(user)); localStorage.setItem('pnc.userId', user.user_id); localStorage.setItem('pnc.tenantId', user.tenant_id); localStorage.setItem('pnc.role', user.role); }
}