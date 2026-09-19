import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, shareReplay, tap } from 'rxjs';

export type Role = 'SECURITY_ANALYST' | 'SECURITY_REVIEWER' | 'PLATFORM_ADMIN';
export type Permission = 'DASHBOARD_VIEW' | 'SCAN_EXECUTE' | 'VULNERABILITY_VIEW' | 'VULNERABILITY_REMEDIATE' | 'APPROVAL_REVIEW' | 'USER_ADMINISTRATION' | 'PROFILE_MANAGE';
export interface AuthUser { user_id: string; tenant_id: string; name: string; email: string; role: Role; permissions: Permission[]; }

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly key = 'pnc.auth';
  private usersCache?: Observable<AuthUser[]>;
  login(email: string, password: string): Observable<AuthUser> { return this.http.post<AuthUser>('/api/v1/auth/login', { email, password }).pipe(tap(user => this.save(user))); }
  register(name: string, email: string, password: string, role: Role): Observable<AuthUser> { return this.http.post<AuthUser>('/api/v1/auth/register', { name, email, password, role }).pipe(tap(user => this.save(user))); }
  updateProfile(name: string): Observable<AuthUser> { return this.http.patch<AuthUser>('/api/v1/auth/profile', { name }).pipe(tap(user => this.save(user))); }
  users(): Observable<AuthUser[]> { if (!this.usersCache) { this.usersCache = this.http.get<AuthUser[]>('/api/v1/admin/users').pipe(shareReplay({bufferSize: 1, refCount: false})); window.setTimeout(() => this.usersCache = undefined, 60_000); } return this.usersCache; }
  updateUserRole(userId: string, role: Role): Observable<AuthUser> { return this.http.patch<AuthUser>(`/api/v1/admin/users/${userId}/role`, { role }).pipe(tap(() => this.usersCache = undefined)); }
  user(): AuthUser | null { const value = localStorage.getItem(this.key); if (!value) return null; try { return JSON.parse(value) as AuthUser; } catch { localStorage.removeItem(this.key); return null; } }
  isAuthenticated(): boolean { return this.user() !== null; }
  hasRole(roles: Role[]): boolean { const user = this.user(); return !!user && roles.includes(user.role); }
  hasPermission(permission: Permission): boolean { const user = this.user(); return !!user && (user.permissions?.includes(permission) ?? this.permissionsForRole(user.role).includes(permission)); }
  logout(): void { localStorage.removeItem(this.key); localStorage.removeItem('pnc.userId'); localStorage.removeItem('pnc.tenantId'); localStorage.removeItem('pnc.role'); }
  private save(user: AuthUser): void { localStorage.setItem(this.key, JSON.stringify(user)); localStorage.setItem('pnc.userId', user.user_id); localStorage.setItem('pnc.tenantId', user.tenant_id); localStorage.setItem('pnc.role', user.role); }
  private permissionsForRole(role: Role): Permission[] { if (role === 'PLATFORM_ADMIN') return ['DASHBOARD_VIEW', 'SCAN_EXECUTE', 'VULNERABILITY_VIEW', 'VULNERABILITY_REMEDIATE', 'APPROVAL_REVIEW', 'USER_ADMINISTRATION', 'PROFILE_MANAGE']; if (role === 'SECURITY_REVIEWER') return ['DASHBOARD_VIEW', 'SCAN_EXECUTE', 'VULNERABILITY_VIEW', 'VULNERABILITY_REMEDIATE', 'APPROVAL_REVIEW', 'PROFILE_MANAGE']; return ['DASHBOARD_VIEW', 'SCAN_EXECUTE', 'VULNERABILITY_VIEW', 'PROFILE_MANAGE']; }
}