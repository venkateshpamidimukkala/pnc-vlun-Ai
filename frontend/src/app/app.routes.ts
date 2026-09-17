import { Routes } from '@angular/router';
import { authGuard } from './core/auth.guard';

export const routes: Routes = [
  { path: 'login', loadComponent: () => import('./login/login.component').then(m => m.LoginComponent) },
  { path: 'register', loadComponent: () => import('./register/register.component').then(m => m.RegisterComponent) },
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'dashboard', canActivate: [authGuard], loadComponent: () => import('./dashboard/dashboard.component').then(m => m.DashboardComponent) },
  { path: 'executive', canActivate: [authGuard], loadComponent: () => import('./operations/operations.component').then(m => m.OperationsComponent) },
  { path: 'security', canActivate: [authGuard], loadComponent: () => import('./operations/operations.component').then(m => m.OperationsComponent) },
  { path: 'developer', canActivate: [authGuard], loadComponent: () => import('./operations/operations.component').then(m => m.OperationsComponent) },
  { path: 'execute', canActivate: [authGuard], loadComponent: () => import('./execute/execute.component').then(m => m.ExecuteComponent) },
  { path: 'vulnerabilities', canActivate: [authGuard], loadComponent: () => import('./vulnerabilities/vulnerabilities.component').then(m => m.VulnerabilitiesComponent) },
  { path: 'remediation', canActivate: [authGuard], loadComponent: () => import('./remediation/remediation.component').then(m => m.RemediationComponent) },
  { path: 'approvals', canActivate: [authGuard], data: { roles: ['SECURITY_REVIEWER', 'PLATFORM_ADMIN'] }, loadComponent: () => import('./approvals/approvals.component').then(m => m.ApprovalsComponent) },
  { path: 'enterprise', canActivate: [authGuard], data: { roles: ['PLATFORM_ADMIN'] }, loadComponent: () => import('./enterprise/enterprise.component').then(m => m.EnterpriseComponent) },
  { path: 'applications', canActivate: [authGuard], loadComponent: () => import('./operations/operations.component').then(m => m.OperationsComponent) },
  { path: 'jira', canActivate: [authGuard], loadComponent: () => import('./operations/operations.component').then(m => m.OperationsComponent) },
  { path: 'pull-requests', canActivate: [authGuard], loadComponent: () => import('./operations/operations.component').then(m => m.OperationsComponent) },
  { path: 'test-case-validation', canActivate: [authGuard], loadComponent: () => import('./operations/operations.component').then(m => m.OperationsComponent) },
  { path: 'security-gateway', canActivate: [authGuard], loadComponent: () => import('./operations/operations.component').then(m => m.OperationsComponent) },
  { path: 'audit-log', canActivate: [authGuard], loadComponent: () => import('./operations/operations.component').then(m => m.OperationsComponent) },
  { path: 'pr-history', canActivate: [authGuard], loadComponent: () => import('./operations/operations.component').then(m => m.OperationsComponent) },
  { path: 'knowledge-repo', canActivate: [authGuard], loadComponent: () => import('./operations/operations.component').then(m => m.OperationsComponent) },
  { path: 'copilot', canActivate: [authGuard], loadComponent: () => import('./copilot/copilot.component').then(m => m.CopilotComponent) },
  { path: '**', redirectTo: 'dashboard' },
];
