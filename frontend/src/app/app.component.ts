import { Component, inject } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from './core/auth.service';

@Component({ selector: 'app-root', standalone: true, imports: [RouterOutlet, RouterLink, RouterLinkActive], template: `
  @if (!isLogin()) {
    <header class="topbar"><div class="brand"><span class="brand-mark">PNC</span><div><strong>Vuln AI</strong><small>Enterprise Security Operations</small></div></div><div class="top-actions"><span class="environment">LOCAL DEVELOPMENT</span><span class="avatar">{{ initials }}</span><button class="logout" (click)="logout()">Sign out</button></div></header>
    <div class="shell"><nav><p class="nav-label">Workspace</p><a routerLink="/dashboard" routerLinkActive="active">Overview</a><a routerLink="/vulnerabilities" routerLinkActive="active">Vulnerability inventory</a><a routerLink="/remediation" routerLinkActive="active">AI remediation</a><a routerLink="/approvals" routerLinkActive="active">Approval queue</a><p class="nav-label">Operations</p><a routerLink="/enterprise" routerLinkActive="active">Enterprise modules</a><a routerLink="/copilot" routerLinkActive="active">Security Copilot</a><div class="nav-footer"><span class="status-dot"></span><span>Platform healthy</span></div></nav><main><router-outlet /></main></div>
    <footer>PNC Vuln AI <span>Secure by design · © 2026 PNC</span></footer>
  } @else { <router-outlet /> }
`, styleUrl: './app.component.scss' })
export class AppComponent {
  private readonly auth = inject(AuthService);
  get initials(): string { return (this.auth.user()?.name || 'User').split(' ').map(part => part[0]).join('').slice(0, 2).toUpperCase(); }
  constructor(private readonly router: Router) {}
  isLogin(): boolean { return this.router.url.startsWith('/login') || this.router.url.startsWith('/register'); }
  logout(): void { this.auth.logout(); this.router.navigateByUrl('/login'); }
}
