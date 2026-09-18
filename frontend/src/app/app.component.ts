import { Component, inject } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from './core/auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
  @if (!isLogin()) {
    <header class="topbar">
      <a class="brand" routerLink="/dashboard" aria-label="Vuln AI dashboard">
        <span class="brand-mark">PNC</span>
        <strong>Vuln AI</strong>
      </a>
      <label class="portal-search">
        <span class="material-icons" aria-hidden="true">search</span>
        <input type="search" placeholder="Search vulnerability, repository..." aria-label="Search vulnerability or repository" />
      </label>
      <div class="top-actions">
        <span class="environment">DEV</span>
        <span class="avatar">{{ initials }}</span>
        <button class="logout" (click)="logout()" aria-label="Sign out">Sign Out</button>
      </div>
    </header>
    <div class="shell" [class.collapsed]="collapsed">
      <nav class="sidebar" aria-label="Primary navigation">
        <button class="nav-toggle" type="button" (click)="collapsed = !collapsed" [attr.aria-expanded]="!collapsed" aria-controls="primary-navigation">
          <span class="material-icons" aria-hidden="true">{{ collapsed ? 'menu' : 'close' }}</span>
          <span class="nav-toggle-label">{{ collapsed ? 'Expand navigation' : 'Collapse navigation' }}</span>
        </button>
        <div id="primary-navigation" class="nav-links">
        <a routerLink="/dashboard" routerLinkActive="active" title="Dashboard"><span class="material-icons">dashboard</span><span>Dashboard</span></a>
        <a routerLink="/executive" routerLinkActive="active" title="Executive"><span class="material-icons">analytics</span><span>Executive</span></a>
        <a routerLink="/execute" routerLinkActive="active" title="Scan Code Base"><span class="material-icons">folder_scan</span><span>Scan Code Base</span></a>
        <a routerLink="/security" routerLinkActive="active" title="Security"><span class="material-icons">shield</span><span>Security</span></a>
        <a routerLink="/developer" routerLinkActive="active" title="Developer"><span class="material-icons">code</span><span>Developer</span></a>
        <p class="nav-label">Management</p>
        <a routerLink="/applications" routerLinkActive="active" title="Applications"><span class="material-icons">apps</span><span>Applications</span></a>
        <a routerLink="/vulnerabilities" routerLinkActive="active" title="Vulnerabilities"><span class="material-icons">bug_report</span><span>Vulnerabilities</span></a>
        <a routerLink="/remediation" routerLinkActive="active" title="Remediation"><span class="material-icons">build</span><span>Remediation</span></a>
        <a routerLink="/pull-requests" routerLinkActive="active" title="Pull Requests"><span class="material-icons">merge</span><span>Pull Requests</span></a>
        <a routerLink="/test-case-validation" routerLinkActive="active" title="Test Case Validation"><span class="material-icons">fact_check</span><span>Test Case Validation</span></a>
         @if (auth.hasPermission('USER_ADMINISTRATION')) {
           <p class="nav-label">Administration</p>
           <a routerLink="/administration/users" routerLinkActive="active" title="User Administration"><span class="material-icons">manage_accounts</span><span>User Administration</span></a>
         }
         <p class="nav-label">Profile</p>
         <a routerLink="/profile" routerLinkActive="active" title="Profile"><span class="material-icons">person</span><span>Profile</span></a>
        </div>
      </nav>
      <main><router-outlet /></main>
    </div>
    <footer>PNC Vuln AI <span>Secure by design · © 2026 PNC</span></footer>
  } @else { <router-outlet /> }
`,
  styleUrl: './app.component.scss'
})
export class AppComponent {
  readonly auth = inject(AuthService);
  collapsed = false;
  get initials(): string { return (this.auth.user()?.name || 'User').split(' ').map(part => part[0]).join('').slice(0, 2).toUpperCase(); }
  constructor(private readonly router: Router) {}
  isLogin(): boolean { return this.router.url.startsWith('/login') || this.router.url.startsWith('/register'); }
  logout(): void { this.auth.logout(); this.router.navigateByUrl('/login'); }
}