import { Component, inject } from '@angular/core';
import { AuthService, AuthUser, Role } from '../core/auth.service';

@Component({
  standalone: true,
  template: `<section class="page"><header class="page-header"><div><p class="eyebrow">Administration</p><h1>User administration</h1><p class="subtitle">Review registered users and manage their roles and permissions.</p></div><button class="btn" (click)="load()">Refresh users</button></header><article class="panel table-wrap"><table class="data-table"><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Permissions</th><th>Status</th></tr></thead><tbody>@for (item of users; track item.user_id) {<tr><td>{{item.name}}</td><td>{{item.email}}</td><td><select class="field" [value]="item.role" (change)="changeRole(item, $any($event.target).value)"><option value="SECURITY_ANALYST">Security Analyst</option><option value="SECURITY_REVIEWER">Security Reviewer</option><option value="PLATFORM_ADMIN">Platform Admin</option></select></td><td>{{item.permissions.join(', ')}}</td><td><span class="badge badge-success">Active</span></td></tr>}</tbody></table>@if(error){<p class="error">{{error}}</p>}</article></section>`,
  styles: [`.error{color:var(--danger);margin-top:1rem}`]
})
export class UsersComponent {
  private readonly auth = inject(AuthService); users: AuthUser[] = []; error = '';
  constructor() { this.load(); }
  load(): void { this.auth.users().subscribe({ next: users => this.users = users, error: () => this.error = 'Unable to load users.' }); }
  changeRole(user: AuthUser, role: Role): void { this.auth.updateUserRole(user.user_id, role).subscribe({ next: updated => Object.assign(user, updated), error: () => this.error = 'Unable to update role.' }); }
}