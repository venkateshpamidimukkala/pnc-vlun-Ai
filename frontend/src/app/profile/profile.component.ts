import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AuthService } from '../core/auth.service';

@Component({
  standalone: true,
  imports: [FormsModule],
  template: `<section class="page"><header class="page-header"><div><p class="eyebrow">Profile</p><h1>My profile</h1><p class="subtitle">Review your account and update your display name.</p></div></header><div class="two-column"><article class="panel"><h2>Account details</h2><label>Full name<input class="field full" [(ngModel)]="name" name="name"></label><label>Email<input class="field full" [value]="user?.email" disabled></label><button class="btn" (click)="save()" [disabled]="saving">{{saving ? 'Saving…' : 'Update profile'}}</button>@if(message){<p class="success">{{message}}</p>}@if(error){<p class="error">{{error}}</p>}</article><article class="panel"><h2>Access</h2><p><strong>Role:</strong> {{user?.role}}</p><p class="subtitle">Permissions assigned to this account</p><ul class="list-reset">@for (permission of user?.permissions || []; track permission) {<li class="list-row"><span>{{permission}}</span><span class="badge badge-success">Granted</span></li>}</ul></article></div></section>`,
  styles: [`.full{display:block;width:100%;margin:.4rem 0 1rem}.panel label{display:block;margin-bottom:.8rem;font-size:.8rem;font-weight:600}.success{color:var(--success);margin-top:1rem}.error{color:var(--danger);margin-top:1rem}`]
})
export class ProfileComponent {
  private readonly auth = inject(AuthService);
  user = this.auth.user(); name = this.user?.name || ''; saving = false; message = ''; error = '';
  save(): void { this.saving = true; this.message = ''; this.error = ''; this.auth.updateProfile(this.name).subscribe({ next: user => { this.user = user; this.name = user.name; this.message = 'Profile updated.'; this.saving = false; }, error: () => { this.error = 'Unable to update profile.'; this.saving = false; } }); }
}