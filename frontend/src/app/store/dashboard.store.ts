import { Injectable, signal } from '@angular/core';
import { ApiService, DashboardMetrics } from '../core/api.service';

@Injectable({providedIn:'root'})
export class DashboardStore {
  readonly metrics = signal<DashboardMetrics | null>(null);
  readonly loading = signal(false);
  constructor(private readonly api: ApiService) {}
  load(): void { this.loading.set(true); this.api.metrics().subscribe({next: value => this.metrics.set(value), error: () => this.metrics.set(null), complete: () => this.loading.set(false)}); }
}
