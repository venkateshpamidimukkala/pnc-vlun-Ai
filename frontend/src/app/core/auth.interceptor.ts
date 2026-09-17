import { HttpInterceptorFn } from '@angular/common/http';

export const authInterceptor: HttpInterceptorFn = (request, next) => {
  const tenantId = localStorage.getItem('pnc.tenantId');
  const userId = localStorage.getItem('pnc.userId');
  const role = localStorage.getItem('pnc.role');
  const headers: Record<string, string> = {};
  if (tenantId) headers['X-Tenant-ID'] = tenantId;
  if (userId) headers['X-User-ID'] = userId;
  if (role) headers['X-User-Role'] = role;
  return next(request.clone({ setHeaders: headers }));
};
