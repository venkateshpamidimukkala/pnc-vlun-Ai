import { HttpInterceptorFn } from '@angular/common/http';

export const authInterceptor: HttpInterceptorFn = (request, next) => {
  const storedUser = readStoredUser();
  const tenantId = localStorage.getItem('pnc.tenantId') || storedUser?.tenant_id;
  const userId = localStorage.getItem('pnc.userId') || storedUser?.user_id;
  const role = localStorage.getItem('pnc.role') || storedUser?.role;
  const headers: Record<string, string> = {};
  if (tenantId) headers['X-Tenant-ID'] = tenantId;
  if (userId) headers['X-User-ID'] = userId;
  if (role) headers['X-User-Role'] = role;
  return next(request.clone({ setHeaders: headers }));
};

interface StoredUser {
  user_id?: string;
  tenant_id?: string;
  role?: string;
}

function readStoredUser(): StoredUser | null {
  const value = localStorage.getItem('pnc.auth');
  if (!value) return null;
  try {
    return JSON.parse(value) as StoredUser;
  } catch {
    return null;
  }
}
