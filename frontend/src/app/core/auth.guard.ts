import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { AuthService, Role } from './auth.service';

export const authGuard: CanActivateFn = (route) => {
  const auth = inject(AuthService);
  if (!auth.isAuthenticated()) return inject(Router).createUrlTree(['/login']);
  const roles = route.data['roles'] as Role[] | undefined;
  if (roles && !auth.hasRole(roles)) return inject(Router).createUrlTree(['/dashboard']);
  return true;
};
