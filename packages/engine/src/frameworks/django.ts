/**
 * Django Framework Profile
 *
 * Django provides built-in protections that overlap with several COPPA rules:
 * - Template engine auto-escapes all variables by default
 * - SecurityMiddleware enforces HTTPS when configured
 * - Built-in password validators enforce complexity requirements
 * - django-lifecycle and django-reversion can handle data retention externally
 */

import { FrameworkProfile } from './types';

export const djangoProfile: FrameworkProfile = {
  id: 'django',
  name: 'Django',
  ecosystem: 'python',
  handled_rules: [
    {
      rule_id: 'coppa-sec-015',
      action: 'suppress',
      reason: 'Django templates auto-escape all variables by default.',
      documentation_url: 'https://docs.djangoproject.com/en/stable/ref/templates/language/#automatic-html-escaping',
    },
    {
      rule_id: 'coppa-retention-005',
      action: 'downgrade',
      downgrade_to: 'low',
      reason: 'Django models with django-lifecycle or django-reversion may handle retention externally.',
      documentation_url: 'https://docs.djangoproject.com/en/stable/topics/db/models/',
    },
    {
      rule_id: 'coppa-sec-006',
      action: 'suppress',
      reason: 'Django SecurityMiddleware enforces HTTPS when configured.',
      documentation_url: 'https://docs.djangoproject.com/en/stable/ref/middleware/#module-django.middleware.security',
    },
    {
      rule_id: 'coppa-sec-010',
      action: 'suppress',
      reason: 'Django built-in password validators enforce complexity.',
      documentation_url: 'https://docs.djangoproject.com/en/stable/topics/auth/passwords/#module-django.contrib.auth.password_validation',
    },
  ],
  safe_patterns: [
    {
      description: 'Django CSRF middleware for cross-site request forgery protection',
      patterns: [/CsrfViewMiddleware/, /csrf_token/],
      applies_to_rules: ['coppa-sec-015'],
    },
    {
      description: 'Django admin interface with built-in auth and access controls',
      patterns: [/admin\.site\.register/, /class.*Admin\(/, /admin\.py/],
      applies_to_rules: ['coppa-auth-001', 'coppa-ui-008', 'coppa-default-020'],
    },
  ],
};
