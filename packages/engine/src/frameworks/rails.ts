/**
 * Ruby on Rails Framework Profile
 *
 * Rails provides built-in protections that overlap with several COPPA rules:
 * - ERB templates auto-escape all output by default
 * - Strong parameters filter mass assignment (mitigates PII leaks)
 * - ActiveRecord supports soft delete via acts_as_paranoid or discard gem
 * - force_ssl config enforces HTTPS application-wide
 */

import { FrameworkProfile } from './types';

export const railsProfile: FrameworkProfile = {
  id: 'rails',
  name: 'Ruby on Rails',
  ecosystem: 'ruby',
  handled_rules: [
    {
      rule_id: 'coppa-sec-015',
      action: 'suppress',
      reason: 'ERB templates auto-escape all output by default.',
      documentation_url: 'https://guides.rubyonrails.org/security.html#cross-site-scripting-xss',
    },
    {
      rule_id: 'coppa-data-002',
      action: 'downgrade',
      downgrade_to: 'low',
      reason: 'Rails strong parameters filter mass assignment.',
      documentation_url: 'https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters',
    },
    {
      rule_id: 'coppa-retention-005',
      action: 'downgrade',
      downgrade_to: 'low',
      reason: 'ActiveRecord supports soft delete via acts_as_paranoid or discard gem.',
      documentation_url: 'https://github.com/jhawthorn/discard',
    },
    {
      rule_id: 'coppa-sec-006',
      action: 'suppress',
      reason: 'Rails force_ssl config enforces HTTPS.',
      documentation_url: 'https://guides.rubyonrails.org/configuring.html#config-force-ssl',
    },
  ],
  safe_patterns: [
    {
      description: 'Rails CSRF protection via protect_from_forgery and authenticity tokens',
      patterns: [/protect_from_forgery/, /authenticity_token/],
      applies_to_rules: ['coppa-sec-015'],
    },
    {
      description: 'Rails ActiveRecord encryption for sensitive attributes',
      patterns: [/encrypts\s+:/, /has_encrypted/],
      applies_to_rules: ['coppa-sec-006'],
    },
  ],
};
