/**
 * Halo VS Code Extension — License Management
 *
 * Handles license key storage, validation, and tier-based feature gating.
 * License key stored in VS Code global state (persists across sessions).
 *
 * Free tier: Local regex scanning only (no scan limit in editor)
 * Pro+: Full scanning + upload results to cloud dashboard
 * Business/Enterprise: All features + org-wide settings
 */

import * as vscode from 'vscode';

const SUPABASE_URL = 'https://wrfwcmyxxbafcdvxlmug.supabase.co';
const LICENSE_KEY = 'halo.licenseKey';
const LICENSE_CACHE_KEY = 'halo.licenseCache';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export interface LicenseInfo {
  valid: boolean;
  tier: 'free' | 'pro' | 'business' | 'enterprise';
  email: string;
  status: string;
  cachedAt: number;
}

const FREE_LICENSE: LicenseInfo = {
  valid: true,
  tier: 'free',
  email: '',
  status: 'active',
  cachedAt: Date.now(),
};

/**
 * Get current license info (from cache or validate remotely)
 */
export async function getLicense(context: vscode.ExtensionContext): Promise<LicenseInfo> {
  const licenseKey = context.globalState.get<string>(LICENSE_KEY);

  if (!licenseKey) {
    return FREE_LICENSE;
  }

  // Check cache
  const cached = context.globalState.get<LicenseInfo>(LICENSE_CACHE_KEY);
  if (cached && (Date.now() - cached.cachedAt) < CACHE_TTL_MS) {
    return cached;
  }

  // Validate remotely
  try {
    const response = await fetch(`${SUPABASE_URL}/functions/v1/validate-license`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: licenseKey }),
    });

    const data = await response.json();

    const license: LicenseInfo = {
      valid: data.valid === true,
      tier: data.tier || 'free',
      email: data.email || '',
      status: data.status || 'unknown',
      cachedAt: Date.now(),
    };

    // Cache result
    await context.globalState.update(LICENSE_CACHE_KEY, license);

    if (!license.valid) {
      vscode.window.showWarningMessage(
        `Halo: License expired or invalid. Running in free mode.`,
        'Enter License Key'
      ).then(selection => {
        if (selection === 'Enter License Key') {
          vscode.commands.executeCommand('halo.activate');
        }
      });
      return FREE_LICENSE;
    }

    return license;
  } catch {
    // Network error — use cache if available, else free mode
    if (cached) return cached;
    return FREE_LICENSE;
  }
}

/**
 * Prompt user to enter license key
 */
export async function activateLicense(context: vscode.ExtensionContext): Promise<LicenseInfo> {
  const key = await vscode.window.showInputBox({
    prompt: 'Enter your Halo license key',
    placeHolder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
    password: false,
    validateInput: (value) => {
      if (!value) return 'License key is required';
      // Basic UUID format check
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
        return 'Invalid license key format (expected UUID)';
      }
      return null;
    }
  });

  if (!key) return FREE_LICENSE;

  // Validate
  try {
    const response = await fetch(`${SUPABASE_URL}/functions/v1/validate-license`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: key }),
    });

    const data = await response.json();

    if (!data.valid) {
      vscode.window.showErrorMessage(`Halo: Invalid license key. ${data.error || ''}`);
      return FREE_LICENSE;
    }

    // Store key
    await context.globalState.update(LICENSE_KEY, key);

    const license: LicenseInfo = {
      valid: true,
      tier: data.tier || 'pro',
      email: data.email || '',
      status: data.status || 'active',
      cachedAt: Date.now(),
    };

    await context.globalState.update(LICENSE_CACHE_KEY, license);

    const tierLabel = license.tier.charAt(0).toUpperCase() + license.tier.slice(1);
    vscode.window.showInformationMessage(
      `Halo: License activated! ${tierLabel} plan (${license.email})`
    );

    return license;
  } catch (err) {
    vscode.window.showErrorMessage('Halo: Failed to validate license key. Check your internet connection.');
    return FREE_LICENSE;
  }
}

/**
 * Clear stored license
 */
export async function deactivateLicense(context: vscode.ExtensionContext): Promise<void> {
  await context.globalState.update(LICENSE_KEY, undefined);
  await context.globalState.update(LICENSE_CACHE_KEY, undefined);
  vscode.window.showInformationMessage('Halo: License removed. Running in free mode.');
}

/**
 * Check if a feature is available for the current tier
 */
export function canUseFeature(license: LicenseInfo, feature: string): boolean {
  const TIER_FEATURES: Record<string, string[]> = {
    free: ['local_scan', 'quick_fix', 'explain_rule'],
    pro: ['local_scan', 'quick_fix', 'explain_rule', 'cloud_upload', 'ai_review', 'workspace_scan'],
    business: ['local_scan', 'quick_fix', 'explain_rule', 'cloud_upload', 'ai_review', 'workspace_scan', 'org_settings', 'api_keys'],
    enterprise: ['local_scan', 'quick_fix', 'explain_rule', 'cloud_upload', 'ai_review', 'workspace_scan', 'org_settings', 'api_keys', 'custom_rules', 'sso'],
  };

  const features = TIER_FEATURES[license.tier] || TIER_FEATURES.free;
  return features.includes(feature);
}
