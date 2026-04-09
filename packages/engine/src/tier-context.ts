/**
 * TierContext — 4-tier feature gating for Halo 2.0
 *
 * Every output surface (CLI, GitHub Action, PDF, dashboard, API)
 * queries tier permissions from this single source.
 *
 * Don't Go Backwards Rule: TierContext is the ONLY way to gate features.
 * No scattered if-statements. One place to update, one place to test, one place to audit.
 */

export type HaloTier = 'free' | 'pro' | 'business' | 'enterprise';

export interface TierLimits {
  scansPerDay: number;
  repos: number;
  seats: number;
  rulesAvailable: number;
  aiReviewBudgetPerRepo: number; // monthly $ cap, 0 = disabled, Infinity = unlimited
}

export interface TierFeatures {
  aiReview: boolean;
  astAnalysis: boolean;
  pdfSummary: boolean;
  pdfAttestation: boolean;
  sarif: boolean;
  recurringScans: boolean;
  driftAlerts: boolean;
  auditTrail: boolean;
  enforcementAlerts: boolean;
  dashboardTrend: boolean;
  multiRepo: boolean;
  roleBasedViews: boolean;
  customRules: boolean;
  coppa2Countdown: boolean;
  scanDiff: boolean;
  complianceHistory: boolean;
}

export interface TierContext {
  tier: HaloTier;
  limits: TierLimits;
  features: TierFeatures;
  /** Check if a feature is available in this tier */
  can(feature: keyof TierFeatures): boolean;
  /** Check if a limit hasn't been exceeded */
  withinLimit(limit: keyof TierLimits, current: number): boolean;
  /** Human-readable tier name for display */
  displayName: string;
}

/* ── Tier Definitions ──────────────────────────────────── */

const TIER_LIMITS: Record<HaloTier, TierLimits> = {
  free: {
    scansPerDay: 5,
    repos: 1,
    seats: 1,
    rulesAvailable: 25,
    aiReviewBudgetPerRepo: 0,
  },
  pro: {
    scansPerDay: Infinity,
    repos: 3,
    seats: 3,
    rulesAvailable: 160,
    aiReviewBudgetPerRepo: 5,
  },
  business: {
    scansPerDay: Infinity,
    repos: 10,
    seats: 5,
    rulesAvailable: 160,
    aiReviewBudgetPerRepo: 15,
  },
  enterprise: {
    scansPerDay: Infinity,
    repos: Infinity,
    seats: Infinity,
    rulesAvailable: 160,
    aiReviewBudgetPerRepo: Infinity,
  },
};

const TIER_FEATURES: Record<HaloTier, TierFeatures> = {
  free: {
    aiReview: false,
    astAnalysis: false,
    pdfSummary: false,
    pdfAttestation: false,
    sarif: false,
    recurringScans: false,
    driftAlerts: false,
    auditTrail: false,
    enforcementAlerts: false,
    dashboardTrend: false,
    multiRepo: false,
    roleBasedViews: false,
    customRules: false,
    coppa2Countdown: true,
    scanDiff: false,
    complianceHistory: false,
  },
  pro: {
    aiReview: true,
    astAnalysis: true,
    pdfSummary: true,
    pdfAttestation: false,
    sarif: true,
    recurringScans: false,
    driftAlerts: false,
    auditTrail: false,
    enforcementAlerts: false,
    dashboardTrend: true,
    multiRepo: false,
    roleBasedViews: false,
    customRules: false,
    coppa2Countdown: true,
    scanDiff: false,
    complianceHistory: false,
  },
  business: {
    aiReview: true,
    astAnalysis: true,
    pdfSummary: true,
    pdfAttestation: true,
    sarif: true,
    recurringScans: true,
    driftAlerts: true,
    auditTrail: true,
    enforcementAlerts: true,
    dashboardTrend: true,
    multiRepo: true,
    roleBasedViews: true,
    customRules: false,
    coppa2Countdown: true,
    scanDiff: true,
    complianceHistory: true,
  },
  enterprise: {
    aiReview: true,
    astAnalysis: true,
    pdfSummary: true,
    pdfAttestation: true,
    sarif: true,
    recurringScans: true,
    driftAlerts: true,
    auditTrail: true,
    enforcementAlerts: true,
    dashboardTrend: true,
    multiRepo: true,
    roleBasedViews: true,
    customRules: true,
    coppa2Countdown: true,
    scanDiff: true,
    complianceHistory: true,
  },
};

const TIER_DISPLAY_NAMES: Record<HaloTier, string> = {
  free: 'Free',
  pro: 'Pro',
  business: 'Business',
  enterprise: 'Enterprise',
};

/* ── Factory ───────────────────────────────────────────── */

/**
 * Create a TierContext for a given tier.
 * All feature/limit checks go through this object.
 */
export function createTierContext(tier: HaloTier): TierContext {
  const limits = TIER_LIMITS[tier];
  const features = TIER_FEATURES[tier];

  return {
    tier,
    limits,
    features,
    displayName: TIER_DISPLAY_NAMES[tier],

    can(feature: keyof TierFeatures): boolean {
      return features[feature] === true;
    },

    withinLimit(limit: keyof TierLimits, current: number): boolean {
      const max = limits[limit];
      if (max === Infinity) return true;
      return current < max;
    },
  };
}

/* ── Resolution ────────────────────────────────────────── */

/**
 * Resolve tier from a license key string.
 * Fails gracefully to free tier on any error (network, expired, invalid).
 * Don't Go Backwards Rule: Never error. Never block the scan.
 */
export async function resolveTierFromKey(
  licenseKey: string | undefined,
  validateFn?: (key: string) => Promise<HaloTier>
): Promise<TierContext> {
  if (!licenseKey) return createTierContext('free');

  try {
    if (validateFn) {
      const tier = await validateFn(licenseKey);
      return createTierContext(tier);
    }
    // If no validation function provided, parse the key format
    // Key format: halo_{tier}_{uuid} (e.g., halo_pro_abc123)
    const tierMatch = licenseKey.match(/^halo_(free|pro|business|enterprise)_/);
    if (tierMatch) {
      return createTierContext(tierMatch[1] as HaloTier);
    }
    // Unrecognized key format — default to free
    console.warn('[TierContext] Unrecognized license key format, defaulting to free');
    return createTierContext('free');
  } catch (err) {
    console.warn('[TierContext] License validation failed, defaulting to free:', err);
    return createTierContext('free');
  }
}

/* ── Utilities ─────────────────────────────────────────── */

/**
 * Get the upgrade CTA message for a given tier.
 * Used by CLI, GitHub Action comments, and PDF footers.
 */
export function getUpgradeCTA(currentTier: HaloTier): string | null {
  switch (currentTier) {
    case 'free':
      return 'Upgrade to Pro ($29/mo) for AI-verified compliance results → runhalo.dev/pricing';
    case 'pro':
      return 'Upgrade to Business ($99/mo) for compliance attestation, recurring scans, and audit trail → runhalo.dev/pricing';
    case 'business':
      return 'Need custom rules, unlimited repos, or SLA support? → runhalo.dev/enterprise';
    case 'enterprise':
      return null; // No upsell for enterprise
  }
}

/**
 * Get the tier comparison table as structured data.
 * Used by pricing pages, upgrade modals, and help output.
 */
export function getTierComparison(): {
  tiers: HaloTier[];
  features: { name: string; key: keyof TierFeatures; values: Record<HaloTier, boolean> }[];
  limits: { name: string; key: keyof TierLimits; values: Record<HaloTier, string> }[];
  prices: Record<HaloTier, string>;
} {
  const tiers: HaloTier[] = ['free', 'pro', 'business', 'enterprise'];

  const featureNames: Record<keyof TierFeatures, string> = {
    aiReview: 'AI Review Board',
    astAnalysis: 'AST Structural Analysis',
    pdfSummary: 'PDF Summary Report',
    pdfAttestation: 'Compliance Attestation PDF',
    sarif: 'SARIF Output',
    recurringScans: 'Scheduled Recurring Scans',
    driftAlerts: 'Compliance Drift Alerts',
    auditTrail: 'Immutable Audit Trail',
    enforcementAlerts: 'Enforcement Intelligence Alerts',
    dashboardTrend: 'Compliance Trend Charts',
    multiRepo: 'Multi-Repo Workspace',
    roleBasedViews: 'Role-Based Views',
    customRules: 'Custom Rules',
    coppa2Countdown: 'COPPA 2.0 Countdown',
    scanDiff: 'PR Scan Diff',
    complianceHistory: 'Compliance History',
  };

  return {
    tiers,
    features: (Object.keys(featureNames) as (keyof TierFeatures)[]).map(key => ({
      name: featureNames[key],
      key,
      values: Object.fromEntries(tiers.map(t => [t, TIER_FEATURES[t][key]])) as Record<HaloTier, boolean>,
    })),
    limits: [
      { name: 'Scans per day', key: 'scansPerDay' as keyof TierLimits, values: { free: '5', pro: 'Unlimited', business: 'Unlimited', enterprise: 'Unlimited' } },
      { name: 'Repositories', key: 'repos' as keyof TierLimits, values: { free: '1', pro: '3', business: '10', enterprise: 'Unlimited' } },
      { name: 'Team seats', key: 'seats' as keyof TierLimits, values: { free: '1', pro: '3', business: '5', enterprise: 'Unlimited' } },
      { name: 'Rules available', key: 'rulesAvailable' as keyof TierLimits, values: { free: '25 COPPA', pro: 'All 160', business: 'All 160', enterprise: 'All + Custom' } },
    ],
    prices: { free: '$0', pro: '$29/mo', business: '$99/mo', enterprise: 'Custom' },
  };
}

/* ── Constants Export ───────────────────────────────────── */

export { TIER_LIMITS, TIER_FEATURES, TIER_DISPLAY_NAMES };
