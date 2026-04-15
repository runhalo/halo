import {
  createTierContext,
  resolveTierFromKey,
  getUpgradeCTA,
  getTierComparison,
  HaloTier,
  TIER_LIMITS,
  TIER_FEATURES,
} from '../tier-context';

describe('TierContext', () => {
  describe('createTierContext', () => {
    const tiers: HaloTier[] = ['free', 'pro', 'business', 'enterprise'];

    it.each(tiers)('creates context for %s tier', (tier) => {
      const ctx = createTierContext(tier);
      expect(ctx.tier).toBe(tier);
      expect(ctx.limits).toBeDefined();
      expect(ctx.features).toBeDefined();
      expect(typeof ctx.can).toBe('function');
      expect(typeof ctx.withinLimit).toBe('function');
      expect(ctx.displayName).toBeTruthy();
    });
  });

  describe('Feature gating', () => {
    it('free tier cannot use aiReview', () => {
      const ctx = createTierContext('free');
      expect(ctx.can('aiReview')).toBe(false);
      expect(ctx.can('astAnalysis')).toBe(false);
      expect(ctx.can('pdfSummary')).toBe(false);
      expect(ctx.can('pdfAttestation')).toBe(false);
      expect(ctx.can('sarif')).toBe(false);
    });

    it('free tier always has coppa2Countdown', () => {
      const ctx = createTierContext('free');
      expect(ctx.can('coppa2Countdown')).toBe(true);
    });

    it('pro tier has aiReview but not pdfAttestation', () => {
      const ctx = createTierContext('pro');
      expect(ctx.can('aiReview')).toBe(true);
      expect(ctx.can('astAnalysis')).toBe(true);
      expect(ctx.can('pdfSummary')).toBe(true);
      expect(ctx.can('sarif')).toBe(true);
      expect(ctx.can('pdfAttestation')).toBe(false);
      expect(ctx.can('auditTrail')).toBe(false);
      expect(ctx.can('recurringScans')).toBe(false);
      expect(ctx.can('driftAlerts')).toBe(false);
    });

    it('business tier has attestation, recurring scans, drift alerts', () => {
      const ctx = createTierContext('business');
      expect(ctx.can('aiReview')).toBe(true);
      expect(ctx.can('pdfAttestation')).toBe(true);
      expect(ctx.can('recurringScans')).toBe(true);
      expect(ctx.can('driftAlerts')).toBe(true);
      expect(ctx.can('auditTrail')).toBe(true);
      expect(ctx.can('enforcementAlerts')).toBe(true);
      expect(ctx.can('multiRepo')).toBe(true);
      expect(ctx.can('roleBasedViews')).toBe(true);
      expect(ctx.can('scanDiff')).toBe(true);
      expect(ctx.can('complianceHistory')).toBe(true);
      expect(ctx.can('customRules')).toBe(false); // enterprise only
    });

    it('enterprise tier has everything including customRules', () => {
      const ctx = createTierContext('enterprise');
      const allFeatures = Object.keys(TIER_FEATURES.enterprise) as (keyof typeof TIER_FEATURES.enterprise)[];
      allFeatures.forEach(feature => {
        expect(ctx.can(feature)).toBe(true);
      });
    });

    it('every tier has coppa2Countdown', () => {
      const tiers: HaloTier[] = ['free', 'pro', 'business', 'enterprise'];
      tiers.forEach(tier => {
        expect(createTierContext(tier).can('coppa2Countdown')).toBe(true);
      });
    });
  });

  describe('Limit checking', () => {
    it('free tier has 5 scans/day limit', () => {
      const ctx = createTierContext('free');
      expect(ctx.withinLimit('scansPerDay', 4)).toBe(true);
      expect(ctx.withinLimit('scansPerDay', 5)).toBe(false);
      expect(ctx.withinLimit('scansPerDay', 10)).toBe(false);
    });

    it('pro tier has unlimited scans', () => {
      const ctx = createTierContext('pro');
      expect(ctx.withinLimit('scansPerDay', 999999)).toBe(true);
    });

    it('free tier limited to 1 repo', () => {
      const ctx = createTierContext('free');
      expect(ctx.withinLimit('repos', 0)).toBe(true);
      expect(ctx.withinLimit('repos', 1)).toBe(false);
    });

    it('business tier limited to 10 repos', () => {
      const ctx = createTierContext('business');
      expect(ctx.withinLimit('repos', 9)).toBe(true);
      expect(ctx.withinLimit('repos', 10)).toBe(false);
    });

    it('free tier has 25 rules', () => {
      const ctx = createTierContext('free');
      expect(ctx.limits.rulesAvailable).toBe(25);
    });

    it('pro/business/enterprise have 26 rules', () => {
      expect(createTierContext('pro').limits.rulesAvailable).toBe(26);
      expect(createTierContext('business').limits.rulesAvailable).toBe(26);
      expect(createTierContext('enterprise').limits.rulesAvailable).toBe(26);
    });
  });

  describe('resolveTierFromKey', () => {
    it('returns free tier for undefined key', async () => {
      const ctx = await resolveTierFromKey(undefined);
      expect(ctx.tier).toBe('free');
    });

    it('returns free tier for empty key', async () => {
      const ctx = await resolveTierFromKey('');
      expect(ctx.tier).toBe('free');
    });

    it('parses tier from key format', async () => {
      const ctx = await resolveTierFromKey('halo_pro_abc123');
      expect(ctx.tier).toBe('pro');
    });

    it('parses business tier from key format', async () => {
      const ctx = await resolveTierFromKey('halo_business_xyz789');
      expect(ctx.tier).toBe('business');
    });

    it('defaults to free for unrecognized key format', async () => {
      const ctx = await resolveTierFromKey('some_random_key');
      expect(ctx.tier).toBe('free');
    });

    it('uses custom validation function when provided', async () => {
      const validate = async (_key: string): Promise<HaloTier> => 'enterprise';
      const ctx = await resolveTierFromKey('any-key', validate);
      expect(ctx.tier).toBe('enterprise');
    });

    it('falls back to free tier when validation function throws', async () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const validate = async (): Promise<HaloTier> => { throw new Error('Network timeout'); };
      const ctx = await resolveTierFromKey('any-key', validate);
      expect(ctx.tier).toBe('free');
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('[TierContext]'),
        expect.any(Error)
      );
      warnSpy.mockRestore();
    });
  });

  describe('getUpgradeCTA', () => {
    it('returns Pro upgrade for free tier', () => {
      const cta = getUpgradeCTA('free');
      expect(cta).toContain('Pro');
      expect(cta).toContain('$29');
    });

    it('returns Business upgrade for pro tier', () => {
      const cta = getUpgradeCTA('pro');
      expect(cta).toContain('Business');
      expect(cta).toContain('$99');
    });

    it('returns Enterprise upgrade for business tier', () => {
      const cta = getUpgradeCTA('business');
      expect(cta).toContain('enterprise');
    });

    it('returns null for enterprise tier', () => {
      expect(getUpgradeCTA('enterprise')).toBeNull();
    });
  });

  describe('getTierComparison', () => {
    it('returns all 4 tiers', () => {
      const comparison = getTierComparison();
      expect(comparison.tiers).toEqual(['free', 'pro', 'business', 'enterprise']);
    });

    it('includes all features', () => {
      const comparison = getTierComparison();
      expect(comparison.features.length).toBeGreaterThan(10);
      comparison.features.forEach(f => {
        expect(f.name).toBeTruthy();
        expect(f.key).toBeTruthy();
        expect(f.values.free).toBeDefined();
        expect(f.values.pro).toBeDefined();
        expect(f.values.business).toBeDefined();
        expect(f.values.enterprise).toBeDefined();
      });
    });

    it('includes prices', () => {
      const comparison = getTierComparison();
      expect(comparison.prices.free).toBe('$0');
      expect(comparison.prices.pro).toBe('$29/mo');
      expect(comparison.prices.business).toBe('$99/mo');
      expect(comparison.prices.enterprise).toBe('Custom');
    });
  });
});
