// Fixture: gdpr-art8-age-gate-001 — SHOULD NOT TRIGGER
// Dynamic age threshold with region-based routing
function checkAccess(user: any, region: string) {
  const threshold = getAgeThresholdForRegion(region);
  if (user.age < threshold) {
    return { allowed: false };
  }
  return { allowed: true };
}
