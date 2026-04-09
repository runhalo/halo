// Fixture: gdpr-art8-age-gate-001 — SHOULD TRIGGER
// Hardcoded age 13 without EU member-state geo-routing
const minimumAge = 13;
function checkAccess(user: any) {
  if (user.age < 13) {
    return { allowed: false, reason: 'underage' };
  }
  return { allowed: true };
}
