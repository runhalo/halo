// Fixture: lgpd-parental-consent-003 — SHOULD TRIGGER
function checkChildAccess(age: number) {
  if (age < 12) {
    return { blocked: true, reason: 'too_young' };
  }
}
