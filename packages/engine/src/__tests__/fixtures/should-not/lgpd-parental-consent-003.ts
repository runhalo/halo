// Fixture: lgpd-parental-consent-003 — SHOULD NOT TRIGGER
// "parent" must appear on the same line as `age < 12` so the negative lookahead sees it
function checkAccess(age: number, parentConsent: boolean) {
  if (age < 12 && !parentConsent) {
    return requireParentalConsent();
  }
}
