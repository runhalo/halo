// Fixture: dpdp-parental-consent-002 — SHOULD TRIGGER
function checkConsent(userAge: number) {
  if (userAge < 16) {
    return { needsConsent: true, type: 'standard' };
  }
}
