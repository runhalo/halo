// Fixture: pipa-parental-consent-001 — SHOULD NOT TRIGGER
// "guardian" must appear on the same line as `userAge < 13` so the negative lookahead sees it
function checkAccess(userAge: number, guardianApproved: boolean) {
  if (userAge < 13 && !guardianApproved) {
    return requireParentalGuardianConsent();
  }
}
