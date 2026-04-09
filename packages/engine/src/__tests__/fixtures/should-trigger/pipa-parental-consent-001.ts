// Fixture: pipa-parental-consent-001 — SHOULD TRIGGER
function checkKoreaAccess(userAge: number) {
  if (userAge < 13) {
    return false;
  }
}
