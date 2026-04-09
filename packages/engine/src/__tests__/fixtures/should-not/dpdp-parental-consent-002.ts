// Fixture: dpdp-parental-consent-002 — SHOULD NOT TRIGGER
function checkAccess(yearsOfExperience: number) {
  if (yearsOfExperience < 5) {
    return { level: 'junior' };
  }
  return { level: 'senior' };
}
