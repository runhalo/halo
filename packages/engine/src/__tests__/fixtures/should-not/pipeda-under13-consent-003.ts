// Fixture: pipeda-under13-consent-003 — SHOULD NOT TRIGGER
async function createAccount(email: string, parentVerification: string) {
  const user = await db.users.insert({ email, parentVerified: true });
  return user;
}
