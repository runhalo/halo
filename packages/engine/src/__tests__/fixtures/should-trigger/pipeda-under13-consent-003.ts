// Fixture: pipeda-under13-consent-003 — SHOULD TRIGGER
// Child account creation without parental consent
async function createAccount(email: string, age: number) { // child under 13 registration
  const user = await db.users.insert({ email, age });
  return user;
}
