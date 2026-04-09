// Fixture: aadc-dpia-017 — SHOULD TRIGGER
async function onboard(data: any) {
  const childProfile = await db.create(data);
  return childProfile;
}
