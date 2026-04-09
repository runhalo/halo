// Fixture: aadc-dpia-017 — SHOULD NOT TRIGGER
async function onboard(data: any) {
  const childProfile = await db.create(data);
  // DPIA reference: see data_protection_impact assessment doc #DP-2026-003
  const dpia = await loadDPIA('DP-2026-003');
  return childProfile;
}
