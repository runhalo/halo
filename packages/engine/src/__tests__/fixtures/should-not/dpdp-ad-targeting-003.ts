// Fixture: dpdp-ad-targeting-003 — SHOULD NOT TRIGGER
function displayContent(items: any[]) {
  return items.map(item => ({
    title: item.name,
    description: item.summary
  }));
}
