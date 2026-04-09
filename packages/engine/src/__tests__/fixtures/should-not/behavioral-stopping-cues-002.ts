// Fixture: behavioral-stopping-cues-002 — SHOULD NOT TRIGGER
async function loadContent(cursor: string) {
  const items = await fetchNextPage(cursor, { limit: 20, maxPages: 5 });
  return items;
}
