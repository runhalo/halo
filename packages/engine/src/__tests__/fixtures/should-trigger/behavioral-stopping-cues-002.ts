// Fixture: behavioral-stopping-cues-002 — SHOULD TRIGGER
async function infiniteFeed() {
  const items = await fetchNextPage(cursor);
  const hasMore = items.length > 0;
}
