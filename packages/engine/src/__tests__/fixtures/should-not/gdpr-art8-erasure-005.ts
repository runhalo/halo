// Fixture: gdpr-art8-erasure-005 — SHOULD NOT TRIGGER
async function handleRequest(userId: string) {
  await db.users.update(userId, { status: 'active' });
}
