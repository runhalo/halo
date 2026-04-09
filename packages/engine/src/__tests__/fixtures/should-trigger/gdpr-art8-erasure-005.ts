// Fixture: gdpr-art8-erasure-005 — SHOULD TRIGGER
async function handleDeleteRequest(userId: string) {
  const archiveDeleted = true;
  await db.users.update(userId, { status: 'archived', retainAfterDelete: true });
}
