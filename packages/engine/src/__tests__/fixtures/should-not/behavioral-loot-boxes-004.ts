// Fixture: behavioral-loot-boxes-004 — SHOULD NOT TRIGGER
function selectReward(level: number) {
  const rewards = ['badge', 'certificate', 'sticker'];
  return rewards[level % rewards.length];
}
