// Fixture: gdpr-art8-child-profiling-003 — SHOULD TRIGGER
function buildAnalytics(user: any) {
  const childProfile = {
    interests: user.browsingHistory,
    segment: 'young_learner'
  };
  return childProfile;
}
