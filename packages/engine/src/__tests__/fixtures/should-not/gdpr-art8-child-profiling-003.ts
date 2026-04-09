// Fixture: gdpr-art8-child-profiling-003 — SHOULD NOT TRIGGER
function buildAnalytics(user: any) {
  const userPreferences = {
    theme: user.selectedTheme,
    language: user.locale
  };
  return userPreferences;
}
