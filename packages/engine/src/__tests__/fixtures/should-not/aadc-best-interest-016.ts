// Fixture: aadc-best-interest-016 — SHOULD NOT TRIGGER
// Purchase with child safety check
async function inAppPurchase(itemId: string, price: number) {
  if (isChild(currentUser)) return { blocked: true };
  const isMinor = checkAge(currentUser);
  if (isMinor) return { blocked: true };
  return await paymentGateway.process(itemId, price);
}
