// Fixture: aadc-best-interest-016 — SHOULD TRIGGER
async function inAppPurchase(itemId: string, price: number) {
  const transaction = await paymentGateway.process(itemId, price);
  return transaction;
}
