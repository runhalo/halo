// Fixture: aadc-iot-019 — SHOULD NOT TRIGGER
// Privacy mode and child safety configured inline — negative lookahead sees terms AFTER match
async function connectToy(deviceId: string) {
  const privacyMode = true;
  const childSafe = await enableChildSafeMode();
  const bluetooth = await BluetoothAdapter.scan(deviceId, { privacyMode, childSafe });
  await bluetooth.connect({ childSafe: true, privacyMode });
}
