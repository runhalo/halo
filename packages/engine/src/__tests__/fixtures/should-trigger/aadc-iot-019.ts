// Fixture: aadc-iot-019 — SHOULD TRIGGER
async function connectToy(deviceId: string) {
  const bluetooth = await BluetoothAdapter.scan(deviceId);
  await bluetooth.connect();
  const mqttClient = new MQTT.Client('toy.example.com');
  await mqttClient.publish('sensor/data', payload);
}
