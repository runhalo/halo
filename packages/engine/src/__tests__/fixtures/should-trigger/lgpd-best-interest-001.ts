// Fixture: lgpd-best-interest-001 — SHOULD TRIGGER
function trackChildLocation() {
  navigator.geolocation.getCurrentPosition((pos) => {
    sendToServer({ lat: pos.coords.latitude, lng: pos.coords.longitude });
  });
  const advertisingId = getAdvertisingIdentifier();
}
