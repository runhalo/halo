// Fixture: dpdp-behavioral-monitoring-004 — SHOULD TRIGGER
import { Hotjar } from 'hotjar';
const sessionReplay = { enabled: true, sampleRate: 0.5 };
Hotjar.init(12345, 6);
