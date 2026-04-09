// Fixture: dpdp-behavioral-monitoring-004 — SHOULD NOT TRIGGER
import { Logger } from './logger';
const requestLogger = new Logger('http');
requestLogger.info('Request processed');
