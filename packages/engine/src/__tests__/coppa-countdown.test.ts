import {
  getCoppaCountdown,
  formatCoppaCountdownCLI,
  formatCoppaCountdownMarkdown,
  formatCoppaCountdownPDF,
  COPPA_2_ENFORCEMENT_DATE,
  PENALTY_PER_VIOLATION_PER_DAY,
} from '../coppa-countdown';

describe('COPPA 2.0 Countdown', () => {
  describe('getCoppaCountdown', () => {
    it('returns days remaining before enforcement', () => {
      const march15 = new Date('2026-03-15T12:00:00Z');
      const cd = getCoppaCountdown(march15);
      expect(cd.days).toBe(38);
      expect(cd.isActive).toBe(false);
      expect(cd.message).toContain('38 days');
      expect(cd.message).toContain('April 22, 2026');
    });

    it('returns 1 day on April 21', () => {
      const april21 = new Date('2026-04-21T12:00:00Z');
      const cd = getCoppaCountdown(april21);
      expect(cd.days).toBe(1);
      expect(cd.isActive).toBe(false);
      expect(cd.message).toContain('1 day');
      // Should not say "1 days" (singular)
      expect(cd.message).not.toContain('1 days');
    });

    it('returns active on April 22', () => {
      const april22 = new Date('2026-04-22T12:00:00Z');
      const cd = getCoppaCountdown(april22);
      expect(cd.days).toBe(0);
      expect(cd.isActive).toBe(true);
      expect(cd.message).toContain('NOW IN EFFECT');
    });

    it('returns active after enforcement date', () => {
      const may1 = new Date('2026-05-01T12:00:00Z');
      const cd = getCoppaCountdown(may1);
      expect(cd.days).toBe(0);
      expect(cd.isActive).toBe(true);
    });

    it('includes penalty amount', () => {
      const cd = getCoppaCountdown();
      expect(cd.penaltyPerDay).toBe(53088);
    });

    it('includes enforcement date', () => {
      const cd = getCoppaCountdown();
      expect(cd.enforcementDate).toEqual(COPPA_2_ENFORCEMENT_DATE);
    });
  });

  describe('formatCoppaCountdownCLI', () => {
    it('includes penalty amount before enforcement', () => {
      const cd = getCoppaCountdown(new Date('2026-03-15T12:00:00Z'));
      const output = formatCoppaCountdownCLI(cd);
      expect(output).toContain('53,088');
      expect(output).toContain('38 days');
    });

    it('shows urgent message after enforcement', () => {
      const cd = getCoppaCountdown(new Date('2026-05-01T12:00:00Z'));
      const output = formatCoppaCountdownCLI(cd);
      expect(output).toContain('NOW IN EFFECT');
    });
  });

  describe('formatCoppaCountdownMarkdown', () => {
    it('returns markdown with blockquote', () => {
      const cd = getCoppaCountdown(new Date('2026-03-15T12:00:00Z'));
      const output = formatCoppaCountdownMarkdown(cd);
      expect(output).toContain('> ');
      expect(output).toContain('**COPPA 2.0');
      expect(output).toContain('38 day');
      expect(output).toContain('53,088');
    });

    it('shows active message after enforcement', () => {
      const cd = getCoppaCountdown(new Date('2026-05-01T12:00:00Z'));
      const output = formatCoppaCountdownMarkdown(cd);
      expect(output).toContain('NOW IN EFFECT');
    });
  });

  describe('formatCoppaCountdownPDF', () => {
    it('returns urgent severity when under 30 days', () => {
      const cd = getCoppaCountdown(new Date('2026-04-01T12:00:00Z'));
      const pdf = formatCoppaCountdownPDF(cd);
      expect(pdf.severity).toBe('urgent');
      expect(pdf.text).toContain('ENFORCEMENT IN');
    });

    it('returns warning severity when over 30 days', () => {
      const cd = getCoppaCountdown(new Date('2026-03-01T12:00:00Z'));
      const pdf = formatCoppaCountdownPDF(cd);
      expect(pdf.severity).toBe('warning');
    });

    it('returns active severity after enforcement', () => {
      const cd = getCoppaCountdown(new Date('2026-05-01T12:00:00Z'));
      const pdf = formatCoppaCountdownPDF(cd);
      expect(pdf.severity).toBe('active');
      expect(pdf.text).toContain('NOW IN EFFECT');
    });
  });

  describe('Constants', () => {
    it('enforcement date is April 22, 2026', () => {
      expect(COPPA_2_ENFORCEMENT_DATE.getUTCFullYear()).toBe(2026);
      expect(COPPA_2_ENFORCEMENT_DATE.getUTCMonth()).toBe(3); // 0-indexed: April = 3
      expect(COPPA_2_ENFORCEMENT_DATE.getUTCDate()).toBe(22);
    });

    it('penalty is $53,088 per violation per day', () => {
      expect(PENALTY_PER_VIOLATION_PER_DAY).toBe(53088);
    });
  });
});
