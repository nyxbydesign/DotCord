/** Null is an explicit continuous deadline, never a numeric sentinel. */
export type Deadline = number | null;
export const deadlineActive = (until: Deadline, now = Date.now()): boolean => until === null || Number.isFinite(until) && until > now;
export const deadlineFrom = (until: string | null): Deadline => until === null ? null : Date.parse(until);
export const deadlineIso = (until: Deadline): string | null => until === null ? null : new Date(until).toISOString();
export const earlierDeadline = (a: Deadline, b: Deadline): Deadline => a === null ? b : b === null ? a : Math.min(a,b);
