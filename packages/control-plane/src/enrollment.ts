/**
 * The enrolment spend path's stable import path. The IMPLEMENTATION lives
 * inside invite.ts — the SAME module as the InviteStore — because the burn
 * is an ECMAScript #private method whose only accessor is module-scoped:
 * any design that hands a spend capability across a module boundary (an
 * exported brand, a claim-once minter) is a first-import race, not an
 * exclusive capability. See invite.ts's file header for the full argument.
 */
export { performEnrollment } from "./invite.js";
export type { EnrollmentOutcome, PerformEnrollmentOptions } from "./invite.js";
