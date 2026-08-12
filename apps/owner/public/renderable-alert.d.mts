/** Types for the browser alert validator public/renderable-alert.mjs (plain JS at runtime). */

export const RENDERABLE_ALERT_V1_LIMITS: { agentId: number; tool: number; summary: number };
export const RENDERABLE_ALERT_FORBIDDEN: RegExp;

export interface AlertViolation {
  field: "agentId" | "tool" | "summary" | "v" | "envelope";
  reason:
    | "malformed"
    | "unexpected-property"
    | "unsupported-version"
    | "not-a-string"
    | "too-long"
    | "forbidden-character";
}

export function validateRenderableAlert(alert: unknown): AlertViolation | null;
export function canonicalRenderableAlert(alert: unknown): string;
export function renderContentHash(alert: unknown): Promise<string>;
