/** Types for public/workspace-core.mjs (plain JS at runtime). */

export const DEFAULT_VETO_WINDOW_MS: number;

export function isSafeId(value: unknown): boolean;

export type KillViewState = "armed" | "killed" | "unreachable";

export interface KillView {
  state: KillViewState;
  badge: "ARMED" | "KILLED" | "UNREACHABLE";
  /** unreachable AND killed render with the stopped visuals */
  treatAsKilled: boolean;
  epoch: number | null;
  scopedKills: string[];
  warnings: string[];
  detail: string;
}

export function classifyKillState(reading: unknown): KillView;

export function formatCountdown(msRemaining: number): string;

export interface Countdown {
  msRemaining: number;
  label: string;
  fraction: number;
}

export function countdown(deadline: number, nowMs: number, windowMs?: number): Countdown;

export function formatClock(ms: number): string;

export interface PendingWindow {
  id: string;
  status: "pending" | "extended";
  agentId: string;
  tool: string;
  deadline: number;
  delivered: boolean;
}

export function validatePendingWindow(entry: unknown): PendingWindow | null;

export interface PendingWindowView extends PendingWindow, Countdown {}

export interface PendingView {
  kind: "unconfigured" | "unreachable" | "ok";
  windows: PendingWindowView[];
  dropped: number;
}

export function pendingModel(reading: unknown, nowMs: number): PendingView;

export type VetoAction = "stopped" | "retry" | "superseded";

export function vetoResultAction(
  armedWindowId: string,
  currentWindowId: string | null,
  result: unknown,
): VetoAction;

export interface WindowDiff {
  appeared: string[];
  disappeared: string[];
}

export function diffWindowIds(prevIds: string[], nextIds: string[]): WindowDiff;

export function closedWindowText(id: string, finalStatus: unknown): string;

export type JournalTone = "info" | "ok" | "warn" | "stop";

export function closedWindowTone(finalStatus: unknown): JournalTone;

export interface DeviceView {
  deviceId: string;
  name: string;
  enrolledAt: number;
  enrolledOn: string;
  revoked: boolean;
  pushRegistered: boolean;
}

export interface DevicesView {
  kind: "unconfigured" | "unreachable" | "refused" | "ok";
  devices: DeviceView[];
  upstreamStatus?: number;
  error?: string;
}

export function devicesModel(reading: unknown): DevicesView;

export interface JournalEntry {
  seq: number;
  at: number;
  kind: string;
  text: string;
  tone: JournalTone;
  count: number;
}

export interface Journal {
  push(at: number, kind: string, text: string, tone?: JournalTone): JournalEntry;
  entries(): JournalEntry[];
}

export function createJournal(limit?: number): Journal;

export interface JournalSeed {
  kind: string;
  text: string;
  tone: JournalTone;
}

export function killStateTransitionEvents(prev: KillView | null, next: KillView | null): JournalSeed[];

export const STATUS_FRESH_TTL_MS: number;

export function isStatusStale(lastFreshAt: number | null, nowMs: number, ttlMs?: number): boolean;

export function staleKillView(prev: Pick<KillView, "epoch"> | KillView | null): KillView;

export function reduceKillView(prev: KillView | null, next: KillView): KillView;

export interface KillConfirmation {
  kind: "confirmed" | "confirmed-degraded" | "unconfirmed";
  text: string;
}

export function killConfirmation(result: unknown): KillConfirmation;
