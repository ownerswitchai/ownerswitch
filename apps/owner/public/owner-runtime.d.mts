/** Types for the foreground runtime public/owner-runtime.mjs (plain JS at runtime). */

export interface VetoResult {
  ok: boolean;
  status: number;
  vetoed: boolean;
  body: unknown;
}

export interface SeenAckResult {
  ok: boolean;
  status: number;
  body: unknown;
}

export function ensureDeviceKey(): Promise<CryptoKeyPair>;
export function enrolledPublicKeySpki(): Promise<string>;
export function subscribeAndEnroll(registration: ServiceWorkerRegistration): Promise<PushSubscription>;
export function resubscribeFromWorker(registration: ServiceWorkerRegistration): Promise<PushSubscription>;
export function fetchDetail(windowId: string): Promise<Record<string, unknown>>;

/** The texts read back from the painted detail view, keyed like the envelope. */
export interface RenderedDomTexts {
  agentId: string | null;
  tool: string | null;
  summary: string | null;
}

export interface SeenAckBody {
  deliveryId: string;
  revision: unknown;
  renderContentHash: string;
}

export function ackBodyForRender(detail: unknown, domTexts: RenderedDomTexts | null): Promise<SeenAckBody | null>;
export function domTextsMatch(alert: unknown, domTexts: RenderedDomTexts | null): boolean;
export function evidenceGuard(
  alert: unknown,
  readDomTexts: () => RenderedDomTexts | null,
  baseGuard?: () => boolean,
): () => boolean;
export function sendSeenAck(windowId: string, ackBody: unknown, guard?: () => boolean): Promise<SeenAckResult>;
export function sendVeto(windowId: string): Promise<VetoResult>;

export const VETO_BUTTON_LABEL: string;

/** A minimal button surface — enough for the pure state helpers below. */
export interface VetoButtonLike {
  textContent: string;
  disabled: boolean;
  removeAttribute?: (name: string) => void;
}

export function armVetoButton(btn: VetoButtonLike): void;

export type VetoAction = "superseded" | "stopped" | "retry";

export function vetoResultAction(
  armedGen: number,
  currentGen: number,
  result: unknown,
  armedWindowId?: string,
  currentWindowId?: string,
): VetoAction;
