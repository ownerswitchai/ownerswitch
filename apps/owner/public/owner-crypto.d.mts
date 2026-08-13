/** Types for the browser signer public/owner-crypto.mjs (plain JS at runtime). */
export const OWNER_DEVICE_SIG_LABEL: string;

export interface SignFields {
  deviceId: string;
  method: string;
  pathAndQuery: string;
  body?: string | Uint8Array;
  timestamp: number;
  nonce: string;
}

export interface DeviceSigHeaders {
  "x-device-id": string;
  "x-device-timestamp": string;
  "x-device-nonce": string;
  "x-device-signature": string;
}

export function deviceSigPreimage(fields: SignFields): Promise<Uint8Array>;
export function generateOwnerDeviceKey(): Promise<CryptoKeyPair>;
export function exportPublicKeySpki(publicKey: CryptoKey): Promise<string>;
export function signRequestHeaders(privateKey: CryptoKey, fields: SignFields): Promise<DeviceSigHeaders>;
export function nonce(): string;
