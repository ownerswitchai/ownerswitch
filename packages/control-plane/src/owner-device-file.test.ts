import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadOwnerDeviceKeysFile } from "./owner-device-file.js";
import { enrolledOwnerDeviceFromSpki } from "./owner-device.js";

const p256 = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const spkiPem = (kp: ReturnType<typeof p256>) => kp.publicKey.export({ format: "pem", type: "spki" }).toString();
const pkcs8Pem = (kp: ReturnType<typeof p256>) => kp.privateKey.export({ format: "pem", type: "pkcs8" }).toString();

const tmp = () => mkdtempSync(join(tmpdir(), "ownerswitch-devkeys-"));
const write = (dir: string, name: string, content: string, mode = 0o600) => {
  const path = join(dir, name);
  writeFileSync(path, content, { mode });
  chmodSync(path, mode);
  return path;
};
const OPTS = { unsafeAllowUntrustedAncestryForTests: true } as const;

describe("enrolledOwnerDeviceFromSpki — strict public-key parsing", () => {
  it("accepts an SPKI public PEM and a base64 DER, canonicalizing both", () => {
    const kp = p256();
    const fromPem = enrolledOwnerDeviceFromSpki("d", spkiPem(kp));
    expect(fromPem.deviceId).toBe("d");
    const der = kp.publicKey.export({ format: "der", type: "spki" }).toString("base64");
    expect(() => enrolledOwnerDeviceFromSpki("d", der)).not.toThrow();
  });

  it("REJECTS a private key PEM — public-key config must never carry signing authority", () => {
    const kp = p256();
    expect(() => enrolledOwnerDeviceFromSpki("d", pkcs8Pem(kp))).toThrow(/PRIVATE key/i);
  });

  it("REJECTS trailing bytes after the SPKI — a private key or padding cannot hide behind the public half", () => {
    const kp = p256();
    const spkiDer = kp.publicKey.export({ format: "der", type: "spki" }) as Buffer;
    const pkcs8Der = kp.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;

    // canonical SPKI || matching PKCS#8 private key, base64'd as one DER input
    const smuggled = Buffer.concat([spkiDer, pkcs8Der]).toString("base64");
    expect(() => enrolledOwnerDeviceFromSpki("d", smuggled)).toThrow(/trailing bytes/);

    // even a single appended 0x00 is refused
    const padded = Buffer.concat([spkiDer, Buffer.from([0x00])]).toString("base64");
    expect(() => enrolledOwnerDeviceFromSpki("d", padded)).toThrow(/trailing bytes/);

    // the clean SPKI still passes
    expect(() => enrolledOwnerDeviceFromSpki("d", spkiDer.toString("base64"))).not.toThrow();
  });

  it("REJECTS two base64 encodings concatenated as TEXT — the decoder drops the tail, but the file still carries the private key", () => {
    const kp = p256();
    const spkiDer = kp.publicKey.export({ format: "der", type: "spki" }) as Buffer;
    const pkcs8Der = kp.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;

    // base64(SPKI) || base64(PKCS8): NOT base64(SPKI||PKCS8). Node's base64
    // decoder stops after the canonical SPKI padding and silently ignores the
    // rest, so the DECODED bytes are a clean SPKI (the DER check passes) — but
    // the raw file text still holds the full private key in base64. Only a
    // canonical-encoding round-trip catches it.
    const bodyConcat = spkiDer.toString("base64") + pkcs8Der.toString("base64");
    expect(() => enrolledOwnerDeviceFromSpki("d", bodyConcat)).toThrow(/canonical base64/);

    // and the same smuggle inside a single PUBLIC KEY PEM body
    const pem = `-----BEGIN PUBLIC KEY-----\n${bodyConcat}\n-----END PUBLIC KEY-----\n`;
    expect(() => enrolledOwnerDeviceFromSpki("d", pem)).toThrow(/canonical base64/);

    // base64url smuggle on the raw path is refused too
    const urlConcat = spkiDer.toString("base64url") + pkcs8Der.toString("base64url");
    expect(() => enrolledOwnerDeviceFromSpki("d", urlConcat)).toThrow(/canonical base64|trailing bytes/);

    // a clean base64url SPKI (the browser export form) still passes
    expect(() => enrolledOwnerDeviceFromSpki("d", spkiDer.toString("base64url"))).not.toThrow();
  });

  it("rejects a non-P-256 key and multiple PEM blocks", () => {
    const ed = generateKeyPairSync("ed25519");
    expect(() => enrolledOwnerDeviceFromSpki("d", ed.publicKey.export({ format: "pem", type: "spki" }).toString())).toThrow(
      /P-256|prime256v1/,
    );
    const two = spkiPem(p256()) + spkiPem(p256());
    expect(() => enrolledOwnerDeviceFromSpki("d", two)).toThrow(/exactly one/);
  });
});

describe("loadOwnerDeviceKeysFile — hardened file load", () => {
  it("loads a well-formed 0600 keys file and returns canonical PEMs", () => {
    const dir = tmp();
    const kp = p256();
    const path = write(dir, "keys.json", JSON.stringify({ "owner-phone": spkiPem(kp) }));
    const keys = loadOwnerDeviceKeysFile(path, OPTS);
    expect(Object.keys(keys)).toEqual(["owner-phone"]);
    expect(keys["owner-phone"]).toMatch(/-----BEGIN PUBLIC KEY-----/);
    // the returned key is usable by the verifier
    expect(() => enrolledOwnerDeviceFromSpki("owner-phone", keys["owner-phone"])).not.toThrow();
  });

  it("refuses a private key inside the file", () => {
    const dir = tmp();
    const path = write(dir, "keys.json", JSON.stringify({ "owner-phone": pkcs8Pem(p256()) }));
    expect(() => loadOwnerDeviceKeysFile(path, OPTS)).toThrow(/PRIVATE key/i);
  });

  it("refuses a group/world-writable file, a symlink, a relative path, and a ':' in the device id", () => {
    const dir = tmp();
    const good = JSON.stringify({ "owner-phone": spkiPem(p256()) });

    const writable = write(dir, "writable.json", good, 0o646);
    expect(() => loadOwnerDeviceKeysFile(writable, OPTS)).toThrow(/writable/);

    const real = write(dir, "real.json", good, 0o600);
    const link = join(dir, "link.json");
    symlinkSync(real, link);
    expect(() => loadOwnerDeviceKeysFile(link, OPTS)).toThrow(/symlink/);

    expect(() => loadOwnerDeviceKeysFile("keys.json", OPTS)).toThrow(/absolute/);

    const colon = write(dir, "colon.json", JSON.stringify({ "a:b": spkiPem(p256()) }), 0o600);
    expect(() => loadOwnerDeviceKeysFile(colon, OPTS)).toThrow(/invalid/);
  });

  it("refuses malformed JSON and a non-object body", () => {
    const dir = tmp();
    expect(() => loadOwnerDeviceKeysFile(write(dir, "a.json", "not json", 0o600), OPTS)).toThrow(/JSON/);
    expect(() => loadOwnerDeviceKeysFile(write(dir, "b.json", "[]", 0o600), OPTS)).toThrow(/object/);
  });
});
