import { describe, expect, it } from "vitest";
import { createSecretLedger } from "./secret-ledger.js";

describe("createSecretLedger", () => {
  it("redacts every recorded secret, forever", () => {
    const ledger = createSecretLedger();
    ledger.add("ghs_old_token_0123456789");
    ledger.add("ghs_new_token_9876543210");
    const text =
      "first ghs_old_token_0123456789 then ghs_new_token_9876543210 then ghs_old_token_0123456789 again";
    expect(ledger.redact(text)).toBe("first [REDACTED] then [REDACTED] then [REDACTED] again");
  });

  it("redacts the JSON-escaped form of a secret with newlines — the shape a PEM key takes inside a JSON error body", () => {
    const ledger = createSecretLedger();
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----";
    ledger.add(pem);
    // a server echoing the key inside a JSON string escapes the newlines
    const jsonBody = JSON.stringify({ message: `bad key: ${pem}` });
    const redacted = ledger.redact(jsonBody);
    expect(redacted).not.toContain("MIIEow");
    expect(redacted).toContain("[REDACTED]");
    // and the raw form is covered too
    expect(ledger.redact(`raw: ${pem}`)).toBe("raw: [REDACTED]");
  });

  it("redacts longest-first so a secret containing another leaves no fragments", () => {
    const ledger = createSecretLedger();
    ledger.add("token");
    ledger.add("token-with-suffix");
    expect(ledger.redact("x token-with-suffix y")).toBe("x [REDACTED] y");
  });

  it("ignores empty and undefined values instead of shredding all text", () => {
    const ledger = createSecretLedger();
    ledger.add(undefined);
    ledger.add("");
    expect(ledger.redact("nothing to hide")).toBe("nothing to hide");
  });
});
