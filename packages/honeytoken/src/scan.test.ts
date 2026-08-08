import { describe, expect, it } from "vitest";
import { generateHoneytoken } from "./generate.js";
import { scanForHoneytokens } from "./scan.js";

describe("scanForHoneytokens", () => {
  it("a decoy value inside tool-call arguments trips the scanner", () => {
    const token = generateHoneytoken({ kind: "stripe" });
    const args = JSON.stringify({
      tool: "stripe.create_payout",
      args: { api_key: token.value, amount_cents: 125_000 },
    });

    const matches = scanForHoneytokens(args);

    expect(matches).toHaveLength(1);
    expect(matches[0].canaryId).toBe(token.canaryId);
    expect(matches[0].core).toBe(token.core);
    expect(matches[0].index).toBe(args.indexOf(token.core));
    expect(matches[0].kindHint).toBe("stripe");
  });

  it("reports each distinct token once, in order of first appearance", () => {
    const aws = generateHoneytoken({ kind: "aws" });
    const openai = generateHoneytoken({ kind: "openai" });
    const text = `${aws.value} then ${openai.value} and ${aws.value} again`;

    const matches = scanForHoneytokens(text);

    expect(matches.map((m) => m.canaryId)).toEqual([aws.canaryId, openai.canaryId]);
    expect(matches.map((m) => m.kindHint)).toEqual(["aws", "openai"]);
  });

  it("real credential-shaped strings that are not ours do NOT trip", () => {
    const foreignCredentials = [
      // AWS's own documented example access key and secret
      "AKIAIOSFODNN7EXAMPLE",
      "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      // live-shaped Stripe / OpenAI / GitHub / Slack material
      "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
      "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH",
      "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
      "xoxb-2222222222-3333333333333-AbCdEfGhIjKlMnOpQrStUvWx",
      `postgres://svc:${"p".repeat(24)}@db.internal:5432/prod`,
    ];
    for (const credential of foreignCredentials) {
      expect(scanForHoneytokens(credential)).toEqual([]);
    }
  });

  it("the CANARY marker alone is not enough — the checksum must validate", () => {
    // prose that happens to contain CANARY + ten base32-alphabet characters
    expect(scanForHoneytokens("the CANARYTOKENSDEMO project pages")).toEqual([]);
    expect(scanForHoneytokens("CANARY22222222AA and CANARYABCDEFGHJK in prose")).toEqual([]);

    // a real token whose final checksum character was corrupted
    const token = generateHoneytoken({ kind: "aws" });
    const corrupted = token.value.slice(0, -1) + (token.value.endsWith("A") ? "B" : "A");
    expect(scanForHoneytokens(corrupted)).toEqual([]);
  });

  it("clean text scans clean", () => {
    expect(scanForHoneytokens("")).toEqual([]);
    expect(scanForHoneytokens(JSON.stringify({ path: "/tmp/notes.md", content: "hello" }))).toEqual(
      [],
    );
  });
});
