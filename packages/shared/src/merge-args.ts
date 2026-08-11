/**
 * The GitHub merge purpose — the one (connector, operation) pair a
 * MergeGrant may authorize today — and the strict, CLOSED argument schema
 * that purpose accepts.
 *
 * This lives in shared because every party enforces it INDEPENDENTLY, and
 * none of them trusts another's parse: the gateway refuses unknown fields
 * before the owner ever sees a request (validateMergePrRequestArgs), the
 * control plane refuses to register or sign a merge-purpose window whose
 * arguments do not parse as exactly one merge, and the executing broker
 * re-parses the signed bytes before acting. A key set that is closed in
 * three places cannot be re-opened by compromising one of them.
 */

export const GITHUB_CONNECTOR = "github";
export const MERGE_PULL_REQUEST = "merge_pull_request";

export interface MergePrArgs {
  owner: string;
  repo: string;
  pullNumber: number;
  /**
   * The head the owner's approval was pinned to — mandatory, and derived
   * server-side at review time. A merge is sent with exactly this sha; a
   * branch that moved after review draws a 409 instead of merging commits
   * nobody reviewed.
   */
  expectedHeadSha: string;
  /**
   * The DESTINATION branch the owner's approval was pinned to — mandatory,
   * derived server-side at review time, same as the head sha. GitHub lets a
   * PR be retargeted to a different base branch after approval, and the
   * merge API's `sha` parameter guards only the head — so without this pin
   * the same approved commits could be merged into a branch the owner never
   * saw. The executor re-reads the PR's base immediately before dispatch
   * and refuses on mismatch (the API offers no atomic base guard; the
   * residual read-to-PUT race is documented in DESIGN.md).
   */
  expectedBaseRef: string;
  mergeMethod?: "merge" | "squash" | "rebase";
}

/** The exact, closed key set of a canonical merge action. Nothing else. */
const MERGE_PR_CANONICAL_KEYS: ReadonlySet<string> = new Set([
  "owner",
  "repo",
  "pullNumber",
  "mergeMethod",
  "expectedHeadSha",
  "expectedBaseRef",
]);

/** Branch names are short; anything past this is not a ref, it's an attack. */
const MAX_BASE_REF_LENGTH = 300;

/**
 * Rejects strings that would be UNSAFE TO DISPLAY to the owner: a signed
 * approval is worthless if the bytes the owner saw are not the bytes that
 * execute, and Unicode gives many ways to make "main" render as something
 * else. Rather than enumerate code points (which misses cases like U+061C
 * ARABIC LETTER MARK, U+00AD SOFT HYPHEN, U+180E, U+FFF9–FFFB and the astral
 * default-ignorables), we refuse by Unicode PROPERTY — the categories that
 * are by definition non-printing or reorder-the-render:
 *  - `Cc` control, `Cf` format, `Zl`/`Zp` line/paragraph separators;
 *  - `Bidi_Control` (the "reorder the visible identifier" attack);
 *  - `Default_Ignorable_Code_Point` (soft hyphen, variation selectors, tag
 *    characters, and other glyphs a renderer may drop entirely).
 * We refuse rather than sanitize — sanitizing invites its own confusion —
 * and additionally require NFC form so one code-point sequence has one
 * representation both when hashed and when rendered. Git itself permits many
 * of these in ref names, so the pin cannot lean on git's rules; OwnerSwitch's
 * display contract is stricter than git on purpose.
 */
const UNSAFE_DISPLAY_CHARS =
  /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Bidi_Control}\p{Default_Ignorable_Code_Point}]/u;

export function isSafeToDisplay(value: string): boolean {
  if (UNSAFE_DISPLAY_CHARS.test(value)) return false;
  // NFC idempotence: the value must already be in normalized form, so the
  // hash the owner's device signs over covers exactly the glyphs shown.
  return value.normalize("NFC") === value;
}

/**
 * The DECISION-CRITICAL identifier grammar: printable ASCII only, matching
 * how a git ref is actually written. Property filtering (above) removes
 * non-printing characters, but it cannot make identifiers UNSPOOFABLE — a
 * Cyrillic "а"/U+0430 or the Latin-looking "і"/U+0456 pass NFC and every
 * property check while resembling ASCII letters. For v0 we sidestep the
 * whole confusables problem for the one field the owner's decision turns on
 * (the merge DESTINATION): it must be printable ASCII, so what the owner
 * reads is exactly the bytes that execute. GitHub allows non-ASCII branch
 * names; OwnerSwitch refuses to pin/merge one rather than risk a homoglyph.
 */
const ASCII_REF = /^[\x21-\x7e]+$/;

export function isAsciiDisplaySafeRef(value: string): boolean {
  return ASCII_REF.test(value) && isSafeToDisplay(value);
}

/**
 * Parse canonical merge arguments STRICTLY: the closed key set above, the
 * allowed merge methods, a full-length head sha. An unknown key is a hard
 * error, never ignored — arguments that carry a field execution would not
 * honor must not become owner-reviewed, signed, or executed bytes.
 */
export function parseMergePrArgs(canonicalArgs: string): MergePrArgs {
  let parsed: unknown;
  try {
    parsed = JSON.parse(canonicalArgs);
  } catch {
    throw new Error("canonicalArgs is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("canonicalArgs must be a JSON object");
  }
  for (const key of Object.keys(parsed)) {
    if (!MERGE_PR_CANONICAL_KEYS.has(key)) {
      throw new Error(
        `unknown argument "${key}" for merge_pull_request — the argument schema is closed: ` +
          `owner, repo, pullNumber, mergeMethod, expectedHeadSha, expectedBaseRef`,
      );
    }
  }
  const { owner, repo, pullNumber, mergeMethod, expectedHeadSha, expectedBaseRef } =
    parsed as Record<string, unknown>;
  if (typeof owner !== "string" || owner === "") throw new Error("merge_pull_request requires owner");
  if (typeof repo !== "string" || repo === "") throw new Error("merge_pull_request requires repo");
  if (typeof pullNumber !== "number" || !Number.isSafeInteger(pullNumber) || pullNumber <= 0) {
    throw new Error("merge_pull_request requires a safe positive integer pullNumber");
  }
  if (
    mergeMethod !== undefined &&
    mergeMethod !== "merge" &&
    mergeMethod !== "squash" &&
    mergeMethod !== "rebase"
  ) {
    throw new Error(`unknown mergeMethod "${String(mergeMethod)}"`);
  }
  // MANDATORY, and a full commit id (40-hex SHA-1 or 64-hex SHA-256), never
  // an abbreviation: an approval must bind to exactly one head, and a
  // prefix can be ambiguous. The proxy derives this server-side at review
  // time; a ticket without it was minted by nothing this system ships.
  if (
    typeof expectedHeadSha !== "string" ||
    !/^([0-9a-f]{40}|[0-9a-f]{64})$/i.test(expectedHeadSha)
  ) {
    throw new Error(
      "merge_pull_request requires expectedHeadSha: a full 40- or 64-character hex commit id, " +
        "pinned by OwnerSwitch at review time",
    );
  }
  // MANDATORY, server-derived like the head sha: the merge destination the
  // owner approved. Non-empty, bounded, and SAFE TO DISPLAY — the owner sees
  // and approves this branch name, so a bidi override or a non-NFC form that
  // renders as a different branch is refused, not just C0 controls. Compared
  // as an exact string against GitHub's reported base ref.
  if (
    typeof expectedBaseRef !== "string" ||
    expectedBaseRef === "" ||
    expectedBaseRef.length > MAX_BASE_REF_LENGTH ||
    !isAsciiDisplaySafeRef(expectedBaseRef)
  ) {
    throw new Error(
      "merge_pull_request requires expectedBaseRef: the destination branch pinned by " +
        "OwnerSwitch at review time (non-empty, bounded, and PRINTABLE ASCII — a non-ASCII " +
        "branch name is refused rather than risk a homoglyph the owner cannot distinguish)",
    );
  }
  return {
    owner,
    repo,
    pullNumber,
    expectedHeadSha,
    expectedBaseRef,
    ...(mergeMethod !== undefined ? { mergeMethod } : {}),
  };
}

/**
 * RenderableApprovalV1 — the TYPED, per-field structure the owner's app
 * displays and approves. The owner does not read raw canonical JSON: they
 * read named fields, each already proven safe to display, and their passkey
 * signs a challenge bound to the HASH of this exact structure. That closes
 * the gap the reviewer named: WebAuthn proves user verification over the
 * challenge, but only binding the challenge to a hashed, sanitized,
 * per-field rendering proves the owner saw the transaction that will run.
 */
export interface RenderableApprovalV1 {
  v: 1;
  action: "github.merge_pull_request";
  owner: string;
  repo: string;
  pullNumber: number;
  expectedHeadSha: string;
  expectedBaseRef: string;
  mergeMethod: "merge" | "squash" | "rebase" | "default";
}

/**
 * Build the renderable from parsed merge args, re-validating EVERY string
 * field as safe to display (owner/repo/base/head). Throws if any field is
 * unsafe — the owner must never be shown, or asked to approve, a spoofable
 * identifier.
 */
export function buildRenderableApproval(args: MergePrArgs): RenderableApprovalV1 {
  for (const [field, value] of [
    ["owner", args.owner],
    ["repo", args.repo],
    ["expectedBaseRef", args.expectedBaseRef],
    ["expectedHeadSha", args.expectedHeadSha],
  ] as const) {
    if (!isSafeToDisplay(value)) {
      throw new Error(`merge_pull_request ${field} is not safe to display`);
    }
  }
  return {
    v: 1,
    action: "github.merge_pull_request",
    owner: args.owner,
    repo: args.repo,
    pullNumber: args.pullNumber,
    expectedHeadSha: args.expectedHeadSha,
    expectedBaseRef: args.expectedBaseRef,
    mergeMethod: args.mergeMethod ?? "default",
  };
}
