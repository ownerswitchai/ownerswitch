/**
 * SecretLedger — one place that knows every secret the GitHub connector has
 * ever held, so redaction can be applied uniformly to anything that might
 * leave the connector: results, error messages, nothing else exists.
 *
 * The design stance (DESIGN.md §5, §6): the connector is written so a
 * credential never enters a log line or an error in the first place —
 * redaction is the SECOND line of defence, catching what should never have
 * been emitted at all, plus the one case structure cannot prevent: a remote
 * API quoting the credential back in its own response body ("Bad
 * credentials: ghs_…").
 *
 * The ledger accumulates and never forgets: an installation token that
 * expired five minutes ago must still be redacted from an error produced
 * now, because a log written now can be read while a replayed request with
 * that token might still be honored elsewhere. Entries are only ever added.
 */
export interface SecretLedger {
  /** record a secret; empty/undefined values are ignored */
  add(secret: string | undefined): void;
  /** replace every occurrence of every recorded secret with [REDACTED] */
  redact(text: string): string;
}

export function createSecretLedger(): SecretLedger {
  /**
   * Every representation a secret might surface under: the raw value, and
   * its JSON-escaped form — a PEM key or any secret with newlines/quotes
   * embedded in a JSON error body appears escaped, and an exact-match scrub
   * of only the raw bytes would sail right past it.
   */
  const secrets = new Set<string>();

  return {
    add(secret: string | undefined): void {
      if (secret === undefined || secret === "") return;
      secrets.add(secret);
      const escaped = JSON.stringify(secret).slice(1, -1);
      if (escaped !== secret) secrets.add(escaped);
    },
    redact(text: string): string {
      // longest first, so a secret that contains another secret as a
      // substring cannot leave recognizable fragments behind
      const ordered = [...secrets].sort((a, b) => b.length - a.length);
      let out = text;
      for (const secret of ordered) out = out.split(secret).join("[REDACTED]");
      return out;
    },
  };
}
