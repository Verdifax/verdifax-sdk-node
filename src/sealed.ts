// Sealed records keep the exact text the server sent (round 57, N5). A
// record's hash covers every field the server sealed, and JSON.parse rounds
// a number above 2^53, so a record parsed and written back with
// JSON.stringify could stop matching its hash. Every object and list this
// SDK reads from the server's JSON answer (sign-offs, policy changes, feed
// pages and events among them) and every verified webhook event carries
// `sealedJson`: the exact text of that object or list as the server sent
// it. It is read-only and not enumerable, so JSON.stringify and spreading
// never include it. Save `sealedJson` to check a record with
// `verdifax-verify`.

import { VerdifaxError } from "./errors.js";

/** A value as the server sent it: `sealedJson` is its exact text. */
export type Sealed<T> = T & { readonly sealedJson: string };

/** A list as the server sent it, each element with its own exact text. */
export type SealedList<T> = Sealed<Sealed<T>[]>;

/**
 * Parses JSON text as JSON.parse does, and gives every object and array in
 * it a read-only, non-enumerable `sealedJson` property holding that value's
 * exact text. Numbers are read as JSON.parse reads them; their exact digits
 * are in the `sealedJson` of the object or list that holds them.
 */
export function parseSealed<T>(text: string): T {
  const p = new SealedParser(text);
  p.space();
  const value = p.value();
  p.space();
  if (p.at < text.length) p.fail("text after the value");
  return value as T;
}

class SealedParser {
  at = 0;
  constructor(private readonly text: string) {}

  fail(what: string): never {
    throw new VerdifaxError(`verdifax: the server's JSON is not valid: ${what} at offset ${this.at}`);
  }

  space(): void {
    while (this.at < this.text.length) {
      const c = this.text.charCodeAt(this.at);
      if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return;
      this.at++;
    }
  }

  value(): unknown {
    const c = this.text[this.at];
    if (c === "{") return this.object();
    if (c === "[") return this.array();
    if (c === '"') return this.string();
    return this.literal();
  }

  object(): Record<string, unknown> {
    const start = this.at;
    const out: Record<string, unknown> = {};
    this.at++;
    this.space();
    if (this.text[this.at] === "}") {
      this.at++;
      return seal(out, this.text.slice(start, this.at));
    }
    for (;;) {
      this.space();
      if (this.text[this.at] !== '"') this.fail("expected a member name");
      const key = this.string();
      this.space();
      if (this.text[this.at] !== ":") this.fail("expected ':'");
      this.at++;
      this.space();
      const v = this.value();
      // As JSON.parse does: a repeated name keeps its last value, and
      // "__proto__" is an own member, never the prototype.
      Object.defineProperty(out, key, { value: v, enumerable: true, writable: true, configurable: true });
      this.space();
      const sep = this.text[this.at];
      this.at++;
      if (sep === "}") return seal(out, this.text.slice(start, this.at));
      if (sep !== ",") this.fail("expected ',' or '}'");
    }
  }

  array(): unknown[] {
    const start = this.at;
    const out: unknown[] = [];
    this.at++;
    this.space();
    if (this.text[this.at] === "]") {
      this.at++;
      return seal(out, this.text.slice(start, this.at));
    }
    for (;;) {
      this.space();
      out.push(this.value());
      this.space();
      const sep = this.text[this.at];
      this.at++;
      if (sep === "]") return seal(out, this.text.slice(start, this.at));
      if (sep !== ",") this.fail("expected ',' or ']'");
    }
  }

  string(): string {
    const start = this.at;
    this.at++;
    while (this.at < this.text.length) {
      const c = this.text[this.at];
      if (c === "\\") {
        this.at += 2;
        continue;
      }
      this.at++;
      if (c === '"') return this.decode(this.text.slice(start, this.at)) as string;
    }
    this.fail("unterminated string");
  }

  literal(): unknown {
    const start = this.at;
    while (this.at < this.text.length && !/[\s,\]}:]/.test(this.text.charAt(this.at))) this.at++;
    if (this.at === start) this.fail("expected a value");
    return this.decode(this.text.slice(start, this.at));
  }

  // decode reads one string, number or literal token exactly as JSON.parse
  // reads it, so this parser accepts and refuses what JSON.parse does.
  decode(token: string): unknown {
    try {
      return JSON.parse(token);
    } catch {
      this.fail(`bad token ${JSON.stringify(token.slice(0, 40))}`);
    }
  }
}

function seal<T extends object>(value: T, text: string): T {
  Object.defineProperty(value, "sealedJson", { value: text, enumerable: false, writable: false, configurable: false });
  return value;
}
