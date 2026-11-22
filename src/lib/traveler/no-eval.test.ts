import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { describe, it } from "node:test";

// The published desk's Content-Security-Policy has no 'unsafe-eval': code compiled from a
// string does not run there. This test keeps the library honest about that in Node, where
// nothing would otherwise stop it — and keeps the parser that is tested the parser that
// ships (schema.ts pins zod's interpreter; see the comment there).
//
// `Function` is replaced BEFORE the library is loaded, so a compile at import time counts.

const compiled: string[] = [];
const RealFunction = globalThis.Function;
const spy = new Proxy(RealFunction, {
  construct(target, args: unknown[]) {
    compiled.push(`new Function(${args.map(String).join(", ").slice(0, 60)})`);
    return Reflect.construct(target, args) as object;
  },
  apply(target, thisArg, args: unknown[]) {
    compiled.push(`Function(${args.map(String).join(", ").slice(0, 60)})`);
    return Reflect.apply(target, thisArg, args) as unknown;
  },
});

const vector = (dir: string, file: string): Uint8Array =>
  readFileSync(new URL(`../../../conformance/${dir}/${file}`, import.meta.url));

describe("the library never compiles code from strings", () => {
  it("the spy sees a compile (the test can fail)", () => {
    globalThis.Function = spy;
    try {
      new Function("return 1");
    } finally {
      globalThis.Function = RealFunction;
    }
    assert.equal(compiled.length, 1);
    compiled.length = 0;
  });

  it("parsing, levelling, hashing and verifying compile nothing", async () => {
    globalThis.Function = spy;
    try {
      const { parseTravelerJson, parseQuote, levelOf } = await import("./conformance.ts");
      const { travelerHash } = await import("./hash.ts");
      const { parseDirectoryJson } = await import("./directory.ts");
      const { verificationReport } = await import("./authenticity.ts");
      const { parseSjeEnvelope } = await import("./transport.ts");

      // Every traveler vector, accepted or refused: both outcomes run the schema.
      const listed = (dir: string) =>
        readdirSync(new URL(`../../../conformance/${dir}/`, import.meta.url))
          .filter((f) => f.endsWith(".json") && f !== "expected.json" && f !== "reject-reasons.json")
          .sort();
      let accepted = 0;
      let refused = 0;
      for (const dir of ["travelers", "travelers/reject"]) {
        for (const file of listed(dir)) {
          try {
            const t = parseTravelerJson(vector(dir, file));
            levelOf(t);
            travelerHash(t);
            for (const q of t.quotes ?? []) parseQuote(q);
            accepted += 1;
          } catch {
            refused += 1;
          }
        }
      }
      assert.ok(accepted >= 5 && refused >= 20, `ran ${accepted} accepted and ${refused} refused vectors`);

      // The signed path: a directory, a signed traveler, an envelope.
      const signed = JSON.parse(
        new TextDecoder().decode(vector("signatures", "signed-traveler.json")),
      ) as { traveler: unknown; directory: unknown; root_public_key_hex: string };
      const directory = parseDirectoryJson(JSON.stringify(signed.directory));
      const traveler = parseTravelerJson(JSON.stringify(signed.traveler));
      const report = verificationReport(
        traveler,
        directory,
        signed.root_public_key_hex,
        new Date("2027-01-01T00:00:00.000Z"),
      );
      assert.equal(report.authored, true, "the signed vector verifies");
      const sealed = JSON.parse(
        new TextDecoder().decode(vector("signatures", "envelope.json")),
      ) as { envelope: unknown };
      parseSjeEnvelope(JSON.stringify(sealed.envelope));
    } finally {
      globalThis.Function = RealFunction;
    }
    assert.deepEqual(compiled, []);
  });
});
