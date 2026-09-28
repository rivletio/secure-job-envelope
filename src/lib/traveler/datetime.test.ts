import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isoDateTimeMs, isoDayOk } from "./datetime.ts";

describe("strict ISO-8601 datetime (cross-impl with Rust rfc3339_millis)", () => {
  it("parses the no-fraction and fractional forms to the same instant", () => {
    assert.equal(isoDateTimeMs("1970-01-01T00:00:00Z"), 0);
    assert.equal(isoDateTimeMs("1970-01-01T00:00:00.000Z"), 0);
    assert.equal(isoDateTimeMs("2026-05-01T12:00:00.5Z"), isoDateTimeMs("2026-05-01T12:00:00.500Z"));
    assert.ok((isoDateTimeMs("2026-09-30T00:00:00.000Z") ?? 0) > 0);
  });

  it("refuses anything a lenient parser would coerce", () => {
    assert.equal(isoDateTimeMs("2026-05-01T12:00:00.000+00:00"), null); // trailing offset, not Z
    assert.equal(isoDateTimeMs("2026-5-1T12:00:00Z"), null); // single-digit fields
    assert.equal(isoDateTimeMs("2026-05-01T12:00:60.000Z"), null); // second 60
    assert.equal(isoDateTimeMs("2026-05-01T24:00:00.000Z"), null); // hour 24
    assert.equal(isoDateTimeMs("2026-02-31T12:00:00.000Z"), null); // impossible calendar day
    assert.equal(isoDateTimeMs("2026-13-01T00:00:00Z"), null); // month 13
    assert.equal(isoDateTimeMs("2026-01-01T12:00:00.0000000000Z"), null); // > 9 fractional digits
    assert.equal(isoDateTimeMs("garbage"), null);
  });

  it("is leap-year aware", () => {
    assert.ok(isoDateTimeMs("2024-02-29T00:00:00Z") !== null);
    assert.equal(isoDateTimeMs("2026-02-29T00:00:00Z"), null);
  });

  it("isoDayOk validates a real calendar day", () => {
    assert.ok(isoDayOk("2026-10-24"));
    assert.ok(isoDayOk("2024-02-29"));
    assert.ok(!isoDayOk("2026-02-29"));
    assert.ok(!isoDayOk("2026-02-31"));
    assert.ok(!isoDayOk("2026-13-01"));
    assert.ok(!isoDayOk("2026-1-1")); // single-digit fields
  });
});
