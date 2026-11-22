import assert from "node:assert/strict";
import { describe, it } from "node:test";

// A zone well west of UTC, set BEFORE anything formats a date: the old formatter went
// through local time, so this is the configuration in which it showed the wrong day.
process.env.TZ = "America/Los_Angeles";
const { formatDay } = await import("./format.ts");

describe("formatDay", () => {
  it("shows the day written in the document, whatever the viewer's time zone", () => {
    assert.equal(new Date("2026-10-30T00:00:00Z").getDate(), 29, "precondition: this process is west of UTC");
    assert.equal(formatDay("2026-10-30"), "30 Oct 2026");
    assert.equal(formatDay("2026-10-30T00:00:00.000Z"), "30 Oct 2026");
    assert.equal(formatDay("2026-01-01T00:30:00.000Z"), "1 Jan 2026");
    assert.equal(formatDay("2027-12-31T23:59:59.999Z"), "31 Dec 2027");
  });

  it("shows a dash for nothing and passes through what it cannot read", () => {
    assert.equal(formatDay(undefined), "—");
    assert.equal(formatDay(null), "—");
    assert.equal(formatDay(""), "—");
    assert.equal(formatDay("soon"), "soon");
    assert.equal(formatDay("2026-13-01"), "2026-13-01");
    assert.equal(formatDay("2026-10-30x"), "2026-10-30x");
  });
});
