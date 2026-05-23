"use strict";

const assert = require("assert");

// Extract the regex directly from the route source so the test stays coupled to it
const fs = require("fs");
const src = fs.readFileSync(require.resolve("../../app/routes/profile.js"), "utf8");

// Pull the regexPattern line and eval it to get the live pattern
const match = src.match(/const regexPattern = (\/[^;]+\/);/);
assert.ok(match, "could not locate regexPattern in profile.js");
const regexPattern = eval(match[1]); // eslint-disable-line no-eval

describe("profile.js – bankRouting regex (M-2 ReDoS)", () => {

    it("accepts a valid routing number (digits + #)", () => {
        assert.ok(regexPattern.test("0198212#"), "valid routing number must pass");
    });

    it("rejects a routing number with no trailing #", () => {
        assert.ok(!regexPattern.test("0198212"), "missing # must fail");
    });

    it("rejects an empty string", () => {
        assert.ok(!regexPattern.test(""), "empty string must fail");
    });

    it("resolves malicious input (no #) in < 100 ms — no catastrophic backtracking", () => {
        const malicious = "1".repeat(30);
        const start = Date.now();
        regexPattern.test(malicious);
        const elapsed = Date.now() - start;
        assert.ok(elapsed < 100, `regex took ${elapsed}ms on malicious input — catastrophic backtracking suspected`);
    });

});
