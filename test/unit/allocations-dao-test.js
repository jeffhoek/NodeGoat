"use strict";

const assert = require("assert");

// Extract searchCriteria logic by instantiating AllocationsDAO with a minimal db stub
const { AllocationsDAO } = require("../../app/data/allocations-dao");

function makeDb() {
    return {
        collection: () => ({
            update: () => {},
            findOne: () => {},
            find: () => ({ toArray: () => {} })
        })
    };
}

// Reach into getByUserIdAndThreshold to test the searchCriteria branch directly
// by calling the DAO and capturing the query passed to find()
function captureQuery(threshold) {
    let capturedQuery;
    const db = {
        collection: () => ({
            find: (q) => { capturedQuery = q; return { toArray: () => {} }; },
            findOne: () => {},
            update: () => {}
        })
    };
    const dao = new AllocationsDAO(db);
    try {
        dao.getByUserIdAndThreshold(1, threshold, () => {});
    } catch (e) {
        return { threw: e };
    }
    return capturedQuery;
}

describe("AllocationsDAO – getByUserIdAndThreshold", () => {

    it("sanitizes DoS injection string to leading integer — no code injected", () => {
        // "0';while(true){}'" → parseInt = 0; safe query produced, injection never reaches DB
        const result = captureQuery("0';while(true){}'");
        assert.ok(!result.threw, "should not throw — leading digit is a valid threshold");
        assert.ok(result.$where, "expected $where clause with sanitized value");
        assert.ok(!result.$where.includes("while"), "injection payload must not appear in query");
        assert.ok(result.$where.includes(" 0"), "sanitized value 0 must appear in query");
    });

    it("sanitizes filter-bypass string to leading integer — no code injected", () => {
        // "1'; return 1 == '1" → parseInt = 1; safe numeric query produced
        const result = captureQuery("1'; return 1 == '1");
        assert.ok(!result.threw, "should not throw — leading digit is a valid threshold");
        assert.ok(result.$where, "expected $where clause with sanitized value");
        assert.ok(!result.$where.includes("return"), "injection payload must not appear in query");
        assert.ok(result.$where.includes(" 1"), "sanitized value 1 must appear in query");
    });

    it("rejects out-of-range threshold (> 99) — throws", () => {
        const result = captureQuery("100");
        assert.ok(result.threw, "expected throw for threshold > 99");
    });

    it("accepts valid threshold — produces numeric comparison in $where", () => {
        const result = captureQuery("50");
        assert.ok(result.$where, "expected $where clause");
        assert.ok(!result.$where.includes("'50'"), "threshold must not be quoted (string injection risk)");
        assert.ok(result.$where.includes("50"), "threshold value must appear in query");
    });

    it("returns plain userId query when no threshold supplied", () => {
        const result = captureQuery(undefined);
        assert.ok(!result.$where, "expected no $where clause when threshold absent");
        assert.ok("userId" in result);
    });

});
