"use strict";

const assert = require("assert");
const ContributionsHandler = require("../../app/routes/contributions");

function makeDb() {
    return {
        collection: () => ({
            update: () => {},
            findOne: () => {}
        })
    };
}

function makeReq(preTax, afterTax, roth) {
    return {
        session: { userId: 1 },
        body: { preTax: String(preTax), afterTax: String(afterTax), roth: String(roth) }
    };
}

function makeRes() {
    const res = {};
    res.render = (template, data) => { res.lastTemplate = template; res.lastData = data; };
    return res;
}

// Use a noop for next — tests below only exercise validation branches that call res.render, not next
function noop() {}

const handler = new ContributionsHandler(makeDb());

describe("ContributionsHandler – handleContributionsUpdate", () => {

    it("rejects non-numeric injection string without executing it", () => {
        // eval("require('child_process')") would have returned a module object;
        // parseInt("require('child_process')", 10) returns NaN — no execution, input rejected
        const req = makeReq("require('child_process')", "0", "0");
        const res = makeRes();
        handler.handleContributionsUpdate(req, res, noop);
        assert.strictEqual(res.lastTemplate, "contributions");
        assert.ok(res.lastData.updateError, "expected updateError for non-numeric input");
    });

    it("rejects negative values", () => {
        const req = makeReq("-5", "0", "0");
        const res = makeRes();
        handler.handleContributionsUpdate(req, res, noop);
        assert.strictEqual(res.lastTemplate, "contributions");
        assert.ok(res.lastData.updateError);
    });

    it("rejects contributions sum exceeding 30%", () => {
        const req = makeReq("20", "10", "1");
        const res = makeRes();
        handler.handleContributionsUpdate(req, res, noop);
        assert.strictEqual(res.lastTemplate, "contributions");
        assert.ok(res.lastData.updateError);
    });

});
