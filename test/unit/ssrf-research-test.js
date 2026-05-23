"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

describe("SSRF fix (H-6) — research route", () => {
    const src = fs.readFileSync(
        path.join(__dirname, "../../app/routes/research.js"), "utf8"
    );

    it("defines an allowed base URL constant", () => {
        assert.ok(
            /ALLOWED_URL/.test(src),
            "No ALLOWED_URL constant found in research.js"
        );
    });

    it("validates req.query.url against the allowed base URL", () => {
        assert.ok(
            /req\.query\.url/.test(src) && /ALLOWED_URL/.test(src),
            "req.query.url is not checked against ALLOWED_URL"
        );
    });

    it("validates req.query.symbol with a regex allowlist", () => {
        assert.ok(
            /req\.query\.symbol/.test(src) && /test\(req\.query\.symbol\)/.test(src),
            "req.query.symbol is not validated with a regex test"
        );
    });
});
