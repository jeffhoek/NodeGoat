"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

function stripAllComments(src) {
    return src
        .replace(/\/\*[\s\S]*?\*\//g, "")   // block comments
        .replace(/\/\/[^\n]*/g, "");          // line comments
}

describe("Session fixation fix (H-8)", () => {
    const src = stripAllComments(
        fs.readFileSync(path.join(__dirname, "../../app/routes/session.js"), "utf8")
    );

    it("handleLoginRequest regenerates the session before setting userId", () => {
        // After the fix, req.session.regenerate wraps the isAdmin redirect.
        // Check that regenerate appears within 200 chars of the login redirect,
        // distinguishing it from the signup handler which uses res.render, not res.redirect.
        assert.ok(
            /regenerate[\s\S]{0,200}isAdmin.*["']\/benefits["']/.test(src),
            "req.session.regenerate not found wrapping the login redirect in handleLoginRequest"
        );
    });
});
