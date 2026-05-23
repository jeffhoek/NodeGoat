"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

function stripBlockComments(src) {
    return src.replace(/\/\*[\s\S]*?\*\//g, "");
}

describe("Session cookie flags (H-5)", () => {
    const activeSrc = stripBlockComments(
        fs.readFileSync(path.join(__dirname, "../../server.js"), "utf8")
    );

    it("session cookie has httpOnly: true in active server.js code", () => {
        assert.ok(
            /httpOnly\s*:\s*true/.test(activeSrc),
            "httpOnly: true not found in active session config"
        );
    });
});
