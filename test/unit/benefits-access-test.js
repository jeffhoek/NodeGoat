"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

function stripBlockComments(src) {
    return src.replace(/\/\*[\s\S]*?\*\//g, "");
}

describe("Benefits access control (H-7)", () => {
    const src = stripBlockComments(
        fs.readFileSync(path.join(__dirname, "../../app/routes/index.js"), "utf8")
    );

    it("GET /benefits requires isAdmin middleware", () => {
        assert.ok(
            /app\.get\(["']\/benefits["'][^)]*isAdmin/.test(src),
            "GET /benefits route does not include isAdmin middleware"
        );
    });

    it("POST /benefits requires isAdmin middleware", () => {
        assert.ok(
            /app\.post\(["']\/benefits["'][^)]*isAdmin/.test(src),
            "POST /benefits route does not include isAdmin middleware"
        );
    });
});
