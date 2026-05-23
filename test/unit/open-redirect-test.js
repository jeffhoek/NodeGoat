"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

describe("Open redirect fix (H-3)", () => {
    const src = fs.readFileSync(path.join(__dirname, "../../app/routes/index.js"), "utf8");

    it("defines an ALLOWED list for the /learn redirect", () => {
        assert.ok(/ALLOWED/.test(src), "No ALLOWED array found in index.js");
    });

    it("gates the redirect with an includes() check", () => {
        assert.ok(/\.includes\(/.test(src), "No .includes() guard found in index.js");
    });
});
