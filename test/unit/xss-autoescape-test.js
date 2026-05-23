"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

function stripBlockComments(src) {
    return src.replace(/\/\*[\s\S]*?\*\//g, "");
}

describe("Swig autoescape / XSS fix (H-4)", () => {
    const serverSrc = stripBlockComments(
        fs.readFileSync(path.join(__dirname, "../../server.js"), "utf8")
    );

    it("autoescape is not set to false in active server.js code", () => {
        assert.ok(
            !/autoescape\s*:\s*false/.test(serverSrc),
            "autoescape: false found in active server.js code"
        );
    });

    it("autoescape: true is set in server.js", () => {
        assert.ok(
            /autoescape\s*:\s*true/.test(serverSrc),
            "autoescape: true not found in server.js"
        );
    });

    it("memos.html pipes marked() output through | safe", () => {
        const src = fs.readFileSync(
            path.join(__dirname, "../../app/views/memos.html"), "utf8"
        );
        assert.ok(
            /marked\(doc\.memo\)\s*\|\s*safe/.test(src),
            "memos.html: marked(doc.memo) is missing the | safe filter"
        );
    });

    ["layout.html", "login.html", "signup.html"].forEach(tpl => {
        it(`${tpl} pipes {{script}} through | safe`, () => {
            const src = fs.readFileSync(
                path.join(__dirname, `../../app/views/${tpl}`), "utf8"
            );
            assert.ok(
                /\{\{\s*script\s*\|\s*safe\s*\}\}/.test(src),
                `${tpl}: {{script}} is missing the | safe filter`
            );
        });
    });
});
