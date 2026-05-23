"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

// Strip /* */ block comments so we can distinguish active code from commented-out code.
function stripBlockComments(src) {
    return src.replace(/\/\*[\s\S]*?\*\//g, "");
}

describe("CSRF protection (H-1)", () => {
    const serverPath = path.join(__dirname, "../../server.js");
    const serverSrc = fs.readFileSync(serverPath, "utf8");
    const activeSrc = stripBlockComments(serverSrc);

    it("csurf is imported (not commented out)", () => {
        const lines = activeSrc.split("\n");
        const found = lines.some(l => /^\s*const csrf\s*=\s*require\(['"]csurf['"]\)/.test(l));
        assert.ok(found, "const csrf = require('csurf') is commented out or missing");
    });

    it("csrf() middleware is registered via app.use", () => {
        assert.ok(
            /app\.use\(csrf\(\)\)/.test(activeSrc),
            "app.use(csrf()) not found in active (non-commented) server.js code"
        );
    });

    it("csrftoken is exposed to templates via res.locals", () => {
        assert.ok(
            /res\.locals\.csrftoken/.test(activeSrc),
            "res.locals.csrftoken not set in active server.js code"
        );
    });

    const templates = [
        "profile.html",
        "contributions.html",
        "login.html",
        "benefits.html",
        "memos.html",
    ];

    templates.forEach(tpl => {
        it(`${tpl} contains a hidden _csrf input`, () => {
            const html = fs.readFileSync(
                path.join(__dirname, `../../app/views/${tpl}`),
                "utf8"
            );
            assert.ok(
                /name=["']_csrf["']/.test(html),
                `${tpl} is missing <input type="hidden" name="_csrf" ...>`
            );
        });
    });
});
