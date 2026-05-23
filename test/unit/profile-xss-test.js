"use strict";

const assert = require("assert");
const ProfileHandler = require("../../app/routes/profile");

// Minimal DB stub: getByUserId returns a doc with whatever is passed in
function makeDb(doc) {
    return {
        collection: () => ({
            findOne: (_q, cb) => cb(null, Object.assign({}, doc)),
            update: (_q, _u, cb) => cb(null),
            find: () => ({ toArray: () => {} })
        })
    };
}

// Capture what res.render() is called with
function makeRes() {
    const res = { rendered: null };
    res.render = (view, locals) => { res.rendered = { view, locals }; };
    return res;
}

function makeReq(session, body) {
    return { session: session || {}, body: body || {} };
}

describe("profile.js – M-4 XSS fixes", () => {

    describe("displayProfile – website scheme validation", () => {

        it("passes a valid https:// website through to the template", (done) => {
            const db = makeDb({ _id: 1, firstName: "Alice", website: "https://example.com" });
            const handler = new ProfileHandler(db);
            const req = makeReq({ userId: 1 });
            const res = makeRes();
            handler.displayProfile(req, res, done);
            setImmediate(() => {
                assert.ok(res.rendered, "render should have been called");
                assert.strictEqual(res.rendered.locals.website, "https://example.com",
                    "valid https:// website must pass through");
                done();
            });
        });

        it("blanks a javascript: website before rendering", (done) => {
            const db = makeDb({ _id: 1, firstName: "Alice", website: "javascript:alert(1)" });
            const handler = new ProfileHandler(db);
            const req = makeReq({ userId: 1 });
            const res = makeRes();
            handler.displayProfile(req, res, done);
            setImmediate(() => {
                assert.ok(res.rendered, "render should have been called");
                assert.strictEqual(res.rendered.locals.website, "",
                    "javascript: website must be blanked before rendering");
                done();
            });
        });

        it("blanks a non-http website before rendering", (done) => {
            const db = makeDb({ _id: 1, firstName: "Alice", website: "ftp://evil.com" });
            const handler = new ProfileHandler(db);
            const req = makeReq({ userId: 1 });
            const res = makeRes();
            handler.displayProfile(req, res, done);
            setImmediate(() => {
                assert.ok(res.rendered, "render should have been called");
                assert.strictEqual(res.rendered.locals.website, "",
                    "non-http/https website must be blanked before rendering");
                done();
            });
        });

    });

    describe("handleProfileUpdate – firstNameSafeString is not raw firstName", () => {

        it("does not pass raw firstName as href when bankRouting is invalid", () => {
            const db = makeDb({});
            const handler = new ProfileHandler(db);
            const req = makeReq(
                { userId: 1 },
                { firstName: "javascript:alert(1)", lastName: "Smith",
                  ssn: "", dob: "", address: "", bankAcc: "", bankRouting: "INVALID" }
            );
            const res = makeRes();
            handler.handleProfileUpdate(req, res, (err) => { throw err; });
            assert.ok(res.rendered, "render should have been called on validation failure");
            const { firstNameSafeString } = res.rendered.locals;
            assert.notStrictEqual(firstNameSafeString, "javascript:alert(1)",
                "firstNameSafeString must not equal raw firstName");
        });

        it("firstNameSafeString is a safe Google search URL", () => {
            const db = makeDb({});
            const handler = new ProfileHandler(db);
            const req = makeReq(
                { userId: 1 },
                { firstName: "Alice Smith", lastName: "Smith",
                  ssn: "", dob: "", address: "", bankAcc: "", bankRouting: "INVALID" }
            );
            const res = makeRes();
            handler.handleProfileUpdate(req, res, (err) => { throw err; });
            assert.ok(res.rendered, "render should have been called on validation failure");
            const { firstNameSafeString } = res.rendered.locals;
            assert.ok(firstNameSafeString.startsWith("https://www.google.com/search?q="),
                "firstNameSafeString must be a safe Google search URL");
            assert.ok(firstNameSafeString.includes(encodeURIComponent("Alice Smith")),
                "firstNameSafeString must include URL-encoded name");
        });

    });

});
