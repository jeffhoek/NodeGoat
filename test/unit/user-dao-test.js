"use strict";

const assert = require("assert");
const bcrypt = require("bcrypt-nodejs");
const { UserDAO } = require("../../app/data/user-dao");

function makeDb(opts) {
    opts = opts || {};
    return {
        collection: (name) => {
            if (name === "counters") {
                return {
                    findAndModify: (q, s, u, o, cb) => cb(null, { value: { seq: 42 } })
                };
            }
            return {
                insert: (doc, cb) => {
                    if (opts.onInsert) opts.onInsert(doc);
                    cb(null, { ops: [doc] });
                },
                findOne: (q, cb) => cb(null, opts.storedUser || null)
            };
        }
    };
}

describe("UserDAO – password handling (H-2)", () => {

    describe("addUser", () => {
        it("stores a bcrypt hash, not the plaintext password", (done) => {
            const dao = new UserDAO(makeDb());
            dao.addUser("testuser", "Test", "User", "s3cr3t!", "t@example.com", (err, user) => {
                assert.ifError(err);
                assert.notStrictEqual(user.password, "s3cr3t!", "plaintext password was stored");
                assert.ok(
                    bcrypt.compareSync("s3cr3t!", user.password),
                    "stored value is not a valid bcrypt hash of the password"
                );
                done();
            });
        });
    });

    describe("validateLogin", () => {
        const hash = bcrypt.hashSync("correct_pw", bcrypt.genSaltSync());

        it("accepts correct password against a bcrypt hash", (done) => {
            const dao = new UserDAO(makeDb({ storedUser: { userName: "u", password: hash } }));
            dao.validateLogin("u", "correct_pw", (err, user) => {
                assert.ifError(err);
                assert.ok(user, "expected user to be returned");
                done();
            });
        });

        it("rejects wrong password against a bcrypt hash", (done) => {
            const dao = new UserDAO(makeDb({ storedUser: { userName: "u", password: hash } }));
            dao.validateLogin("u", "wrong_pw", (err, user) => {
                assert.ok(err && err.invalidPassword, "expected invalidPassword error for wrong password");
                assert.strictEqual(user, null);
                done();
            });
        });
    });
});
