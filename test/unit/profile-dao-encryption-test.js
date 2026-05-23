"use strict";

const assert = require("assert");
const { ProfileDAO } = require("../../app/data/profile-dao");

// Stub DB that captures the $set payload from update() and can feed it to findOne()
function makeDb() {
    let stored = {};
    return {
        _stored: () => stored,
        collection: () => ({
            update: (_query, doc, cb) => {
                stored = doc.$set || {};
                cb(null);
            },
            findOne: (_query, cb) => {
                cb(null, stored);
            }
        })
    };
}

describe("ProfileDAO – SSN/DOB encryption at rest", () => {

    it("does not store SSN as plaintext", (done) => {
        const db = makeDb();
        const dao = new ProfileDAO(db);
        dao.updateUser(1, "Alice", "Smith", "123-45-6789", "1990-01-01", "123 Main St", null, null, (err) => {
            assert.ifError(err);
            const stored = db._stored();
            assert.notStrictEqual(stored.ssn, "123-45-6789", "SSN must not be stored in plaintext");
            done();
        });
    });

    it("does not store DOB as plaintext", (done) => {
        const db = makeDb();
        const dao = new ProfileDAO(db);
        dao.updateUser(1, "Alice", "Smith", "123-45-6789", "1990-01-01", "123 Main St", null, null, (err) => {
            assert.ifError(err);
            const stored = db._stored();
            assert.notStrictEqual(stored.dob, "1990-01-01", "DOB must not be stored in plaintext");
            done();
        });
    });

    it("roundtrips SSN through encrypt/decrypt", (done) => {
        const db = makeDb();
        const dao = new ProfileDAO(db);
        dao.updateUser(1, "Alice", "Smith", "123-45-6789", "1990-01-01", "123 Main St", null, null, (err) => {
            assert.ifError(err);
            dao.getByUserId(1, (err2, user) => {
                assert.ifError(err2);
                assert.strictEqual(user.ssn, "123-45-6789", "SSN must decrypt back to original value");
                done();
            });
        });
    });

    it("roundtrips DOB through encrypt/decrypt", (done) => {
        const db = makeDb();
        const dao = new ProfileDAO(db);
        dao.updateUser(1, "Alice", "Smith", "123-45-6789", "1990-01-01", "123 Main St", null, null, (err) => {
            assert.ifError(err);
            dao.getByUserId(1, (err2, user) => {
                assert.ifError(err2);
                assert.strictEqual(user.dob, "1990-01-01", "DOB must decrypt back to original value");
                done();
            });
        });
    });

    it("produces different ciphertext on each encrypt call (unique IV)", (done) => {
        const results = [];
        let remaining = 2;
        const finish = () => {
            if (--remaining === 0) {
                assert.notStrictEqual(results[0], results[1], "each encrypt call must produce a unique ciphertext");
                done();
            }
        };
        for (let i = 0; i < 2; i++) {
            const db = makeDb();
            const dao = new ProfileDAO(db);
            dao.updateUser(1, "Alice", "Smith", "123-45-6789", "1990-01-01", "123 Main St", null, null, (err) => {
                assert.ifError(err);
                results.push(db._stored().ssn);
                finish();
            });
        }
    });

});
