/* The ProfileDAO must be constructed with a connected database object */
function ProfileDAO(db) {

    "use strict";

    /* If this constructor is called without the "new" operator, "this" points
     * to the global object. Log a warning and call it correctly. */
    if (false === (this instanceof ProfileDAO)) {
        console.log("Warning: ProfileDAO constructor called without 'new' operator");
        return new ProfileDAO(db);
    }

    const users = db.collection("users");

    // Fix for A6 - Sensitive Data Exposure
    // Use crypto module to save sensitive data such as ssn, dob in encrypted format
    const crypto = require("crypto");
    const config = require("../../config/config");

    // Derive a fixed 32-byte key from the configured secret (aes-256-cbc requires 32-byte key)
    const KEY = crypto.scryptSync(config.cryptoKey, "nodegoat-salt", 32);
    const ALGO = "aes-256-cbc";

    // IV is generated fresh per call and prepended to ciphertext as "ivHex:dataHex"
    const encrypt = (plaintext) => {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(ALGO, KEY, iv);
        const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
        return iv.toString("hex") + ":" + enc.toString("hex");
    };

    const decrypt = (ciphertext) => {
        const [ivHex, dataHex] = ciphertext.split(":");
        const decipher = crypto.createDecipheriv(ALGO, KEY, Buffer.from(ivHex, "hex"));
        return Buffer.concat([decipher.update(Buffer.from(dataHex, "hex")), decipher.final()]).toString("utf8");
    };

    this.updateUser = (userId, firstName, lastName, ssn, dob, address, bankAcc, bankRouting, callback) => {

        // Create user document
        const user = {};
        if (firstName) {
            user.firstName = firstName;
        }
        if (lastName) {
            user.lastName = lastName;
        }
        if (address) {
            user.address = address;
        }
        if (bankAcc) {
            user.bankAcc = bankAcc;
        }
        if (bankRouting) {
            user.bankRouting = bankRouting;
        }
        if (ssn) {
            user.ssn = encrypt(ssn);
        }
        if (dob) {
            user.dob = encrypt(dob);
        }

        users.update({
                _id: parseInt(userId)
            }, {
                $set: user
            },
            err => {
                if (!err) {
                    console.log("Updated user profile");
                    return callback(null, user);
                }

                return callback(err, null);
            }
        );
    };

    this.getByUserId = (userId, callback) => {
        users.findOne({
                _id: parseInt(userId)
            },
            (err, user) => {
                if (err) return callback(err, null);
                // Fix for A6 - Sensitive Data Exposure
                // Decrypt ssn and DOB values to display to user
                user.ssn = user.ssn ? decrypt(user.ssn) : "";
                user.dob = user.dob ? decrypt(user.dob) : "";

                callback(null, user);
            }
        );
    };
}

module.exports = { ProfileDAO };
