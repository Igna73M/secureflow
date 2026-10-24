const session = require("express-session");

class SqliteSessionStore extends session.Store {
    constructor(db) {
        super();
        this.db = db;
        this.getSession = db.prepare("SELECT sess, expired FROM sessions WHERE sid = ?");
        this.putSession = db.prepare(`
            INSERT INTO sessions (sid, sess, expired)
            VALUES (?, ?, ?)
            ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expired = excluded.expired
        `);
        this.deleteSession = db.prepare("DELETE FROM sessions WHERE sid = ?");
        this.deleteExpired = db.prepare("DELETE FROM sessions WHERE expired <= ?");
    }

    get(sid, callback) {
        try {
            const row = this.getSession.get(sid);
            if (!row) return callback(null, null);
            if (row.expired <= Date.now()) {
                this.deleteSession.run(sid);
                return callback(null, null);
            }
            return callback(null, JSON.parse(row.sess));
        } catch (error) {
            return callback(error);
        }
    }

    set(sid, value, callback = () => { }) {
        try {
            const expires = value.cookie?.expires
                ? new Date(value.cookie.expires).getTime()
                : Date.now() + (value.cookie?.maxAge ?? 30 * 60 * 1000);
            this.deleteExpired.run(Date.now());
            this.putSession.run(sid, JSON.stringify(value), expires);
            callback(null);
        } catch (error) {
            callback(error);
        }
    }

    touch(sid, value, callback = () => { }) {
        this.set(sid, value, callback);
    }

    destroy(sid, callback = () => { }) {
        try {
            this.deleteSession.run(sid);
            callback(null);
        } catch (error) {
            callback(error);
        }
    }
}

module.exports = SqliteSessionStore;
