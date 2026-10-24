class ScanCapacityError extends Error {
    constructor() {
        super("Scan capacity is full.");
        this.name = "ScanCapacityError";
    }
}

function abortError() {
    const error = new Error("Scan admission was cancelled.");
    error.name = "AbortError";
    return error;
}

class ScanLimiter {
    #active = 0;
    #queue = [];

    constructor(maxActive, maxQueued) {
        if (!Number.isSafeInteger(maxActive) || maxActive < 1) {
            throw new RangeError("maxActive must be a positive safe integer.");
        }
        if (!Number.isSafeInteger(maxQueued) || maxQueued < 0) {
            throw new RangeError("maxQueued must be a non-negative safe integer.");
        }

        this.maxActive = maxActive;
        this.maxQueued = maxQueued;
    }

    get activeCount() {
        return this.#active;
    }

    get queuedCount() {
        return this.#queue.length;
    }

    acquire(signal) {
        if (signal?.aborted) return Promise.reject(abortError());
        if (this.#active < this.maxActive) {
            this.#active += 1;
            return Promise.resolve(this.#createLease());
        }
        if (this.#queue.length >= this.maxQueued) {
            return Promise.reject(new ScanCapacityError());
        }

        return new Promise((resolve, reject) => {
            const entry = { resolve, reject, signal, onAbort: null };
            if (signal) {
                entry.onAbort = () => {
                    const index = this.#queue.indexOf(entry);
                    if (index !== -1) {
                        this.#queue.splice(index, 1);
                        reject(abortError());
                    }
                };
                signal.addEventListener("abort", entry.onAbort, { once: true });
            }
            this.#queue.push(entry);
        });
    }

    #createLease() {
        let released = false;
        return () => {
            if (released) return;
            released = true;
            this.#active -= 1;
            this.#admitWaiting();
        };
    }

    #admitWaiting() {
        while (this.#active < this.maxActive && this.#queue.length > 0) {
            const entry = this.#queue.shift();
            entry.signal?.removeEventListener("abort", entry.onAbort);
            if (entry.signal?.aborted) {
                entry.reject(abortError());
                continue;
            }
            this.#active += 1;
            entry.resolve(this.#createLease());
        }
    }
}

function readLimit(name, fallback, allowZero) {
    const raw = process.env[name];
    if (raw === undefined) return fallback;
    if (!/^(0|[1-9]\d*)$/.test(raw)) {
        throw new Error(`${name} must be a ${allowZero ? "non-negative" : "positive"} integer.`);
    }
    const value = Number(raw);
    if (!Number.isSafeInteger(value) || (!allowZero && value === 0)) {
        throw new Error(`${name} must be a ${allowZero ? "non-negative" : "positive"} safe integer.`);
    }
    return value;
}

const scanLimiter = new ScanLimiter(
    readLimit("SECUREFLOW_SCAN_CONCURRENCY", 2, false),
    readLimit("SECUREFLOW_SCAN_QUEUE_LIMIT", 4, true)
);

module.exports = { ScanCapacityError, ScanLimiter, scanLimiter };
