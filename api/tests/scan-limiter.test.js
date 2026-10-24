const { test } = require("node:test");
const assert = require("node:assert/strict");
const { ScanCapacityError, ScanLimiter } = require("../src/scan-limiter");

test("bounds active scans and the FIFO waiting queue, then recovers capacity", async () => {
    const limiter = new ScanLimiter(1, 1);
    const releaseFirst = await limiter.acquire();
    const waiting = limiter.acquire();

    assert.equal(limiter.activeCount, 1);
    assert.equal(limiter.queuedCount, 1);
    await assert.rejects(limiter.acquire(), ScanCapacityError);
    assert.equal(limiter.queuedCount, 1);

    releaseFirst();
    const releaseSecond = await waiting;
    assert.equal(limiter.activeCount, 1);
    assert.equal(limiter.queuedCount, 0);

    releaseSecond();
    const releaseRecovered = await limiter.acquire();
    assert.equal(limiter.activeCount, 1);
    releaseRecovered();
    assert.equal(limiter.activeCount, 0);
});

test("removes disconnected waiters without consuming future capacity", async () => {
    const limiter = new ScanLimiter(1, 1);
    const releaseActive = await limiter.acquire();
    const controller = new AbortController();
    const waiting = limiter.acquire(controller.signal);

    controller.abort();
    await assert.rejects(waiting, { name: "AbortError" });
    assert.equal(limiter.queuedCount, 0);

    releaseActive();
    const releaseNext = await limiter.acquire();
    assert.equal(limiter.activeCount, 1);
    releaseNext();
});

test("releases a lease in failure cleanup", async () => {
    const limiter = new ScanLimiter(1, 0);

    await assert.rejects(async () => {
        const release = await limiter.acquire();
        try {
            throw new Error("simulated scan failure");
        } finally {
            release();
        }
    }, /simulated scan failure/);

    assert.equal(limiter.activeCount, 0);
    const releaseRecovered = await limiter.acquire();
    releaseRecovered();
});
