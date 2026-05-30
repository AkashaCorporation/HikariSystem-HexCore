/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Tests for the emulation session serialization lock (GitHub issue #28).
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { SessionLock, type SessionLockHandle } from './sessionLock';

suite('SessionLock — emulation session serialization (issue #28)', () => {

	test('acquire() resolves immediately when the lock is free', async () => {
		const lock = new SessionLock(60_000);
		assert.strictEqual(lock.isHeld, false);
		const h = await lock.acquire();
		assert.strictEqual(lock.isHeld, true);
		assert.ok(typeof h.token === 'number');
	});

	// THE CORE ISSUE #28 ASSERTION: a second emulate must WAIT for the first's
	// dispose instead of proceeding (which is what stomped the shared worker).
	test('second acquire() WAITS until the first releases (no stomping)', async () => {
		const lock = new SessionLock(60_000);

		const sessionA = await lock.acquire();   // job A's emulate

		let bAcquired = false;
		const bPromise = lock.acquire().then((h) => { bAcquired = true; return h; });

		// Let microtasks flush — B must still be blocked because A holds the lock.
		await Promise.resolve();
		await Promise.resolve();
		assert.strictEqual(bAcquired, false, 'job B must not acquire while job A holds the session');
		assert.strictEqual(lock.waiterCount, 1, 'job B should be queued');
		assert.strictEqual(lock.isHeld, true);

		// Job A disposes -> releases. Now B is allowed to proceed.
		lock.release(sessionA);
		const sessionB = await bPromise;
		assert.strictEqual(bAcquired, true, 'job B must acquire only after job A releases');
		assert.notStrictEqual(sessionB.token, sessionA.token, 'each session gets a distinct token');
		assert.strictEqual(lock.isHeld, true, 'lock is now held by B');
		assert.strictEqual(lock.waiterCount, 0);
	});

	test('release order is FIFO across multiple waiters', async () => {
		const lock = new SessionLock(60_000);
		const a = await lock.acquire();

		const order: string[] = [];
		const pB = lock.acquire().then((h) => { order.push('B'); return h; });
		const pC = lock.acquire().then((h) => { order.push('C'); return h; });

		assert.strictEqual(lock.waiterCount, 2);

		lock.release(a);
		const b = await pB;
		assert.deepStrictEqual(order, ['B'], 'B (first waiter) runs first');
		lock.release(b);
		const c = await pC;
		assert.deepStrictEqual(order, ['B', 'C'], 'C (second waiter) runs after B releases');
		lock.release(c);
		assert.strictEqual(lock.isHeld, false);
	});

	// Models the keepAlive multi-step flow: emulate(A) ... dispose(A) releases,
	// and a stale/duplicate dispose for an already-released session is a no-op
	// that must NOT release a DIFFERENT session that has since acquired.
	test('stale release for a non-holder token is ignored', async () => {
		const lock = new SessionLock(60_000);
		const a = await lock.acquire();
		lock.release(a);              // proper dispose of A
		const b = await lock.acquire(); // B now holds

		// A late/duplicate dispose carrying A's old token must not free B.
		lock.release(a);
		assert.strictEqual(lock.isHeld, true, 'B must still hold the lock');
		assert.strictEqual(b.token, b.token);

		lock.release(b);
		assert.strictEqual(lock.isHeld, false);
	});

	test('release(undefined) is a safe no-op (dispose without an active keepAlive handle)', async () => {
		const lock = new SessionLock(60_000);
		const a = await lock.acquire();
		// e.g. disposeHeadless called when keepAliveLockHandle is undefined
		lock.release(undefined as unknown as SessionLockHandle);
		assert.strictEqual(lock.isHeld, true, 'a no-op release must not drop the real holder');
		lock.release(a);
		assert.strictEqual(lock.isHeld, false);
	});

	// A crashed/abandoned session (never disposed) must not deadlock all future
	// emulations: the safety timer force-releases and hands off to the waiter.
	test('safety timeout force-releases an abandoned session and unblocks the next', async () => {
		const lock = new SessionLock(20); // 20ms hold budget for the test

		await lock.acquire(); // session A — intentionally NEVER released

		let bAcquired = false;
		const bPromise = lock.acquire().then((h) => { bAcquired = true; return h; });

		assert.strictEqual(bAcquired, false, 'B blocked while A holds');

		const b = await bPromise; // resolves only once the safety timer fires
		assert.strictEqual(bAcquired, true, 'B must acquire after A times out');
		assert.strictEqual(lock.isHeld, true, 'B now holds the lock');
		lock.release(b);
		assert.strictEqual(lock.isHeld, false);
	});

	test('a normal release cancels that session\'s safety timer (no stale force-release of the next holder)', async () => {
		// A acquires then releases promptly. A's safety timer must be cancelled by
		// that release, so it can NEVER fire later and stomp a subsequent holder B.
		// B is then held WELL WITHIN its own budget; it must stay held.
		const lock = new SessionLock(80);
		const a = await lock.acquire();
		lock.release(a); // releases ~immediately, far inside the 80ms budget

		const b = await lock.acquire(); // B gets its own fresh 80ms budget
		// Wait past A's original 80ms window but inside B's: if A's timer had not
		// been cancelled it would (wrongly) have force-released B around now.
		await new Promise((r) => setTimeout(r, 30));
		assert.strictEqual(lock.isHeld, true, 'B must still hold; A\'s cancelled timer must not force-release B');
		lock.release(b);
		assert.strictEqual(lock.isHeld, false);
	});
});
