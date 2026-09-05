import * as assert from 'assert';
import { describeQueueObservation } from './queueObservation';

suite('queue observation context', () => {
	test('identifies the running observer without hiding other work', () => {
		const jobs = [{ jobId: 'observer', status: 'running' }, { jobId: 'other', status: 'running' }];
		const result = describeQueueObservation(jobs, { jobId: 'observer', executionId: 'run' });
		assert.strictEqual(result.includesCurrentJob, true);
		assert.strictEqual(result.terminalSnapshot, false);
		assert.strictEqual(jobs.length, 2);
	});
	test('does not mistake another running job for the observer', () => {
		assert.strictEqual(describeQueueObservation([{ jobId: 'other', status: 'running' }], { executionId: 'manual' }).includesCurrentJob, false);
	});
	test('direct queries without execution context are explicitly unknown', () => {
		assert.strictEqual(describeQueueObservation([]).includesCurrentJob, null);
	});
});
