/**
 * A counting semaphore for bounding one resource independently of the caller's own
 * concurrency limit (WAL-61 AC2): downloads may run at `DOWNLOAD_CONCURRENCY`, but a
 * CPU-bound transform must not run eight times over the same cores.
 */
export class Semaphore {
  private permits: number;
  private readonly waiters: Array<() => void> = [];

  constructor(permits: number) {
    if (!Number.isInteger(permits) || permits < 1) {
      throw new Error(`Semaphore permits must be a positive integer, got ${permits}`);
    }
    this.permits = permits;
  }

  /** Resolves once a permit is held; the returned function releases it. */
  async acquire(): Promise<() => void> {
    if (this.permits > 0) {
      this.permits -= 1;
      return () => this.release();
    }
    await new Promise<void>((resolve) => this.waiters.push(resolve));
    return () => this.release();
  }

  /** Run `fn` while holding one permit, releasing when it settles. */
  async withPermit<T>(fn: () => Promise<T>): Promise<T> {
    const release = await this.acquire();
    try {
      return await fn();
    } finally {
      release();
    }
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) {
      next();
      return;
    }
    this.permits += 1;
  }
}
