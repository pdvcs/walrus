import { describe, expect, it } from "vitest";
import { Semaphore } from "../../src/common/semaphore.js";

describe("Semaphore", () => {
  it("rejects a permit count that cannot bound anything", () => {
    expect(() => new Semaphore(0)).toThrow(/positive integer/);
    expect(() => new Semaphore(1.5)).toThrow(/positive integer/);
  });

  it("holds a caller until a permit is handed back", async () => {
    const sem = new Semaphore(1);
    const first = await sem.acquire();

    let secondEntered = false;
    const second = sem.acquire().then((release) => {
      secondEntered = true;
      return release;
    });

    await Promise.resolve();
    expect(secondEntered).toBe(false);

    first();
    await second;
    expect(secondEntered).toBe(true);
  });

  it("ignores a second release rather than inventing a permit", async () => {
    // Releasing twice used to raise the ceiling: the bound is what keeps a CPU-bound
    // transform from running once per download slot (WAL-73 finding 7).
    const sem = new Semaphore(1);
    const release = await sem.acquire();
    release();
    release();

    await sem.acquire();

    let secondEntered = false;
    void sem.acquire().then(() => {
      secondEntered = true;
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(secondEntered).toBe(false);
  });

  it("releases the permit when withPermit's body throws", async () => {
    const sem = new Semaphore(1);
    await expect(sem.withPermit(() => Promise.reject(new Error("boom")))).rejects.toThrow("boom");

    await expect(sem.withPermit(() => Promise.resolve("ran"))).resolves.toBe("ran");
  });
});
