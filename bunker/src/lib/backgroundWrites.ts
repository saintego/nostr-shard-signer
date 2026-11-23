// Relay writes that don't hold up the sign-in window (#110): each write starts
// at once and the caller goes on; the window waits for them only before it
// closes, and at most `maxMs`.

/** Publishes events (resolves when done; may take seconds per relay). */
export type Publish<E> = (events: E[]) => Promise<unknown>;

export interface BackgroundWrites<E> {
  /** Starts the write and resolves at once; failures are left to the publisher's own retries. */
  readonly publish: (events: E[]) => Promise<void>;
  /** Counts other background work (e.g. a database syncing before it closes) as a write. */
  readonly track: (work: Promise<unknown>) => void;
  /** How many writes are still running. */
  readonly pending: () => number;
  /** Resolves when every running write has finished, or after `maxMs`. */
  readonly settled: (maxMs: number) => Promise<void>;
}

export function backgroundWrites<E>(publish: Publish<E>): BackgroundWrites<E> {
  const running = new Set<Promise<unknown>>();
  const track = (work: Promise<unknown>) => {
    const write = work.catch(() => {});
    running.add(write);
    void write.finally(() => running.delete(write));
  };
  return {
    publish: async (events) => track(publish(events)),
    track,
    pending: () => running.size,
    settled: (maxMs) =>
      Promise.race([
        Promise.allSettled([...running]).then(() => undefined),
        new Promise<void>((resolve) => setTimeout(resolve, maxMs)),
      ]),
  };
}

/** Rejects with `message` if `step` takes longer than `ms` (#110): never spin for minutes. */
export function withTimeout<T>(step: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    step.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e: unknown) => {
        clearTimeout(timer);
        reject(e);
      }
    );
  });
}

/** Logs how long a step took, for finding slow steps in a user's console (#110). */
export async function timed<T>(label: string, step: Promise<T>): Promise<T> {
  const start = performance.now();
  try {
    return await step;
  } finally {
    console.log('[signin] %s: %d ms', label, Math.round(performance.now() - start));
  }
}
