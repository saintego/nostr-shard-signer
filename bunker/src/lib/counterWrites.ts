// Writing the identity counter (D12, #140): never below what any relay holds.
// Pure apart from the reads and writes the caller passes in.

import type { Event, Filter } from 'nostr-tools';
import { buildCounter, counterFilter, readCounter } from './counter';

export interface CounterIo {
  readonly query: (filter: Filter) => Promise<Event[] | null>;
  /** Waits for every relay; default `query`. */
  readonly queryAll?: (filter: Filter) => Promise<Event[] | null>;
  readonly publish: (events: Event[]) => Promise<void>;
}

export function counterWrites(
  root: Uint8Array,
  counterPub: string,
  io: CounterIo,
  now: () => number
) {
  /**
   * The counter from every relay: what a counter write builds on. Undefined
   * when the relays can't say; then no counter is written.
   */
  const full = async (): Promise<number | null | undefined> => {
    const events = await (io.queryAll ?? io.query)(counterFilter(counterPub));
    return events === null ? undefined : readCounter(events, root);
  };
  /** Publishes the counter: at least `next`, never below what any relay holds. */
  const write = async (next: number, seen?: number | null) => {
    const known = seen === undefined ? await full() : seen;
    if (known === undefined) return; // can't read every relay: retried at a later sign-in
    await io.publish([await buildCounter(root, Math.max(next, known ?? 0), now())]);
  };
  return { full, write };
}
