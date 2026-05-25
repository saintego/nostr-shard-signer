import { SimplePool, finalizeEvent } from "nostr-tools";
import type { UserProfile } from "../types";

export const DEFAULT_PUBLISH_RELAYS = [
  "wss://relay.damus.io",
  "wss://relay.nostr.band",
  "wss://nos.lol",
];

export const DEFAULT_REGISTRY_RELAYS = [
  "wss://relay.damus.io",
  "wss://relay.nostr.band",
];

export function publishToRelay(relayUrl: string, event: object): Promise<void> {
  return new Promise((resolve, reject) => {
    let ws: WebSocket | null = null;
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        ws?.close();
      } catch (_) {
        // Ignore close errors
      }
      fn();
    };

    const timer = setTimeout(() => {
      settle(() => reject(new Error("Timeout")));
    }, 8000);

    try {
      ws = new WebSocket(relayUrl);
    } catch (e) {
      clearTimeout(timer);
      reject(e as Error);
      return;
    }

    ws.onopen = () => ws!.send(JSON.stringify(["EVENT", event]));
    ws.onmessage = (e) => {
      let msg: unknown;
      try {
        msg = JSON.parse(e.data as string);
      } catch {
        return;
      }
      if (Array.isArray(msg) && msg[0] === "OK") {
        msg[2] !== false
          ? settle(() => resolve())
          : settle(() => reject(new Error((msg[3] as string) || "Rejected")));
      }
    };
    ws.onerror = () => {
      settle(() => reject(new Error("WebSocket error")));
    };
  });
}

export async function publishProfile(
  profile: UserProfile,
  privateKeyBytes: Uint8Array,
  relays: string[],
): Promise<void> {
  const event = finalizeEvent(
    {
      kind: 0,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content: JSON.stringify(profile),
    },
    privateKeyBytes,
  );
  await Promise.any(relays.map((r) => publishToRelay(r, event)));
}

export async function fetchProfile(
  pubkeyHex: string,
  relays = DEFAULT_PUBLISH_RELAYS,
): Promise<UserProfile | null> {
  const pool = new SimplePool();
  try {
    const events = await pool.querySync(
      relays,
      { authors: [pubkeyHex], kinds: [0], limit: 1 },
      { maxWait: 5000 },
    );
    if (!events.length) return null;
    return JSON.parse(events[0].content) as UserProfile;
  } catch (_) {
    return null;
  } finally {
    pool.close(relays);
  }
}
