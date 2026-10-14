/// <reference types="nostr-shard-signer/window" />
import { API_VERSION, loadNostrBridge } from "nostr-shard-signer";
import type { NostrBridgeAuthState, NostrBridgeConfig, NostrSignedEvent } from "nostr-shard-signer";

const config: NostrBridgeConfig = { clientId: "id", layout: "in-place", mountSelector: "#signer" };
const version: 1 = API_VERSION;

export async function main(): Promise<void> {
  const bridge = await loadNostrBridge(config);
  await loadNostrBridge();
  const off: () => void = bridge.onAuthChange((s: NostrBridgeAuthState) => console.log(s.pubkey));
  off();
  const apiVersion: number = bridge.apiVersion;
  // The global is typed too, for code that doesn't hold the loader's result.
  const state: NostrBridgeAuthState = NostrBridge.getAuthState();
  // window.nostr is typed by nostr-shard-signer/window.
  const signed: NostrSignedEvent = await window.nostr.signEvent({ kind: 1, created_at: 0, tags: [], content: "" });
  console.log(version, apiVersion, state, signed.sig);

  // @ts-expect-error: layout is a union
  loadNostrBridge({ layout: "sideways" });
  // @ts-expect-error: apiVersion is read-only
  bridge.apiVersion = 2;
}
