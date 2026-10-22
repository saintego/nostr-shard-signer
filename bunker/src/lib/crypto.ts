import { finalizeEvent, nip04, nip44 } from "nostr-tools";
import { bytesToHex } from "./hex";

export async function processRpc(
  method: string,
  params: string[],
  privateKeyBytes: Uint8Array,
  publicKeyHex: string,
): Promise<string> {
  switch (method) {
    case "get_public_key":
      return publicKeyHex;

    case "sign_event": {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const signed = finalizeEvent(
        JSON.parse(params[0]) as any,
        privateKeyBytes,
      );
      return JSON.stringify(signed);
    }

    case "nip04_encrypt":
      return nip04.encrypt(bytesToHex(privateKeyBytes), params[0], params[1]);

    case "nip04_decrypt":
      return nip04.decrypt(bytesToHex(privateKeyBytes), params[0], params[1]);

    case "nip44_encrypt": {
      const ck = nip44.v2.utils.getConversationKey(privateKeyBytes, params[0]);
      return nip44.v2.encrypt(params[1], ck);
    }

    case "nip44_decrypt": {
      const ck = nip44.v2.utils.getConversationKey(privateKeyBytes, params[0]);
      return nip44.v2.decrypt(params[1], ck);
    }

    default:
      throw new Error(`Unknown method: ${method}`);
  }
}
