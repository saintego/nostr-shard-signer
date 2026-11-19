// C8: OPFS sync access handle in a dedicated worker (needed by Evolu's SQLite).
(async () => {
    try {
        const root = await navigator.storage.getDirectory();
        const f = await root.getFileHandle('checks_c8_sync.bin', { create: true });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const handle = await (f as any).createSyncAccessHandle();
        handle.write(new TextEncoder().encode('sync ok'), { at: 0 });
        handle.flush();
        const size = handle.getSize();
        handle.close();
        postMessage(`ok (${size} bytes)`);
    } catch (e) {
        postMessage(`failed: ${(e as Error).message}`);
    }
})();
