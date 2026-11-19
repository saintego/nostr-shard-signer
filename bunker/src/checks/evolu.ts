// C8, second half: a real Evolu instance (same versions as Evolustr) at top
// level and in the cross-site iframe. Every context uses the same *public test*
// owner, so rows written in one context should reach the others through
// Evolu's relay: that also checks sync from a partitioned iframe (D11).
//
// The test owner's secret is derived from a fixed string: anyone can read and
// write these rows. Never put anything real here.

import { AppName, createAppOwner, createEvolu, createQueryBuilder, id, NonEmptyTrimmedString1000, OwnerSecret } from '@evolu/common';
import { createEvoluDeps, createRun } from '@evolu/web';
import { Report, age, button, crossFrame, h, originPicker, otherOrigin, role } from './ui';

const Schema = { checkRow: { id: id('CheckRow'), text: NonEmptyTrimmedString1000 } };

async function testOwner() {
    const secret = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('nostr-shard-signer/checks/evolu-test-owner')));
    return createAppOwner(OwnerSecret.orThrow(secret));
}

export function viewEvolu(r: Report): HTMLElement {
    const rowsEl = h('ul', { style: 'font-size:13px' });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let evolu: any = null;
    const createQuery = createQueryBuilder(Schema);
    const allRows = createQuery(db => db.selectFrom('checkRow').select(['id', 'text', 'createdAt']).where('isDeleted', 'is not', 1).orderBy('createdAt'));
    const label = `${role} on ${location.host}`;

    // loadQuery caches; after the first load, rows come from the subscription.
    const show = async (why: string) => {
        if (!evolu) return;
        const rows = evolu.getQueryRows(allRows) as ReadonlyArray<{ text: string; createdAt: string }>;
        rowsEl.replaceChildren(...rows.slice(-8).map(x => h('li', {}, `${x.text} (${age(Date.now() - Date.parse(x.createdAt))} ago)`)));
        const mine = rows.filter(x => x.text.startsWith(label)).length;
        const others = rows.length - mine;
        r.info(`${why}: ${rows.length} rows (${mine} written here, ${others} from other contexts)`);
        return rows.length;
    };

    void (async () => {
        try {
            const deps = createEvoluDeps();
            deps.evoluError.subscribe(() => {
                const e = deps.evoluError.get();
                if (e !== null) r.fail(`Evolu error: ${JSON.stringify(e).slice(0, 300)}`);
            });
            const run = createRun(deps);
            const t0 = performance.now();
            evolu = await run.ok(createEvolu(Schema, {
                appName: AppName.orThrow('nss-checks'),
                appOwner: await testOwner(),
                onDatabaseDeleted: () => { },
            }));
            r.pass(`Evolu started (${Math.round(performance.now() - t0)} ms)`);
            await evolu.loadQuery(allRows);
            await show('Local database');
            evolu.subscribeQuery(allRows)(() => void show('Rows changed'));
        } catch (e) {
            r.fail(`Evolu didn't start: ${(e as Error)?.message ?? JSON.stringify(e)}`);
        }
    })();

    return h('div', {},
        h('p', {},
            button('Write a row', () => {
                if (!evolu) return r.fail('Evolu not started');
                const text = `${label} at ${new Date().toISOString().slice(11, 19)}`;
                // Evolu 8: insert returns { id } and validates typed values up front.
                try {
                    evolu.insert('checkRow', { text: NonEmptyTrimmedString1000.orThrow(text) },
                        { onComplete: () => r.info('Row written') });
                } catch (e) { r.fail(`insert: ${(e as Error)?.message ?? JSON.stringify(e)}`); }
            }), ' ',
            button('Reload rows (shows synced rows)', () => show('Now')),
        ),
        rowsEl,
    );
}

export function hostEvolu(r: Report): HTMLElement {
    const box = h('div');
    const mount = () => box.replaceChildren(crossFrame('EVOLU', otherOrigin()));
    mount();
    return h('div', {},
        h('ol', {},
            h('li', {}, 'Wait for "Evolu started" here and in the dashed iframe.'),
            h('li', {}, 'Click "Write a row" here, then "Reload rows" in the iframe after a few seconds: the row should arrive through Evolu\'s relay. Then the other way round.'),
            h('li', {}, 'Reload the page: rows written earlier should still be there (local database survives).'),
            h('li', {}, 'Copy both reports. Revisit with C8 after 1, 3, 7, 10 days.'),
        ),
        viewEvolu(r),
        originPicker(mount),
        box,
    );
}
