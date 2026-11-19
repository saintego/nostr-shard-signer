import { useRef, type ButtonHTMLAttributes } from 'react';
import { useClickGuard } from '../lib/clickGuard';

/** A button that ignores clicks the user may not have meant (src/lib/clickGuard.ts). */
export function GuardedButton({ disabled, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
    const ref = useRef<HTMLButtonElement>(null);
    const armed = useClickGuard(ref);
    return <button ref={ref} {...props} disabled={disabled || !armed} data-armed={armed ? 'true' : 'false'} />;
}
