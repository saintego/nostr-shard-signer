/** A value or an error, returned instead of throwing. */
export type Result<T, E = EvolustrError> = {
    readonly ok: true;
    readonly value: T;
} | {
    readonly ok: false;
    readonly error: E;
};
/** Errors are plain data: a stable `type` plus a human-readable `message`. */
export interface EvolustrError {
    readonly type: string;
    readonly message: string;
}
export declare const ok: <T>(value: T) => Result<T, never>;
export declare const err: <E>(error: E) => Result<never, E>;
export declare const error: (type: string, message: string) => Result<never, EvolustrError>;
export declare const map: <T, U, E>(r: Result<T, E>, f: (value: T) => U) => Result<U, E>;
export declare const flatMap: <T, U, E, F>(r: Result<T, E>, f: (value: T) => Result<U, F>) => Result<U, E | F>;
/** Runs `f` and turns a thrown exception into an error result. */
export declare const attempt: <T>(type: string, f: () => T) => Result<T, EvolustrError>;
/** Async variant of {@link attempt}. */
export declare const attemptAsync: <T>(type: string, f: () => Promise<T>) => Promise<Result<T, EvolustrError>>;
/** Collects results: the first error, or all values. */
export declare const all: <T, E>(results: ReadonlyArray<Result<T, E>>) => Result<ReadonlyArray<T>, E>;
/** For tests and boundaries where an error is a bug. */
export declare const unwrap: <T, E>(r: Result<T, E>) => T;
//# sourceMappingURL=result.d.ts.map