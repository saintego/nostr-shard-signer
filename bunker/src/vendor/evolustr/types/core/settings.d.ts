/** Shared settings document (SPEC §9): per-field values with timestamps. */
import { type EvolustrError, type Result } from "./result.ts";
export interface SharedSettings {
    readonly theme: "light" | "dark" | "system";
    readonly language: string;
    readonly locale: string;
    readonly timeZone: string;
    readonly reducedMotion: boolean;
    readonly fontScale: number;
    readonly density: "compact" | "comfortable";
}
export type SettingKey = keyof SharedSettings;
export interface SettingEntry {
    readonly value: unknown;
    /** Unix seconds of the change. */
    readonly at: number;
}
export interface SettingsDoc {
    readonly v: 1;
    readonly values: Readonly<Record<string, SettingEntry>>;
}
export declare const emptySettings: SettingsDoc;
/** Own keys only: `constructor`, `__proto__` and the like are not settings (#33). */
export declare const isSettingKey: (key: string) => key is SettingKey;
/** Valid value for a known key? Unknown (namespaced) keys accept any JSON value. */
export declare const isValidSetting: (key: string, value: unknown) => boolean;
export declare const parseSettings: (json: string) => Result<SettingsDoc, EvolustrError>;
/** Per field, the newer `at` wins; unknown keys are kept (SPEC §9.1). */
export declare const mergeSettings: (a: SettingsDoc, b: SettingsDoc) => SettingsDoc;
export declare const setSetting: (doc: SettingsDoc, key: string, value: unknown, at: number) => Result<SettingsDoc, EvolustrError>;
export declare const defaultSettings: (env?: {
    readonly language?: string;
    readonly timeZone?: string;
}) => SharedSettings;
/** `app ?? shared ?? default`, ignoring invalid stored values (SPEC §9.2). */
export declare const resolveSetting: <K extends SettingKey>(key: K, app: SettingsDoc, shared: SettingsDoc, defaults: SharedSettings) => SharedSettings[K];
//# sourceMappingURL=settings.d.ts.map