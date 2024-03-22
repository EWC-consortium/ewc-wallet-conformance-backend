import { DisclosureData, HasherAndAlg, HasherAndAlgSync } from '@sd-jwt/types';

declare const base64urlEncode: (src: string) => string;
declare const base64urlDecode: (src: string) => string;
declare const uint8ArrayToBase64Url: (input: Uint8Array) => string;

declare class SDJWTException extends Error {
    details?: unknown;
    constructor(message: string, details?: unknown);
    getFullMessage(): string;
}

declare class Disclosure<T = unknown> {
    salt: string;
    key?: string;
    value: T;
    _digest: string | undefined;
    private _encoded;
    constructor(data: DisclosureData<T>, _meta?: {
        digest: string;
        encoded: string;
    });
    static fromEncode<T>(s: string, hash: HasherAndAlg): Promise<Disclosure<T>>;
    static fromEncodeSync<T>(s: string, hash: HasherAndAlgSync): Disclosure<T>;
    static fromArray<T>(item: DisclosureData<T>, _meta?: {
        digest: string;
        encoded: string;
    }): Disclosure<T>;
    encode(): string;
    decode(): DisclosureData<T>;
    digest(hash: HasherAndAlg): Promise<string>;
    digestSync(hash: HasherAndAlgSync): string;
}

export { Disclosure, SDJWTException, base64urlDecode, base64urlEncode, uint8ArrayToBase64Url };
