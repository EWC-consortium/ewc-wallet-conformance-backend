import { Disclosure } from '@sd-jwt/utils';
import { Hasher, HasherAndAlg } from '@sd-jwt/types';
import { HasherSync, HasherAndAlgSync } from '@sd-jwt/types/src/type';

declare const decodeJwt: <H extends Record<string, unknown>, T extends Record<string, unknown>>(jwt: string) => {
    header: H;
    payload: T;
    signature: string;
};
declare const splitSdJwt: (sdjwt: string) => {
    jwt: string;
    disclosures: string[];
    kbJwt?: string;
};
declare const decodeSdJwt: (sdjwt: string, hasher: Hasher) => Promise<DecodedSDJwt>;
declare const decodeSdJwtSync: (sdjwt: string, hasher: HasherSync) => DecodedSDJwt;
declare const getClaims: <T>(rawPayload: Record<string, unknown>, disclosures: Array<Disclosure>, hasher: Hasher) => Promise<T>;
declare const getClaimsSync: <T>(rawPayload: Record<string, unknown>, disclosures: Array<Disclosure>, hasher: HasherSync) => T;
declare const unpackArray: (arr: Array<unknown>, map: Record<string, Disclosure>, prefix?: string) => {
    unpackedObj: unknown;
    disclosureKeymap: Record<string, string>;
};
declare const unpackObj: (obj: unknown, map: Record<string, Disclosure>, prefix?: string) => {
    unpackedObj: unknown;
    disclosureKeymap: Record<string, string>;
};
declare const createHashMapping: (disclosures: Array<Disclosure>, hash: HasherAndAlg) => Promise<Record<string, Disclosure<unknown>>>;
declare const createHashMappingSync: (disclosures: Array<Disclosure>, hash: HasherAndAlgSync) => Record<string, Disclosure<unknown>>;
declare const getSDAlgAndPayload: (SdJwtPayload: Record<string, unknown>) => {
    _sd_alg: string;
    payload: {
        [x: string]: unknown;
    };
};
declare const unpack: (SdJwtPayload: Record<string, unknown>, disclosures: Array<Disclosure>, hasher: Hasher) => Promise<{
    unpackedObj: unknown;
    disclosureKeymap: Record<string, string>;
}>;
declare const unpackSync: (SdJwtPayload: Record<string, unknown>, disclosures: Array<Disclosure>, hasher: HasherSync) => {
    unpackedObj: unknown;
    disclosureKeymap: Record<string, string>;
};
type DecodedSDJwt = {
    jwt: {
        header: Record<string, unknown>;
        payload: Record<string, unknown>;
        signature: string;
    };
    disclosures: Array<Disclosure>;
    kbJwt?: {
        header: Record<string, unknown>;
        payload: Record<string, unknown>;
        signature: string;
    };
};

export { type DecodedSDJwt, createHashMapping, createHashMappingSync, decodeJwt, decodeSdJwt, decodeSdJwtSync, getClaims, getClaimsSync, getSDAlgAndPayload, splitSdJwt, unpack, unpackArray, unpackObj, unpackSync };
