import { Hasher, PresentationFrame } from '@sd-jwt/types';
import { Disclosure } from '@sd-jwt/utils';
import { HasherSync } from '@sd-jwt/types/src/type';

declare const presentableKeys: (rawPayload: Record<string, unknown>, disclosures: Array<Disclosure>, hasher: Hasher) => Promise<string[]>;
declare const presentableKeysSync: (rawPayload: Record<string, unknown>, disclosures: Array<Disclosure>, hasher: HasherSync) => string[];
declare const present: <T extends Record<string, unknown>>(sdJwt: string, presentFrame: PresentationFrame<T>, hasher: Hasher) => Promise<string>;
declare const presentSync: <T extends Record<string, unknown>>(sdJwt: string, presentFrame: PresentationFrame<T>, hasher: HasherSync) => string;
/**
 * Transform the object keys into an array of strings. We are not sorting the array in any way.
 * @param obj The object to transform
 * @param prefix The prefix to add to the keys
 * @returns
 */
declare const transformPresentationFrame: <T extends object>(obj: PresentationFrame<T>, prefix?: string) => string[];
type SerializedDisclosure = {
    digest: string;
    encoded: string;
    salt: string;
    key: string | undefined;
    value: unknown;
};
declare const createHashMappingForSerializedDisclosure: (disclosures: SerializedDisclosure[]) => Record<string, Disclosure<unknown>>;
/**
 * This function selects the serialized disclosures from the payload
 * and array of serialized disclosure based on the presentation frame.
 * If you want to know what is serialized disclosures, check type SerializedDisclosure.
 * @param payload: Record<string, unknown>
 * @param disclosures: SerializedDisclosure[]
 * @param presentationFrame: PresentationFrame<T>
 */
declare const selectDisclosures: <T extends Record<string, unknown>>(payload: Record<string, unknown>, disclosures: SerializedDisclosure[], presentationFrame: PresentationFrame<T>) => SerializedDisclosure[];

export { type SerializedDisclosure, createHashMappingForSerializedDisclosure, present, presentSync, presentableKeys, presentableKeysSync, selectDisclosures, transformPresentationFrame };
