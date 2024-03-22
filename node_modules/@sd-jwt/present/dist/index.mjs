var __async = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};

// src/present.ts
import {
  SD_SEPARATOR
} from "@sd-jwt/types";
import { Disclosure, SDJWTException } from "@sd-jwt/utils";
import {
  createHashMapping,
  decodeSdJwt,
  getSDAlgAndPayload,
  splitSdJwt,
  unpack,
  createHashMappingSync,
  decodeSdJwtSync,
  unpackSync,
  unpackObj
} from "@sd-jwt/decode";
var presentableKeys = (rawPayload, disclosures, hasher) => __async(void 0, null, function* () {
  const { disclosureKeymap } = yield unpack(rawPayload, disclosures, hasher);
  return Object.keys(disclosureKeymap).sort();
});
var presentableKeysSync = (rawPayload, disclosures, hasher) => {
  const { disclosureKeymap } = unpackSync(rawPayload, disclosures, hasher);
  return Object.keys(disclosureKeymap).sort();
};
var present = (sdJwt, presentFrame, hasher) => __async(void 0, null, function* () {
  const { jwt, kbJwt } = splitSdJwt(sdJwt);
  const {
    jwt: { payload },
    disclosures
  } = yield decodeSdJwt(sdJwt, hasher);
  const { _sd_alg: alg } = getSDAlgAndPayload(payload);
  const hash = { alg, hasher };
  const keys = transformPresentationFrame(presentFrame);
  const hashmap = yield createHashMapping(disclosures, hash);
  const { disclosureKeymap } = yield unpack(payload, disclosures, hasher);
  const presentedDisclosures = keys.map((k) => hashmap[disclosureKeymap[k]]).filter((d) => d !== void 0);
  return [
    jwt,
    ...presentedDisclosures.map((d) => d.encode()),
    kbJwt != null ? kbJwt : ""
  ].join(SD_SEPARATOR);
});
var presentSync = (sdJwt, presentFrame, hasher) => {
  const { jwt, kbJwt } = splitSdJwt(sdJwt);
  const {
    jwt: { payload },
    disclosures
  } = decodeSdJwtSync(sdJwt, hasher);
  const { _sd_alg: alg } = getSDAlgAndPayload(payload);
  const hash = { alg, hasher };
  const keys = transformPresentationFrame(presentFrame);
  const hashmap = createHashMappingSync(disclosures, hash);
  const { disclosureKeymap } = unpackSync(payload, disclosures, hasher);
  const presentedDisclosures = keys.map((k) => hashmap[disclosureKeymap[k]]).filter((d) => d !== void 0);
  return [
    jwt,
    ...presentedDisclosures.map((d) => d.encode()),
    kbJwt != null ? kbJwt : ""
  ].join(SD_SEPARATOR);
};
var transformPresentationFrame = (obj, prefix = "") => {
  return Object.entries(obj).reduce((acc, [key, value]) => {
    const newPrefix = prefix ? `${prefix}.${key}` : key;
    if (typeof value === "boolean") {
      if (value) {
        acc.push(newPrefix);
      }
    } else {
      acc.push(
        newPrefix,
        ...transformPresentationFrame(value, newPrefix)
      );
    }
    return acc;
  }, []);
};
var createHashMappingForSerializedDisclosure = (disclosures) => {
  const map = {};
  for (let i = 0; i < disclosures.length; i++) {
    const disclosure = disclosures[i];
    const { digest, encoded, key, salt, value } = disclosure;
    map[digest] = Disclosure.fromArray(
      key ? [salt, key, value] : [salt, value],
      { digest, encoded }
    );
  }
  return map;
};
var selectDisclosures = (payload, disclosures, presentationFrame) => {
  if (disclosures.length === 0) {
    return [];
  }
  const hashmap = createHashMappingForSerializedDisclosure(disclosures);
  const { disclosureKeymap } = unpackObj(payload, hashmap);
  const keys = transformPresentationFrame(presentationFrame);
  const presentedDisclosures = keys.map((k) => hashmap[disclosureKeymap[k]]).filter((d) => d !== void 0);
  const selectedDisclosures = presentedDisclosures.map(
    (d) => {
      const { salt, key, value, _digest } = d;
      if (!_digest) {
        throw new SDJWTException(
          "Implementation error: _digest is not defined"
        );
      }
      return {
        digest: _digest,
        encoded: d.encode(),
        salt,
        key,
        value
      };
    }
  );
  return selectedDisclosures;
};
export {
  createHashMappingForSerializedDisclosure,
  present,
  presentSync,
  presentableKeys,
  presentableKeysSync,
  selectDisclosures,
  transformPresentationFrame
};
