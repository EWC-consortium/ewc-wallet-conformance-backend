"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
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

// src/index.ts
var src_exports = {};
__export(src_exports, {
  createHashMappingForSerializedDisclosure: () => createHashMappingForSerializedDisclosure,
  present: () => present,
  presentSync: () => presentSync,
  presentableKeys: () => presentableKeys,
  presentableKeysSync: () => presentableKeysSync,
  selectDisclosures: () => selectDisclosures,
  transformPresentationFrame: () => transformPresentationFrame
});
module.exports = __toCommonJS(src_exports);

// src/present.ts
var import_types = require("@sd-jwt/types");
var import_utils = require("@sd-jwt/utils");
var import_decode = require("@sd-jwt/decode");
var presentableKeys = (rawPayload, disclosures, hasher) => __async(void 0, null, function* () {
  const { disclosureKeymap } = yield (0, import_decode.unpack)(rawPayload, disclosures, hasher);
  return Object.keys(disclosureKeymap).sort();
});
var presentableKeysSync = (rawPayload, disclosures, hasher) => {
  const { disclosureKeymap } = (0, import_decode.unpackSync)(rawPayload, disclosures, hasher);
  return Object.keys(disclosureKeymap).sort();
};
var present = (sdJwt, presentFrame, hasher) => __async(void 0, null, function* () {
  const { jwt, kbJwt } = (0, import_decode.splitSdJwt)(sdJwt);
  const {
    jwt: { payload },
    disclosures
  } = yield (0, import_decode.decodeSdJwt)(sdJwt, hasher);
  const { _sd_alg: alg } = (0, import_decode.getSDAlgAndPayload)(payload);
  const hash = { alg, hasher };
  const keys = transformPresentationFrame(presentFrame);
  const hashmap = yield (0, import_decode.createHashMapping)(disclosures, hash);
  const { disclosureKeymap } = yield (0, import_decode.unpack)(payload, disclosures, hasher);
  const presentedDisclosures = keys.map((k) => hashmap[disclosureKeymap[k]]).filter((d) => d !== void 0);
  return [
    jwt,
    ...presentedDisclosures.map((d) => d.encode()),
    kbJwt != null ? kbJwt : ""
  ].join(import_types.SD_SEPARATOR);
});
var presentSync = (sdJwt, presentFrame, hasher) => {
  const { jwt, kbJwt } = (0, import_decode.splitSdJwt)(sdJwt);
  const {
    jwt: { payload },
    disclosures
  } = (0, import_decode.decodeSdJwtSync)(sdJwt, hasher);
  const { _sd_alg: alg } = (0, import_decode.getSDAlgAndPayload)(payload);
  const hash = { alg, hasher };
  const keys = transformPresentationFrame(presentFrame);
  const hashmap = (0, import_decode.createHashMappingSync)(disclosures, hash);
  const { disclosureKeymap } = (0, import_decode.unpackSync)(payload, disclosures, hasher);
  const presentedDisclosures = keys.map((k) => hashmap[disclosureKeymap[k]]).filter((d) => d !== void 0);
  return [
    jwt,
    ...presentedDisclosures.map((d) => d.encode()),
    kbJwt != null ? kbJwt : ""
  ].join(import_types.SD_SEPARATOR);
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
    map[digest] = import_utils.Disclosure.fromArray(
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
  const { disclosureKeymap } = (0, import_decode.unpackObj)(payload, hashmap);
  const keys = transformPresentationFrame(presentationFrame);
  const presentedDisclosures = keys.map((k) => hashmap[disclosureKeymap[k]]).filter((d) => d !== void 0);
  const selectedDisclosures = presentedDisclosures.map(
    (d) => {
      const { salt, key, value, _digest } = d;
      if (!_digest) {
        throw new import_utils.SDJWTException(
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  createHashMappingForSerializedDisclosure,
  present,
  presentSync,
  presentableKeys,
  presentableKeysSync,
  selectDisclosures,
  transformPresentationFrame
});
