"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getOwnPropSymbols = Object.getOwnPropertySymbols;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __propIsEnum = Object.prototype.propertyIsEnumerable;
var __objRest = (source, exclude) => {
  var target = {};
  for (var prop in source)
    if (__hasOwnProp.call(source, prop) && exclude.indexOf(prop) < 0)
      target[prop] = source[prop];
  if (source != null && __getOwnPropSymbols)
    for (var prop of __getOwnPropSymbols(source)) {
      if (exclude.indexOf(prop) < 0 && __propIsEnum.call(source, prop))
        target[prop] = source[prop];
    }
  return target;
};
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
  createHashMapping: () => createHashMapping,
  createHashMappingSync: () => createHashMappingSync,
  decodeJwt: () => decodeJwt,
  decodeSdJwt: () => decodeSdJwt,
  decodeSdJwtSync: () => decodeSdJwtSync,
  getClaims: () => getClaims,
  getClaimsSync: () => getClaimsSync,
  getSDAlgAndPayload: () => getSDAlgAndPayload,
  splitSdJwt: () => splitSdJwt,
  unpack: () => unpack,
  unpackArray: () => unpackArray,
  unpackObj: () => unpackObj,
  unpackSync: () => unpackSync
});
module.exports = __toCommonJS(src_exports);

// src/decode.ts
var import_utils = require("@sd-jwt/utils");
var import_types = require("@sd-jwt/types");
var decodeJwt = (jwt) => {
  const { 0: header, 1: payload, 2: signature, length } = jwt.split(".");
  if (length !== 3) {
    throw new import_utils.SDJWTException("Invalid JWT as input");
  }
  return {
    header: JSON.parse((0, import_utils.base64urlDecode)(header)),
    payload: JSON.parse((0, import_utils.base64urlDecode)(payload)),
    signature
  };
};
var splitSdJwt = (sdjwt) => {
  const [encodedJwt, ...encodedDisclosures] = sdjwt.split(import_types.SD_SEPARATOR);
  if (encodedDisclosures.length === 0) {
    return {
      jwt: encodedJwt,
      disclosures: []
    };
  }
  const encodedKeyBindingJwt = encodedDisclosures.pop();
  return {
    jwt: encodedJwt,
    disclosures: encodedDisclosures,
    kbJwt: encodedKeyBindingJwt || void 0
  };
};
var decodeSdJwt = (sdjwt, hasher) => __async(void 0, null, function* () {
  const [encodedJwt, ...encodedDisclosures] = sdjwt.split(import_types.SD_SEPARATOR);
  const jwt = decodeJwt(encodedJwt);
  if (encodedDisclosures.length === 0) {
    return {
      jwt,
      disclosures: []
    };
  }
  const encodedKeyBindingJwt = encodedDisclosures.pop();
  const kbJwt = encodedKeyBindingJwt ? decodeJwt(encodedKeyBindingJwt) : void 0;
  const { _sd_alg } = getSDAlgAndPayload(jwt.payload);
  const disclosures = yield Promise.all(
    encodedDisclosures.map(
      (ed) => import_utils.Disclosure.fromEncode(ed, { alg: _sd_alg, hasher })
    )
  );
  return {
    jwt,
    disclosures,
    kbJwt
  };
});
var decodeSdJwtSync = (sdjwt, hasher) => {
  const [encodedJwt, ...encodedDisclosures] = sdjwt.split(import_types.SD_SEPARATOR);
  const jwt = decodeJwt(encodedJwt);
  if (encodedDisclosures.length === 0) {
    return {
      jwt,
      disclosures: []
    };
  }
  const encodedKeyBindingJwt = encodedDisclosures.pop();
  const kbJwt = encodedKeyBindingJwt ? decodeJwt(encodedKeyBindingJwt) : void 0;
  const { _sd_alg } = getSDAlgAndPayload(jwt.payload);
  const disclosures = encodedDisclosures.map(
    (ed) => import_utils.Disclosure.fromEncodeSync(ed, { alg: _sd_alg, hasher })
  );
  return {
    jwt,
    disclosures,
    kbJwt
  };
};
var getClaims = (rawPayload, disclosures, hasher) => __async(void 0, null, function* () {
  const { unpackedObj } = yield unpack(rawPayload, disclosures, hasher);
  return unpackedObj;
});
var getClaimsSync = (rawPayload, disclosures, hasher) => {
  const { unpackedObj } = unpackSync(rawPayload, disclosures, hasher);
  return unpackedObj;
};
var unpackArray = (arr, map, prefix = "") => {
  const keys = {};
  const unpackedArray = [];
  arr.forEach((item, idx) => {
    if (typeof item === "object" && item !== null) {
      const hash = item[import_types.SD_LIST_KEY];
      if (hash) {
        const disclosed = map[hash];
        if (disclosed) {
          const presentKey = prefix ? `${prefix}.${idx}` : `${idx}`;
          keys[presentKey] = hash;
          const { unpackedObj, disclosureKeymap: disclosureKeys } = unpackObj(
            disclosed.value,
            map,
            presentKey
          );
          unpackedArray.push(unpackedObj);
          Object.assign(keys, disclosureKeys);
        }
      } else {
        const newKey = prefix ? `${prefix}.${idx}` : `${idx}`;
        const { unpackedObj, disclosureKeymap: disclosureKeys } = unpackObj(
          item,
          map,
          newKey
        );
        unpackedArray.push(unpackedObj);
        Object.assign(keys, disclosureKeys);
      }
    } else {
      unpackedArray.push(item);
    }
  });
  return { unpackedObj: unpackedArray, disclosureKeymap: keys };
};
var unpackObj = (obj, map, prefix = "") => {
  const keys = {};
  if (typeof obj === "object" && obj !== null) {
    if (Array.isArray(obj)) {
      return unpackArray(obj, map, prefix);
    }
    for (const key in obj) {
      if (key !== import_types.SD_DIGEST && key !== import_types.SD_LIST_KEY && typeof obj[key] === "object") {
        const newKey = prefix ? `${prefix}.${key}` : key;
        const { unpackedObj: unpackedObj2, disclosureKeymap: disclosureKeys } = unpackObj(
          obj[key],
          map,
          newKey
        );
        obj[key] = unpackedObj2;
        Object.assign(keys, disclosureKeys);
      }
    }
    const _a = obj, { _sd } = _a, payload = __objRest(_a, ["_sd"]);
    const claims = {};
    if (_sd) {
      for (const hash of _sd) {
        const disclosed = map[hash];
        if (disclosed == null ? void 0 : disclosed.key) {
          const presentKey = prefix ? `${prefix}.${disclosed.key}` : disclosed.key;
          keys[presentKey] = hash;
          const { unpackedObj: unpackedObj2, disclosureKeymap: disclosureKeys } = unpackObj(
            disclosed.value,
            map,
            presentKey
          );
          claims[disclosed.key] = unpackedObj2;
          Object.assign(keys, disclosureKeys);
        }
      }
    }
    const unpackedObj = Object.assign(payload, claims);
    return { unpackedObj, disclosureKeymap: keys };
  }
  return { unpackedObj: obj, disclosureKeymap: keys };
};
var createHashMapping = (disclosures, hash) => __async(void 0, null, function* () {
  const map = {};
  for (let i = 0; i < disclosures.length; i++) {
    const disclosure = disclosures[i];
    const digest = yield disclosure.digest(hash);
    map[digest] = disclosure;
  }
  return map;
});
var createHashMappingSync = (disclosures, hash) => {
  const map = {};
  for (let i = 0; i < disclosures.length; i++) {
    const disclosure = disclosures[i];
    const digest = disclosure.digestSync(hash);
    map[digest] = disclosure;
  }
  return map;
};
var getSDAlgAndPayload = (SdJwtPayload) => {
  const _a = SdJwtPayload, { _sd_alg } = _a, payload = __objRest(_a, ["_sd_alg"]);
  if (typeof _sd_alg !== "string") {
    return { _sd_alg: "sha-256", payload };
  }
  return { _sd_alg, payload };
};
var unpack = (SdJwtPayload, disclosures, hasher) => __async(void 0, null, function* () {
  const { _sd_alg, payload } = getSDAlgAndPayload(SdJwtPayload);
  const hash = { hasher, alg: _sd_alg };
  const map = yield createHashMapping(disclosures, hash);
  return unpackObj(payload, map);
});
var unpackSync = (SdJwtPayload, disclosures, hasher) => {
  const { _sd_alg, payload } = getSDAlgAndPayload(SdJwtPayload);
  const hash = { hasher, alg: _sd_alg };
  const map = createHashMappingSync(disclosures, hash);
  return unpackObj(payload, map);
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  createHashMapping,
  createHashMappingSync,
  decodeJwt,
  decodeSdJwt,
  decodeSdJwtSync,
  getClaims,
  getClaimsSync,
  getSDAlgAndPayload,
  splitSdJwt,
  unpack,
  unpackArray,
  unpackObj,
  unpackSync
});
