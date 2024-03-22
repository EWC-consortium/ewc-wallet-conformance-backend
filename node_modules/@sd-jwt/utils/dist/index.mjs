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

// src/base64url.ts
import { Base64 } from "js-base64";
var base64urlEncode = Base64.encodeURI;
var base64urlDecode = Base64.decode;
var uint8ArrayToBase64Url = (input) => Base64.fromUint8Array(input, true);

// src/error.ts
var SDJWTException = class _SDJWTException extends Error {
  constructor(message, details) {
    super(message);
    Object.setPrototypeOf(this, _SDJWTException.prototype);
    this.name = "SDJWTException";
    this.details = details;
  }
  getFullMessage() {
    return `${this.name}: ${this.message} ${this.details ? `- ${JSON.stringify(this.details)}` : ""}`;
  }
};

// src/disclosure.ts
var Disclosure = class _Disclosure {
  constructor(data, _meta) {
    this._digest = _meta == null ? void 0 : _meta.digest;
    this._encoded = _meta == null ? void 0 : _meta.encoded;
    if (data.length === 2) {
      this.salt = data[0];
      this.value = data[1];
      return;
    }
    if (data.length === 3) {
      this.salt = data[0];
      this.key = data[1];
      this.value = data[2];
      return;
    }
    throw new SDJWTException("Invalid disclosure data");
  }
  // We need to digest of the original encoded data.
  // After decode process, we use JSON.stringify to encode the data.
  // This can be different from the original encoded data.
  static fromEncode(s, hash) {
    return __async(this, null, function* () {
      const { hasher, alg } = hash;
      const digest = yield hasher(s, alg);
      const digestStr = uint8ArrayToBase64Url(digest);
      const item = JSON.parse(base64urlDecode(s));
      return _Disclosure.fromArray(item, { digest: digestStr, encoded: s });
    });
  }
  static fromEncodeSync(s, hash) {
    const { hasher, alg } = hash;
    const digest = hasher(s, alg);
    const digestStr = uint8ArrayToBase64Url(digest);
    const item = JSON.parse(base64urlDecode(s));
    return _Disclosure.fromArray(item, { digest: digestStr, encoded: s });
  }
  static fromArray(item, _meta) {
    return new _Disclosure(item, _meta);
  }
  encode() {
    if (!this._encoded) {
      this._encoded = base64urlEncode(JSON.stringify(this.decode()));
    }
    return this._encoded;
  }
  decode() {
    return this.key ? [this.salt, this.key, this.value] : [this.salt, this.value];
  }
  digest(hash) {
    return __async(this, null, function* () {
      const { hasher, alg } = hash;
      if (!this._digest) {
        const hash2 = yield hasher(this.encode(), alg);
        this._digest = uint8ArrayToBase64Url(hash2);
      }
      return this._digest;
    });
  }
  digestSync(hash) {
    const { hasher, alg } = hash;
    if (!this._digest) {
      const hash2 = hasher(this.encode(), alg);
      this._digest = uint8ArrayToBase64Url(hash2);
    }
    return this._digest;
  }
};
export {
  Disclosure,
  SDJWTException,
  base64urlDecode,
  base64urlEncode,
  uint8ArrayToBase64Url
};
