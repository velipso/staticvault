//
// staticvault - Encrypt, host, and share files on a static website
// by Sean Connelly (@velipso), https://sean.fun
// Project Home: https://github.com/velipso/staticvault
// SPDX-License-Identifier: 0BSD
//

import { stringToBytes, bytesToString, stringify } from './util';

export class CryptoKey {
  key: Uint8Array;

  private constructor(key: Uint8Array) {
    this.key = key;
  }

  assertEqual(other: CryptoKey | null) {
    if (!other || this.key.length !== other.key.length) {
      throw new Error('Keys not equal');
    }
    for (let i = 0; i < this.key.length; i++) {
      if (this.key[i] !== other.key[i]) {
        throw new Error('Keys not equal');
      }
    }
  }

  static async generate(): Promise<CryptoKey> {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const rawKey = await crypto.subtle.exportKey('raw', key);
    return new CryptoKey(new Uint8Array(rawKey));
  }

  static importUnsafeRaw(str: string): CryptoKey {
    return new CryptoKey(stringToBytes(str));
  }

  static async importWithPassword(
    encryptedKey: string,
    password: string
  ): Promise<{ key: CryptoKey, difficulty: number } | null> {
    const parts = encryptedKey.split('.');
    if (parts.length !== 4) {
      // invalid encryptedKey
      return null;
    }
    const difficulty = parseFloat(parts[3]);
    if (isNaN(difficulty) || difficulty <= 0) {
      // invalid difficulty
      return null;
    }
    try {
      const [keyEnc, salt, iv] = parts;
      const baseKey = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
      );
      const derivedKey = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: stringToBytes(salt),
          iterations: difficulty * 100000,
          hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
      const rawKey = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: stringToBytes(iv) },
        derivedKey,
        stringToBytes(keyEnc)
      );
      return { key: new CryptoKey(new Uint8Array(rawKey)), difficulty };
    } catch (_) {
      // wrong password
      return null;
    }
  }

  exportUnsafeRaw(): string {
    return bytesToString(this.key);
  }

  async exportWithPassword(password: string, difficulty = 5): Promise<string> {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: difficulty * 100000,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );
    const keyEnc = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      derivedKey,
      this.key
    );
    return ([
      bytesToString(new Uint8Array(keyEnc)),
      bytesToString(salt),
      bytesToString(iv),
      `${difficulty}`
    ]).join('.');
  }

  async encryptString(str: string): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await crypto.subtle.importKey(
      'raw', this.key, { name: 'AES-GCM' }, false, ['encrypt']
    );
    const strEnc = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      k,
      new TextEncoder().encode(str)
    );
    return ([
      bytesToString(new Uint8Array(strEnc)),
      bytesToString(iv)
    ]).join('.');
  }

  async decryptString(encryptedStr: string): Promise<string | null> {
    const parts = encryptedStr.split('.');
    if (parts.length !== 2) {
      // invalid encryptedStr
      return null;
    }
    try {
      const [strEnc, iv] = parts;
      const k = await crypto.subtle.importKey(
        'raw', this.key, { name: 'AES-GCM' }, false, ['decrypt']
      );
      const str = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: stringToBytes(iv) },
        k,
        stringToBytes(strEnc)
      );
      return new TextDecoder().decode(str);
    } catch (_) {
      // wrong key
      return null;
    }
  }

  async encryptObject(obj: Record<string, unknown> | unknown[]): Promise<string> {
    const str = await this.encryptString(stringify(obj));
    // add a random prefix to make it slightly different from encryptString/decryptString
    const ch = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    return ch[Math.floor(Math.random() * ch.length)] + str;
  }

  async decryptObject(encryptedObj: string): Promise<Record<string, unknown> | unknown[] | null> {
    try {
      const str = await this.decryptString(encryptedObj.substr(1));
      if (!str) {
        // wrong key
        return null;
      }
      const obj = JSON.parse(str);
      if (obj && typeof obj === 'object') {
        return obj;
      }
      // invalid JSON
      return null;
    } catch (_) {
      // invalid JSON
      return null;
    }
  }

  // encryptedBytes is saved to a file
  // iv is non-secret metadata required to decrypt
  async encryptBytes(bytes: Uint8Array): Promise<{ encryptedBytes: Uint8Array; iv: string }> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await crypto.subtle.importKey(
      'raw', this.key, { name: 'AES-GCM' }, false, ['encrypt']
    );
    const bytesEnc = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      k,
      bytes
    );
    return {
      encryptedBytes: new Uint8Array(bytesEnc),
      iv: bytesToString(iv)
    };
  }

  async decryptBytes(encryptedBytes: Uint8Array, iv: string): Promise<Uint8Array | null> {
    try {
      const k = await crypto.subtle.importKey(
        'raw', this.key, { name: 'AES-GCM' }, false, ['decrypt']
      );
      const bytes = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: stringToBytes(iv) },
        k,
        encryptedBytes
      );
      return new Uint8Array(bytes);
    } catch (_) {
      // wrong key
      return null;
    }
  }
};

