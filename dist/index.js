"use strict";
var StaticVault = (() => {
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

  // src/index.ts
  var index_exports = {};
  __export(index_exports, {
    BrowserFileIO: () => BrowserFileIO,
    CacheFileIO: () => CacheFileIO,
    CryptoKey: () => CryptoKey,
    DirectoryFileIO: () => DirectoryFileIO,
    FileIO: () => FileIO,
    MemoryFileIO: () => MemoryFileIO,
    ReadonlyFileIO: () => ReadonlyFileIO,
    Vault: () => Vault,
    bytesToString: () => bytesToString,
    hashBytes: () => hashBytes,
    resolvePath: () => resolvePath,
    stringToBytes: () => stringToBytes,
    stringify: () => stringify
  });

  // src/util.ts
  function bytesToString(bytes) {
    const b64 = typeof process !== "undefined" ? Buffer.from(bytes).toString("base64") : btoa(String.fromCharCode(...bytes));
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function stringToBytes(str) {
    let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    return typeof process !== "undefined" ? new Uint8Array(Buffer.from(b64, "base64")) : new Uint8Array(atob(b64).split("").map((c) => c.charCodeAt(0)));
  }
  function stringify(obj) {
    if (obj !== null && typeof obj === "object" && !Array.isArray(obj)) {
      const keys = Object.keys(obj);
      keys.sort((a, b) => a.localeCompare(b));
      const out = [];
      for (const k of keys) {
        out.push(`${JSON.stringify(k)}:${stringify(obj[k])}`);
      }
      return `{${out.join(",")}}`;
    } else {
      return JSON.stringify(obj);
    }
  }
  async function hashBytes(bytes) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  function resolvePath(currentDirectory, path) {
    if (!currentDirectory.startsWith("/")) {
      throw new Error("Current directory must be absolute");
    }
    const here = path.startsWith("/") || currentDirectory === "/" ? [] : currentDirectory.substr(1).split("/");
    const parts = path.split("/");
    for (const part of parts) {
      if (part === ".") {
      } else if (part === "..") {
        here.pop();
      } else if (part !== "") {
        here.push(part);
      }
    }
    return here;
  }

  // src/CryptoKey.ts
  var CryptoKey = class _CryptoKey {
    constructor(key) {
      this.key = key;
    }
    assertEqual(other) {
      if (!other || this.key.length !== other.key.length) {
        throw new Error("Keys not equal");
      }
      for (let i = 0; i < this.key.length; i++) {
        if (this.key[i] !== other.key[i]) {
          throw new Error("Keys not equal");
        }
      }
    }
    static async generate() {
      const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      const rawKey = await crypto.subtle.exportKey("raw", key);
      return new _CryptoKey(new Uint8Array(rawKey));
    }
    static importUnsafeRaw(str) {
      return new _CryptoKey(stringToBytes(str));
    }
    static async importWithPassword(encryptedKey, password) {
      const parts = encryptedKey.split(".");
      if (parts.length !== 4) {
        return null;
      }
      const difficulty = parseFloat(parts[3]);
      if (isNaN(difficulty) || difficulty <= 0) {
        return null;
      }
      try {
        const [keyEnc, salt, iv] = parts;
        const baseKey = await crypto.subtle.importKey(
          "raw",
          new TextEncoder().encode(password),
          { name: "PBKDF2" },
          false,
          ["deriveKey"]
        );
        const derivedKey = await crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: stringToBytes(salt),
            iterations: difficulty * 1e5,
            hash: "SHA-256"
          },
          baseKey,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"]
        );
        const rawKey = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: stringToBytes(iv) },
          derivedKey,
          stringToBytes(keyEnc)
        );
        return { key: new _CryptoKey(new Uint8Array(rawKey)), difficulty };
      } catch (_) {
        return null;
      }
    }
    exportUnsafeRaw() {
      return bytesToString(this.key);
    }
    async exportWithPassword(password, difficulty = 5) {
      const enc = new TextEncoder();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const baseKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
      const derivedKey = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt,
          iterations: difficulty * 1e5,
          hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );
      const keyEnc = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        derivedKey,
        this.key
      );
      return [
        bytesToString(new Uint8Array(keyEnc)),
        bytesToString(salt),
        bytesToString(iv),
        `${difficulty}`
      ].join(".");
    }
    async encryptString(str) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const k = await crypto.subtle.importKey(
        "raw",
        this.key,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );
      const strEnc = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        k,
        new TextEncoder().encode(str)
      );
      return [
        bytesToString(new Uint8Array(strEnc)),
        bytesToString(iv)
      ].join(".");
    }
    async decryptString(encryptedStr) {
      const parts = encryptedStr.split(".");
      if (parts.length !== 2) {
        return null;
      }
      try {
        const [strEnc, iv] = parts;
        const k = await crypto.subtle.importKey(
          "raw",
          this.key,
          { name: "AES-GCM" },
          false,
          ["decrypt"]
        );
        const str = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: stringToBytes(iv) },
          k,
          stringToBytes(strEnc)
        );
        return new TextDecoder().decode(str);
      } catch (_) {
        return null;
      }
    }
    async encryptObject(obj) {
      const str = await this.encryptString(stringify(obj));
      const ch = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      return ch[Math.floor(Math.random() * ch.length)] + str;
    }
    async decryptObject(encryptedObj) {
      try {
        const str = await this.decryptString(encryptedObj.substr(1));
        if (!str) {
          return null;
        }
        const obj = JSON.parse(str);
        if (obj && typeof obj === "object") {
          return obj;
        }
        return null;
      } catch (_) {
        return null;
      }
    }
    // encryptedBytes is saved to a file
    // iv is non-secret metadata required to decrypt
    async encryptBytes(bytes) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const k = await crypto.subtle.importKey(
        "raw",
        this.key,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );
      const bytesEnc = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        k,
        bytes
      );
      return {
        encryptedBytes: new Uint8Array(bytesEnc),
        iv: bytesToString(iv)
      };
    }
    async decryptBytes(encryptedBytes, iv) {
      try {
        const k = await crypto.subtle.importKey(
          "raw",
          this.key,
          { name: "AES-GCM" },
          false,
          ["decrypt"]
        );
        const bytes = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: stringToBytes(iv) },
          k,
          encryptedBytes
        );
        return new Uint8Array(bytes);
      } catch (_) {
        return null;
      }
    }
  };

  // src/Vault.ts
  var VaultFile = class _VaultFile {
    constructor(id, key, metadata) {
      this.dirty = false;
      this.id = id;
      this.key = key;
      this.metadata = metadata;
    }
    async serialize() {
      return await this.key.encryptObject(this.metadata);
    }
    handle(name) {
      return {
        n: name,
        i: this.id,
        k: this.key.exportUnsafeRaw()
      };
    }
    static isMetadata(obj) {
      return obj !== null && typeof obj === "object" && !Array.isArray(obj) && "f" in obj && typeof obj.f === "string" && "h" in obj && typeof obj.h === "string" && "v" in obj && typeof obj.v === "string";
    }
    static async deserialize(id, key, metadata) {
      const obj = await key.decryptObject(metadata);
      if (!obj || !_VaultFile.isMetadata(obj)) {
        return null;
      }
      return new _VaultFile(id, key, obj);
    }
  };
  var VaultFolder = class _VaultFolder {
    constructor(id, key, metadata) {
      this.folders = /* @__PURE__ */ new Map();
      this.files = /* @__PURE__ */ new Map();
      this.dirty = false;
      this.id = id;
      this.key = key;
      this.metadata = metadata ?? { s: [], f: [] };
    }
    async serialize() {
      return await this.key.encryptObject(this.metadata);
    }
    handle(name) {
      return {
        n: name,
        i: this.id,
        k: this.key.exportUnsafeRaw()
      };
    }
    static isMetadata(obj) {
      const isHandle = (h) => h !== null && typeof h === "object" && !Array.isArray(h) && "n" in h && typeof h.n === "string" && "i" in h && typeof h.i === "number" && "k" in h && typeof h.k === "string";
      return obj !== null && typeof obj === "object" && !Array.isArray(obj) && "s" in obj && Array.isArray(obj.s) && obj.s.every(isHandle) && "f" in obj && Array.isArray(obj.f) && obj.f.every(isHandle);
    }
    static async deserialize(id, key, metadata) {
      const obj = await key.decryptObject(metadata);
      if (!obj || !_VaultFolder.isMetadata(obj)) {
        return null;
      }
      return new _VaultFolder(id, key, obj);
    }
    isFolder(name, id) {
      return !!this.metadata.s.find(
        ({ n, i }) => n === name && (typeof id === "undefined" || i === id)
      );
    }
    isFile(name, id) {
      return !!this.metadata.f.find(
        ({ n, i }) => n === name && (typeof id === "undefined" || i === id)
      );
    }
    listFolders() {
      const f = this.metadata.s.map(({ n }) => n);
      f.sort((a, b) => a.localeCompare(b));
      return f;
    }
    listFiles() {
      const f = this.metadata.f.map(({ n }) => n);
      f.sort((a, b) => a.localeCompare(b));
      return f;
    }
    listDirtyFolders() {
      const f = [...this.folders.entries()].filter(([_, f2]) => f2.dirty).map(([n, _]) => n);
      f.sort((a, b) => a.localeCompare(b));
      return f;
    }
    listDirtyFiles() {
      const f = [...this.files.entries()].filter(([_, f2]) => f2.dirty).map(([n, _]) => n);
      f.sort((a, b) => a.localeCompare(b));
      return f;
    }
    async getFolderOrNull(name, io) {
      const f = this.folders.get(name);
      if (f) {
        return f;
      }
      const pf = this.metadata.s.find((f2) => f2.n === name);
      if (!pf) {
        return null;
      }
      const key = CryptoKey.importUnsafeRaw(pf.k);
      const metadata = await io.readString(`${pf.i}.txt`);
      const folder = await _VaultFolder.deserialize(pf.i, key, metadata);
      if (!folder) {
        return null;
      }
      this.folders.set(name, folder);
      return folder;
    }
    async getFolder(name, io) {
      const folder = await this.getFolderOrNull(name, io);
      if (!folder) {
        throw new Error(`Folder not found: ${name}`);
      }
      return folder;
    }
    async getFileOrNull(name, io) {
      const f = this.files.get(name);
      if (f) {
        return f;
      }
      const pf = this.metadata.f.find((f2) => f2.n === name);
      if (!pf) {
        return null;
      }
      const key = CryptoKey.importUnsafeRaw(pf.k);
      const metadata = await io.readString(`${pf.i}.txt`);
      const file = await VaultFile.deserialize(pf.i, key, metadata);
      if (!file) {
        return null;
      }
      this.files.set(name, file);
      return file;
    }
    async getFile(name, io) {
      const file = await this.getFileOrNull(name, io);
      if (!file) {
        throw new Error(`File not found: ${name}`);
      }
      return file;
    }
    async findHash(hash, io) {
      for (const name of this.listFiles()) {
        const file = await this.getFile(name, io);
        if (file.metadata.h === hash) {
          return file;
        }
      }
      for (const name of this.listFolders()) {
        const folder = await this.getFolder(name, io);
        const file = await folder.findHash(hash, io);
        if (file) {
          return file;
        }
      }
      return null;
    }
    putFolder(name, folder) {
      this.deleteFile(name);
      this.dirty = true;
      this.folders.set(name, folder);
      const handle = folder.handle(name);
      const i = this.metadata.s.findIndex((f) => f.n === name);
      if (i >= 0) {
        this.metadata.s[i] = handle;
      } else {
        this.metadata.s.push(handle);
      }
    }
    deleteFolder(name) {
      const i = this.metadata.s.findIndex((f) => f.n === name);
      if (i < 0) {
        return;
      }
      this.dirty = true;
      this.folders.delete(name);
      this.metadata.s.splice(i, 1);
    }
    putFile(name, file) {
      this.deleteFolder(name);
      this.dirty = true;
      this.files.set(name, file);
      const handle = file.handle(name);
      const i = this.metadata.f.findIndex((f) => f.n === name);
      if (i >= 0) {
        this.metadata.f[i] = handle;
      } else {
        this.metadata.f.push(handle);
      }
      return this;
    }
    deleteFile(name) {
      const i = this.metadata.f.findIndex((f) => f.n === name);
      if (i < 0) {
        return;
      }
      this.dirty = true;
      this.files.delete(name);
      this.metadata.f.splice(i, 1);
    }
    async maxId(io) {
      let maxId = this.id;
      for (const name of this.listFiles()) {
        const file = await this.getFile(name, io);
        maxId = Math.max(maxId, file.id);
      }
      for (const name of this.listFolders()) {
        const folder = await this.getFolder(name, io);
        maxId = Math.max(maxId, await folder.maxId(io));
      }
      return maxId;
    }
    async findId(id, io) {
      if (this.id === id) {
        return true;
      }
      for (const name of this.listFiles()) {
        const file = await this.getFile(name, io);
        if (file.id === id) {
          return true;
        }
      }
      for (const name of this.listFolders()) {
        const folder = await this.getFolder(name, io);
        if (folder.id === id) {
          return true;
        }
        const found = await folder.findId(id, io);
        if (found) {
          return true;
        }
      }
      return false;
    }
  };
  var Vault = class _Vault {
    constructor(root, difficulty, io) {
      this.root = root;
      this.io = io;
      this.path = [];
      this.difficulty = difficulty;
    }
    static async create(io) {
      const key = await CryptoKey.generate();
      const root = new VaultFolder(-1, key);
      root.dirty = true;
      return new _Vault(root, 0, io);
    }
    static async deserialize(data, password, io) {
      const parts = data.split("~");
      if (parts.length !== 2) {
        return null;
      }
      const imp = await CryptoKey.importWithPassword(parts[0], password);
      if (!imp) {
        return null;
      }
      const { key, difficulty } = imp;
      const root = await VaultFolder.deserialize(-1, key, parts[1]);
      if (!root) {
        return null;
      }
      return new _Vault(root, difficulty, io);
    }
    containerDirty() {
      return this.root.dirty;
    }
    async serialize(password, difficulty = 0) {
      const d = difficulty > 0 ? difficulty : this.difficulty > 0 ? this.difficulty : 5;
      const k = await this.root.key.exportWithPassword(password, d);
      return `${k}~${await this.root.serialize()}`;
    }
    async save(forceEverything = false) {
      const saveFile = async (file) => {
        await this.io.writeString(`${file.id}.txt`, await file.serialize());
        file.dirty = false;
      };
      const saveFolder = async (folder) => {
        if (folder.id >= 0 && (forceEverything || folder.dirty)) {
          await this.io.writeString(`${folder.id}.txt`, await folder.serialize());
          folder.dirty = false;
        }
        const files = forceEverything ? folder.listFiles() : folder.listDirtyFiles();
        await Promise.all(files.map((n) => folder.getFile(n, this.io).then((f) => saveFile(f))));
        const sub = folder.listFolders();
        await Promise.all(sub.map((n) => folder.getFolder(n, this.io).then((f) => saveFolder(f))));
      };
      await saveFolder(this.root);
    }
    currentFolder() {
      if (this.path.length <= 0) {
        return this.root;
      }
      return this.path[0].folder;
    }
    getPath() {
      return `/${this.path.map(({ name }) => name).reverse().join("/")}`;
    }
    async setPath(path) {
      const current = this.path.map(({ name }) => name).reverse();
      const parts = resolvePath(`/${current.join("/")}`, path);
      let i = 0;
      for (; i < current.length && i < parts.length; i++) {
        if (current[i] !== parts[i]) {
          break;
        }
      }
      while (current.length > i) {
        current.pop();
        this.exitFolder();
      }
      for (; i < parts.length; i++) {
        await this.enterFolder(parts[i]);
      }
    }
    listFolders() {
      return this.currentFolder().listFolders();
    }
    listFiles() {
      return this.currentFolder().listFiles();
    }
    async enterFolder(name) {
      const folder = await this.currentFolder().getFolder(name, this.io);
      this.path.unshift({ name, folder });
    }
    exitFolder() {
      this.path.shift();
    }
    exitToRoot() {
      this.path = [];
    }
    async putFile(name, bytes) {
      if (name.indexOf("/") >= 0 || name === "." || name === "..") {
        throw new Error(`Invalid file name: ${name}`);
      }
      const hash = await hashBytes(bytes);
      const file = await this.root.findHash(hash, this.io);
      if (file) {
        if (this.currentFolder().isFile(name, file.id)) {
          return "exists";
        }
        this.currentFolder().putFile(name, file);
        return "linked";
      }
      const id = 1 + await this.root.maxId(this.io);
      const key = await CryptoKey.generate();
      const filename = `file-${crypto.randomUUID()}.bin`;
      const { encryptedBytes, iv } = await key.encryptBytes(bytes);
      const newFile = new VaultFile(id, key, { f: filename, h: hash, v: iv });
      newFile.dirty = true;
      this.currentFolder().putFile(name, newFile);
      await this.io.write(filename, encryptedBytes);
      return "success";
    }
    async putFileLink(name, filePath, from) {
      if (name.indexOf("/") >= 0 || name === "." || name === "..") {
        throw new Error(`Invalid file name: ${name}`);
      }
      const src = from ?? this;
      const parts = resolvePath(src.getPath(), filePath);
      if (parts.length <= 0) {
        throw new Error(`Invalid source file: ${name}`);
      }
      let here = src.root;
      for (let i = 0; i < parts.length - 1; i++) {
        here = await here.getFolder(parts[i], this.io);
      }
      const file = await here.getFile(parts[parts.length - 1], this.io);
      if (this.currentFolder().isFile(name, file.id)) {
        return "exists";
      }
      this.currentFolder().putFile(name, file);
      return "linked";
    }
    async putFolder(name) {
      if (name.indexOf("/") >= 0 || name === "." || name === "..") {
        throw new Error(`Invalid folder name: ${name}`);
      }
      if (this.currentFolder().isFolder(name)) {
        return "exists";
      }
      const id = 1 + await this.root.maxId(this.io);
      const key = await CryptoKey.generate();
      const newFolder = new VaultFolder(id, key);
      newFolder.dirty = true;
      this.currentFolder().putFolder(name, newFolder);
      return "success";
    }
    async putFolderLink(name, folderPath, from) {
      if (name.indexOf("/") >= 0 || name === "." || name === "..") {
        throw new Error(`Invalid folder name: ${name}`);
      }
      const src = from ?? this;
      const parts = resolvePath(src.getPath(), folderPath);
      let here = src.root;
      for (let i = 0; i < parts.length; i++) {
        here = await here.getFolder(parts[i], this.io);
      }
      if (this.currentFolder().isFolder(name, here.id)) {
        return "exists";
      }
      this.currentFolder().putFolder(name, here);
      return "linked";
    }
    async getFile(name) {
      const file = await this.currentFolder().getFileOrNull(name, this.io);
      if (!file) {
        return null;
      }
      const encryptedBytes = await this.io.read(file.metadata.f);
      const bytes = await file.key.decryptBytes(encryptedBytes, file.metadata.v);
      if (!bytes) {
        return null;
      }
      return bytes;
    }
    async remove(name) {
      const deleteFile = async (parent, name2, file2) => {
        parent.deleteFile(name2);
        if (await this.root.findId(file2.id, this.io)) {
          return "unlinked-file";
        } else {
          await this.io.remove(file2.metadata.f);
          await this.io.remove(`${file2.id}.txt`);
          return "removed-file";
        }
      };
      const deleteFolder = async (parent, name2, folder2) => {
        for (const n of folder2.listFolders()) {
          const sub = await folder2.getFolder(n, this.io);
          await deleteFolder(folder2, n, sub);
        }
        for (const n of folder2.listFiles()) {
          const file2 = await folder2.getFile(n, this.io);
          await deleteFile(folder2, n, file2);
        }
        parent.deleteFolder(name2);
        if (await this.root.findId(folder2.id, this.io)) {
          return "unlinked-folder";
        } else {
          await this.io.remove(`${folder2.id}.txt`);
          return "removed-folder";
        }
      };
      const here = this.currentFolder();
      const file = await here.getFileOrNull(name, this.io);
      if (file) {
        return deleteFile(here, name, file);
      }
      const folder = await here.getFolderOrNull(name, this.io);
      if (folder) {
        return deleteFolder(here, name, folder);
      }
      return "notfound";
    }
  };

  // src/FileIO.ts
  var FileIO = class {
    async readString(path) {
      const data = await this.read(path);
      return new TextDecoder().decode(data);
    }
    async writeString(path, str) {
      await this.write(path, new TextEncoder().encode(str));
    }
  };
  var MemoryFileIO = class extends FileIO {
    constructor() {
      super(...arguments);
      this.files = /* @__PURE__ */ new Map();
    }
    async remove(path) {
      this.files.delete(path);
    }
    async read(path) {
      const data = this.files.get(path);
      if (!data) {
        throw new Error(`File not found: ${path}`);
      }
      return data;
    }
    async write(path, data) {
      this.files.set(path, data);
    }
  };
  var CacheFileIO = class extends FileIO {
    constructor(maxFiles, io) {
      super();
      this.cache = /* @__PURE__ */ new Map();
      this.maxFiles = maxFiles;
      this.io = io;
    }
    update(path, data) {
      this.cache.set(path, { data, lastUsed: Date.now() });
      if (this.cache.size > this.maxFiles) {
        let oldestKey = "";
        let oldestLastUsed = Date.now();
        for (const [k, c] of this.cache) {
          if (c.lastUsed < oldestLastUsed) {
            oldestKey = k;
            oldestLastUsed = c.lastUsed;
          }
        }
        this.cache.delete(oldestKey);
      }
    }
    async remove(path) {
      await this.io.remove(path);
      this.cache.delete(path);
    }
    async read(path) {
      const c = this.cache.get(path);
      if (c) {
        c.lastUsed = Date.now();
        return c.data;
      }
      const data = await this.io.read(path);
      this.update(path, data);
      return data;
    }
    async readString(path) {
      const c = this.cache.get(path);
      if (c) {
        c.lastUsed = Date.now();
        return new TextDecoder().decode(c.data);
      }
      const data = await this.io.readString(path);
      this.update(path, new TextEncoder().encode(data));
      return data;
    }
    async write(path, data) {
      await this.io.write(path, data);
      this.update(path, data);
    }
    async writeString(path, data) {
      await this.io.writeString(path, data);
      this.update(path, new TextEncoder().encode(data));
    }
  };
  var DirectoryFileIO = class extends FileIO {
    constructor(rootDir, io, separator = "/") {
      super();
      this.rootDir = rootDir;
      this.io = io;
      this.separator = separator;
    }
    remove(path) {
      return this.io.remove(`${this.rootDir}${this.separator}${path}`);
    }
    read(path) {
      return this.io.read(`${this.rootDir}${this.separator}${path}`);
    }
    readString(path) {
      return this.io.readString(`${this.rootDir}${this.separator}${path}`);
    }
    write(path, data) {
      return this.io.write(`${this.rootDir}${this.separator}${path}`, data);
    }
    writeString(path, data) {
      return this.io.writeString(`${this.rootDir}${this.separator}${path}`, data);
    }
  };
  var ReadonlyFileIO = class extends FileIO {
    constructor(io) {
      super();
      this.io = io;
    }
    remove(path) {
      throw new Error(`Cannot remove in read-only mode`);
    }
    read(path) {
      return this.io.read(path);
    }
    readString(path) {
      return this.io.readString(path);
    }
    write(path, data) {
      throw new Error(`Cannot write in read-only mode`);
    }
    writeString(path, data) {
      throw new Error(`Cannot write in read-only mode`);
    }
  };

  // src/BrowserFileIO.ts
  var BrowserFileIO = class extends FileIO {
    async remove(path) {
      throw new Error("Cannot remove files in browser");
    }
    async read(path) {
      const response = await fetch(path, { cache: "no-store" });
      const buffer = await response.arrayBuffer();
      return new Uint8Array(buffer);
    }
    async readString(path) {
      const response = await fetch(path, { cache: "no-store" });
      return await response.text();
    }
    async write(path, data) {
      throw new Error("Cannot write bytes in browser");
    }
  };
  return __toCommonJS(index_exports);
})();
