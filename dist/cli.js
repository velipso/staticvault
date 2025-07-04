#!/usr/bin/env node

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
function resolvePath(currentDirectory, path2) {
  if (!currentDirectory.startsWith("/")) {
    throw new Error("Current directory must be absolute");
  }
  const here = path2.startsWith("/") || currentDirectory === "/" ? [] : currentDirectory.substr(1).split("/");
  const parts = path2.split("/");
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

// src/FileIO.ts
var FileIO = class {
  async readString(path2) {
    const data = await this.read(path2);
    return new TextDecoder().decode(data);
  }
  async writeString(path2, str) {
    await this.write(path2, new TextEncoder().encode(str));
  }
};
var MemoryFileIO = class extends FileIO {
  constructor() {
    super(...arguments);
    this.files = /* @__PURE__ */ new Map();
  }
  async remove(path2) {
    this.files.delete(path2);
  }
  async read(path2) {
    const data = this.files.get(path2);
    if (!data) {
      throw new Error(`File not found: ${path2}`);
    }
    return data;
  }
  async write(path2, data) {
    this.files.set(path2, data);
  }
};
var DirectoryFileIO = class extends FileIO {
  constructor(rootDir, io, separator = "/") {
    super();
    this.rootDir = rootDir;
    this.io = io;
    this.separator = separator;
  }
  remove(path2) {
    return this.io.remove(`${this.rootDir}${this.separator}${path2}`);
  }
  read(path2) {
    return this.io.read(`${this.rootDir}${this.separator}${path2}`);
  }
  readString(path2) {
    return this.io.readString(`${this.rootDir}${this.separator}${path2}`);
  }
  write(path2, data) {
    return this.io.write(`${this.rootDir}${this.separator}${path2}`, data);
  }
  writeString(path2, data) {
    return this.io.writeString(`${this.rootDir}${this.separator}${path2}`, data);
  }
};
var ReadonlyFileIO = class extends FileIO {
  constructor(io) {
    super();
    this.io = io;
  }
  remove(path2) {
    throw new Error(`Cannot remove in read-only mode`);
  }
  read(path2) {
    return this.io.read(path2);
  }
  readString(path2) {
    return this.io.readString(path2);
  }
  write(path2, data) {
    throw new Error(`Cannot write in read-only mode`);
  }
  writeString(path2, data) {
    throw new Error(`Cannot write in read-only mode`);
  }
};

// src/NodeFileIO.ts
import * as fs from "node:fs/promises";
var NodeFileIO = class extends FileIO {
  async remove(path2) {
    await fs.rm(path2, { force: true });
  }
  async read(path2) {
    const buffer = await fs.readFile(path2);
    return new Uint8Array(buffer);
  }
  async readString(path2) {
    return await fs.readFile(path2, { encoding: "utf8" });
  }
  async write(path2, data) {
    await fs.writeFile(path2, data);
  }
  async writeString(path2, data) {
    await fs.writeFile(path2, data, { encoding: "utf8" });
  }
};

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
  async setPath(path2) {
    const current = this.path.map(({ name }) => name).reverse();
    const parts = resolvePath(`/${current.join("/")}`, path2);
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

// src/cli.ts
import * as fs2 from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "child_process";
var __filename = fileURLToPath(import.meta.url);
var __dirname = path.dirname(__filename);
function printUsage(filter) {
  console.log(`Usage:
  staticvault <command> [arguments]`);
  if (!filter) {
    console.log(`
Commands:`);
  } else {
    console.log(`
Current command:`);
  }
  if (!filter || filter === "dump") {
    console.log(`
- dump <vault> <destination> [-p password]

  Decrypt and copy out entire vault to destination

  <vault>          Vault directory
  <destination>    Decryption target directory
  [-p password]    Encryption password`);
  }
  if (!filter || filter === "ingest") {
    console.log(`
- ingest <vault> <source> [-p password]

  Encrypt and copy source folders/files into vault

  <vault>          Vault directory
  <source>         Source directory
  [-p password]    Encryption password`);
  }
  if (!filter || filter === "init") {
    console.log(`
- init <vault> [-p password] [-d difficulty]

  Initialize a new vault

  <vault>          Vault directory
  [-p password]    Encryption password
  [-d difficulty]  Encryption difficulty (default: 5)`);
  }
  if (!filter || filter === "rm") {
    console.log(`
- rm <vault> <path> [-p password]

  Remove a file/folder

  <vault>          Vault directory
  <path>           Path of the secure file/folder
  [-p password]    Encryption password`);
  }
  if (!filter || filter === "test") {
    console.log(`
- test

  Run internal tests`);
  }
  if (!filter || filter === "tree") {
    console.log(`
- tree <vault> [-p password]

  Recursive directory listing

  <vault>          Vault directory
  [-p password]    Encryption password`);
  }
  if (!filter || filter === "version") {
    console.log(`
- version

  Output version of staticvault`);
  }
}
function promptPassword(prompt) {
  const cmd = `read -s -p "${prompt}: " pwd && echo $pwd`;
  const result = execSync(`bash -c '${cmd}'`, { stdio: ["inherit", "pipe", "inherit"] }).toString().trim();
  console.log("");
  return result;
}
function treeChars(depth, last, folder, status) {
  let prefix = "";
  for (let j = 0; j < depth; j++) {
    prefix += "\u2502  ";
  }
  prefix += last ? "\u2514\u2500 " : "\u251C\u2500 ";
  let postfix = folder ? "/" : "";
  if (status) {
    postfix += " " + status;
  }
  return { prefix, postfix };
}
async function cmdDump(args) {
  let target = null;
  let destination = null;
  let password = null;
  for (; ; ) {
    const arg = args.shift();
    if (typeof arg === "undefined") break;
    if (arg === "-p") {
      if (password === null) {
        const pw = args.shift();
        if (typeof pw === "undefined") {
          printUsage("dump");
          console.error(`
Missing password`);
          return 1;
        }
        password = pw;
      } else {
        printUsage("dump");
        console.error(`
Cannot specify password more than once`);
        return 1;
      }
    } else if (target === null) {
      target = arg;
    } else if (destination === null) {
      destination = arg;
    } else {
      printUsage("dump");
      console.error(`
Unknown argument: ${arg}`);
      return 1;
    }
  }
  if (target === null) {
    printUsage("dump");
    console.error(`
Missing vault directory`);
    return 1;
  }
  if (destination === null) {
    printUsage("dump");
    console.error(`
Missing destination directory`);
    return 1;
  }
  if (password === null) {
    password = promptPassword("Password");
  }
  const io = new DirectoryFileIO(target, new NodeFileIO());
  const root = await io.readString("securevault.txt");
  const vault = await Vault.deserialize(root, password, io);
  if (!vault) {
    console.error(`Wrong password`);
    return 1;
  }
  const walk = async (dir) => {
    for (const folder of vault.listFolders()) {
      const d = path.join(dir, folder);
      await fs2.mkdir(d);
      await vault.enterFolder(folder);
      await walk(d);
      vault.exitFolder();
    }
    for (const file of vault.listFiles()) {
      const bytes = await vault.getFile(file);
      await fs2.writeFile(path.join(dir, file), bytes);
    }
  };
  await walk(destination);
  return 0;
}
async function cmdIngest(args) {
  let target = null;
  let source = null;
  let password = null;
  for (; ; ) {
    const arg = args.shift();
    if (typeof arg === "undefined") break;
    if (arg === "-p") {
      if (password === null) {
        const pw = args.shift();
        if (typeof pw === "undefined") {
          printUsage("ingest");
          console.error(`
Missing password`);
          return 1;
        }
        password = pw;
      } else {
        printUsage("ingest");
        console.error(`
Cannot specify password more than once`);
        return 1;
      }
    } else if (target === null) {
      target = arg;
    } else if (source === null) {
      source = arg;
    } else {
      printUsage("ingest");
      console.error(`
Unknown argument: ${arg}`);
      return 1;
    }
  }
  if (target === null) {
    printUsage("ingest");
    console.error(`
Missing vault directory`);
    return 1;
  }
  if (source === null) {
    printUsage("ingest");
    console.error(`
Missing source directory`);
    return 1;
  }
  if (password === null) {
    password = promptPassword("Password");
  }
  const srcIO = new NodeFileIO();
  const io = new DirectoryFileIO(target, new NodeFileIO());
  const root = await io.readString("securevault.txt");
  const vault = await Vault.deserialize(root, password, io);
  if (!vault) {
    console.error(`Wrong password`);
    return 1;
  }
  const walk = async (depth, src) => {
    const items = [];
    const entries = await fs2.readdir(src, { withFileTypes: true });
    for (const ent of entries) {
      const dir = ent.isDirectory();
      if (dir || ent.isFile()) {
        items.push({ name: ent.name, dir });
      }
    }
    items.sort((a, b) => {
      if (a.dir && !b.dir) {
        return -1;
      } else if (!a.dir && b.dir) {
        return 1;
      }
      return a.name.localeCompare(b.name);
    });
    const statusMap = {
      exists: "(exists)",
      success: "(copied!)",
      linked: "(linked!)"
    };
    for (let i = 0; i < items.length; i++) {
      const { name, dir } = items[i];
      const full = path.join(src, name);
      let status = "?";
      if (dir) {
        status = statusMap[await vault.putFolder(name)];
      } else {
        const bytes = await srcIO.read(full);
        status = statusMap[await vault.putFile(name, bytes)];
      }
      const { prefix, postfix } = treeChars(depth, i >= items.length - 1, dir, status);
      console.log(prefix + name + postfix);
      if (dir) {
        await vault.enterFolder(name);
        await walk(depth + 1, full);
        vault.exitFolder();
      }
    }
  };
  await walk(0, source);
  await vault.save();
  if (vault.containerDirty()) {
    await io.writeString("securevault.txt", await vault.serialize(password));
  }
  return 0;
}
async function cmdInit(args) {
  let target = null;
  let password = null;
  let difficulty = null;
  for (; ; ) {
    const arg = args.shift();
    if (typeof arg === "undefined") break;
    if (arg === "-p") {
      if (password === null) {
        const pw = args.shift();
        if (typeof pw === "undefined") {
          printUsage("init");
          console.error(`
Missing password`);
          return 1;
        }
        password = pw;
      } else {
        printUsage("init");
        console.error(`
Cannot specify password more than once`);
        return 1;
      }
    } else if (arg === "-d") {
      if (difficulty === null) {
        const d = args.shift();
        if (typeof d === "undefined") {
          printUsage("init");
          console.error(`
Missing difficulty`);
          return 1;
        }
        if (~/^[1-9][0-9]*$/.test(d)) {
          printUsage("init");
          console.error(`
Difficulty must be a positive integer`);
          return 1;
        }
        difficulty = parseInt(d, 10);
      } else {
        printUsage("init");
        console.error(`
Cannot specify difficulty more than once`);
        return 1;
      }
    } else if (target === null) {
      target = arg;
    } else {
      printUsage("init");
      console.error(`
Unknown argument: ${arg}`);
      return 1;
    }
  }
  if (target === null) {
    printUsage("init");
    console.error(`
Missing vault directory`);
    return 1;
  }
  if (difficulty === null) {
    difficulty = 5;
  }
  if (isNaN(difficulty) || difficulty < 1 || Math.floor(difficulty) !== difficulty) {
    printUsage("init");
    console.error(`
Invalid difficulty`);
  }
  if (password === null) {
    password = promptPassword("Password");
    const p2 = promptPassword("Again");
    if (password !== p2) {
      console.error(`Passwords don't match`);
      return 1;
    }
  }
  await fs2.mkdir(target, { recursive: true });
  const io = new DirectoryFileIO(target, new NodeFileIO());
  const vault = await Vault.create(io);
  const data = await vault.serialize(password, difficulty);
  await Promise.all([
    io.writeString("securevault.txt", data),
    io.write("index.html", await fs2.readFile(path.join(__dirname, "index.html"))),
    io.write("index.min.js", await fs2.readFile(path.join(__dirname, "index.min.js")))
  ]);
  return 0;
}
async function cmdRm(args) {
  let target = null;
  let spath = null;
  let password = null;
  for (; ; ) {
    const arg = args.shift();
    if (typeof arg === "undefined") break;
    if (arg === "-p") {
      if (password === null) {
        const pw = args.shift();
        if (typeof pw === "undefined") {
          printUsage("rm");
          console.error(`
Missing password`);
          return 1;
        }
        password = pw;
      } else {
        printUsage("rm");
        console.error(`
Cannot specify password more than once`);
        return 1;
      }
    } else if (target === null) {
      target = arg;
    } else if (spath === null) {
      spath = arg;
    } else {
      printUsage("rm");
      console.error(`
Unknown argument: ${arg}`);
      return 1;
    }
  }
  if (target === null) {
    printUsage("rm");
    console.error(`
Missing vault directory`);
    return 1;
  }
  if (spath === null) {
    printUsage("rm");
    console.error(`
Missing secure path`);
    return 1;
  }
  if (password === null) {
    password = promptPassword("Password");
  }
  const io = new DirectoryFileIO(target, new NodeFileIO());
  const root = await io.readString("securevault.txt");
  const vault = await Vault.deserialize(root, password, io);
  if (!vault) {
    console.error(`Wrong password`);
    return 1;
  }
  const parts = resolvePath("/", spath);
  for (let i = 0; i < parts.length - 1; i++) {
    await vault.enterFolder(parts[i]);
  }
  const result = await vault.remove(parts[parts.length - 1]);
  if (result === "notfound") {
    console.error(`Path not found: ${spath}`);
    return 1;
  }
  await vault.save();
  if (vault.containerDirty()) {
    await io.writeString("securevault.txt", await vault.serialize(password));
  }
  return 0;
}
async function cmdTest(args) {
  console.log("Running tests...");
  const key = await CryptoKey.generate();
  key.assertEqual(key);
  key.assertEqual(
    (await CryptoKey.importWithPassword(
      await key.exportWithPassword("hello world"),
      "hello world"
    ))?.key ?? null
  );
  if (null !== await CryptoKey.importWithPassword(
    await key.exportWithPassword("hello1"),
    "hello2"
  )) {
    throw new Error("Wrong password should return null");
  }
  if ("hello world" !== await key.decryptString(await key.encryptString("hello world"))) {
    throw new Error("Failed to encrypt/decrypt string");
  }
  {
    const obj1 = { b: 1, a: 2 };
    const obj2 = [4, 5, 6];
    const obj1Enc = await key.encryptObject(obj1);
    const obj2Enc = await key.encryptObject(obj2);
    if (stringify(await key.decryptObject(obj1Enc)) !== stringify(obj1)) {
      throw new Error("Invalid decrypted object");
    }
    if (stringify(await key.decryptObject(obj2Enc)) !== stringify(obj2)) {
      throw new Error("Invalid decrypted object");
    }
  }
  for (const js of ["true", "false", "null", '"hello"', "123"]) {
    if (null !== await key.decryptObject("x" + await key.encryptString(js))) {
      throw new Error("Invalid decrypted object");
    }
  }
  {
    const ar = Array.from({ length: 100 }).map(() => Math.floor(Math.random() * 256));
    const bytes = new Uint8Array(ar);
    const { encryptedBytes, iv } = await key.encryptBytes(bytes);
    const bytesDec = await key.decryptBytes(encryptedBytes, iv);
    if (bytesDec && bytesToString(bytes) !== bytesToString(bytesDec)) {
      throw new Error("Failed to decrypt bytes");
    }
  }
  if ("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" !== await hashBytes(new Uint8Array("hello".split("").map((a) => a.charCodeAt(0))))) {
    throw new Error("Failed to hash bytes");
  }
  {
    const io = new MemoryFileIO();
    const vault1 = await Vault.create(io);
    const file1 = "hello world";
    await vault1.putFolder("test");
    await vault1.enterFolder("test");
    await vault1.putFile("hello.txt", new TextEncoder().encode(file1));
    await vault1.save();
    const vaultEnc = await vault1.serialize("hello");
    const vault2 = await Vault.deserialize(vaultEnc, "hello", io);
    if (!vault2) {
      throw new Error(`Failed to reopen vault`);
    }
    const data1 = await vault2.getFile("hello.txt");
    if (data1) {
      throw new Error(`File shouldn't be found`);
    }
    await vault2.enterFolder("test");
    const data2 = await vault2.getFile("hello.txt");
    if (!data2) {
      throw new Error(`File not found`);
    }
    const file2 = new TextDecoder().decode(data2);
    if (file1 !== file2) {
      throw new Error(`Failed to encrypt and decrypt file`);
    }
  }
  {
    const io = new MemoryFileIO();
    const vault1 = await Vault.create(io);
    const file1 = "hello world";
    await vault1.putFolder("test1");
    await vault1.enterFolder("test1");
    await vault1.putFolder("test2");
    await vault1.enterFolder("test2");
    await vault1.putFile("hello1.txt", new TextEncoder().encode(file1));
    vault1.exitToRoot();
    await vault1.putFile("hello2.txt", new TextEncoder().encode(file1));
    vault1.putFolderLink("test3", "/test1/test2");
    await vault1.save();
    const vaultEnc = await vault1.serialize("hello");
    if ([...io.files.keys()].length !== 4) {
      throw new Error("Should only have 4 keys");
    }
    const vault2 = await Vault.deserialize(vaultEnc, "hello", io);
    if (!vault2) {
      throw new Error(`Failed to reopen vault`);
    }
    const file2d = await vault2.getFile("hello2.txt");
    if (!file2d) {
      throw new Error(`Missing hello2.txt`);
    }
    const file2 = new TextDecoder().decode(file2d);
    if (file1 !== file2) {
      throw new Error(`Failed to read linked file`);
    }
    await vault2.setPath("/test3");
    const file3d = await vault2.getFile("hello1.txt");
    if (!file3d) {
      throw new Error(`Missing hello1.txt`);
    }
    const file3 = new TextDecoder().decode(file3d);
    if (file1 !== file3) {
      throw new Error(`Failed to read file through linked folder`);
    }
    for (const p of ["/test1", "/test1/test2", "/test3"]) {
      await vault2.setPath(p);
      if (p !== vault2.getPath()) {
        throw new Error(`Failed to set path: ${p}`);
      }
    }
  }
  {
    const io = new MemoryFileIO();
    const vault1 = await Vault.create(io);
    const file1 = "hello world";
    await vault1.putFile("hello1.txt", new TextEncoder().encode(file1));
    await vault1.save();
    const vaultEnc = await vault1.serialize("hello");
    const ro = new ReadonlyFileIO(io);
    const vault2 = await Vault.create(ro);
    await vault2.putFileLink("hello2.txt", "/hello1.txt", vault1);
    await vault2.save();
    const vault2Enc = await vault2.serialize("asdf");
    const vault3 = await Vault.deserialize(vault2Enc, "asdf", ro);
    if (!vault3) {
      throw new Error(`Failed to reopen vault`);
    }
    if (JSON.stringify(vault3.listFiles()) !== '["hello2.txt"]' || JSON.stringify(vault3.listFolders()) !== "[]") {
      throw new Error(`Failed to create isolated read-only vault`);
    }
    const file2d = await vault3.getFile("hello2.txt");
    if (!file2d) {
      throw new Error(`Failed to get hello2.txt`);
    }
    const file2 = new TextDecoder().decode(file2d);
    if (file1 !== file2) {
      throw new Error(`Failed to decrypt hello2.txt`);
    }
  }
  console.log("success!");
  return 0;
}
async function cmdTree(args) {
  let target = null;
  let password = null;
  for (; ; ) {
    const arg = args.shift();
    if (typeof arg === "undefined") break;
    if (arg === "-p") {
      if (password === null) {
        const pw = args.shift();
        if (typeof pw === "undefined") {
          printUsage("tree");
          console.error(`
Missing password`);
          return 1;
        }
        password = pw;
      } else {
        printUsage("tree");
        console.error(`
Cannot specify password more than once`);
        return 1;
      }
    } else if (target === null) {
      target = arg;
    } else {
      printUsage("tree");
      console.error(`
Unknown argument: ${arg}`);
      return 1;
    }
  }
  if (target === null) {
    printUsage("tree");
    console.error(`
Missing vault directory`);
    return 1;
  }
  if (password === null) {
    password = promptPassword("Password");
  }
  const io = new DirectoryFileIO(target, new NodeFileIO());
  const root = await io.readString("securevault.txt");
  const vault = await Vault.deserialize(root, password, io);
  if (!vault) {
    console.error(`Wrong password`);
    return 1;
  }
  const walk = async (depth) => {
    const folders = vault.listFolders();
    const files = vault.listFiles();
    const itemLength = folders.length + files.length;
    for (let i = 0; i < itemLength; i++) {
      const name = i < folders.length ? folders[i] : files[i - folders.length];
      const { prefix, postfix } = treeChars(depth, i >= itemLength - 1, i < folders.length);
      console.log(prefix + name + postfix);
      if (i < folders.length) {
        await vault.enterFolder(name);
        await walk(depth + 1);
        vault.exitFolder();
      }
    }
  };
  await walk(0);
  return 0;
}
async function cmdVersion(args) {
  const data = await fs2.readFile(path.join(__dirname, "..", "package.json"), { encoding: "utf8" });
  const pack = JSON.parse(data);
  console.log(`StaticVault v${pack.version}
Encrypt, host, and share files on a static website
by Sean Connelly (@velipso), https://sean.fun
Project Home: https://github.com/velipso/staticvault
SPDX-License-Identifier: 0BSD`);
  return 0;
}
async function main(args) {
  if (args.length <= 0) {
    printUsage();
    return 0;
  }
  const cmd = args.shift();
  switch (cmd) {
    case "dump":
      return cmdDump(args);
    case "ingest":
      return cmdIngest(args);
    case "init":
      return cmdInit(args);
    case "rm":
      return cmdRm(args);
    case "test":
      return cmdTest(args);
    case "tree":
      return cmdTree(args);
    case "version":
      return cmdVersion(args);
    default:
      printUsage();
      console.error(`
Unknown command: ${cmd}`);
      return 1;
  }
  return 0;
}
main(process.argv.slice(2)).then(
  (code) => {
    process.exit(code);
  },
  (err) => {
    console.error(err);
    process.exit(1);
  }
);
