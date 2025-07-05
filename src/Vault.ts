//
// staticvault - Encrypt, host, and share files on a static website
// by Sean Connelly (@velipso), https://sean.fun
// Project Home: https://github.com/velipso/staticvault
// SPDX-License-Identifier: 0BSD
//

import { stringify, hashBytes, resolvePath } from './util';
import { FileIO } from './FileIO';
import { CryptoKey } from './CryptoKey';

interface IVaultMetadataHandle {
  n: string; // name
  i: number; // id
  k: string; // key
}

interface IVaultFileMetadata extends Record<string, unknown> {
  f: string; // filename
  h: string; // hash
  j: string; // file key
  v: string; // iv
}

class VaultFile {
  id: number;
  key: CryptoKey;
  metadata: IVaultFileMetadata;
  dirty = false;

  constructor(id: number, key: CryptoKey, metadata: IVaultFileMetadata) {
    this.id = id;
    this.key = key;
    this.metadata = metadata;
  }

  async serialize(): Promise<string> {
    return await this.key.encryptObject(this.metadata);
  }

  handle(name: string): IVaultMetadataHandle {
    return {
      n: name,
      i: this.id,
      k: this.key.exportUnsafeRaw()
    };
  }

  static isMetadata(obj: unknown): obj is IVaultFileMetadata {
    return (
      obj !== null &&
      typeof obj === 'object' &&
      !Array.isArray(obj) &&
      'f' in obj &&
      typeof obj.f === 'string' &&
      'h' in obj &&
      typeof obj.h === 'string' &&
      'j' in obj &&
      typeof obj.j === 'string' &&
      'v' in obj &&
      typeof obj.v === 'string'
    );
  }

  static async deserialize(
    id: number,
    key: CryptoKey,
    metadata: string
  ): Promise<VaultFile | null> {
    const obj = await key.decryptObject(metadata);
    if (!obj || !VaultFile.isMetadata(obj)) {
      return null;
    }
    return new VaultFile(id, key, obj);
  }
}

interface IVaultFolderMetadata extends Record<string, unknown> {
  s: IVaultMetadataHandle[]; // subfolders
  f: IVaultMetadataHandle[]; // files
}

class VaultFolder {
  id: number;
  key: CryptoKey;
  metadata: IVaultFolderMetadata;
  folders = new Map<string, VaultFolder>();
  files = new Map<string, VaultFile>();
  dirty = false;

  constructor(id: number, key: CryptoKey, metadata?: IVaultFolderMetadata) {
    this.id = id;
    this.key = key;
    this.metadata = metadata ?? { s: [], f: [] };
  }

  async serialize(extra?: object): Promise<string> {
    return await this.key.encryptObject(extra ? {...extra, ...this.metadata} : this.metadata);
  }

  handle(name: string): IVaultMetadataHandle {
    return {
      n: name,
      i: this.id,
      k: this.key.exportUnsafeRaw()
    };
  }

  static isMetadata(obj: unknown): obj is IVaultFolderMetadata {
    const isHandle = (h: unknown): h is IVaultMetadataHandle => (
      h !== null &&
      typeof h === 'object' &&
      !Array.isArray(h) &&
      'n' in h &&
      typeof h.n === 'string' &&
      'i' in h &&
      typeof h.i === 'number' &&
      'k' in h &&
      typeof h.k === 'string'
    );
    return (
      obj !== null &&
      typeof obj === 'object' &&
      !Array.isArray(obj) &&
      's' in obj &&
      Array.isArray(obj.s) &&
      obj.s.every(isHandle) &&
      'f' in obj &&
      Array.isArray(obj.f) &&
      obj.f.every(isHandle)
    );
  }

  static async deserialize(
    id: number,
    key: CryptoKey,
    metadata: string
  ): Promise<VaultFolder | null> {
    const obj = await key.decryptObject(metadata);
    if (!obj || !VaultFolder.isMetadata(obj)) {
      return null;
    }
    return new VaultFolder(id, key, obj);
  }

  isFolder(name: string, id?: number) {
    return !!this.metadata.s.find(
      ({ n, i }) => n === name && (typeof id === 'undefined' || i === id)
    );
  }

  isFile(name: string, id?: number) {
    return !!this.metadata.f.find(
      ({ n, i }) => n === name && (typeof id === 'undefined' || i === id)
    );
  }

  listFolders(): string[] {
    const f = this.metadata.s.map(({ n }) => n);
    f.sort((a, b) => a.localeCompare(b));
    return f;
  }

  listFiles(): string[] {
    const f = this.metadata.f.map(({ n }) => n);
    f.sort((a, b) => a.localeCompare(b));
    return f;
  }

  listDirtyFolders(): string[] {
    const f = [...this.folders.entries()].filter(([_, f]) => f.dirty).map(([n, _]) => n);
    f.sort((a, b) => a.localeCompare(b));
    return f;
  }

  listDirtyFiles(): string[] {
    const f = [...this.files.entries()].filter(([_, f]) => f.dirty).map(([n, _]) => n);
    f.sort((a, b) => a.localeCompare(b));
    return f;
  }

  async getFolderOrNull(name: string, io: FileIO): Promise<VaultFolder | null> {
    const f = this.folders.get(name);
    if (f) {
      return f;
    }
    const pf = this.metadata.s.find(f => f.n === name);
    if (!pf) {
      return null;
    }
    const key = CryptoKey.importUnsafeRaw(pf.k);
    const metadata = await io.readString(`${pf.i}.txt`);
    const folder = await VaultFolder.deserialize(pf.i, key, metadata);
    if (!folder) {
      return null;
    }
    this.folders.set(name, folder);
    return folder;
  }

  async getFolder(name: string, io: FileIO): Promise<VaultFolder> {
    const folder = await this.getFolderOrNull(name, io);
    if (!folder) {
      throw new Error(`Folder not found: ${name}`);
    }
    return folder;
  }

  async getFileOrNull(name: string, io: FileIO): Promise<VaultFile | null> {
    const f = this.files.get(name);
    if (f) {
      return f;
    }
    const pf = this.metadata.f.find(f => f.n === name);
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

  async getFile(name: string, io: FileIO): Promise<VaultFile> {
    const file = await this.getFileOrNull(name, io);
    if (!file) {
      throw new Error(`File not found: ${name}`);
    }
    return file;
  }

  async findHash(hash: string, io: FileIO): Promise<VaultFile | null> {
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

  putFolder(name: string, folder: VaultFolder) {
    this.deleteFile(name);
    this.dirty = true;
    this.folders.set(name, folder);
    const handle = folder.handle(name);
    const i = this.metadata.s.findIndex(f => f.n === name);
    if (i >= 0) {
      this.metadata.s[i] = handle;
    } else {
      this.metadata.s.push(handle);
    }
  }

  deleteFolder(name: string) {
    const i = this.metadata.s.findIndex(f => f.n === name);
    if (i < 0) {
      return;
    }
    this.dirty = true;
    this.folders.delete(name);
    this.metadata.s.splice(i, 1);
  }

  putFile(name: string, file: VaultFile) {
    this.deleteFolder(name);
    this.dirty = true;
    this.files.set(name, file);
    const handle = file.handle(name);
    const i = this.metadata.f.findIndex(f => f.n === name);
    if (i >= 0) {
      this.metadata.f[i] = handle;
    } else {
      this.metadata.f.push(handle);
    }
    return this;
  }

  deleteFile(name: string) {
    const i = this.metadata.f.findIndex(f => f.n === name);
    if (i < 0) {
      return;
    }
    this.dirty = true;
    this.files.delete(name);
    this.metadata.f.splice(i, 1);
  }

  async maxId(io: FileIO): Promise<number> {
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

  async findId(id: number, io: FileIO): Promise<boolean> {
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

  getType(name: string): 'notfound' | 'folder' | 'file' {
    if (this.isFolder(name)) {
      return 'folder';
    }
    if (this.isFile(name)) {
      return 'file';
    }
    return 'notfound';
  }
}

export class Vault {
  static DEFAULT_DIFFICULTY = 5;
  static ROOT_FILE = 'staticvault.txt';
  root: VaultFolder;
  io: FileIO;
  path: { name: string; folder: VaultFolder }[];
  difficulty: number;

  private constructor(root: VaultFolder, difficulty: number, io: FileIO) {
    this.root = root;
    this.io = io;
    this.path = [];
    this.difficulty = difficulty;
  }

  static async create(io: FileIO) {
    const key = await CryptoKey.generate();
    const root = new VaultFolder(-1, key);
    root.dirty = true;
    return new Vault(root, 0, io);
  }

  static async deserialize(
    data: string,
    password: string,
    io: FileIO
  ): Promise<Vault | null> {
    const parts = data.split('~');
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
    const metadata: object = root.metadata;
    if ('x' in metadata && typeof metadata.x === 'number') {
      const now = Math.floor(Date.now() / 60000);
      if (now >= metadata.x) {
        // expired
        return null;
      }
    }
    return new Vault(root, difficulty, io);
  }

  containerDirty() {
    return this.root.dirty;
  }

  // expiration is enforced on the client-side... so not 100% secure but at least it's something
  async serialize(password: string, difficulty = 0, expiresInMinutes = 0): Promise<string> {
    const d =
      difficulty > 0
      ? difficulty
      : this.difficulty > 0
      ? this.difficulty
      : Vault.DEFAULT_DIFFICULTY;
    let more: object | undefined = undefined;
    if (expiresInMinutes > 0) {
      more = { x: Math.ceil(Date.now() / 60000) + expiresInMinutes };
    }
    const k = await this.root.key.exportWithPassword(password, d);
    const r = await this.root.serialize(more);
    return `${k}~${r}`;
  }

  async save(forceEverything = false) {
    const saveFile = async (file: VaultFile) => {
      await this.io.writeString(`${file.id}.txt`, await file.serialize());
      file.dirty = false;
    }
    const saveFolder = async (folder: VaultFolder) => {
      if (folder.id >= 0 && (forceEverything || folder.dirty)) {
        await this.io.writeString(`${folder.id}.txt`, await folder.serialize());
        folder.dirty = false;
      }
      const files = forceEverything ? folder.listFiles() : folder.listDirtyFiles();
      await Promise.all(files.map(n => folder.getFile(n, this.io).then(f => saveFile(f))));
      const sub = folder.listFolders();
      await Promise.all(sub.map(n => folder.getFolder(n, this.io).then(f => saveFolder(f))));
    };
    await saveFolder(this.root);
  }

  async rekey(all = false, silent = false) {
    const newFiles = new Map<number, VaultFile>();
    const newFolders = new Map<number, VaultFolder>();
    const rekeyFile = async (path: string, file: VaultFile) => {
      if (!silent) {
        console.log(path);
      }
      file.key = await CryptoKey.generate();
      file.dirty = true;
      newFiles.set(file.id, file);
      if (all) {
        let fkey = CryptoKey.importUnsafeRaw(file.metadata.j);
        const oldBytes = await this.io.read(file.metadata.f);
        const bytes = await fkey.decryptBytes(oldBytes, file.metadata.v);
        if (!bytes) {
          if (!silent) {
            console.warn(`Warning: Failed to decrypt file: ${path} (${file.metadata.f})`);
          }
          return;
        }
        fkey = await CryptoKey.generate();
        const { encryptedBytes, iv } = await fkey.encryptBytes(bytes);
        file.metadata.j = fkey.exportUnsafeRaw();
        file.metadata.v = iv;
        await this.io.write(file.metadata.f, encryptedBytes);
      }
    };
    const rekeyFolder = async (path: string, folder: VaultFolder) => {
      if (!silent && path) {
        console.log(path);
      }
      folder.key = await CryptoKey.generate();
      folder.dirty = true;
      newFolders.set(folder.id, folder);
      for (const name of folder.listFolders()) {
        const sub = await folder.getFolder(name, this.io);
        const sub2 = newFolders.get(sub.id);
        folder.deleteFolder(name);
        if (sub2) {
          folder.putFolder(name, sub2);
        } else {
          await rekeyFolder(`${path}/${name}`, sub);
          folder.putFolder(name, sub);
        }
      }
      for (const name of folder.listFiles()) {
        const file = await folder.getFile(name, this.io);
        const file2 = newFiles.get(file.id);
        folder.deleteFile(name);
        if (file2) {
          folder.putFile(name, file2);
        } else {
          await rekeyFile(`${path}/${name}`, file);
          folder.putFile(name, file);
        }
      }
    };
    await rekeyFolder('', this.root);
  }

  private currentFolder() {
    if (this.path.length <= 0) {
      return this.root;
    }
    return this.path[0].folder;
  }

  getPath() {
    return `/${this.path.map(({ name }) => name).reverse().join('/')}`;
  }

  async setPath(path: string) {
    const current = this.path.map(({ name }) => name).reverse();
    const parts = resolvePath(`/${current.join('/')}`, path);
    // find shared base directory
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

  getType(name: string): 'notfound' | 'folder' | 'file' {
    return this.currentFolder().getType(name);
  }

  listFolders() {
    return this.currentFolder().listFolders();
  }

  listFiles() {
    return this.currentFolder().listFiles();
  }

  async enterFolder(name: string) {
    const folder = await this.currentFolder().getFolder(name, this.io);
    this.path.unshift({ name, folder });
  }

  exitFolder() {
    this.path.shift();
  }

  exitToRoot() {
    this.path = [];
  }

  async putFile(name: string, bytes: Uint8Array): Promise<'exists' | 'linked' | 'success'> {
    if (name.indexOf('/') >= 0 || name === '.' || name === '..') {
      throw new Error(`Invalid file name: ${name}`);
    }
    const hash = await hashBytes(bytes);
    const file = await this.root.findHash(hash, this.io);
    if (file) {
      if (this.currentFolder().isFile(name, file.id)) {
        return 'exists';
      }
      this.currentFolder().putFile(name, file);
      return 'linked';
    }
    const id = 1 + await this.root.maxId(this.io);
    const [key, fkey] = await Promise.all([CryptoKey.generate(), CryptoKey.generate()]);
    const j = fkey.exportUnsafeRaw();
    const filename = `file-${crypto.randomUUID()}.bin`;
    const { encryptedBytes, iv } = await fkey.encryptBytes(bytes);
    const newFile = new VaultFile(id, key, { f: filename, h: hash, j, v: iv });
    newFile.dirty = true;
    this.currentFolder().putFile(name, newFile);
    await this.io.write(filename, encryptedBytes);
    return 'success';
  }

  async putFileLink(name: string, filePath: string, from?: Vault): Promise<'exists' | 'linked'> {
    if (name.indexOf('/') >= 0 || name === '.' || name === '..') {
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
      return 'exists';
    }
    this.currentFolder().putFile(name, file);
    return 'linked';
  }

  async putFolder(name: string): Promise<'exists' | 'success'> {
    if (name.indexOf('/') >= 0 || name === '.' || name === '..') {
      throw new Error(`Invalid folder name: ${name}`);
    }
    if (this.currentFolder().isFolder(name)) {
      return 'exists';
    }
    const id = 1 + await this.root.maxId(this.io);
    const key = await CryptoKey.generate();
    const newFolder = new VaultFolder(id, key);
    newFolder.dirty = true;
    this.currentFolder().putFolder(name, newFolder);
    return 'success';
  }

  async putFolderLink(
    name: string,
    folderPath: string,
    from?: Vault
  ): Promise<'exists' | 'linked'> {
    if (name.indexOf('/') >= 0 || name === '.' || name === '..') {
      throw new Error(`Invalid folder name: ${name}`);
    }
    const src = from ?? this;
    const parts = resolvePath(src.getPath(), folderPath);
    let here = src.root;
    for (let i = 0; i < parts.length; i++) {
      here = await here.getFolder(parts[i], this.io);
    }
    if (this.currentFolder().isFolder(name, here.id)) {
      return 'exists';
    }
    this.currentFolder().putFolder(name, here);
    return 'linked';
  }

  async getFile(name: string): Promise<Uint8Array | null> {
    const file = await this.currentFolder().getFileOrNull(name, this.io);
    if (!file) {
      return null;
    }
    const encryptedBytes = await this.io.read(file.metadata.f);
    const fkey = CryptoKey.importUnsafeRaw(file.metadata.j);
    const bytes = await fkey.decryptBytes(encryptedBytes, file.metadata.v);
    if (!bytes) {
      return null;
    }
    return bytes;
  }

  async remove(
    name: string
  ): Promise<'notfound' | 'unlinked-file' | 'removed-file' | 'unlinked-folder' | 'removed-folder'> {
    const deleteFile = async (
      parent: VaultFolder,
      name: string,
      file: VaultFile
    ): Promise<'unlinked-file' | 'removed-file'> => {
      parent.deleteFile(name);
      if (await this.root.findId(file.id, this.io)) {
        // someone else uses this file, so keep it around
        return 'unlinked-file';
      } else {
        // no more references to this file, so delete from disk
        await this.io.remove(file.metadata.f);
        await this.io.remove(`${file.id}.txt`);
        return 'removed-file';
      }
    };

    const deleteFolder = async (
      parent: VaultFolder,
      name: string,
      folder: VaultFolder
    ): Promise<'unlinked-folder' | 'removed-folder'> => {
      // remove subfolders
      for (const n of folder.listFolders()) {
        const sub = await folder.getFolder(n, this.io);
        await deleteFolder(folder, n, sub);
      }
      // remove files
      for (const n of folder.listFiles()) {
        const file = await folder.getFile(n, this.io);
        await deleteFile(folder, n, file);
      }
      // finally, remove this folder
      parent.deleteFolder(name);
      if (await this.root.findId(folder.id, this.io)) {
        // someone else uses this folder, so keep it around
        return 'unlinked-folder';
      } else {
        // no more references to this folder, so delete from disk
        await this.io.remove(`${folder.id}.txt`);
        return 'removed-folder';
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
    return 'notfound';
  }
}
