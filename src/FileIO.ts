//
// staticvault - Encrypt, host, and share files on a static website
// by Sean Connelly (@velipso), https://sean.fun
// Project Home: https://github.com/velipso/staticvault
// SPDX-License-Identifier: 0BSD
//

import { stringify } from './util';

export abstract class FileIO {
  abstract remove(path: string): Promise<void>;
  abstract read(path: string): Promise<Uint8Array>;
  abstract write(path: string, data: Uint8Array): Promise<void>;

  async readString(path: string): Promise<string> {
    const data = await this.read(path);
    return new TextDecoder().decode(data);
  }

  async writeString(path: string, str: string): Promise<void> {
    await this.write(path, new TextEncoder().encode(str));
  }
}

export class MemoryFileIO extends FileIO {
  files = new Map<string, Uint8Array>();

  async remove(path: string): Promise<void> {
    this.files.delete(path);
  }

  async read(path: string): Promise<Uint8Array> {
    const data = this.files.get(path);
    if (!data) {
      throw new Error(`File not found: ${path}`);
    }
    return data;
  }

  async write(path: string, data: Uint8Array): Promise<void> {
    this.files.set(path, data);
  }
}

export class CacheFileIO extends FileIO {
  maxFiles: number;
  io: FileIO;
  cache = new Map<string, { data: Uint8Array; lastUsed: number }>();

  constructor(maxFiles: number, io: FileIO) {
    super();
    this.maxFiles = maxFiles;
    this.io = io;
  }

  private update(path: string, data: Uint8Array) {
    this.cache.set(path, { data, lastUsed: Date.now() });
    if (this.cache.size > this.maxFiles) {
      let oldestKey = '';
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

  async remove(path: string): Promise<void> {
    await this.io.remove(path);
    this.cache.delete(path);
  }

  async read(path: string): Promise<Uint8Array> {
    const c = this.cache.get(path);
    if (c) {
      c.lastUsed = Date.now();
      return c.data;
    }
    const data = await this.io.read(path);
    this.update(path, data);
    return data;
  }

  async readString(path: string): Promise<string> {
    const c = this.cache.get(path);
    if (c) {
      c.lastUsed = Date.now();
      return new TextDecoder().decode(c.data);
    }
    const data = await this.io.readString(path);
    this.update(path, new TextEncoder().encode(data));
    return data;
  }

  async write(path: string, data: Uint8Array): Promise<void> {
    await this.io.write(path, data);
    this.update(path, data);
  }

  async writeString(path: string, data: string): Promise<void> {
    await this.io.writeString(path, data);
    this.update(path, new TextEncoder().encode(data));
  }
}

export class DirectoryFileIO extends FileIO {
  rootDir: string;
  io: FileIO;
  separator: string;

  constructor(rootDir: string, io: FileIO, separator = '/') {
    super();
    this.rootDir = rootDir;
    this.io = io;
    this.separator = separator;
  }

  remove(path: string): Promise<void> {
    return this.io.remove(`${this.rootDir}${this.separator}${path}`);
  }

  read(path: string): Promise<Uint8Array> {
    return this.io.read(`${this.rootDir}${this.separator}${path}`);
  }

  readString(path: string): Promise<string> {
    return this.io.readString(`${this.rootDir}${this.separator}${path}`);
  }

  write(path: string, data: Uint8Array): Promise<void> {
    return this.io.write(`${this.rootDir}${this.separator}${path}`, data);
  }

  writeString(path: string, data: string): Promise<void> {
    return this.io.writeString(`${this.rootDir}${this.separator}${path}`, data);
  }
}

export class ReadonlyFileIO extends FileIO {
  io: FileIO;

  constructor(io: FileIO) {
    super();
    this.io = io;
  }

  remove(path: string): Promise<void> {
    throw new Error(`Cannot remove in read-only mode`);
  }

  read(path: string): Promise<Uint8Array> {
    return this.io.read(path);
  }

  readString(path: string): Promise<string> {
    return this.io.readString(path);
  }

  write(path: string, data: Uint8Array): Promise<void> {
    throw new Error(`Cannot write in read-only mode`);
  }

  writeString(path: string, data: string): Promise<void> {
    throw new Error(`Cannot write in read-only mode`);
  }
}
