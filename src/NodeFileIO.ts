//
// staticvault - Encrypt, host, and share files on a static website
// by Sean Connelly (@velipso), https://sean.fun
// Project Home: https://github.com/velipso/staticvault
// SPDX-License-Identifier: 0BSD
//

import { FileIO } from './FileIO';
import * as fs from 'node:fs/promises';

export class NodeFileIO extends FileIO {
  async remove(path: string): Promise<void> {
    await fs.rm(path, { force: true });
  }

  async read(path: string): Promise<Uint8Array> {
    const buffer = await fs.readFile(path);
    return new Uint8Array(buffer);
  }

  async readString(path: string): Promise<string> {
    return await fs.readFile(path, { encoding: 'utf8' });
  }

  async write(path: string, data: Uint8Array): Promise<void> {
    await fs.writeFile(path, data);
  }

  async writeString(path: string, data: string): Promise<void> {
    await fs.writeFile(path, data, { encoding: 'utf8' });
  }
}
