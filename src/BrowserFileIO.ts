//
// staticvault - Encrypt, host, and share files on a static website
// by Sean Connelly (@velipso), https://sean.fun
// Project Home: https://github.com/velipso/staticvault
// SPDX-License-Identifier: 0BSD
//

import { FileIO } from './FileIO';

export class BrowserFileIO extends FileIO {
  async remove(path: string): Promise<void> {
    throw new Error('Cannot remove files in browser');
  }

  async read(path: string): Promise<Uint8Array> {
    const response = await fetch(path, { cache: 'no-store' });
    const buffer = await response.arrayBuffer();
    return new Uint8Array(buffer);
  }

  async readString(path: string): Promise<string> {
    const response = await fetch(path, { cache: 'no-store' });
    return await response.text();
  }

  async write(path: string, data: Uint8Array): Promise<void> {
    throw new Error('Cannot write bytes in browser');
  }
}
