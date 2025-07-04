//
// staticvault - Encrypt, host, and share files on a static website
// by Sean Connelly (@velipso), https://sean.fun
// Project Home: https://github.com/velipso/staticvault
// SPDX-License-Identifier: 0BSD
//

export function bytesToString(bytes: Uint8Array): string {
  const b64 = typeof process !== 'undefined'
    ? Buffer.from(bytes).toString('base64')
    : btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function stringToBytes(str: string): Uint8Array {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return typeof process !== 'undefined'
    ? new Uint8Array(Buffer.from(b64, 'base64'))
    : new Uint8Array(atob(b64).split('').map(c => c.charCodeAt(0)));
}

export function stringify(obj: unknown): string {
  if (obj !== null && typeof obj === 'object' && !Array.isArray(obj)) {
    // sort the keys so stringify is consistent
    const keys = Object.keys(obj);
    keys.sort((a, b) => a.localeCompare(b));
    const out = [];
    for (const k of keys) {
      out.push(`${JSON.stringify(k)}:${stringify((obj as Record<string, unknown>)[k])}`);
    }
    return `{${out.join(',')}}`;
  } else {
    return JSON.stringify(obj);
  }
}

export async function hashBytes(bytes: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function resolvePath(currentDirectory: string, path: string) {
  if (!currentDirectory.startsWith('/')) {
    throw new Error('Current directory must be absolute');
  }
  const here: string[] = path.startsWith('/') || currentDirectory === '/'
    ? []
    : currentDirectory.substr(1).split('/');
  const parts = path.split('/');
  for (const part of parts) {
    if (part === '.') {
      // do nothing
    } else if (part === '..') {
      here.pop();
    } else if (part !== '') {
      here.push(part);
    }
  }
  return here;
}
