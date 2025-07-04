//
// staticvault - Encrypt, host, and share files on a static website
// by Sean Connelly (@velipso), https://sean.fun
// Project Home: https://github.com/velipso/staticvault
// SPDX-License-Identifier: 0BSD
//

import { stringify, stringToBytes, bytesToString, hashBytes, resolvePath } from './util';
import { DirectoryFileIO, MemoryFileIO, ReadonlyFileIO } from './FileIO';
import { NodeFileIO } from './NodeFileIO';
import { CryptoKey } from './CryptoKey';
import { Vault } from './Vault';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as readline from 'readline';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function printUsage(filter?: string) {
  console.log(`Usage:\n  staticvault <command> [arguments]`);
  if (!filter) {
    console.log(`\nCommands:`);
  } else {
    console.log(`\nCurrent command:`);
  }
  if (!filter || filter === 'chpass') {
    console.log(`
- chpass <vault> [-p password] [-n newpassword]

  Change vault password

  <vault>          Vault directory
  [-p password]    Current password
  [-n newpassword] New password`);
  }
  if (!filter || filter === 'dump') {
    console.log(`
- dump <vault> <destination> [-p password]

  Decrypt and copy out entire vault to destination

  <vault>          Vault directory
  <destination>    Decryption target directory
  [-p password]    Encryption password`);
  }
  if (!filter || filter === 'ingest') {
    console.log(`
- ingest <vault> <source> [-p password]

  Encrypt and copy source folders/files into vault

  <vault>          Vault directory
  <source>         Source directory
  [-p password]    Encryption password`);
  }
  if (!filter || filter === 'init') {
    console.log(`
- init <vault> [-p password] [-d difficulty]

  Initialize a new vault

  <vault>          Vault directory
  [-p password]    Encryption password
  [-d difficulty]  Encryption difficulty (default: ${Vault.DEFAULT_DIFFICULTY})`);
  }
  if (!filter || filter === 'rm') {
    console.log(`
- rm <vault> <path> [-p password]

  Remove a file/folder

  <vault>          Vault directory
  <path>           Path of the secure file/folder
  [-p password]    Encryption password`);
  }
  if (!filter || filter === 'test') {
    console.log(`
- test

  Run internal tests`);
  }
  if (!filter || filter === 'tree') {
    console.log(`
- tree <vault> [-p password]

  Recursive directory listing

  <vault>          Vault directory
  [-p password]    Encryption password`);
  }
  if (!filter || filter === 'version') {
    console.log(`
- version

  Output version of staticvault`);
  }
}

async function promptPassword(prompt = 'Password: '): Promise<string> {
  if (!process.stdin.isTTY) {
    console.error(`Password prompt requires a TTY`);
    process.exit(1);
  }
  process.stdout.write(prompt + ': ');
  return await new Promise<string>((resolve) => {
    const stdin = process.stdin;
    const input: string[] = [];
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');

    const onData = (char: string) => {
      if (char === '\r' || char === '\n') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(input.join(''));
      } else if (char === '\u0003') { // ctrl-c
        process.exit();
      } else if (char === '\u0008' || char === '\u007F') {
        input.pop(); // backspace/delete
      } else {
        input.push(char);
      }
    };

    stdin.on('data', onData);
  });
}

function treeChars(depth: number, last: boolean, folder: boolean, status?: string) {
  let prefix = '';
  for (let j = 0; j < depth; j++) {
    prefix += '│  ';
  }
  prefix += last ? '└─ ' : '├─ ';
  let postfix = folder ? '/' : '';
  if (status) {
    postfix += ' ' + status;
  }
  return { prefix, postfix };
}

async function cmdChpass(args: string[]): Promise<number> {
  let target: string | null = null;
  let password: string | null = null;
  let newpassword: string | null = null;
  for (;;) {
    const arg = args.shift();
    if (typeof arg === 'undefined') break;
    if (arg === '-p') {
      if (password === null) {
        const pw = args.shift();
        if (typeof pw === 'undefined') {
          printUsage('chpass');
          console.error(`\nMissing password`);
          return 1;
        }
        password = pw;
      } else {
        printUsage('chpass');
        console.error(`\nCannot specify password more than once`);
        return 1;
      }
    } else if (arg === '-n') {
      if (newpassword === null) {
        const pw = args.shift();
        if (typeof pw === 'undefined') {
          printUsage('chpass');
          console.error(`\nMissing new password`);
          return 1;
        }
        newpassword = pw;
      } else {
        printUsage('chpass');
        console.error(`\nCannot specify new password more than once`);
        return 1;
      }
    } else if (target === null) {
      target = arg;
    } else {
      printUsage('chpass');
      console.error(`\nUnknown argument: ${arg}`);
      return 1;
    }
  }
  if (target === null) {
    printUsage('chpass');
    console.error(`\nMissing vault directory`);
    return 1;
  }
  if (password === null) {
    password = await promptPassword('Password');
  }
  if (newpassword === null) {
    newpassword = await promptPassword('New Password');
    const p2 = await promptPassword('Again');
    if (newpassword !== p2) {
      console.error(`Passwords don't match`);
      return 1;
    }
  }
  const io = new DirectoryFileIO(target, new NodeFileIO());
  const root = await io.readString(Vault.ROOT_FILE);
  const vault = await Vault.deserialize(root, password, io);
  if (!vault) {
    console.error(`Wrong password`);
    return 1;
  }
  await io.writeString(Vault.ROOT_FILE, await vault.serialize(newpassword));
  return 0;
}

async function cmdDump(args: string[]): Promise<number> {
  let target: string | null = null;
  let destination: string | null = null;
  let password: string | null = null;
  for (;;) {
    const arg = args.shift();
    if (typeof arg === 'undefined') break;
    if (arg === '-p') {
      if (password === null) {
        const pw = args.shift();
        if (typeof pw === 'undefined') {
          printUsage('dump');
          console.error(`\nMissing password`);
          return 1;
        }
        password = pw;
      } else {
        printUsage('dump');
        console.error(`\nCannot specify password more than once`);
        return 1;
      }
    } else if (target === null) {
      target = arg;
    } else if (destination === null) {
      destination = arg;
    } else {
      printUsage('dump');
      console.error(`\nUnknown argument: ${arg}`);
      return 1;
    }
  }
  if (target === null) {
    printUsage('dump');
    console.error(`\nMissing vault directory`);
    return 1;
  }
  if (destination === null) {
    printUsage('dump');
    console.error(`\nMissing destination directory`);
    return 1;
  }
  if (password === null) {
    password = await promptPassword('Password');
  }
  const io = new DirectoryFileIO(target, new NodeFileIO());
  const root = await io.readString(Vault.ROOT_FILE);
  const vault = await Vault.deserialize(root, password, io);
  if (!vault) {
    console.error(`Wrong password`);
    return 1;
  }
  const walk = async (dir: string) => {
    for (const folder of vault.listFolders()) {
      const d = path.join(dir, folder);
      await fs.mkdir(d);
      await vault.enterFolder(folder);
      await walk(d);
      vault.exitFolder();
    }
    for (const file of vault.listFiles()) {
      const bytes = await vault.getFile(file);
      if (!bytes) {
        console.warn(`Warning: Failed to decrypt file: ${vault.getPath()}/${file}`);
      } else {
        await fs.writeFile(path.join(dir, file), bytes);
      }
    }
  };
  await walk(destination);
  return 0;
}

async function cmdIngest(args: string[]): Promise<number> {
  let target: string | null = null;
  let source: string | null = null;
  let password: string | null = null;
  for (;;) {
    const arg = args.shift();
    if (typeof arg === 'undefined') break;
    if (arg === '-p') {
      if (password === null) {
        const pw = args.shift();
        if (typeof pw === 'undefined') {
          printUsage('ingest');
          console.error(`\nMissing password`);
          return 1;
        }
        password = pw;
      } else {
        printUsage('ingest');
        console.error(`\nCannot specify password more than once`);
        return 1;
      }
    } else if (target === null) {
      target = arg;
    } else if (source === null) {
      source = arg;
    } else {
      printUsage('ingest');
      console.error(`\nUnknown argument: ${arg}`);
      return 1;
    }
  }
  if (target === null) {
    printUsage('ingest');
    console.error(`\nMissing vault directory`);
    return 1;
  }
  if (source === null) {
    printUsage('ingest');
    console.error(`\nMissing source directory`);
    return 1;
  }
  if (password === null) {
    password = await promptPassword('Password');
  }
  const srcIO = new NodeFileIO();
  const io = new DirectoryFileIO(target, new NodeFileIO());
  const root = await io.readString(Vault.ROOT_FILE);
  const vault = await Vault.deserialize(root, password, io);
  if (!vault) {
    console.error(`Wrong password`);
    return 1;
  }
  const walk = async (depth: number, src: string) => {
    const items: { name: string; dir: boolean }[] = [];
    const entries = await fs.readdir(src, { withFileTypes: true });
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
      exists: '(exists)',
      success: '(copied!)',
      linked: '(linked!)'
    };
    for (let i = 0; i < items.length; i++) {
      const { name, dir } = items[i];
      const full = path.join(src, name);
      let status = '?';
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
  }
  await walk(0, source);
  await vault.save();
  if (vault.containerDirty()) {
    await io.writeString(Vault.ROOT_FILE, await vault.serialize(password));
  }
  return 0;
}

async function cmdInit(args: string[]): Promise<number> {
  let target: string | null = null;
  let password: string | null = null;
  let difficulty: number | null = null;
  for (;;) {
    const arg = args.shift();
    if (typeof arg === 'undefined') break;
    if (arg === '-p') {
      if (password === null) {
        const pw = args.shift();
        if (typeof pw === 'undefined') {
          printUsage('init');
          console.error(`\nMissing password`);
          return 1;
        }
        password = pw;
      } else {
        printUsage('init');
        console.error(`\nCannot specify password more than once`);
        return 1;
      }
    } else if (arg === '-d') {
      if (difficulty === null) {
        const d = args.shift();
        if (typeof d === 'undefined') {
          printUsage('init');
          console.error(`\nMissing difficulty`);
          return 1;
        }
        if (~/^[1-9][0-9]*$/.test(d)) {
          printUsage('init');
          console.error(`\nDifficulty must be a positive integer`);
          return 1;
        }
        difficulty = parseInt(d, 10);
      } else {
        printUsage('init');
        console.error(`\nCannot specify difficulty more than once`);
        return 1;
      }
    } else if (target === null) {
      target = arg;
    } else {
      printUsage('init');
      console.error(`\nUnknown argument: ${arg}`);
      return 1;
    }
  }
  if (target === null) {
    printUsage('init');
    console.error(`\nMissing vault directory`);
    return 1;
  }
  if (difficulty === null) {
    difficulty = Vault.DEFAULT_DIFFICULTY;
  }
  if (isNaN(difficulty) || difficulty < 1 || Math.floor(difficulty) !== difficulty) {
    printUsage('init');
    console.error(`\nInvalid difficulty`);
  }
  if (password === null) {
    password = await promptPassword('Password');
    const p2 = await promptPassword('Again');
    if (password !== p2) {
      console.error(`Passwords don't match`);
      return 1;
    }
  }
  await fs.mkdir(target, { recursive: true });
  const io = new DirectoryFileIO(target, new NodeFileIO());
  const vault = await Vault.create(io);
  const data = await vault.serialize(password, difficulty);
  await Promise.all([
    io.writeString(Vault.ROOT_FILE, data),
    io.write('index.html', await fs.readFile(path.join(__dirname, 'index.html'))),
    io.write('index.min.js', await fs.readFile(path.join(__dirname, 'index.min.js')))
  ]);
  return 0;
}

async function cmdRm(args: string[]): Promise<number> {
  let target: string | null = null;
  let spath: string | null = null;
  let password: string | null = null;
  for (;;) {
    const arg = args.shift();
    if (typeof arg === 'undefined') break;
    if (arg === '-p') {
      if (password === null) {
        const pw = args.shift();
        if (typeof pw === 'undefined') {
          printUsage('rm');
          console.error(`\nMissing password`);
          return 1;
        }
        password = pw;
      } else {
        printUsage('rm');
        console.error(`\nCannot specify password more than once`);
        return 1;
      }
    } else if (target === null) {
      target = arg;
    } else if (spath === null) {
      spath = arg;
    } else {
      printUsage('rm');
      console.error(`\nUnknown argument: ${arg}`);
      return 1;
    }
  }
  if (target === null) {
    printUsage('rm');
    console.error(`\nMissing vault directory`);
    return 1;
  }
  if (spath === null) {
    printUsage('rm');
    console.error(`\nMissing secure path`);
    return 1;
  }
  if (password === null) {
    password = await promptPassword('Password');
  }
  const io = new DirectoryFileIO(target, new NodeFileIO());
  const root = await io.readString(Vault.ROOT_FILE);
  const vault = await Vault.deserialize(root, password, io);
  if (!vault) {
    console.error(`Wrong password`);
    return 1;
  }
  const parts = resolvePath('/', spath);
  for (let i = 0; i < parts.length - 1; i++) {
    await vault.enterFolder(parts[i]);
  }
  const result = await vault.remove(parts[parts.length - 1]);
  if (result === 'notfound') {
    console.error(`Path not found: ${spath}`);
    return 1;
  }
  await vault.save();
  if (vault.containerDirty()) {
    await io.writeString(Vault.ROOT_FILE, await vault.serialize(password));
  }
  return 0;
}

async function cmdTest(args: string[]): Promise<number> {
  console.log('Running tests...');

  const key = await CryptoKey.generate();
  key.assertEqual(key);
  key.assertEqual(
    (await CryptoKey.importWithPassword(
      await key.exportWithPassword('hello world'),
      'hello world'
    ))?.key ?? null
  );

  if (null !== await CryptoKey.importWithPassword(
    await key.exportWithPassword('hello1'),
    'hello2'
  )) {
    throw new Error('Wrong password should return null');
  }

  if ('hello world' !== await key.decryptString(await key.encryptString('hello world'))) {
    throw new Error('Failed to encrypt/decrypt string');
  }

  {
    const obj1 = { b: 1, a: 2 };
    const obj2 = [4, 5, 6];
    const obj1Enc = await key.encryptObject(obj1);
    const obj2Enc = await key.encryptObject(obj2);
    if (stringify(await key.decryptObject(obj1Enc)) !== stringify(obj1)) {
      throw new Error('Invalid decrypted object');
    }
    if (stringify(await key.decryptObject(obj2Enc)) !== stringify(obj2)) {
      throw new Error('Invalid decrypted object');
    }
  }

  for (const js of ['true', 'false', 'null', '"hello"', '123']) {
    if (null !== await key.decryptObject('x' + await key.encryptString(js))) {
      throw new Error('Invalid decrypted object');
    }
  }

  {
    const ar = Array.from({ length: 100 }).map(() => Math.floor(Math.random() * 256));
    const bytes = new Uint8Array(ar);
    const { encryptedBytes, iv } = await key.encryptBytes(bytes);
    const bytesDec = await key.decryptBytes(encryptedBytes, iv);
    if (bytesDec && bytesToString(bytes) !== bytesToString(bytesDec)) {
      throw new Error('Failed to decrypt bytes');
    }
  }

  if (
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' !==
    await hashBytes(new Uint8Array('hello'.split('').map(a => a.charCodeAt(0))))
  ) {
    throw new Error('Failed to hash bytes');
  }

  {
    const io = new MemoryFileIO();
    const vault1 = await Vault.create(io);
    const file1 = 'hello world';
    await vault1.putFolder('test');
    await vault1.enterFolder('test');
    await vault1.putFile('hello.txt', new TextEncoder().encode(file1));
    await vault1.save();
    const vaultEnc = await vault1.serialize('hello');

    const vault2 = await Vault.deserialize(vaultEnc, 'hello', io);
    if (!vault2) {
      throw new Error(`Failed to reopen vault`);
    }
    const data1 = await vault2.getFile('hello.txt');
    if (data1) {
      throw new Error(`File shouldn't be found`);
    }
    await vault2.enterFolder('test');
    const data2 = await vault2.getFile('hello.txt');
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
    const file1 = 'hello world';
    await vault1.putFolder('test1');
    await vault1.enterFolder('test1');
    await vault1.putFolder('test2');
    await vault1.enterFolder('test2');
    await vault1.putFile('hello1.txt', new TextEncoder().encode(file1));
    vault1.exitToRoot();
    await vault1.putFile('hello2.txt', new TextEncoder().encode(file1));
    vault1.putFolderLink('test3', '/test1/test2');
    await vault1.save();
    const vaultEnc = await vault1.serialize('hello');

    if ([...io.files.keys()].length !== 4) {
      throw new Error('Should only have 4 keys');
    }

    const vault2 = await Vault.deserialize(vaultEnc, 'hello', io);
    if (!vault2) {
      throw new Error(`Failed to reopen vault`);
    }
    const file2d = await vault2.getFile('hello2.txt');
    if (!file2d) {
      throw new Error(`Missing hello2.txt`);
    }
    const file2 = new TextDecoder().decode(file2d);
    if (file1 !== file2) {
      throw new Error(`Failed to read linked file`);
    }
    await vault2.setPath('/test3');
    const file3d = await vault2.getFile('hello1.txt');
    if (!file3d) {
      throw new Error(`Missing hello1.txt`);
    }
    const file3 = new TextDecoder().decode(file3d);
    if (file1 !== file3) {
      throw new Error(`Failed to read file through linked folder`);
    }
    for (const p of ([ '/test1', '/test1/test2', '/test3' ])) {
      await vault2.setPath(p);
      if (p !== vault2.getPath()) {
        throw new Error(`Failed to set path: ${p}`);
      }
    }
  }

  {
    const io = new MemoryFileIO();
    const vault1 = await Vault.create(io);
    const file1 = 'hello world';
    await vault1.putFile('hello1.txt', new TextEncoder().encode(file1));
    await vault1.save();
    const vaultEnc = await vault1.serialize('hello');

    const ro = new ReadonlyFileIO(io);
    const vault2 = await Vault.create(ro);
    await vault2.putFileLink('hello2.txt', '/hello1.txt', vault1);
    await vault2.save();
    const vault2Enc = await vault2.serialize('asdf');

    const vault3 = await Vault.deserialize(vault2Enc, 'asdf', ro);
    if (!vault3) {
      throw new Error(`Failed to reopen vault`);
    }
    if (
      JSON.stringify(vault3.listFiles()) !== '["hello2.txt"]' ||
      JSON.stringify(vault3.listFolders()) !== '[]'
    ) {
      throw new Error(`Failed to create isolated read-only vault`);
    }
    const file2d = await vault3.getFile('hello2.txt');
    if (!file2d) {
      throw new Error(`Failed to get hello2.txt`);
    }
    const file2 = new TextDecoder().decode(file2d);
    if (file1 !== file2) {
      throw new Error(`Failed to decrypt hello2.txt`);
    }
  }

  console.log('success!');
  return 0;
}

async function cmdTree(args: string[]): Promise<number> {
  let target: string | null = null;
  let password: string | null = null;
  for (;;) {
    const arg = args.shift();
    if (typeof arg === 'undefined') break;
    if (arg === '-p') {
      if (password === null) {
        const pw = args.shift();
        if (typeof pw === 'undefined') {
          printUsage('tree');
          console.error(`\nMissing password`);
          return 1;
        }
        password = pw;
      } else {
        printUsage('tree');
        console.error(`\nCannot specify password more than once`);
        return 1;
      }
    } else if (target === null) {
      target = arg;
    } else {
      printUsage('tree');
      console.error(`\nUnknown argument: ${arg}`);
      return 1;
    }
  }
  if (target === null) {
    printUsage('tree');
    console.error(`\nMissing vault directory`);
    return 1;
  }
  if (password === null) {
    password = await promptPassword('Password');
  }
  const io = new DirectoryFileIO(target, new NodeFileIO());
  const root = await io.readString(Vault.ROOT_FILE);
  const vault = await Vault.deserialize(root, password, io);
  if (!vault) {
    console.error(`Wrong password`);
    return 1;
  }
  const walk = async (depth: number) => {
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

async function cmdVersion(args: string[]): Promise<number> {
  const data = await fs.readFile(path.join(__dirname, '..', 'package.json'), { encoding: 'utf8' });
  const pack = JSON.parse(data);
  console.log(`StaticVault v${pack.version}
Encrypt, host, and share files on a static website
by Sean Connelly (@velipso), https://sean.fun
Project Home: https://github.com/velipso/staticvault
SPDX-License-Identifier: 0BSD`);
  return 0;
}

async function main(args: string[]): Promise<number> {
  if (args.length <= 0) {
    printUsage();
    return 0;
  }
  const cmd = args.shift();
  switch (cmd) {
    case 'chpass':
      return cmdChpass(args);
    case 'dump':
      return cmdDump(args);
    case 'ingest':
      return cmdIngest(args);
    case 'init':
      return cmdInit(args);
    case 'rm':
      return cmdRm(args);
    case 'test':
      return cmdTest(args);
    case 'tree':
      return cmdTree(args);
    case 'version':
      return cmdVersion(args);
    default:
      printUsage();
      console.error(`\nUnknown command: ${cmd}`);
      return 1;
  }
  return 0;
}

main(process.argv.slice(2)).then(
  (code: number) => {
    process.exit(code);
  },
  (err: unknown) => {
    console.error(err);
    process.exit(1);
  }
);
