StaticVault
===========

**StaticVault** lets you create an encrypted, client-decryptable file system that can be hosted on
static web platforms like S3, GitHub Pages, or any CDN. Ideal for secure, private content
delivery, and easily hosted on static blogs (Hugo, Jekyll, etc).

You encrypt and manage your files locally, then deploy the encrypted vault. A lightweight
browser-based app (included) allows in-browser decryption and previews of text and images.

[Demo vault](https://sean.fun/staticvault-demo/) (password: `hello`).

Features
--------

- Encrypt files locally
- Host anywhere: S3, Netlify, GitHub Pages, etc
- Duplicate files are only stored once
- CLI for creating, ingesting, listing, and extracting files

Client features:

- Mobile friendly site for browsing files
- Preview images/text in browser
- Share files/folders with friends
- Set expiration for shared links (enforced client-side)

Quick Start
-----------

You don't need to install anything globally - just use `npx`:

```bash
npx staticvault init path/to/vault
npx staticvault ingest path/to/vault path/to/files
```

Then upload the contents of `path/to/vault` to your static site host.

Your newly created vault includes the client, `index.html`, and library `index.min.js`, which you
can access on your site.

Commands
--------

```bash
npx staticvault <command> [arguments]
```

## `chpass`

Change vault password.

```bash
chpass <vault> [-p password] [-n newpassword]
```

## `dump`

Decrypt the vault into a directory.

```bash
npx staticvault dump <vault> <destination> [-p password]
```

## `init`

Initialize a new vault.

```bash
npx staticvault init <vault> [-p password] [-d difficulty]
```

## `ingest`

Encrypt and add files to an existing vault.

```bash
npx staticvault ingest <vault> <source> [-p password]
```

## `rekey`

Generates new encryption keys. By default, this will rotate the metadata keys. Use `-a` to rotate
the file keys as well, but this will mean re-encrypting all files, which could be expensive.

Useful for revoking access to all shared links.

```bash
npx staticvault rekey <vault> [-p password] [-a]
```

## `rm`

Remove a file or folder from the vault.

```bash
npx staticvault rm <vault> <path> [-p password]
```

## `test`

Run internal tests.

```bash
npx staticvault test
```

## `tree`

List the contents of the vault.

```bash
npx staticvault tree <vault> [-p password]
```

## `version`

Output version.

```bash
npx staticvault version
```

Example Workflow
----------------

```bash
npx staticvault init myvault
npx staticvault ingest myvault ./blog-attachments
npx staticvault tree myvault
```

Then upload the contents of `myvault/` to your static host.
