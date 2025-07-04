StaticVault
===========

**StaticVault** lets you create an encrypted, client-decryptable file system that can be hosted on
static web platforms like S3, GitHub Pages, or any CDN. Ideal for secure, private content
delivery, and easily hosted on static blogs (Hugo, Jekyll, etc).

You encrypt and manage your files locally, then deploy the encrypted vault. A lightweight
browser-based app (included) allows in-browser decryption and previews of text and images.

Features
--------

- 💾 Encrypt files locally
- 🌐 Host anywhere: S3, Netlify, GitHub Pages, etc
- 🖼️ In-browser decryption and preview for text/images
- 🗂️ CLI for creating, ingesting, listing, and extracting files

Quick Start
-----------

You don't need to install anything globally - just use `npx`:

```bash
npx staticvault init path/to/vault
npx staticvault ingest path/to/files path/to/vault
```

Then upload the contents of `path/to/vault` to your static site host.

Your newly created vault includes the client, `index.html`, and library `index.min.js`, which you
can access on your site.

Commands
--------

```bash
npx staticvault <command> [arguments]
```

## `init`

Initialize a new vault.

```bash
npx staticvault init <vault> [-p password] [-d difficulty]
```

## `ingest`

Encrypt and add files to an existing vault.

```bash
npx staticvault ingest <source> <vault> [-p password]
```

## `dump`

Decrypt the vault into a directory.

```bash
npx staticvault dump <vault> <destination> [-p password]
```

## `rm`

Remove a file or folder from the vault.

```bash
npx staticvault rm <vault> <path> [-p password]
```

## `tree`

List the contents of the vault.

```bash
npx staticvault tree <vault> [-p password]
```

## `test`

Run internal tests.

```bash
npx staticvault test
```

Example Workflow
----------------

```bash
npx staticvault init myvault -p mypassword
npx staticvault ingest ./blog-attachments myvault -p mypassword
npx staticvault tree myvault -p mypassword
```

Then upload the contents of `myvault/` to your static host.
