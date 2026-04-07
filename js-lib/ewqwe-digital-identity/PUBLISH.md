# Publishing `@ewqwe/digital-identity` to npm

## Pre-requisites

- Node.js ≥ 18 installed
- An npm account with publish access to the `@ewqwe` organisation (or a scoped token)
- All changes committed and PRs merged to `main`

## Checklist before publishing

1. **Bump the version** in `package.json` following [Semantic Versioning](https://semver.org/):
   - `patch` — bug fixes only
   - `minor` — backward-compatible new features
   - `major` — breaking API changes

   ```bash
   cd js-lib/ewqwe-digital-identity
   npm version patch   # or minor / major
   ```

2. **Run the full build and tests:**

   ```bash
   npm run build
   npm test
   ```

   The build script (`vite build && tsc --emitDeclarationOnly`) produces:

   | File             | Purpose                                      |
   |------------------|----------------------------------------------|
   | `dist/index.mjs` | ESM bundle — loaded by browsers & modern tooling |
   | `dist/index.cjs` | CommonJS bundle — loaded by `require()`     |
   | `dist/index.d.ts`| TypeScript declaration file                 |
   | `dist/*.map`     | Source maps for debugging                   |

3. **Verify the published file list** (`files` in `package.json`):

   ```bash
   npm pack --dry-run
   ```

   Expected output includes `dist/`, `README.md`, and `LICENSE`.

4. **Check for any untracked breaking changes:**

   ```bash
   npx arethetypeswrong --pack .
   ```

## Publishing

### Public scoped package

If the package is publicly available under `@ewqwe`:

```bash
npm publish --access public
```

### Private scoped package (e.g., GitHub Packages or private npm registry)

Configure `.npmrc` in the project root (do **not** commit auth tokens):

```ini
@ewqwe:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NPM_TOKEN}
```

Then publish normally:

```bash
npm publish
```

### CI / GitHub Actions example

```yaml
- name: Publish @ewqwe/digital-identity
  working-directory: js-lib/ewqwe-digital-identity
  run: |
    npm ci
    npm run build
    npm test
    npm publish --access public
  env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

## After publishing

- Tag the release in git:

  ```bash
  git tag js-lib/ewqwe-digital-identity@$(node -p "require('./package.json').version")
  git push --tags
  ```

- Update the `CHANGELOG.md` with the new version and release notes.

## Notes on the Chrome `crbug/1173575` warning

This warning — _"non-JS module files deprecated"_ — appears when Chrome's native
ES module loader receives a file that is not `text/javascript` (e.g., a raw
TypeScript `.ts` source file served with a wrong MIME type via a Vite alias).

The fix applied here ensures:

- The Vite build target is `es2022 / node18` — no legacy transforms that could
  rewrite top-level `await` or class fields into incompatible code.
- `dist/index.mjs` is pure compiled JavaScript (no TypeScript syntax) and is
  served with `Content-Type: text/javascript` by every HTTP server.
- The webapp `vite.config.ts` alias resolves `@ewqwe/digital-identity` to
  `dist/index.mjs` (compiled JS), **not** the raw TypeScript source.
- `"sideEffects": false` in `package.json` enables bundler tree-shaking without
  any extra analysis.

To verify: open Chrome DevTools → Console; there should be no `crbug/1173575`
entries after the fix is deployed.
