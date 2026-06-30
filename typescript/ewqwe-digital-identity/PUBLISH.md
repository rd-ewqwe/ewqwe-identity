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
   cd typescript/ewqwe-digital-identity
   pnpm version patch   # or minor / major
   ```

2. **Run the full build and tests:**

   ```bash
   pnpm run build
   pnpm test
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
   pnpm pack --dry-run
   ```

   Expected output includes `dist/`, `README.md`, and `LICENSE`.

4. **Check for any untracked breaking changes:**

   ```bash
   npx arethetypeswrong --pack .
   ```

## Publishing

Assuming the package will be publicly available under `@ewqwe`:

```bash
pnpm publish --access public
```



### CI / GitHub Actions (NOT YET ENFORCED)

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
