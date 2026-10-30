# Releasing

Releases are cut by hand. Tags and GitHub Releases never publish on their own; the `release` workflow does, through
npm trusted publishing, so no npm token is stored anywhere.

## Once, before the first release

npm attaches a trusted publisher to a package that already exists, so the name has to be published once by hand:

1. Log in to npm as the account that will own the package (2FA on).
2. Publish a placeholder: set `"version": "0.0.0-stage"` in a scratch copy of `package.json`, then
   `npm publish --access public --tag stage`. Do not publish real code this way.
3. On npmjs.com, open the package → Settings → Trusted publishing → GitHub Actions, and add: organisation/user
   `ef0100dev`, repository `ef0100`, workflow `release.yml`, environment `npm`.
4. In the GitHub repository, create an environment named `npm` (Settings → Environments) and restrict who may approve
   it.
5. Turn on private vulnerability reporting (Settings → Security).

## Each release

1. On a branch: move the entries under `## Unreleased` in CHANGELOG.md to `## X.Y.Z — YYYY-MM-DD` (UTC date), with a
   one-paragraph summary on top, and set `"version": "X.Y.Z"` in `package.json`.
2. Open a pull request; CI must pass on Node 22 and 24, including the packed-tarball smoke test.
3. Merge, then tag the merge commit: `git tag -a vX.Y.Z -m "vX.Y.Z"` and `git push origin vX.Y.Z`.
4. Actions → release → Run workflow, with version `X.Y.Z`. It checks out the tag, checks that the tag matches
   `package.json`, builds, lints, tests, verifies `SHA256SUMS` and publishes with provenance.
5. Create the GitHub Release from the tag, with the CHANGELOG section as its notes.
