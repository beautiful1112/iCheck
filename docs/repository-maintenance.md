# Repository cleanup and artifact retention

## Audit completed 14 October 2026

The disk pressure mainly came from accumulated packaged builds, not application
source. Before cleanup the repository occupied about 9.9 GiB: generated output
was 5.5 GiB, frontend dependencies 1.2 GiB and Git objects 3.0 GiB. The root
filesystem had approximately 561 MiB available.

At completion, available root space is **8.6 GiB** and filesystem usage is 87%.
The repository is **4.6 GiB**, down from 9.9 GiB. Verification build output was
also removed after the build passed, so it does not remain as another duplicate.

After checking imports, framework entrypoints, CLI scripts, tests, documentation,
file ownership and running-process references, the cleanup removed:

- 52 unused UI starter components and their unused mobile hook.
- Six files from the unused D1/Drizzle database example and three placeholder SVGs.
- 16 unused runtime dependencies and the Drizzle development dependency; npm
  pruned 67 installed packages. Lockfile entries fell from 878 to 765 without
  changing the version of any retained package.
- 195 old generated build directories/archives/wheel files, including the
  separately approved repository-local release copies. This artifact deletion
  recovered 7.82 GiB. Source, deployment scripts and standalone acceptance records
  outside those copied build packages were preserved.

Two stale tests still expected the retired Services UI and backup downloads on
the MCP installation page. They now verify the Services redirect and the dedicated
MCP test/backup page, keeping download protection checks intact.

Verification: all 178 frontend tests, 72 focused backend/package tests, native
production build/typecheck and accessibility source guards pass. Python reports
no broken dependency requirements. All 14 live application/monitoring services
remain active and the API health check succeeds; no live deployment or restart
was performed.

The backend audit covered 376 modules. Apparent orphans were documented public
helpers or sample-generation CLIs, not abandoned code. All declared backend
runtime dependencies have actual imports, CLI usage or documented optional
adapter consumers. This is a conservative reference audit, not a proof that
every function/branch is reachable.

Detailed removal paths and checks are in
the cleanup receipt (private development evidence; not distributed).

## Retention rules

- Keep source, tests, migrations, design docs, acceptance receipts and protected
  configuration. Do not delete migrations merely because the database is current.
- Generated wheels, standalone frontend copies and release archives are
  rebuildable output, not source. New ignore rules keep them out of future commits.
- Once a release is safely staged and verified, remove its temporary duplicate
  build inputs; preserve the small verification receipt. Build output must not
  accumulate once per iteration indefinitely.
- `/opt/icheck` releases and `/var/backups` remain untouched by repository cleanup.
  Removing retained deployed versions requires a separate explicit retention
  decision. The installed r19.24 release is unchanged.
- Git's roughly 3 GiB of objects is history, not confirmed garbage. No reset,
  history rewrite, object pruning or reflog expiration was performed.
- Do not manually delete transitive or platform-specific packages solely because
  application code does not import them. In particular React DOM, native compiler
  bindings and locked WASM fallback packages are not abandoned product features.
- The Sites/Vite/Wrangler build path still has executable callers. Removing that
  supported build target is a product/build-system change, not automatic dead-code
  cleanup. The empty optional D1 example did not have a product caller.

Disposable database directories and account-wide browser/package caches were
not removed: this task did not establish that all of those are abandoned.
