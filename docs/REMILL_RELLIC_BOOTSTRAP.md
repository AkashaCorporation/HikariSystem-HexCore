# Remill + Rellic Bootstrap Plan

> Date: 2026-02-11  
> Scope: Prepare HexCore Akasha for native decompilation engines without destabilizing stable release workflow.

## Goal
- Integrate `hexcore-remill` and `hexcore-rellic` as standalone native modules.
- Keep main installer pipeline stable.
- Enable experimental engine builds via dedicated workflow toggle.

## Repository Contract (Standalone Engines)

### 1. `hexcore-remill`
- Repo: `LXrdKnowkill/hexcore-remill`
- Required scripts:
  - `npm run build`
  - `npm run prebuild`
- Required package fields:
  - `"name": "hexcore-remill"`
  - `"version": "x.y.z"`
  - `"binary.napi_versions": [8]` (or chosen N-API target)
- Required output:
  - `prebuilds/` directory
  - release asset name: `hexcore-remill-v<version>-napi-v<napi>-win32-x64.tar.gz`

### 2. `hexcore-rellic`
- Repo: `LXrdKnowkill/hexcore-rellic`
- Required scripts:
  - `npm run build`
  - `npm run prebuild`
- Required package fields:
  - `"name": "hexcore-rellic"`
  - `"version": "x.y.z"`
  - `"binary.napi_versions": [8]` (or chosen N-API target)
- Required output:
  - `prebuilds/` directory
  - release asset name: `hexcore-rellic-v<version>-napi-v<napi>-win32-x64.tar.gz`

## Integration Contract (Main Repo)
- Do not wire these engines into installer path until prebuild assets are consistently published.
- Keep experimental workflows opt-in.
- Validate that adding new engines does not alter existing `capstone/unicorn/llvm-mc` prebuild behavior.

## CI Strategy
- `hexcore-native-prebuilds.yml` keeps stable engines always on.
- Experimental job for `remill/rellic` only runs when dispatch input enables it.
- This prevents accidental red runs while repos are still being stabilized.

## Acceptance Checklist
- [ ] `hexcore-remill` release contains valid Windows prebuild asset.
- [ ] `hexcore-rellic` release contains valid Windows prebuild asset.
- [ ] Experimental prebuild workflow passes for both engines.
- [ ] Main prebuild workflow still passes for stable engines.
- [ ] No regression in installer workflow due to new engine metadata/dependencies.
