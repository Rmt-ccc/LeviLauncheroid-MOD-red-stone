# RedstoneTweaksMod (LeviLaunchroid native mod)

A work-in-progress LeviLaunchroid native mod that ports the parts of
**Redstone Tweaks** (a Java Edition resource pack by RexxStone, v2.5.5) that
can't be done with a plain Bedrock resource pack or add-on — things like
rendering a redstone wire's signal strength in-world.

## Current status

This is built on top of LiteLDev/LeviLaunchroid's official
`examples/full-cpp-mod` (a working, verified example), trimmed down to a
minimal module.

- `manifest.json` — mod name/entry renamed for RedstoneTweaksMod
- `src/RedstoneTweaksMod.cpp` — minimal module that only registers itself in
  the Mod Menu as "Redstone Tweaks Info" (the demo HUD buttons from the
  official sample were removed)
- `src/RedstoneTweaksConfig.hpp` — minimal config (just an `enabled` toggle)
- `src/GenerateConfig.cpp` — generates `config.json` / `config.schema.json`,
  same mechanism as the official sample
- `CMakeLists.txt` / `build.ps1` — copied from the official sample, with the
  `preloader-android` dependency path adjusted (see below)

### What was changed from the official sample

The official sample assumes it's nested inside the LeviLaunchroid repo itself,
and locates `preloader-android` (the repo that implements `pl::Mod.hpp` etc.)
via `../../app/src/main/cpp/preloader`. Since this is a standalone repo,
`preloader-android` is fetched separately instead (see the CI workflow).

## Tablet-first workflow

No local NDK/CMake build is required — GitHub Actions does the build in the
cloud. On the device, all you need to do is push files to the GitHub repo:

1. Create a new GitHub repository
2. Upload this project's files (`.github`, `src`, `manifest.json`,
   `CMakeLists.txt`, `build.ps1`, `README.md`) via GitHub's web UI
   ("Add file → Upload files")
3. Commit — `.github/workflows/build.yml` starts automatically
   - The workflow checks out `LiteLDev/preloader-android` itself as a second
     step, so **no local git submodule setup is needed**
4. Once the build finishes, download `RedstoneTweaksMod.levipack` from the
   Actions run (or from a GitHub Release if you push a tag like `v0.0.1`)

`build.ps1` is kept around for anyone who wants to build locally on a PC
later; it's not needed for the tablet-only workflow above.

## Not implemented yet

Reading world block state (e.g. a `redstone_wire` block's signal strength)
and rendering it isn't implemented. The official sample has no such
functionality to begin with — this will require exploring
`preloader-android`'s Hook API, and likely reverse-engineering new
offsets/signatures for the target Minecraft build (e.g. with Ghidra) since
nothing like this currently exists in the public LeviLaunchroid mod
ecosystem.
