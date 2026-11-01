# Starshot fixes

Source and sparse patches preserving the installed October 31, 2026 experimental Windows build. Includes the timer-precision fix, widescreen renderer changes, expanded entity/render storage and distance changes, and independent XInput camera controls. This remains a patched 32-bit game, not a source rebuild.

## Apply

Download the complete preview package from Releases. Close the game. Supply a folder containing the exact supported baseline SpaceCircus.exe and glide.i3D. The installer reads those files and writes patched files to a **new, separate folder**:

```powershell
powershell.exe -NoProfile -File .\Apply-Patch.ps1 -Source 'D:\Games\Starshot-original' -Destination 'C:\Games\Starshot-patched-files'
```

The destination parent must exist. Already patched and unsupported files are rejected before output is created. The original installation is unchanged. Preserve backups of the installed SpaceCircus.exe, glide.i3D, StarshotCamera.dll, and StarshotCamera.ini, then copy the four generated files into the installation. Do not replace your only original copy. Restore those backups to remove the patch. Steam verification or updates may replace patched files.

The snapshot includes a separate optional config/dgVoodoo.conf. It is the existing 1600x900 windowed configuration, not an automatically installed dependency. Obtain dgVoodoo separately if your installation needs it; its binaries are not bundled here.

## Supported baseline and result

| File | Baseline SHA-256 | Result SHA-256 |
| --- | --- | --- |
| SpaceCircus.exe | `e324118295a3f847736a0718ec0ec4c147a72b0049f8c5d9ef6de0d61afdb17f` | `aec39726e2eae0bd76478262efb584dc751cc9f72ad17d1ede3ccc4aea7e5a49` |
| glide.i3D | `374b316b1e621ba49171f68d2a0370c33dbf270a2a9d226aafe649ac37d44fda` | `eaa8bd6995a7c64062281061e4e3c59d101d18c70a4d911c5c3d18d8e3cc320a` |

These baselines are the pre-investigation backup files used by this project. Other editions are not assumed compatible. This package captures the current installed file hashes. Historical notes describe several earlier distance experiments and sometimes disagree about which is current; the manifest is the authoritative binary snapshot. Full-game stability remains unverified.

## Build and maintain

Run `.\Build-Helper.ps1` with LLVM/MinGW clang and 32-bit Windows headers/libraries. It creates build/StarshotCamera.dll and runs camera input tests, including loading the actual 32-bit DLL. A rebuild may differ from the historical DLL hash; update payload hashes intentionally when packaging a new version.

- source/: camera helper and tests.
- patch-manifest.json: sparse byte changes plus input/output and payload hashes.
- Apply-Patch.ps1: standalone, hash-checked patcher; no Python/compiler needed to install a release.
- payload/: default settings. The DLL is in the release, excluded from Git.
- research/: original construction scripts, retained as maintenance context. Some depend on excluded local analysis catalogs and intermediate files; do not run them against a live installation.
- docs/: historical implementation, controls, and rollback notes. Their absolute paths refer to the original investigation environment.

The manifest can recreate both exact patched game binaries from the matching baseline without the research catalogs. It never contains the complete game binaries or assets.

## Controls

Right stick controls the camera; horizontal direction is inverted by default. Triggers zoom, right-stick click resets the camera, and Start maps to Escape/pause. Adjust payload/StarshotCamera.ini before packaging or the installed INI after installation. Some added mappings still need in-game confirmation; see docs/Starshot-right-stick-camera.md.

## Notices

No custom-code license is selected. Game files are player-supplied. No dgVoodoo binaries, ROMs, original game assets, saves, captures, crash dumps, or analysis catalogs are uploaded.
