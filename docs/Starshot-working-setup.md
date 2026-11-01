# Starshot current setup

The installed October 31, 2026 test build has these changes:

- Corrected Windows timer precision; observed gameplay around75 FPS and update timing75.3 per second.
- 16:9 camera and high-resolution output; menu text still stretches.
- Gentle distant fog150-480 (new renderer-distance test; previously100-360).
- 7x activation distance (initial100-second live check passed:402 entities /306 renderer entries,75.3 updates per second).
- Actual entity and renderer queue storage expanded to512, with sorting-buffer headroom2048.
- Independent Xbox right-stick camera, inverted horizontal axis, trigger zoom, right-stick click reset, Start pause-menu mapping.
- Windowed mode with dgVoodoo requested resolution1600x900.

The capacity build reached203 active entities in a live walking sample without crashing. Earlier code capped these at150. A later sample showed counts dropping to1-45 while renderer contexts changed; the process remained running and no new fault for that process was found in the checked event log. These observations are encouraging, not whole-game stability certification. The 3x distance setting was subsequently reinstalled at the user's request, retaining expanded capacity.

Launch normally, including through Steam. No special timer argument is required.

See Starshot-capacity-expansion.md for capacity patch details and rollback, and Starshot-right-stick-camera.md for control settings and rollback. The .working-fixes-20261010.bak files describe an older2x/no-fog baseline, not this current setup.

To undo the latest capacity changes, close Starshot and restore SpaceCircus.exe.before-capacity512-20261031.bak as SpaceCircus.exe and glide.i3D.before-capacity512-20261031.bak as glide.i3D. Keep the backup files. Controller settings and helper DLL can remain installed.

To restore the original pre-investigation files, close the game and restore:

| Backup | Destination |
| --- | --- |
| SpaceCircus.exe.before-timer-precision-20261010-163007.bak | SpaceCircus.exe |
| glide.i3D.before-fog-test-20261010-163435.bak | glide.i3D |
| dgVoodoo.conf.before-starshot-test-20261010-155751.bak | dgVoodoo.conf |

The supplied N64 ROM was not modified. pcrecomp assisted analysis; this remains a patched32-bit game, not a source rebuild. Steam file verification or an update may replace patched files.

## Installed checksums (SHA256)

SpaceCircus.exe: aec39726e2eae0bd76478262efb584dc751cc9f72ad17d1ede3ccc4aea7e5a49

glide.i3D: eaa8bd6995a7c64062281061e4e3c59d101d18c70a4d911c5c3d18d8e3cc320a

StarshotCamera.dll: 023f08fa3443f501a9ac7e719e527a2e46bbbaf71be2006f59c1e71d5902afa8

StarshotCamera.ini: 16d9ebcf43968f215f49e411013c07be7aa6952ea32ea6666de4d16603a4ba60

dgVoodoo.conf: ccc677f4be064ede9b592fdd4dcd86e69af1591ab94beb2cac7031f7fb522b55

