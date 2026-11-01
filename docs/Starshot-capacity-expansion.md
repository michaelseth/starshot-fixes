> Current experiment:7x object activation,40% beyond5x, retaining512 capacity and gentle fog150-480. Restore SpaceCircus.exe.capacity512-5x-before-7x-20261031.bak as SpaceCircus.exe to return to the working5x build. Current executable SHA256 aec39726e2eae0bd76478262efb584dc751cc9f72ad17d1ede3ccc4aea7e5a49. Initial100-second7x monitoring passed: peak402/512 entities,306/512 renderer entries, steady timing75.3 updates/second, no observed crash or new game fault. Wider gameplay remains unverified. Older stages below describe prior builds.

> Current renderer experiment: gentle fog150-480, previously100-360, with the renderer far plane extended to480 in the typical scene. 5x character activation and512 capacity remain. Restore glide.i3D.capacity512-fog360-before-fog480-20261031.bak as glide.i3D to undo only this fog/far-distance change. Renderer SHA256 eaa8bd6995a7c64062281061e4e3c59d101d18c70a4d911c5c3d18d8e3cc320a. Visual/live testing is pending.

> Current experiment: 5x activation, approximately43% beyond3.5x, retaining512-entry storage. Restore SpaceCircus.exe.capacity512-3_5x-before-5x-20261031.bak as SpaceCircus.exe to return to the working3.5x build. Current SHA256: 454935c521f925a4cf58cd6a87cc22a1afee11684efbdcd72b295e6edc0f0b49. Initial100-second5x monitoring passed: peak278 entities, renderer184, steady gameplay timing75.3 updates/second, no observed crash or new game fault. Wider gameplay remains unverified. Older stages below describe prior builds.

> Current experiment: 3.5x activation, about17% beyond3x, retaining512-entry storage. The user reported3x remained stable through an area remembered as crashing before. Restore SpaceCircus.exe.capacity512-3x-before-3_5x-20261031.bak as SpaceCircus.exe to return to that3x build. Current SHA256: c7dc270920f84427da7ff3c07934f6031ec6173887f8e441a3558655aea5692f. Initial100-second3.5x test passed, reaching200 entities at approximately75.3 updates/second with no observed crash. Wider testing remains necessary. Older test stages are recorded below.

> Current experiment: 3x activation is installed with the 512-entry capacity expansion. The 2.5x capacity build is retained as SpaceCircus.exe.capacity512-2_5x-before-3x-20261031.bak. Restore that executable to return to 2.5x while keeping expanded storage and the controller mappings. Current executable SHA256: e8c603861860728d3b389b58958a66c899cfdc59183b3c5c0d126b44ce46747e. Initial live 3x monitoring passed100 seconds, reaching195 active entities with approximately75.3 updates/second and no observed crash. Broader gameplay remains unverified.

# Starshot capacity expansion — test build

The installed test build expands the active entity list from 150 to 512 entries. The renderer's separate queue is also expanded to 512, and both sorting buffers are expanded to 2048 records. Object activation remains at 2.5x while the capacity change is tested separately.

All prior camera/controller features, FPS fix, widescreen, gentle distant fog and windowed configuration are retained. The game remains 32-bit; these fixed arrays were the immediate limitation, not the address-space width.

## Changes

The main game object now allocates 0x18000 bytes instead of 0x177c4 and zeroes that complete allocation. A new 512-pointer array starts at object+0x17800. The original count remains at +0x1c. Seven array-address calculation sites and the update loop's list-relative count read are redirected. Existing structure fields retain their addresses.

The Glide renderer's context now allocates 0xc00 bytes instead of 0x328. Its queue moves to context+0x400. Producer and reader use the relocated queue. The original inclusive bound allowed an entry at index 150 to overlap field +0x294; the new bound accepts indices 0–511 and rejects 512. Both dynamic sorting buffers are increased to 2048 records.

The patch adds small code sections and preserves original imports and base relocations, including the controller DLL import. No allocation-failure null check was removed or bypassed; objects are actually allocated and tracked in larger storage.

## Verification

Emulated execution passed: 512 entity allocations, rejecting the 513th, removing entity 173 and compacting the new list, allocating again after removal, all redirected list readers, the separate update count read, 512 renderer insertions, overflow rejection, preserved neighboring fields, and PE relocation parsing/rebasing. These checks do not establish whole-game stability. Live walking reached 203 active entities without a crash in the observed run (406 samples above 150 during a 30-second window). Game timing remained 75.3 updates per second. Wider gameplay and level-change testing remain necessary.

## Rollback

Close Starshot. In F:/SteamLibrary/steamapps/common/Starshot/, copy SpaceCircus.exe.before-capacity512-20261031.bak over SpaceCircus.exe and glide.i3D.before-capacity512-20261031.bak over glide.i3D. Keep the backup files. These restore the previous 2.5x build and renderer while leaving your controller mappings intact.

Additional snapshot copies of StarshotCamera.dll, StarshotCamera.ini and dgVoodoo.conf were saved with the same .before-capacity512-20261031.bak suffix; they were not changed by this test.

Executable SHA256: 09dc9b6e92653f6e45ef5aec879c61ddc99d10115786d98e824db0ce25b68328

Renderer SHA256: 5ebecc77fd32d822f4c704b259847421478bedae7010328eb267c86b63de733a
