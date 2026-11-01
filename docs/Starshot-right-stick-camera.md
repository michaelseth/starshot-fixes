# Starshot right-stick camera patch

Installed October 31, 2026 in F:/SteamLibrary/steamapps/common/Starshot/.

Launch normally, including through Steam. The Xbox controller's right stick controls the camera without Select. The left stick retains normal movement. The horizontal right-stick direction is inverted as requested. Left trigger zooms out and right trigger zooms in without Select. Clicking the right stick resets the camera. Start acts as Escape to open the pause menu or go back in menus. Existing Select + A/B zoom and the original camera controls remain available.

The user confirmed the original right-stick camera works in-game. Horizontal inversion and trigger zoom have now been added and passed automated checks; these additions still need in-game confirmation. The first connected XInput controller is used. Disconnected controllers are retried once per second. Camera input is suppressed while another application has focus.

## Adjustments

Close the game and edit StarshotCamera.ini in the game folder:

- SensitivityPercent=100: default analog range. Values 1�300 supported.
- DeadZone=8689: prevents typical stick drift. Values 0�30000 supported.
- InvertY=0: change to 1 to reverse vertical camera movement.
- InvertX=1: reverses horizontal right-stick movement; set to 0 for the previous direction.
- TriggerZoom=1: left trigger zooms out, right trigger zooms in. Set to 0 to disable.
- RightStickReset=1: enables camera reset on right-stick click.
- StartMenu=1: maps Start to native Escape/pause and menu-cancel input.
- TriggerThreshold=30: pressure must exceed 30 out of 255. Both triggers together cancel the added zoom.

Restart to apply adjustments. The in-game settings screen still describes the original controls.

## Restore the previous executable

Close Starshot. Copy SpaceCircus.exe.before-right-stick-20261031.bak over SpaceCircus.exe in the game folder. Keep the backup itself. StarshotCamera.dll and StarshotCamera.ini are then unused and can remain in the folder. This restores the prior FPS, 2.5x distance and widescreen setup; it does not restore the unmodified original game.

## Technical validation

The original input pipeline runs first. An added import loads StarshotCamera.dll; a small hook calls CameraApply after the existing input function at 409ef0. The helper uses XInput and modifies only camera axes at input+98 and input+94, plus the camera-active bit at input+1ce, mirroring the native independent POV camera path. It does not synthesize Select or change the movement axes, zoom flags, or action-button states.

Checks passed for neutral input, dead zone, signed full deflection, vertical inversion, clamping, focus loss, and disconnect handling. A 32-bit Windows process loaded the DLL and resolved CameraApply. Emulation verified the hook preserves integer registers, stack, flags, x87 control word and an active floating-point stack. The added import and IAT relocation were verified, including a rebased image.

Executable SHA256: 0fa3d280c70772a4ace8bfec371670892ebdf411b1972815bb2edebccc29e01c

Camera DLL SHA256: See the latest installed DLL checksum in Starshot-investigation.md.

The first camera-only DLL and settings are retained as StarshotCamera.dll.before-trigger-zoom-20261031.bak and StarshotCamera.ini.before-trigger-zoom-20261031.bak. Restore those two files to undo only inversion/trigger additions.

Right-stick reset and Start-menu mappings passed synthetic input tests (press, hold, release and re-press, focus loss, unplugging, and physical Escape preservation). In-game confirmation of these two mappings is pending. Restore StarshotCamera.dll.before-reset-start-20261031.bak and StarshotCamera.ini.before-reset-start-20261031.bak to undo only these two additions.
