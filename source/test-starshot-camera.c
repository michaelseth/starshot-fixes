#include <windows.h>
#include <xinput.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
static int focused=1;
static SHORT physical_escape;
static SHORT test_async_key(int key) { return key==VK_ESCAPE ? physical_escape : 0; }
static HWND test_foreground(void) { return focused ? (HWND)1 : 0; }
static DWORD test_window_pid(HWND hwnd, DWORD *pid) { (void)hwnd; *pid=42;return 1; }
static DWORD test_current_pid(void) { return 42; }
#define GetForegroundWindow test_foreground
#define GetWindowThreadProcessId test_window_pid
#define GetCurrentProcessId test_current_pid
#define GetAsyncKeyState test_async_key
#include "starshot_camera.c"
static XINPUT_STATE test_state;
static int disconnected;
static DWORD WINAPI mock_state(DWORD index, XINPUT_STATE *state) {
    (void)index;*state=test_state;return disconnected ? ERROR_DEVICE_NOT_CONNECTED : ERROR_SUCCESS;
}
int main(int argc, char **argv) {
    unsigned char input[0x300], before[0x300];
    initialized=1;get_state=mock_state;selected=0;
    memset(input,0x5a,sizeof input);
    *(float *)(input+0x94)=0.0f;*(float *)(input+0x98)=0.0f;
    memcpy(before,input,sizeof input);
    CameraApply(input);assert(!memcmp(input,before,sizeof input));
    test_state.Gamepad.sThumbRX=8689;test_state.Gamepad.sThumbRY=-8689;
    CameraApply(input);assert(!memcmp(input,before,sizeof input));
    test_state.Gamepad.sThumbRX=32767;test_state.Gamepad.sThumbRY=32767;
    CameraApply(input);assert(*(float *)(input+0x98)==1.0f);assert(*(float *)(input+0x94)==-1.0f);
    assert(input[0x1ce]==(unsigned char)(before[0x1ce]|1));
    // Only camera axes and the native camera-active bit may change.
    memset(input+0x94,0,8);input[0x1ce]=before[0x1ce];assert(!memcmp(input,before,sizeof input));
    invert_y=1;test_state.Gamepad.sThumbRX=-32768;
    CameraApply(input);assert(*(float *)(input+0x98)==-1.0f);assert(*(float *)(input+0x94)==1.0f);
    memset(input+0x94,0,8);invert_x=1;
    CameraApply(input);assert(*(float *)(input+0x98)==1.0f);
    invert_x=0;
    memset(input+0x94,0,8);input[0x1ce]=before[0x1ce];focused=0;CameraApply(input);assert(!memcmp(input,before,sizeof input));
    focused=1;disconnected=1;CameraApply(input);assert(!memcmp(input,before,sizeof input));
    disconnected=0;selected=0;memset(&test_state,0,sizeof test_state);
    memset(input,0,sizeof input);test_state.Gamepad.bRightTrigger=30;
    CameraApply(input);assert(input[0x1cf]==0 && input[0x1d0]==0 && input[0x1ce]==0);
    test_state.Gamepad.bRightTrigger=31;
    CameraApply(input);assert(input[0x1cf]==1 && input[0x1d0]==0 && input[0x1ce]==1);
    memset(input,0,sizeof input);test_state.Gamepad.bRightTrigger=0;test_state.Gamepad.bLeftTrigger=255;
    CameraApply(input);assert(input[0x1d0]==1 && input[0x1cf]==0 && input[0x1ce]==1);
    memset(input,0,sizeof input);test_state.Gamepad.bRightTrigger=255;
    CameraApply(input);assert(input[0x1cf]==0 && input[0x1d0]==0 && input[0x1ce]==0);
    input[0x1cf]=1;CameraApply(input);assert(input[0x1cf]==1);
    memset(input,0,sizeof input);trigger_zoom=0;test_state.Gamepad.bLeftTrigger=0;
    CameraApply(input);assert(input[0x1cf]==0 && input[0x1ce]==0);
    puts("PASS: horizontal inversion, trigger threshold, right/in, left/out, both cancel, original zoom preserved, optional trigger disable");
    memset(input,0,sizeof input);test_state.Gamepad.wButtons=XINPUT_GAMEPAD_RIGHT_THUMB;
    CameraApply(input);assert(input[0x1d1]==1 && input[0x1ce]==1);
    input[0x1d1]=3;CameraApply(input);assert(input[0x1d1]==3); // Held does not re-arm consumed action.
    test_state.Gamepad.wButtons=0;CameraApply(input);
    test_state.Gamepad.wButtons=XINPUT_GAMEPAD_RIGHT_THUMB;CameraApply(input);assert(input[0x1d1]==1);
    memset(input,0,sizeof input);test_state.Gamepad.wButtons=XINPUT_GAMEPAD_START;
    CameraApply(input);assert(input[0xa1]==1 && input[0x1cd]==1);
    input[0xa1]=3;input[0x1cd]=3;CameraApply(input);assert(input[0xa1]==3 && input[0x1cd]==3);
    test_state.Gamepad.wButtons=0;CameraApply(input);assert(input[0xa1]==0 && input[0x1cd]==0);
    test_state.Gamepad.wButtons=XINPUT_GAMEPAD_START;CameraApply(input);assert(input[0xa1]==1);
    physical_escape=(SHORT)0x8000;test_state.Gamepad.wButtons=0;CameraApply(input);assert(input[0xa1]==1);
    physical_escape=0;input[0xa1]=0;test_state.Gamepad.wButtons=XINPUT_GAMEPAD_START;CameraApply(input);
    focused=0;CameraApply(input);assert(input[0xa1]==0);focused=1;
    CameraApply(input);assert(input[0xa1]==0); // Held through focus change does not re-open menu.
    test_state.Gamepad.wButtons=0;CameraApply(input);test_state.Gamepad.wButtons=XINPUT_GAMEPAD_START;CameraApply(input);
    disconnected=1;CameraApply(input);assert(input[0xa1]==0);disconnected=0;selected=0;
    start_menu=0;right_stick_reset=0;previous_buttons=0;memset(input,0,sizeof input);
    test_state.Gamepad.wButtons=XINPUT_GAMEPAD_START|XINPUT_GAMEPAD_RIGHT_THUMB;CameraApply(input);
    assert(input[0xa1]==0 && input[0x1d1]==0);
    puts("PASS: right-stick reset and Start/Escape edges, hold/release/re-press, physical Escape preservation, focus/disconnect cleanup, optional disable");
    puts("PASS: neutral/deadzone, full deflection, inversion, clamping, focus, disconnect, unchanged movement/zoom/buttons");
    HMODULE plugin=LoadLibraryA(argc > 1 ? argv[1] : "StarshotCamera.dll");assert(plugin);
    assert(GetProcAddress(plugin,"CameraApply"));FreeLibrary(plugin);
    puts("PASS: 32-bit Windows DLL loads and CameraApply resolves");
    return 0;
}
