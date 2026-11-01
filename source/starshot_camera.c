#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <xinput.h>

typedef DWORD (WINAPI *GetStateFn)(DWORD, XINPUT_STATE *);
static GetStateFn get_state;
static int initialized;
static DWORD retry_time;
static int selected = -1;
static float sensitivity = 1.0f;
static int deadzone = 8689;
static int invert_y;
static int invert_x;
static int trigger_zoom = 1;
static int trigger_threshold = 30;
static int right_stick_reset = 1;
static int start_menu = 1;
static WORD previous_buttons;
static int synthetic_escape;
static HMODULE self_module;

static void initialize(void) {
    const char *names[] = {"xinput1_4.dll", "xinput1_3.dll", "xinput9_1_0.dll"};
    char path[MAX_PATH], value[64];
    DWORD len = GetModuleFileNameA(self_module, path, MAX_PATH);
    if (len && len < MAX_PATH) {
        while (len && path[len-1] != '\\' && path[len-1] != '/') --len;
        lstrcpyA(path + len, "StarshotCamera.ini");
        deadzone = GetPrivateProfileIntA("Camera", "DeadZone", 8689, path);
        if (deadzone < 0 || deadzone > 30000) deadzone = 8689;
        invert_y = GetPrivateProfileIntA("Camera", "InvertY", 0, path) != 0;
        invert_x = GetPrivateProfileIntA("Camera", "InvertX", 0, path) != 0;
        trigger_zoom = GetPrivateProfileIntA("Camera", "TriggerZoom", 1, path) != 0;
        trigger_threshold = GetPrivateProfileIntA("Camera", "TriggerThreshold", 30, path);
        if (trigger_threshold < 0 || trigger_threshold > 254) trigger_threshold = 30;
        right_stick_reset = GetPrivateProfileIntA("Camera", "RightStickReset", 1, path) != 0;
        start_menu = GetPrivateProfileIntA("Camera", "StartMenu", 1, path) != 0;
        GetPrivateProfileStringA("Camera", "SensitivityPercent", "100", value, sizeof(value), path);
        int speed = 0;
        for (int i=0; value[i]>='0' && value[i]<='9' && i<5; ++i) speed = speed*10 + value[i]-'0';
        if (speed >= 1 && speed <= 300) sensitivity = speed * 0.01f;
    }
    for (int i=0; i<3 && !get_state; ++i) {
        HMODULE library = LoadLibraryA(names[i]);
        if (library) get_state = (GetStateFn)GetProcAddress(library, "XInputGetState");
    }
    initialized = 1;
}

static float axis_value(SHORT raw) {
    int magnitude = raw < 0 ? -(int)raw : (int)raw;
    if (magnitude <= deadzone) return 0.0f;
    float value = (magnitude - deadzone) / (float)(32767 - deadzone);
    if (value > 1.0f) value = 1.0f;
    return raw < 0 ? -value : value;
}

static float clamp(float value) {
    return value < -1.0f ? -1.0f : (value > 1.0f ? 1.0f : value);
}

static void release_escape(unsigned char *input) {
    if (synthetic_escape && input && !(GetAsyncKeyState(VK_ESCAPE) & 0x8000)) {
        input[0xa1] &= (unsigned char)~3;
        if (!(input[0x1b9] & 1)) input[0x1cd] &= (unsigned char)~3;
    }
    synthetic_escape = 0;
}

// Called after the original input pipeline. Mirror the existing independent
// POV camera path: axes 0x98/0x94 plus camera-active flag 0x1ce.
__declspec(dllexport) void __cdecl CameraApply(unsigned char *input) {
    XINPUT_STATE state;
    if (!initialized) initialize();
    if (!get_state || !input) return;
    if (selected >= 0) {
        if (get_state((DWORD)selected, &state) != ERROR_SUCCESS) {
            release_escape(input);
            previous_buttons = 0;
            selected = -1;
            retry_time = GetTickCount() + 1000;
            return;
        }
    } else {
        DWORD now = GetTickCount();
        if (retry_time && (LONG)(now-retry_time) < 0) return;
        for (int i=0; i<4; ++i) {
            if (get_state((DWORD)i, &state) == ERROR_SUCCESS) { selected=i; break; }
        }
        if (selected < 0) { retry_time=now+1000; return; }
    }
    // Windows may continue polling after Alt+Tab; avoid camera input while unfocused.
    DWORD foreground_pid=0;
    HWND foreground=GetForegroundWindow();
    if (!foreground || !GetWindowThreadProcessId(foreground, &foreground_pid) || foreground_pid != GetCurrentProcessId()) {
        release_escape(input);
        previous_buttons = state.Gamepad.wButtons;
        return;
    }
    WORD pressed = state.Gamepad.wButtons & (WORD)~previous_buttons;
    previous_buttons = state.Gamepad.wButtons;
    if (start_menu && (pressed & XINPUT_GAMEPAD_START)) {
        // Native Escape key and menu-cancel action, with one edge per press.
        input[0xa1] = (input[0xa1] & (unsigned char)~3) | 1;
        input[0x1cd] = (input[0x1cd] & (unsigned char)~3) | 1;
        synthetic_escape = 1;
    } else if (!(state.Gamepad.wButtons & XINPUT_GAMEPAD_START) || !start_menu) {
        release_escape(input);
    }
    if (right_stick_reset && (pressed & XINPUT_GAMEPAD_RIGHT_THUMB)) {
        input[0x1d1] = (input[0x1d1] & (unsigned char)~3) | 1;
        input[0x1ce] |= 1;
    }
    float x = axis_value(state.Gamepad.sThumbRX) * sensitivity * (invert_x ? -1.0f : 1.0f);
    float y = axis_value(state.Gamepad.sThumbRY) * sensitivity * (invert_y ? 1.0f : -1.0f);
    if (x != 0.0f) *(float *)(input+0x98) = clamp(*(float *)(input+0x98) + x);
    if (y != 0.0f) *(float *)(input+0x94) = clamp(*(float *)(input+0x94) + y);
    if (x != 0.0f || y != 0.0f) input[0x1ce] |= 1;
    if (trigger_zoom) {
        int zoom_in = state.Gamepad.bRightTrigger > trigger_threshold;
        int zoom_out = state.Gamepad.bLeftTrigger > trigger_threshold;
        // Preserve original Select+A/B. Opposing triggers cancel each other.
        if (zoom_in != zoom_out) {
            input[zoom_in ? 0x1cf : 0x1d0] |= 1;
            input[0x1ce] |= 1;
        }
    }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) { self_module=instance; DisableThreadLibraryCalls(instance); }
    return TRUE;
}
