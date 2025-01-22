#define _CRT_SECURE_NO_WARNINGS

#include "dma.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "vmmdll.h"
#include "leechcore.h"
#include "stdbool.h"
#include <inttypes.h>


#define VMMDLL_PID_PHYSICAL_MEMORY ((DWORD)-1)
unsigned char abort2[4] = { 0x10, 0x00, 0x10, 0x00 };
#define PRINT(format, ...) printf(format, ##__VA_ARGS__)

DMAContext* Construct() {
    DMAContext* ctx = (DMAContext*)malloc(sizeof(DMAContext));
    if (!ctx) {
        return NULL;
    }

    memset(ctx, 0, sizeof(DMAContext));

    PRINT("Attempting to load required libraries...\n");
    ctx->modules.VMM = LoadLibraryA("vmm.dll");
    ctx->modules.FTD3XX = LoadLibraryA("FTD3XX.dll");
    ctx->modules.LEECHCORE = LoadLibraryA("leechcore.dll");

    if (!ctx->modules.VMM || !ctx->modules.FTD3XX || !ctx->modules.LEECHCORE) {
        PRINT("vmm: %p\n", ctx->modules.VMM);
        PRINT("ftd: %p\n", ctx->modules.FTD3XX);
        PRINT("leech: %p\n", ctx->modules.LEECHCORE);
        free(ctx);
        return NULL;
    }

    PRINT("All required libraries loaded successfully!\n");

    return ctx;
}

void Release(DMAContext* memory) {
    if (memory) {
        if (memory->vHandle) {
            VMMDLL_Close(memory->vHandle);
        }
        FreeLibrary(memory->modules.VMM);
        FreeLibrary(memory->modules.FTD3XX);
        FreeLibrary(memory->modules.LEECHCORE);
        free(memory);
    }
}

bool DumpMemoryMap(DMAContext* memory, bool debug) {
    LPSTR args[] = { "", "-device", "fpga://algo=0", "", "", "", "" };

    int argc = 3;
    if (debug) {
        args[argc++] = "-v";
        args[argc++] = "-printf";
    }

    VMM_HANDLE handle = VMMDLL_Initialize(argc, args);
    if (!handle) {
        PRINT("[!] Failed to open a VMM Handle\n");
        return false;
    }

    PVMMDLL_MAP_PHYSMEM pPhysMemMap = NULL;
    if (!VMMDLL_Map_GetPhysMem(handle, &pPhysMemMap)) {
        PRINT("[!] Failed to get physical memory map\n");
        VMMDLL_Close(handle);
        return false;
    }

    if (pPhysMemMap->dwVersion != VMMDLL_MAP_PHYSMEM_VERSION) {
        PRINT("[!] Invalid VMM Map Version\n");
        VMMDLL_MemFree(pPhysMemMap);
        VMMDLL_Close(handle);
        return false;
    }

    if (pPhysMemMap->cMap == 0) {
        PRINT("[!] Failed to get physical memory map\n");
        VMMDLL_MemFree(pPhysMemMap);
        VMMDLL_Close(handle);
        return false;
    }

    char temp_path[MAX_PATH];
    DWORD path_len = GetTempPathA(MAX_PATH, temp_path);
    if (path_len == 0 || path_len > MAX_PATH) {
        PRINT("[!] Failed to get temp path\n");
        VMMDLL_MemFree(pPhysMemMap);
        VMMDLL_Close(handle);
        return false;
    }

    char file_path[MAX_PATH];
    snprintf(file_path, sizeof(file_path), "%s\\mmap.txt", temp_path);

    FILE* file = fopen(file_path, "w");
    if (!file) {
        PRINT("[!] Unable to create file for writing\n");
        VMMDLL_MemFree(pPhysMemMap);
        VMMDLL_Close(handle);
        return false;
    }

    for (DWORD i = 0; i < pPhysMemMap->cMap; i++) {
        fprintf(file, "%04x  %llx  -  %llx  ->  %llx\n",
            i,
            pPhysMemMap->pMap[i].pa,
            pPhysMemMap->pMap[i].pa + pPhysMemMap->pMap[i].cb - 1,
            pPhysMemMap->pMap[i].pa);
    }

    fclose(file);
    VMMDLL_MemFree(pPhysMemMap);
    PRINT("Successfully dumped memory map to file!\n");
    Sleep(3000);
    VMMDLL_Close(handle);
    return true;
}

bool InitializeDMAContext(DMAContext* memory, const char* process_name, bool memMap, bool debug) {
    if (!memory || !process_name) return false;

    if (!memory->DMA_INITIALIZED) {
        PRINT("Starting initialization process...\n");

        LPCSTR args[7] = { "", "-device", "fpga://algo=0" };
        DWORD argc = 3;
        char path[MAX_PATH] = "";

        if (debug) {
            args[argc++] = "-v";
            args[argc++] = "-printf";
        }

        if (memMap) {
            GetTempPathA(MAX_PATH, path);
            GetTempFileNameA(path, "mmap", 0, path);
            strcat(path, ".txt");

            if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
                PRINT("Generating memory map file...\n");
                if (!DumpMemoryMap(memory, debug)) {
                    PRINT("Error: Memory map generation unsuccessful. Proceeding without it.\n");
                }
                else {
                    args[argc++] = "-memmap";
                    args[argc++] = "auto";
                    PRINT("Memory map generation complete\n");
                }
            }
        }

        memory->vHandle = VMMDLL_Initialize(argc, args);
        if (!memory->vHandle) {
            if (memMap) {
                PRINT("Initialization with Memory map failed. Retrying without it.\n");
                return InitializeDMAContext(memory, process_name, false, debug);
            }
            PRINT("Error: Initialization failed. Check DMA connection or availability.\n");
            return false;
        }

        ULONG64 FPGA_ID, DEVICE_ID;
        VMMDLL_ConfigGet(memory->vHandle, LC_OPT_FPGA_FPGA_ID, &FPGA_ID);
        VMMDLL_ConfigGet(memory->vHandle, LC_OPT_FPGA_DEVICE_ID, &DEVICE_ID);
        PRINT("FPGA ID: %llu\nDEVICE ID: %llu\nInitialization completed successfully\n", FPGA_ID, DEVICE_ID);

        memory->DMA_INITIALIZED = true;
    }
    else {
        PRINT("DMA already in initialized state\n");
    }

    if (memory->PROCESS_INITIALIZED) {
        PRINT("Process initialization already complete\n");
        return true;
    }

    memory->current_process.PID = GetPidFromName(memory, process_name);
    if (!memory->current_process.PID) {
        PRINT("Error: Unable to retrieve PID for the given process name\n");
        return false;
    }
    strncpy(memory->current_process.process_name, process_name, sizeof(memory->current_process.process_name) - 1);

    memory->current_process.base_address = GetBaseAddress(memory, process_name);
    memory->current_process.base_size = GetBaseSize(memory, process_name);

    if (!memory->current_process.base_address || !memory->current_process.base_size) {
        PRINT("Error: Base address or size retrieval failed\n");
        return false;
    }

    PRINT("Process details for %s\nPID: %i\nBase Address: 0x%p\nBase Size: 0x%p\n",
        process_name, memory->current_process.PID,
        (void*)memory->current_process.base_address, (void*)memory->current_process.base_size);

    memory->PROCESS_INITIALIZED = true;
    return true;
}

DWORD GetPidFromName(DMAContext* memory, const char* process_name) {
    DWORD pid = 0;
    VMMDLL_PidGetFromName(memory->vHandle, process_name, &pid);
    return pid;
}

void GetPidListFromName(DMAContext* memory, const char* name, int** list, int* count) {
    PVMMDLL_PROCESS_INFORMATION process_info = NULL;
    DWORD total_processes = 0;
    *list = NULL;
    *count = 0;

    if (!VMMDLL_ProcessGetInformationAll(memory->vHandle, &process_info, &total_processes)) {
        PRINT("Error: Process list retrieval failed\n");
        return;
    }
    *list = (int*)calloc(total_processes, sizeof(int));
    if (!*list) {
        PRINT("Error: Memory allocation for process list failed\n");
        goto cleanup;
    }
    for (DWORD i = 0; i < total_processes; i++) {
        if (strstr(process_info[i].szNameLong, name)) {
            (*list)[(*count)++] = process_info[i].dwPID;
        }
    }
    if (*count == 0) {
        free(*list);
        *list = NULL;
    }
cleanup:
    VMMDLL_MemFree(process_info);
}

void GetModuleList(DMAContext* memory, const char* process_name, char*** list, int* count) {
    PVMMDLL_MAP_MODULE module_info;
    *list = NULL;
    *count = 0;

    if (!VMMDLL_Map_GetModuleU(memory->vHandle, memory->current_process.PID, &module_info, VMMDLL_MODULE_FLAG_NORMAL)) {
        PRINT("Error: Module list retrieval failed\n");
        return;
    }

    *list = (char**)malloc(module_info->cMap * sizeof(char*));
    if (!*list) {
        PRINT("Error: Memory allocation for module list failed\n");
        VMMDLL_MemFree(module_info);
        return;
    }

    for (size_t i = 0; i < module_info->cMap; i++) {
        (*list)[i] = _strdup(module_info->pMap[i].uszText);
        (*count)++;
    }

    VMMDLL_MemFree(module_info);
}

size_t GetBaseAddress(DMAContext* memory, const char* module_name) {
    PVMMDLL_MAP_MODULEENTRY module_info;
    if (!VMMDLL_Map_GetModuleFromNameU(memory->vHandle, memory->current_process.PID, module_name, &module_info, VMMDLL_MODULE_FLAG_NORMAL)) {
        PRINT("Error: Base Address for %s not found\n", module_name);
        return 0;
    }

    PRINT("Base Address for %s located at 0x%p\n", module_name, (void*)module_info->vaBase);
    return module_info->vaBase;
}

size_t GetBaseSize(DMAContext* memory, const char* module_name) {
    PVMMDLL_MAP_MODULEENTRY module_info;
    if (!VMMDLL_Map_GetModuleFromNameU(memory->vHandle, memory->current_process.PID, module_name, &module_info, VMMDLL_MODULE_FLAG_NORMAL)) {
        PRINT("Error: Base Size for %s not found\n", module_name);
        return 0;
    }

    PRINT("Base Size for %s is 0x%p\n", module_name, (void*)module_info->cbImageSize);
    return module_info->cbImageSize;
}

static uint8_t GetByte(const char* hex) {
    unsigned int value;
    sscanf(hex, "%2x", &value);
    return (uint8_t)value;
}

static uint8_t HexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

uint64_t FindSignature(DMAContext* memory, const char* signature, uint64_t range_start, uint64_t range_end, int PID)
{
    if (!signature || signature[0] == '\0')
        return 0;

    PID = (PID == 0) ? memory->current_process.PID : PID;

    uint8_t sig_bytes[256];
    bool sig_mask[256];
    size_t sig_length = 0;

    const char* ptr = signature;
    while (*ptr && sig_length < 256)
    {
        if (*ptr == ' ' || *ptr == '\t')
        {
            ptr++;
            continue;
        }
        if (*ptr == '?' || *ptr == 'x' || *ptr == 'X')
        {
            sig_bytes[sig_length] = 0;
            sig_mask[sig_length] = false;
            sig_length++;
            ptr++;
        }
        else if (isxdigit(ptr[0]) && isxdigit(ptr[1]))
        {
            sig_bytes[sig_length] = (HexCharToByte(ptr[0]) << 4) | HexCharToByte(ptr[1]);
            sig_mask[sig_length] = true;
            sig_length++;
            ptr += 2;
        }
        else
        {
            ptr++;
        }
    }

    PVMMDLL_MAP_VAD pVadMap = NULL;
    if (!VMMDLL_Map_GetVadU(memory->vHandle, PID, TRUE, &pVadMap)) {
        PRINT("Error: Failed to get VAD map\n");
        return 0;
    }

    const size_t chunk_size = 0x1000;
    uint8_t* buffer = (uint8_t*)malloc(chunk_size);
    if (!buffer)
    {
        PRINT("Error: Memory allocation for buffer failed\n");
        VMMDLL_MemFree(pVadMap);
        return 0;
    }

    uint64_t result = 0;

    for (DWORD i = 0; i < pVadMap->cMap; i++)
    {
        VMMDLL_MAP_VADENTRY entry = pVadMap->pMap[i];
        if (range_start != 0 && range_end != 0)
        {
            if (entry.vaEnd < range_start || entry.vaStart > range_end)
                continue;
        }
        for (uint64_t address = entry.vaStart; address < entry.vaEnd; address += chunk_size)
        {
            size_t bytes_to_read = (address + chunk_size > entry.vaEnd) ? (entry.vaEnd - address) : chunk_size;
            if (!VMMDLL_MemReadEx(memory->vHandle, PID, address, buffer, bytes_to_read, NULL, VMMDLL_FLAG_NOCACHE))
            {
                continue;
            }
            for (size_t j = 0; j < bytes_to_read - sig_length + 1; j++)
            {
                bool found = true;
                for (size_t k = 0; k < sig_length; k++)
                {
                    if (sig_mask[k] && buffer[j + k] != sig_bytes[k])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    result = address + j;
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    free(buffer);
    VMMDLL_MemFree(pVadMap);
    return result;
}

bool Write(const DMAContext* memory, uintptr_t address, void* buffer, size_t size) {
    if (!(address > 0x2000000 && address < 0x7FFFFFFFFFFF))
        return false;
    if (!VMMDLL_MemWrite(memory->vHandle, memory->current_process.PID, address, (PBYTE)buffer, size)) {
        PRINT("Error: Memory write operation at 0x%p failed\n", (void*)address);
        return false;
    }
    return true;
}

bool Read(const DMAContext* memory, uintptr_t address, void* buffer, size_t size) {
    if (!VMMDLL_MemReadEx(memory->vHandle, memory->current_process.PID, address, (PBYTE)buffer, size, NULL, VMMDLL_FLAG_NOCACHE)) {
        printf("[!] Failed to read Memory at 0x%p\n", (void*)address);
        return false;
    }
    return true;
}

void* ReadMemory(const DMAContext* memory, uintptr_t address, size_t size) {
    void* buffer = malloc(size);
    if (!buffer) {
        printf("[!] Failed to allocate memory for read operation\n");
        return NULL;
    }

    if (!Read(memory, address, buffer, size)) {
        free(buffer);
        return NULL;
    }

    return buffer;
}

uint16_t ReadUInt16(const DMAContext* memory, uintptr_t address) {
    uint16_t value = 0;
    if (!Read(memory, address, &value, sizeof(value))) {
        PRINT("Error: Failed to read UInt16 at address 0x%p\n", (void*)address);
    }
    return value;
}

uint32_t ReadUInt32(const DMAContext* memory, uintptr_t address) {
    uint32_t value = 0;
    Read(memory, address, &value, sizeof(value));
    return value;
}

int32_t ReadInt32(const DMAContext* memory, uintptr_t address) {
    int32_t value = 0;
    Read(memory, address, &value, sizeof(value));
    return value;
}


float ReadFloat(const DMAContext* memory, uintptr_t address) {
    float value = 0.0f;
    Read(memory, address, &value, sizeof(value));
    return value;
}
char* ReadString(const DMAContext* memory, uintptr_t address) {
    uint32_t header;
    if (!Read(memory, address, &header, sizeof(header))) {
        PRINT("Error: Failed to read string header at address 0x%p\n", (void*)address);
        return NULL;
    }

    uint8_t length;
    if (!Read(memory, address + 4, &length, sizeof(length))) {
        PRINT("Error: Failed to read string length at address 0x%p\n", (void*)(address + 4));
        return NULL;
    }

    if (length == 0) {
        return _strdup("");
    }

    size_t bufferSize = (length * 2) + 2;
    wchar_t* wideBuffer = (wchar_t*)malloc(bufferSize);
    if (!wideBuffer) {
        PRINT("Error: Failed to allocate memory for wide string buffer\n");
        return NULL;
    }

    if (!Read(memory, address + 8, wideBuffer, length * 2)) {
        PRINT("Error: Failed to read string content at address 0x%p\n", (void*)(address + 8));
        free(wideBuffer);
        return NULL;
    }

    wideBuffer[length] = L'\0';

    int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wideBuffer, -1, NULL, 0, NULL, NULL);
    if (utf8Length == 0) {
        PRINT("Error: Failed to determine UTF-8 string length\n");
        free(wideBuffer);
        return NULL;
    }

    char* utf8String = (char*)malloc(utf8Length);
    if (!utf8String) {
        PRINT("Error: Failed to allocate memory for UTF-8 string\n");
        free(wideBuffer);
        return NULL;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, wideBuffer, -1, utf8String, utf8Length, NULL, NULL) == 0) {
        PRINT("Error: Failed to convert UTF-16 to UTF-8\n");
        free(wideBuffer);
        free(utf8String);
        return NULL;
    }

    free(wideBuffer);
    return utf8String;
}



VMMDLL_SCATTER_HANDLE CreateScatterHandle(DMAContext* memory) {
    VMMDLL_SCATTER_HANDLE ScatterHandle = VMMDLL_Scatter_Initialize(memory->vHandle, memory->current_process.PID, VMMDLL_FLAG_NOCACHE);
    if (!ScatterHandle)
        PRINT("Error: Scatter handle creation failed\n");
    return ScatterHandle;
}

VMMDLL_SCATTER_HANDLE CreateScatterHandleForPid(DMAContext* memory, int pid) {
    VMMDLL_SCATTER_HANDLE ScatterHandle = VMMDLL_Scatter_Initialize(memory->vHandle, pid, VMMDLL_FLAG_NOCACHE);
    if (!ScatterHandle)
        PRINT("Error: Scatter handle creation for PID failed\n");
    return ScatterHandle;
}

//Base               int64 sig:F8 01 74 04 83 65
//Beatmap            uint32  [Base - 0xC]
//MapID              uint32   [Beatmap] + 0xC8 
//AR                 float32 [Beatmap] + 0x2C
//CS                 float32 [Beatmap] + 0x30
//HP                 float32 [Beatmap] + 0x34
//OD                 float32 [Beatmap] + 0x38
//MenuGameMode       int32   [Base - 0x33]
//Artist             string  [[Beatmap] + 0x18]
//Title              string  [[Beatmap] + 0x24]
//AudioFilename      string  [[Beatmap] + 0x64]

typedef struct {
    uint32_t mapID;
    float ar;
    float cs;
    float hp;
    float od;
    int32_t menuGameMode;
    char* artist;
    char* title;
    char* audioFilename;
} Beatmap;

void UpdateBeatmapInfo(const DMAContext* memory, uint64_t baseAddress, uint32_t beatmapAddress, Beatmap* beatmap) {
    beatmap->mapID = ReadUInt32(memory, beatmapAddress + 0xC8);
    beatmap->ar = ReadFloat(memory, beatmapAddress + 0x2C);
    beatmap->cs = ReadFloat(memory, beatmapAddress + 0x30);
    beatmap->hp = ReadFloat(memory, beatmapAddress + 0x34);
    beatmap->od = ReadFloat(memory, beatmapAddress + 0x38);

    beatmap->menuGameMode = ReadInt32(memory, baseAddress - 0x33);

    uint32_t artistPtr = ReadUInt32(memory, beatmapAddress + 0x18);
    beatmap->artist = ReadString(memory, artistPtr);

    uint32_t titlePtr = ReadUInt32(memory, beatmapAddress + 0x24);
    beatmap->title = ReadString(memory, titlePtr + 0x7);

    uint32_t audioFilenamePtr = ReadUInt32(memory, beatmapAddress + 0x64);
    beatmap->audioFilename = ReadString(memory, audioFilenamePtr);
}

//Rulesets            int64 sig:7D 15 A1 ? ? ? ? 85 C0
//Ruleset             uint32 [[Rulesets - 0xB]+ 0x4]
//PlayerName          uint32 [[[Ruleset + 0x68] + 0x38] + 0x28]
//ModsXor1            uint32  [[[Ruleset + 0x68] + 0x38] + 0x1C] + 0xC
//ModsXor2            uint32  [[[Ruleset + 0x68] + 0x38] + 0x1C] + 0x8
//Combo               uint16  [[Ruleset + 0x68] + 0x38] + 0x9
typedef struct {
    char* playerName;
    uint32_t modsXor1;
    uint32_t modsXor2;
    uint16_t combo;
} RulesetInfo;

void UpdateRulesetInfo(const DMAContext* memory, uint32_t rulesetsAddress, RulesetInfo* rulesetInfo) {
    uint32_t rulesetPtr = ReadUInt32(memory, rulesetsAddress - 0xB);
    uint32_t rulesetAddress = ReadUInt32(memory, rulesetPtr + 0x4);

    uint32_t pointer1 = ReadUInt32(memory, rulesetAddress + 0x68);
    uint32_t pointer2 = ReadUInt32(memory, pointer1 + 0x38);

    uint32_t playerNamePtr = ReadUInt32(memory, pointer2 + 0x28);
    rulesetInfo->playerName = ReadString(memory, playerNamePtr);

    uint32_t modsPtr = ReadUInt32(memory, pointer2 + 0x1C);
    rulesetInfo->modsXor1 = ReadUInt32(memory, modsPtr + 0xC);
    rulesetInfo->modsXor2 = ReadUInt32(memory, modsPtr + 0x8);

    rulesetInfo->combo = ReadUInt16(memory, pointer2 + 0x94);
}

int main(int argc, char* argv[]) {
    DMAContext* memory = Construct();
    if (!memory) {
        PRINT("Error: Memory object creation failed\n");
        return 1;
    }

    const char* processName = "osu!.exe";
    if (!InitializeDMAContext(memory, processName, true, false)) {
        PRINT("Error: Memory initialization for process %s failed\n", processName);
        Release(memory);
        return 1;
    }

    uint64_t playTimeSignature = FindSignature(memory, "5E 5F 5D C3 A1 ? ? ? ? 89 ? 04", 0, 0, 0);
    if (playTimeSignature == 0) {
        PRINT("Error: Play Time signature not found\n");
        Release(memory);
        return 1;
    }
    PRINT("Play Time signature found at: 0x%" PRIx64 "\n", playTimeSignature);

    uint32_t playTimeAddress = ReadUInt32(memory, playTimeSignature + 5);
    PRINT("Play Time address: 0x%X\n", playTimeAddress);

    uint64_t baseAddress = FindSignature(memory, "F8 01 74 04 83 65", 0, 0, 0);
    if (baseAddress == 0) {
        PRINT("Error: Beatmap signature not found\n");
        Release(memory);
        return 1;
    }
    PRINT("Beatmap signature found at: 0x%" PRIx64 "\n", baseAddress);

    uint32_t beatmapAddress = ReadUInt32(memory, baseAddress - 0xC);
    PRINT("Beatmap address: 0x%X\n", beatmapAddress);

    uint64_t rulesetsAddress = FindSignature(memory, "7D 15 A1 ? ? ? ? 85 C0", 0, 0, 0);
    if (rulesetsAddress == 0) {
        PRINT("Error: Rulesets signature not found\n");
        Release(memory);
        return 1;
    }
    PRINT("Rulesets signature found at: 0x%" PRIx64 "\n", rulesetsAddress);

    PRINT("Rulesets address: 0x%X\n", rulesetsAddress);

    Beatmap currentBeatmap;
    RulesetInfo rulesetInfo = { NULL, 0, 0 };

    while (1) {
        system("cls");

        uint32_t actualBeatmapAddress = ReadUInt32(memory, beatmapAddress);
        UpdateBeatmapInfo(memory, baseAddress, actualBeatmapAddress, &currentBeatmap);
        UpdateRulesetInfo(memory, rulesetsAddress, &rulesetInfo);

        uint32_t playTime = ReadUInt32(memory, playTimeAddress);

        PRINT("Audio Filename: %s\n", currentBeatmap.audioFilename ? currentBeatmap.audioFilename : "N/A");
        PRINT("Artist: %s\n", currentBeatmap.artist ? currentBeatmap.artist : "N/A");
        PRINT("Play Time: %d seconds\n", playTime);
        PRINT("MapID: %d\n\n", currentBeatmap.mapID);
        PRINT("AR: %.2f\n", currentBeatmap.ar);
        PRINT("CS: %.2f\n", currentBeatmap.cs);
        PRINT("HP: %.2f\n", currentBeatmap.hp);
        PRINT("OD: %.2f\n", currentBeatmap.od);

        PRINT("Player Name: %s\n", rulesetInfo.playerName ? rulesetInfo.playerName : "N/A");
        PRINT("Mods XOR 1: %d\n", rulesetInfo.modsXor1);
        PRINT("Mods XOR 2: %d\n", rulesetInfo.modsXor2);
        PRINT("Combo: %d\n\n", rulesetInfo.combo);

        PRINT("Menu Game Mode: %d\n", currentBeatmap.menuGameMode);
        PRINT("Title: %s\n", currentBeatmap.title ? currentBeatmap.title : "N/A");

        PRINT("\nPress Ctrl+C to exit...\n");

        Sleep(100);

        // Free the allocated memory for player name
        if (rulesetInfo.playerName) {
            free(rulesetInfo.playerName);
            rulesetInfo.playerName = NULL;
        }

        if (currentBeatmap.artist) {
            free(currentBeatmap.artist);
            currentBeatmap.artist = NULL;
        }
        if (currentBeatmap.title) {
            free(currentBeatmap.title);
            currentBeatmap.title = NULL;
        }
        if (currentBeatmap.audioFilename) {
            free(currentBeatmap.audioFilename);
            currentBeatmap.audioFilename = NULL;
        }
    }

    Release(memory);
    return 0;
}
