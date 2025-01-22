#ifndef MEMORY_H
#define MEMORY_H

#include <windows.h>
#include <stdint.h>
#include "vmmdll.h"
#include <stdbool.h>

// Forward declarations
typedef struct DMAContext DMAContext;
typedef HANDLE VMMDLL_SCATTER_HANDLE;

typedef struct {
    HMODULE VMM;
    HMODULE FTD3XX;
    HMODULE LEECHCORE;
} LibModules;

typedef struct {
    int PID;
    size_t base_address;
    size_t base_size;
    char process_name[256];
} CurrentProcessInformation;

struct DMAContext {
    LibModules modules;
    CurrentProcessInformation current_process;
    bool DMA_INITIALIZED;
    bool PROCESS_INITIALIZED;
    VMM_HANDLE vHandle;
};

// Function prototypes
DMAContext* Construct(void);
void Release(DMAContext* memory);
bool DumpMemoryMap(DMAContext* memory, bool debug);
bool InitializeDMAContext(DMAContext* memory, const char* process_name, bool memMap, bool debug);
DWORD GetPidFromName(DMAContext* memory, const char* process_name);
void GetPidListFromName(DMAContext* memory, const char* name, int** list, int* count);
void GetModuleList(DMAContext* memory, const char* process_name, char*** list, int* count);
size_t GetBaseAddress(DMAContext* memory, const char* module_name);
size_t GetBaseSize(DMAContext* memory, const char* module_name);
uintptr_t GetExportTableAddress(DMAContext * memory, const char* import, const char* process, const char* module);
uintptr_t GetImportTableAddress(DMAContext * memory, const char* import, const char* process, const char* module);
bool DumpMemory(DMAContext* memory, const char* path);
uint64_t FindSignature(DMAContext* memory, const char* signature, uint64_t range_start, uint64_t range_end, int PID);
uint64_t ScanBufferForPattern(const uint8_t* buffer, size_t buffer_size, const char* signature, uint64_t base_address);
bool Write(const DMAContext* memory, uintptr_t address, void* buffer, size_t size);
bool Read(const DMAContext* memory, uintptr_t address, void* buffer, size_t size);
VMMDLL_SCATTER_HANDLE CreateScatterHandle(DMAContext* memory);
VMMDLL_SCATTER_HANDLE CreateScatterHandleForPid(DMAContext* memory, int pid);
uint8_t HexCharToByte(char c);

// New read functions
void* ReadMemory(const DMAContext* memory, uintptr_t address, size_t size);
uint8_t ReadUInt8(const DMAContext* memory, uintptr_t address);
uint16_t ReadUInt16(const DMAContext* memory, uintptr_t address);
int32_t ReadInt32(const DMAContext* memory, uintptr_t address);
uint32_t ReadUInt32(const DMAContext* memory, uintptr_t address);
uint64_t ReadUInt64(const DMAContext* memory, uintptr_t address);
float ReadFloat(const DMAContext* memory, uintptr_t address);
double ReadDouble(const DMAContext* memory, uintptr_t address);
char* ReadString(const DMAContext* memory, uintptr_t address);
wchar_t* ReadWideString(const DMAContext* memory, uintptr_t address, size_t maxLength);
char* WideToUTF8(const wchar_t* wstr);

#endif // MEMORY_H
