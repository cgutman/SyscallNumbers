#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <detours.h>
#pragma comment(lib, "detours.lib")

#include <capstone/capstone.h>
#pragma comment(lib, "capstone.lib")

#include <stdio.h>

#if defined(_M_ARM64)
#define CAP_ARCH CS_ARCH_AARCH64
#define CAP_MODE CS_MODE_LITTLE_ENDIAN
#elif defined(_M_AMD64)
#define CAP_ARCH CS_ARCH_X86
#define CAP_MODE CS_MODE_64
#elif defined(_M_IX86)
#define CAP_ARCH CS_ARCH_X86
#define CAP_MODE CS_MODE_32
#else
#error Unknown architecture
#endif

csh CapstoneHandle;

int GetSyscallNumber(LPCSTR SymbolName, PVOID Function)
{
    cs_insn* instructions;
    size_t count = cs_disasm(CapstoneHandle, (uint8_t*)Function, 128, (uintptr_t)Function, 0, &instructions);
    if (count <= 0) {
        fprintf(stderr, "Unable to disassemble function: %s (possibly data export?)\n", SymbolName);
        return -1;
    }

    int syscallNum = -1;
    bool confirmedSyscall = false;

    for (size_t i = 0; i < count; i++) {
#if defined(_M_IX86) || defined(_M_AMD64)
        // mov eax,12Ah
        if (instructions[i].id == X86_INS_MOV &&
            instructions[i].detail->x86.op_count == 2 &&
            instructions[i].detail->x86.operands[0].type == X86_OP_REG &&
            instructions[i].detail->x86.operands[0].reg == X86_REG_EAX &&
            instructions[i].detail->x86.operands[1].type == X86_OP_IMM &&
            syscallNum == -1) {
            syscallNum = (int)instructions[i].detail->x86.operands[1].imm;
        }
        else if (instructions[i].id == X86_INS_SYSCALL || instructions[i].id == X86_INS_SYSENTER) {
            confirmedSyscall = true;
            break;
        }
#elif defined(_M_ARM64)
        // svc #0x19
        if (instructions[i].id == AARCH64_INS_SVC &&
            instructions[i].detail->aarch64.op_count == 1 &&
            instructions[i].detail->aarch64.operands[0].type == AARCH64_OP_IMM) {
            syscallNum = (int)instructions[i].detail->aarch64.operands[0].imm;
            confirmedSyscall = true;
            break;
        }
#else
#error Unsupported architecture for syscall number determination
#endif
    }

    if (!confirmedSyscall) {
        // This wasn't a syscall function after all
        syscallNum = -1;
        goto Exit;
    }

Exit:
    cs_free(instructions, count);
    return syscallNum;
}

BOOL CALLBACK ExportCallback(PVOID Context, ULONG Ordinal, LPCSTR SymbolName, PVOID Target)
{
    UNREFERENCED_PARAMETER(Context);

    if (SymbolName && Target) {
        int syscallNum = GetSyscallNumber(SymbolName, Target);
        if (syscallNum >= 0) {
            printf("%s\t%u\n", SymbolName, syscallNum);
        }
    }

    return TRUE;
}

int main(int argc, char* argv[])
{
    if (argc <= 1) {
        fprintf(stderr, "SyscallNumbers Module1.dll [Module2.dll ...]");
        return 1;
    }

    if (cs_open(CAP_ARCH, CAP_MODE, &CapstoneHandle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return 1;
    }

    cs_option(CapstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);

    for (int i = 1; i < argc; i++) {
        HMODULE lib = LoadLibraryExA(argv[i], NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (lib == NULL) {
            fprintf(stderr, "Failed to load %s: %u\n", argv[i], GetLastError());
            return 1;
        }

        if (!DetourEnumerateExports(lib, NULL, ExportCallback)) {
            fprintf(stderr, "Failed to enumerate exports for %s: %u\n", argv[i], GetLastError());
            return 1;
        }

        FreeLibrary(lib);
    }

    cs_close(&CapstoneHandle);
    return 0;
}
