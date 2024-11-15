#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <string>
#include <tchar.h>
#include <stdio.h>
#include <locale>
#include <vector>
#include <map>
#include <format>
#include <cassert>

const ULONG32 cFirstStreamID = LastReservedStream + 1;
const ULONG32 cSecondStreamID = LastReservedStream + 2;

#pragma comment(lib, "dbghelp.lib")

std::string SymbolPath = "";  // 传入 EXE 和 PDB 文件所在的路径
std::string dumpFilePath = ""; // 传入 dump 文件的路径

struct MdmpModule
{
    ULONG64 m_uBaseAddr;   // Base address
    ULONG64 m_uImageSize;  // Size of module
    std::wstring m_sModuleName; // Module name  
    std::wstring m_sImageName;  // The image name. The name may or may not contain a full path. 
    std::wstring m_sLoadedImageName; // The full path and file name of the file from which symbols were loaded. 
    std::wstring m_sLoadedPdbName;   // The full path and file name of the .pdb file.     
    BOOL m_bImageUnmatched;     // If TRUE than there wasn't matching binary found.
    BOOL m_bPdbUnmatched;       // If TRUE than there wasn't matching PDB file found.
    BOOL m_bNoSymbolInfo;       // If TRUE than no symbols were generated for this module.
    VS_FIXEDFILEINFO* m_pVersionInfo; // Version info for module.
};

// Describes a stack frame
struct MdmpStackFrame
{
    MdmpStackFrame()
    {
        m_nModuleRowID = -1;
        m_dw64OffsInSymbol = 0;
        m_nSrcLineNumber = -1;
    }

    DWORD64 m_dwAddrPCOffset;
    int m_nModuleRowID;         // ROWID of the record in CPR_MDMP_MODULES table.
    std::wstring m_sSymbolName;      // Name of symbol
    DWORD64 m_dw64OffsInSymbol; // Offset in symbol
    std::wstring m_sSrcFileName;     // Name of source file
    int m_nSrcLineNumber;       // Line number in the source file
};


// Describes a thread
struct MdmpThread
{
    MdmpThread()
    {
        m_dwThreadId = 0;
        m_pThreadContext = NULL;
        m_bStackWalk = FALSE;
    }

    DWORD m_dwThreadId;        // Thread ID.
    CONTEXT* m_pThreadContext; // Thread context
    BOOL m_bStackWalk;         // Was stack trace retrieved for this thread?
    std::wstring m_sStackTraceMD5;
    std::vector<MdmpStackFrame> m_StackTrace; // Stack trace for this thread.
};

// Describes a memory range
struct MdmpMemRange
{
    ULONG64 m_u64StartOfMemoryRange; // Starting address
    ULONG32 m_uDataSize;             // Size of data
    LPVOID m_pStartPtr;              // Pointer to the memrange data stored in minidump
};

struct MdmpData
{
    MdmpData()
    {
        m_hProcess = INVALID_HANDLE_VALUE;
        m_uProcessorArchitecture = 0;
        m_uchProductType = 0;
        m_ulVerMajor = 0;
        m_ulVerMinor = 0;
        m_ulVerBuild = 0;
        m_uExceptionCode = 0;
        m_uExceptionAddress = 0;
        m_uExceptionThreadId = 0;
        m_pExceptionThreadContext = NULL;
    }

    HANDLE m_hProcess; // Process ID

    USHORT m_uProcessorArchitecture; // CPU architecture
    UCHAR  m_uchNumberOfProcessors;  // Number of processors
    UCHAR  m_uchProductType;         // Type of machine (workstation, server, ...)
    ULONG  m_ulVerMajor;             // OS major version number
    ULONG  m_ulVerMinor;             // OS minor version number
    ULONG  m_ulVerBuild;             // OS build number
    std::wstring m_sCSDVer;               // The latest service pack installed

    ULONG32 m_uExceptionCode;        // Structured exception's code
    ULONG64 m_uExceptionAddress;     // Exception address
    ULONG32 m_uExceptionThreadId;    // Exceptions thread ID 
    CONTEXT* m_pExceptionThreadContext; // Thread context

    std::vector<MdmpThread> m_Threads;       // The list of threads.
    std::map<DWORD, size_t> m_ThreadIndex;   // <thread_id, thread_entry_index> pairs
    std::vector<MdmpModule> m_Modules;       // The list of loaded modules.
    std::map<DWORD64, size_t> m_ModuleIndex; // <base_addr, module_entry_index> pairs
    std::vector<MdmpMemRange> m_MemRanges;   // The list of memory ranges.  
    std::vector<std::wstring> m_LoadLog; // Load log
};


MdmpData m_DumpData; // Minidump data

// 函数：将 CHAR 字符数组转换为 std::wstring
std::wstring CharArrayToWString(const CHAR* charArray) {
    // 计算宽字符字符串所需的大小
    int wideCharLen = MultiByteToWideChar(CP_UTF8, 0, charArray, -1, NULL, 0);
    if (wideCharLen == 0) {
        std::cerr << "Error calculating wide char length: " << GetLastError() << std::endl;
        return L"";
    }

    // 创建一个足够大的 std::wstring 来存储转换后的结果
    std::wstring wideString(wideCharLen, L'\0');

    // 使用 MultiByteToWideChar 函数将 CHAR 数组转换为 std::wstring
    MultiByteToWideChar(CP_UTF8, 0, charArray, -1, &wideString[0], wideCharLen);

    return wideString;
}

int GetThreadRowIdByThreadId(DWORD dwThreadId)
{
    std::map<DWORD, size_t>::iterator it = m_DumpData.m_ThreadIndex.find(dwThreadId);
    if (it != m_DumpData.m_ThreadIndex.end())
        return (int)it->second;
    return -1;
}


// This callback function is used by StackWalk64. It provides access to 
// ranges of memory stored in minidump file
BOOL CALLBACK ReadProcessMemoryProc64(
    HANDLE hProcess,
    DWORD64 lpBaseAddress,
    PVOID lpBuffer,
    DWORD nSize,
    LPDWORD lpNumberOfBytesRead)
{

    return ReadProcessMemory(hProcess, (LPCVOID)lpBaseAddress, lpBuffer, nSize, (SIZE_T*)lpNumberOfBytesRead);
//     *lpNumberOfBytesRead = 0;
// 
//     // Validate input parameters
//     if (hProcess != m_DumpData.m_hProcess ||
//         lpBaseAddress == NULL ||
//         lpBuffer == NULL ||
//         nSize == 0)
//     {
//         // Invalid parameter
//         return FALSE;
//     }
// 
//     ULONG i;
//     for (i = 0; i < m_DumpData.m_MemRanges.size(); i++)
//     {
//         MdmpMemRange& mr = m_DumpData.m_MemRanges[i];
//         if (lpBaseAddress >= mr.m_u64StartOfMemoryRange &&
//             lpBaseAddress < mr.m_u64StartOfMemoryRange + mr.m_uDataSize)
//         {
//             DWORD64 dwOffs = lpBaseAddress - mr.m_u64StartOfMemoryRange;
// 
//             LONG64 lBytesRead = 0;
// 
//             if (mr.m_uDataSize - dwOffs > nSize)
//                 lBytesRead = nSize;
//             else
//                 lBytesRead = mr.m_uDataSize - dwOffs;
// 
//             if (lBytesRead <= 0 || nSize < lBytesRead)
//                 return FALSE;
// 
//             *lpNumberOfBytesRead = (DWORD)lBytesRead;
//             memcpy(lpBuffer, (LPBYTE)mr.m_pStartPtr + dwOffs, (size_t)lBytesRead);
// 
//             return TRUE;
//         }
//     }
// 
//     return FALSE;
}

// This callback function is used by StackWalk64. It provides access to 
// function table stored in minidump file
PVOID CALLBACK FunctionTableAccessProc64(
    HANDLE hProcess,
    DWORD64 AddrBase)
{
    return SymFunctionTableAccess64(hProcess, AddrBase);
}

// This callback function is used by StackWalk64. It provides access to 
// module list stored in minidump file
DWORD64 CALLBACK GetModuleBaseProc64(
    HANDLE hProcess,
    DWORD64 Address)
{
    return SymGetModuleBase64(hProcess, Address);
}

int GetModuleRowIdByBaseAddr(DWORD64 dwBaseAddr)
{
    std::map<DWORD64, size_t>::iterator it = m_DumpData.m_ModuleIndex.find(dwBaseAddr);
    if (it != m_DumpData.m_ModuleIndex.end())
        return (int)it->second;
    return -1;
}


ULONG64 GetModuleBaseAddress(ULONG64 PCAddress)
{
    for (auto& Module : m_DumpData.m_Modules)
    {
        if (PCAddress >= Module.m_uBaseAddr && PCAddress < (Module.m_uBaseAddr + Module.m_uImageSize))
        {
            return Module.m_uBaseAddr;
        }
    }
}


bool ResolveSymbol(HANDLE processHandle, DWORD64 address, std::string& symbolName) {
    SYMBOL_INFO* symbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char), 1);
    if (symbol != nullptr)
    {
        symbol->MaxNameLen = 255;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

        if (SymFromAddr(processHandle, address, 0, symbol)) {
            symbolName = symbol->Name;

            // 查找并去掉 "ILT+" 等修饰符
            auto pos = symbolName.find("?");
            if (pos != std::string::npos) {
                symbolName = symbolName.substr(pos + 1); // 去掉前缀部分
            }

            // 去掉符号尾部的修饰字符
            pos = symbolName.find('@');
            if (pos != std::string::npos) {
                symbolName = symbolName.substr(0, pos); // 去掉尾部修饰
            }
            // 去掉函数名称中的后缀修饰符，如 "YA_NXZ)"
            pos = symbolName.find("YA_");
            if (pos != std::string::npos) {
                symbolName = symbolName.substr(0, pos); // 去掉后缀修饰
            }

            // 去掉括号及括号后的内容，例如 "TestValidAddress)"
            pos = symbolName.find(')');
            if (pos != std::string::npos) {
                symbolName = symbolName.substr(0, pos); // 去掉右括号部分
            }
            free(symbol);
            return true;
        }
        else {
            free(symbol);
            return false;
        }
    }
    return false;
}

int StackWalk(DWORD dwThreadId)
{
    int nThreadIndex = GetThreadRowIdByThreadId(dwThreadId);
    if (m_DumpData.m_Threads[nThreadIndex].m_bStackWalk == TRUE)
        return 0; // Already done

    CONTEXT* pThreadContext = NULL;

    if (m_DumpData.m_Threads[nThreadIndex].m_dwThreadId == m_DumpData.m_uExceptionThreadId)
        pThreadContext = m_DumpData.m_pExceptionThreadContext;
    else
        pThreadContext = m_DumpData.m_Threads[nThreadIndex].m_pThreadContext;

    if (pThreadContext == NULL)
        return 1;

    // Make modifiable context
    CONTEXT Context;
    memcpy(&Context, pThreadContext, sizeof(CONTEXT));
    Context.ContextFlags = CONTEXT_FULL;  // 获取完整的上下文信息

   // g_pMiniDumpReader = this;

    // Init stack frame with correct initial values
    // See this:
    // http://www.codeproject.com/KB/threads/StackWalker.aspx
    //
    // Given a current dbghelp, your code should:
    //  1. Always use StackWalk64
    //  2. Always set AddrPC to the current instruction pointer (Eip on x86, Rip on x64 and StIIP on IA64)
    //  3. Always set AddrStack to the current stack pointer (Esp on x86, Rsp on x64 and IntSp on IA64)
    //  4. Set AddrFrame to the current frame pointer when meaningful. On x86 this is Ebp, on x64 you 
    //     can use Rbp (but is not used by VC2005B2; instead it uses Rdi!) and on IA64 you can use RsBSP. 
    //     StackWalk64 will ignore the value when it isn't needed for unwinding.
    //  5. Set AddrBStore to RsBSP for IA64. 

    STACKFRAME64 sf;
    memset(&sf, 0, sizeof(STACKFRAME64));

//     sf.AddrPC.Mode = AddrModeFlat;
//     sf.AddrFrame.Mode = AddrModeFlat;
//     sf.AddrStack.Mode = AddrModeFlat;
//     sf.AddrBStore.Mode = AddrModeFlat;

    DWORD dwMachineType = 0;
    switch (m_DumpData.m_uProcessorArchitecture)
    {
#ifdef _X86_
    case PROCESSOR_ARCHITECTURE_INTEL:
        dwMachineType = IMAGE_FILE_MACHINE_I386;
        sf.AddrPC.Offset = pThreadContext->Eip;
        sf.AddrStack.Offset = pThreadContext->Esp;
        sf.AddrFrame.Offset = pThreadContext->Ebp;
        break;
#endif
#ifdef _AMD64_
    case PROCESSOR_ARCHITECTURE_AMD64:
        dwMachineType = IMAGE_FILE_MACHINE_AMD64;
        sf.AddrPC.Offset = pThreadContext->Rip;
        sf.AddrStack.Offset = pThreadContext->Rsp;
        sf.AddrFrame.Offset = pThreadContext->Rbp;
        break;
#endif
#ifdef _IA64_
    case PROCESSOR_ARCHITECTURE_AMD64:
        dwMachineType = IMAGE_FILE_MACHINE_IA64;
        sf.AddrPC.Offset = pThreadContext->StIIP;
        sf.AddrStack.Offset = pThreadContext->IntSp;
        sf.AddrFrame.Offset = pThreadContext->RsBSP;
        sf.AddrBStore.Offset = pThreadContext->RsBSP;
        break;
#endif 
    default:
    {
        assert(0);
        return 1; // Unsupported architecture
    }
    }

    for (;;)
    {
        BOOL bWalk = ::StackWalk64(
            dwMachineType,               // machine type
            m_DumpData.m_hProcess,       // our process handle
            (HANDLE)dwThreadId,          // thread ID
            &sf,                         // stack frame
            /*dwMachineType == IMAGE_FILE_MACHINE_I386 ? NULL : (&Context), // used for non-I386 machines */
            &Context,
            ReadProcessMemoryProc64,     // our routine
            FunctionTableAccessProc64,   // our routine
            GetModuleBaseProc64,         // our routine
            NULL                         // safe to be NULL
        );

        if (!bWalk)
            break;

        if (sf.AddrPC.Offset == 0) {
            break;
        }

        MdmpStackFrame stack_frame;
        stack_frame.m_dwAddrPCOffset = sf.AddrPC.Offset;

        // Get module info
        IMAGEHLP_MODULE64 mi;
        memset(&mi, 0, sizeof(IMAGEHLP_MODULE64));
        mi.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

        ULONG64 ModuleAddress = GetModuleBaseAddress(sf.AddrPC.Offset);
        stack_frame.m_nModuleRowID = GetModuleRowIdByBaseAddr(ModuleAddress);

        std::string symbolName;
        ResolveSymbol(m_DumpData.m_hProcess, sf.AddrPC.Offset, symbolName);
        //129005275
//         BOOL bGetModuleInfo = SymGetModuleInfo64(m_DumpData.m_hProcess, sf.AddrPC.Offset, &mi);
//         if (bGetModuleInfo)
//         {
//             stack_frame.m_nModuleRowID = GetModuleRowIdByBaseAddr(mi.BaseOfImage);
//         }

        // Get symbol info
        DWORD64 dwDisp64;
        BYTE buffer[4096];
        SYMBOL_INFO* sym_info = (SYMBOL_INFO*)buffer;
        sym_info->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym_info->MaxNameLen = 4096 - sizeof(SYMBOL_INFO) - 1;
        BOOL bGetSym = SymFromAddr(
            m_DumpData.m_hProcess,
            sf.AddrPC.Offset,
            &dwDisp64,
            sym_info);
        if (bGetSym)
        {
            stack_frame.m_sSymbolName = CharArrayToWString(sym_info->Name);
            stack_frame.m_dw64OffsInSymbol = dwDisp64;
        }

        // Get source filename and line
        DWORD dwDisplacement;
        IMAGEHLP_LINE64 line;
        BOOL bGetLine = SymGetLineFromAddr64(
            m_DumpData.m_hProcess,
            sf.AddrPC.Offset,
            &dwDisplacement,
            &line);

        if (bGetLine)
        {
            stack_frame.m_sSrcFileName = CharArrayToWString(line.FileName);
            stack_frame.m_nSrcLineNumber = line.LineNumber;
        }

        //DWORD address = sf.AddrPC.Offset - 
        m_DumpData.m_Threads[nThreadIndex].m_StackTrace.push_back(stack_frame);
    }


    std::wstring sStackTrace;
    UINT i;
    for (i = 0; i < m_DumpData.m_Threads[nThreadIndex].m_StackTrace.size(); i++)
    {
        MdmpStackFrame& frame = m_DumpData.m_Threads[nThreadIndex].m_StackTrace[i];

        if (frame.m_sSymbolName.length() == 0)
            continue;

        std::wstring sModuleName;
        std::wstring sAddrPCOffset;
        std::wstring sSymbolName;
        std::wstring sOffsInSymbol;
        std::wstring sSourceFile;
        std::wstring sSourceLine;

        if (frame.m_nModuleRowID >= 0)
        {
            sModuleName = m_DumpData.m_Modules[frame.m_nModuleRowID].m_sModuleName;
        }

        sSymbolName = frame.m_sSymbolName;
        sAddrPCOffset = std::format(L"0x{}", frame.m_dwAddrPCOffset);
        sSourceFile = frame.m_sSrcFileName;
        sSourceLine= std::format(L"{}", frame.m_nSrcLineNumber);
        sOffsInSymbol = std::format(L"0x{}", frame.m_dw64OffsInSymbol);

        std::wstring str;
        str = sModuleName;
        if (!str.length())
            str += _T("!");

        if (sSymbolName.length() == 0)
            str += sAddrPCOffset;
        else
        {
            str += sSymbolName;
            str += _T("+");
            str += sOffsInSymbol;
        }

        if (!sSourceFile.length() == 0)
        {
            size_t pos = sSourceFile.rfind('\\');
            if (pos != std::wstring::npos) {
                sSourceFile = sSourceFile.substr((int)pos + 1);
            }
            str += _T(" [ ");
            str += sSourceFile;
            str += _T(": ");
            str += sSourceLine;
            str += _T(" ] ");
        }

        sStackTrace += str;
        sStackTrace += _T("\n");
    }
    m_DumpData.m_Threads[nThreadIndex].m_sStackTraceMD5 = sStackTrace;
//     if (!sStackTrace.length())
//     {
//         LPCSTR szStackTrace = sStackTrace.c_str();
// //         MD5 md5;
// //         MD5_CTX md5_ctx;
// //         unsigned char md5_hash[16];
// //         md5.MD5Init(&md5_ctx);
// //         md5.MD5Update(&md5_ctx, (unsigned char*)szStackTrace, (unsigned int)strlen(szStackTrace));
// //         md5.MD5Final(md5_hash, &md5_ctx);
// 
// //         for (i = 0; i < 16; i++)
// //         {
// //             CString number;
// //             number.Format(_T("%02x"), md5_hash[i]);
// //             m_DumpData.m_Threads[nThreadIndex].m_sStackTraceMD5 += number;
// //         }
//     }

    m_DumpData.m_Threads[nThreadIndex].m_bStackWalk = TRUE;


    return 0;
}



void PrintError(const std::string& msg) {
    std::cerr << msg << " Error code: " << GetLastError() << std::endl;
}


bool _GetFileSize(const TCHAR* pFileName, DWORD& FileSize)
{
    if (pFileName == 0)
    {
        return false;
    }

    HANDLE hFile = ::CreateFile(pFileName, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        _tprintf(_T("CreateFile() failed. Error: %u \n"), ::GetLastError());
        return false;
    }


    // Obtain the size of the file 

    FileSize = ::GetFileSize(hFile, NULL);

    if (FileSize == INVALID_FILE_SIZE)
    {
        _tprintf(_T("GetFileSize() failed. Error: %u \n"), ::GetLastError());
        // and continue ... 
    }


    // Close the file 

    if (!::CloseHandle(hFile))
    {
        _tprintf(_T("CloseHandle() failed. Error: %u \n"), ::GetLastError());
        // and continue ... 
    }


    // Complete 

    return (FileSize != INVALID_FILE_SIZE);

}

bool GetFileParams(const TCHAR* pFileName, DWORD64& BaseAddr, DWORD& FileSize)
{
    // Check parameters 

    if (pFileName == 0)
    {
        return false;
    }


    // Determine the extension of the file 

    TCHAR szFileExt[_MAX_EXT] = { 0 };

    _tsplitpath(pFileName, NULL, NULL, NULL, szFileExt);


    // Is it .PDB file ? 

    if (_tcsicmp(szFileExt, _T(".PDB")) == 0)
    {
        // Yes, it is a .PDB file 

        // Determine its size, and use a dummy base address 

        BaseAddr = 0x10000000; // it can be any non-zero value, but if we load symbols 
        // from more than one file, memory regions specified 
        // for different files should not overlap 
        // (region is "base address + file size") 

        if (!_GetFileSize(pFileName, FileSize))
        {
            return false;
        }

    }
    else
    {
        // It is not a .PDB file 

        // Base address and file size can be 0 

        BaseAddr = 0;
        FileSize = 0;
    }


    // Complete 

    return true;

}

std::wstring GetMinidumpString(LPVOID start_addr, RVA rva)
{
    MINIDUMP_STRING* pms = (MINIDUMP_STRING*)((LPBYTE)start_addr + rva);
    //CString sModule = CString(pms->Buffer, pms->Length);
    std::wstring sModule = pms->Buffer;
    return sModule;
}

bool LoadSymbols(HANDLE processHandle, const std::string& SymbolPath) {
    // 假设 PDB 和 EXE 在同一目录
    std::string pdbPath = SymbolPath + "UE_game-Win64-Shipping.pdb";
    std::string exePath = SymbolPath + "UE_game-Win64-Shipping.exe";

    // 打印路径用于调试
    std::cout << "Exe Path: " << exePath << std::endl;
    std::cout << "Pdb Path: " << pdbPath << std::endl;

    // 检查文件是否存在
    DWORD fileAttrExe = GetFileAttributesA(exePath.c_str());
    DWORD fileAttrPdb = GetFileAttributesA(pdbPath.c_str());

    if (fileAttrExe == INVALID_FILE_ATTRIBUTES) {
        PrintError("Exe file not found");
        return false;
    }
    if (fileAttrPdb == INVALID_FILE_ATTRIBUTES) {
        PrintError("Pdb file not found");
        return false;
    }

    // 初始化符号处理程序
    std::wstring SymbolPathW= std::wstring(SymbolPath.begin(), SymbolPath.end());
//     char SymbolPathA[1024];
// 
//     // Convert wchar_t* to char*
//     wcstombs(SymbolPathA, SymbolPathW.c_str(), SymbolPathW.length() + 1);

//     char narrowPath[MAX_PATH];
//     int converted = WideCharToMultiByte(CP_ACP, 0, SymbolPathW.c_str(), -1, narrowPath, sizeof(narrowPath), NULL, NULL);

    
    if (!SymInitialize(processHandle, "C:\\Symbols", TRUE)) {
        DWORD dwError = GetLastError();
        std::cerr << "SymInitialize failed with error: " << dwError << std::endl;
        return false;
    }

    // 设置符号文件搜索路径
    if (!SymSetSearchPath(processHandle, SymbolPath.c_str())) {
        PrintError("SymSetSearchPath failed");
        return false;
    }

    // 加载 EXE 文件模块（用于符号解析）
    //
    if (!SymLoadModule64(processHandle, NULL, exePath.c_str(), NULL, 0, 0)) {
    //if (!SymLoadModule64(processHandle, NULL, "UE_game-Win64-Shipping.exe", NULL, 0, 0)) {
        PrintError("Failed to load EXE module");
        SymCleanup(processHandle);
        return false;
    }
 
    DWORD64   BaseAddr = 0;
    DWORD     FileSize = 0;

    std::wstring wstr(pdbPath.begin(), pdbPath.end());
    if (!GetFileParams(wstr.c_str(), BaseAddr, FileSize))
    {
        _tprintf(_T("Error: Cannot obtain file parameters (internal error).\n"));
        return false;
    }


    // 加载 PDB 文件
    DWORD64 baseAddr = SymLoadModule64(processHandle, NULL, pdbPath.c_str(), NULL, BaseAddr, FileSize);
    //DWORD64 baseAddr = SymLoadModule64(processHandle, NULL, "UE_game-Win64-Shipping.pdb", NULL, BaseAddr, FileSize);
    if (baseAddr == 0) {
        PrintError("Failed to load PDB file. SymLoadModule64 returned: 0");
        // 提供更详细的错误信息
        DWORD dwLastError = GetLastError();
        if (dwLastError != 0) {
            std::cerr << "GetLastError: " << dwLastError << std::endl;
        }
        SymCleanup(processHandle);
        return false;
    }

    std::cout << "PDB loaded successfully, base address: " << baseAddr << std::endl;
    return true;
}


int ReadSysInfoStream(PVOID pBaseOfDump)
{
    LPVOID pStreamStart = NULL;
    ULONG uStreamSize = 0;
    MINIDUMP_DIRECTORY* pmd = NULL;
    BOOL bRead = FALSE;

    bRead = MiniDumpReadDumpStream(pBaseOfDump, SystemInfoStream,
        &pmd, &pStreamStart, &uStreamSize);

    if (bRead)
    {
        MINIDUMP_SYSTEM_INFO* pSysInfo = (MINIDUMP_SYSTEM_INFO*)pStreamStart;

        m_DumpData.m_uProcessorArchitecture = pSysInfo->ProcessorArchitecture;
        m_DumpData.m_uchNumberOfProcessors = pSysInfo->NumberOfProcessors;
        m_DumpData.m_uchProductType = pSysInfo->ProductType;
        m_DumpData.m_ulVerMajor = pSysInfo->MajorVersion;
        m_DumpData.m_ulVerMinor = pSysInfo->MinorVersion;
        m_DumpData.m_ulVerBuild = pSysInfo->BuildNumber;
        m_DumpData.m_sCSDVer = GetMinidumpString(pBaseOfDump, pSysInfo->CSDVersionRva);

        // Clean up
        pStreamStart = NULL;
        uStreamSize = 0;
        pmd = NULL;
    }
    else
    {
        return 1;
    }

    return 0;
}

int ReadModuleListStream(PVOID pBaseOfDump)
{
    LPVOID pStreamStart = NULL;
    ULONG uStreamSize = 0;
    MINIDUMP_DIRECTORY* pmd = NULL;
    BOOL bRead = FALSE;

    bRead = MiniDumpReadDumpStream(
        pBaseOfDump,
        ModuleListStream,
        &pmd,
        &pStreamStart,
        &uStreamSize);

    if (bRead)
    {
        MINIDUMP_MODULE_LIST* pModuleStream = (MINIDUMP_MODULE_LIST*)pStreamStart;
        if (pModuleStream != NULL)
        {
            ULONG32 uNumberOfModules = pModuleStream->NumberOfModules;
            ULONG32 i;
            for (i = 0; i < uNumberOfModules; i++)
            {
                MINIDUMP_MODULE* pModule =
                    (MINIDUMP_MODULE*)((LPBYTE)pModuleStream->Modules + i * sizeof(MINIDUMP_MODULE));

                std::wstring sModuleName = GetMinidumpString(pBaseOfDump, pModule->ModuleNameRva);
                LPCWSTR szModuleName = sModuleName.c_str();
                DWORD64 dwBaseAddr = pModule->BaseOfImage;
                DWORD64 dwImageSize = pModule->SizeOfImage;

                std::wstring sShortModuleName = sModuleName;
                int pos = -1;
                pos = sModuleName.rfind(L'\\');
                if (pos != std::wstring::npos) {
                   sShortModuleName = sModuleName.substr(pos + 1);
                }

                DWORD64 dwLoadResult = SymLoadModuleExW(
                    m_DumpData.m_hProcess,
                    NULL,
                    (PWSTR)szModuleName,
                    NULL,
                    dwBaseAddr,
                    (DWORD)dwImageSize,
                    NULL,
                    0);

                IMAGEHLP_MODULE64 modinfo;
                memset(&modinfo, 0, sizeof(IMAGEHLP_MODULE64));
                modinfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
                BOOL bModuleInfo = SymGetModuleInfo64(m_DumpData.m_hProcess,
                    dwBaseAddr,
                    &modinfo);
                MdmpModule m;
                if (!bModuleInfo)
                {
                    m.m_bImageUnmatched = TRUE;
                    m.m_bNoSymbolInfo = TRUE;
                    m.m_bPdbUnmatched = TRUE;
                    m.m_pVersionInfo = NULL;
                    m.m_sImageName = sModuleName;
                    m.m_sModuleName = sShortModuleName;
                    m.m_uBaseAddr = dwBaseAddr;
                    m.m_uImageSize = dwImageSize;
                }
                else
                {
                    m.m_uBaseAddr = modinfo.BaseOfImage;
                    m.m_uImageSize = modinfo.ImageSize;
                    m.m_sModuleName = sShortModuleName;
                     

                    m.m_sImageName = CharArrayToWString(modinfo.ImageName);
                    m.m_sLoadedImageName = CharArrayToWString(modinfo.LoadedImageName);
                    m.m_sLoadedPdbName = CharArrayToWString(modinfo.LoadedPdbName);
                    m.m_pVersionInfo = &pModule->VersionInfo;
                    m.m_bPdbUnmatched = modinfo.PdbUnmatched;
                    BOOL bTimeStampMatched = pModule->TimeDateStamp == modinfo.TimeDateStamp;
                    m.m_bImageUnmatched = !bTimeStampMatched;
                    m.m_bNoSymbolInfo = !modinfo.GlobalSymbols;
                }

                m_DumpData.m_Modules.push_back(m);
                m_DumpData.m_ModuleIndex[m.m_uBaseAddr] = m_DumpData.m_Modules.size() - 1;

                std::wstring sMsg;
                if (m.m_bImageUnmatched)
                {
                    sMsg =  std::format(L"Loaded '*{}'", sModuleName);
                }
                else
                {
                    sMsg = std::format(L"Loaded '*{}'", m.m_sLoadedImageName);
                }

                if (m.m_bImageUnmatched)
                    sMsg += _T(", No matching binary found.");
                else if (m.m_bPdbUnmatched)
                    sMsg += _T(", No matching PDB file found.");
                else
                {
                    if (m.m_bNoSymbolInfo)
                        sMsg += _T(", No symbols loaded.");
                    else
                        sMsg += _T(", Symbols loaded.");
                }
                m_DumpData.m_LoadLog.push_back(sMsg);
            }
        }
    }
    else
    {
        return 1;
    }

    return 0;
}

int ReadThreadListStream(PVOID pBaseOfDump)
{
    LPVOID pStreamStart = NULL;
    ULONG uStreamSize = 0;
    MINIDUMP_DIRECTORY* pmd = NULL;
    BOOL bRead = FALSE;

    bRead = MiniDumpReadDumpStream(
        pBaseOfDump,
        ThreadListStream,
        &pmd,
        &pStreamStart,
        &uStreamSize);

    if (bRead)
    {
        MINIDUMP_THREAD_LIST* pThreadList = (MINIDUMP_THREAD_LIST*)pStreamStart;
        if (pThreadList != NULL &&
            uStreamSize >= sizeof(MINIDUMP_THREAD_LIST))
        {
            ULONG32 uThreadCount = pThreadList->NumberOfThreads;

            ULONG32 i;
            for (i = 0; i < uThreadCount; i++)
            {
                MINIDUMP_THREAD* pThread = (MINIDUMP_THREAD*)(&pThreadList->Threads[i]);

                MdmpThread mt;
                mt.m_dwThreadId = pThread->ThreadId;
                mt.m_pThreadContext = (CONTEXT*)(((LPBYTE)pBaseOfDump) + pThread->ThreadContext.Rva);

                m_DumpData.m_Threads.push_back(mt);
                m_DumpData.m_ThreadIndex[mt.m_dwThreadId] = m_DumpData.m_Threads.size() - 1;
            }
        }
    }
    else
    {
        return 1;
    }

    return 0;
}

int ReadMemoryListStream(PVOID pBaseOfDump)
{
    LPVOID pStreamStart = NULL;
    ULONG uStreamSize = 0;
    MINIDUMP_DIRECTORY* pmd = NULL;
    BOOL bRead = FALSE;

    bRead = MiniDumpReadDumpStream(
        pBaseOfDump,
        MemoryListStream,
        &pmd,
        &pStreamStart,
        &uStreamSize);

    if (bRead)
    {
        MINIDUMP_MEMORY_LIST* pMemStream = (MINIDUMP_MEMORY_LIST*)pStreamStart;
        if (pMemStream != NULL)
        {
            ULONG32 uNumberOfMemRanges = pMemStream->NumberOfMemoryRanges;
            ULONG i;
            for (i = 0; i < uNumberOfMemRanges; i++)
            {
                MINIDUMP_MEMORY_DESCRIPTOR* pMemDesc = (MINIDUMP_MEMORY_DESCRIPTOR*)(&pMemStream->MemoryRanges[i]);
                MdmpMemRange mr;
                mr.m_u64StartOfMemoryRange = pMemDesc->StartOfMemoryRange;
                mr.m_uDataSize = pMemDesc->Memory.DataSize;
                mr.m_pStartPtr = (LPBYTE)pBaseOfDump + pMemDesc->Memory.Rva;

                m_DumpData.m_MemRanges.push_back(mr);
            }
        }
    }
    else
    {
        return 1;
    }

    return 0;
}

int GetModuleRowIdByAddress(DWORD64 dwAddress)
{
    UINT i;
    for (i = 0; i < m_DumpData.m_Modules.size(); i++)
    {
        if (m_DumpData.m_Modules[i].m_uBaseAddr <= dwAddress &&
            dwAddress < m_DumpData.m_Modules[i].m_uBaseAddr + m_DumpData.m_Modules[i].m_uImageSize)
            return i;
    }

    return -1;
}

// 使用地址获取符号
void GetSymbolFromAddress(DWORD64 address) {
    HANDLE hProcess = GetCurrentProcess();

    // 创建符号信息结构
    SYMBOL_INFO* pSymbol = (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    if (pSymbol == NULL) {
        PrintError("Failed to allocate memory for SYMBOL_INFO");
        return;
    }

    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

  //  address = 0x0000000007b076db;
    // 使用 SymFromAddr 解析地址到符号
    if (SymFromAddr(hProcess, address, 0, pSymbol)) {
        std::wcout << L"Symbol: " << pSymbol->Name << L" at address 0x" << std::hex << pSymbol->Address << std::endl;
    }
    else {
        DWORD dwLastError = GetLastError();
        std::cerr << "Failed to get symbol: Error " << dwLastError << std::endl;
    }

    free(pSymbol);
}




int ReadExceptionStream(PVOID pBaseOfDump)
{
    LPVOID pStreamStart = NULL;
    ULONG uStreamSize = 0;
    MINIDUMP_DIRECTORY* pmd = NULL;
    BOOL bRead = FALSE;

    bRead = MiniDumpReadDumpStream(
        pBaseOfDump,
        ExceptionStream,
        &pmd,
        &pStreamStart,
        &uStreamSize);

    if (bRead)
    {
        MINIDUMP_EXCEPTION_STREAM* pExceptionStream = (MINIDUMP_EXCEPTION_STREAM*)pStreamStart;
        if (pExceptionStream != NULL &&
            uStreamSize >= sizeof(MINIDUMP_EXCEPTION_STREAM))
        {
            m_DumpData.m_uExceptionThreadId = pExceptionStream->ThreadId;
            m_DumpData.m_uExceptionCode = pExceptionStream->ExceptionRecord.ExceptionCode;
            m_DumpData.m_uExceptionAddress = pExceptionStream->ExceptionRecord.ExceptionAddress;
            m_DumpData.m_pExceptionThreadContext =
                (CONTEXT*)(((LPBYTE)pBaseOfDump) + pExceptionStream->ThreadContext.Rva);

//             std::string symbolName;
//             HANDLE processHandle = GetCurrentProcess();
//             bool resolveResult = ResolveSymbol(processHandle, m_DumpData.m_uExceptionAddress, symbolName);
            GetSymbolFromAddress(m_DumpData.m_uExceptionAddress);
            std::wstring sMsg;
            int nExcModuleRowID = GetModuleRowIdByAddress(m_DumpData.m_uExceptionAddress);
            if (nExcModuleRowID >= 0)
            {
                sMsg = std::format(L"Unhandled exception at 0x{} in {}: 0x{} : {}",
                    m_DumpData.m_uExceptionAddress,
                    m_DumpData.m_Modules[nExcModuleRowID].m_sModuleName,
                    m_DumpData.m_uExceptionCode,
                    L"Exception description."
                );
                
            }
            else
            {

            }
            m_DumpData.m_LoadLog.push_back(sMsg);
        }
    }
    else
    {
        std::wstring sMsg;
        sMsg = _T("No exception information found in minidump.");
        m_DumpData.m_LoadLog.push_back(sMsg);
        return 1;
    }

    // Extract and print the stack trace for all threads in the dump
//     LPVOID pThreadStreamStart = NULL;
//     ULONG uThreadStreamSize = 0;
//     bRead = MiniDumpReadDumpStream(
//         pBaseOfDump,
//         ThreadListStream,
//         &pmd,
//         &pThreadStreamStart,
//         &uThreadStreamSize);
// 
//     if (bRead)
//     {
//         MINIDUMP_THREAD_LIST* pThreadList = (MINIDUMP_THREAD_LIST*)pStreamStart;
//         if (pThreadList != NULL &&
//             uStreamSize >= sizeof(MINIDUMP_THREAD_LIST))
//         {
//             ULONG32 uThreadCount = pThreadList->NumberOfThreads;
// 
//             ULONG32 i;
//             for (i = 0; i < uThreadCount; i++)
//             {
//                 MINIDUMP_THREAD* pThread = (MINIDUMP_THREAD*)(&pThreadList->Threads[i]);
// 
//                 StackWalk(pThread->ThreadId);
//             }
//         }
//     }
//     else
//     {
//         std::wstring sMsg = L"No thread information found in minidump.";
//         m_DumpData.m_LoadLog.push_back(sMsg);
//         return 1;
//     }
    return 0;
}



void ProcessDumpFile(const std::string& dumpFilePath) {
    static DWORD dwProcessID = 0;

    // 打开 dump 文件
    HANDLE hFile = CreateFileA(dumpFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
        PrintError("Failed to open dump file");
        return;
    }

    // 创建文件映射
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        PrintError("Failed to create file mapping");
        CloseHandle(hFile);
        return;
    }

    // 映射文件到内存
    PVOID pBaseOfDump = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (pBaseOfDump == NULL) {
        PrintError("Failed to map view of file");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

//     // 读取 dump 文件头部
//     MINIDUMP_EXCEPTION_INFORMATION exceptionInfo;
//     MINIDUMP_HEADER header;
//     DWORD bytesRead;
//     if (!ReadFile(hFile, &header, sizeof(MINIDUMP_HEADER), &bytesRead, NULL)) {
//         PrintError("Failed to read dump file header");
//         CloseHandle(hFile);
//         return;
//     }
// 
//     // 获取异常信息
//     if (!ReadFile(hFile, &exceptionInfo, sizeof(MINIDUMP_EXCEPTION_INFORMATION), &bytesRead, NULL)) {
//         PrintError("Failed to read exception information from dump");
//         CloseHandle(hFile);
//         return;
//     }
// 
//     // 获取异常地址
//     DWORD64 exceptionAddress = (DWORD64)(uintptr_t)exceptionInfo.ExceptionPointers->ExceptionRecord->ExceptionAddress;

    m_DumpData.m_hProcess = (HANDLE)(++dwProcessID);

    DWORD dwOptions = 0;
    //dwOptions |= SYMOPT_DEFERRED_LOADS; // Symbols are not loaded until a reference is made requiring the symbols be loaded.
    //dwOptions |= SYMOPT_EXACT_SYMBOLS; // Do not load an unmatched .pdb file. 
   // dwOptions |= SYMOPT_FAIL_CRITICAL_ERRORS; // Do not display system dialog boxes when there is a media failure such as no media in a drive.
    dwOptions |= SYMOPT_LOAD_ANYTHING; // All symbols are presented in undecorated form.   
    dwOptions |= SYMOPT_UNDNAME; // All symbols are presented in undecorated form.   
    SymSetOptions(dwOptions);

    HANDLE hProcess = GetCurrentProcess();
    m_DumpData.m_hProcess = hProcess;
    std::wstring dumpFilePathW(dumpFilePath.begin(), dumpFilePath.end());
    BOOL bSymInit = LoadSymbols(m_DumpData.m_hProcess, SymbolPath);
    if (!bSymInit)
    {
        m_DumpData.m_hProcess = NULL;
        return ;
    }

   bool m_bReadSysInfoStream = FALSE;
   bool m_bReadExceptionStream = FALSE;
   bool  m_bReadModuleListStream = FALSE;
   bool  m_bReadMemoryListStream = FALSE;
   bool  m_bReadThreadListStream = FALSE;

    
    m_bReadSysInfoStream = !ReadSysInfoStream(pBaseOfDump);
    m_bReadModuleListStream = !ReadModuleListStream(pBaseOfDump);
    m_bReadThreadListStream = !ReadThreadListStream(pBaseOfDump);
    m_bReadMemoryListStream = !ReadMemoryListStream(pBaseOfDump);
    m_bReadExceptionStream = !ReadExceptionStream(pBaseOfDump);

    int nThreadROWID = GetThreadRowIdByThreadId(m_DumpData.m_uExceptionThreadId);
    if (nThreadROWID >= 0)
    {
        StackWalk(m_DumpData.m_Threads[nThreadROWID].m_dwThreadId);
        std::wstring StackTrace = m_DumpData.m_Threads[nThreadROWID].m_sStackTraceMD5;
        std::wcout << StackTrace << std::endl; // 输出每一条日志
    }

//     for (const auto& log : m_DumpData.m_LoadLog) {
//         std::wcout << log << std::endl; // 输出每一条日志
//     }
    // 清理资源
    SymCleanup(GetCurrentProcess());
    UnmapViewOfFile(pBaseOfDump);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    SymCleanup(m_DumpData.m_hProcess);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <exe file path> <dump file path>" << std::endl;
        return 1;
    }

    SymbolPath = argv[1];  // 传入 EXE 和 PDB 文件所在的路径
    dumpFilePath = argv[2]; // 传入 dump 文件的路径

    // 加载符号文件
//     HANDLE processHandle = GetCurrentProcess();
//     if (!LoadSymbols(processHandle, SymbolPath)) {
//         return 1;
//     }


    // 处理 DUMP 文件
    ProcessDumpFile(dumpFilePath);

    // 清理符号处理程序
   

    return 0;
}
