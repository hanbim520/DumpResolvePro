#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <string>

#pragma comment(lib, "dbghelp.lib")
#define ASSERT_TRUE(condition, message)                                         \
    do {                                                                        \
        if (!(condition)) {                                                     \
            std::cerr << "Test failed: " << message << std::endl;               \
            return false;                                                       \
        }                                                                       \
    } while (0)

std::string pdbPath = "";
void PrintError(const std::string& msg) {
    std::cerr << msg << " Error code: " << GetLastError() << std::endl;
}

bool ResolveSymbol(HANDLE processHandle, DWORD64 address, std::string& symbolName) {
    SYMBOL_INFO* symbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char), 1);
    if (symbol != nullptr)
    {
        symbol->MaxNameLen = 255;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

        if (SymFromAddr(processHandle, address, 0, symbol)) {
            symbolName = symbol->Name;

            // ���Ҳ�ȥ�� "ILT+" �����η�
            auto pos = symbolName.find("?");
            if (pos != std::string::npos) {
                symbolName = symbolName.substr(pos + 1); // ȥ��ǰ׺����
            }

            // ȥ������β���������ַ�
            pos = symbolName.find('@');
            if (pos != std::string::npos) {
                symbolName = symbolName.substr(0, pos); // ȥ��β������
            }
            // ȥ�����������еĺ�׺���η����� "YA_NXZ)"
            pos = symbolName.find("YA_");
            if (pos != std::string::npos) {
                symbolName = symbolName.substr(0, pos); // ȥ����׺����
            }

            // ȥ�����ż����ź�����ݣ����� "TestValidAddress)"
            pos = symbolName.find(')');
            if (pos != std::string::npos) {
                symbolName = symbolName.substr(0, pos); // ȥ�������Ų���
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

bool VerifySymbolResolution(HANDLE processHandle, DWORD64 address) {
    std::string symbolName;
    bool resolved = ResolveSymbol(processHandle, address, symbolName);

    if (resolved) {
        std::cout << "Verification successful: Symbol " << symbolName << " resolved." << std::endl;
    }
    else {
        std::cout << "Verification failed: Symbol could not be resolved." << std::endl;
    }

    return resolved;
}

bool TestValidAddress(std::string pdbPath) {
    HANDLE processHandle = GetCurrentProcess();

    if (!SymInitialize(processHandle, NULL, TRUE)) {
        std::cerr << "Failed to initialize symbol handler" << std::endl;
        return false;
    }

    // Set symbol search path to your local .pdb directory
    SymSetSearchPath(processHandle, pdbPath.c_str());

    DWORD64 knownAddress = reinterpret_cast<DWORD64>(&TestValidAddress);
    std::string symbolName;

    bool resolveResult = ResolveSymbol(processHandle, knownAddress, symbolName);
    ASSERT_TRUE(resolveResult, "ResolveSymbol should succeed for valid address");
    ASSERT_TRUE(symbolName == "TestValidAddress", "Symbol name should match 'TestValidAddress'");

    bool verifyResult = VerifySymbolResolution(processHandle, knownAddress);
    ASSERT_TRUE(verifyResult, "VerifySymbolResolution should return true for valid address");

    SymCleanup(processHandle);
    return true;
}

bool TestInvalidAddress(std::string pdbPath) {
    HANDLE processHandle = GetCurrentProcess();

    if (!SymInitialize(processHandle, NULL, TRUE)) {
        std::cerr << "Failed to initialize symbol handler" << std::endl;
        return false;
    }

    // Set symbol search path to your local .pdb directory
    SymSetSearchPath(processHandle, pdbPath.c_str());

    DWORD64 invalidAddress = 0xDEADBEEF;
    std::string symbolName;

    bool resolveResult = ResolveSymbol(processHandle, invalidAddress, symbolName);
    ASSERT_TRUE(resolveResult, "ResolveSymbol should fail for invalid address");

    bool verifyResult = VerifySymbolResolution(processHandle, invalidAddress);
    ASSERT_TRUE(verifyResult, "VerifySymbolResolution should return false for invalid address");

    SymCleanup(processHandle);
    return true;
}

void RunTests() {
    int passed = 0;
    int total = 2;

    if (TestValidAddress(pdbPath)) {
        std::cout << "TestValidAddress passed." << std::endl;
        ++passed;
    }
    else {
        std::cout << "TestValidAddress failed." << std::endl;
    }

    if (TestInvalidAddress(pdbPath)) {
        std::cout << "TestInvalidAddress passed." << std::endl;
        ++passed;
    }
    else {
        std::cout << "TestInvalidAddress failed." << std::endl;
    }

    std::cout << "Passed " << passed << " out of " << total << " tests." << std::endl;
}

int main(int argc, char** argv)
{

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <symbol file path> <address>" << std::endl;
        return 1;
    }

    // ��ȡ�����ļ�·���͵�ַ����
    pdbPath = argv[1];
//     DWORD64 address = 0;
//     try {
//         address = std::stoull(argv[2], nullptr, 16);  // ��ʮ�����ƽ�����ַ
//     }
//     catch (const std::invalid_argument&) {
//         std::cerr << "Invalid address format." << std::endl;
//         return 1;
//     }


    RunTests();
    return 0;
}
