#pragma once

#include <string>
#include <unordered_map>
#include <Mod/CppUserModBase.hpp>

namespace WorkshopPakLoader {
    class SignatureManager {
        public:
            static void Initialize();
            static void* GetSignature(const std::string& ClassAndFunction);

        private:
            static inline std::unordered_map<std::string, void*> SignatureMap;
            static inline std::unordered_map<std::string, std::string> Signatures {
                { "FPakPlatformFile::GetPakFolders", "48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 4C 89 74 24 ?? 55 48 8B EC 48 83 EC 40 48 8D 4D" },
                { "FMemory::Free", "48 85 C9 74 ?? 53 48 83 EC 20 48 8B D9 48 8B 0D" },
            };
    };

    class HookManager {
        public:
            static void Init();
            static void Destroy();
        private:
            static void SetupAlternativePakPathReader();
            static void GetPakFolders(const RC::Unreal::TCHAR* CmdLine, RC::Unreal::TArray<RC::Unreal::FString>* OutPakFolders);
    };

    class WorkshopPakLoader : public CppUserModBase {
        public:
            WorkshopPakLoader();
            ~WorkshopPakLoader();
        private:
            static void BuildPakFolders();
    };
}

namespace WorkshopPakLoader::UnrealOffsets {
    static void Initialize();
    static void InitializeGMalloc();
}