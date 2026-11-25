// This is pretty much an stripped (and butchered) version of palschema AlternativePakPathReader.

#include <WorkshopPakLoader.hpp>

#include <bit>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "Helpers/String.hpp"
#include <UE4SSProgram.hpp>
#include <DynamicOutput/DynamicOutput.hpp>
#include <Unreal/Core/Containers/Array.hpp>
#include <Unreal/Core/Containers/UnrealString.hpp>
#include "SigScanner/SinglePassSigScanner.hpp"
#include <Signatures.hpp>
#include <Unreal/Core/HAL/UnrealMemory.hpp>
#include <polyhook2/Detour/x64Detour.hpp>
#include <ASMHelper/ASMHelper.hpp>
#include "Unreal/Hooks.hpp"
#include <Zydis/Zydis.h>
#include <Mod/CppUserModBase.hpp>

using namespace RC;
using namespace RC::Unreal;

namespace WorkshopPakLoader {
    uint64_t Trampoline{};
    std::unique_ptr<PLH::x64Detour> GetPakFolders_Det;
    
    std::vector<std::filesystem::path> pakFolders;
    
    void SignatureManager::Initialize()
    {
        std::vector<SignatureContainer> SigContainerBox;
        SinglePassScanner::SignatureContainerMap SigContainerMap;
        
        for (auto& [ClassAndName, Signature] : Signatures)
        {
            SignatureContainer SigContainer = [=]() -> SignatureContainer {
                return {
                    {{Signature}},
                    [=](SignatureContainer& self) {
                        void* FunctionPointer = static_cast<void*>(self.get_match_address());
                        
                        SignatureMap.emplace(ClassAndName, FunctionPointer);
                        Output::send<LogLevel::Normal>(STR("[WorkshopPaksLoader] Found {}: {}\n"), RC::to_generic_string(ClassAndName), FunctionPointer);
                        
                        self.get_did_succeed() = true;
                        
                        return true;
                    },
                    [=](const SignatureContainer& self) {
                        if (!self.get_did_succeed())
                        {
                            Output::send<LogLevel::Error>(STR("[WorkshopPaksLoader] Failed to find signature for {}.\n"), RC::to_generic_string(ClassAndName));
                        }
                    }
                };
            }();
            SigContainerBox.emplace_back(SigContainer);
        }

        SigContainerMap.emplace(ScanTarget::MainExe, SigContainerBox);
        SinglePassScanner::start_scan(SigContainerMap);
    }
    
    void* SignatureManager::GetSignature(const std::string& ClassAndFunction)
    {
        auto It = SignatureMap.find(ClassAndFunction);
        if (It != SignatureMap.end())
        {
            return It->second;
        }
        
        return nullptr;
    }
    
    void UnrealOffsets::Initialize()
    {
        Unreal::Version::Major = 5;
        Unreal::Version::Minor = 4;
        Output::send<LogLevel::Verbose>(STR("[WorkshopPaksLoader] Unreal Version set to {}.{}.\n"), Unreal::Version::Major, Unreal::Version::Minor);
        
        UnrealInitializer::InitializeVersionedContainer();
        Output::send<LogLevel::Verbose>(STR("[WorkshopPaksLoader] Versioned Container initialized.\n"));
    }
    
    void UnrealOffsets::InitializeGMalloc()
    {
        if (RC::Unreal::GMalloc) return;
        
        Output::send<LogLevel::Verbose>(STR("[WorkshopPaksLoader] Initializing GMalloc...\n"));
        
        auto StartAddr = static_cast<uint8_t*>(SignatureManager::GetSignature("FMemory::Free"));
        if (!StartAddr)
        {
            throw std::runtime_error("Signature for FMemory::Free was invalid.");
        }
        
        ZydisDecoder Decoder{};
        ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ZyanUSize Offset = 0;
        ZydisDecodedInstruction Instruction{};
        ZydisDecodedOperand Operands[10]{};
        bool CallFound = false;
        
        while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, StartAddr + Offset, 100 - Offset, &Instruction, Operands)))
        {
            if (CallFound)
            {
                break;
            }
            
            if (Instruction.mnemonic == ZYDIS_MNEMONIC_CALL)
            {
                CallFound = true;
            }
            
            Offset += Instruction.length;
        }
        
        if (Instruction.mnemonic != ZYDIS_MNEMONIC_MOV)
        {
            throw std::runtime_error(std::format("Expected MOV instruction after CALL, but found {}", ZydisMnemonicGetString(Instruction.mnemonic)));
        }
        
        if (Instruction.operand_count < 2)
        {
            throw std::runtime_error("MOV instruction has less than 2 operands.");
        }
        
        if (Operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || Operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY)
        {
            throw std::runtime_error("Unexpected operand types. Expected [REGISTER, MEMORY].");
        }
        
        const auto& MemOp = Operands[1].mem;
        if (MemOp.base != ZYDIS_REGISTER_RIP)
        {
            throw std::runtime_error(std::format("Unexpected base register. Expected [RIP]."));
        }
        
        if (!MemOp.disp.has_displacement)
        {
            throw std::runtime_error(std::format("RIP operand is missing displacement field."));
        }
        
        uint8_t* MovInstructionAddr = StartAddr + Offset;
        uint8_t* NextInstructionAddr = MovInstructionAddr + Instruction.length;
        int64_t DispValue = MemOp.disp.value;
        uint8_t* GMallocAddr = static_cast<uint8_t*>(NextInstructionAddr) + DispValue;
        
        RC::Unreal::GMalloc = std::bit_cast<RC::Unreal::FMalloc**>(GMallocAddr);
        
        Output::send<LogLevel::Verbose>(STR("[WorkshopPaksLoader] Found GMalloc: {}\n"), static_cast<void*>(GMallocAddr));
    }
    
    void HookManager::Init() {
        SetupAlternativePakPathReader();
    }
    
    void HookManager::Destroy() {
        if (GetPakFolders_Det) GetPakFolders_Det->unHook();
    }
    
    void HookManager::GetPakFolders(const TCHAR* CmdLine, TArray<FString>* OutPakFolders)
    {
        reinterpret_cast<void (*)(const TCHAR*, TArray<FString>*)>(Trampoline)(CmdLine, OutPakFolders);

        try
        {
            UnrealOffsets::InitializeGMalloc();
        }
        catch (const std::exception& e)
        {
            Output::send<LogLevel::Error>(STR("[WorkshopPaksLoader] Failed to initialize GMalloc early: {}\n"), RC::to_generic_string(e.what()));
            return;
        }
        
        for (const auto& folder : pakFolders)
        {
            std::wstring folderSlash = folder.generic_wstring() + L"/";
            
            bool present = false;
            for (const auto& existing : *OutPakFolders) present = present || (std::wcscmp(*existing, folderSlash.c_str()) == 0);
            if (present) continue;
            
            OutPakFolders->Add(FString(folderSlash.c_str()));
            Output::send<LogLevel::Verbose>(STR("[WorkshopPaksLoader] added pak folder {}\n"), folderSlash);
        }
    }
    
    void HookManager::SetupAlternativePakPathReader()
    {
        auto GetPakFolders_Address = SignatureManager::GetSignature("FPakPlatformFile::GetPakFolders");
        if (GetPakFolders_Address)
        {
            GetPakFolders_Det = std::make_unique<PLH::x64Detour>(reinterpret_cast<uint64_t>(GetPakFolders_Address), reinterpret_cast<uint64_t>(&GetPakFolders), &Trampoline);
            if (!GetPakFolders_Det->hook())
            {
                Output::send<LogLevel::Error>(STR("[WorkshopPaksLoader] failed to hook GetPakFolders\n"));
                GetPakFolders_Det.reset();
                return;
            }
        }
        else
        {
            Output::send<LogLevel::Error>(STR("[WorkshopPaksLoader] Unable to setup additional .pak read directory, signature for FPakPlatformFile::GetPakFolders is outdated.\n"));
        }
    }

    WorkshopPakLoader::WorkshopPakLoader() {
        ModName = STR("WorkshopPaksLoader");
        ModVersion = STR("1.0");
        ModDescription = STR("Allows Paks to be loaded from steam workshop folders.");
        ModAuthors = STR("Diyagi");

        SignatureManager::Initialize();
        UnrealOffsets::Initialize();
        BuildPakFolders();
        HookManager::Init();
    }

    WorkshopPakLoader::~WorkshopPakLoader() {
        HookManager::Destroy();
    }

    void WorkshopPakLoader::BuildPakFolders()
    {
        std::vector<std::filesystem::path> workshop_mods = UE4SSProgram::get_program().get_workshop_mods_directories();

        if (workshop_mods.empty())
            return;
        
        for (const auto& mod : workshop_mods)
        {
            std::error_code ec{};
            for (const auto& item : std::filesystem::directory_iterator(mod, std::filesystem::directory_options::skip_permission_denied, ec))
            {
                if (!item.is_directory(ec)) continue;
                
                for (const wchar_t* name : {L"PatchPaks", L"LogicPaks"})
                {
                    std::filesystem::path p = item.path() / name;
                    if (std::filesystem::is_directory(p, ec) && !std::filesystem::is_empty(p)) 
                    pakFolders.push_back(p);
                }
            }
        }
    }
}
