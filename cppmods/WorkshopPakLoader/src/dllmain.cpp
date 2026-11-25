#include <Mod/CppUserModBase.hpp>
#include <UE4SSProgram.hpp>
#include <WorkshopPakLoader.hpp>

#define WORKSHOP_PAKS_API __declspec(dllexport)
extern "C"
{
    WORKSHOP_PAKS_API CppUserModBase* start_mod()
    {
        return new WorkshopPakLoader::WorkshopPakLoader();
    }

    WORKSHOP_PAKS_API void uninstall_mod(CppUserModBase* mod)
    {
        delete mod;
    }
}