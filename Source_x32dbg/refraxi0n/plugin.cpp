#include "plugin.h"

#include <vector>
#include <xstring>
#include <cinttypes>


// ----------------------------------------------------------------------------


typedef std::vector<intptr_t> Pointers_t;


// ----------------------------------------------------------------------------


bool FindReferencesToPointer(const MEMPAGE& memPage, const intptr_t memoryPointer, Pointers_t& out)
{
	out.clear();

	for (size_t i = 0; i < memPage.mbi.RegionSize; i += sizeof(void*))
	{
		auto currentPtr = (intptr_t)memPage.mbi.BaseAddress + i;

		/// Must be a double pointer
		const duint functionPtr = Script::Memory::ReadPtr(currentPtr);
		if (!functionPtr)
		{
			continue;
		}

		///
		/// It's a pointer. But does it also point to our data?
		///
		if (functionPtr != memoryPointer)
		{
			continue;
		}

		out.push_back( currentPtr );
	}

	return out.empty() == false;
}


const MEMPAGE* GetBaseAddressAndSizeOfMemmapOfPointer(const MEMMAP& memmap, const intptr_t memoryPointer)
{
	for (auto i = 0; i < memmap.count; i++)
	{
		const MEMPAGE& mempage = memmap.page[i];
		if (memoryPointer >= (intptr_t)mempage.mbi.BaseAddress)
		{
			const intptr_t mempageEnd = (intptr_t)mempage.mbi.BaseAddress + mempage.mbi.RegionSize;
			const intptr_t memoryDiff = mempageEnd - memoryPointer;
			if (memoryDiff > 0)
			{
				return &mempage;
			}
		}
	}

	return nullptr;
}


// ----------------------------------------------------------------------------


static bool cbCommand(int argc, char* argv[])
{
	char messageLine[256] = { 0 };


	/// Alternative, in case the active window is the Disassembly: Script::Gui::Disassembly::SelectionGetStart();
    const uintptr_t memoryLocationForPossibleIAT = Script::Gui::Dump::SelectionGetStart();


	///
	/// Support finding pointers to the IAT table(s)
	///
	uintptr_t iatReferenceLocation = memoryLocationForPossibleIAT;
	if (argc > 1)
	{
		iatReferenceLocation = DbgValFromString(argv[1]);
	}


	sprintf_s(
		messageLine,
		sizeof(messageLine),
		"* Will search for IAT(s) in the memory block containing 0x%" PRIxPTR " and then find references to these IAT(s) in the memory block containing 0x%" PRIxPTR "\n",
		memoryLocationForPossibleIAT,
		iatReferenceLocation
	);
	GuiAddLogMessage(messageLine);



	MEMMAP memMap;
	DbgMemMap(&memMap);



	const MEMPAGE* pMemoryMapInfoForIatPointer = GetBaseAddressAndSizeOfMemmapOfPointer(memMap, iatReferenceLocation);

	Pointers_t pointersToCurrentIAT;

	std::string descriptionString;


	const auto memoryMapInfo = GetBaseAddressAndSizeOfMemmapOfPointer(memMap, memoryLocationForPossibleIAT);

	if (!memoryMapInfo)
	{
		GuiAddLogMessage("[E] Couldn't find the memory map for the selected address\n");
		return false;
	}


	///
	/// Open result file
	///
	char modulePath[MAX_PATH] = { 0 };
	Script::Module::GetMainModulePath(modulePath);

	char resultPath[MAX_PATH] = { 0 };
	sprintf_s(resultPath, sizeof(resultPath), "%s.iat.txt", modulePath);

	const HANDLE hFile = CreateFileA(
		resultPath,
		GENERIC_WRITE,              // Desired access
		0,                          // Share mode
		NULL,                       // Security attributes
		OPEN_ALWAYS,                // Creation disposition
		FILE_ATTRIBUTE_NORMAL,      // Flags and attributes
		NULL                        // Template file
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		sprintf_s(
			messageLine,
			sizeof(messageLine),
			"[W] Couldn't open result file for write: %s\n",
			resultPath
			);

		GuiAddLogMessage(messageLine);
	}

	//const auto pMainAddr = Script::Module::GetMainModuleBase();




	///
	/// Loop through the *entire* memory map; one pointer at a time while evaluating if it's a pointer
	/// to a known label in x32dbg/x64dbg.
	///
	for (size_t i = 0; i < memoryMapInfo->mbi.RegionSize; i += sizeof(void*))
	{
		auto currentPtr = (intptr_t)memoryMapInfo->mbi.BaseAddress + i;

		/// Must be a double pointer
		const duint functionPtr = Script::Memory::ReadPtr(currentPtr);
		if (!functionPtr)
		{
			continue;
		}

		char labelAtAddress[256] = { 0 };
		DbgGetLabelAt(currentPtr, SEG_DEFAULT, labelAtAddress);
		/// We're looking for labels that x64dbg has resolved for us already
		if (labelAtAddress[0] == 0)
		{
			continue;
		}


		///
		/// A label/name was found for the data/code that the current pointer references.
		///

		char moduleNameForIAT[256] = { 0 };
		DbgGetModuleAt(currentPtr, moduleNameForIAT);


		char moduleNameFunction[256] = { 0 };
		DbgGetModuleAt(functionPtr, moduleNameFunction);

		sprintf_s(messageLine, sizeof(messageLine), "0x%" PRIxPTR " : %s.%s", currentPtr, moduleNameFunction, labelAtAddress);
		descriptionString = messageLine;

		///
		/// Try to locate any pointers to this IAT
		///
		if (pMemoryMapInfoForIatPointer)
		{
			if (FindReferencesToPointer(*pMemoryMapInfoForIatPointer, currentPtr, pointersToCurrentIAT))
			{
				descriptionString.append(" : ");

				for (auto it = pointersToCurrentIAT.cbegin(); it != pointersToCurrentIAT.cend(); it++)
				{
					if (it != pointersToCurrentIAT.cbegin())
					{
						descriptionString.append(",");
					}

					const intptr_t pIatPointer = *it;
					sprintf_s(messageLine, sizeof(messageLine), "0x%" PRIxPTR, pIatPointer);
					descriptionString.append(messageLine);
				}
			}
		}

		descriptionString.append("\n");
		GuiAddLogMessage(descriptionString.c_str());

		if (hFile != INVALID_HANDLE_VALUE)
		{
			WriteFile(hFile, descriptionString.c_str(), (DWORD)descriptionString.length(), nullptr, nullptr);
		}
	}


	GuiAddLogMessage("* Done\n");

	if (hFile != INVALID_HANDLE_VALUE)
	{
		sprintf_s(messageLine, sizeof(messageLine), "* Result file is at: %s\n", resultPath);
		GuiAddLogMessage(messageLine);

		CloseHandle(hFile);
	}

    return true;
}


// ----------------------------------------------------------------------------


bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    if (!_plugin_registercommand(pluginHandle, PLUGIN_NAME, &cbCommand, false))
	{
		_plugin_logputs("[" PLUGIN_NAME "] Error registering the \"" PLUGIN_NAME "\" command!");
	}

	return true;
}


bool pluginStop()
{
    return true;
}


void pluginSetup()
{
}
