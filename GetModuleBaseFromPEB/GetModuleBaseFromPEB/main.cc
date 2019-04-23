#include "Includes.h"

//#define GETX86
//#define GETX64
//#define GETPROCESSBASE

ULONG64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name) {
	PPEB pPeb = (PPEB)PsGetProcessPeb(proc); // get Process PEB, function is unexported and undoc

	if (!pPeb) {
		return 0; // failed
	}

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr) {
		KeUnstackDetachProcess(&state);
		return 0; // failed
	}

	UNICODE_STRING name;

	// loop the linked list
	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink;
		list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink) {
		PLDR_DATA_TABLE_ENTRY pEntry =
			CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) ==
			0) {
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}

	KeUnstackDetachProcess(&state);

	return 0; // failed
}

ULONG GetModuleBasex86(PEPROCESS proc, UNICODE_STRING module_name) {
	PPEB32 pPeb = (PPEB32)PsGetProcessWow64Process(proc);// get Process PEB for the x86 part, function is unexported and undoc

	if (!pPeb) {
		return 0; // failed
	}

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA32 pLdr = (PPEB_LDR_DATA32)pPeb->Ldr;

	if (!pLdr) {
		KeUnstackDetachProcess(&state);
		return 0; // failed
	}

	UNICODE_STRING name;

	// loop the linked list
	for (PLIST_ENTRY32 list = (PLIST_ENTRY32)pLdr->InLoadOrderModuleList.Flink;
		list != &pLdr->InLoadOrderModuleList; list = (PLIST_ENTRY32)list->Flink) {
		PLDR_DATA_TABLE_ENTRY32 pEntry =
			CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
		// since the PEB is x86, the DLL is x86, and so the base address is in x86 (4 byte as compared to 8 byte)
		// and the UNICODE STRING is in 32 bit(UNICODE_STRING32), and because there is no viable conversion
		// we are just going to force everything in.
		// believe me it works.
		UNICODE_STRING DLLname;
		DLLname.Length = pEntry->BaseDllName.Length;
		DLLname.MaximumLength = pEntry->BaseDllName.MaximumLength;
		DLLname.Buffer = (PWCH)pEntry->BaseDllName.Buffer;

		if (RtlCompareUnicodeString(&DLLname, &module_name, TRUE) ==
			0) {
			ULONG baseAddr = pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}

	KeUnstackDetachProcess(&state);

	return 0; // failed
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT obj, PUNICODE_STRING path)
{
	DWORD TargetPID = 4; // TODO: add your method of getting r3 pid
	PEPROCESS TargetProcess;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)TargetPID, &TargetProcess);

#ifdef GETX86
	UNICODE_STRING DLLName;
	RtlInitUnicodeString(&DLLName, L"Somex86.dll");
	ULONG BaseAddr = GetModuleBasex86(TargetProcess, DLLName); // this contains the base addr of the module u are lookingh for


#endif // GETX86

#ifdef GETX64
	UNICODE_STRING DLLName;
	RtlInitUnicodeString(&DLLName, L"Somex64.dll");
	ULONG64 BaseAddr = GetModuleBasex64(TargetProcess, DLLName); // this contains the base addr of the module u are looking for
#endif // GETX64


#ifdef GETPROCESSBASE
	ULONG64 ProcessBase = (ULONG_PTR)PsGetProcessSectionBaseAddress(TargetProcess);
#endif // GETPROCESSBASE



	return STATUS_UNSUCCESSFUL; // too lazy to implement unload functions, so just exit.
}
