# Stealthy DLL Injection via Native API

This project demonstrates a method for DLL injection into a remote process using undocumented Windows Native API functions (`ntdll.dll`). The technique avoids standard Win32 API calls like `CreateRemoteThread` and `GetProcAddress` to remain stealthy and bypass common detection mechanisms.

## Key Features

-   **Process Handle Acquisition:** Uses `NtOpenProcess` instead of `OpenProcess`.
-   **Memory Management:** Employs `NtAllocateVirtualMemory` and `NtWriteVirtualMemory` for remote memory operations.
-   **Remote Thread Creation:** Leverages the powerful `NtCreateThreadEx` function.
-   **Manual Address Resolution:** Manually parses the PEB and a module's Export Address Table to find function addresses without calling `GetModuleHandle` or `GetProcAddress`.

## Further Reading

For a detailed, step-by-step explanation of how this code works and the concepts behind it, please read the full article:

**[DLL Injection Explained: A Deep Dive into Stealth Techniques](https://portfolio-three-alpha-27.vercel.app/Blogs/dll-injection )**
