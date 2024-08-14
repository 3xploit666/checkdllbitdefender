# Module Enumerator and Patching Tool

This Rust project is designed to enumerate loaded modules within a process, identify suspicious modules, and apply patches to functions in memory, particularly focusing on detecting and unhooking potential hooks in critical functions like `CreateRemoteThreadEx` and `NtWriteVirtualMemory`.

<p align="center">
  <img src="/assets/poc.png">
</p>


## Features

- **Module Enumeration:** Enumerates all modules loaded in the current process.
- **Suspicious Module Detection:** Detects suspicious modules by name (e.g., `atcuf64.dll`, `bdhkm64.dll`).
- **Function Hook Detection:** Checks if critical functions like `CreateRemoteThreadEx` and `NtWriteVirtualMemory` are hooked by examining the first bytes of the function.
- **Memory Patching:** Applies patches to unhook or modify functions in memory.
- **Logging with Colors:** Outputs information with color-coded messages for easy readability.

## How It Works

1. **Module Enumeration:** The program first enumerates all the modules loaded in the current process using the `EnumProcessModules` API.

2. **Detection of Suspicious Modules:** It then checks the names of these modules to see if they match any known suspicious modules, such as `atcuf64.dll` or `bdhkm64.dll`.

3. **Function Hook Detection:** For critical functions like `CreateRemoteThreadEx` and `NtWriteVirtualMemory`, the program reads the first few bytes of the function to check for signs of hooking (e.g., an `E9` opcode, indicating a JMP instruction).

4. **Unhooking and Patching:** If a hook is detected, the program can apply a patch to restore the function to its original state.

5. **Logging:** Throughout the process, the program logs its findings and actions, using color-coded messages to indicate status (e.g., green for success, red for errors).

## Getting Started

### Prerequisites

- Rust toolchain (Install from [rustup.rs](https://rustup.rs/))
- Windows operating system

### Building the Project

Clone the repository:

```bash
git clone https://github.com/3xploit666/checkdllbitdefender
cd checkdllbitdefender
cargo build
```

<p align="center">
  <img src="/assets/poc2.png">
</p>


```bash
[0] Starting module enumeration...

[+] Module loaded: kernel32.dll
[+] Module loaded: user32.dll
[!] Suspicious Modules Detected:
[API HOOK] Suspicious module detected: atcuf64.dll
[!] CreateRemoteThreadEx is hooked!
[*] Instructions at CreateRemoteThreadEx: E9 XX XX XX XX
[*] Jump target address: 0x7FFD5D2C1234
[+] Unhook successful for NtWriteVirtualMemory.
```
