extern crate termcolor;
extern crate winapi;

use std::ffi::CString;
use std::io::Write;
use std::ptr::null_mut;
use kernel32::{GetModuleHandleA, GetProcAddress};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use winapi::ctypes::c_void;
use winapi::shared::minwindef::HINSTANCE__;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::psapi::{EnumProcessModules, GetModuleFileNameExA};

// Punto de entrada principal
fn main() {
    let process = unsafe { GetCurrentProcess() };
    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    log_message(&mut stdout, "[0] Starting module enumeration...\n", Color::White);

    match enumerate_modules(process) {
        Ok(suspicious_modules) => {
            if suspicious_modules.is_empty() {
                log_message(&mut stdout, "\nNo suspicious modules detected.", Color::Green);
            } else {
                handle_suspicious_modules(suspicious_modules, &mut stdout);
            }
        }
        Err(error_code) => {
            log_message(&mut stdout, &format!("[!] Failed to enumerate modules. Error code: {}", error_code), Color::Red);
        }
    }

    unhook_nt_write_virtual_memory(&mut stdout);
}

// Función para enumerar los módulos del proceso actual y detectar módulos sospechosos
fn enumerate_modules(process: *mut c_void) -> Result<Vec<String>, u32> {
    let mut h_mods = [null_mut(); 1024];
    let mut cb_needed: u32 = 0;

    if unsafe { EnumProcessModules(process, h_mods.as_mut_ptr(), std::mem::size_of_val(&h_mods) as u32, &mut cb_needed) } == 0 {
        return Err(unsafe { GetLastError() });
    }

    let count = cb_needed as usize / std::mem::size_of::<*mut c_void>();
    let mut suspicious_modules = Vec::new();

    for &module in &h_mods[..count] {
        if let Some(module_name) = get_module_name(process, module) {
            if module_name.contains("atcuf64.dll") || module_name.contains("bdhkm64.dll") {
                suspicious_modules.push(module_name);
            } else {
                log_message(&mut StandardStream::stdout(ColorChoice::Always), &format!("[+] Module loaded: {}", module_name), Color::White);
            }
        }
    }

    Ok(suspicious_modules)
}

// Función para obtener el nombre de un módulo
fn get_module_name(process: *mut c_void, module: *mut HINSTANCE__) -> Option<String> {
    let mut module_name = vec![0u8; 512];
    let name_length = unsafe {
        GetModuleFileNameExA(
            process,
            module,
            module_name.as_mut_ptr() as *mut i8,
            module_name.len() as u32,
        )
    };

    if name_length == 0 {
        return None;
    }

    let name_cstr = unsafe { CString::from_vec_unchecked(module_name[..name_length as usize].to_vec()) };
    Some(name_cstr.to_string_lossy().into_owned())
}

// Función para manejar módulos sospechosos detectados
fn handle_suspicious_modules(modules: Vec<String>, stdout: &mut StandardStream) {
    log_message(stdout, "\n[!] Suspicious Modules Detected:", Color::Red);

    for module in modules {
        log_message(stdout, &module, Color::Red);
        log_api_hook(&module, stdout);

        if is_function_hooked("CreateRemoteThreadEx\0", stdout) {
            log_message(stdout, "[!] CreateRemoteThreadEx is hooked!", Color::Red);
            print_instructions("CreateRemoteThreadEx\0", stdout);
            print_jump_target("CreateRemoteThreadEx\0", stdout);
        } else {
            log_message(stdout, "[+] CreateRemoteThreadEx is clean.", Color::Green);
        }

        if let Some(patched_address) = perform_patch("CreateRemoteThreadEx\0", stdout) {
            log_message(stdout, &format!("[*] Patched function address: {:?}", patched_address), Color::Yellow);
        }
    }
}

// Función para verificar si una función está enganchada
fn is_function_hooked(function_name: &str, stdout: &mut StandardStream) -> bool {
    if let Some(proc_address) = get_function_address("kernel32\0", function_name) {
        let mut buffer = [0u8; 6];
        read_memory(proc_address, &mut buffer);

        buffer[0] == 0xE9 || buffer[0] == 0xFF
    } else {
        log_message(stdout, &format!("[!] Failed to get the address of {}.", function_name), Color::Red);
        false
    }
}

// Función para obtener la dirección de una función
fn get_function_address(module_name: &str, function_name: &str) -> Option<*const c_void> {
    let handle = unsafe { GetModuleHandleA(module_name.as_ptr() as *const i8) };
    if handle.is_null() {
        return None;
    }

    let proc_address = unsafe { GetProcAddress(handle, function_name.as_ptr() as *const i8) };
    if proc_address.is_null() {
        None
    } else {
        Some(proc_address as *const c_void)
    }
}

// Función para leer la memoria de un proceso
fn read_memory(address: *const c_void, buffer: &mut [u8]) {
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len(),
            null_mut(),
        );
    }
}

// Función para escribir en la memoria de un proceso
fn write_memory(address: *mut c_void, data: &[u8]) -> bool {
    unsafe {
        WriteProcessMemory(
            GetCurrentProcess(),
            address,
            data.as_ptr() as *const c_void,
            data.len(),
            null_mut(),
        ) != 0
    }
}

// Función para parchear una función en memoria
fn perform_patch(function_name: &str, stdout: &mut StandardStream) -> Option<*const c_void> {
    if let Some(proc_address) = get_function_address("kernel32\0", function_name) {
        log_message(stdout, &format!("[*] Function address {}: {:?}", function_name, proc_address), Color::Yellow);

        let patch_data = b"\x4C\x8B\xDC\x53\x56";
        if write_memory(proc_address as *mut c_void, patch_data) {
            log_message(stdout, "[+] Patch successful.", Color::Green);
            print_instructions(function_name, stdout);
            Some(proc_address)
        } else {
            log_message(stdout, "[!] Patch failed.", Color::Red);
            None
        }
    } else {
        None
    }
}

// Función para desenganchar NtWriteVirtualMemory
fn unhook_nt_write_virtual_memory(stdout: &mut StandardStream) {
    if let Some(proc_address) = get_function_address("ntdll.dll\0", "NtWriteVirtualMemory\0") {
        log_message(stdout, &format!("[*] Function address NtWriteVirtualMemory: 0x{:X}", proc_address as usize), Color::Yellow);

        let mut buffer = [0u8; 6];
        read_memory(proc_address, &mut buffer);

        if buffer[0] == 0xE9 {
            log_message(stdout, "[!] NtWriteVirtualMemory is hooked!", Color::Red);
            log_message(stdout, &format!("[*] Current JMP instruction: {:02X?}", &buffer[..5]), Color::Yellow);

            let original_instructions = b"\x4C\x8B\xDC\x53\x56";
            if write_memory(proc_address as *mut c_void, original_instructions) {
                log_message(stdout, "[+] Unhook successful for NtWriteVirtualMemory.", Color::Green);
                print_instructions("NtWriteVirtualMemory\0", stdout);
            } else {
                log_message(stdout, "[!] Unhook failed for NtWriteVirtualMemory.", Color::Red);
            }
        } else {
            log_message(stdout, "[+] NtWriteVirtualMemory is not hooked.", Color::Green);
        }
    } else {
        log_message(stdout, "[!] Failed to get the address of NtWriteVirtualMemory.", Color::Red);
    }
}

// Función para imprimir instrucciones de una función
fn print_instructions(function_name: &str, stdout: &mut StandardStream) {
    if let Some(proc_address) = get_function_address("kernel32\0", function_name) {
        let mut buffer = [0u8; 6];
        read_memory(proc_address, &mut buffer);
        log_message(stdout, &format!("[*] Instructions at {}: {:02X?}", function_name, buffer), Color::Yellow);
        log_message(stdout, &format!("[*] Instructions (Hex): {}", hex_representation(&buffer)), Color::Yellow);
    }
}

// Función para imprimir la dirección de salto de una función enganchada
fn print_jump_target(function_name: &str, stdout: &mut StandardStream) {
    if let Some(proc_address) = get_function_address("kernel32\0", function_name) {
        let mut buffer = [0u8; 6];
        read_memory(proc_address, &mut buffer);

        if buffer[0] == 0xE9 {
            let relative_offset = i32::from_le_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]);
            let jump_address = unsafe { proc_address.offset(5).offset(relative_offset as isize) };
            log_message(stdout, &format!("[*] Jump target address: 0x{:X}", jump_address as usize), Color::Yellow);
        }
    }
}

// Función para registrar un hook de API
fn log_api_hook(module_name: &str, stdout: &mut StandardStream) {
    log_message(stdout, &format!("[API HOOK] Suspicious module detected: {}", module_name), Color::Yellow);
}

// Funcion log inform
fn log_message(stdout: &mut StandardStream, message: &str, color: Color) {
    stdout.set_color(ColorSpec::new().set_fg(Some(color))).unwrap();
    writeln!(stdout, "{}", message).unwrap();
}

// Función para generar la representación en hexadecimal de un buffer
fn hex_representation(buffer: &[u8]) -> String {
    buffer.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(" ")
}
