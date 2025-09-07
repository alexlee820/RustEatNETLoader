# RustEATNETLoader

RustEATNETLoader is a exe version of RustEATNETLoader to load .NET assembly by using clroxide library .This is just a practise for me to write some rust stuff.

When writing an eat hook in Rust, many troublesome issues emerged. Due to Rust's memory protection mechanisms, the eat hook for Windows libraries encountered problems because the addresses of the Windows libraries are relatively high, while our dummy function is located at a lower position. When we attempt to change the RVA of the target function, the RVA becomes negative because the address of our dummy function is smaller than that of the Windows API we want to hook. However, since the RVA is stored using DWORD/ULONG, which only occupies 8 bytes, when the RVA we obtain is negative, it gets truncated, resulting in a positive RVA instead. Therefore, the redirection is not to our dummy function but to an incorrect location. This is why we also found that sometimes using inline-ea would cause crashes, but I haven't actually debugged it, so I'm not sure if this is the cause.

So now you might ask how we can solve this. Actually, the solution is quite simple. We just need to set up a trampoline and use some high-level library functions in Windows, such as MessageBoxA. We patch MessageBoxA to do mov rax, 1; ret; The assembly code, then change the RVA of EventWrite and AMSIscanbuffer in the eat hook to MessageBoxA minus their library base (amsi.dll and advapi32.dll), then our hook will be successful. Here, we don't need to worry. After testing, edr only temporarily monitors the patching of specific functions, so our patching won't cause an alert to appear.

This repo includes:

- EAT hook Amsi.dll!AmsiScanBuffer and advapi32!Event
- Patching MessageboxA via indirect syscall to create trampoline

Pending Improve:

- VirtualProtect in EAT hook (When I am using the NtProtectVirtualMemory , the CLR donot know why can’t run without any error. If anyone know why ,can make a pull request.)