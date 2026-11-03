$code = @"
using System;
using System.Runtime.InteropServices;

public class WinDesktopLauncher {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    public static int LaunchOnDefaultDesktop(string exePath, string commandLine, string workingDir) {
        var si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        si.lpDesktop = @"WinSta0\Default";
        si.dwFlags = 1; // STARTF_USESHOWWINDOW
        si.wShowWindow = 5; // SW_SHOW

        var pi = new PROCESS_INFORMATION();
        bool success = CreateProcess(
            exePath,
            commandLine,
            IntPtr.Zero,
            IntPtr.Zero,
            false,
            0,
            IntPtr.Zero,
            workingDir,
            ref si,
            out pi);

        if (!success) {
            int err = Marshal.GetLastWin32Error();
            throw new System.ComponentModel.Win32Exception(err);
        }

        return pi.dwProcessId;
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'WinDesktopLauncher').Type) {
    Add-Type -TypeDefinition $code
}

$metavaultRoot = "C:\Users\Mowreez.DESKTOP-D1GHS6J\metavault"
$exePath = Join-Path $metavaultRoot "packages\app\release\win-unpacked\MetaVault OSS.exe"

$launchedPid = [WinDesktopLauncher]::LaunchOnDefaultDesktop($exePath, "`"$exePath`"", $metavaultRoot)
Write-Output "Successfully launched MetaVault OSS on WinSta0\Default with PID: $launchedPid"
Wait-Process -Id $launchedPid
