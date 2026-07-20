param(
  [Parameter(Mandatory = $true)][string]$CommandBase64,
  [Parameter(Mandatory = $true)][string]$ArgumentsBase64,
  [Parameter(Mandatory = $true)][string]$WorkingDirectoryBase64
)

$ErrorActionPreference = "Stop"

# @ref LLP 0032#process-tree-termination — the wrapper joins a kill-on-close
# Job Object before it launches the evidence command, so every descendant is
# contained before repository code can run.
Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class IbexCapsecJobObject
{
    private const UInt32 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private static IntPtr job = IntPtr.Zero;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public Int64 PerProcessUserTimeLimit;
        public Int64 PerJobUserTimeLimit;
        public UInt32 LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public UInt32 ActiveProcessLimit;
        public IntPtr Affinity;
        public UInt32 PriorityClass;
        public UInt32 SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public UInt64 ReadOperationCount;
        public UInt64 WriteOperationCount;
        public UInt64 OtherOperationCount;
        public UInt64 ReadTransferCount;
        public UInt64 WriteTransferCount;
        public UInt64 OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
        UInt32 informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    public static void Initialize()
    {
        job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed");

        var information = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(
                job,
                9,
                ref information,
                (UInt32)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject failed");

        if (!AssignProcessToJobObject(job, GetCurrentProcess()))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject failed");
    }

}
"@

function Decode-Utf8([string]$Value) {
  return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value))
}

$command = Decode-Utf8 $CommandBase64
$argumentsJson = Decode-Utf8 $ArgumentsBase64
$workingDirectory = Decode-Utf8 $WorkingDirectoryBase64
$arguments = @((ConvertFrom-Json -InputObject $argumentsJson))

[IbexCapsecJobObject]::Initialize()
$childExitCode = 1
try {
  $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $command
  $startInfo.WorkingDirectory = $workingDirectory
  $startInfo.UseShellExecute = $false
  foreach ($argument in $arguments) {
    [void]$startInfo.ArgumentList.Add([string]$argument)
  }
  $child = [System.Diagnostics.Process]::Start($startInfo)
  if ($null -eq $child) {
    throw "failed to start command"
  }
  $child.WaitForExit()
  $childExitCode = $child.ExitCode
  $child.Dispose()
}
finally {
  # The wrapper is itself a member of this kill-on-close job. Keep its only
  # job handle alive until process teardown: closing it here terminates the
  # wrapper before PowerShell can preserve the child's exit status. OS process
  # teardown closes the handle and therefore still kills every descendant.
  [System.Environment]::Exit([int]$childExitCode)
}
