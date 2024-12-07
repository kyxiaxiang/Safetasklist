using System;
using System.Diagnostics;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;

class Program
{
    static void Main()
    {
        // Keywords
        string[] dllKeywords = new string[] 
        {
            "InProcessClient*", "bdhkm*", "atcuf*", "FlexHook*", "SBA_ISWWH*", 
            "cphnt*", "nddPrint.Agent.SpoolMonitor*", "cphusr*", "umppc*", "CsXumd*",
            "mfehcinj*", "mfehcthe*", "mvcairo*", "mfedeeprem*", "TmUmEvt*",
            "tmmon*", "TmUmSnsr*", "qmhookhelper*", "qmdlphook*", "libcimudisk*", "SafeBase*", "LHShield*"
        };

        // Network DLLs to monitor
        string[] networkDlls = new string[] { "wininet.dll", "winhttp.dll", "ws2_32.dll" };

        // Processes to exclude from monitoring
        string[] excludeProcesses = new string[]
        {
            "AddInProcess", "AddInProcess32", "AddInUtil", "AppLaunch",
            "aspnet_compiler", "aspnet_regbrowsers", "aspnet_regiis", "aspnet_regsql",
            "aspnet_state", "aspnet_wp", "CasPol", "ComSvcConfig", "csc", "cvtres",
            "DataSvcUtil", "EdmGen", "ilasm", "InstallUtil", "jsc", "Microsoft.Workflow.Compiler",
            "MSBuild", "mscorsvw", "ngen", "ngentask", "RegAsm", "RegSvcs", "ServiceModelReg",
            "vbc", "WsatConfig", "dllhost", "regsvr32", "GPUpdate", "SearchProtocolHost",
            "msiexec", "rundll32", "dwm", "lsass", "taskhostw", "vmtoolsd"
        };

        // Get all processes
        var processes = Process.GetProcesses();

        // Lists to store processes that meet OPSEC criteria for PE and .NET processes
        List<ProcessInfo> opsecPeProcesses = new List<ProcessInfo>();
        List<ProcessInfo> opsecNetProcesses = new List<ProcessInfo>();
        List<ProcessInfo> opsecAttentionProcesses = new List<ProcessInfo>();

        // List to store information about all processes
        List<ProcessInfo> allProcesses = new List<ProcessInfo>();

        foreach (var process in processes)
        {
            try
            {
                string processName = process.ProcessName;
                int processId = process.Id;

                // Skip excluded processes
                if (excludeProcesses.Contains(processName, StringComparer.OrdinalIgnoreCase))
                    continue;

                var status = GetProcessStatus(process, dllKeywords);
                var type = GetProcessType(process);
                var networkDllStatus = GetNetworkDllStatus(process, networkDlls);
                var privilege = GetProcessPrivilege(process);

                // Add process information to the list
                allProcesses.Add(new ProcessInfo
                {
                    ProcessId = processId,
                    ProcessName = processName,
                    Status = status,
                    Type = type,
                    NetworkDllStatus = networkDllStatus,
                    Privilege = privilege
                });

                // If the process meets OPSEC rules, classify and store it
                if ((type == "[PE]" && status == "[Safe]" && networkDllStatus == "[Loaded]") || 
                    (type == "[.NET]" && status == "[Safe]" && networkDllStatus == "[Loaded]"))
                {
                    if (type == "[PE]")
                    {
                        opsecPeProcesses.Add(new ProcessInfo
                        {
                            ProcessId = processId,
                            ProcessName = processName,
                            Status = status,
                            Type = type,
                            NetworkDllStatus = networkDllStatus,
                            Privilege = privilege
                        });
                    }
                    else if (type == "[.NET]")
                    {
                        opsecNetProcesses.Add(new ProcessInfo
                        {
                            ProcessId = processId,
                            ProcessName = processName,
                            Status = status,
                            Type = type,
                            NetworkDllStatus = networkDllStatus,
                            Privilege = privilege
                        });
                    }
                }
                // New condition: Safe but no network DLL loaded
                else if (status == "[Safe]" && networkDllStatus == "[Not Loaded]")
                {
                    opsecAttentionProcesses.Add(new ProcessInfo
                    {
                        ProcessId = processId,
                        ProcessName = processName,
                        Status = status,
                        Type = type,
                        NetworkDllStatus = networkDllStatus,
                        Privilege = privilege
                    });
                }
            }
            catch (Exception)
            {
                // If unable to fetch process information, mark as unknown
                var processId = process.Id;
                allProcesses.Add(new ProcessInfo
                {
                    ProcessId = processId,
                    ProcessName = process.ProcessName,
                    Status = "[Unknown]",
                    Type = "[Unknown]",
                    NetworkDllStatus = "[Unknown]",
                    Privilege = "[Unknown]"
                });
            }
        }

        // Output information about all processes
        Console.WriteLine("\n[All Processes]:");
        Console.WriteLine("{0,-10} {1,-30} {2,-10} {3,-10} {4,-15} {5}", 
            "PID", "ProcessName", "Status", "Type", "NetworkDllStatus", "Privilege");
        foreach (var process in allProcesses)
        {
            Console.WriteLine("{0,-10} {1,-30} {2,-10} {3,-10} {4,-15} {5}", 
                process.ProcessId, process.ProcessName, process.Status, process.Type, process.NetworkDllStatus, process.Privilege);
        }

        // Output PE processes that meet OPSEC criteria
        Console.WriteLine("\n[OPSEC] PE Processes (with network DLLs loaded):");
        Console.WriteLine("{0,-10} {1,-30} {2,-10} {3,-10} {4,-15} {5}", 
            "PID", "ProcessName", "Status", "Type", "NetworkDllStatus", "Privilege");
        foreach (var process in opsecPeProcesses)
        {
            Console.WriteLine("{0,-10} {1,-30} {2,-10} {3,-10} {4,-15} {5}", 
                process.ProcessId, process.ProcessName, process.Status, process.Type, process.NetworkDllStatus, process.Privilege);
        }

        // Output .NET processes that meet OPSEC criteria
        Console.WriteLine("\n[OPSEC] .NET Processes (with network DLLs loaded):");
        Console.WriteLine("{0,-10} {1,-30} {2,-10} {3,-10} {4,-15} {5}", 
            "PID", "ProcessName", "Status", "Type", "NetworkDllStatus", "Privilege");
        foreach (var process in opsecNetProcesses)
        {
            Console.WriteLine("{0,-10} {1,-30} {2,-10} {3,-10} {4,-15} {5}", 
                process.ProcessId, process.ProcessName, process.Status, process.Type, process.NetworkDllStatus, process.Privilege);
        }
        // Output Attention processes that meet OPSEC criteria (Safe but no network DLLs loaded)
        Console.WriteLine("\n[OPSEC & Attention] Processes (Safe but no network DLLs loaded):");
        Console.WriteLine("{0,-10} {1,-30} {2,-10} {3,-10} {4,-15} {5}", 
            "PID", "ProcessName", "Status", "Type", "NetworkDllStatus", "Privilege");
        foreach (var process in opsecAttentionProcesses)
        {
            Console.WriteLine("{0,-10} {1,-30} {2,-10} {3,-10} {4,-15} {5}", 
                process.ProcessId, process.ProcessName, process.Status, process.Type, process.NetworkDllStatus, process.Privilege);
        }
    }

    // Determine the process status based on modules loaded
    static string GetProcessStatus(Process process, string[] dllKeywords)
    {
        try
        {
            var modules = process.Modules.Cast<ProcessModule>().Select(m => m.ModuleName).ToList();

            foreach (var keyword in dllKeywords)
            {
                bool isMatching = modules.Any(m => System.Text.RegularExpressions.Regex.IsMatch(m, keyword.Replace("*", ".*")));
                if (isMatching)
                {
                    return "[Unsafe]";
                }
            }

            return "[Safe]";
        }
        catch (Exception)
        {
            return "[Unknown]";
        }
    }

    // Determine the process type: .NET or PE
    static string GetProcessType(Process process)
    {
        try
        {
            var modules = process.Modules.Cast<ProcessModule>().Select(m => m.ModuleName).ToList();

            if (modules.Any(m => m.Equals("mscoree.dll", StringComparison.OrdinalIgnoreCase)))
            {
                return "[.NET]";
            }

            return "[PE]";
        }
        catch (Exception)
        {
            return "[Unknown]";
        }
    }

    // Check if the process has loaded network DLLs
    static string GetNetworkDllStatus(Process process, string[] networkDlls)
    {
        try
        {
            var modules = process.Modules.Cast<ProcessModule>().Select(m => m.ModuleName).ToList();

            foreach (var dll in networkDlls)
            {
                if (modules.Contains(dll, StringComparer.OrdinalIgnoreCase))
                {
                    return "[Loaded]";
                }
            }

            return "[Not Loaded]";
        }
        catch (Exception)
        {
            return "[Unknown]";
        }
    }

    // Check the process privilege level
    static string GetProcessPrivilege(Process process)
    {
        try
        {
            return IsProcessElevated(process) ? "[Elevated]" : "[Normal]";
        }
        catch (Exception)
        {
            return "[Unknown]";
        }
    }

    // Check if the process has elevated privileges (admin rights)
    static bool IsProcessElevated(Process process)
    {
        IntPtr tokenHandle = IntPtr.Zero;

        try
        {
            if (!OpenProcessToken(process.Handle, 0x0008, out tokenHandle))
            {
                return false;
            }

            var tokenElevation = new TOKEN_ELEVATION();
            int returnLength = 0;

            if (!GetTokenInformation(tokenHandle, TokenInformationClass.TokenElevation, out tokenElevation, Marshal.SizeOf(tokenElevation), out returnLength))
            {
                return false;
            }

            return tokenElevation.TokenIsElevated > 0;
        }
        finally
        {
            if (tokenHandle != IntPtr.Zero)
            {
                CloseHandle(tokenHandle);
            }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr hProcess, uint dwDesiredAccess, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr hToken, TokenInformationClass tokenInfoClass, out TOKEN_ELEVATION tokenInformation, int tokenInformationLength, out int returnLength);

    // Enum for process access flags
    [Flags]
    public enum ProcessAccessFlags : uint
    {
        QueryInformation = 0x0400, // Flag to query process information
    }

    // Enum for token information classes
    public enum TokenInformationClass
    {
        TokenElevation = 20 // Information class for token elevation
    }

    // Struct to store token elevation information
    public struct TOKEN_ELEVATION
    {
        public uint TokenIsElevated;
    }

    // Class to store process information
    class ProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string Status { get; set; }
        public string Type { get; set; }
        public string NetworkDllStatus { get; set; }
        public string Privilege { get; set; }
    }
}
