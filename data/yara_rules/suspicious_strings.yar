rule ProcessInjection {
    meta:
        description = "Detects common process injection API patterns"
        severity = "high"
        category = "process_injection"
    strings:
        $api1 = "CreateRemoteThread" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "VirtualAllocEx" ascii wide
        $api4 = "NtMapViewOfSection" ascii wide
    condition:
        2 of them
}

rule ShellExecution {
    meta:
        description = "Detects shell and script execution references"
        severity = "medium"
        category = "script_exec"
    strings:
        $s1 = "powershell" ascii wide nocase
        $s2 = "cmd.exe" ascii wide nocase
        $s3 = "WScript.Shell" ascii wide
        $s4 = "/bin/sh" ascii
        $s5 = "/bin/bash" ascii
    condition:
        2 of them
}

rule SuspiciousNetwork {
    meta:
        description = "Detects suspicious network indicators"
        severity = "medium"
        category = "network"
    strings:
        $url = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(\/\S*)?/ ascii
        $socket = "WSAStartup" ascii wide
        $connect = "InternetOpenA" ascii wide
    condition:
        $url and ($socket or $connect)
}

rule AntiAnalysis {
    meta:
        description = "Detects anti-analysis and evasion techniques"
        severity = "high"
        category = "anti_analysis"
    strings:
        $dbg1 = "IsDebuggerPresent" ascii wide
        $dbg2 = "CheckRemoteDebuggerPresent" ascii wide
        $dbg3 = "NtQueryInformationProcess" ascii wide
        $vm1 = "VMwareVMware" ascii
        $vm2 = "VBoxGuest" ascii
        $ptrace = "ptrace" ascii
    condition:
        2 of them
}

rule MemoryManipulation {
    meta:
        description = "Detects suspicious memory manipulation"
        severity = "high"
        category = "memory_exec"
    strings:
        $api1 = "VirtualAlloc" ascii wide
        $api2 = "VirtualProtect" ascii wide
        $api3 = "RtlMoveMemory" ascii wide
        $api4 = "mach_vm_write" ascii
        $api5 = "mprotect" ascii
    condition:
        2 of them
}
