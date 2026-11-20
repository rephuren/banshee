// Original teaching rules. They look for benign markers, not for real malware.

rule banshee_test_marker : demo
{
    meta:
        description = "Planted marker string used by the bundled samples"
        mitre_attack = "T1027"
    strings:
        $m = "BANSHEE-TEST-MARKER-7f3a" ascii wide
    condition:
        $m
}

rule banshee_shell_dropper_script
{
    meta:
        description = "Shell script that downloads and pipes straight into a shell"
        mitre_attack = "T1059.004, T1105"
    strings:
        $dl1 = /curl\s+[^|\n]*\|\s*(sh|bash)/
        $dl2 = /wget\s+[^|\n]*-O-?\s*\|\s*(sh|bash)/
    condition:
        uint16(0) == 0x2123 and any of ($dl*)
}

rule banshee_pe_with_injection_apis
{
    meta:
        description = "Windows executable that names the classic process-injection API trio"
        mitre_attack = "T1055"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and all of them
}

rule banshee_elf_header_stub
{
    meta:
        description = "Tiny file that starts with an ELF header"
    strings:
        $x = { 7F 45 4C 46 ?? ?? 01 }
    condition:
        uint32be(0) == 0x7F454C46 and filesize < 1KB and $x
}
