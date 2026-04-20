// HexCore built-in rules — anti-VM / anti-sandbox detection
// Toggle: hexcore.yara.builtinRulesEnabled (default true)
//
// Detects:
//   - VM product strings (VMware, VirtualBox, Hyper-V, Parallels, QEMU, Xen)
//   - CPUID opcode for hypervisor bit detection
//   - Registry paths checked for VM presence
//   - GetComputerName + VM string combo

rule AntiVM_VMware_Strings
{
    meta:
        description = "Contains VMware-related strings — VM detection"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiVM"
    strings:
        $s1 = "VMware" nocase
        $s2 = "VMTools" nocase
        $s3 = "vmtoolsd" nocase
        $s4 = "VMwareService" nocase
        $s5 = "VBoxService" nocase
    condition:
        any of them
}

rule AntiVM_VirtualBox_Strings
{
    meta:
        description = "Contains VirtualBox-related strings — VM detection"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiVM"
    strings:
        $s1 = "VBOX" nocase
        $s2 = "VirtualBox" nocase
        $s3 = "VBoxGuest"
        $s4 = "VBoxMouse"
        $s5 = "VBoxSF"
        $s6 = "VBoxVideo"
    condition:
        any of them
}

rule AntiVM_HyperV_Strings
{
    meta:
        description = "Contains Hyper-V-related strings — VM detection"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiVM"
    strings:
        $s1 = "Hyper-V" nocase
        $s2 = "HyperV" nocase
        $s3 = "vmbus"
    condition:
        any of them
}

rule AntiVM_Generic_Virtual_Strings
{
    meta:
        description = "Contains generic virtualization indicator strings"
        severity = "medium"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiVM"
    strings:
        $s1 = "QEMU" nocase
        $s2 = "Parallels" nocase
        $s3 = "VIRTUAL" nocase
        $s4 = "Xen" nocase
        $s5 = "bochs" nocase
        $s6 = "KVM" nocase
    condition:
        any of them
}

rule AntiVM_Registry_VBox
{
    meta:
        description = "References VirtualBox registry path — anti-VM sandbox check"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiVM"
    strings:
        $reg1 = "SOFTWARE\\VirtualBox Guest Additions" nocase ascii
        $reg2 = "SOFTWARE\\VirtualBox Guest Additions" nocase wide
        $reg3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase
        $reg4 = "HARDWARE\\ACPI\\DSDT\\VBOX__" nocase
    condition:
        any of them
}

rule AntiVM_Registry_VMware
{
    meta:
        description = "References VMware registry path — anti-VM sandbox check"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiVM"
    strings:
        $reg1 = "SOFTWARE\\VMware, Inc.\\VMware Tools" nocase ascii
        $reg2 = "SOFTWARE\\VMware, Inc.\\VMware Tools" nocase wide
        $reg3 = "SYSTEM\\CurrentControlSet\\Services\\VMTools" nocase
        $reg4 = "SYSTEM\\ControlSet001\\Services\\vmci" nocase
    condition:
        any of them
}

rule AntiVM_CPUID_Opcode
{
    meta:
        description = "Uses cpuid instruction — often for hypervisor bit detection (leaf 1 ECX bit 31)"
        severity = "medium"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiVM"
    strings:
        // cpuid: 0F A2
        $cpuid = { 0F A2 }
    condition:
        $cpuid
}

rule AntiVM_VMCALL_Opcode
{
    meta:
        description = "Uses vmcall instruction — direct hypervisor interaction"
        severity = "critical"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiVM"
    strings:
        // vmcall: 0F 01 C1
        $vmcall = { 0F 01 C1 }
    condition:
        $vmcall
}

rule AntiVM_GetComputerName_With_VMstrings
{
    meta:
        description = "Imports GetComputerName + contains VM strings — hostname-based VM detection"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiVM"
    strings:
        $api1 = "GetComputerNameA"
        $api2 = "GetComputerNameW"
        $api3 = "GetComputerNameExA"
        $api4 = "GetComputerNameExW"
        $vm1 = "VBox" nocase
        $vm2 = "VMware" nocase
        $vm3 = "SANDBOX" nocase
        $vm4 = "MALTEST" nocase
    condition:
        any of ($api*) and any of ($vm*)
}

rule AntiVM_Driver_Names
{
    meta:
        description = "References VM driver file names"
        severity = "medium"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiVM"
    strings:
        $s1 = "vboxguest.sys" nocase
        $s2 = "vmci.sys" nocase
        $s3 = "vmhgfs.sys" nocase
        $s4 = "vmmemctl.sys" nocase
        $s5 = "vmouse.sys" nocase
        $s6 = "vmx_svga.sys" nocase
    condition:
        any of them
}
