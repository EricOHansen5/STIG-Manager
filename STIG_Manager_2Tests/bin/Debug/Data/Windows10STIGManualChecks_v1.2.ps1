<# 

    Created:  11 June 2019
    Modified: 9 September 2019
    Version:  1.2
    Purpose:  Windows 10 Manual STIG Checks

    1.0 - Created for 2019 Q2 STIG Review, based on Win10 v1r16 STIG
    1.1 - Added Self Elevate section
    1.2 - Modified for 2019 Q3, Win10 v1r18 STIG
        - Removed V-63603 (no longer in STIG)
        - Added V-94859 and V-94861 (Bitlocker PIN + PIN Length)

#>
#================== Functions =================================

    Function Test-DEP-ASLR2-Payload {Param([string]$exe)

        #Test process mitigations
        $processMitigation = Get-ProcessMitigation -Name $exe

        if($processMitigation){

            "===Process Mitigation - $exe===" | Out-File $logName -Append

            #Test DEP
            if($processMitigation.Dep.Enable -eq "ON"){
                "PASS - DEP Is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - DEP Is Disabled" | Out-File $logName -Append
            }

            #Test ASLR
            if($processMitigation.Aslr.BottomUp -eq "ON"){
                "PASS - ASLR BottomUp is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - ASLR BottomUp is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Aslr.ForceRelocateImages -eq "ON"){
                "PASS - ASLR ForceRelocateImages is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - ASLR ForceRelocateImages is Disabled" | Out-File $logName -Append
            }

            #Test Payload
            if($processMitigation.Payload.EnableExportAddressFilter -eq "ON"){
                "PASS - Payload EnableExportAddressFilter is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableExportAddressFilter is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON"){
                "PASS - Payload EnableExportAddressFilterPlus is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableExportAddressFilterPlus is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableImportAddressFilter -eq "ON"){
                "PASS - Payload EnableImportAddressFilter is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableImportAddressFilter is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopStackPivot -eq "ON"){
                "PASS - Payload EnableRopStackPivot is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopStackPivot is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopCallerCheck -eq "ON"){
                "PASS - Payload EnableRopCallerCheck is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopCallerCheck is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopSimExec -eq "ON"){
                "PASS - Payload EnableRopSimExec is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopSimExec is Disabled" | Out-File $logName -Append
            }
        }else{
            "N/A - $exe Not Present" | Out-File $logName -Append
        }

    }

    Function Test-DEP-ASLR-Payload {Param([string]$exe)

        #Test process mitigations
        $processMitigation = Get-ProcessMitigation -Name $exe

        if($processMitigation){

            "===Process Mitigation - $exe===" | Out-File $logName -Append

            #Test DEP
            if($processMitigation.Dep.Enable -eq "ON"){
                "PASS - DEP Is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - DEP Is Disabled" | Out-File $logName -Append
            }

            #Test ASLR
            if($processMitigation.Aslr.ForceRelocateImages -eq "ON"){
                "PASS - ASLR ForceRelocateImages is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - ASLR ForceRelocateImages is Disabled" | Out-File $logName -Append
            }

            #Test Payload
            if($processMitigation.Payload.EnableExportAddressFilter -eq "ON"){
                "PASS - Payload EnableExportAddressFilter is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableExportAddressFilter is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON"){
                "PASS - Payload EnableExportAddressFilterPlus is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableExportAddressFilterPlus is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableImportAddressFilter -eq "ON"){
                "PASS - Payload EnableImportAddressFilter is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableImportAddressFilter is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopStackPivot -eq "ON"){
                "PASS - Payload EnableRopStackPivot is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopStackPivot is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopCallerCheck -eq "ON"){
                "PASS - Payload EnableRopCallerCheck is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopCallerCheck is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopSimExec -eq "ON"){
                "PASS - Payload EnableRopSimExec is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopSimExec is Disabled" | Out-File $logName -Append
            }
        }else{
            "N/A - $exe Not Present" | Out-File $logName -Append
        }

    }

    Function Test-DEP-Payload {Param([string]$exe)

        #Test process mitigations
        $processMitigation = Get-ProcessMitigation -Name $exe

        if($processMitigation){

            "===Process Mitigation - $exe===" | Out-File $logName -Append

            #Test DEP
            if($processMitigation.Dep.Enable -eq "ON"){
                "PASS - DEP Is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - DEP Is Disabled" | Out-File $logName -Append
            }

            #Test Payload
            if($processMitigation.Payload.EnableExportAddressFilter -eq "ON"){
                "PASS - Payload EnableExportAddressFilter is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableExportAddressFilter is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON"){
                "PASS - Payload EnableExportAddressFilterPlus is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableExportAddressFilterPlus is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableImportAddressFilter -eq "ON"){
                "PASS - Payload EnableImportAddressFilter is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableImportAddressFilter is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopStackPivot -eq "ON"){
                "PASS - Payload EnableRopStackPivot is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopStackPivot is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopCallerCheck -eq "ON"){
                "PASS - Payload EnableRopCallerCheck is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopCallerCheck is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopSimExec -eq "ON"){
                "PASS - Payload EnableRopSimExec is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopSimExec is Disabled" | Out-File $logName -Append
            }
        }else{
            "N/A - $exe Not Present" | Out-File $logName -Append
        }

    }

    Function Test-DEP-ASLR-ImageLoad-Payload {Param([string]$exe)

        #Test process mitigations
        $processMitigation = Get-ProcessMitigation -Name $exe

        if($processMitigation){

            "===Process Mitigation - $exe===" | Out-File $logName -Append

            #Test DEP
            if($processMitigation.Dep.Enable -eq "ON"){
                "PASS - DEP Is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - DEP Is Disabled" | Out-File $logName -Append
            }

            #Test ASLR
            if($processMitigation.Aslr.ForceRelocateImages -eq "ON"){
                "PASS - ASLR ForceRelocateImages is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - ASLR ForceRelocateImages is Disabled" | Out-File $logName -Append
            }

            #Test ImageLoad
            if($processMitigation.ImageLoad.BlockRemoteImageLoads -eq "ON"){
                "PASS - ImageLoad BlockRemoteImageLoads is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - ImageLoad BlockRemoteImageLoads is Disabled" | Out-File $logName -Append
            }

            #Test Payload
            if($processMitigation.Payload.EnableExportAddressFilter -eq "ON"){
                "PASS - Payload EnableExportAddressFilter is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableExportAddressFilter is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON"){
                "PASS - Payload EnableExportAddressFilterPlus is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableExportAddressFilterPlus is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableImportAddressFilter -eq "ON"){
                "PASS - Payload EnableImportAddressFilter is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableImportAddressFilter is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopStackPivot -eq "ON"){
                "PASS - Payload EnableRopStackPivot is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopStackPivot is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopCallerCheck -eq "ON"){
                "PASS - Payload EnableRopCallerCheck is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopCallerCheck is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopSimExec -eq "ON"){
                "PASS - Payload EnableRopSimExec is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopSimExec is Disabled" | Out-File $logName -Append
            }
        }else{
            "N/A - $exe Not Present" | Out-File $logName -Append
        }

    }

    Function Test-DEP-PayloadLess {Param([string]$exe)

        #Test process mitigations
        $processMitigation = Get-ProcessMitigation -Name $exe

        if($processMitigation){

            "===Process Mitigation - $exe===" | Out-File $logName -Append

            #Test DEP
            if($processMitigation.Dep.Enable -eq "ON"){
                "PASS - DEP Is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - DEP Is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopStackPivot -eq "ON"){
                "PASS - Payload EnableRopStackPivot is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopStackPivot is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopCallerCheck -eq "ON"){
                "PASS - Payload EnableRopCallerCheck is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopCallerCheck is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopSimExec -eq "ON"){
                "PASS - Payload EnableRopSimExec is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopSimExec is Disabled" | Out-File $logName -Append
            }
        }else{
            "N/A - $exe Not Present" | Out-File $logName -Append
        }

    }

    Function Test-DEP {Param([string]$exe)

        #Test process mitigations
        $processMitigation = Get-ProcessMitigation -Name $exe

        if($processMitigation){

            "===Process Mitigation - $exe===" | Out-File $logName -Append

            #Test DEP
            if($processMitigation.Dep.Enable -eq "ON"){
                "PASS - DEP Is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - DEP Is Disabled" | Out-File $logName -Append
            }

        }else{
            "N/A - $exe Not Present" | Out-File $logName -Append
        }

    }

    Function Test-DEP-ASLR2 {Param([string]$exe)

        #Test process mitigations
        $processMitigation = Get-ProcessMitigation -Name $exe

        if($processMitigation){

            "===Process Mitigation - $exe===" | Out-File $logName -Append

            #Test DEP
            if($processMitigation.Dep.Enable -eq "ON"){
                "PASS - DEP Is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - DEP Is Disabled" | Out-File $logName -Append
            }

            #Test ASLR
            if($processMitigation.Aslr.BottomUp -eq "ON"){
                "PASS - ASLR BottomUp is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - ASLR BottomUp is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Aslr.ForceRelocateImages -eq "ON"){
                "PASS - ASLR ForceRelocateImages is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - ASLR ForceRelocateImages is Disabled" | Out-File $logName -Append
            }
        }else{
            "N/A - $exe Not Present" | Out-File $logName -Append
        }

    }

    Function Test-DEP-ImageLoad-Payload {Param([string]$exe)

        #Test process mitigations
        $processMitigation = Get-ProcessMitigation -Name $exe

        if($processMitigation){

            "===Process Mitigation - $exe===" | Out-File $logName -Append

            #Test DEP
            if($processMitigation.Dep.Enable -eq "ON"){
                "PASS - DEP Is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - DEP Is Disabled" | Out-File $logName -Append
            }

            #Test ImageLoad
            if($processMitigation.ImageLoad.BlockRemoteImageLoads -eq "ON"){
                "PASS - ImageLoad BlockRemoteImageLoads is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - ImageLoad BlockRemoteImageLoads is Disabled" | Out-File $logName -Append
            }

            #Test Payload
            if($processMitigation.Payload.EnableExportAddressFilter -eq "ON"){
                "PASS - Payload EnableExportAddressFilter is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableExportAddressFilter is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON"){
                "PASS - Payload EnableExportAddressFilterPlus is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableExportAddressFilterPlus is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableImportAddressFilter -eq "ON"){
                "PASS - Payload EnableImportAddressFilter is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableImportAddressFilter is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopStackPivot -eq "ON"){
                "PASS - Payload EnableRopStackPivot is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopStackPivot is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopCallerCheck -eq "ON"){
                "PASS - Payload EnableRopCallerCheck is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopCallerCheck is Disabled" | Out-File $logName -Append
            }

            if($processMitigation.Payload.EnableRopSimExec -eq "ON"){
                "PASS - Payload EnableRopSimExec is Enabled" | Out-File $logName -Append
            }else{
                "FAIL - Payload EnableRopSimExec is Disabled" | Out-File $logName -Append
            }
        }else{
            "N/A - $exe Not Present" | Out-File $logName -Append
        }

    }

#================== End Functions =============================

# Self-elevate the script and pass off the script into the new elevated window
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
    Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
    Exit
}

#Create logfile
$logName = "C:\Win10ManualSTIG_$(hostname)_$(get-date -f yyyy-MM-dd).txt"

#Clear current log if present with same name and machine name
hostname | Out-File $logName

#Insert current date
Get-Date | Out-File $logName -Append

#Begin STIG Checks

# Vuln ID V-63323
# Domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.
    "=====Vuln ID V-63323=====" | Out-File $logName -Append
    
    #Test if TPM is present
    $tpmPresent = Get-Tpm | select -ExpandProperty TpmPresent
    if ($tpmPresent){
        "PASS - TPM Present" | Out-File $logName -Append
    }else{
        "FAIL - TPM Not Present" | Out-File $logName -Append
    }

    #Test if TPM is at least 2.0
    $tpm2 = Get-Tpm | select -ExpandProperty ManufacturerID
    if($tpm2 -eq 1314145024){
        "PASS - TPM 2.0" | Out-File $logName -Append
    }else{
        "FAIL - Not TPM 2.0" | Out-File $logName -Append
    }

# Vuln ID V-63337
# Windows 10 information systems must use BitLocker to encrypt all disks to protect the confidentiality and integrity of all information at rest.
    "=====Vuln ID V-63337=====" | Out-File $logName -Append
    
    #Test Bitlocker status
    $bitlockerStatus = Get-BitLockerVolume | where VolumeType -eq "OperatingSystem" | select -ExpandProperty ProtectionStatus

    if($bitlockerStatus -eq "On"){
        "PASS - Bitlocker On" | Out-File $logName -Append
    }else{
        "FAIL - Bitlocker On" | Out-File $logName -Append
    }

    #Test if Bitlocker is set to fully encrypt the OS/Fixed drives
    $bitlockerFull = Get-BitLockerVolume | where VolumeType -eq "OperatingSystem" | select -ExpandProperty VolumeStatus

    if ($bitlockerFull -eq "FullyEncrypted"){
        "PASS - Bitlocker Fully Encrypted" | Out-File $logName -Append
    }else{
        "FAIL - Bitlocker Fully Encrypted" | Out-File $logName -Append
    }

# Vuln ID V-63343
# The operating system must employ automated mechanisms to determine the state of system components with regard to flaw remediation.
    "=====Vuln ID V-63343=====" | Out-File $logName -Append
    
    #Check for the HBSS Service
    $HBSS = Get-Service enterceptAgent | select -ExpandProperty Status

    #Determine if present and if so status
    if($HBSS){
        if($HBSS -eq "Running"){
            "PASS - HBSS Present And Running" | Out-File $logName -Append
        }else{
            "FAIL - HBSS Present, Not Running" | Out-File $logName -Append
        }
    }else{
        "FAIL - HBSS Not Present" | Out-File $logName -Append
    }

# Vuln ID V-63345
# The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.
    "=====Vuln ID V-63345=====" | Out-File $logName -Append
    "FAIL - No Software Whitelisting" | Out-File $logName -Append

# Vuln ID V-63351
# The Windows 10 system must use an anti-virus program.
    "=====Vuln ID V-63351=====" | Out-File $logName -Append

    #Test if VSE is installed and running
    $VSE = Get-Service McShield | select -ExpandProperty Status

    #Determine if present and if so status
    if($VSE){
        if($VSE -eq "Running"){
            "PASS - McAfee VSE Present And Running" | Out-File $logName -Append
        }else{
            "FAIL - McAfee VSE Present, Not Running" | Out-File $logName -Append
        }
    }else{
        "FAIL - McAfee VSE Not Present" | Out-File $logName -Append
    }

    <#  Alternate way of testing if installed

        #Test if McAfee VSE is installed
        cd HKLM:\software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\
        $mcafeeInstalled = Get-ChildItem -Recurse -ea SilentlyContinue | %{if((Get-ItemProperty -Path $_.PsPath) -match "McAfee VirusScan Enterprise"){$_.PsPath}}
        cd c:

        if ($mcafeeInstalled){
            "PASS - AV Installed" | Out-File $logName -Append
        }else{
            "FAIL - AV Installed" | Out-File $logName -Append
        }

    #>

# Vuln ID V-63355
# Allowing other operating systems to run on a secure system may allow security to be circumvented.
    "=====Vuln ID V-63355=====" | Out-File $logName -Append
    "MANUAL CHECK REQUIRED - No OS Other Than Win10" | Out-File $logName -Append

# Vuln ID V-63357
# Non system-created file shares on a system must limit access to groups that require it.
    "=====Vuln ID V-63357=====" | Out-File $logName -Append

    #Get shares on local computer and test if there are any that are not defaults
    $shares = Get-SmbShare | select -ExpandProperty Name
    $nonDefaultShares = foreach($share in $shares){ if(!($share -eq "ADMIN$" -or $share -eq "C$" -or $share -eq "IPC$")){$share}}
    if(!($nonDefaultShares)){
        "PASS - No Shares Other Than Default" | Out-File $logName -Append
    }else{
        "FAIL - No Shares Other Than Default" | Out-File $logName -Append
    }

# Vuln ID V-63359
# Unused accounts must be disabled or removed from the system after 35 days of inactivity.
    "=====Vuln ID V-63359=====" | Out-File $logName -Append

    #Get all local enabled users that have not logged on in 35 days or more
    $localUsers30days = Get-LocalUser | where Enabled -eq $true | where {$_.LastLogon -le (Get-Date).AddDays(-35)}

    #Test if local users are specified local admin or not
    if($localUsers30days){
        Foreach ($user in $localUsers30days){
            if ($user.Name -eq "BoucherDT"){
                "PASS WITH CONDITIONS - $user Is Local Admin; Ensure Documentation" | Out-file $logName -Append
            }else{
                "FAIL - Inactive Local Users: $user" | Out-file $logName -Append
            }
        }
    }else{
        "PASS - No Inactive Local Users" | Out-file $logName -Append
    }

# Vuln ID V-63361
# Only accounts responsible for the administration of a system must have Administrator rights on the system.

    "=====Vuln ID V-63361=====" | Out-File $logName -Append
    "MANUAL CHECK REQUIRED - Limit Admin Accounts To Those Responsible As Noted In Documentation" | Out-File $logName -Append
<#
    #Check local admin group for unauth users
    $approvedUsers = "BoucherDT","PIRSN-Admins","James.Kirk"

    $localAdmins = Get-LocalGroupMember -Group Administrators 

    foreach ($admin in $localAdmins){
        
        #Get list of authorized admins present
        foreach ($approved in $approvedUsers){
            
            $app = "*" + $approved
            if($admin.name -like $app){
                [array]$authorizedLocalAdmins = $authorizedLocalAdmins + $admin.name
            }
        }
    }

    if($authorizedLocalAdmins){
        "PASS WITH CONDITIONS - $authorizedLocalAdmins is/are authorized; Ensure Documentation" | Out-file $logName -Append
    }
#>

# Vuln ID V-63363
# Only accounts responsible for the backup operations must be members of the Backup Operators group.
    "=====Vuln ID V-63363=====" | Out-File $logName -Append

    #Check Backup Operators for unauthorized members
    $backupOperators = Get-LocalGroupMember -Group "Backup Operators"

    if($backupOperators){
        "MANUAL CHECK REQUIRED - Found Backup Operators: $backupOperators.name; Determine Authorization" | Out-file $logName -Append
    }else{
        "PASS - No Members of Backup Operators" | Out-file $logName -Append
    }

# Vuln ID V-63367
# Standard local user accounts must not exist on a system in a domain.
    "=====Vuln ID V-63367=====" | Out-File $logName -Append

    #Get all local user accounts that are enabled
    $localUsers = Get-LocalUser | where Enabled -eq $true | select -ExpandProperty Name

    #Test if local users are specified local admin or not
    if($localUsers){
        Foreach ($user in $localUsers){
            if ($user -eq "BoucherDT"){
                "PASS WITH CONDITIONS - $user Is Local Admin; Ensure Documentation" | Out-file $logName -Append
            }else{
                "FAIL - Non-essential Local Account Present: $user" | Out-file $logName -Append
            }
        }
    }else{
        "PASS - No Enabled Local Users" | Out-file $logName -Append
    }

# Vuln ID V-63373
# Permissions for system files and directories must conform to minimum requirements.
    "=====Vuln ID V-63373=====" | Out-File $logName -Append

    #Assign correct values for use in comparisons
    [array]$cPerms = "c:\ BUILTIN\Administrators:(OI)(CI)(F)","    NT AUTHORITY\SYSTEM:(OI)(CI)(F)","    BUILTIN\Users:(OI)(CI)(RX)","    NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)","    NT AUTHORITY\Authenticated Users:(AD)","    Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)","","Successfully processed 1 files; Failed processing 0 files"
    [array]$programFilesPerms = "c:\program files NT SERVICE\TrustedInstaller:(F)","                 NT SERVICE\TrustedInstaller:(CI)(IO)(F)","                 NT AUTHORITY\SYSTEM:(M)","                 NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)","                 BUILTIN\Administrators:(M)","                 BUILTIN\Administrators:(OI)(CI)(IO)(F)","                 BUILTIN\Users:(RX)","                 BUILTIN\Users:(OI)(CI)(IO)(GR,GE)","                 CREATOR OWNER:(OI)(CI)(IO)(F)","                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)","                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)","                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)","                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)","","Successfully processed 1 files; Failed processing 0 files"
    [array]$windowsPerms = "c:\windows NT SERVICE\TrustedInstaller:(F)","           NT SERVICE\TrustedInstaller:(CI)(IO)(F)","           NT AUTHORITY\SYSTEM:(M)","           NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)","           BUILTIN\Administrators:(M)","           BUILTIN\Administrators:(OI)(CI)(IO)(F)","           BUILTIN\Users:(RX)","           BUILTIN\Users:(OI)(CI)(IO)(GR,GE)","           CREATOR OWNER:(OI)(CI)(IO)(F)","           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)","           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)","           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)","           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)","","Successfully processed 1 files; Failed processing 0 files"

    #Get current icacls info for c:\, c:\program files, and c:\windows and assign to variables for comparison
    $currentCPerms = icacls "c:\"
    $currentProgramFilesPerms = icacls "c:\program files"
    $currentWindowsPerms = icacls "c:\windows"

    #Compare current with correct values and test for difference
    if(Compare-Object $cPerms $currentCPerms){
        "FAIL - Permissions for C:\ Differ From Default" | Out-file $logName -Append
    }else{
        "PASS - Permissions for C:\ Are Default" | Out-file $logName -Append
    }

    if(Compare-Object $programFilesPerms $currentProgramFilesPerms){
        "FAIL - Permissions for C:\Program Files Differ From Default" | Out-file $logName -Append
    }else{
        "PASS - Permissions for C:\Program Files Are Default" | Out-file $logName -Append
    }

    if(Compare-Object $cPerms $currentCPerms){
        "FAIL - Permissions for C:\Windows Differ From Default" | Out-file $logName -Append
    }else{
        "PASS - Permissions for C:\Windows Are Default" | Out-file $logName -Append
    }

# Vuln ID V-63393
# Software certificate installation files must be removed from a system.
    "=====Vuln ID V-63393=====" | Out-File $logName -Append
    
    #Get all of the directories off C:\ 
    cd c:\
    $dirs = gci -Directory

    #CD to each and search for P12 and PFX files
    foreach($dir in $dirs){
        cd $dir
        $p12 = gci "*.p12" -Recurse -ErrorAction SilentlyContinue
        $pfx = gci "*.pfx" -Recurse -ErrorAction SilentlyContinue
        cd..
    }

    #Check if any p12 or pfx files were found
    if($p12){
        foreach($file in $p12){
            "FAIL - P12 File Found: $file" | Out-file $logName -Append
        }
    }else{
        "PASS - No P12 Files Found" | Out-file $logName -Append
    }

    if($pfx){
        foreach($file in $pfx){
            "FAIL - PFX File Found: $file" | Out-file $logName -Append
        }
    }else{
        "PASS - No PFX Files Found" | Out-file $logName -Append
    }

    <# Attempted to recursively check all directories using Get-ChildItem, but found that running that from the root of C: yielded several Access Denied messages.
        This is due to junction points on user account folders and several hidden folders. This is a compatibility features for use with Vist and prior OS's, 
        but PowerShell doesn't know how to handle them. 
        
        Got an idea from online to get all dirs from root C:\, cd to each, then run gci to captures results.
        C:\Windows is the only folder that returns loads of Access Denied using this. 
        Not foolproof, but I think acceptable.        
    #>

# Vuln ID V-63399
# A host-based firewall must be installed and enabled on the system.
    "=====Vuln ID V-63399=====" | Out-File $logName -Append

    "MANUAL CHECK REQUIRED - Verify If Firewall Is Enabled" | Out-File $logName -Append

<# Since Firwall is controlled by GP, and the GP store check is separate from the local check, the below check is not accurate - MD 20190619 

    #Ensure firewall is enabled
    $firewall = Get-NetFirewallProfile
    foreach ($fire in $firewall){ 
        if ($fire.Enabled -ne $true){
            "FAIL - Firewall Is Disabled: $fire" | Out-file $logName -Append
        }else{
            "PASS - Firewall Enabled: $fire" | Out-file $logName -Append
        }
    }
#>

# Vuln ID V-63403
# Inbound exceptions to the firewall on domain workstations must only allow authorized remote management hosts.
    "=====Vuln ID V-63403=====" | Out-File $logName -Append
    "MANUAL CHECK REQUIRED - Verify Inbound Firewall Rules" | Out-File $logName -Append

# Vuln ID V-63451
# The system must be configured to audit Detailed Tracking - PNP Activity successes.
    "=====Vuln ID V-63451=====" | Out-File $logName -Append

    #Get the current audit policy and compare it to the standard from the STIG check
        $audit = auditpol /get /category:*
        $plugnplay = $audit -match "Plug and Play Events"
        $plugnplayStandard = "  Plug and Play Events                    Success"
        $plugnplayCompare = Compare-Object $plugnplay $plugnplayStandard

    #Determine if current setting differs from standard
        if($plugnplayCompare){
            "FAIL - Plug and Play Events Auditing Is Set Incorrectly: $plugnplay" | Out-File $logName -Append
        }else{
            "PASS - Plug and Play Events Auditing Is Set Correctly" | Out-File $logName -Append
        }
        

# Vuln ID V-63457
# The system must be configured to audit Logon/Logoff - Group Membership successes.
    "=====Vuln ID V-63457=====" | Out-File $logName -Append

    #Get the current audit policy and compare it to the standard from the STIG check
        $audit = auditpol /get /category:*
        $groupMembership = $audit -match "Group Membership"
        $groupMembershipStandard = "  Group Membership                        Success"
        $groupMembershipCompare = Compare-Object $groupMembership $groupMembershipStandard

    #Determine if current setting differs from standard
        if($groupMembershipCompare){
            "FAIL - Group Membership Events Auditing Is Set Incorrectly: $groupMembership" | Out-File $logName -Append
        }else{
            "PASS - Group Membership Events Auditing Is Set Correctly" | Out-File $logName -Append
        }


# Vuln ID V-63471
# The system must be configured to audit Object Access - Removable Storage failures.
    "=====Vuln ID V-63471=====" | Out-File $logName -Append

    "MANUAL CHECK REQUIRED - Audit Object Access" | Out-File $logName -Append

    <#

    #Get the current audit policy and compare it to the standard from the STIG check
        $audit = auditpol /get /category:*
        $removableStorage = $audit -match "Removable Storage"
        $removableStorageStandard1 = "  Removable Storage                       Failure"
        $removableStorageStandard2 = "  Removable Storage                       Success and Failure"
        $removableStorageCompare = Compare-Object $removableStorage $removableStorageStandard

    #Determine if current setting differs from standard
        if($removableStorageCompare){
            "FAIL - Removable Storage Events Auditing Is Set Incorrectly: $removableStorage" | Out-File $logName -Append
        }else{
            "PASS - Removable Storage Events Auditing Is Set Correctly" | Out-File $logName -Append
        }

    #>

# Vuln ID V-63473
# The system must be configured to audit Object Access - Removable Storage successes.
    "=====Vuln ID V-63473=====" | Out-File $logName -Append
    "MANUAL CHECK REQUIRED - Audit Object Access" | Out-File $logName -Append

    #See notes above, same applies here

# Vuln ID V-63545
# Camera access from the lock screen must be disabled.
    "=====Vuln ID V-63545=====" | Out-File $logName -Append

    #Check if camera installed
    $camera = Get-WmiObject win32_pnpentity | where {$_.caption -match 'camera'}

    if($camera){
        $cameraSetting = Get-ItemProperty -Path HKLM:\software\Policies\Microsoft\Windows\Personalization\
        if($cameraSetting.NoLockScreenCamera -eq 1){
            "PASS - Correct Camera Lock Screen Setting" | Out-File $logName -Append
        }else{
            "FAIL - Camera Lock Screen Setting: $cameraSetting.NoLockScreenCamera" | Out-File $logName -Append
        }
    }else{
        "N/A - No Camera Installed" | Out-File $logName -Append
    }

# Vuln ID V-63593
# Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained.
    "=====Vuln ID V-63593=====" | Out-File $logName -Append

    "MANUAL CHECK REQUIRED - Verify HKLM Permissions" | Out-File $logName -Append

    # It's going to be a nightmare comparing all of the permissions required

# Vuln ID V-63595
# Virtualization Based Security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection.
    "=====Vuln ID V-63595=====" | Out-File $logName -Append

    #Get Device Guard settings
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

    #Check for Secure Boot enabled (set to 2 or 3)
    if($deviceGuard.RequiredSecurityProperties -contains 2){
        "PASS - Secure Boot Enabled" | Out-File $logName -Append
    }else{
        "FAIL - Secure Boot Not Enabled" | Out-File $logName -Append
    }

    #Check if Device Guard is currently running (set to 2)
    if($deviceGuard.VirtualizationBasedSecurityStatus -eq 2){
        "PASS - Device Guard Running" | Out-File $logName -Append
    }else{
        "FAIL - Device Guard Not Running" | Out-File $logName -Append
    }

# Vuln ID V-63599
# Credential Guard must be running on domain-joined systems.
    "=====Vuln ID V-63599=====" | Out-File $logName -Append

    #Get Device Guard settings
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

    #Check for Credential Guard running (1)
    if($deviceGuard.SecurityServicesRunning -contains 1){
        "PASS - Credential Guard Running" | Out-File $logName -Append
    }else{
        "FAIL - Credential Guard Not Running" | Out-File $logName -Append
    }

# Vuln ID V-63717
# The use of a hardware security device with Windows Hello for Business must be enabled.
    "=====Vuln ID V-63717=====" | Out-File $logName -Append

    #Get registry value for Windows Hello settings
    $windowsHello = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\

    if($windowsHello.RequireSecurityDevice -eq 1){
        "PASS - Hardware Security In Use for Windows Hello" | Out-File $logName -Append
    }else{
        "FAIL - Hardware Security Not In Use for Windows Hello" | Out-File $logName -Append
    }

# Vuln ID V-63739
# Anonymous SID/Name translation must not be allowed.
    "=====Vuln ID V-63739=====" | Out-File $logName -Append

    "MANUAL CHECK REQUIRED - Check For Anonymous SIDs" | Out-File $logName -Append
        
    <# You can do this one of two ways:

        1. Run "Get-GPResultantSetOfPolicy" and somehow assign to variable and parse the results looking for one specific setting
        2. Find the corresponding registry value of that setting using procmon and look for registry settings, which will be much easier in PS directly

    #>

# Vuln ID V-63839
# Toast notifications to the lock screen must be turned off.
    "=====Vuln ID V-63839=====" | Out-File $logName -Append

    #Get Toast notification settings
    $toast = Get-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\

    #Check if notifications on lock screen are off
    if($toast.NoToastApplicationNotificationOnLockScreen -eq 1){
        "PASS - Toast Notifications Disabled on Lock Screen" | Out-File $logName -Append
    }else{
        "FAIL - Toast Notifications Enabled on Lock Screen" | Out-File $logName -Append
    }

# Vuln ID V-63841
# Zone information must be preserved when saving attachments.
    "=====Vuln ID V-63841=====" | Out-File $logName -Append

    #Get zone information settings
    $zoneInfo = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\

    #Determine if zone information is default (variable will be null) or set correctly
    if($zoneInfo){
        if($zoneInfo.SaveZoneInformation -eq 2){
            "PASS - Zone Information Set Correctly" | Out-File $logName -Append
        }else{
            "FAIL - Zone Information Set To: $zoneInfo.SaveZoneInformation" | Out-File $logName -Append
        }
    }else{
        "PASS - Zone Information Set To Default (key not present)" | Out-File $logName -Append
    }

# Vuln ID V-72765
# Bluetooth must be turned off unless approved by the organization.
    "=====Vuln ID V-72765=====" | Out-File $logName -Append
    "MANUAL CHECK REQUIRED - Turn Off Bluetooth" | Out-File $logName -Append

    # The only thing I found for now was a vbscript way of using wmi to test for a bluetooth adapter present. Could probably adapt to Powershell using wmi. 

# Vuln ID V-72767
# Bluetooth must be turned off when not in use.
    "=====Vuln ID V-72767=====" | Out-File $logName -Append
    "MANUAL CHECK REQUIRED - Check documentation for Bluetooth Off When Not in Use Policy" | Out-File $logName -Append

# Vuln ID V-72769
# The system must notify the user when a Bluetooth device attempts to connect.
    "=====Vuln ID V-72769=====" | Out-File $logName -Append    
    "MANUAL CHECK REQUIRED - Notify If Bluetooth Device Attempts Connection" | Out-File $logName -Append

# Vuln ID V-74413
# Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.
    "=====Vuln ID V-74413=====" | Out-File $logName -Append

    #Get registry value for ECC Curves setting and compare to the proper setting specified in STIG
    $eccCurves = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\
    $properECC = "NistP384","NistP256"
    $findDiff = Compare-Object $eccCurves.EccCurves $properECC

    if($findDiff){
        "FAIL - Incorrect ECC Curves Value Set: $eccCurves.EccCurves" | Out-File $logName -Append
    }else{
        "PASS - Correct ECC Curves Value Set" | Out-File $logName -Append
    }

# Vuln ID V-76505
# Orphaned security identifiers (SIDs) must be removed from user rights on Windows 10.
    "=====Vuln ID V-76505=====" | Out-File $logName -Append
    "MANUAL CHECK REQUIRED - Orphaned SIDs" | Out-File $logName -Append

# Vuln ID V-77083
# Windows 10 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.
    "=====Vuln ID V-77083=====" | Out-File $logName -Append
    
    #Check boot type and test if EFI
    $bootType = (Select-String -path C:\Windows\panther\setupact.log -Pattern "Detected boot environment").line -replace '.*:\s+'

     if($bootType -eq "EFI"){
        "PASS - Boot Set to EFI" | Out-File $logName -Append
     }else{
        "FAIL - Boot Not Set to EFI: $bootType" | Out-File $logName -Append
     }

# Vuln ID V-77085
# Secure Boot must be enabled on Windows 10 systems.
    "=====Vuln ID V-77085=====" | Out-File $logName -Append

    #Ensure Secure Boot is enabled
    $secureBoot = Confirm-SecureBootUEFI

    if($secureBoot -eq $true){
        "PASS - Secure Boot Enabled" | Out-File $logName -Append
    }else{
        "FAIL - Secure Boot Disabled" | Out-File $logName -Append
    }

# Vuln ID V-77091
# Windows 10 Exploit Protection system-level mitigation, Data Execution Prevention (DEP), must be on.
    "=====Vuln ID V-77091=====" | Out-File $logName -Append

    #Test if Exploit Protection (DEP) is set to default (NOT SET) or set to ON. If not, fail
    $processMitigation = Get-ProcessMitigation -System

    if($processMitigation.Dep.Enable -eq "ON" -or $processMitigation.Dep.Enable -eq "NOTSET"){
        "PASS - Exploit Protection (DEP) Is Enabled" | Out-File $logName -Append
    }else{
        "FAIL - Exploit Protection (DEP) Is Disabled" | Out-File $logName -Append
    }

# Vuln ID V-77095
# Windows 10 Exploit Protection system-level mitigation, Randomize memory allocations (Bottom-Up ASLR), must be on.
    "=====Vuln ID V-77095=====" | Out-File $logName -Append

    #Test if Exploit Protection (Bottom-Up ASLR) is set to default (NOT SET) or set to ON. If not, fail
    $processMitigation = Get-ProcessMitigation -System

    if($processMitigation.Aslr.BottomUp -eq "ON" -or $processMitigation.Aslr.BottomUp -eq "NOTSET"){
        "PASS - Exploit Protection (Bottom-Up ASLR) Is Enabled" | Out-File $logName -Append
    }else{
        "FAIL - Exploit Protection (Bottom-Up ASLR) Is Disabled" | Out-File $logName -Append
    }

# Vuln ID V-77097
# Windows 10 Exploit Protection system-level mitigation, Control flow guard (CFG), must be on.
    "=====Vuln ID V-77097=====" | Out-File $logName -Append

    #Test if Exploit Protection (Control Flow Guard) is set to default (NOT SET) or set to ON. If not, fail
    $processMitigation = Get-ProcessMitigation -System

    if($processMitigation.Cfg.Enable -eq "ON" -or $processMitigation.Cfg.Enable -eq "NOTSET"){
        "PASS - Exploit Protection (Control Flow Guard) Is Enabled" | Out-File $logName -Append
    }else{
        "FAIL - Exploit Protection (Control Flow Guard) Is Disabled" | Out-File $logName -Append
    }

# Vuln ID V-77101
# Windows 10 Exploit Protection system-level mitigation, Validate exception chains (SEHOP), must be on.
    "=====Vuln ID V-77101=====" | Out-File $logName -Append

    #Test if SEHOP is set to default (NOT SET) or set to ON. If not, fail
    $processMitigation = Get-ProcessMitigation -System

    if($processMitigation.SEHOP.Enable -eq "ON" -or $processMitigation.SEHOP.Enable -eq "NOTSET"){
        "PASS - Exploit Protection (SEHOP) Is Enabled" | Out-File $logName -Append
    }else{
        "FAIL - Exploit Protection (SEHOP) Is Disabled" | Out-File $logName -Append
    }

# Vuln ID V-77103
# Windows 10 Exploit Protection system-level mitigation, Validate heap integrity, must be on.
    "=====Vuln ID V-77103=====" | Out-File $logName -Append

    #Test if Heap Integrity is set to default (NOT SET) or set to ON. If not, fail
    $processMitigation = Get-ProcessMitigation -System

    if($processMitigation.Heap.TerminateOnError -eq "ON" -or $processMitigation.Heap.TerminateOnError -eq "NOTSET"){
        "PASS - Exploit Protection (Heap Integrity) Is Enabled" | Out-File $logName -Append
    }else{
        "FAIL - Exploit Protection (Heap Integrity) Is Disabled" | Out-File $logName -Append
    }

# Vuln ID V-77189
# Exploit Protection mitigations in Windows 10 must be configured for Acrobat.exe.
    "=====Vuln ID V-77189=====" | Out-File $logName -Append

    #Test process mitigation for Acrobat
    Test-DEP-ASLR2-Payload("Acrobat.exe")

# Vuln ID V-77191
# Exploit Protection mitigations in Windows 10 must be configured for AcroRd32.exe.
    "=====Vuln ID V-77191=====" | Out-File $logName -Append

    #Test process mitigation for Reader
    Test-DEP-ASLR2-Payload("AcroRd32.exe")

# Vuln ID V-77195
# Exploit Protection mitigations in Windows 10 must be configured for chrome.exe.
    "=====Vuln ID V-77195=====" | Out-File $logName -Append

    #Test process mitigation for Chrome
    Test-DEP("chrome.exe")

# Vuln ID V-77201
# Exploit Protection mitigations in Windows 10 must be configured for EXCEL.EXE.
    "=====Vuln ID V-77201=====" | Out-File $logName -Append
    
    #Test process mitigation for Excel
    Test-DEP-ASLR-Payload("EXCEL.EXE")

# Vuln ID V-77205
# Exploit Protection mitigations in Windows 10 must be configured for firefox.exe.
    "=====Vuln ID V-77205=====" | Out-File $logName -Append

    #Test process mitigation for Firefox
    Test-DEP-ASLR2("firefox.exe")

# Vuln ID V-77209
# Exploit Protection mitigations in Windows 10 must be configured for FLTLDR.EXE.
    "=====Vuln ID V-77209=====" | Out-File $logName -Append

    #Test process mitigation for FLTLDR.EXE
    Test-DEP-ImageLoad-Payload("FLTLDR.EXE")

# Vuln ID V-77213
# Exploit Protection mitigations in Windows 10 must be configured for GROOVE.EXE.
    "=====Vuln ID V-77213=====" | Out-File $logName -Append

    #Test process mitigation for GROOVE.EXE
    Test-DEP-ASLR-ImageLoad-Payload("GROOVE.EXE")

# Vuln ID V-77217
# Exploit Protection mitigations in Windows 10 must be configured for iexplore.exe.
    "=====Vuln ID V-77217=====" | Out-File $logName -Append

    #Test process mitigation for IE
    Test-DEP-ASLR2-Payload("iexplore.exe")

# Vuln ID V-77221
# Exploit Protection mitigations in Windows 10 must be configured for INFOPATH.EXE.
    "=====Vuln ID V-77221=====" | Out-File $logName -Append

    #Test process mitigation for INFOPATH.EXE
    Test-DEP-ASLR-Payload("INFOPATH.EXE")

# Vuln ID V-77223
# Exploit Protection mitigations in Windows 10 must be configured for java.exe, javaw.exe, and javaws.exe.
    "=====Vuln ID V-77223=====" | Out-File $logName -Append

    #Test process mitigation for java.exe
    Test-DEP-Payload("java.exe")

    #Test process mitigation for javaw.exe
    Test-DEP-Payload("javaw.exe")

    #Test process mitigation for javaws.exe
    Test-DEP-Payload("javaws.exe")

# Vuln ID V-77227
# Exploit Protection mitigations in Windows 10 must be configured for lync.exe.
    "=====Vuln ID V-77227=====" | Out-File $logName -Append

    #Test process mitigation for MS Lync
    Test-DEP-ASLR-Payload("lync.exe")

# Vuln ID V-77231
# Exploit Protection mitigations in Windows 10 must be configured for MSACCESS.EXE.
    "=====Vuln ID V-77231=====" | Out-File $logName -Append

    #Test process mitigation for MS Access
    Test-DEP-ASLR-Payload("MSACCESS.EXE")

# Vuln ID V-77233
# Exploit Protection mitigations in Windows 10 must be configured for MSPUB.EXE.
    "=====Vuln ID V-77233=====" | Out-File $logName -Append

    #Test process mitigation for MS Publisher
    Test-DEP-ASLR-Payload("MSPUB.EXE")

# Vuln ID V-77235
# Exploit Protection mitigations in Windows 10 must be configured for OneDrive.exe.
    "=====Vuln ID V-77235=====" | Out-File $logName -Append

    #Test process mitigation for OneDrive
    Test-DEP-ASLR-ImageLoad-Payload("OneDrive.exe")

# Vuln ID V-77239
# Exploit Protection mitigations in Windows 10 must be configured for OIS.EXE.
    "=====Vuln ID V-77239=====" | Out-File $logName -Append

    #Test process mitigation for OIS.EXE
    Test-DEP-Payload("OIS.EXE")

# Vuln ID V-77243
# Exploit Protection mitigations in Windows 10 must be configured for OUTLOOK.EXE.
    "=====Vuln ID V-77243=====" | Out-File $logName -Append

    #Test process mitigation for MS Outlook
    Test-DEP-ASLR-Payload("OUTLOOK.EXE")

# Vuln ID V-77245
# Exploit Protection mitigations in Windows 10 must be configured for plugin-container.exe.
    "=====Vuln ID V-77245=====" | Out-File $logName -Append

    #Test process mitigation for plugin-container.exe
    Test-DEP-Payload("plugin-container.exe")

# Vuln ID V-77247
# Exploit Protection mitigations in Windows 10 must be configured for POWERPNT.EXE.
    "=====Vuln ID V-77247=====" | Out-File $logName -Append

    #Test process mitigation for MS PowerPoint
    Test-DEP-ASLR-Payload("POWERPNT.EXE")

# Vuln ID V-77249
# Exploit Protection mitigations in Windows 10 must be configured for PPTVIEW.EXE.
    "=====Vuln ID V-77249=====" | Out-File $logName -Append

    #Test process mitigation for MS PowerPoint Viewer
    Test-DEP-ASLR-Payload("PPTVIEW.EXE")

# Vuln ID V-77255
# Exploit Protection mitigations in Windows 10 must be configured for VISIO.EXE.
    "=====Vuln ID V-77255=====" | Out-File $logName -Append

    #Test process mitigation for MS Visio
    Test-DEP-ASLR-Payload("VISIO.EXE")

# Vuln ID V-77259
# Exploit Protection mitigations in Windows 10 must be configured for VPREVIEW.EXE.
    "=====Vuln ID V-77259=====" | Out-File $logName -Append

    #Test process mitigation for VPREVIEW.EXE
    Test-DEP-ASLR-Payload("VPREVIEW.EXE")

# Vuln ID V-77263
# Exploit Protection mitigations in Windows 10 must be configured for WINWORD.EXE.
    "=====Vuln ID V-77263=====" | Out-File $logName -Append

    #Test process mitigation for MS Word
    Test-DEP-ASLR-Payload("WINWORD.EXE")

# Vuln ID V-77267
# Exploit Protection mitigations in Windows 10 must be configured for wmplayer.exe.
    "=====Vuln ID V-77267=====" | Out-File $logName -Append

    #Test process mitigation for Windows Media Player
    Test-DEP-PayloadLess("wmplayer.exe")

# Vuln ID V-77269
# Exploit Protection mitigations in Windows 10 must be configured for wordpad.exe.
    "=====Vuln ID V-77269=====" | Out-File $logName -Append

    #Test process mitigation for WordPad
    Test-DEP-Payload("wordpad.exe")

# Vuln ID V-78129
# Administrative accounts must not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.
    "=====Vuln ID V-78129=====" | Out-File $logName -Append

    "MANUAL CHECK REQUIRED - Block Admin Accounts from Internet Access" | Out-File $logName -Append
    
# Vuln ID V-82137
# The use of personal accounts for OneDrive synchronization must be disabled.
    "=====Vuln ID V-82137=====" | Out-File $logName -Append

    #Get registry value for OneDrive
    $oneDrive = Get-ItemProperty -Path HKCU:\Software\Policies\Microsoft\OneDrive\

    if($oneDrive.DisablePersonalSync -eq 1){
        "PASS - Personal OneDrive Accounts Disabled" | Out-File $logName -Append
    }else{
        "FAIL - Personal OneDrive Accounts Are Not Disabled" | Out-File $logName -Append
    }

# Vuln ID V-88203
# OneDrive must only allow synchronizing of accounts for DoD organization instances.
    "=====Vuln ID V-88203=====" | Out-File $logName -Append

    #Clear oneDrive variable
    $oneDrive = $null

    #Get registry value for OneDrive
    $oneDrive = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\AllowTenantList\

    if($oneDrive.1111-2222-3333-4444 -eq "1111-2222-3333-4444"){
        "PASS - OneDrive External Syncing Is Restricted" | Out-File $logName -Append
    }else{
        "FAIL - OneDrive External Syncing Is Not Restricted" | Out-File $logName -Append
    }

#Vuln ID V-94859
# Windows 10 systems must use a BitLocker PIN for pre-boot authentication.
    "=====Vuln ID V-94859=====" | Out-File $logName -Append

    "MANUAL CHECK REQUIRED - Check if Bitlocker pre-boot PIN is enforced" | Out-File $logName -Append

#Vuln ID V-94861
# Windows 10 systems must use a BitLocker PIN with a minimum length of 6 digits for pre-boot authentication.
    "=====Vuln ID V-94861=====" | Out-File $logName -Append

    "MANUAL CHECK REQUIRED - Check if Bitlocker PIN uses minimum of 6 digits" | Out-File $logName -Append