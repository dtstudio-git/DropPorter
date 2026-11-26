#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^DropPorter\.NdisCap\.[0-9a-f]{32}$')][string]$Name,
    [Parameter(Mandatory = $true)][guid]$AdapterGuid,
    [Parameter(Mandatory = $true)][uint32]$AdapterIndex,
    [Parameter(Mandatory = $true)][uint32]$ControllerPid,
    [Parameter(Mandatory = $true)][string]$ReadyPath,
    [Parameter(Mandatory = $true)][string]$StopPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Write-StartupTiming([string]$Stage) {
    if ([System.Diagnostics.Stopwatch]::IsHighResolution) {
        $timestamp = [System.Diagnostics.Stopwatch]::GetTimestamp()
        $microseconds = [long][Math]::Floor($timestamp * 1000000.0 / [System.Diagnostics.Stopwatch]::Frequency)
        [Console]::WriteLine("ndiscap_startup_timing stage=$Stage steady_us=$microseconds")
    }
}

Write-StartupTiming 'script_entered'
$moduleRoot = [System.IO.Path]::Combine($PSHOME, 'Modules')
$env:PSModulePath = $moduleRoot
Import-Module -Name ([System.IO.Path]::Combine($moduleRoot, 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Management.psd1')) -Force
Import-Module -Name ([System.IO.Path]::Combine($moduleRoot, 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Utility.psd1')) -Force
Write-StartupTiming 'core_modules_loaded'
Import-Module -Name ([System.IO.Path]::Combine($moduleRoot, 'CimCmdlets', 'CimCmdlets.psd1')) -Force
Write-StartupTiming 'cim_module_loaded'
# Use the same inbox CIM cmdlet definitions as the manifests, limited to
# adapter identity and the capture session, provider, and adapter filter.
$adapterDefinition = [System.IO.Path]::Combine($moduleRoot, 'NetAdapter', 'MSFT_NetAdapter.cmdletDefinition.cdxml')
Import-Module -Name $adapterDefinition -Function Get-NetAdapter -Force
Write-StartupTiming 'netadapter_module_loaded'
$captureModuleRoot = [System.IO.Path]::Combine($moduleRoot, 'NetEventPacketCapture')
foreach ($definition in 'MSFT_NetEventSession.cdxml', 'MSFT_NetEventPacketCaptureProvider.cdxml', 'MSFT_NetEventNetworkAdapter.cdxml') {
    Import-Module -Name ([System.IO.Path]::Combine($captureModuleRoot, $definition)) -Force
}
Write-StartupTiming 'capture_module_loaded'
$PSModuleAutoLoadingPreference = 'None'
$session = $null
$primaryFailure = $null
$cleanupErrors = [System.Collections.Generic.List[string]]::new()

try {
    $controller = Get-Process -Id $ControllerPid -ErrorAction Stop
    if ($controller.WaitForExit(0)) { throw 'ndiscap_controller_exited_before_start' }

    $adapters = @(Get-NetAdapter -Physical | Where-Object {
        [guid]$_.InterfaceGuid -eq $AdapterGuid
    })
    if ($adapters.Count -ne 1 -or [uint32]$adapters[0].InterfaceIndex -ne $AdapterIndex) {
        throw 'ndiscap_adapter_identity_mismatch'
    }
    $adapter = $adapters[0]
    $actualAdapterGuid = [guid]$adapter.InterfaceGuid
    Write-StartupTiming 'adapter_verified'

    $session = New-NetEventSession -Name $Name -CaptureMode RealtimeLocal -Confirm:$false
    if ($session.Name -cne $Name) { throw 'ndiscap_session_name_mismatch' }
    Write-StartupTiming 'session_created'

    Add-NetEventPacketCaptureProvider -SessionName $Name -CaptureType Physical `
        -MultiLayer $false -TruncationLength 0 -Confirm:$false | Out-Null
    Write-StartupTiming 'provider_added'
    Add-NetEventNetworkAdapter -Name $adapter.Name -PromiscuousMode $false -Confirm:$false | Out-Null

    $configuredAdapters = @(Get-NetEventNetworkAdapter -Name $adapter.Name)
    if ($configuredAdapters.Count -ne 1 -or $configuredAdapters[0].Name -cne $adapter.Name) {
        throw 'ndiscap_session_adapter_mismatch'
    }
    Write-StartupTiming 'adapter_filter_verified'

    Start-NetEventSession -Name $Name -Confirm:$false
    Write-StartupTiming 'session_start_returned'
    $activeSession = Get-NetEventSession -Name $Name
    if ([guid]$activeSession.Guid -ne [guid]$session.Guid -or [int]$activeSession.SessionStatus -ne 0) {
        throw 'ndiscap_session_not_active'
    }
    if ($controller.WaitForExit(0)) { throw 'ndiscap_controller_exited_during_start' }
    Write-StartupTiming 'session_active_verified'

    $ready = @(
        'ndiscap_ready=1'
        "session_name=$Name"
        "session_guid=$(([guid]$session.Guid).ToString('B').ToLowerInvariant())"
        "adapter_guid=$($actualAdapterGuid.ToString('B').ToLowerInvariant())"
        "adapter_ifindex=$([uint32]$adapter.InterfaceIndex)"
    ) -join "`n"
    $readyTemp = $ReadyPath + '.tmp'
    [System.IO.File]::WriteAllText($readyTemp, $ready + "`n", [System.Text.Encoding]::ASCII)
    Write-StartupTiming 'ready_record_prepared'
    [System.IO.File]::Move($readyTemp, $ReadyPath)

    while (-not (Test-Path -LiteralPath $StopPath -PathType Leaf)) {
        if ($controller.WaitForExit(250)) { break }
    }
}
catch {
    $primaryFailure = $_.Exception.Message
}
finally {
    if ($null -ne $session) {
        $canRemove = $false
        try {
            $owned = @(Get-NetEventSession | Where-Object { $_.Name -ceq $Name })
            if ($owned.Count -gt 1) { throw 'ndiscap_session_name_not_unique_before_stop' }
            if ($owned.Count -eq 0) {
                $canRemove = $true
            }
            else {
                if ([guid]$owned[0].Guid -ne [guid]$session.Guid) {
                    throw 'ndiscap_session_identity_changed_before_stop'
                }
                if ([int]$owned[0].SessionStatus -eq 0) {
                    Stop-NetEventSession -InputObject $session -Confirm:$false
                }
                $stopped = @(Get-NetEventSession | Where-Object { $_.Name -ceq $Name })
                if ($stopped.Count -ne 1 -or [guid]$stopped[0].Guid -ne [guid]$session.Guid -or
                    [int]$stopped[0].SessionStatus -ne 1) {
                    throw 'ndiscap_session_stop_not_confirmed'
                }
                $canRemove = $true
            }
        }
        catch { $cleanupErrors.Add("stop: $($_.Exception.Message)") }

        if ($canRemove) {
            try {
                $owned = @(Get-NetEventSession | Where-Object { $_.Name -ceq $Name })
                if ($owned.Count -gt 1) { throw 'ndiscap_session_name_not_unique_before_remove' }
                if ($owned.Count -eq 1) {
                    if ([guid]$owned[0].Guid -ne [guid]$session.Guid -or [int]$owned[0].SessionStatus -ne 1) {
                        throw 'ndiscap_session_identity_changed_before_remove'
                    }
                    Remove-NetEventSession -InputObject $session -Confirm:$false
                }
                if (@(Get-NetEventSession | Where-Object { $_.Name -ceq $Name }).Count -ne 0) {
                    throw 'ndiscap_session_still_present'
                }
            }
            catch { $cleanupErrors.Add("remove: $($_.Exception.Message)") }
        }
    }
}

if ($null -ne $primaryFailure) {
    [Console]::Error.WriteLine("NdisCap session failed: $primaryFailure")
}
foreach ($problem in $cleanupErrors) {
    [Console]::Error.WriteLine("NdisCap cleanup failed: $problem")
}
if ($cleanupErrors.Count -ne 0) { exit 2 }
if ($null -ne $primaryFailure) { exit 1 }
exit 0
