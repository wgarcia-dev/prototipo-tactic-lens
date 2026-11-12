# Read-only; dot-source from the launcher and the privileged configurator.
function Test-FirewallDemo {
    param([string]$LocalIP,[string]$UbuntuIP,[int]$InterfaceIndex)
    try {
        $rule = Get-NetFirewallRule -Name 'TacticLens-DemoHTTP-Ubuntu' -ErrorAction Stop
        if ([int]$rule.Enabled -ne 1 -or [int]$rule.Direction -ne 1 -or [int]$rule.Action -ne 2 -or [int]$rule.EdgeTraversalPolicy -ne 0) { return $false }
        $address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
        $port = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
        $adapter = $rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
        $interface = (Get-NetAdapter -InterfaceIndex $InterfaceIndex -ErrorAction Stop).Name
        if (@($address.LocalAddress).Count -ne 1 -or @($address.LocalAddress)[0] -ne $LocalIP -or
            @($address.RemoteAddress).Count -ne 1 -or @($address.RemoteAddress)[0] -ne $UbuntuIP -or
            @($port.LocalPort).Count -ne 1 -or @($port.LocalPort)[0] -ne '8000' -or $port.Protocol -notin @('TCP','6') -or
            @($adapter.InterfaceAlias).Count -ne 1 -or @($adapter.InterfaceAlias)[0] -ne $interface) { return $false }
        $category = [int](Get-NetConnectionProfile -InterfaceIndex $InterfaceIndex -ErrorAction Stop).NetworkCategory
        $profileName = switch ($category) { 0 { 'Public' } 1 { 'Private' } 2 { 'Domain' } default { return $false } }
        $profile = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
        # Any profile is safe here because both addresses and the interface are
        # exact. A narrower rule must include the active profile.
        $mask = switch ($category) { 0 { 4 } 1 { 2 } 2 { 1 } }
        $profiles = [int]$rule.Profile
        return ([int]$profile.Enabled -eq 1 -and [int]$profile.DefaultInboundAction -eq 4 -and
                ($profiles -eq 0 -or ($profiles -band $mask) -ne 0))
    } catch { return $false }
}
