# Get the interface number for the Private IP defined at Vagrantfile 
$interface = Get-NetIPAddress | Where-Object {$_.IPAddress -match "10.10.10.13"} | select -ExpandProperty InterfaceIndex

# Show current routes for debugging
Write-Host ("Current routes for interface " + $interface)
Get-NetRoute -InterfaceIndex $interface | Format-Table

# Try to remove the route if it exists
try {
    $existingRoute = Get-NetRoute -InterfaceIndex $interface -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
    if ($existingRoute) {
        Remove-NetRoute -InterfaceIndex $interface -DestinationPrefix "0.0.0.0/0" -Confirm:$false
    }
} catch {
    Write-Host "No default route found to remove"
}

# Create the new route
New-NetRoute -InterfaceIndex $interface -NextHop "10.10.10.254" -DestinationPrefix "0.0.0.0/0" -confirm:$false -ErrorAction Stop

# Disable firewall from Windows
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False