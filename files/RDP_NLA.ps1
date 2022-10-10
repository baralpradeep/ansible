# This corrects a misconfiguration of RDP that corresponds to the following vulnerability.
#   BID:  13818
#   OSVDB:  17131 
#   CVE:  CVE-2005-1794
#   
#   CPE: cpe:/a:microsoft:remote_desktop_connection cpe:/a:microsoft:windows_terminal_services_using_rdp
#   Exploit Available: true
#   Exploit Ease: Exploits are available
#   Vulnerability Pub Date: May 28, 2005

# Author: David Frazer
# Date Created: 10/06/2017

Param(
  $ComputerName,
  [ValidateSet("True","False")]
  [String]$Enable,
  [Switch]$ViewOnly
  )
Try {
  Foreach($Computer in $ComputerName){
    If($ViewOnly){
      $Value = (Get-WMIObject -Class "Win32_TSGeneralSetting" -NameSpace root\cimv2\terminalservices -ComputerName $Computer -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired
      If($Value -eq 0) {
        return "[$($ComputerName)]: NLA Disabled"
      } ElseIf($Value -eq 1) {
        return "[$($ComputerName)]: NLA Enabled"
      } Else {
        return "[$($ComputerName)]: NLA is set to $($Value)"
      }
    } Else {

      If($Enable -eq $True){
        ((Get-WMIObject -Class "Win32_TSGeneralSetting" -NameSpace root\cimv2\terminalservices -ComputerName $Computer -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1)) 2>&1 | Out-Null
        $Err = $?
        If($Err){
          "NLA Enabled on $($Computer)"
        } Else {
          $Error[0]
        }
      } ElseIf($Enable -eq $False){
        ((Get-WMIObject -Class "Win32_TSGeneralSetting" -NameSpace root\cimv2\terminalservices -ComputerName $Computer -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)) 2>&1 | Out-Null
        $Err = $?
        If($Err){
          "NLA Disabled on $($Computer)"
        } Else {
          $Error[0]
        }
      } Else {
        "Do nothing"
      }
    }
  }
} Catch {
  $Error[0]
}
