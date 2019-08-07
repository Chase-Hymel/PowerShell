##################################################################
#   InfoSec Team Automation - IOC Check-Local - v.0.1
#   Date: 08/06/2019
#   Author: DOA\OTS - InfoSecTeam
#-----------------------------------------------------------------

# Environment Variables
$FileIOCs = 'id_up.exe','tiki.exe','CCleaner.exe*','wdcsam.inf.2823sf8551*'
$IPIOCs = '84.146.54.187','75.147.173.236','218.16.120.253','170.238.117.187','195.123.237.129','194.5.250.123','85.204.116.158','31.184.254.18','186.10.243.70'
$PortIOCs = '445','447','449','8082','16993'

#Look for known bad file indicators
$FileData = Get-Childitem -Path "C:\" -Include $FileIOCs -Recurse -ErrorAction SilentlyContinue
   if ($FileData){
   Write-Host File IoCs Found -ForegroundColor Yellow
   $FileData.FullName
   $FileData.Fullname | Out-File "$($env:USERPROFILE)\Desktop\FileIndicators.txt"
   }

Write-Host
Write-Host

#Look for known bad IP Indicators
$IPData = Get-NetTCPConnection -RemoteAddress $IPIOCs -ErrorAction SilentlyContinue
   if ($IPData){
   Write-Host IP IoCs Found -ForegroundColor Yellow
   $IPData.RemoteAddress
   $IPData.RemoteAddress | Out-File "$($env:USERPROFILE)\Desktop\IPIndicators.txt"
   }

Write-Host
Write-Host

#Look for known bad port Indicators
$PortData = Get-NetTCPConnection -RemotePort $PortIOCs -ErrorAction SilentlyContinue | Where {($_.RemoteAddress -notlike "10.*") -AND ($_.RemoteAddress -notlike "172.*") -AND ($_.RemoteAddress -notlike "192.*") }
   if ($PortData){
   Write-Host Port IoCs Found -ForegroundColor Yellow
   $PortData
   $PortData | Out-File "$($env:USERPROFILE)\Desktop\PortIndicators.txt"
   }