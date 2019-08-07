##################################################################
#   InfoSec Team Automation - IOC Check-Remote - v.0.1
#   Date: 08/06/2019
#   Author: DOA\OTS - InfoSecTeam
#-----------------------------------------------------------------
#   PS Remoting Must be enabled
#   Credentials with admin access to all workstations must be used
#-----------------------------------------------------------------

# Environment Variables
$FileIOCs = 'id_up.exe','tiki.exe','CCleaner.exe*','wdcsam.inf.2823sf8551*'
$IPIOCs = '84.146.54.187','75.147.173.236','218.16.120.253','170.238.117.187','195.123.237.129','194.5.250.123','85.204.116.158','31.184.254.18','186.10.243.70'
$PortIOCs = '445','447','449','8082','16993'
$RemoteComputers = Get-ADComputer -filter ('Enabled -eq $True')

#INSERT ADMIN CREDS HERE
$AdminAccount = "USERNAME"
$AdminPassword = "PASSWORD"


$PasswordString = ConvertTo-SecureString -String $AdminPassword -AsPlainText -force
$DomainCreds = New-Object System.Management.Automation.PSCredential($AdminAccount, $PasswordString) 

#Create export directory
$dir = "$($env:USERPROFILE)\Desktop\Indicators"
if(!(Test-Path -Path $dir )){
    New-Item -ItemType directory -Path $dir
    #Write-Host "New folder created"
}
else
{

}



Foreach ($computer in $RemoteComputers){

#Look for known bad file indicators on remote host
$FileData = Invoke-Command -ComputerName $computer -ScriptBlock {Get-Childitem -Path "C:\" -Include 'id_up.exe','tiki.exe','CCleaner.exe*','wdcsam.inf.2823sf8551*' -Recurse -ErrorAction SilentlyContinue} -Credential $DomainCreds -ErrorAction SilentlyContinue
   if ($FileData){
   Write-Host File IoCs Found on $computer -ForegroundColor Yellow
   $FileData.FullName
   $FileData.Fullname | Out-File "$dir\$computer-FileIndicators.txt"
   }

Write-Host
Write-Host

#Look for known bad IP Indicators on remote host
$IPData = Invoke-Command -ComputerName $computer -ScriptBlock {Get-NetTCPConnection -RemoteAddress '84.146.54.187','75.147.173.236','218.16.120.253','170.238.117.187','195.123.237.129','194.5.250.123','85.204.116.158','31.184.254.18','186.10.243.70' -ErrorAction SilentlyContinue} -Credential $DomainCreds -ErrorAction SilentlyContinue
   if ($IPData){
   Write-Host IP IoCs Found on $computer -ForegroundColor Yellow
   $IPData.RemoteAddress
   $IPData.RemoteAddress | Out-File "$dir\$computer-IPIndicators.txt"
   }

Write-Host
Write-Host

#Look for known bad port Indicators on remote host
$PortData = Invoke-Command -ComputerName $computer -ScriptBlock {Get-NetTCPConnection -RemotePort '445','447','449','8082','16993' -ErrorAction SilentlyContinue | Where {($_.RemoteAddress -notlike "10.*") -AND ($_.RemoteAddress -notlike "172.*") -AND ($_.RemoteAddress -notlike "192.*") }} -Credential $DomainCreds -ErrorAction SilentlyContinue
   if ($PortData){
   Write-Host Port IoCs Found on $computer -ForegroundColor Yellow
   $PortData
   $PortData | Out-File "$dir\$computer-PortIndicators.txt"
   }

}