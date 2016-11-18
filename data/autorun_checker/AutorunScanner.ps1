$workDir = "C:\autorun_checker\"
$scanDir = $workDir + "Scan\"
$logDir = $workDir + "Log\"
$logFile = $logDir + "autoruns.log"
$previousScanName = "previous.snap"
$previousScan = $scanDir + $previousScanName
$currentScanName = "current.snap"
$currentScan = $scanDir + $currentScanName
$cmd = $workDir + "autorunsc.exe"
$arg = "-a * -ct -h -m -s -nobanner /accepteula" 

If (Test-Path $currentScan) {
  Move-Item -path $currentScan -destination $previousScan -Force
} Else {
  New-Item -path $scanDir -name $previousScanName -ItemType File -Force -value " "
}

Start-Process -FilePath $cmd -ArgumentList $arg -workingdirectory $workDir -RedirectStandardOutput $currentScan -Wait -NoNewWindow
$compName = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
Compare-Object -ReferenceObject (Get-Content $previousScan) -DifferenceObject (Get-Content $currentScan) | Where-Object {$_.SideIndicator -eq "=>"} | Select -ExpandProperty InputObject | %{$compName + "`t" + $_} >> $logFile

