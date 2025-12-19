$tsharkPath = "C:\Program Files\Wireshark\tshark.exe"

if (-not (Test-Path $tsharkPath)) {
    Write-Host "TShark not found at standard location: $tsharkPath" -ForegroundColor Red
    Write-Host "Please ensure Wireshark is installed or update this script with the correct path."
    exit
}

# Convert Attack Files
$attackFiles = Get-ChildItem -Filter "*attack*.pcapng"
foreach ($file in $attackFiles) {
    if ($file.Name -match "(.*)\.pcapng") {
        $baseName = $matches[1]
        $output = "ftp_attack_$baseName.csv"
        Write-Host "Converting $file to $output..."
        
        & $tsharkPath -r $file.FullName `
        -T fields `
        -e frame.time_epoch `
        -e ip.src `
        -e ip.dst `
        -e tcp.srcport `
        -e tcp.dstport `
        -e frame.len `
        -e tcp.flags `
        -e tcp.stream `
        -e ftp.request.command `
        -e ftp.request.arg `
        -e ftp.response.code `
        -e ftp.response.arg `
        -E header=y `
        -E separator=, `
        -E quote=d `
        -E occurrence=f > $output
    }
}

# Convert Normal Files
$normalFiles = Get-ChildItem -Filter "*norm*.pcapng" -Recurse | Where-Object { $_.Name -match "normal|noraml" }
foreach ($file in $normalFiles) {
    if ($file.Name -match "(.*)\.pcapng") {
        $baseName = $matches[1]
        $output = "ftp_normal_$baseName.csv"
        Write-Host "Converting $file to $output..."
        
        & $tsharkPath -r $file.FullName `
        -T fields `
        -e frame.time_epoch `
        -e ip.src `
        -e ip.dst `
        -e tcp.srcport `
        -e tcp.dstport `
        -e frame.len `
        -e tcp.flags `
        -e tcp.stream `
        -e ftp.request.command `
        -e ftp.request.arg `
        -e ftp.response.code `
        -e ftp.response.arg `
        -E header=y `
        -E separator=, `
        -E quote=d `
        -E occurrence=f > $output
    }
}

Write-Host "Conversion Complete!" -ForegroundColor Green
