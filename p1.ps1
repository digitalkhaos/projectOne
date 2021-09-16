<#
    project one (p1.ps1) - SOC Analyst IP info tool
    by bulletproof
    2021

    TODO: turn into a windowed GUI
    TODO:(possibly) X-force report
#>

$VT_API_KEY = 'e3cf255cf4c5cf3d5438189b28c91fe91796ed569f6e4a39bed3834e93fba13c'
$AB_API_KEY = '7664fdaa5ee24939ea1f2fa2c39ca21f9d0530e58b030d8bf92d714ac89eba6104f0b1df95d495a9'

Function Get-WhoIsInfo {
    [cmdletbinding()]
    [OutputType("WhoIsResult")]
    Param (
        [parameter(
            Position = 0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]

        #friggin regex
        [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]
        [ValidateScript({
                $test_ip = ($_.split(".")).where({[int]$_ -gt 254})
                if ($test_ip) {
                    Throw "$_ is not valid"
                    $false
                }
                else {
                    $true
                }
        })]
        [string]$IPAddress
    )

    $whois_url = 'http://whois.arin.net/rest'

    #default is XML 
    $header = @{"Accept" = "application/xml"}

    Write-Host "- WHOIS Record -"
    $url = "$whois_url/ip/$ipaddress"
    $r = Invoke-Restmethod $url -Headers $header -ErrorAction stop
    $newUrl = "http://whois.arin.net/rest/org/"
    $handle = $r.net.orgRef.handle
    $info_url = $newUrl + $handle 
    $orgUrl = Invoke-Restmethod $info_url -Headers $header -ErrorAction stop

    #standard return info is ugly, will use this instead
    if ($r.net) {
        [pscustomobject]@{
            PSTypeName             = "WhoIsResult"
            IP                     = $ipaddress
            Name                   = $r.net.parentNetRef.name
            RegisteredOrganization = $orgUrl.org.name
            Description            = $r.net.desc
            City                   = $orgUrl.org.city
            Country                = $orgUrl.org.'iso3166-1'.name
            StartAddress           = $r.net.startAddress
            EndAddress             = $r.net.endAddress
            NetBlocks              = $r.net.netBlocks.netBlock | foreach-object {"$($_.startaddress)/$($_.cidrLength)"}
            Updated                = $r.net.updateDate -as [datetime]
        }
     }
}

Function Get-VirusTotalInfo {
    param (
        [Parameter(
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]

        #friggin regex
        [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]
        [ValidateScript( {
            $test_ip = ($_.split(".")).where({[int]$_ -gt 254})
                
            if ($test_ip) {
                 Throw "$_ is not valid"
                 $false
            }
            else {
                $true
            }
        })]
        [string]$ip_address
    )
    
    $url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    $Body = @{'ip' = $ip_address; 'apikey' = $VT_API_KEY}

    # parameters for REST Method
    $Params =  @{}
    $Params.add('Body', $Body)
    $Params.add('Method', 'Get')
    $Params.add('Uri', $url)

    #get the report
    $IPReport = Invoke-RestMethod @Params 

    #positive and total counts need to be looked at more

    $url_pos = 0
    $url_total = 0

    $IPReport.detected_urls | ForEach-Object {
        $url_pos = $_.positives
        $url_total = $_.total
    }
    
    Write-Host "- VirusTotal Analysis -"
    Write-Host "Associated url's with detected positives: $url_pos"
    Write-Host "Total number of submissions: $url_total`n" 

    $file_pos = 0
    $file_total = 0

    $IPReport.detected_downloaded_samples | ForEach-Object {
        $file_pos = $_.positives
        $file_total = $_.total
    }

    Write-Host "Associated files with detected positives: $file_pos"
    Write-Host "Total number of submissions: $file_total`n"
}

function Get-TorIPInfo {
    param (
        [Parameter(
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]

        #friggin regex
        [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]
        [ValidateScript( {
            $test_ip = ($_.split(".")).where({[int]$_ -gt 254})
                
            if ($test_ip) {
                 Throw "$_ is not valid"
                 $false
            }
            else {
                $true
            }
        })]
        [string]$ip_address
    )

    $tor_url = 'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1'
    $flag = 0

    Write-Host "- TOR Node Status -"

    #check ip_address against tor's list
    foreach($line in (Invoke-RestMethod $tor_url).split("`n")) {    
        if($line -eq $ip_address) {
            Write-Host "*******************ALERT ALERT******************"
            Write-Host "ALERT: $ip_address IS A TOR EXIT NODE" 
            write-host "*******************ALERT ALERT******************`n"
            $flag = 1
        }
    }
    # I have no idea why else{} won't work here but whatever, something to do with Jack sucking
    if($flag -eq 0) {
        write-host "No TOR exit node detected`n"
        $flag = 0
    }
}

Function Get-AbusedIPInfo {
    param (
        [Parameter(
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]

        [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]
        [ValidateScript( {
            $test_ip = ($_.split(".")).where({[int]$_ -gt 254})
                
            if ($test_ip) {
                 Throw "$_ is not valid"
                 $false
            }
            else {
                $true
            }
        })]
        [string]$ip_address
    )

    $url = 'https://api.abuseipdb.com/api/v2/check'
    $days = 180

    $query = @{
        'ipAddress' = $ip_address
        'maxAgeInDays' = $days
    }

    $header = @{
        'Accept' = 'application/json'
        'Key' = $AB_API_KEY
    }

    write-host "- AbuseIPDB Analysis -"

    
    #$response = Invoke-RestMethod -Method Get -Uri $url -Body $query -Headers $header
    $test_response = Invoke-RestMethod -Method Get -Uri 'https://api.abuseipdb.com/api/v2/check' -Body $query -Headers $header

    write-host "IP Address:        " $test_response.data.ipAddress
    write-host "Domain Name:       " $test_response.data.domain
    write-host "Total Reports:     " $test_response.data.totalReports
    write-host "Abuse Score:       " $test_response.data.abuseconfidencescore "%" 
    write-host "Last Report:       " $test_response.data.lastReportedAt 

    if($test_response.data.abuseconfidencescore -gt 5) {
        write-host "*******************ALERT ALERT******************"
        write-host "ALERT: $ip_address has ISSUES"
        write-host "*******************ALERT ALERT******************`n"
    }
}

$ip = Read-Host -Prompt "Enter an IP address to lookup"

Get-WhoIsInfo($ip)
Get-VirusTotalInfo($ip)
Get-TorIPInfo($ip)
Get-AbusedIPInfo($ip)
