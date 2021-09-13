<#
project one (p1.ps1) - SOC Analyst IP info tool
by John
2021

TODO: turn into a windowed GUI
TODO: add abusedIP report
TODO: add IPQualityScore report
TODO:(possibly) X-force report

#>

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
    
    #standard return info is ugly, will use this instead
    if ($r.net) {
        [pscustomobject]@{
            PSTypeName             = "WhoIsResult"
            IP                     = $ipaddress
            Name                   = $r.net.customerRef.name
            RegisteredOrganization = $r.net.orgRef.name
            Description            = $r.net.desc
            #City                   = (Invoke-RestMethod $r.net.orgRef.'#text').org.city
            Country                = $r.net.countryRef.name
            StartAddress           = $r.net.startAddress
            EndAddress             = $r.net.endAddress
            NetBlocks              = $r.net.netBlocks.netBlock | foreach-object {"$($_.startaddress)/$($_.cidrLength)"}
            Updated                = $r.net.updateDate -as [datetime]
            Handle                 = $r.net.parentNetRef.handle
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
    $Body = @{'ip' = $ip_address; 'apikey' = 'e3cf255cf4c5cf3d5438189b28c91fe91796ed569f6e4a39bed3834e93fba13c'}

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
    Write-Host "Total number of submissions: $url_total"
    Write-Host
    Write-Host 

    $file_pos = 0
    $file_total = 0

    $IPReport.detected_downloaded_samples | ForEach-Object {
        $file_pos = $_.positives
        $file_total = $_.total
    }

    Write-Host "Associated files with detected positives: $file_pos"
    Write-Host "Total number of submissions: $file_total"
    Write-Host
    Write-Host
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
            $flag = 1
        }
    }
    # I have no idea why else{} won't work here but whatever, something to do with Jack sucking
    if($flag -eq 0) {
        write-host "No TOR exit node detected"
        $flag = 0
    }
}

$ip = Read-Host -Prompt "Enter an IP address to lookup"

Get-WhoIsInfo($ip)
Get-VirusTotalInfo($ip)
Get-TorIPInfo($ip)
