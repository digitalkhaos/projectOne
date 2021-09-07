<#
project one (p1.ps1) - SOC Analyst IP info tool
by John
2021

TODO: turn into a windowed GUI
TODO: add abusedIP report
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

    $whoisinfo = Get-WhoIs($IPAddress)

    Write-Host $whoisinfo.Name
    Write-Host $whoisinfo.Country
    Write-Host $whoisinfo.Organization

}

function Get-VirusTotalInfo {
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

    $url_pos = 0
    $url_total = 0

    $IPReport.detected_urls | ForEach-Object {
        $url_pos = $_.positives
        $url_total = $_.total
    }
    
    Write-Host "- VirusTotal Analysis -"
    Write-Host "Associated url's with detected positives: $url_pos"
    Write-Host "Total number of submissions: $url_total"

    $file_pos = 0
    $file_total = 0

    $IPReport.detected_downloaded_samples | ForEach-Object {
        $file_pos = $_.positives
        $file_total = $_.total
    }

    Write-Host "Associated files with detected positives: $file_pos"
    Write-Host "Total number of submissions: $file_total"
}

$ip = Read-Host -Prompt "Enter an IP address to lookup"

Get-WhoIsInfo($ip)
Get-VirusTotalInfo($ip)
