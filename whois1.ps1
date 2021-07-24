Function Get-WhoIs {
    [cmdletbinding()]
    [OutputType("WhoIsResult")]
    Param (
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an IPV4 address to lookup with WhoIs",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]
         [ValidateScript( {
            #verify each octet is valid to simplify the regex
                $test = ($_.split(".")).where({[int]$_ -gt 254})
                if ($test) {
                    Throw "$_ does not appear to be a valid IPv4 address"
                    $false
                }
                else {
                    $true
                }
            })]
        [string]$IPAddress
    )

    Begin {
        Write-Verbose "Starting $($MyInvocation.Mycommand)"
        $baseURL = 'http://whois.arin.net/rest'
        #default is XML anyway
        $header = @{"Accept" = "application/xml"}

    } #begin

    Process {
        Write-Verbose "Getting WhoIs information for $IPAddress"
        $url = "$baseUrl/ip/$ipaddress"
        Try {
            $r = Invoke-Restmethod $url -Headers $header -ErrorAction stop
            Write-verbose ($r.net | Out-String)
        }
        Catch {
            $errMsg = "Sorry. There was an error retrieving WhoIs information for $IPAddress. $($_.exception.message)"
            $host.ui.WriteErrorLine($errMsg)
        }

        if ($r.net) {
            Write-Verbose "Creating result"
            [pscustomobject]@{
                PSTypeName             = "WhoIsResult"
                IP                     = $ipaddress
                Name                   = $r.net.name
                RegisteredOrganization = $r.net.orgRef.name
                City                   = (Invoke-RestMethod $r.net.orgRef.'#text').org.city
                StartAddress           = $r.net.startAddress
                EndAddress             = $r.net.endAddress
                NetBlocks              = $r.net.netBlocks.netBlock | foreach-object {"$($_.startaddress)/$($_.cidrLength)"}
                Updated                = $r.net.updateDate -as [datetime]
            }
        } #If $r.net
    } #Process

    End {
        Write-Verbose "Ending $($MyInvocation.Mycommand)"
    } #end
}

function Get-VirusTotalInfo {
    param (
        [Parameter(Position = 0,
                HelpMessage = "Enter an api key:",
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true)]       
        [ValidateNotNullOrEmpty()]
        [string]$vt_api_key,

        [Parameter(Position = 1,
                HelpMessage = "Enter an IP address:",
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]
        [ValidateScript( {
                #verify each octet is valid to simplify the regex
                $test = ($_.split(".")).where({[int]$_ -gt 254})
                
                if ($test) {
                    Throw "$_ does not appear to be a valid IPv4 address"
                    $false
                }
                else {
                    $true
                }
            })]
        [string]$ip_address
    )
    
    $baseURL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    $parameters = @{ 'apikey' = $vt_api_key, 'resource' = $ip_address }
   
    $response = Invoke-RestMethod -Method Get -Uri $baseURL -Headers @{ "Accept-Encoding" = "gzip" } -Body $parameters
    
    write-host "$response"
}

Write-Host "Starting $($MyInvocation.Mycommand)"
Get-WhoIs
Get-VirusTotalInfo

