<#
    project one (p1.ps1) - SOC Analyst IP info tool
    by bulletproof
    2021

    TODO: clean up virustotal counts
    TODO:(possibly) X-force report


#>
$XFORCE_API_KEY = '4f3bb142-bd30-4d99-97cb-29060807f022'
$XFORCE_API_PASSWORD = '518bd860-f238-4672-87c6-ed01a47ddf18'
$VT_API_KEY = 'e3cf255cf4c5cf3d5438189b28c91fe91796ed569f6e4a39bed3834e93fba13c'
$AB_API_KEY = '7664fdaa5ee24939ea1f2fa2c39ca21f9d0530e58b030d8bf92d714ac89eba6104f0b1df95d495a9'

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
Add-Type -AssemblyName System.Drawing

$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Size = New-Object System.Drawing.Size(550, 430)
$mainForm.FormBorderStyle = 'Fixed3D'
$mainform.MaximizeBox = $false
$mainForm.Text = 'Bulletproof Security Analyst Tool'
$mainForm.StartPosition = 'CenterScreen'
$mainForm.AcceptButton = $okBtn
$mainForm.Font = New-Object System.Drawing.Font("opensans", 10, [System.Drawing.FontStyle]::bold)

$okBtn = New-Object System.Windows.Forms.Button
$okBtn.Location = New-Object System.Drawing.Point(275, 30)
$okBtn.Size = New-Object System.Drawing.Size(75, 23)
$okBtn.Height = 25
$okBtn.Width = 80
$okBtn.Text = 'Search'
$okBtn.Font = New-Object System.Drawing.Font("opensans", 8, [System.Drawing.FontStyle]::bold)
$mainForm.Controls.Add($okBtn)

$clearBtn = New-Object System.Windows.Forms.Button
$clearBtn.Location = New-Object System.Drawing.Point(375, 30)
$clearBtn.Size = New-Object System.Drawing.Size(75, 23)
$clearBtn.Height = 25
$clearBtn.Width = 80
$clearBtn.Text = 'Clear'
$clearBtn.Font = New-Object System.Drawing.Font("opensans", 8, [System.Drawing.FontStyle]::bold)
$mainForm.Controls.Add($clearBtn)

$exitBtn = New-Object System.Windows.Forms.Button
$exitBtn.Location = New-Object System.Drawing.Point(427, 345)
$exitBtn.Size = New-Object System.Drawing.Size(60, 13)
$exitBtn.Height = 25
$exitBtn.Width = 80
$exitBtn.Text = 'Exit'
$exitBtn.Font = New-Object System.Drawing.Font("opensans", 10, [System.Drawing.FontStyle]::Regular)
$exitBtn.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$mainForm.CancelButton = $exitBtn
$mainForm.Controls.Add($exitBtn)

$lbl = New-Object System.Windows.Forms.label
$lbl.Location = New-Object System.Drawing.Point(10, 30)
$lbl.Size = New-Object System.Drawing.Size(80, 30)
$lbl.Text = 'IP Address:'
$mainForm.Controls.Add($lbl)

$whoisTxtBox = New-Object System.Windows.Forms.TextBox
$whoisTxtBox.Location = New-Object System.Drawing.Point(22, 72)
$whoisTxtBox.Size = New-Object System.Drawing.Size(300, 10)
$whoisTxtBox.Height = 230
$whoisTxtBox.Width = 210
$whoisTxtBox.Multiline = $true
$whoisTxtBox.ReadOnly = $true
$whoisTxtBox.Font = New-Object System.Drawing.Font("opensans", 9, [System.Drawing.FontStyle]::Regular)
$mainForm.Controls.Add($whoisTxtBox)

$abusedipTxtBox = New-Object System.Windows.Forms.TextBox
$abusedipTxtBox.Location = New-Object System.Drawing.Point(247, 73)
$abusedipTxtBox.Size = New-Object System.Drawing.Size(420, 10)
$abusedipTxtBox.Multiline = $true
$abusedipTxtBox.Height =104
$abusedipTxtBox.Width = 260
$abusedipTxtBox.Font = New-Object System.Drawing.Font("opensans", 9, [System.Drawing.FontStyle]::Regular)
$abusedipTxtBox.ReadOnly = $true
$mainForm.Controls.Add($abusedipTxtBox)

$ipTxtBox = New-Object System.Windows.Forms.TextBox
$ipTxtBox.Location = New-Object System.Drawing.Point(90, 30)
$ipTxtBox.Size = New-Object System.Drawing.Size(420, 10)
$ipTxtBox.Multiline = $false
$ipTxtBox.Height = 185
$ipTxtBox.Width = 165
$ipTxtBox.ReadOnly = $false
$mainForm.Controls.Add($ipTxtBox)

$virustotalTxtBox = New-Object System.Windows.Forms.TextBox
$virustotalTxtBox.Location = New-Object System.Drawing.Point(247, 187)
$virustotalTxtBox.Size = New-Object System.Drawing.Size(300, 10)
$virustotalTxtBox.Multiline = $true
$virustotalTxtBox.Height = 104
$virustotalTxtBox.Width = 260
$virustotalTxtBox.ReadOnly = $true
$virustotalTxtBox.Font = New-Object System.Drawing.Font("opensans", 9, [System.Drawing.FontStyle]::Regular)
$mainForm.Controls.Add($virustotalTxtBox)

$torTxtBox = New-Object System.Windows.Forms.TextBox
$torTxtBox.Location = New-Object System.Drawing.Point(247, 300)
$torTxtBox.Size = New-Object System.Drawing.Size(10, 200)
$torTxtBox.Multiline = $true
$torTxtBox.Height = 20
$torTxtBox.Width = 250
$torTxtBox.ReadOnly = $true
$torTxtBox.Font = New-Object System.Drawing.Font("opensans", 8, [System.Drawing.FontStyle]::Regular)
$mainForm.Controls.Add($torTxtBox)

$xforceTxtBox = New-Object system.Windows.Forms.TextBox
$xforceTxtBox.location = New-Object System.Drawing.Point(24,309)
$xforceTxtBox.multiline = $true
$xforceTxtBox.width = 207
$xforceTxtBox.height = 65
$xforceTxtBox.readonly = $true
$xforceTxtBox.Font = New-Object System.Drawing.Font("opensans", 9, [System.Drawing.FontStyle]::Regular)   
$mainForm.Controls.Add($xforceTxtBox)    

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

    $whoisTxtBox.Text = "- WHOIS Record -`n"

    $url = "$whois_url/ip/$ipaddress"
    $r = Invoke-Restmethod $url -Headers $header -ErrorAction stop
    $newUrl = "http://whois.arin.net/rest/org/"
    $handle = $r.net.orgRef.handle
    $infoUrl = $newUrl + $handle 
    $orgUrl = Invoke-Restmethod $infoUrl -Headers $header -ErrorAction stop

    #standard return info is ugly, will use this instead
    if ($r.net) {
        $whoisTxtBox.AppendText(`
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
        )
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
    
    $virustotalTxtBox.text =  "- VirusTotal Analysis -`r`n"
    $virustotalTxtBox.AppendText("Associated url's with detected positives: $url_pos`r`n")
    $virustotalTxtBox.AppendText("Total number of submissions: $url_total`r`n")

    $file_pos = 0
    $file_total = 0

    $IPReport.detected_downloaded_samples | ForEach-Object {
        $file_pos = $_.positives
        $file_total = $_.total
    }

    $virustotalTxtBox.AppendText("Associated files with detected positives: $file_pos`r`n")
    $virustotalTxtBox.AppendText("Total number of submissions: $file_total`r`n")
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

    #$torTxtBox.Text =  "- TOR Node Status -`n"

    #check ip_address against tor's list
    foreach($line in (Invoke-RestMethod $tor_url).split("`n")) {    
        if($line -eq $ip_address) {
            #$torTxtBox.AppendText("*******************ALERT ALERT******************`n")
            $torTxtBox.Text("ALERT: $ip_address IS A TOR EXIT NODE`n") 
            #$torTxtBox.AppendText("*******************ALERT ALERT******************`n")
            $flag = 1
        }
    }
    # I have no idea why else{} won't work here but whatever
    if($flag -eq 0) {
        $torTxtBox.Text = "No TOR exit node detected"
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

    #$url = 'https://api.abuseipdb.com/api/v2/check'
    $days = 180

    $query = @{
        'ipAddress' = $ip_address
        'maxAgeInDays' = $days
    }

    $header = @{
        'Accept' = 'application/json'
        'Key' = $AB_API_KEY
    }

    $abusedipTxtBox.Text = "`n- AbuseIPDB Analysis -`n"

    #no idea why this needs a string literal but whatever
    #$response = Invoke-RestMethod -Method Get -Uri $url -Body $query -Headers $header
    $test_response = Invoke-RestMethod -Method Get -Uri 'https://api.abuseipdb.com/api/v2/check' -Body $query -Headers $header

    $abusedipTxtBox.AppendText("`r`nIP Address:        " + $test_response.data.ipAddress)
    $abusedipTxtBox.AppendText("`r`nDomain Name:       " + $test_response.data.domain)
    $abusedipTxtBox.AppendText("`r`nTotal Reports:     " + $test_response.data.totalReports)
    $abusedipTxtBox.AppendText("`r`nAbuse Score:       " + $test_response.data.abuseconfidencescore)
    $abusedipTxtBox.AppendText("`r`nLast Report:       " + $test_response.data.lastReportedAt)

    if($test_response.data.abuseconfidencescore -gt 5) {
        $abusedipTxtBox.AppendText("`nALERT: $ip_address has issues!`n")
    }
}

Function Get-XFORCEInfo {
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

    $head = New-APIAuthHeader -Key $XFORCE_API_KEY -Password $XFORCE_API_PASSWORD
    $API_URI_URL = "https://api.xforce.ibmcloud.com/url"
    $API_URI_IP = "https://api.xforce.ibmcloud.com/ipr"

     #IP Report
     $ipR = $(Invoke-RestMethod -Uri "$API_URI_IP/$ip_address" -Method: Get -Headers $head)
     write-host $ipR.ip

     $report = [Ordered] @{
         'IP' = $ipR.ip
         'Geo_IP' = $ipR.geo.country
         'IP_Score' = $ipR.score
         'Score_Reason' = $ipR.reason
         'Score_Description' = $ipR.reasonDescription
         'Categories' = $ipR.cats
     }
     
     $report = New-Object -TypeName PSObject -ArgumentList $report

     $xforceTxtBox.Text = "- XForce Analysis -`n"
     $xforceTxtBox.AppendText("$API_URI_IP/$ip_address")
     #$xforceTxtBox.AppendText($report.ToString())
}

function New-APIAuthHeader{
    [cmdletbinding()]
     Param (
         [Parameter (Mandatory=$True, HelpMessage = "Username or API key if not given a username",Position = 1)][string]$Key,
         [Parameter (Mandatory=$True, HelpMessage = "Password or API key if not given a password",Position = 2)][Alias('Pass')][string]$Password
     )

         $pair = "$Key" + ":" + "$Password"
         $encoded = "Basic " + "$([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair)))"
         $header = @{Authorization = $encoded}
 }

Function Clear-Info{
    $virustotalTxtBox.Text = ""
    $torTxtBox.Text = ""
    $abusedipTxtBox.Text = ""
    $whoisTxtBox.Text = ""
    $ipTxtBox.Text = ""
    $xforceTxtBox.Text = ""
}

$okBtn.Add_Click({
    Get-WhoIsInfo($ipTxtBox.Text.Trim())
    Get-VirusTotalInfo($ipTxtBox.Text.Trim())
    Get-TorIPInfo($ipTxtBox.Text.Trim())
    Get-AbusedIPInfo($ipTxtBox.Text.Trim())
    Get-XFORCEInfo($ipTxtBox.Text.Trim())
})

$clearBtn.Add_Click({
    Clear-Info
})

# bring up mainForm
$mainForm.Add_Shown({$mainForm.activate()})
$mainForm.ShowDialog()  
