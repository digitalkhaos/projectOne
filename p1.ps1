<#
    project one (p1.ps1) - SOC Analyst IP info tool
    2021 by bulletproof

    TODO: clean up virustotal counts
#>

$XFORCE_API_KEY = ''
$XFORCE_API_PASSWORD = ''
$VT_API_KEY = ''
$AB_API_KEY = ''

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
Add-Type -AssemblyName System.Drawing

$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Size = New-Object System.Drawing.Size(550, 450)
$mainForm.FormBorderStyle = 'Fixed3D'
$mainform.MaximizeBox = $false
$mainForm.Text = 'Bulletproof Security Analyst Tool'
$mainForm.StartPosition = 'CenterScreen'
$mainForm.AcceptButton = $okBtn
$mainForm.CancelButton = $cancelBtn
$mainForm.KeyPreview = $true
#$mainForm.Icon = "C:\Users\bsi534\OneDrive - Bulletproof\Pictures\fav.png"
$mainForm.Font = New-Object System.Drawing.Font("opensans", 10, [System.Drawing.FontStyle]::bold)

$searchBtn = New-Object System.Windows.Forms.Button
$searchBtn.Location = New-Object System.Drawing.Point(275, 30)
$searchBtn.Size = New-Object System.Drawing.Size(75, 23)
$searchBtn.Height = 25
$searchBtn.Width = 80
$searchBtn.Text = 'Search'
$searchBtn.Font = New-Object System.Drawing.Font("opensans", 8, [System.Drawing.FontStyle]::bold)
$mainForm.Controls.Add($searchBtn)

$clearBtn = New-Object System.Windows.Forms.Button
$clearBtn.Location = New-Object System.Drawing.Point(375, 30)
$clearBtn.Size = New-Object System.Drawing.Size(75, 23)
$clearBtn.Height = 25
$clearBtn.Width = 80
$clearBtn.Text = 'Clear'
$clearBtn.Font = New-Object System.Drawing.Font("opensans", 8, [System.Drawing.FontStyle]::bold)
$mainForm.Controls.Add($clearBtn)

$exitBtn = New-Object System.Windows.Forms.Button
$exitBtn.Location = New-Object System.Drawing.Point(427, 375)
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
$ipTxtBox.Select()

$ipTxtBox.Add_Keydown({
    If ($_.KeyCode -eq 'Return'){
        $searchBtn.PerformClick()
    }   
  })

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
$torTxtBox.Height = 50
$torTxtBox.Width = 260
$torTxtBox.ReadOnly = $true
$torTxtBox.Font = New-Object System.Drawing.Font("opensans", 8, [System.Drawing.FontStyle]::Regular)
$mainForm.Controls.Add($torTxtBox)

$xforceTxtBox = New-Object system.Windows.Forms.TextBox
$xforceTxtBox.location = New-Object System.Drawing.Point(24,310)
$xforceTxtBox.multiline = $true
$xforceTxtBox.width = 207
$xforceTxtBox.height = 85
$xforceTxtBox.readonly = $true
$xforceTxtBox.Font = New-Object System.Drawing.Font("opensans", 8, [System.Drawing.FontStyle]::Regular)   
$mainForm.Controls.Add($xforceTxtBox)    

Function Get-WhoIsInfo {
    Param ([string]$ip_address)

    $whois_url = 'http://whois.arin.net/rest'
    $header = @{"Accept" = "application/xml"}
    $url = "$whois_url/ip/$ip_address"
    $r = Invoke-Restmethod $url -Headers $header -ErrorAction stop
    $newUrl = "http://whois.arin.net/rest/org/"
    $handle = $r.net.orgRef.handle
    $infoUrl = $newUrl + $handle 
    $orgUrl = Invoke-Restmethod $infoUrl -Headers $header -ErrorAction stop

    $whoisTxtBox.Text = "- WHOIS Record -`r`n"

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
            Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ip_address
    )
    
    $url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    $Body = @{'ip' = $ip_address; 'apikey' = $VT_API_KEY}

    # parameters for REST
    $Params =  @{}
    $Params.add('Body', $Body)
    $Params.add('Method', 'Get')
    $Params.add('Uri', $url)

    #get report
    $IPReport = Invoke-RestMethod @Params 

    #zero counts need to be looked at more

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
    param ([string]$ip_address)

    $tor_url = 'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1'
    $flag = 0

    #check ip_address against tor's list
    foreach($line in (Invoke-RestMethod $tor_url).split("`n")) {    
        if($line -eq $ip_address) {
            $torTxtBox.Text = "ALERT: $ip_address IS A TOR EXIT NODE`n"
            $flag = 1
        }
    }
    # I have no idea why else{} won't work here but whatever, this does...
    if($flag -eq 0) {
        $torTxtBox.Text = "No TOR exit node detected"
        $flag = 0
    }
}

Function Get-AbusedIPInfo {
    param ([string]$ip_address)

    $days = 180
    $query = @{
        'ipAddress' = $ip_address
        'maxAgeInDays' = $days
    }
    $head = @{
        'Accept' = 'application/json'
        'Key' = $AB_API_KEY
    }

    $abusedipTxtBox.Text = "`r`n- AbuseIPDB Analysis -"

    #no idea why this needs a string literal but whatever
    $test_response = Invoke-RestMethod -Method Get -Uri 'https://api.abuseipdb.com/api/v2/check' -Body $query -Headers $head

    $abusedipTxtBox.AppendText("`r`nIP Address:        " + $test_response.data.ipAddress)
    $abusedipTxtBox.AppendText("`r`nDomain Name:       " + $test_response.data.domain)
    $abusedipTxtBox.AppendText("`r`nTotal Reports:     " + $test_response.data.totalReports)
    $abusedipTxtBox.AppendText("`r`nAbuse Score:       " + $test_response.data.abuseconfidencescore + "%")
    $abusedipTxtBox.AppendText("`r`nLast Report:       " + $test_response.data.lastReportedAt)

    if($test_response.data.abuseconfidencescore -gt 5) {
        $abusedipTxtBox.AppendText("`r`nALERT: $ip_address has issues!`n")
    }
}

function Get-Header{
     Param ([string]$Key, [string]$Password)

         $pair = "$Key" + ":" + "$Password"
         $encoded = "Basic " + "$([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair)))"
         $header = @{Authorization = $encoded}
         Write-Output -InputObject $header
 }

Function Get-XFORCEInfo {
    param ([string]$ip_address)

    $head = Get-Header -Key $XFORCE_API_KEY -Password $XFORCE_API_PASSWORD
    $API_URI_IP = "https://api.xforce.ibmcloud.com/ipr"
     $ipReport = $(Invoke-RestMethod -Uri "$API_URI_IP/$ip_address" -Method: Get -Headers $head)
  
     $report = [Ordered] @{
         'IP_Score' = $ipReport.score
         'Score_Reason' = $ipReport.reason
         'Score_Description' = $ipReport.reasonDescription
     }
     
     $report = New-Object -TypeName PSObject -ArgumentList $report

     $xforceTxtBox.Text = "- XForce Analysis -"
     $xforceTxtBox.AppendText("`r`nIP Score: " +    $report.IP_Score.ToString())
     $xforceTxtBox.AppendText("`r`nReason: " +      $report.Score_Reason)
     $xforceTxtBox.AppendText("`r`nDescription: " + $report.Score_Description)
}

Function Clear-Info{
    $virustotalTxtBox.Text = ""
    $torTxtBox.Text = ""
    $abusedipTxtBox.Text = ""
    $whoisTxtBox.Text = ""
    $ipTxtBox.Text = ""
    $xforceTxtBox.Text = ""
}

$searchBtn.Add_Click({
    
    #TODO: check for correct input format
    <#
    #friggin regex
       IP_ADDRESS_PATTERN("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
       check for valid octects
                $test_ip = ($_.split(".")).where({[int]$_ -gt 254})
                if ($test_ip) {
                    Throw "$_ is not valid"
                    $false
                }
                else {
                    $true
                }
    #>

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
