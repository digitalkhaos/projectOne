function Get-VTIPReport
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # IP Address to scan for.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$IPAddress,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        $APIKey = $Global:VTAPIKey
    }
    Process
    {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'ip'= $IPAddress; 'apikey'= $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $IPReport = Invoke-RestMethod @Params
        
        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }

        $IPReport.pstypenames.insert(0,'VirusTotal.IP.Report')
        $IPReport
        
    }
    End
    {
    }
}

