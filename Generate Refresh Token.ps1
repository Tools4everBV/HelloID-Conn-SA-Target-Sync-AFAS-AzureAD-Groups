# Azure AD Application Paramters
$AADtenantID = ""
$AADAppId = ""
$AADAppSecret = ""

$redirectUri = "http://localhost"
$scopes = "Group.ReadWrite.All", "Directory.ReadWrite.All", "Directory.AccessAsUser.All"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Function to Genereate Azure Authorization code
Function Get-AzureAuthCode {
    param(
        [parameter(Mandatory=$true)]$AADtenantID,
        [parameter(Mandatory=$true)]$AADAppId,
        [parameter(Mandatory=$true)]$RedirectUri,
        [parameter(Mandatory=$true)]$scopes
    )
    Add-Type -AssemblyName System.Windows.Forms

    # Create base URI with Tenant ID
    $authorizationCodeUri = "https://login.microsoftonline.com/$AADtenantID/oauth2/authorize?response_type=code&prompt=admin_consent"
    # Add App ID
    $authorizationCodeUri = $authorizationCodeUri + "&client_id=$AADAppId"
    # Add redirect URI (URL encoded)
    $redirectUriEncoded = [System.Web.HttpUtility]::UrlEncode($redirectUri)
    $authorizationCodeUri = $authorizationCodeUri + "&redirect_uri=$redirectUriEncoded"
    # Add resource Uri (URL encoded)
    $resourceUri = "https://graph.microsoft.com"
    $resourceUriEncoded = [System.Web.HttpUtility]::UrlEncode($resourceUri)
    $authorizationCodeUri = $authorizationCodeUri + "&resource=$resourceUriEncoded"
    # Add scopes (separted by "%20")
    $scopesEncoded = $scopes -join "%20"
    $authorizationCodeUri = $authorizationCodeUri + "&scope=$scopesEncoded"

    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width=440;Height=640}
    $web  = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width=420;Height=600;Url=$authorizationCodeUri }

    $DocComp  = {
        $Global:uri = $web.Url.AbsoluteUri        
        if ($Global:uri -match "error=[^&]*|code=[^&]*") {$form.Close() }
    }
    $web.ScriptErrorsSuppressed = $true
    $web.Add_DocumentCompleted($DocComp)
    $form.Controls.Add($web)
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() | Out-Null

    $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)
    $output = @{}
    foreach($key in $queryOutput.Keys){
        $output["$key"] = $queryOutput[$key]
    }

    $authCode = $output.code

    return $authCode
}

# Function to Genereate Azure Refresh token from Authorization code
Function Get-AzureRefreshToken {
    param(
        [parameter(Mandatory=$true)]$AADtenantID,
        [parameter(Mandatory=$true)]$AADAppId,
        [parameter(Mandatory=$true)]$RedirectUri,
        [parameter(Mandatory=$true)]$AuthorizationCode
    )
    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"
    $body = @{
        Grant_Type    = "authorization_code"
        client_Id     = $AADAppId
        client_secret = $AADAppSecret
        redirect_uri  = $RedirectUri
        code          = $AuthorizationCode       
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $refreshToken = $Response.refresh_token;

    return $refreshToken
}

try {
   Write-Verbose -Verbose"Generating Microsoft Graph API Authorization Code.."

    $authorizationCode = Get-AzureAuthCode -AADtenantID $AADtenantID -AADAppId $AADAppId -RedirectUri $redirectUri -scopes $scopes
} catch {
    Write-Error "Could not create Authorization Code. Error: $_"
}

try {
   Write-Verbose -Verbose"Generating Microsoft Graph API Refresh Token.."

    $refreshToken = Get-AzureRefreshToken -AADtenantID $AADtenantID -AADAppId $AADAppId -AuthorizationCode $authorizationCode -RedirectUri $redirectUri
    Write-Output $refreshToken
} catch {
    Write-Error "Could not create Refresh Token. Error: $_"
}