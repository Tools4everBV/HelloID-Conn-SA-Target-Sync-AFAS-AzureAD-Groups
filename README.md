<!-- TABLE OF CONTENTS -->
## Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Connection settings](#connection-settings)
- [contents](#contents)
- [Remarks](#remarks)
- [Getting the Azure AD graph API access](#getting-the-azure-ad-graph-api-access)
  - [Application Registration](#application-registration)
  - [Configuring App Permissions](#configuring-app-permissions)
  - [Authentication and Authorization](#authentication-and-authorization)
  - [Creating the Refresh token](#creating-the-refresh-token)
- [Getting help](#getting-help)
- [HelloID Docs](#helloid-docs)


## Introduction
Make sure you have Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running.

By using this connector you will have the ability to create AD groups based on data from the AFAS Profit HR system.


## Getting started

### Prerequisites

- [ ] Azure Active Directory App Reqistration

  The Azure Active Directory App Reqistration must be created and granted the following __delegated permissions__ (https://docs.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=http). These are __delegated permissions__ since the attributes __allowExternalSenders__ & __autoSubscribeNewMembers__, support only delegated permissions. See known issues for examples.
  (https://docs.microsoft.com/en-us/graph/api/group-update?view=graph-rest-1.0&tabs=http)
  - Group.ReadWrite.All
  - Directory.ReadWrite.All
  - Directory.AccessAsUser.All

- [ ] Azure Active Directory App refresh token

  Since we are using delegated permmissions, we need to create an access token which has permissions to act "as a user". This access token can be created by using the refresh token, which we have to create (one-time) manually.

- [ ] Windows PowerShell 5.1

  Windows PowerShell 5.1 must be installed on the server where the 'HelloID Directory agent and Service Automation agent' are running.

  > The connector is compatible with older versions of Windows PowerShell. Although we cannot guarantuee the compatibility.

- [ ] AFAS App Token

  Connecting to Profit is done using the app connector system.
  Please see the following pages from the AFAS Knowledge Base for more information.
  
  - [Create the APP connector](https://help.afas.nl/help/NL/SE/App_Apps_Custom_Add.htm)
  - [Manage the APP connector](https://help.afas.nl/help/NL/SE/App_Apps_Custom_Maint.htm)
  - [Manual add a token to the APP connector](https://help.afas.nl/help/NL/SE/App_Apps_Custom_Tokens_Manual.htm)

- [ ] AFAS GetConnector Tools4ever - HelloID - T4E_HelloID_OrganizationalUnits

  The interface to communicate with Profit is through a set of GetConnectors, which is component that allows the creation of custom views on the Profit data. GetConnectors are based on a pre-defined 'data collection', which is an existing view based on the data inside the Profit database. 
  
  For this connector we have created a default set, which can be imported directly into the AFAS Profit environment.
  
  The following GetConnectors are required by HelloID: 
  -	Tools4ever - HelloID - T4E_HelloID_OrganizationalUnits

### Connection settings

The connection settings are defined in the automation variables.
 1. Create the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)

| Variable name     | Description                                                   | Example value                         |
| ----------------- | ------------------------------------------------------------- | ------------------------------------- |
| AFASBaseUri       | Base URI of the AFAS REST API endpoint for this environment   | https://12345.rest.afas.online/ProfitRestServices |
| AFASToke          | App token in XML format for this environment                  | \<token>\<version>1\</version>\<data>D5R324DD5F4TRD945E530ED3CDD70D94BBDEC4C732B43F285ECB12345678\</data>\</token>    |
| AADtenantID       | Id of the Azure tenant                                        | 12fc345b-0c67-4cde-8902-dabf2cad34b5  |
| AADAppId          | Id of the Azure app                                           | f12345c6-7890-1f23-b456-789eb0bb1c23  |
| AADAppSecret      | Secret of the Azure app                                       | G1X2HsBw-co3dTIB45RE6vY.mSU~6u.7.8    |
| AADRefreshToken   | Refresh token of the Azure app                                | 0.ABCDEFGHIJKLMNOPQRS_PK0mtsE5afl5BYdPsASFbrS7jIZ0AAc.AgABAAAAAAD--DLA3VO7QrddgJg7WevrAgDs_wQA9P-XOTtPMo2xp9vfbHGvVkHaBZh4D3YmTkx_WagBOk358QjDwHUsiuVvyKvP6FTbQQt8kCidfMC9cmIYesHG4Ft2B1HwJNX28OpiFPuFti1D4Is30GgQ685i_ovS4iXDCUgtm2zpI6ZQJVqoOidXZQW_lSupdcclMK_JCIb7LBuJBDXfy0-f75C734_nxL0nggS9mn-e_KuJpHvypvU8OS9MPDBArhUopZum2y-2oNE65Wr-xpKm_Zeyr3iUGSZg98nbaryHw-lbeyFC8LcNqqMB_T7BcgvJicHSnj6DtjjpMyjKMwsCAnxz2bUYoLLjGFHk8EhDUCuV9lzUW1BTko5_I31TQdX0XY94vHTU34N93t3QPrQFMf8UhDjfQKiCDj3r2b7YR9ndS8MNp9MIa1CbL8vI4EM8GO4wtVI30Dhca4HaMtpph6uJp3echt-q7AVNQ_7ZHgx_YFZNqDmJyYq3nrae7LYRo0kvM382ss7JpCylodwya89mC_SlnrFhLM_zbt1TQkOtZqiVHbdQk3z-MX1iZso5Mk17Yks1ao0mS0RJfWVWSlOq_Sp-2yaiCsP-lV1PVdvvY_AkuOulP1kPG_VfC0DN3pGjSQJ8J9Ot5hfyElWyPst9Nc-ODErLhEqIl-3IR6wPKFN2ffjt8-dtCVMlVdBd1QANQOFBiIGA-_BZdGLvzROrWCOE9dDtyBQ_LnxdnnOVdjUqJ-xdql1p13Xjy6ZTtcZtTDmFN5hSMffYuUtuwEOy_Xb91Y2tvwOxcSe9dj7ElOLZDo2C7fGsMgaIJ1gK8xt9OWsS1o1sQZKQADTZq5TTxJp7PY3tJsUnOlD4q8ZEyVBQAvRKinpajBRcbq2lTCVt0JgXAryWztqYTpAxiqaBr51vuR4pbVRtKv-h_10tYD-TUV1WeX2fY3GuZA4B5g |

## contents

| File/Directory                                             | Description                                                  |
| ---------------------------------------------------------- | ------------------------------------------------------------ |
| Sync AFAS Organizational Units to AD Groups.ps1            | Synchronizes the AFAS data to AD groups                      |
| Tools4ever - HelloID - T4E_HelloID_OrganizationalUnits.gcn | AFAS GetConnector to provide all Organizational Units        | 

## Remarks
- The groups are only created, no update or deletion will take place.
  
> When a group already exists, the group will be skipped (no update will take place).

## Getting the Azure AD graph API access

### Application Registration
The first step to connect to Graph API and make requests, is to register a new __Azure Active Directory Application__. The application is used to connect to the API and to manage permissions.

* Navigate to __App Registrations__ in Azure, and select “New Registration” (__Azure Portal > Azure Active Directory > App Registration > New Application Registration__).
* Next, give the application a name. In this example we are using “__HelloID PowerShell__” as application name.
* Specify who can use this application (__Accounts in this organizational directory only__).
* Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
* Click the “__Register__” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

To assign your application the right permissions, navigate to __Azure Portal > Azure Active Directory >App Registrations__.
Select the application we created before, and select “__API Permissions__” or “__View API Permissions__”.
To assign a new permission to your application, click the “__Add a permission__” button.
From the “__Request API Permissions__” screen click “__Microsoft Graph__”.
For this connector the following permissions are used as __Delegated permissions__:
- User.ReadWrite.All
- Group.ReadWrite.All
- Directory.ReadWrite.All
- Directory.AccessAsUser.All

Some high-privilege permissions can be set to admin-restricted and require an administrators consent to be granted.

To grant admin consent to our application press the “__Grant admin consent for TENANT__” button.

### Authentication and Authorization
There are multiple ways to authenticate to the Graph API with each has its own pros and cons, in this example we are using the __Refreh Token__ grant type.

- First we need to get the __Client ID__, go to the __Azure Portal > Azure Active Directory > App Registrations__.
- Select your application and copy the Application (client) ID value.
- After we have the Client ID we also have to create a __Client Secret__.
- From the Azure Portal, go to __Azure Active Directory > App Registrations__.
- Select the application we have created before, and select "__Certificates and Secrets__". 
- Under “Client Secrets” click on the “__New Client Secret__” button to create a new secret.
- Provide a logical name for your secret in the Description field, and select the expiration date for your secret.
- It's IMPORTANT to copy the newly generated client secret, because you cannot see the value anymore after you close the page.
- And last we need to get the __Tenant ID__. This can be found in the Azure Portal by going to __Azure Active Directory > Custom Domain Names__, and then finding the .onmicrosoft.com domain.

### Creating the Refresh token
Now we can create the Refresh token.
- Run the following PowerShell script as Administrator.
- Provide the variables __\$AADtenantID__, __\$AADAppId__ and __\$AADAppSecret__ with the corresponding values.
> the variables __\$redirectUri__ and __\$scopes__ are prefilled and only need to be updated if you have provided other scopes or another redirectUri.
- The script will prompt your to login as a __Global Admin__ an ask to provide admin consent for the requested permissions.
- After confirming authorization and granting consent, the refresh token will be shown in the console

```powershell
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
```

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
