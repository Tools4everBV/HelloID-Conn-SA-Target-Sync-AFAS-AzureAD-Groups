#Region Script
# AFAS Profit Parameters
$baseUri = $AFASBaseUri
$token = $AFASToken

# Azure AD Application Paramters
$AADtenantID = ""
$AADAppId = ""
$AADAppSecret = ""
$AADRefreshToken = ""

$azureADGroupNamePrefix = "HelloID-Department-"
$azureADGroupNameSuffix = ""
$azureADGroupDescriptionPrefix = "Microsoft 365 Group for "
$azureADGroupDescriptionSuffix = ""

# Fixed values
$redirectUri = "http://localhost"
$scopes = "Group.ReadWrite.All", "Directory.ReadWrite.All", "Directory.AccessAsUser.All"

$visibility = "Private"
$GroupType = "Microsoft 365 group"
$allowExternalSenders = $true #- Not supported with Application permissions
$autoSubscribeNewMembers = $true #- Not supported with Application permissions

$debug = $true

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12


#region Supporting Functions
function Get-AFASConnectorData
{
    param(
        [parameter(Mandatory=$true)]$Token,
        [parameter(Mandatory=$true)]$BaseUri,
        [parameter(Mandatory=$true)]$Connector,
        [parameter(Mandatory=$true)][ref]$data
    )

    try {
        $encodedToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Token))
        $authValue = "AfasToken $encodedToken"
        $Headers = @{ Authorization = $authValue }

        $take = 100
        $skip = 0

        $uri = $BaseUri + "/connectors/" + $Connector + "?skip=$skip&take=$take"
        $counter = 0 
        do {
            if ($counter -gt 0) {
                $skip += 100
                $uri = $BaseUri + "/connectors/" + $Connector + "?skip=$skip&take=$take"
            }    
            $counter++
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
            $dataset = Invoke-RestMethod -Method GET -Uri $uri -ContentType "application/json" -Headers $Headers #-UseBasicParsing

            foreach ($record in $dataset.rows) { $null = $data.Value.add($record) }

        }until([string]::IsNullOrEmpty($dataset.rows))
    } catch {
        $data.Value = $null
        throw $_
    }
}

# Function to Genereate Azure Access token from Refresh token
Function Get-AzureAccessToken {
    param(
        [parameter(Mandatory=$true)]$AADAppId,
        [parameter(Mandatory=$true)]$AADAppSecret,
        [parameter(Mandatory=$true)]$RedirectUri,
        [parameter(Mandatory=$true)]$Scopes,
        [parameter(Mandatory=$true)]$RefreshToken
    )

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"
    $body = @{
        Grant_Type    = "refresh_token"
        client_Id     = $AADAppId
        client_secret = $AADAppSecret
        redirect_uri  = $RedirectUri
        scope         = $Scopes
        refresh_token = $RefreshToken
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response;

    return $accessToken
}

function Get-ADSanitizeGroupName
{
    param(
        [parameter(Mandatory = $true)][String]$Name
    )
    $newName = $name.trim();
    $newName = $newName -replace ' - ','_'
    $newName = $newName -replace '[`,~,!,#,$,%,^,&,*,(,),+,=,<,>,?,/,'',",;,:,\,|,},{,.]',''
    $newName = $newName -replace '\[','';
    $newName = $newName -replace ']','';
    $newName = $newName -replace ' ','_';
    $newName = $newName -replace '\.\.\.\.\.','.';
    $newName = $newName -replace '\.\.\.\.','.';
    $newName = $newName -replace '\.\.\.','.';
    $newName = $newName -replace '\.\.','.';
    return $newName;
}

function Remove-StringLatinCharacters
{
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}
#endregion Supporting Functions

try{
    Hid-Write-Status -Event "Information" -Message "Processing T4E_HelloID_OrganizationalUnits.."
    $organizationalUnits = New-Object System.Collections.ArrayList
    Get-AFASConnectorData -Token $token -BaseUri $baseUri -Connector "T4E_HelloID_OrganizationalUnits" ([ref]$organizationalUnits)
    
    # Troubleshooting
    $organizationalUnits = $organizationalUnits[0]
    Hid-Write-Status -Event "Warning" -Message ("Found T4E_HelloID_OrganizationalUnits: " + @($organizationalUnits).Count)

    $departments = $organizationalUnits | Sort-Object ExternalId -Unique | Sort-Object ExternalId, DisplayName
    foreach($department in $departments){
        try{
            try {
                Hid-Write-Status -Event Information -Message "Generating Microsoft Graph API Access Token.."
            
                $accessToken = Get-AzureAccessToken -AADAppId $AADAppId -AADAppSecret $AADAppSecret -RefreshToken $AADRefreshToken -RedirectUri $redirectUri -Scopes $scopes 
                $accessToken = $accessToken.access_token
            } catch {
                Write-Error "Could not create Access Token. Error: $_" 
            }
 
            #Add the authorization header to the request
            $authorization = @{
                Authorization = "Bearer $accesstoken";
                'Content-Type' = "application/json";
                Accept = "application/json";
                charset = "utf-8";
            }
                        
            
            # The names of security principal objects can contain all Unicode characters except the special LDAP characters defined in RFC 2253.
            # This list of special characters includes: a leading space; a trailing space; and any of the following characters: # , + " \ < > ;
            # A group account cannot consist solely of numbers, periods (.), or spaces. Any leading periods or spaces are cropped.
            # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc776019(v=ws.10)?redirectedfrom=MSDN
            # https://www.ietf.org/rfc/rfc2253.txt
            $AzureADGroupName = ("$azureADGroupNamePrefix$($department.ExternalId)$azureADGroupNameSuffix")
            $AzureADGroupName = Get-ADSanitizeGroupName -Name $AzureADGroupName
            # Remove Diactritics
            $AzureADGroupName = Remove-StringLatinCharacters $AzureADGroupName
        
            $AzureADGroupDescription = "$azureADGroupDescriptionPrefix$($azureADGroupName)$azureADGroupDescriptionSuffix"

            $AzureADGroupMailNickname = $AzureADGroupName.Replace(" ","")

            Switch($GroupType){
                'Microsoft 365 group' {
                    $group = [PSCustomObject]@{
                        description = $AzureADGroupDescription;
                        displayName = $AzureADGroupName;
        
                        groupTypes = @("Unified");
        
                        mailEnabled = $true;
                        mailNickname = $AzureADGroupMailNickname;
        
                        securityEnabled = $false;
        
                        visibility = $visibility;
                    }
                }
        
                'Security group' {
                    $group = [PSCustomObject]@{
                        description = $AzureADGroupDescription;
                        displayName = $AzureADGroupName;
        
                        #groupTypes = @(""); - Needs to be empty to create Security group
        
                        mailEnabled = $false;
                        mailNickname = $AzureADGroupMailNickname;
        
                        securityEnabled = $true;
        
                        visibility = $visibility;
                    }
                }
            }


            if($debug -eq $true){Hid-Write-Status -Event "Information" -Message "Searching for Group displayName=$($group.displayName)" }
            $baseSearchUri = "https://graph.microsoft.com/"
            $searchUri = $baseSearchUri + 'v1.0/groups?$filter=displayName+eq+' + "'$($group.displayName)'" + '&$count=true'
    
            $azureADGroupResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
            $AzureADGroup = $azureADGroupResponse.value
            
            if($AzureADGroup){
                $event = "update"
                if($debug -eq $true){ Hid-Write-Status -Event "Warning" -Message "AzureAD group [$($group.displayName)] already exists" }

                $baseUpdateUri = "https://graph.microsoft.com/"
                $updateUri = $baseUpdateUri + "v1.0/groups/$($AzureADGroup.id)"

                $body = $group | ConvertTo-Json -Depth 10
                $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false

                # To update the following Exchange-specific properties, you must specify them in their own PATCH request, without including the other properties listed in the table above: allowExternalSenders, autoSubscribeNewMembers, hideFromAddressLists, hideFromOutlookClients, isSubscribedByMail, unseenCount.
                # https://docs.microsoft.com/en-us/graph/api/group-update?view=graph-rest-1.0&tabs=http
                $groupAllowExternalSenders = [PSCustomObject]@{
                    allowExternalSenders = $allowExternalSenders; 
                }
                $body = $groupAllowExternalSenders | ConvertTo-Json -Depth 10
                $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false

                $groupAutoSubscribeNewMembers = [PSCustomObject]@{
                    autoSubscribeNewMembers = $autoSubscribeNewMembers;
                }
                $body = $groupAutoSubscribeNewMembers | ConvertTo-Json -Depth 10
                $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false

                if($debug -eq $true){ Hid-Write-Status -Event "Success" -Message "AzureAD group [$($group.displayName)] updated successfully" }
            }else{
                $event = "create"
                $baseCreateUri = "https://graph.microsoft.com/"
                $createUri = $baseCreateUri + "v1.0/groups"

                $body = $group | ConvertTo-Json -Depth 10
                $response = Invoke-RestMethod -Uri $createUri -Method POST -Headers $authorization -Body $body -Verbose:$false
                $AzureADGroup = $response

                # To update the following Exchange-specific properties, you must specify them in their own PATCH request, without including the other properties listed in the table above: allowExternalSenders, autoSubscribeNewMembers, hideFromAddressLists, hideFromOutlookClients, isSubscribedByMail, unseenCount.
                # https://docs.microsoft.com/en-us/graph/api/group-update?view=graph-rest-1.0&tabs=http
                $baseUpdateUri = "https://graph.microsoft.com/"
                $updateUri = $baseUpdateUri + "v1.0/groups/$($AzureADGroup.id)"

                $groupAllowExternalSenders = [PSCustomObject]@{
                    allowExternalSenders = $allowExternalSenders; 
                }
                $body = $groupAllowExternalSenders | ConvertTo-Json -Depth 10
                $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false

                $groupAutoSubscribeNewMembers = [PSCustomObject]@{
                    autoSubscribeNewMembers = $autoSubscribeNewMembers;
                }
                $body = $groupAutoSubscribeNewMembers | ConvertTo-Json -Depth 10
                $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false

                if($debug -eq $true){ Hid-Write-Status -Event "Success" -Message "AzureAD group [$($group.displayName)] created successfully" }
            }
        } catch {
            if($_.ErrorDetails.Message) { $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message } 
            HID-Write-Status -Event Error -Message ("Error when trying to $event AzureAD group [$($group.displayName)]. Error: $_" + $errorDetailsMessage)
            Hid-Write-Status -Event Error -Message "$($body | Out-String)"
            HID-Write-Summary -Event Failed -Message "Error when trying to $event AzureAD group [$($group.displayName)]"
        }          
    }
    Hid-Write-Summary -Event "Success" -Message "Successfully synchronized $(@($departments).Count) AFAS Organizational Units to Azure AD Groups"
}catch{
    throw $_
}
