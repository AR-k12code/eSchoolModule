<#

.SYNOPSIS
Retrieves the eSP MFA code sent to the user's email address.

.DESCRIPTION
This function will need to be customized and placed into the users profile.
You can find your profile path by entering this in to a Powershell 7 terminal: $PROFILE.CurrentUserCurrentHost

BE SURE to rePLACE espmfa@camtechcs.com with your email address!

#>

#Example for Gmail using GAM, GAM must be in your system path.
function Get-eSPMFACode {

    $startTime = Get-Date

    while ($true) {

        $messages = & gam.exe user "espmfa@camtechcs.com" print messages query -Filter "subject:Powerschool after:$(Get-Date -Format yyyy-MM-dd)" includespamtrash max_to_print 3 showbody convertcrnl
        
        $messages = $messages |
            ConvertFrom-Csv |
            Where-Object { ($_.Date | Get-Date) -ge $startTime }

        @($messages.Body) -match "\d{6}"

        if ($Matches) {
            return $Matches[0].Groups[1].Value
        } else {
            Start-Sleep -Seconds 5
        }

        #codes are only good for 5 minutes.
        if (((Get-Date) - $startTime).TotalMinutes -ge 5) {
            throw "MFA Code not received within 5 minutes."
        }

    }

}

#Example for Gmail using PSGSuite
function Get-eSPMFACode {

    $startTime = Get-Date

    while ($true) {

        $messages = Get-GSGmailMessageList -User "espmfa@camtechcs.com" -Filter "subject:Powerschool after:$(Get-Date -Format yyyy-MM-dd)" -IncludeSpamTrash -Limit 3 |
            Get-GSGmailMessage -ParseMessage |
            Where-Object -Property Date -ge $startTime

        @($messages.TextBody) -match "\d{6}"

        if ($Matches) {
            return $Matches[0].Groups[1].Value
        } else {
            Start-Sleep -Seconds 5
        }

        #codes are only good for 5 minutes.
        if (((Get-Date) - $startTime).TotalMinutes -ge 5) {
            throw "MFA Code not received within 5 minutes."
        }

    }

}

#Example using M365
#https://learn.microsoft.com/en-us/powershell/microsoftgraph/app-only?view=graph-powershell-1.0
function Get-eSPMFACode {

    $startTime = Get-Date

    #this requires you create an app registration with certificate auth. Be sure you add the Mail.ReadBasic.All scope. Then fill out the variables below.
    $TenantId = 
    $ClientId = 
    $CertificateName = 
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateName $CertificateName

    while ($true) {

        $messages = Get-MgUserMessage -UserId "espmfa@camtechcs.com" -Filter "startswith(Subject,'Powerschool') and ReceivedDateTime ge $($startTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))" -Top 1

        @($messages.BodyPreview) -match "\d{6}"

        if ($Matches) {
            return $Matches[0].Groups[1].Value
        } else {
            Start-Sleep -Seconds 5
        }

        #codes are only good for 5 minutes.
        if (((Get-Date) - $startTime).TotalMinutes -ge 5) {
            throw "MFA Code not received within 5 minutes."
        }

    }

}