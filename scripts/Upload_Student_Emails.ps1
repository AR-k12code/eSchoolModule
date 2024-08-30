#Requires -Module eSchoolModule,ActiveDirectory
#Requires -Version 7

<#

.SYNOPSIS
This script will upload the correct email addresses to eSchool.

#>

Param(
    [Parameter(Mandatory=$false)][string]$ADField = "EmployeeNumber",
    [parameter(Mandatory=$false,HelpMessage="Skip uploading to eSchool")][switch]$SkipUpload,
	[parameter(mandatory=$false,Helpmessage="Run mode, V for verfiy and R to commit data changes to eschool")][ValidateSet("R","V")][string]$RunMode="V",
	[parameter(Mandatory=$false,HelpMessage="Enable Student Web Access Flag")][switch]$EnableWebAccess,
	[parameter(mandatory=$false,Helpmessage="Do you want to turn on WEB_ACCESS for Guardians?")][switch]$EnableGuardianWebAccess,
	[parameter(mandatory=$false,Helpmessage="If EnableGuardianWebAccess up to what Priority of Guardian do you want?")][int]$GuardianPriority = 1
)

try {

	if (-Not(Test-Path("$PSScriptRoot\temp\"))) {
		New-Item -Name "temp" -ItemType Directory -Force
	}


    #Force connect in case the definitions have changed. You must reauth after definition changes.
    Assert-eSPSession -Force

    $definitions = Invoke-eSPExecuteSearch -SearchType UPLOADDEF | Select-Object -ExpandProperty interface_id

    @("ESMD0","ESMU0","ESMU1") | ForEach-Object {
        if ($definitions -notcontains $PSItem) {
            Throw "Missing Defininition $($PSItem). New-eSPEmailDefinitions -Force"
        }
    }

    #start the download for the files we need.
    Invoke-eSPDownloadDefinition -InterfaceID ESMD0 -ActiveStudentsOnly -Wait

    $eSPEmails = Get-eSPFile -FileName "student_email_download.csv" -AsObject 

    #Select only Students and their mailing record to do the match.
    $eSchoolStudents = $eSPEmails | Where-Object { $PSItem.'CONTACT_PRIORITY' -eq 0 -AND $PSItem.'CONTACT_TYPE' -eq 'M' }

	#Get AD Accounts and build Hash Table on $ADField
	$adAccounts = Get-ADUser -Filter { Enabled -eq $True -and $ADField -like "*" } -Properties $ADField,Mail | Group-Object -Property $ADField -AsHashTable

	$records = @()
	$webaccess = @()

	$eSchoolStudents | ForEach-Object {

		$student = $PSItem
		$studentId = $PSitem.'STUDENT_ID'

		if ($adAccounts.$studentId) {

			#Check for mismatched email address. Then add to $records to be exported to csv later.
			$adEmailAddress = ($adAccounts.$studentId).Mail
			if ($adEmailAddress -ne $student.'EMAIL') {
				
				$records += [PSCustomObject]@{
					CONTACT_ID = $student.'CONTACT_ID'
					EMAIL = $adEmailAddress
				}
		
			}

			if ($EnableWebAccess) {
				if ($student.'WEB_ACCESS' -ne 'Y') {
					#Always ensure students webaccess flag is enabled.
					$webaccess += [PSCustomObject]@{
						CONTACT_ID = $student.'CONTACT_ID'
						STUDENT_ID = $studentId
						WEB_ACCESS = 'Y'
						CONTACT_TYPE = 'M'
					}
				}
			}

		} else {
			Write-Host "Error: No Active Directory account found for $studentId"
		}
	}
		
	if ($records.Count -ge 1) {

		Write-Host "Info: Found $($records.Count) mismatched or missing email addresses in eSchool. Uploading."
		#Export CSV without header row.
		$records | ConvertTo-CSV -UseQuotes Never -NoTypeInformation | Select-Object -Skip 1 | Out-File "$PSScriptRoot\temp\student_email_upload.csv" -Force
		
		if (-Not($SkipUpload)) {
			Submit-eSPFile -InFile "$PSScriptRoot\temp\student_email_upload.csv"
            Invoke-eSPUploadDefinition -InterfaceID ESMU0 -RunMode $RunMode
		}

	}

	if ($EnableGuardianWebAccess) {

		$eSPEmails | Where-Object { $PSItem.'CONTACT_PRIORITY' -le $GuardianPriority -AND $PSItem.'CONTACT_TYPE' -eq 'G' } | ForEach-Object {

			$guardian = $PSItem
			if ($guardian.'WEB_ACCESS' -ne 'Y') {
				#Ensure guardian webaccess flag is enabled.
				$webaccess += [PSCustomObject]@{
					CONTACT_ID = $guardian.'CONTACT_ID'
					STUDENT_ID = $guardian.'STUDENT_ID' #This is the student they are attached to. Guardian can be attached to multiple students.
					WEB_ACCESS = 'Y'
					CONTACT_TYPE = 'G'
				}
			}
		}
	}

	if ($webaccess.Count -ge 1) {
		#Create Web Access Flag CSV and Run EMLWA
		$webaccess | ConvertTo-CSV -UseQuotes Never -NoTypeInformation | Select-Object -Skip 1 | Out-File "$PSScriptRoot\temp\webaccess_upload.csv" -Force
		
		if (-Not($SkipUpload)) {
            Submit-eSPFile -InFile "$PSScriptRoot\temp\webaccess_upload.csv"
            Invoke-eSPUploadDefinition -InterfaceID ESMU1 -RunMode $RunMode
		}
	}
		
} catch {
	write-host "Error: $_"
}