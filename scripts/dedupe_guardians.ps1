#Requires -Module eSchoolModule,SimplySQL
#Requires -Version 7

<#

    .SYNOPSIS
    This script should help you in deduplicating guardian contacts. Maybe.

#>

Param(
    [Parameter(Mandatory=$false)][switch]$MatchOnAddressAlso,
    [Parameter(Mandatory=$false)][switch]$AllowBlankEmail,
    [Parameter(Mandatory=$false)][string]$EmailAddress, #specify guardian email address to dedupe.
    [Parameter(Mandatory=$false)][ValidateSet("G","O","C")][string]$GuardianType = 'G',
    [Parameter(Mandatory=$false)][switch]$SkipRunningDownloadDefinition
)

#CSVKit Requirement
@("csvclean.exe","csvsql.exe") | ForEach-Object {
    if ($null -eq (Get-Command "$($PSItem)" -ErrorAction SilentlyContinue)) { 
    Write-Error "Unable to find $($PSItem) in your PATH. Install Python3 and run 'pip install csvkit'."
    exit
    }
}

#silence the warnings on csvsql.exe
$env:SQLALCHEMY_SILENCE_UBER_WARNING = 1

if (-Not(Test-Path .\archives)) {
    New-Item -ItemType Directory -Path .\archives
}

$RequiredFiles = @(
    "GUARD_REG_STU_CONTACT",
    "GUARD_REG_CONTACT_PHONE",
    "GUARD_REG_CONTACT",
    "GUARD_REG"
)

if ((Invoke-eSPExecuteSearch -SearchType UPLOADDEF).interface_id -notcontains "ESMD1") {
    Throw "Download Definition does not exist. You need to run New-eSPGuardianDefinition"
}

$MoveGuardiansTo99 = [System.Collections.Generic.List[Object]]::new() #secondary contacts we will move to 99 to be cleaned up later.
$PhoneNumbersForPrimaryGuardian = [System.Collections.Generic.List[Object]]::new() #phone numbers on the secondary contacts that either don't conflict or are newer.
$primaryGuardianToReplaceSecondary = [System.Collections.Generic.List[Object]]::new() #connect the primary guardian by replacing the secondary guardians with the exact same priority and connection information.

if (-Not($SkipRunningDownloadDefinition)) {
    $startTime = Get-Date

    Write-Host "Starting Download Definition ESMD1..."
    Invoke-eSPDownloadDefinition -Interface ESMD1 -Wait

    $Files = Get-eSPFileList | Where-Object {
        $PSItem.RawFileName -like "GUARD_*" -and
        $PSitem.ModifiedDate -gt $startTime -and
        $PSItem.FileExtension -eq ".csv"
    }

    $RequiredFiles | ForEach-Object {
        if ($Files.RawFileName -notcontains "$($PSItem).csv") {
            Throw "Failed to find $($PSitem) on eSchool Servers."
        }
    }
}

#Open-SQLiteConnection -DataSource ":memory:"

Open-SQLiteConnection -DataSource ".\guardians.sqlite3"

$RequiredFiles | ForEach-Object {

    #New-Variable -Name $PSItem -Value (Get-eSPFile -FileName "$($PSItem).csv" -Raw | ConvertFrom-CSV -Delimiter '|' | Select-Object -ExcludeProperty '#!#') -Force
    Write-Host "Downloading file $($PSItem).csv"

    #GUARD_REG_STU_CONTACT contains a notes field which can have LF/CR characters and break import into a database. We need to clean those up before inserting into the database.

    (Get-eSPFile -FileName "$($PSItem).csv" -Raw) -replace "`n",'{LF}' -replace "`r",'{CR}' -replace '\|#!#{CR}{LF}',"`r`n" | Out-File "$($PSItem).csv" -NoNewline
    
    #we have to verify the file is cleaned. This will create a file appended with _out.csv
    & csvclean.exe -d '|' "$($PSItem).csv" #--encoding windows-1252
    if ($LASTEXITCODE -ge 1) {
        & csvclean.exe -d '|' "$($PSItem).csv" --encoding windows-1252
    }

    & csvsql.exe -I --db "sqlite:///guardians.sqlite3" -d ',' -y 0 --insert --overwrite --blanks --tables "$($PSItem)" "$($PSItem)_out.csv"
    if ($LASTEXITCODE -ge 1) {
        & csvsql.exe -I --db "sqlite:///guardians.sqlite3" -d ',' -y 0 --insert --overwrite --blanks --tables "$($PSItem)" "$($PSItem)_out.csv" --encoding windows-1252
    }

    Write-Host "Backing up $($PSitem).csv to archives\$($PSitem)-$(Get-Date -Format 'yyyy-MM-dd-HH-mm-ss').csv"

    Move-Item -Path "$($PSitem).csv" -Destination "archives\$($PSitem)-$(Get-Date -Format 'yyyy-MM-dd-HH-mm-ss').csv" -Force -Verbose

}

if ($existingDuplicates = Invoke-SqlQuery -Query "SELECT * FROM GUARD_REG_STU_CONTACT WHERE CONTACT_PRIORITY = 99 AND CONTACT_TYPE = '$($GuardianType)'") {
    Write-Error "You have already attached duplicate guardians with CONTACT_PRIORITY of 99. You must fix those before running this script again."

    $existingDuplicates | ForEach-Object {
        Write-Host "$($eSchoolSession.Url)Student/Registration/ContactDetail?contactId=$($PSitem.CONTACT_ID)&contactType=Guardian&PageEditMode=Modify&ContactEditMode=Modify&StudentId=$($PSItem.STUDENT_ID)"
    }

    exit 1
}

#a hashtable we can reference later if neeeded. (not currently needed.)
$allGuardians = Invoke-SqlQuery -Query "SELECT * FROM GUARD_REG_CONTACT WHERE CONTACT_ID IN (SELECT CONTACT_ID FROM GUARD_REG_STU_CONTACT WHERE CONTACT_TYPE = '$($GuardianType)')" | Group-Object -Property CONTACT_ID -AsHashTable

if (-Not($AllowBlankEmail)) {
    $emailFilter = " AND EMAIL != '' "
}

if ($EmailAddress) {
    $emailFilter = " AND EMAIL = '$($EmailAddress)' "
}

if ($MatchOnAddressAlso) {
    $groupBy = @("FIRST_NAME","LAST_NAME","EMAIL","ADDRESS")
} else {
    $groupBy = @("FIRST_NAME","LAST_NAME","EMAIL")
}

$guardianDuplicatesByEmail = Invoke-SqlQuery -Query "SELECT
	GUARD_REG_CONTACT.CONTACT_ID,
	GUARD_REG_CONTACT.CHANGE_DATE_TIME,
	GROUP_CONCAT(GUARD_REG_STU_CONTACT.STUDENT_ID) AS STUDENT_IDS,
    COUNT(GUARD_REG_STU_CONTACT.STUDENT_ID) AS STUDENT_COUNT,
	GUARD_REG_CONTACT.FIRST_NAME,
	GUARD_REG_CONTACT.LAST_NAME,
	GUARD_REG_CONTACT.EMAIL,
	(GUARD_REG_CONTACT.STREET_NUMBER || ' ' || GUARD_REG_CONTACT.STREET_NAME) AS ADDRESS,
    GUARD_REG_STU_CONTACT.CONTACT_TYPE
FROM GUARD_REG_CONTACT
LEFT JOIN GUARD_REG_STU_CONTACT ON GUARD_REG_CONTACT.CONTACT_ID = GUARD_REG_STU_CONTACT.CONTACT_ID
LEFT JOIN GUARD_REG ON GUARD_REG_STU_CONTACT.STUDENT_ID = GUARD_REG.STUDENT_ID
WHERE
	GUARD_REG_STU_CONTACT.CONTACT_TYPE = '$($GuardianType)'
$($emailFilter)
AND
	GUARD_REG.CURRENT_STATUS = 'A'
AND
	GUARD_REG_STU_CONTACT.CONTACT_PRIORITY != 99
GROUP BY GUARD_REG_CONTACT.CONTACT_ID
ORDER BY EMAIL" | Group-Object -Property $groupBy | Where-Object { $PSitem.Count -ge 2 }

$guardianDuplicatesByEmail | ForEach-Object {

    #convert the CHANGE DATE TIME to an actual datetime then sort by STUDENT_COUNT This should give us an array with the highest number of connected students first.
    $duplicates = $PSitem.Group | 
        Select-Object -Property *,@{ Name = 'MODIFIED_DATE_TIME'; Expression = { (Get-Date "$($PSItem.CHANGE_DATE_TIME)") } } -ExcludeProperty RowError,RowState,Table,ItemArray,HasErrors | 
        Sort-Object -Property STUDENT_COUNT -Descending
        
    if ($duplicates[0].STUDENT_COUNT -eq $duplicates[1].STUDENT_COUNT) {
        #If the student count matches then we have a tie for firest place. We need to resort by MODIFIED_DATE_TIME.
        $duplicates = $duplicates | Sort-Object -Property MODIFIED_DATE_TIME -Descending
    }

    $primaryContactId = $duplicates | Select-Object -ExpandProperty CONTACT_ID -First 1
    $secondaryStuContacts = $duplicates | Select-Object -Property CONTACT_ID,STUDENT_IDS -Skip 1

    #now we need to move the $secondaryStuContacts to 99.
    $secondaryStuContacts | ForEach-Object {
        $contactId = $PSitem.CONTACT_ID
        ($PSitem.STUDENT_IDS).split(',') | ForEach-object {

            $studentId = $PSItem

            $MoveGuardiansTo99.Add(
                [PSCustomObject]@{
                    CONTACT_ID = $contactId
                    STUDENT_ID = $studentId
                    CONTACT_PRIORITY = 99
                    CONTACT_TYPE = "$($GuardianType)"
                }
            )
            
            #we then need to connect the $primaryContactId in place of the $secondaryStuContacts with the $secondaryStuContacts REG_STU_CONTACT fields they get reattached correctly.
            #lets pull the previous guardian record, change the contact_id to the primary and add to be processed.
            $secondarySTUConnection = Invoke-SqlQuery -Query "SELECT * FROM GUARD_REG_STU_CONTACT WHERE CONTACT_ID = '$contactId' AND STUDENT_ID = '$studentId' AND CONTACT_TYPE = '$($GuardianType)'"
            
            $primaryGuardianToReplaceSecondary.Add(
                [PSCustomObject]@{
                    CONTACT_ID = $primaryContactId
                    COMMENTS = $secondarySTUConnection.COMMENTS
                    CONTACT_PRIORITY = $secondarySTUConnection.CONTACT_PRIORITY
                    CONTACT_TYPE = $secondarySTUConnection.CONTACT_TYPE
                    CUST_GUARD = $secondarySTUConnection.CUST_GUARD
                    DISTRICT = $secondarySTUConnection.DISTRICT
                    LEGAL_GUARD = $secondarySTUConnection.LEGAL_GUARD
                    LIVING_WITH = $secondarySTUConnection.LIVING_WITH
                    MAIL_ATT = $secondarySTUConnection.MAIL_ATT
                    MAIL_DISC = $secondarySTUConnection.MAIL_DISC
                    MAIL_FEES = $secondarySTUConnection.MAIL_FEES
                    MAIL_IPR = $secondarySTUConnection.MAIL_IPR
                    MAIL_MED = $secondarySTUConnection.MAIL_MED
                    MAIL_RC = $secondarySTUConnection.MAIL_RC
                    MAIL_REG = $secondarySTUConnection.MAIL_REG
                    MAIL_SCHD = $secondarySTUConnection.MAIL_SCHD
                    MAIL_SSP = $secondarySTUConnection.MAIL_SSP
                    RELATION_CODE = $secondarySTUConnection.RELATION_CODE
                    STUDENT_ID = $secondarySTUConnection.STUDENT_ID
                    TRANSPORT_FROM = $secondarySTUConnection.TRANSPORT_FROM
                    TRANSPORT_TO = $secondarySTUConnection.TRANSPORT_TO
                    UPD_STU_EO_INFO = $secondarySTUConnection.UPD_STU_EO_INFO
                    WEB_ACCESS = $secondarySTUConnection.WEB_ACCESS
                }
            )

        }   
    }

    #we need to attach any phone numbers that were on the $secondaryStuContacts to the $primaryContactId
    $primaryContactPhoneNumbers = Invoke-SqlQuery -Query "SELECT * FROM GUARD_REG_CONTACT_PHONE WHERE CONTACT_ID = $($primaryContactId)" | Group-Object -Property PHONE_TYPE -AsHashTable
    $secondaryContactNumbers = Invoke-SqlQuery -Query "SELECT * FROM GUARD_REG_CONTACT_PHONE WHERE CONTACT_ID IN ($($secondaryStuContacts.CONTACT_ID -join ','))"

    $secondaryContactNumbers | ForEach-Object {
        $phoneNumber = $PSitem
        if ($primaryContactPhoneNumbers.($phonenumber.PHONE_TYPE)) {
            #check which one is newer
            $existingPhoneNumber = $primaryContactPhoneNumbers.($phonenumber.PHONE_TYPE)

            if ($existingPhoneNumber.PHONE -eq $phoneNumber.PHONE) { 
                #nothing to do
                return
            }

            if ((Get-Date "$($existingPhoneNumber.CHANGE_DATE_TIME)") -gt (Get-Date "$($phoneNumber.CHANGE_DATE_TIME)")) {
                #the primary contact has the latest phone number
                return
            } else {
                #lets use the newer phone number.
                $PhoneNumbersForPrimaryGuardian.Add(
                    [PSCustomObject]@{
                        CONTACT_ID = $primaryContactId
                        DISTRICT = $phoneNumber.DISTRICT
                        PHONE = $phoneNumber.PHONE
                        PHONE_EXTENSION = $phoneNumber.PHONE_EXTENSION
                        PHONE_LISTING = $phoneNumber.PHONE_LISTING
                        PHONE_PRIORITY = $phoneNumber.PHONE_PRIORITY
                        PHONE_TYPE = $phoneNumber.PHONE_TYPE
                        SIF_REFID = $phoneNumber.SIF_REFID
                    }
                )
            }

        } else {
            $PhoneNumbersForPrimaryGuardian.Add(
                [PSCustomObject]@{
                    CONTACT_ID = $primaryContactId
                    DISTRICT = $phoneNumber.DISTRICT
                    PHONE = $phoneNumber.PHONE
                    PHONE_EXTENSION = $phoneNumber.PHONE_EXTENSION
                    PHONE_LISTING = $phoneNumber.PHONE_LISTING
                    PHONE_PRIORITY = $phoneNumber.PHONE_PRIORITY
                    PHONE_TYPE = $phoneNumber.PHONE_TYPE
                    SIF_REFID = $phoneNumber.SIF_REFID
                }
            )
        }
    }

}

if ($MoveGuardiansTo99) {
    $MoveGuardiansTo99 | ConvertTo-Csv -UseQuotes AsNeeded | Select-Object -Skip 1 | Out-File .\duplicate_guardians_to_99.csv -Force
    Submit-eSPFile duplicate_guardians_to_99.csv
    Invoke-eSPUploadDefinition -InterfaceID ESMU2 -RunMode V -Wait #Guardian to 99
} 

if ($primaryGuardianToReplaceSecondary) {
    $primaryGuardianToReplaceSecondary | ConvertTo-Csv -UseQuotes AsNeeded | Select-Object -Skip 1 | Out-File .\duplicate_guardians_fix.csv
    Submit-eSPFile duplicate_guardians_fix.csv
    Invoke-eSPUploadDefinition -InterfaceID ESMU3 -RunMode V -InsertNewRecords -Wait #Connect Primary Guardian where duplicate was.
}

if ($PhoneNumbersForPrimaryGuardian) {
    $PhoneNumbersForPrimaryGuardian | ConvertTo-Csv -UseQuotes AsNeeded | Select-Object -Skip 1 | Out-File .\duplicate_guardian_phone_numbers.csv
    Submit-eSPFile duplicate_guardian_phone_numbers.csv
    Invoke-eSPUploadDefinition -InterfaceID ESMU4 -RunMode V -InsertNewRecords -Wait #Insert updated or missing phone records from duplicates to primary.    
}
