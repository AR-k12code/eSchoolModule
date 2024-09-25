<#

.SYNOPSIS
Upload Meal Status to eSchool - Warning! This script come without warranty of any kind.
Use it at your own risk. I assume no liability for the accuracy, correctness, completeness,
or usefulness of any information provided by this site nor for any sort of damages using
these scripts may cause.

.DESCRIPTION
Author: Craig Millsap/CAMTech Computer Services, LLC.
Date: 8/8/2024
Updated: 9/25/2024

.NOTES
This script will upload Meal Status to eSchool and close out any existing Meal Status that is not in the incoming file.

This process requires a multiple step process.

1. We have to download existing Meal Status & Entry Withdrawl so we can set an End Date.
2. We have to upload the changes to the REG_PROGRAMS to reflect entry date Meal Status.
3. We have to upload the other changes so that vector dates can be closed and new ones created. This also updates REG_PERSONAL.

The required CSV to this file should be in the following format (or you can specify the column names with parameters):
STUDENT_ID,MEAL_STATUS,START_DATE
403005966,1,9/19/2023
403005967,3,9/19/2023
403005968,Free,2023/9/19

#>

Param(
    [Parameter(Mandatory=$true,Position = 1)][Alias('File')]$FilePath,
    [Parameter(Mandatory=$false)]$StudentIDField = 'STUDENT_ID', #If you can't rename the headers of the incoming file you can specify them at the command prompt.
    [Parameter(Mandatory=$false)]$MealStatusField = 'MEAL_STATUS', #this should be 1,01,2,02,3,03,4,04,Free,Reduced,Paid
    [Parameter(Mandatory=$false)]$StartDateField = 'START_DATE',
    [Parameter(Mandatory=$false)][ValidateSet("R","V")][string]$RunMode = 'V', #R for Run. V for Verify.
    [Parameter(Mandatory=$false)][switch]$SkipRunningDownloadDefinition
)

if (-Not(Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath"
    Exit 1
}

$incomingCSV = Import-Csv $FilePath

if (-Not($incomingCSV)) {
    Write-Error "CSV file is empty: $FilePath"
    Exit 1
}

try {
    $activeStudentIds = Get-eSPStudents |
        Select-Object -ExpandProperty Student_id
} catch {
    Write-Error "Failed to pull active students." -ErrorAction Stop
}

#Verify the eSchool Definitions exists.
$definitions = Invoke-eSPExecuteSearch -SearchType UPLOADDEF
@('ESMD2','ESMD3','ESMU8') | ForEach-Object {
    if ($definitions.interface_id -notcontains $PSitem) {
        Write-Error "You must run New-eSPMealStatusDefinitions first. eSchool Definitions not found: $PSitem"
        Exit 1
    }
}

#Pull down existing data so we can close old program dates.
if (-Not($SkipRunningDownloadDefinition)) {
    
    $startTime = Get-Date
    Write-Host "Downloading existing Meal Status data from eSchool..."
    Invoke-eSPDownloadDefinition -InterfaceID ESMD2 -Wait

    #Check that we have a new file after the $startTime
    if (Get-eSPFileList | Where-Object -Property RawFileName -EQ "esp_meal_status.csv" | Where-Object -Property ModifiedDate -GE $startTime) {
        Get-eSPFile -FileName "esp_meal_status.csv"
    } else {
        Write-Error "The file timestamp for esp_meal_status.csv are not newer than the start time of the definition. This indicates eSchool did not create the expected file." -ErrorAction Stop
    }

    Write-Host "Downloading Registration Entry Withdraw data from eSchool..."
    Invoke-eSPDownloadDefinition -InterfaceID ESMD3 -Wait

    #Check that we have a new file after the $startTime
    if (Get-eSPFileList | Where-Object -Property RawFileName -EQ "2YR_REG_ENTRY_WITH.csv" | Where-Object -Property ModifiedDate -GE $startTime) {
        Get-eSPFile -FileName "2YR_REG_ENTRY_WITH.csv"
    } else {
        Write-Error "The file timestamp for 2YR_REG_ENTRY_WITH.csv are not newer than the start time of the definition. This indicates eSchool did not create the expected file." -ErrorAction Stop
    }

}

$schoolYear = (Get-Date).Month -ge 7 ? (Get-Date).Year : (Get-Date).AddYears(-1).Year

if (Test-Path "esp_meal_status.csv") {
    Write-Host "Processing Meal Status data..."

    $eSchoolMealStatusData = Import-Csv "esp_meal_status.csv" |
    Add-Member -MemberType ScriptProperty -Name "Latest_Start_Date" -Value { (Get-Date "$($this.START_DATE)") } -PassThru

    $directCertifiedStudentIds = $eSchoolMealStatusData |
        Where-Object -Property PROGRAM_VALUE -EQ '04' |
        Where-Object -Property Latest_Start_Date -GE (Get-Date "7/1/$($schoolYear)") |
        Select-Object -ExpandProperty STUDENT_ID

    $existingLatestMealStatus = @{}
    
    #Sort so that the latest is the last to override in the hashtable.
    $eSchoolMealStatusData |
        Where-Object { $directCertifiedStudentIds -notcontains $PSitem.STUDENT_ID } |
        Sort-Object -Property Student_id,Latest_Start_Date |
        ForEach-Object {
            $existingLatestMealStatus.($PSitem.STUDENT_ID) = $PSitem.PROGRAM_VALUE
        }

} else {
    Write-Error "esp_meal_status.csv not found." -ErrorAction Stop
    Exit 1
}

#import CSV
if (Test-Path "2YR_REG_ENTRY_WITH.csv") {

    $regEntryDate = @{}
    
    Import-Csv "2YR_REG_ENTRY_WITH.csv" |
        Add-Member -MemberType ScriptProperty -Name "Latest_Entry_Date" -Value { (Get-Date "$($this.ENTRY_DATE)") } -PassThru |
        Where-Object -Property Latest_Entry_Date -GE (Get-Date "7/1/$($schoolYear)") |
        Sort-Object -Property Latest_Entry_Date |
        ForEach-Object {
            $regEntryDate.($PSitem.STUDENT_ID) = $PSitem.Latest_Entry_Date
        }

} else {
    Write-Error "2YR_REG_ENTRY_WITH.csv not found." -ErrorAction Stop
}

$UpdateExistingMealStatus = @() #You can't close one status and open another on the same day. If we know the status before they enroll then we need to just update the existing record.
$ChangeMealStatus = @() #Here we need to close out the existing vector and create a new one with a new status.

#bring in the file to process and create the object needed for the CSV upload into eSchool.
$incomingCSV | ForEach-Object {

    $student_id = $PSitem.$StudentIDField
    $meal_status = $PSitem.$MealStatusField
    $start_date = $PSitem.$StartDateField

    Write-Verbose "LINE: $($student_id),$($meal_status),$($start_date)"

    if ($null -EQ $student_id -or $null -EQ $meal_status -or $null -EQ $start_date) {
        Write-Error "Missing required values for CSV." -ErrorAction Stop
    }

    if ($activeStudentIds -notcontains $student_id) {
        Write-Warning "$($student_id): is not an active student."
        return
    }

    if (-Not($regEntryDate.($student_id))) {
        Write-Warning "$($student_id): No enrollment date found. Skipping."
        return
    }
    
    if ($directCertifiedStudentIds -contains $student_id) { 
        Write-Verbose "$($student_id) is Direct Certified. Skipping."
        return
    }

    switch ($meal_status) {
        '01'        { $meal_status = '01' }
        '02'        { $meal_status = '02' }
        '03'        { $meal_status = '03' }
        '1'         { $meal_status = '01' }
        '2'         { $meal_status = '02' }
        '3'         { $meal_status = '03' }
        'Free'      { $meal_status = '01' }
        'Reduced'   { $meal_status = '02' }
        'Paid'      { $meal_status = '03' }
        'F'         { $meal_status = '01' } #Free
        'R'         { $meal_status = '02' } #Reduced
        'N'         { $meal_status = '03' } #No
        default     {
            Write-Error "$($student_id): Invalid meal status code: $meal_status"
            return
        }
    }
    
    #compare the students meal status codes. If a change is required check if the date is newer than the enrollment.
    #if it is newer than the enrollment then override it with the enrollment date.
    if ($existingLatestMealStatus.($student_id) -eq $meal_status) {
        Write-Verbose "$($student_id): No changes necessary for existing record."
        return
    }
    
    #Meal Status Code doesn't match and EXISTING meal status code. Lets check the dates.

    # If the start date is not specified we shouldn't take an action here at all.
    # This should be considered an exception until a real date is provided by the Meal Application.
    if ($start_date -eq '' -and $null -ne $existingLatestMealStatus.($student_id)) {
        Write-Error "$($student_id): Different meal code provided but an empty start date provided."
        return
    }

    # If the Meal Application Date is before the enrollment date then we need to update the existing record on REG_PROGRAMS.
    # The problem is that the ESMU7 definition does not update the REG_PERSONAL table. We have to make the system run ESMU8 to close
    # the ESMU7 date and create a new one for the next day using ESMU8. The values will be the same but at least the data will be correct from day #1.
    if ($start_date -ne '' -and (Get-Date "$start_date") -le $regEntryDate.($student_id)) {
        Write-Warning "$($student_id): Meal Status date is before the enrollment date. Using enrollment date."

        $UpdateExistingMealStatus += [PSCustomObject]@{
            STUDENT_ID = $student_id
            PROGRAM_ID = 'ARSES'
            PROGRAM_VALUE = ([string]$meal_status).PadLeft(2,'0')
            FIELD_NUMBER = 1
            START_DATE = $regEntryDate.($student_id).ToShortDateString()
            END_DATE = ''
            SUMMER_SCHOOL = 'N'
            PROGRAM_OVERRIDE = 'N'
        }

        #if a date prior to enrollment date is used the ESMU7 definition does not update the REG_PERSONAL table. We have to make the system run ESMU8 to close
        # the ESMU7 date and create a new one for the next day. They both will be the same but at least the data will be correct from day #1.
        $ChangeMealStatus += [PSCustomObject]@{
            STUDENT_ID = $student_id
            PROGRAM_VALUE = ([string]$meal_status).PadLeft(2,'0')
            #If a student doesn't have an existing program date we have to account for that and use their entry date.
            START_DATE = ($regEntryDate.($student_id)).AddDays(1).ToShortDateString()
        }

        return
    }

    # This is a change in meal status and the date is after the enrollment date. We can create a new vector date using ESM8.
    $ChangeMealStatus += [PSCustomObject]@{
        STUDENT_ID = $student_id
        PROGRAM_VALUE = ([string]$meal_status).PadLeft(2,'0')
        #If a student doesn't have an existing program date we have to account for that and use their entry date.
        START_DATE = $start_date -eq '' ? $regEntryDate.($student_id).ToShortDateString() : $start_date
    }

}

#This should update existing records where the start date is before the enrollment date.
if ($UpdateExistingMealStatus) {

    Write-Host "Updating the following records:"
    $UpdateExistingMealStatus | Format-Table
    $UpdateExistingMealStatus |
        ConvertTo-Csv -UseQuotes Never |
        Select-Object -Skip 1 |
        Out-File .\meal_status_upload.csv -Force

    Submit-eSPFile -InFile meal_status_upload.csv
    Invoke-eSPUploadDefinition -InterfaceID ESMU7 -RunMode $RunMode -Wait
}

#This should close the last vector date and create the new one.
if ($ChangeMealStatus) {

    Write-Host "Inserting the following records:"
    $ChangeMealStatus | Format-Table
    $ChangeMealStatus |
        ConvertTo-Csv -UseQuotes Never |
        Select-Object -Skip 1 |
        Out-File .\meal_status_upload_changes.csv -Force
    
    Submit-eSPFile -InFile meal_status_upload_changes.csv
    Invoke-eSPUploadDefinition -InterfaceID ESMU8 -RunMode $RunMode -InsertNewRecords -Wait -ProgramStartDateColumn 3 -ProgramEndDatePriorToStartDate
}

Write-Warning "You should run this Cognos Report to review any issues with Meal Status dates:"
Write-Warning "Get-CognosReport -report 'APSCN Invalid Program Dates' -cognosfolder '_Shared Data File Reports\eSchool Data Cleanup Reports' -reportparams 'p_year=$($schoolYear+1)' -TeamContent | Where-Object -Property 'Program Name' -eq 'Meal Status' | Format-Table"
