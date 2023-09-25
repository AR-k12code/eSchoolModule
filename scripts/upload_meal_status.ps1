<#

.SYNOPSIS
Upload Meal Status to eSchool - Warning! This script come without warranty of any kind.
Use it at your own risk. I assume no liability for the accuracy, correctness, completeness,
or usefulness of any information provided by this site nor for any sort of damages using
these scripts may cause.


.DESCRIPTION
Author: Craig Millsap/CAMTech Computer Services, LLC
Date: 9/19/2023

.NOTES
WARNING: This whole process assumes there are no dates specified in eSchool that predates the incoming record.
If so, the web interface will be broken and you will have to manually clean them up 1 by one.

This process requires a multiple step process.

1. We have to download existing Meal Status so we can set an End Date.
2. We have to upload the new Meal Status.

The required CSV to this file should be in the following format (or you can specify the column names with parameters):
STUDENT_ID,MEAL_STATUS,START_DATE
403005966,1,9/19/2023
403005967,3,9/19/2023
403005968,Free,2023/9/19

Produced CSV file Requirments for the upload definition:
STUDENT_ID,PROGRAM_ID,PROGRAM_VALUE,FIELD_NUMBER,START_DATE,END_DATE,SUMMER_SCHOOL,PROGRAM_OVERRIDE
403005966,ARSES,03,1,9/19/2023,,N,N

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

#Verify the eSchool Definitions exists.
$definitions = Invoke-eSPExecuteSearch -SearchType UPLOADDEF
@('ESMD2','ESMU7') | ForEach-Object {
    if ($definitions.interface_id -notcontains $PSitem) {
        Write-Error "eSchool Definitions not found: $PSitem"
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
        Write-Error "The file timestamps are not newer than the start time of the definition. This indicates eSchool did not create the expected file."
        Exit 1
    }

}

$schoolYear = (Get-Date).Month -ge 7 ? (Get-Date).Year : (Get-Date).AddYears(-1).Year

#import CSV
if (Test-Path "esp_meal_status.csv") {

    $eSchoolMealStatusData = Import-Csv "esp_meal_status.csv" |
        Add-Member -MemberType ScriptProperty -Name "Latest_Start_Date" -Value { (Get-Date "$($this.START_DATE)") } -PassThru
    
    $directCertifiedStudentIds = $eSchoolMealStatusData |
        Where-Object -Property PROGRAM_VALUE -EQ '04' |
        Where-Object -Property Latest_Start_Date -GE (Get-Date "7/1/$($schoolYear)") |
        Select-Object -ExpandProperty STUDENT_ID

    $existingMealStatus = $eSchoolMealStatusData |
        Where-Object { $directCertifiedStudentIds -notcontains $PSitem.STUDENT_ID } |
        Sort-Object -Property Latest_Start_Date |
        Group-Object -Property STUDENT_ID -AsHashTable

} else {
    Write-Error "esp_meal_status.csv not found."
    Exit 1
}

#we need to find all the existing open program dates that don't match the incoming file. The comparison needs to be on the Date and Program Value.
$close_existing_meal_status = @()

#bring in the file to process and create the object needed for the CSV upload into eSchool.
$meal_status_upload = $incomingCSV | ForEach-Object {

    $student_id = $PSitem.$StudentIDField
    $meal_status = $PSitem.$MealStatusField
    $start_date = (Get-Date "$($PSitem.$StartDateField)").ToShortDateString()

    if ($directCertifiedStudentIds -contains $student_id) { 
        Write-Warning "$($student_id) is Direct Certified. Skipping."
        return
    }

    if ($null -EQ $student_id -or $null -EQ $meal_status -or $null -EQ $start_date) {
        Write-Error "Missing required fields. Please check the CSV file."
        Exit 1
    }

    if (@('Free','Reduced','Paid') -contains $meal_status) {
        SWITCH ($meal_status) {
            'Free'    { $meal_status = 1 }
            'Reduced' { $meal_status = 2 }
            'Paid'    { $meal_status = 3 }
            'F'       { $meal_status = 1 } #Free
            'R'       { $meal_status = 2 } #Reduced
            'N'       { $meal_status = 3 } #No
        }
    }

    [PSCustomObject]@{
        STUDENT_ID = $student_id
        PROGRAM_ID = 'ARSES'
        PROGRAM_VALUE = ([string]$meal_status).PadLeft(2,'0')
        FIELD_NUMBER = 1
        START_DATE = $start_date
        END_DATE = ''
        SUMMER_SCHOOL = 'N'
        PROGRAM_OVERRIDE = 'N'
    }

}

$meal_status_upload | ForEach-Object {
    #check for existing program value.
    if ($existingMealStatus.($PSitem.STUDENT_ID)) {
        
        #if the latest program value is not the same as the incoming program value then we need to close the existing program.
        $latestRecord = $existingMealStatus.($PSitem.STUDENT_ID) | Select-Object -Last 1

        #This is actually based on the START_DATE not the PROGRAM_VALUE. It could be the same program value with a different start date.  This would just bring eSchool in line with the meal application.
        if (<#$latestRecord.PROGRAM_VALUE -ne $PSitem.PROGRAM_VALUE -and#> $latestRecord.START_DATE -ne $PSitem.START_DATE -and $latestRecord.END_DATE -eq '') {
            #we need to close the existing program.
            $close_existing_meal_status += [PSCustomObject]@{
                STUDENT_ID = $latestRecord.STUDENT_ID
                PROGRAM_ID = 'ARSES'
                PROGRAM_VALUE = $latestRecord.PROGRAM_VALUE
                FIELD_NUMBER = $latestRecord.FIELD_NUMBER
                START_DATE = $latestRecord.START_DATE
                END_DATE = $PSItem.START_DATE #use the incoming start date for the end date of the last record. What if the start date of the last record is after the incoming start date? This breaks the web interface.
                SUMMER_SCHOOL = 'N'
                PROGRAM_OVERRIDE = 'N'
            }
        } else {
            Write-Host "No changes neccessary for existing record: $($PSItem.STUDENT_ID)"
        }

    }
}

#Lets create the CSV file for upload. This will 
if ($meal_status_upload) {
    if ($close_existing_meal_status) {
        #include the closing of the existing meal status. We don't have to filter here because we are definitinly closing a record which means we should be opening another.
        $close_existing_meal_status | ConvertTo-Csv -UseQuotes Never -NoTypeInformation | Select-Object -Skip 1 | Out-File -FilePath "meal_status_upload.csv" -Force
        $meal_status_upload |
            ConvertTo-Csv -UseQuotes Never -NoTypeInformation |
            Select-Object -Skip 1 |
            Out-File -FilePath "meal_status_upload.csv" -Force -Append

        Submit-eSPFile -InFile meal_status_upload.csv
        Invoke-eSPUploadDefinition -InterfaceID ESMU7 -RunMode $RunMode -InsertNewRecords

    } else {
        #no need to close existing meal status but we don't want to constantly upload the same data over and over because the modified time will change. So lets filter it down to only changed data.
        $meal_status_filtered = $meal_status_upload |
            Where-Object { $latestRecord = ($existingMealStatus.($PSitem.STUDENT_ID) | Select-Object -Last 1); $latestRecord.PROGRAM_VALUE -ne $PSitem.PROGRAM_VALUE }

        if ($meal_status_filtered) {
            $meal_status_filtered |
                ConvertTo-Csv -UseQuotes Never -NoTypeInformation |
                Select-Object -Skip 1 |
                Out-File -FilePath "meal_status_upload.csv" -Force

            Submit-eSPFile -InFile meal_status_upload.csv
            Invoke-eSPUploadDefinition -InterfaceID ESMU7 -RunMode $RunMode -InsertNewRecords -Wait
            $eSchoolFiles = Get-eSPFileList
            $fileDateTime = $eSchoolFiles | Where-Object -Property RawFileName -EQ "meal_status_upload.csv" | Select-Object -ExpandProperty ModifiedDate
            $eSchoolFiles | Where-object -Property ModifiedDate -GE $fileDateTime | Where-Object -Property RawFileName -LIKE "Run_Upload_Log*.txt" | Select-Object -Last 1 | Get-eSPFile -Raw
        } else {
            Write-Host "No changes necessary to upload into eSchool."
            Exit 0
        }
    }
}

Write-Warning "You should run this Cognos Report to review any issues with Meal Status dates:"
Write-Warning 'Get-CognosReport -report "APSCN Invalid Program Dates" -cognosfolder "_Shared Data File Reports\eSchool Data Cleanup Reports" -reportparams "p_year=2024" -TeamContent | Where-Object -Property "Program Name" -eq "Meal Status" | Format-Table'
