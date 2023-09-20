# eSchoolModule
These scripts come without warranty of any kind. Use them at your own risk. I assume no liability for the accuracy, correctness, completeness, or usefulness of any information provided by this site nor for any sort of damages using these scripts may cause.

The eSchool Powershell Module requires PowerShell 7
**DO NOT INSTALL THESE SCRIPTS TO A DOMAIN CONTROLLER.**

Create a dedicated VM running Windows Server 2019 or Windows 10 Pro 1809+ for your automation scripts.

## Requirements
Git ````https://git-scm.com/download/win````

Powershell 7 ````https://github.com/PowerShell/powershell/releases````
## Installation Process
Open PowerShell Window as Administrator
````
mkdir "C:\Program Files\PowerShell\Modules\eSchoolModule"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AR-k12code/eSchoolModule/master/eSchoolModule.psd1" -OutFile "C:\Program Files\PowerShell\Modules\eSchoolModule\eSchoolModule.psd1"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AR-k12code/eSchoolModule/master/eSchoolModule.psm1" -OutFile "C:\Program Files\PowerShell\Modules\eSchoolModule\eSchoolModule.psm1"
````

## Initial Configuration
````
PS C:\Scripts> Set-eSchoolConfig -username 0400cmillsap
Please provide your eSchool Password: ********************
````
Provide a name for a specific configuration. Example: If you have multiple users with different privileges.
````
PS C:\Scripts> Set-CognosConfig -ConfigName "Judy" -username 0400judy
Please provide your Cognos Password: ********************
````

### Update Saved Password
````
Update-eSchoolPassword [[-ConfigName] <String>] [[-Password] <SecureString>]
````

# Required eSchool Permissions
As an administrator you should be assigned a role with READ access to all areas of eSchool.

You NEED Read/Write to:
- eSchoolPLUS System > Utilities > RUNLOAD
- eSchoolPLUS System > Setup And Configuration > LOADDEFS

# Tutorial
Coming Soon
[![tutorial](/images/youtube_thumbnail.jpg)](https://www.youtube.com/@camtechcs)

# Commmands

### Establish Connection to eSchool
````
Connect-ToeSchool [[-ConfigName] <String>] [-TrainingSite] [[-Database] <String>]
````

### Get Task List
````
Get-eSPTaskList [-ActiveTasksOnly] [-ErrorsOnly]
````

### Clear Task
````
Clear-eSPFailedTask [-TaskKey] <String>
````

### List Files
````
Get-eSPFileList
````

### Get a File
````
Get-eSPFile -FileName <String> [-OutFile <String>] [-AsObject] [-Raw] [-Delimeter <String>]
````

### Upload a File
````
Submit-eSPFile [-InFile] <Object>
````

### Start a Download Definition
````
Invoke-eSPDownloadDefinition [-InterfaceID] <String> [-ActiveStudentsOnly] [-Wait]
````

### Start an Upload Definition
````
Invoke-eSPUploadDefinition [-InterfaceID] <String> [[-RunMode] <String>] [-DoNotUpdateExistingRecords] [-InsertNewRecords] [-UpdateBlankRecords] [-Wait]
````

### List School Ids
By default will only return schools with a default calendar assigned.
````
Get-eSPSchools [-All]
````

### Get Student Info
````
# Get All Active Students
Get-eSPStudents

# Get Students from a Specific Building
Get-eSPStudents -Building 16

# Get Students in Grade(s)
Get-eSPStudents -Grade '01','08','KF'

# Additional Options
Get-eSPStudents [-InActive] [-Graduated] [-All]

# Include Additional Tables
Get-eSPStudents -Grade '01' -IncludeTable reg_academic,reg_notes
````


### List Staff Catalog
````
Get-eSPStaffCatalog [[-Building] <Int32>]
````

### List eSchool Users
````
Get-eSPSecUsers
````

### List eSchool Security Roles
````
Get-eSPSecRoles
````

### List Master Schedule
````
Get-eSPMasterSchedule
````

# PreDefined Upload/Download Defininitions
Built in download definitions will start with ESMD and upload defintions will start with ESMU. For the last character we will use [0-9] then [A-Z].

## Create Definitions
- New-eSPEmailDefinitions (ESMD0,ESMU0,ESMU1)
- New-eSPGuardianDefinitions (ESMD1,ESMU2,ESMU3,ESMU4)
- New-eSPHACUploadDefinition (ESMU5)
- New-eSPAttUploadDefinitions (ESMU6)

### Download Definitions
- ESMD0 - "eSchoolModule - Email Download Definition" - Download Contact_id,Student_id, and Email. Then you can process to fix them.
- ESMD1 - "eSchoolModule - Guardian Duplication" - Download all the information needed to dedupe guardian contacts.
- ESMD2 - "eSchoolModule - Meal Status" - Download the last 2 years of meal status data for active students.

### Upload Definitions
- ESMU0 - "eSchoolModule - Email Upload Definition" - Upload Student Emails by Contact_id,Email
- ESMU1 - "eSchoolModule - Web Access Upload Definition" - Enable Web Access for Contacts
- ESMU2 - "eSchoolModule - Move Duplicate Guardian Priority" - Move Duplicate Guardians to Priority of 99
- ESMU3 - "eSchoolModule - Connect Duplicate Guardians" - Connect the Existing Contacts to Students
- ESMU4 - "eSchoolModule - Merge Duplicate Guardian Phone Numbers" - Because we don't want lost data.
- ESMU5 - "eSchoolModule - Upload HAC Usernames for Contact ID" - Fix usernames for HAC. This does not fix passwords or generate Access Codes.
- ESMU6 - "eSchoolModule - Upload Attendance" - Push attendance from 3rd party programs back into eSchool. You must be able to match the period name.
- ESMU7 - "eSchoolModule - Upload Meal Status" - Upload Meal Status from Cafeteria Softare.

## Definition Creator
Think Bigger!
````
$newDefinition = New-espDefinitionTemplate -InterfaceId STUID -Description "Pull Student Id Numbers"
$newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
	-InterfaceId "STUID" `
	-HeaderId 1 `
	-HeaderOrder 1 `
	-FileName "studentids.csv" `
	-TableName "reg" `
	-Description "Pull Student Id Numbers" `
    -AdditionalSql 'WHERE CONVERT(DATETIME,CHANGE_DATE_TIME,101) >= DateAdd(Hour, DateDiff(Hour, 0, GetDate())-72, 0)'
	
$newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails +=	New-eSPDefinitionColumn `
	-InterfaceId "STUID" `
	-HeaderId 1 `
	-TableName "reg" `
	-FieldId 1 `
	-FieldOrder 1 `
	-ColumnName STUDENT_ID `
	-FieldLength 255

$newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails +=	New-eSPDefinitionColumn `
	-InterfaceId "STUID" `
	-HeaderId 1 `
	-TableName "reg" `
	-FieldId 2 `
	-FieldOrder 2 `
	-ColumnName CURRENT_STATUS `
	-FieldLength 255

New-eSPDefinition -Definition $newDefinition

Invoke-eSPDownloadDefinition -InterfaceId STUID -Wait

$studentIds = Get-eSPFile -FileName "studentids.csv" -AsObject | Select-Object -First 5
````

## Bulk Export Download Definitions
Think even bigger!

Every row will have a record delimiter of '#!#'.  This is because eSchool doesn't properly escape characters/carriage returns/line feeds.
````
$TablesToExport = @("REG","REG_STU_CONTACT","REG_CONTACT","REG_CONTACT_PHONE","REG_NOTES")

New-eSPBulkDownloadDefinition -Tables $TablesToExport -InterfaceId "REG00" -DoNotLimitSchoolYear -Delimiter "|" -Force

Assert-eSPSession -Force #don't know why you have to do this after creating a Bulk Download Definition.

Invoke-espDownloadDefinition -InterfaceID "REG00" -Wait

$TablesToExport | ForEach-Object {
	New-Variable -Name $PSItem -Value (Get-eSPFile -FileName "$($PSItem).csv" -Raw | ConvertFrom-CSV -Delimiter '|') -Force
}

$REG | Measure-Object
#Count             : 725
````

## Verifying and Sanitizing your Files
There are multiple ways of cleaning up the files exported. You get to choose which way is best for you. This can be because eSchool does not escape Return Carriages, Line Feeds, or extra delimiters in fields with a download definition. Using the Delimiter "Q" for quoting fields doesn't help.

### CSVKit
This will create a file called reg_out.csv in the same folder. It will remove any lines that do not match the columns expected.  
````
# Exmaple of no errors
PS C:\eSchoolModule> csvclean.exe -d '|' reg_contact.csv
No errors.

# Example of row with the incorrect number of delimiters because of carriage returns and fixed.
PS C:\eSchoolModule> csvclean.exe -d '|' reg.csv
1 error logged to .\REG_err.csv
2 rows were joined/reduced to 1 rows after eliminating expected internal line breaks.

# Example of incorrect number of delimiters to return a complete record. Will be stripped from the resulting file.
PS c:\eSchoolModule> csvclean.exe -d '|' .\REG.csv
4 errors logged to .\REG_err.csv
````

### Directly Replace CR/LF
We can directly do replacements on the carriage returns and line feeds before we even save the file to disk. The record delimiter of '#!#' is what makes this possible.
````
$reg_notes = Get-eSPFile -FileName reg_notes.csv -Raw
$reg_notes = $reg_notes -replace "`n",'{LF}' -replace "`r",'{CR}' -replace '\|#!#{CR}{LF}',"`r`n"
$reg_notes | Out-File ".\reg_notes.csv"

#or as one line.
(Get-eSPFile -FileName reg_notes.csv -Raw) -replace "`n",'{LF}' -replace "`r",'{CR}' -replace '\|#!#{CR}{LF}',"`r`n" | Out-File ".\reg_notes.csv" -NoNewLine
````

## Import Into Database

### Microsoft SQL Server
````
$dbConn= @{
	hostname = "1.2.3.4"
	dbname = "schoolsms"
	username = 'smsadmin'
	password = 'xyz' #you should make this safer.
}

$TablesToExport | ForEach-Object {
	Import-DbaCsv -Path "$($PSitem).csv" -SqlInstance $($dbConn.hostname) -database $($dbConn.dbname) -Table "import_($PSitem)" -AutoCreateTable -SqlCredential (New-Object System.Management.Automation.PSCredential ("$($dbConn.username)", (ConvertTo-SecureString "$($dbConn.password)" -AsPlainText -Force))) -Truncate
}
````

### SQLite
````
$TablesToExport | ForEach-Object {
	& csvsql.exe -I --db "sqlite:///schoolsms.sqlite3" --insert --overwrite --blanks --tables "import_$($PSItem)" "$($PSItem).csv"
}
````

### MariaDB or MySQL
````
$dbConn= @{
	hostname = "1.2.3.4"
	dbname = "schoolsms"
	useranme = 'smsadmin'
	password = 'xyz' #you should make this safer.
}

$TablesToExport | ForEach-Object {
	& csvsql.exe -I --db "mysql+mysqlconnector://$($dbConn.username):$($dbConn.password)@$($dbConn.hostname)/$($dbConn.dbname)?charset=utf8mb4" --insert --overwrite --tables "import_$($PSItem)" "$($PSItem).csv"
}
````

# Example Scripts
Examples are in the scripts folder.

## Upload_Student_Emails.ps1
This script should help you upload correct email addresses based on your Active Directory field that contains the Student ID number. Default is EmployeeNumber. Some districts are EmployeeID.
````
.\Upload_Student_Emails.ps1 -ADField EmployeeNumber -SkipUpload -RunMode V -EnableWebAccess -EnableGuardianWebAccess -GuardianPriority 1
````

## Create_Bulk_Table_Definitions.ps1
This script will create download defintion for the REG, MR, SCHD, and ATT tables.  This will include different definitions for the complete table, 3 hour differential, 12 hour differential, 24 hour differential, 1 month differential, 1 year differential. Differentials are limited to the current school year.

## dedupe_guardians.ps1
DANGER WILL ROBINSON! This script is a proposal on deduping guardians. Read it, Understand it, Read it again, Then Understand some more.  By default the upload definition is set to Verification mode. It should NOT make any changes when you run it however we make no guarantees you didn't change something. Read it again.

- Duplicate guardians will be moved to a priority of 99.
- The primary contact ID will then be attached in the same priority, with all the existing data, as the duplciate was before it was moved to 99.
- If the duplicates have additional phone numbers they will be tied to the primary Contact ID for the duplicates. IE. The duplicate had a work number that the original didn't. It will be added.

````
dedupe_guardians.ps1 -MatchOnAddress -AllowBlankEmail
````

## Upload_Meal_Status.ps1
This script will download your existing meal status in eSchool for active students. It will ignore students in eSchool who have a 04 Direct Certification. It will then process the incoming new data, close existing program dates, and upload the new value.
````
.\Upload_Meal_Status.ps1 -FilePath eTrition_Application_Eligitibility.csv -StudentIDField PatronNumber -MealStatus Eligibility -StartDateField ApplicationStartDate -RunMode V
````

This script requires a CSV like the one below but you can specify the required column names on the command line:
````
STUDENT_ID,MEAL_STATUS,START_DATE
403005966,1,9/19/2023
403005967,3,9/19/2023
403005968,Free,2023/9/19
````

# What Now?
PROFIT?!
