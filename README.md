#eSchoolModule
These scripts come without warranty of any kind. Use them at your own risk. I assume no liability for the accuracy, correctness, completeness, or usefulness of any information provided by this site nor for any sort of damages using these scripts may cause.

The eSchool Powershell Module requires PowerShell 7


## Installation Process
Open PowerShell Window as Administrator
````
mkdir "C:\Program Files\PowerShell\Modules\eSchoolModule"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AR-k12code/eSchoolModule/master/eSchoolModule.psd1" -OutFile "C:\Program Files\PowerShell\Modules\eSchoolModule\eSchoolModule.psd1"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AR-k12code/eSchoolModule/master/eSchoolModule.psm1" -OutFile "C:\Program Files\PowerShell\Modules\eSchoolModule\eSchoolModule.psm1"
````

## Initial Configuration
````
PS C:\Scripts> Set-eSchoolConfig -username 0403cmillsap
Please provide your eSchool Password: ********************
````
Provide a name for a specific configuration. Example: If you have multiple users with different privileges.
````
PS C:\Scripts> Set-CognosConfig -ConfigName "Judy" -username 0403judy
Please provide your Cognos Password: ********************
````

## Tutorial
Coming Soon
[![tutorial](/images/youtube_thumbnail.jpg)](https://youtu.be/)

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
Get-eSPFileLIst
````

### Get a File
````
Get-eSPFile -FileName <String> [-OutFile <String>] [-AsObject] [-Delimeter <String>]
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
````
Get-eSPSchools [[-IgnoreBuildings] <String>]
````

### Basic Student Info (unstructured data)
````
Get-eSPStudents -Building <Object>
````

### Additional Student Info (structured data)
````
Get-eSPStudentDetails [-StudentId] <Object>
````

### Update Saved Password
````
Update-eSchoolPassword [[-ConfigName] <String>] [[-Password] <SecureString>]
````