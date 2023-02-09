function Set-eSchoolConfig {
    <#
        .SYNOPSIS
        Creates or updates a config
        .DESCRIPTION
        Creates or updates a config
        .PARAMETER ConfigName
        The friendly name for the config you are creating or updating. Will be stored at $HOME\.config\eSchool\[ConfigName].json
        .PARAMETER Username
        Your eSchool Username
        .EXAMPLE
        Set-eSchoolConfig -Username "0403cmillsap"
        .EXAMPLE
        Set-eSchoolConfig -ConfigName "Training" -Username "0403training"
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
    [cmdletbinding()]
    Param(
        [parameter(Mandatory = $false)]
        [ValidateScript( {
                if ($_ -notmatch '^[a-zA-Z]+[a-zA-Z0-9]*$') {
                    throw "You must specify a ConfigName that starts with a letter and does not contain any spaces, otherwise the Configuration could break."
                } else {
                    $true
                }
            })]
        [string]$ConfigName = "DefaultConfig",
        [parameter(Mandatory = $true)][string]$username
    )

    #ensure the configuration folder exists under this users local home.
    if (-Not(Test-Path "$($HOME)\.config\eSchool")) {
        New-Item "$($HOME)\.config\eSchool" -ItemType Directory -Force
    }

    $eSchoolPassword = Read-Host -Prompt "Please provide your eSchool Password" -AsSecureString | ConvertFrom-SecureString

    $config = @{
        ConfigName = $ConfigName
        Username = $username
        password = $eSchoolPassword
    }

    $configPath = "$($HOME)\.config\eSchool\$($ConfigName).json"
    $config | ConvertTo-Json | Out-File $configPath -Force

}

function Show-eSchoolConfig {
    <#
        .SYNOPSIS
        Display saved eSchool Configurations
        .DESCRIPTION
        Display saved eSchool Configurations
        .EXAMPLE
        Show-eSchoolConfig
    #>
    $configs = Get-ChildItem "$($HOME)\.config\eSchool\*.json" -File

    if ($configs) {

        $configList = [System.Collections.Generic.List[PSObject]]@()
        
        $configs | ForEach-Object { 
            $config = Get-Content $PSitem.FullName | ConvertFrom-Json | Select-Object -Property ConfigName,username,fileName
            $config.fileName = $PSitem.FullName

            if ($config.ConfigName -ne $PSItem.BaseName) {
                Write-Error "ConfigName should match the file name. $($PSitem.FullName) is invalid."
            } else {
                $configList.Add($config)
            }
        }

        $configList | Format-Table

    } else {
        Throw "No configuration files found."
    }

}

function Remove-eSchoolConfig {
    <#
        .SYNOPSIS
        Remove a saved config
        .DESCRIPTION
        Remove a saved config
        .PARAMETER ConfigName
        The friendly name for the config you want to remove. Will be removed from $HOME\.config\eSchool\[ConfigName].json
        .EXAMPLE
        Remove-eSchoolConfig -ConfigName "Gentry"
    #>
    Param(
        [parameter(Mandatory = $true)][string]$ConfigName
    )

    if (Test-Path "$($HOME)\.config\eSchool\$($ConfigName).json") {
        Write-Host "Removing configuration file $($HOME)\.config\eSchool\$($ConfigName).json"
        Remove-Item "$($HOME)\.config\eSchool\$($ConfigName).json" -Force
    } else {
        Write-Error "No configuration file found for the provided $($ConfigName). Run Show-eSchoolConfig to see available configurations."
    }

}

function Update-eSchoolPassword {
    <#
        .SYNOPSIS
        Display saved eSchool Configurations
        .DESCRIPTION
        Display saved eSchool Configurations
        .EXAMPLE
        Show-eSchoolConfig
    #>
    Param(
        [parameter(Mandatory = $false)][string]$ConfigName="DefaultConfig",
        [parameter(Mandatory = $false)][securestring]$Password
    )

    if (Test-Path "$($HOME)\.config\eSchool\$($ConfigName).json") {
        $configPath = "$($HOME)\.config\eSchool\$($ConfigName).json"
        $config = Get-Content "$($HOME)\.config\eSchool\$($ConfigName).json" | ConvertFrom-Json
    } else {
        Write-Error "No configuration file found for the provided $($ConfigName). Run Show-eSchoolConfig to see available configurations." -ErrorAction STOP
    }

    try {
        if ($Password) {
            $eSchoolPassword = $Password | ConvertFrom-SecureString
        } else {
            #prompt for new password
            $eSchoolPassword = Read-Host -Prompt "Please provide your new eSchool Password" -AsSecureString | ConvertFrom-SecureString
        }
        $config.password = $eSchoolPassword
        $config | ConvertTo-Json | Out-File $configPath -Force
    } catch {
        Throw "Failed to update password. $PSItem"
    }

}

function Connect-ToeSchool {
    <#
    
    .SYNOPSIS
    Establish session cookie to eSchool.
    
    #>

    Param(
        [parameter(Mandatory=$false)][string]$ConfigName = "DefaultConfig",
        [parameter(Mandatory=$false)][Switch]$TrainingSite,
        [parameter(Mandatory=$false)][string]$Database
    )

    if (Test-Path "$($HOME)\.config\eSchool\$($ConfigName).json") {
        $config = Get-Content "$($HOME)\.config\eSchool\$($ConfigName).json" -ErrorAction STOP | ConvertFrom-Json
    } elseif (Test-Path "$($HOME)\.config\Cognos\$($ConfigName).json") {
        Write-Warning "No configuration specified. Defaulting back to CognosModule Configuration."
        $config = Get-Content "$($HOME)\.config\Cognos\$($ConfigName).json" -ErrorAction STOP | ConvertFrom-Json
    } else {
        Write-Error "No Configuration Specified"
    }

    if ($TrainingSite) {
        $baseUrl = "https://eschool20.esptrn.k12.ar.us/eSchoolPLUS"
    } else {
        $baseUrl = "https://eschool20.esp.k12.ar.us/eSchoolPLUS20"
    }

    $loginUrl = $baseUrl + '/Account/LogOn'
    $envUrl = $baseUrl + '/Account/SetEnvironment/SessionStart'
    
    $username = $config.username
    $password = (New-Object pscredential "user",($config.password | ConvertTo-SecureString)).GetNetworkCredential().Password
    
    #Get Verification Token.
    $response = Invoke-WebRequest -Uri $loginUrl -SessionVariable eSchoolSession

    #Login
    $params = @{
        'UserName' = $username
        'Password' = $password
        '__RequestVerificationToken' = $response.InputFields[0].value
    }

    $response2 = Invoke-WebRequest -Uri $loginUrl -WebSession $eSchoolSession -Method POST -Body $params -ErrorAction Stop

    if (($response2.ParsedHtml.title -eq "Login") -or ($response2.StatusCode -ne 200)) {
        Write-Error "Failed to login."
    }

    $fields = $response2.InputFields | Group-Object -Property name -AsHashTable
    if (-Not($Database)) {
        # $databaseNumber = $response2.RawContent | Select-String -Pattern 'selected="selected" value="....' -All | Select-Object -Property Matches | ForEach-Object { $PSItem.Matches[0].Value }
        # $databaseNumber = $databaseNumber -replace "[^0-9]" #$Database.Substring($Database.Length-4,4)
        $databaseNumber = $response2.RawContent |
            Select-String -Pattern "<option.*value=""(\d+)"">.*</option>" -All | 
            Select-Object -Property Matches | Select-Object -ExpandProperty Matches | 
            Select-Object -ExpandProperty Groups | 
            Select-Object -ExpandProperty Value -Last 1
    } else {
        $databaseNumber = $response2.RawContent | 
            Select-String -Pattern "<option.*value=""(\d+)"">$($Database)</option>" -All | 
            Select-Object -Property Matches | Select-Object -ExpandProperty Matches | 
            Select-Object -ExpandProperty Groups | 
            Select-Object -ExpandProperty Value -Last 1
    }

    if ([int](Get-Date -Format MM) -ge 7) {
        $schoolYear = [int](Get-Date -Format yyyy) + 1
    } else {
        $schoolYear = [int](Get-Date -Format yyyy)
    }

    #Set Environment
    $params2 = [ordered]@{
        'ServerName' = $fields.'ServerName'.value
        'EnvironmentConfiguration.Database' = $databaseNumber
        'UserErrorMessage' = 'You do not have access to the selected database.'
        'EnvironmentConfiguration.SchoolYear' = $fields.'EnvironmentConfiguration.SchoolYear'.value ? $fields.'EnvironmentConfiguration.SchoolYear'.value : $schoolYear
        'EnvironmentConfiguration.SummerSchool' = 'false'
        'EnvironmentConfiguration.ImpersonatedUser' = ''
    }

    Write-Verbose ($params2 | ConvertTo-Json)

    $response3 = Invoke-WebRequest -Uri $envUrl -WebSession $eSchoolSession -Method POST -Body $params2 -ContentType "application/x-www-form-urlencoded"
    
    if ($response3.StatusCode -ne 200) {
        Write-Error "Failed to Set Environment."
        #Throw "Failed to Set Environment."
    } else {
        Write-Output "Connected to eSchool."
        $global:eSchoolSession = @{
            Session = $eschoolSession
            Username = $username
            Url = $baseUrl
            Params = @{ #used to reestablish session
                Database = $Database
                ConfigName = $ConfigName
                TrainingSite = $TrainingSite ? $true : $false
            }
            
        }

        return
    }

}

function Disconnect-FromeSchool {
    $ignore = Invoke-RestMethod -uri "$($eSchoolSession.url)/Account/LogOff" -WebSession $eSchoolSession.Session -SkipHttpErrorCheck -MaximumRedirection 99
}

function Assert-eSPSession {
    Try {
        #attempt to see the task list. If this sends us a redirect then we know the session has expired. Try to authenticate again.
        #even if this is null it won't fail.
        $tasks = Invoke-RestMethod -Uri "$($eschoolSession.Url)/Task/TaskAndReportData?includeTaskCount=true&includeReports=false&maximumNumberOfReports=1&includeTasks=true&runningTasksOnly=false" -MaximumRedirection 0 -WebSession $eschoolSession.session
    } catch {
        $params = $eschoolSession.Params
        Connect-ToeSchool @params
    }
}
function Get-eSPFileList {
    <#
    
    .SYNOPSIS
    Return list of Files in eSchool

    #>

    Assert-eSPSession

    $reports = Invoke-RestMethod `
        -Uri "$($eschoolSession.Url)/Task/TaskAndReportData?includeTaskCount=true&includeReports=true&maximumNumberOfReports=-1&includeTasks=false&runningTasksOnly=false" `
        -WebSession $eschoolSession.Session | 
        Select-Object -ExpandProperty Reports |
        Select-Object -Property DisplayName,RawFileName,FileExtension,@{ Name = 'ModifiedDate'; Expression = { (Get-Date "$($PSitem.ModifiedDate)") }},ReportSize,ReportPath |
        Sort-Object -Property ModifiedDate -Descending

    return $reports

}

function Get-eSPFile {
    <#
    
    .SYNOPSIS
    Download File from eSchool

    #>

    [CmdletBinding(DefaultParametersetName="FileName")]
    Param(
        [Parameter(Mandatory=$true,ParameterSetName="FileName")][string]$FileName, #Download an exact named file.
        [Parameter(Mandatory=$true,ParameterSetName="NameLike")][string]$NameLike, #Download the latest file that matches. Example would be HomeAccessPasswords* where there are possibly hundreds of unknown files.
        [Parameter(Mandatory=$false)][string]$OutFile,
        [Parameter(Mandatory=$false)][switch]$AsObject,
        [Parameter(Mandatory=$false)][string]$Delimeter = ',' #This could be Pipe or whatever the eSchool Definition uses.
    )

    Assert-eSPSession

    $latestFileList = Get-eSPFileList

    if ($FileName) {
        $report = $latestFileList | Where-Object { $PSItem.RawFileName -eq "$($FileName)" }
    } else {
        $report = $latestFileList | Where-Object { $PSitem.RawFileName -LIKE "$($NameLike)*" } | Select-Object -First 1
    }

    if (-Not($OutFile)) {
        $OutFile = $($report.RawFileName)
    }

    try {    
        if ($AsObject) {
            $response = Invoke-WebRequest -Uri "$($eschoolSession.Url)/Reports/$($report.ReportPath)" -WebSession $eschoolSession.Session
            return $response.Content | ConvertFrom-CSV -Delimiter $Delimeter
        } else {
            Invoke-WebRequest -Uri "$($eschoolSession.Url)/Reports/$($report.ReportPath)" -WebSession $eschoolSession.Session -OutFile $OutFile
        }
    } catch {
        Throw "$PSItem"
    }

    return [PSCustomObject]@{
        Name = $($report.RawFileName)
        Path = Get-ChildItem $OutFile
    }

}

function Submit-eSPFile {
    <#
    .SYNOPSIS
    Upload File to eSchool
    
    #>

    Param(
        [parameter(Mandatory=$true,HelpMessage="File Path")]$InFile
    )

    Assert-eSPSession
    
    if (Test-Path "$InFile") {

        $Form = @{
            name = 'FileToUpload'
            fileData = Get-ChildItem -Path $InFile -File
        }

        #return $fields
        $response = Invoke-WebRequest -Uri "$($eschoolSession.Url)/Utility/UploadFile" -Method Post -WebSession $eschoolSession.Session -Form $Form

        if ($response.StatusCode -eq 200) {
            Write-Host "Success."
            return
        }
        
    } else {
        Throw "Could not find file."
    }

}

function Invoke-eSPDownloadDefinition {
    <#
    
    .SYNOPSIS
    Start a Download Definition
    
    #>

    Param(
        [Parameter(Mandatory=$true)][ValidateScript( { ($PSitem.Length) -eq 5} )][string]$InterfaceID,
        [Parameter(Mandatory=$false)][switch]$ActiveStudentsOnly,
        [Parameter(Mandatory=$false)][switch]$Wait #wait until the scheduled task is complete or errored.
    )

    Assert-eSPSession

    $params = [ordered]@{
        'SearchType' = 'download_filter'
        'SortType' = ''
        'InterfaceId' = $InterfaceID
        'StartDate' = '07/01/2019'
        'ImportDirectory' = 'UD'
        'TxtImportDirectory' = ''
        'TaskScheduler.CurrentTask.Classname' = 'LTDB20_4.CRunDownload'
        'TaskScheduler.CurrentTask.TaskDescription' = "$InterfaceID"
        'groupPredicate' = 'false'
        'Filter.LoginId' = $eSchoolSession.Username
        'Filter.SearchType' = 'download_filter'
        'Filter.SearchNumber' = '0'
        'Filter.GroupingMask' = ''
        'SortFields.Fields[0].SortFieldIndex' = '1'
        'sortFieldTableKey' = ''
        'SortFields.LoginId' = $eSchoolSession.username
        'SortFields.SearchType' = 'download_filter'
        'SortFields.SearchNumber' = '0'
        'TaskScheduler.CurrentTask.ScheduleType' = 'O'
        'TaskScheduler.CurrentTask.ScheduledTimeTime' = (Get-Date).ToString("hh:mm tt") #(Get-Date).AddMinutes(1).ToString("hh:mm tt")
        'TaskScheduler.CurrentTask.ScheduledTimeDate' = Get-Date -UFormat %m/%d/%Y
        'TaskScheduler.CurrentTask.SchdInterval' = '1'
        'TaskScheduler.CurrentTask.Monday' = 'false'
        'TaskScheduler.CurrentTask.Tuesday' = 'false'
        'TaskScheduler.CurrentTask.Wednesday' = 'false'
        'TaskScheduler.CurrentTask.Thursday' = 'false'
        'TaskScheduler.CurrentTask.Friday' = 'false'
        'TaskScheduler.CurrentTask.Saturday' = 'false'
        'TaskScheduler.CurrentTask.Sunday' = 'false'
    }

    if ($ActiveStudentsOnly) {
        $params += @{
            'Filter.Predicates[0].PredicateIndex' = '1'
            'tableKey' = 'reg'
            'Filter.Predicates[0].TableName' = 'reg'
            'columnKey' = 'reg.current_status'
            'Filter.Predicates[0].ColumnName' = 'current_status'
            'Filter.Predicates[0].DataType' = 'Char'
            'Filter.Predicates[0].Operator' = 'Equal'
            'Filter.Predicates[0].Value' = 'A'
            'Filter.Predicates[1].LogicalOperator' = 'And'
            'Filter.Predicates[1].PredicateIndex' = '2'
            'Filter.Predicates[1].DataType' = 'Char'
        }
    }

    Write-Verbose ($params | ConvertTo-Json -Depth 99)

    $response = Invoke-RestMethod -Uri "$($eschoolSession.Url)/Utility/RunDownload" `
        -WebSession $eschoolSession.Session `
        -Method POST `
        -Body $params

    if ($response.PageState -eq 2) {
        Write-Host "Successfully started $InterfaceID download definition."

        if ($Wait) {

            do {

                $response2 = Get-eSPTaskList

                if ($response2.InActiveTasks.TaskName -contains $InterfaceID) {
                    #still waiting to run.
                    Write-Verbose "Waiting to run task."
                } elseif ($response2.ActiveTasks.TaskName -contains $InterfaceID) {
                    Write-Verbose "Task is currently running."
                } else {
                    $complete = $true
                }

                Start-Sleep -Seconds 5

            } until ($complete)

        }

    } elseif ($null -ne $response.PageState) {
        Write-Verbose ($response.ValidationErrorMessages | ConvertTo-Json -Depth 99)
        Write-Error "Failed to start download definition."
        Write-Error "$($response.ValidationErrorMessages.message)"
    } else {
        Throw "$($response)"
    }

}

function Invoke-eSPUploadDefinition {
    <#
    
    .SYNOPSIS
    Start an Upload Definition

    #>

    Param(
        [Parameter(Mandatory=$true)][ValidateScript( { ($PSitem.Length) -eq 5} )][string]$InterfaceID,
        [Parameter(Mandatory=$false)][ValidateSet("R","V")][String][string]$RunMode = 'V',
        [parameter(mandatory=$false)][switch]$DoNotUpdateExistingRecords, #Do you want the upload definition to update existing records?
        [parameter(mandatory=$false)][switch]$InsertNewRecords, #Do you want the upload definition to insert new records?
        [parameter(mandatory=$false)][switch]$UpdateBlankRecords, #Do you want the upload definition to update blank records?
        [Parameter(Mandatory=$false)][switch]$Wait #wait until the scheduled task is complete or errored.
    )

    Assert-eSPSession

    #expecting string but wanting to use switches for function.
    $UpdateExistingRecords = $DoNotUpdateExistingRecords ? 'false' : 'true' #reverse for switch.
    $InsertNew = $InsertNewRecords ? 'true' : 'false'
    $UpdateBlank = $UpdateBlankRecords ? 'true' : 'false'

    $params = [ordered]@{
        'SearchType' = 'upload_filter'
        'SortType' = ''
        'InterfaceId' = "$InterfaceID"
        'RunMode' = "$RunMode"
        'InsertNewRec' = $InsertNew
        'UpdateExistRec' = $UpdateExistingRecords
        'UpdateBlankRec' = $UpdateBlank
        'ImportDirectory' = 'UD'
        'StudWithoutOpenProg' = 'USD'
        'RunType' = 'UPLOAD'
        'ProgramDatesEnabled' = 'N'
        'TaskScheduler.CurrentTask.Classname' = 'LTDB20_4.CRunUpload'
        'TaskScheduler.CurrentTask.TaskDescription' = $InterfaceID
        'groupPredicate' = 'false'
        'Filter.Predicates[0].PredicateIndex' = '1'
        'tableKey' = ''
        'Filter.Predicates[0].DataType' = 'Char'
        'Filter.LoginId' = $eSchoolSession.Username
        'Filter.SearchType' = 'upload_filter'
        'Filter.SearchNumber' = '0'
        'Filter.GroupingMask' = ''
        'TaskScheduler.CurrentTask.ScheduleType' = 'N'
        'TaskScheduler.CurrentTask.SchdInterval' = '1'
        'TaskScheduler.CurrentTask.ScheduledTimeTime' = (Get-Date).ToString("hh:mm tt") #Set forward 1 minute(s) "03:45 PM"
        'TaskScheduler.CurrentTask.ScheduledTimeDate' = Get-Date -UFormat %m/%d/%Y #"05/07/2019"
        'TaskScheduler.CurrentTask.Monday' = 'false'
        'TaskScheduler.CurrentTask.Tuesday' = 'false'
        'TaskScheduler.CurrentTask.Wednesday' = 'false'
        'TaskScheduler.CurrentTask.Thursday' = 'false'
        'TaskScheduler.CurrentTask.Friday' = 'false'
        'TaskScheduler.CurrentTask.Saturday' = 'false'
        'TaskScheduler.CurrentTask.Sunday' = 'false'
        'ProgramStartDate' = ''
        'ProgramEndDate' = ''
        'GridEndDateData' = @{}
        'GridStartDateData' = @{}
    }

    $jsonPayload = $params | ConvertTo-Json -Depth 3
    Write-Verbose $jsonPayload

    $response = Invoke-RestMethod -Uri "$($eschoolSession.Url)/Utility/RunUpload" `
        -WebSession $eschoolSession.Session `
        -Method POST `
        -Body $jsonPayload `
        -ContentType "application/json; charset=UTF-8"

    if ($response.PageState -eq 2) {
        Write-Host "Successfully started $InterfaceID upload definition."

        if ($Wait) {

            do {

                $response2 = Get-eSPTaskList

                if ($response2.InActiveTasks.TaskName -contains $InterfaceID) {
                    #still waiting to run.
                    Write-Verbose "Waiting to run task."
                } elseif ($response2.ActiveTasks.TaskName -contains $InterfaceID) {
                    Write-Verbose "Task is currently running."
                } else {
                    $complete = $true
                }

                Start-Sleep -Seconds 5

            } until ($complete)

        }

    } elseif ($null -ne $response.PageState) {
        Write-Verbose ($response.ValidationErrorMessages | ConvertTo-Json -Depth 99)
        Write-Error "Failed to start upload definition."
        Write-Error "$($response.ValidationErrorMessages.message)"
    } else {
        Throw "$($response)"
    }

}

function Get-eSPTaskList {
    <#

    .SYNOPSIS
    Return list of currently running or scheduled tasks.

    #>

    Param(
        [parameter(Mandatory = $false)][switch]$ActiveTasksOnly,
        [parameter(Mandatory = $false)][switch]$ErrorsOnly
    )

    Assert-eSPSession

    $tasks = Invoke-RestMethod `
        -Uri "$($eschoolSession.Url)/Task/TaskAndReportData?includeTaskCount=true&includeReports=false&maximumNumberOfReports=-1&includeTasks=true&runningTasksOnly=false" `
        -WebSession $eschoolSession.Session | 
        Select-Object -Property RunningTaskCount,ActiveTasks,InactiveTasks

    $erroredTasks = $tasks.ActiveTasks | Where-Object { $PSItem.ErrorOccurred -eq 'True' }

    #Return errored reports.
    if ($ErrorsOnly) {
        return ($erroredTasks | 
            Select-Object -Property TaskKey,TaskName,ProgressDescription,ErrorOccurred,RunTime,@{ Name = "TaskError"; Expression = { $PSItem.TaskError.ScheduledTaskErrorDescription } })
    } else {
        if ($erroredTasks) {
           #print to terminal
            Write-Warning "You have failed tasks in your task list."
            Write-Warning ($erroredTasks | 
                Select-Object -Property TaskKey,TaskName,ProgressDescription,ErrorOccurred,RunTime,@{ Name = "TaskError"; Expression = { $PSItem.TaskError.ScheduledTaskErrorDescription } } | 
                Format-Table | Out-String)
        }
    }

    if ($ActiveTasksOnly) {
        if ($tasks.RunningTaskCount -eq 0) {
            Write-Warning "No currently running tasks."
            return $null
        } else {
            return ($tasks | 
                Select-Object -ExpandProperty ActiveTasks | 
                Where-Object { $PSItem.ErrorOccurred -ne 'True' })
        }
    }

    return $tasks

}

function Clear-eSPFailedTask {
    <#

    .SYNOPSIS
    Clear a failed task from your Task List

    #>

    Param(
        [parameter(Mandatory=$true)][string]$TaskKey
    )

    Assert-eSPSession

    #This always returns the Task List regardless of what we send it.
    $response = Invoke-RestMethod -Uri "$($eschoolSession.Url)/Task/ClearErroredTask" `
        -Method "POST" `
        -WebSession $eschoolSession.Session `
        -ContentType "application/json; charset=UTF-8" `
        -Body "{`"paramKey`":`"$($PSitem.TaskKey)`"}"

}

function Get-eSPSchools {
    <#
    
    .SYNOPSIS
    Return Building Name and Building Number
    
    .DESCRIPTION
    Unfortunately this returns all of them even if they are marked as inactive. So we have to ignore instead.

    #>

    Param(
        [Parameter(Mandatory=$false)][string]$IgnoreBuildings = "9000,80000,88000" #Transfer, Referral, and Sped
    )

    Assert-eSPSession

    $params = [ordered]@{
        "searchType" = "CONTACTMASSUPDATE"
        "ColumnName" = "building"
        "FieldNumber" = $null
        "ColumnKeyString" = "reg.building"
        "TableName" = "reg"
        "ScreenType" = $null
        "ScreenNumber" = $null
        "ProgramId" = $null
        "TableKeyType" = 0
        "TableKeyString" = "reg"
    }

    $schools = Invoke-RestMethod -Uri "$($eschoolSession.Url)/Search/GetValidationTableItems" `
        -Method "POST" `
        -WebSession $eSchoolSession.session `
        -ContentType "application/json; charset=UTF-8" `
        -Body ($params | ConvertTo-Json)

    $schools = $schools | ForEach-Object {
            [PSCustomObject]@{
                School_id = [int]$PSitem.Code
                School_name = $PSItem.Description
            }
        }
    
    if ($IgnoreBuildings) {
        $schools = $schools | Where-Object { $IgnoreBuildings.Split(',') -notcontains $PSItem.School_id }
    }

    return $schools

}

function Get-eSPStudents {

    <#
    
    .SYNOPSIS
    Return basic information about currently enrolled students at a campus.
    
    #>

    [CmdletBinding(DefaultParametersetName="default")]
    Param(
        [Parameter(Mandatory=$true,ParameterSetName="default",ValueFromPipeline=$true)]$Building #ID of the Building
    )

    Begin {
        Assert-eSPSession
        $students = [System.Collections.Generic.List[Object]]::new()
        $schoolIds = [System.Collections.Generic.List[Object]]::new()
    }

    Process {

        if ($Building.School_id) {
            #incoming object has the School_id property.
            $schoolIds.Add($Building.School_id)
        } elseif (([string]$Building).IndexOf(',') -ge 1) {
            #comma separated string. Still get an array for $schoolIds.
            $schoolIds = $Building.Split(',')
        } else {
            #should be processing an array
            $schoolIds = $building
        }

    }

    End {

        Write-Verbose "Buildings $($schoolIds -join ',')"

        $schoolIds | ForEach-Object {

            $params = [ordered]@{
                "Filter" = [ordered]@{
                "LoginId" = $eSchoolSession.Username
                "SearchType" = "REGMASSUPDATE"
                "SearchNumber" = "0"
                "GroupingMask" = ""
                "Predicates"= @(
                    [ordered]@{
                        LogicalOperator = "And"
                        PredicateIndex = 1
                        TableName = "reg"
                        ColumnName = "current_status"
                        Operator = "Equal"
                        DataType = "Char"
                        Value = "A"
                    },
                    [ordered]@{
                        LogicalOperator = "And"
                        PredicateIndex = 2
                        TableName = "reg"
                        ColumnName = "building"
                        Operator = "Equal"
                        DataType = "Int"
                        Value = [int]$($PSitem)
                    }
                )
                }
            }

            $jsonPayload = $params | ConvertTo-Json -Depth 99

            Write-Verbose $jsonPayload

            $response = Invoke-RestMethod -Uri "$($eschoolSession.Url)/Utility/GetRegistrationMUFilterResultsGridData" `
            -Method "POST" `
            -WebSession $eSchoolSession.session `
            -ContentType "application/json; charset=UTF-8" `
            -Body $jsonPayload
            
            if ($response.gridData) {
                $response.gridData | ForEach-Object {
                    $student = [PSCustomObject]@{
                        Student_id = [string]$PSItem.StudentID
                        Last_name = $PSItem.StudentName.Split(', ')[0]
                        First_name = $PSItem.StudentName.Split(', ')[1]
                        Grade = $PSitem.Grade
                        School_id = [int]$PSItem.BuildingNum
                    }
                    $students.Add($student)
                }
            } else {
                Write-Error "No records returned for building $PSitem."
            }

            
        }

        return $students

    }
}

function Get-eSPStudentDetails {
    <#
    
    .SYNOPSIS
    Get some more details from the QuickSearch
    
    #>

    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]$StudentId
    )

    Begin {
        Assert-eSPSession
        $students = [System.Collections.Generic.List[Object]]::new()
        $studentIds = [System.Collections.Generic.List[Object]]::new()
    }

    Process {
        if ($StudentId.Student_id) {
            #incoming object has the School_id property.
            $studentIds.Add($StudentId.Student_id)
        } elseif (([string]$StudentId).IndexOf(',') -ge 1) {
            #comma separated string. Still get an array for $studentIds.
            $studentIds = $StudentId.Split(',')
        } else {
            #should be processing an array
            $studentIds = $StudentId
        }
    }

    End {

        Write-Verbose ($studentIds | ConvertTo-Json)
        $students = $studentIds | ForEach-Object -Parallel {

            try {
                $response = Invoke-RestMethod -Uri "$(($using:eschoolSession).Url)/Search/QuickSearch?query=$($PSitem)&Limit=1" -WebSession ($using:eSchoolSession).session
            
                Write-Verbose $response.SearchQuery

                if ($response.SearchQuery -eq "$($PSItem)") {
                    [PSCustomObject]@{
                        Student_id = [string]$response.StudentResults.StudentID
                        Last_name = $response.StudentResults.LastName
                        First_name = $response.StudentResults.FirstName
                        Middle_name = $response.StudentResults.MiddleName
                        School_id = $response.StudentResults.BuildingId
                        Grade = $response.StudentResults.Grade
                        Age = $response.StudentResults.Age
                        Status = $response.StudentResults.CurrentStatus
                    }

                }
            } catch {
                return
            }
            
        } -ThrottleLimit 10

        return $students
    }

}

