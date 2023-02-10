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
        if ($eschoolSession) {
            #session exists but has probably timed out. Reuse parameters.
            $params = $eschoolSession.Params
            Connect-ToeSchool @params
        } else {
            #new session using default profile.
            Connect-ToeSchool
        }
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

    Write-Verbose ("$($eschoolSession.Url)/Reports/$($report.ReportPath)")

    try {    
        if ($AsObject) {
            $response = Invoke-WebRequest -Uri "$($eschoolSession.Url)/Reports/$($report.ReportPath)" -WebSession $eschoolSession.Session
            return [System.Text.Encoding]::UTF8.GetString($response.Content) | ConvertFrom-CSV -Delimiter $Delimeter
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

    $dateTime = Get-Date

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
        'TaskScheduler.CurrentTask.ScheduledTimeTime' = $dateTime.ToString("hh:mm tt") #(Get-Date).AddMinutes(1).ToString("hh:mm tt")
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

    $response = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/RunDownload" `
        -WebSession $eSchoolSession.Session `
        -Method POST `
        -Body $params

    if ($response.PageState -eq 2) {
        Write-Host "Successfully started $InterfaceID download definition."

        if ($Wait) {

            do {

                $tasks = Get-eSPTaskList -SilentErrors

                if ($tasks.InActiveTasks | 
                    Where-Object { $PSitem.TaskName -eq $InterfaceID -and 
                        (
                            #within 1 min either direction. More than that and you're probably doing something wrong.
                            ($dateTime.AddMinutes(-1) -le (Get-Date "$($PSitem.RunTime)")) -and
                            ($dateTime.AddMinutes(1) -ge (Get-Date "$($PSitem.RunTime)"))
                        )
                     }) {
                    #still waiting to run.
                    Write-Verbose "Waiting for task to run."
                } elseif ($task = $tasks.ActiveTasks | 
                    Where-Object { $PSitem.TaskName -eq $InterfaceID -and 
                        (
                            #within 1 min either direction. More than that and you're probably doing something wrong.
                            ($dateTime.AddMinutes(-1) -le (Get-Date "$($PSitem.RunTime)")) -and
                            ($dateTime.AddMinutes(1) -ge (Get-Date "$($PSitem.RunTime)"))
                        )
                    }) {
                    
                    Write-Verbose "Task is currently running."
                    
                    if ($task.ErrorOccurred -eq 'True') {
                        #Write-Error "Failed to run task."
                        Throw "Failed to run task"
                    }

                    #$progressSplit = $task.ProgressDescription | Select-String -Pattern "\((\d+) of (\d+)\)" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Groups
                    try {
                        $percentage = [math]::Floor( ($($task.RecordsProcessed)/$($task.TotalRecords) * 100) )
                        #$percentage = [math]::Floor( ($($progressSplit[1].Value)/$($progressSplit[2].Value) * 100) )
                        if ($percentage) {
                            Write-Progress -Activity "Processing $($task.TaskName)" -Status "$($task.ProgressDescription)" -PercentComplete $percentage
                        }
                    } catch { <# do nothing #> }

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
        [parameter(Mandatory = $false)][switch]$ErrorsOnly,
        [parameter(Mandatory = $false)][switch]$SilentErrors
    )

    Assert-eSPSession

    $tasks = Invoke-RestMethod `
        -Uri "$($eschoolSession.Url)/Task/TaskAndReportData?includeTaskCount=true&includeReports=false&maximumNumberOfReports=-1&includeTasks=true&runningTasksOnly=false" `
        -WebSession $eschoolSession.Session | 
        Select-Object -Property RunningTaskCount,ActiveTasks,InactiveTasks

    $erroredTasks = $tasks.ActiveTasks | Where-Object { $PSItem.ErrorOccurred -eq 'True' }

    #Return errored reports.
    if ($ErrorsOnly) {
        return $erroredTasks
    } elseif (-Not($SilentErrors)) {
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
        [Parameter(Mandatory=$false,ParameterSetName="default",ValueFromPipeline=$true)]$Building, #ID of the Building
        [Parameter(Mandatory=$false,ParameterSetName="all")][switch]$InActive,
        [Parameter(Mandatory=$false,ParameterSetName="all")][switch]$Graduated,
        [Parameter(Mandatory=$false,ParameterSetName="all")][switch]$All #Include Graduated and Inactive.
    )

    Assert-eSPSession
    
    $params = @()
    $index = 0

    if ($Building) {
        $params += New-eSPSearchPredicate -index $index -TableName REG -ColumnName BUILDING -Operator Equal -DataType Int -Values $($Building)
        $index++
    }

    if ($InActive) {
        $params += New-eSPSearchPredicate -index $index -TableName REG -ColumnName CURRENT_STATUS -Operator In -DataType Char -Values "I"
        $index++
    } elseif ($Graduated) {
        $params += New-eSPSearchPredicate -index $index -TableName REG -ColumnName CURRENT_STATUS -Operator In -DataType Char -Values "G"
        $index++
    } elseif ($All) {
        $params += New-eSPSearchPredicate -index $index -TableName REG -ColumnName CURRENT_STATUS -Operator In -DataType Char -Values "A,I,G"
        $index++
    } else {
        $params += New-eSPSearchPredicate -index $index -TableName REG -ColumnName CURRENT_STATUS -Operator In -DataType Char -Values "A"
        $index++
    }

    # Here we need to start adding the SearchListField from REGMAINT. See the document in resources (incomplete).
    # New-eSPSearchListField

    return Invoke-eSPExecuteSearch -SearchType REGMAINT -SearchParams $params

}

function New-eSPEmailDefinitions {
    <#

    .SYNOPSIS
    This function will create the Upload and Download Definitions used to fix upload definitions.
    Download Definition : EMLDL,Upload Definition : EMLUP

    #>

    <# 

    Download Definition

    #>

    Param(
        [Parameter(Mandatory=$false)][switch]$Force
    )

    $dd = [ordered]@{
        "IsCopyNew" = "False"
        "NewHeaderNames" = @("") #can not be an empty array.
        "InterfaceHeadersToCopy" = @("") #can not be an empty array.
        "InterfaceToCopyFrom" = @("") #can not be an empty array.
        "CopyHeaders" = "False"
        "PageEditMode" = 0
        "UploadDownloadDefinition" = @{
            "UploadDownload" = "D"
            "DistrictId" = 0
            "InterfaceId" = "EMLDL"
            "Description" = "Automated Student Email Download Definition"
            "UploadDownloadRaw" = "D"
            "ChangeUser" = $null
            "DeleteEntity" = $False
            "InterfaceHeaders" = @(

                [ordered]@{
                    "InterfaceId" = "EMLDL"
                    "HeaderId" = "1"
                    "HeaderOrder" = 1
                    "Description" = "Students Student ID Email and Contact ID"
                    "FileName" = "student_email_download.csv"
                    "LastRunDate" = $null
                    "DelimitChar" = ","
                    "UseChangeFlag" = $False
                    "TableAffected" = "reg_contact"
                    "AdditionalSql" = "INNER JOIN reg_stu_contact ON reg_stu_contact.contact_id = reg_contact.contact_id INNER JOIN reg ON reg.student_id = reg_stu_contact.student_id"
                    "ColumnHeaders" = $True
                    "Delete" = $False
                    "CanDelete" = $True
                    "ColumnHeadersRaw" = "Y"
                    "InterfaceDetails" = @()
                }

            )
        }        
    
    }

    $rows = @(
        @{ table = "reg"; column = "STUDENT_ID"; length = 20 },
        @{ table = "reg_contact"; column = "CONTACT_ID"; length = 20 },
        @{ table = "reg_contact"; column = "EMAIL"; length = 250 },
        @{ table = "reg_stu_contact"; column = "WEB_ACCESS"; length = 1 },
        @{ table = "reg_stu_contact"; column = "CONTACT_PRIORITY"; length = 2 },
        @{ table = "reg_stu_contact"; column = "CONTACT_TYPE"; length = 1 }
    )

    $columns = @()
    $columnNum = 1
    $rows | ForEach-Object {
        $columns += [ordered]@{
            "Edit" = $null
            "InterfaceId" = "EMLDL"
            "HeaderId" = "1"
            "FieldId" = "$columnNum"
            "FieldOrder" = $columnNum
            "TableName" = $PSItem.table
            "TableAlias" = $null
            "ColumnName" = $PSItem.column
            "ScreenType" = $null
            "ScreenNumber" = $null
            "FormatString" = $null
            "StartPosition" = $null
            "EndPosition" = $null
            "FieldLength" = "$($PSItem.length)"
            "ValidationTable" = $null
            "CodeColumn" = $null
            "ValidationList" = $null
            "ErrorMessage" = $null
            "ExternalTable" = $null
            "ExternalColumnIn" = $null
            "ExternalColumnOut" = $null
            "Literal" = $null
            "ColumnOverride" = $null
            "Delete" = $False
            "CanDelete" = $True
            "NewRow" = $True
            "InterfaceTranslations" = @("") #can not be an empty array.
        }
        $columnNum++
    }

    $dd.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails = $columns

    $jsonpayload = $dd | ConvertTo-Json -depth 6

    Write-Verbose ($jsonpayload)
 
    #attempt to delete existing if its there already
    Remove-eSPInterfaceId -InterfaceId "EMLDL"

    $response = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/SaveUploadDownload" `
        -WebSession $eSchoolSession.Session `
        -Method "POST" `
        -ContentType "application/json; charset=UTF-8" `
        -Body $jsonpayload -MaximumRedirection 0

    <#
        Upload Definition
    #>

    $ud = [ordered]@{
        IsCopyNew = "False"
        NewHeaderNames = @("")
        InterfaceHeadersToCopy = @("")
        InterfaceToCopyFrom = @("")
        CopyHeaders = "False"
        PageEditMode = 0
        UploadDownloadDefinition = [ordered]@{
            UploadDownload = "U"
            DistrictId = 0
            InterfaceId = "EMLUP"
            Description = "Automated Student Email Upload Definition"
            UploadDownloadRaw = "U"
            ChangeUser = $null
            DeleteEntity = $False
            InterfaceHeaders = @(
                [ordered]@{
                    InterfaceId = "EMLUP"
                    HeaderId = "1"
                    HeaderOrder = 1
                    Description = "Students Student ID Email and Contact ID"
                    FileName = "student_email_upload.csv"
                    LastRunDate = $null
                    DelimitChar = ","
                    UseChangeFlag = $False
                    TableAffected = "reg_contact"
                    AdditionalSql = $null
                    ColumnHeaders = $True
                    Delete = $False
                    CanDelete = $True
                    ColumnHeadersRaw = "Y"
                    InterfaceDetails = @()
                    AffectedTableObject = [ordered]@{
                        Code = "reg_contact"
                        Description = "Contacts"
                        CodeAndDescription = "reg_contact - Contacts"
                        ActiveRaw = "Y"
                        Active = $True
                    }
                }
            )
        }
    }

    $rows = @(
        @{ table = "reg_contact"; column = "CONTACT_ID"; length = 20 },
        @{ table = "reg_contact"; column = "EMAIL"; length = 250 }
    )

    $columns = @()
    $columnNum = 1
    $rows | ForEach-Object {
        $columns += [ordered]@{
            "Edit" = $null
            "InterfaceId" = "EMLUP"
            "HeaderId" = "1"
            "FieldId" = "$columnNum"
            "FieldOrder" = $columnNum
            "TableName" = $PSItem.table
            "TableAlias" = $null
            "ColumnName" = $PSItem.column
            "ScreenType" = $null
            "ScreenNumber" = $null
            "FormatString" = $null
            "StartPosition" = $null
            "EndPosition" = $null
            "FieldLength" = "$($PSItem.length)"
            "ValidationTable" = $null
            "CodeColumn" = $null
            "ValidationList" = $null
            "ErrorMessage" = $null
            "ExternalTable" = $null
            "ExternalColumnIn" = $null
            "ExternalColumnOut" = $null
            "Literal" = $null
            "ColumnOverride" = $null
            "Delete" = $False
            "CanDelete" = $True
            "NewRow" = $True
            "InterfaceTranslations" = @("") #can not be an empty array.
        }
        $columnNum++
    }

    $ud.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails = $columns

    $jsonpayload = $ud | ConvertTo-Json -depth 6

    Write-Verbose ($jsonpayload)
 
    #attempt to delete existing if its there already
    Remove-eSPInterfaceId -InterfaceId "EMLUP"

    $response2 = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/SaveUploadDownload" `
        -WebSession $eSchoolSession.Session `
        -Method "POST" `
        -ContentType "application/json; charset=UTF-8" `
        -Body $jsonpayload -MaximumRedirection 0


    <#
        Web Access Upload Definition.
    #>

    $wa = @{
        IsCopyNew = "False"
        NewHeaderNames = @("")
        InterfaceHeadersToCopy = @("")
        InterfaceToCopyFrom = @("")
        CopyHeaders = "False"
        PageEditMode = 0
        UploadDownloadDefinition = @{
            UploadDownload = "U"
            DistrictId = 0
            InterfaceId = "EMLAC"
            Description = "Automated Student Web Access Upload Definition"
            UploadDownloadRaw = "U"
            ChangeUser = $null
            DeleteEntity = $False
            InterfaceHeaders = @(
                @{
                    InterfaceId = "EMLAC"
                    HeaderId = "1"
                    HeaderOrder = 1
                    Description = "Students Contact ID and WEB_ACCESS"
                    FileName = "webaccess_upload.csv"
                    LastRunDate = $null
                    DelimitChar = ","
                    UseChangeFlag = $False
                    TableAffected = "reg_stu_contact"
                    AdditionalSql = $null
                    ColumnHeaders = $True
                    Delete = $False
                    CanDelete = $True
                    ColumnHeadersRaw = "Y"
                    InterfaceDetails = @()
                    AffectedTableObject = @{
                        Code = "reg_stu_contact"
                        Description = "Contacts"
                        CodeAndDescription = "reg_stu_contact - Contacts"
                        ActiveRaw = "Y"
                        Active = $True
                    }
                }
            )

        }
    }

    $rows = @(
        @{ table = "reg_stu_contact"; column = "CONTACT_ID"; length = 20 },
        @{ table = "reg_stu_contact"; column = "STUDENT_ID"; length = 20 },
        @{ table = "reg_stu_contact"; column = "WEB_ACCESS"; length = 1 },
        @{ table = "reg_stu_contact"; column = "CONTACT_TYPE"; length = 1 }
    )

    $columns = @()
    $columnNum = 1
    $rows | ForEach-Object {
        $columns += [ordered]@{
            "Edit" = $null
            "InterfaceId" = "EMLAC"
            "HeaderId" = "1"
            "FieldId" = "$columnNum"
            "FieldOrder" = $columnNum
            "TableName" = $PSItem.table
            "TableAlias" = $null
            "ColumnName" = $PSItem.column
            "ScreenType" = $null
            "ScreenNumber" = $null
            "FormatString" = $null
            "StartPosition" = $null
            "EndPosition" = $null
            "FieldLength" = "$($PSItem.length)"
            "ValidationTable" = $null
            "CodeColumn" = $null
            "ValidationList" = $null
            "ErrorMessage" = $null
            "ExternalTable" = $null
            "ExternalColumnIn" = $null
            "ExternalColumnOut" = $null
            "Literal" = $null
            "ColumnOverride" = $null
            "Delete" = $False
            "CanDelete" = $True
            "NewRow" = $True
            "InterfaceTranslations" = @("") #can not be an empty array.
        }
        $columnNum++
    }

    $wa.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails = $columns
    
    $jsonpayload = $wa | ConvertTo-Json -depth 6

    Write-Verbose ($jsonpayload)
 
    #attempt to delete existing if its there already
    Remove-eSPInterfaceId -InterfaceId "EMLAC"

    $response2 = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/SaveUploadDownload" `
        -WebSession $eSchoolSession.Session `
        -Method "POST" `
        -ContentType "application/json; charset=UTF-8" `
        -Body $jsonpayload -MaximumRedirection 0


}

function New-eSPDefinition {
    Param(
        [Parameter(Mandatory=$true)]$Definition
    )

    $jsonpayload = $Definition | ConvertTo-Json -depth 6

    Write-Verbose ($jsonpayload)
 
    #attempt to delete existing if its there already
    Remove-eSPInterfaceId -InterfaceId "$($Definition.UploadDownloadDefinition.InterfaceId)"

    $response = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/SaveUploadDownload" `
        -WebSession $eSchoolSession.Session `
        -Method "POST" `
        -ContentType "application/json; charset=UTF-8" `
        -Body $jsonpayload -MaximumRedirection 0

}

function Remove-eSPInterfaceId {

    Param(
        [parameter(mandatory=$true)]$InterfaceID
    )

    $districtId = Invoke-eSPExecuteSearch -SearchType UPLOADDEF | Select-Object -ExpandProperty district -First 1

    $params = [ordered]@{
        SearchType = "UPLOADDEF"
        Columns = @()
        Deleted = @(
            @{ 
                Keys = @(
                    @{
                        Key = "district"
                        Value = "$districtId"
                    },
                    @{
                        Key = "interface_id"
                        Value = $InterfaceID
                    }
                )
            }
        )
    }

    $jsonPayload = $params | ConvertTo-Json -Depth 6

    Write-Verbose ($jsonPayload)
    
    $response = Invoke-RESTMethod -Uri "$($eSchoolSession.Url)/Search/SaveResults" `
        -WebSession $eSchoolSession.Session `
        -Method "POST" `
        -ContentType "application/json; charset=UTF-8" `
        -Body $jsonpayload -MaximumRedirection 0

}

function Invoke-eSPExecuteSearch {
    <#
    
    .SYNOPSIS
    Execute a Search in eSchool and return structured data.
    
    #>

    Param(
        [parameter(Mandatory=$true)][ValidateSet("REGMAINT","UPLOADDEF","DUPLICATECONTACT")][string]$SearchType,
        [parameter(Mandatory=$false)]$SearchParams,
        [parameter(Mandatory=$false)]$pageSize = 250
    )

    Assert-eSPSession

    $results = [System.Collections.Generic.List[Object]]::new()

    #I have tried actually doing the arrays on the Filter and Predicate but it doesn't convert to x-www-form-urlencoded correctly for the index numbers.
    $params = [ordered]@{
        'loginId' = $eSchoolSession.Username
        'searchType' = $SearchType 
        'searchNumber' = 0
        'runAsUserId' = $eSchoolSession.Username
        'ListFields.LoginId' = $eSchoolSession.Username
        'ListFields.SearchType' = $SearchType
        'ListFields.SearchNumber' = 0
        # 'SortFields.LoginId' = $eSchoolSession.Username
        # 'SortFields.SearchType' = $SearchType
        # 'SortFields.SearchNumber' = 0
        'Filter.LoginId' = $eSchoolSession.Username
        'Filter.SearchType' = $SearchType
        'Filter.SearchNumber' = 0
    }

    if ($searchParams) {
        $SearchParams | ForEach-Object {
            $params = $params + $PSItem
        }
    }

    Write-Verbose ($params | ConvertTo-Json)

    $executeSearch = Invoke-WebRequest -Uri "$($eSchoolSession.Url)/Search/ExecuteSearch" `
    -Method "POST" `
    -WebSession $eSchoolSession.session `
    -ContentType "application/x-www-form-urlencoded; charset=UTF-8" `
    -Body $params
   
    $searchResults = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Search/GetSearchResults?searchType=$($SearchType)&SearchNumber=0" `
        -Method "POST" `
        -WebSession $eSchoolSession.Session `
        -ContentType "application/x-www-form-urlencoded; charset=UTF-8" `
        -Body @{
                '_search' = 'false'
                'nd' = [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                'rows' = $pageSize
                'page' = 1
                'sidx' = $null
                'sord' = "asc"
            }

    $pages = $searchResults.Total
    $rows = $searchResults.records

    Write-Verbose "Total Records: $rows; Total Pages: $pages"

    for ($i = 1; $i -le $pages; $i++) {

        Write-Verbose "Retrieving page $i of $pages"
        Write-Progress -Activity "Retrieving" -Status "$i of $pages" -PercentComplete ([Math]::Floor( (($i / $pages) * 100) ))

        $response = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Search/GetSearchResults?searchType=$($SearchType)&SearchNumber=0" `
            -Method "POST" `
            -WebSession $eSchoolSession.Session `
            -ContentType "application/x-www-form-urlencoded; charset=UTF-8" `
            -Body @{
                '_search' = 'false'
                'nd' = [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                'rows' = $pageSize
                'page' = $i
                'sidx' = $null
                'sord' = "asc"
            }

        $columns = $response.rows | Get-Member | Where-Object { $PSitem.MemberType -eq "NoteProperty" -and $PSitem.Name -like "Column*" } | Select-Object -ExpandProperty Name

        $response.rows | ForEach-Object {

            $row = $PSitem
            $rowObject = [PSCustomObject]@{}

            #for the number of columns we need to add them to a new object.
            $columns | ForEach-Object {
                $Column = $PSitem
                $ColumnName = ($row.$Column).ColumnName ? ($row.$Column).ColumnName : $Column
                $ColumnValue = [System.Web.HttpUtility]::HtmlDecode( (($row.$Column).RawValue).Trim() ) # ? ($PSitem.$Column).RawValue : $null
                $rowObject | Add-Member -NotePropertyName "$($ColumnName)" -NotePropertyValue "$($ColumnValue)" -ErrorAction SilentlyContinue
            }

            $results.Add($rowObject)
        }

    }

    return $results

}

function New-eSPSearchPredicate {

    Param(
        [Parameter(Mandatory=$true)]$index = 0,
        [Parameter(Mandatory=$true)]$TableName,
        [Parameter(Mandatory=$true)]$ColumnName,
        [Parameter(Mandatory=$true)][ValidateSet("Equal","In")]$Operator = 'Equal',
        [Parameter(Mandatory=$true)][ValidateSet("Char","VarChar","Int")]$DataType = "VarChar",
        [Parameter(Mandatory=$true)]$Values
    )

    return [ordered]@{
        "Filter.Predicates[$index].LogicalOperator" = "And"
        "Filter.Predicates[$index].TableName" = $TableName
        "Filter.Predicates[$index].ColumnName" = $ColumnName
        "Filter.Predicates[$index].Operator" = $Operator
        "Filter.Predicates[$index].DataType" = $DataType
        "Filter.Predicates[$index].ScreenType" = ""
        "Filter.Predicates[$index].ScreenNumber" = ""
        "Filter.Predicates[$index].FieldNumber" = ""
        "Filter.Predicates[$index].Values" = $Values
        "Filter.Predicates[$index].ValuesCheckAll" = "false"
    }
}

function New-eSPSearchListField {

    Param(
        [Parameter(Mandatory=$true)]$index = 0,
        [Parameter(Mandatory=$true)]$TableName,
        [Parameter(Mandatory=$true)]$ColumnName
    )

    return [ordered]@{
        "ListFields.Fields[$index].ListFieldIndex" = ($index + 1)
        "ListFields.Fields[$index].TableName" = $TableName
        "ListFields.Fields[$index].ColumnName" = $ColumnName
    }
}

function New-eSPDefinitionTemplate {

    Param(
        [Parameter(Mandatory=$false)][ValidateSet("Download","Upload")]$DefintionType = "Download",
        [Parameter(Mandatory=$true)][ValidateScript( { ($PSitem.Length) -eq 5} )]$InterfaceId,
        [Parameter(Mandatory=$false)]$Description = "eSchoolModule Definition"

    )

    
    $definition = [ordered]@{
        IsCopyNew = "False"
        NewHeaderNames = @("")
        InterfaceHeadersToCopy = @("")
        InterfaceToCopyFrom = @("")
        CopyHeaders = "False"
        PageEditMode = 0
        UploadDownloadDefinition = @{
            UploadDownload = $DefintionType -eq "Download" ? "D" : "U"
            DistrictId = 0
            InterfaceId = $InterfaceId
            Description = $Description
            UploadDownloadRaw = $DefintionType -eq "Download" ? "D" : "U"
            ChangeUser = $null
            DeleteEntity = $False
            InterfaceHeaders = @() #New-eSPInterfaceHeader
        }
    }

    return $definition

}

function New-eSPInterfaceHeader {

    Param(
        [Parameter(Mandatory=$true)][ValidateScript( { ($PSitem.Length) -eq 5} )]$InterfaceId,
        [Parameter(Mandatory=$true)]$HeaderId,
        [Parameter(Mandatory=$true)]$HeaderOrder,
        [Parameter(Mandatory=$false)]$Description,
        [Parameter(Mandatory=$true)]$FileName,
        [Parameter(Mandatory=$true)]$TableName,
        [Parameter(Mandatory=$false)]$AdditionalSql = "",
        [Parameter(Mandatory=$false)]$Delimiter = ","
        # [Parameter(Mandatory=$false)][switch]$UploadDef #if this is an upload definition we need additional information.
    )

    $interfaceHeader = [ordered]@{
        InterfaceId = $InterfaceID
        HeaderId = "$HeaderId"
        HeaderOrder = $HeaderOrder
        Description = $Description
        FileName = $FileName
        LastRunDate = $null
        DelimitChar = $Delimiter
        TableAffected = $TableName
        UseChangeFlag = $False
        AdditionalSql = $AdditionalSql
        ColumnHeaders = $True
        Delete = $False
        CanDelete = $True
        ColumnHeadersRaw = "Y"
        InterfaceDetails = @()
        AffectedTableObject = @{
                Code = $TableName
                Description = $TableName
                CodeAndDescription = $TableName
                ActiveRaw = "Y"
                Active = $True
        }
    }

    # if ($UploadDef) {
    #     $interfaceHeader += [ordered]@{
    #         AffectedTableObject = @{
    #                 Code = $TableName
    #                 Description = $TableName
    #                 CodeAndDescription = $TableName
    #                 ActiveRaw = "Y"
    #                 Active = $True
    #         }
    #     }
    # }

    return $interfaceHeader
}

function New-eSPDefinitionColumn {

    Param(
        [Parameter(Mandatory=$true)]$InterfaceID,
        [Parameter(Mandatory=$true)]$HeaderID,
        [Parameter(Mandatory=$true)][string]$FieldId, #must be a string.
        [Parameter(Mandatory=$true)]$FieldOrder,
        [Parameter(Mandatory=$true)]$TableName,
        [Parameter(Mandatory=$true)]$ColumnName,
        [Parameter(Mandatory=$false)]$FieldLength = 255,
        [Parameter(Mandatory=$false)]$TableAlias = $null
    )

    return [ordered]@{
        "Edit" = $null
        "InterfaceId" = $InterfaceID
        "HeaderId" = $HeaderID
        "FieldId" = "$FieldId"
        "FieldOrder" = $FieldOrder
        "TableName" = $TableName
        "TableAlias" = $null
        "ColumnName" = $ColumnName
        "ScreenType" = $null
        "ScreenNumber" = $null
        "FormatString" = $null
        "StartPosition" = $null
        "EndPosition" = $null
        "FieldLength" = "$FieldLength"
        "ValidationTable" = $null
        "CodeColumn" = $null
        "ValidationList" = $null
        "ErrorMessage" = $null
        "ExternalTable" = $null
        "ExternalColumnIn" = $null
        "ExternalColumnOut" = $null
        "Literal" = $null
        "ColumnOverride" = $null
        "Delete" = $False
        "CanDelete" = $True
        "NewRow" = $True
        "InterfaceTranslations" = @("")
    }
}

function Get-eSPDefinitionsUpdates {

    #ensure the configuration folder exists under this users local home.
    if (-Not(Test-Path "$($HOME)\.config\eSchool")) {
        New-Item "$($HOME)\.config\eSchool" -ItemType Directory -Force
    }

    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AR-k12code/eSchoolModule/main/resources/eSchoolDatabase.csv" -OutFile "$($HOME)\.config\eSchool\eSchoolDatabase.csv"

}

function New-eSPBulkDownloadDefinition {
    Param(
        [parameter(Mandatory=$true)][array]$Tables, #Which tables do you want to create a download definition for.
        [Parameter(Mandatory=$true)][ValidateScript( { ($PSitem.Length) -eq 5} )]$InterfaceId,
        [parameter(Mandatory=$false)][String]$AdditionalSQL = $null, #additional SQL
        [parameter(Mandatory=$false)][Switch]$DoNotLimitSchoolYear, #otherwise all queries are limited to the current school year if the table has the SCHOOL_YEAR in it.
        [parameter(Mandatory=$false)]$delimiter = ',',
        [parameter(Mandatory=$false)][Switch]$Force #overwrite existing.
    )

    Assert-eSPSession

    if ($AdditionalSQL) {
        $sqlspecified = $True
    }

    $eSchoolDatabase = Get-ChildItem "$($HOME)\.config\eSchool\eSchoolDatabase.csv" -File

    if (-Not($eSchoolDatabase)) {
        Write-Error "Missing definitions. They must be downloaded first. Use Get-eSPDefinitionsUpdates first."
        Throw "Missing definitions"
    }

    #Import-CSV ".\resources\eSchool Tables with SCHOOL_YEAR.csv" | Select-Object -ExpandProperty tblName
    $tables_with_years = @("AR_CLASS_DOWN","AR_DOWN_ALE_DAYS","AR_DOWN_ATTEND","AR_DOWN_CAL","AR_DOWN_DISCIPLINE","AR_DOWN_DISTRICT","AR_DOWN_EC","AR_DOWN_EIS1","AR_DOWN_EIS2","AR_DOWN_EMPLOYEE",
    "AR_DOWN_GRADUATE","AR_DOWN_HEARING","AR_DOWN_JOBASSIGN","AR_DOWN_REFERRAL","AR_DOWN_REGISTER","AR_DOWN_SCHL_AGE","AR_DOWN_SCHOOL","AR_DOWN_SCOLIOSIS","AR_DOWN_SE_STAFF","AR_DOWN_STU","AR_DOWN_STU_ID",
    "AR_DOWN_STUDENT_GRADES","AR_DOWN_VISION","ARTB_SE_REFERRAL","ATT_AUDIT_TRAIL","ATT_BOTTOMLINE","ATT_CFG","ATT_CFG_CODES","ATT_CFG_MISS_SUB","ATT_CFG_PERIODS","ATT_CODE","ATT_CODE_BUILDING",
    "ATT_CONFIG_PERCENT","ATT_HRM_SEATING","ATT_INTERVAL","ATT_LOCK_DATE","ATT_NOTIFY_CRIT","ATT_NOTIFY_CRIT_CD","ATT_NOTIFY_CRIT_PD","ATT_NOTIFY_ELIG_CD","ATT_NOTIFY_GROUP","ATT_NOTIFY_LANG",
    "ATT_NOTIFY_STU_DET","ATT_NOTIFY_STU_HDR","ATT_PERIOD","ATT_STU_AT_RISK","ATT_STU_DAY_TOTALS","ATT_STU_ELIGIBLE","ATT_STU_HRM_SEAT","ATT_STU_INT_CRIT","ATT_STU_INT_GROUP","ATT_STU_INT_MEMB",
    "ATT_TWS_TAKEN","ATT_VIEW_ABS","ATT_VIEW_CYC","ATT_VIEW_DET","ATT_VIEW_HDR","ATT_VIEW_INT","ATT_VIEW_MSE_BLDG","ATT_VIEW_PER","ATT_YREND_RUN","COTB_REPORT_PERIOD","CP_STU_FUTURE_REQ",
    "DISC_ACT_USER","DISC_ATT_NOTIFY","DISC_INCIDENT","DISC_LINK_ISSUE","DISC_LTR_CRIT","DISC_LTR_CRIT_ACT","DISC_LTR_CRIT_ELIG","DISC_LTR_CRIT_OFF","DISC_LTR_DETAIL","DISC_LTR_HEADER","DISC_NOTES",
    "DISC_OCCURRENCE","DISC_OFF_ACTION","DISC_OFF_CHARGE","DISC_OFF_CODE","DISC_OFF_CONVICT","DISC_OFF_DRUG","DISC_OFF_FINE","DISC_OFF_SUBCODE","DISC_OFF_WEAPON","DISC_OFFENDER","DISC_PRINT_CITATION",
    "DISC_STU_AT_RISK","DISC_STU_ELIGIBLE","DISC_USER","DISC_VICTIM","DISC_VICTIM_ACTION","DISC_VICTIM_INJURY","DISC_WITNESS","DISC_YEAREND_RUN","FEE_GROUP_CRIT","FEE_GROUP_DET","FEE_GROUP_HDR",
    "FEE_ITEM","FEE_STU_AUDIT","FEE_STU_GROUP","FEE_STU_ITEM","FEE_STU_PAYMENT","FEE_TEXTBOOK","FEE_TEXTBOOK_CRS","FEE_TEXTBOOK_TEA","FEE_YREND_RUN","FEETB_CATEGORY","FEETB_PAYMENT","FEETB_STU_STATUS",
    "FEETB_SUB_CATEGORY","FEETB_UNIT_DESCR","ltdb_group_det","ltdb_group_hdr","LTDB_YEAREND_RUN","MD_ATTENDANCE_DOWN","MD_RUN","MD_SCGT_DOWN","MED_YEAREND_RUN","MR_AVERAGE_CALC","MR_AVERAGE_SETUP",
    "MR_CLASS_SIZE","MR_CREDIT_SETUP","MR_CREDIT_SETUP_AB","MR_CREDIT_SETUP_GD","MR_CREDIT_SETUP_MK","MR_CRSEQU_DET","MR_CRSEQU_HDR","MR_CRSEQU_SETUP","MR_CRSEQU_SETUP_AB","MR_CRSEQU_SETUP_MK",
    "MR_GB_ASMT_STU_COMP_ATTACH","MR_GB_CATEGORY_TYPE_DET","MR_GB_CATEGORY_TYPE_HDR","MR_GB_SCALE","MR_GB_SCALE_DET","MR_HONOR_ELIG_CD","MR_IMPORT_STU_CRS_HDR","MR_IPR_ELIG_CD","MR_IPR_PRINT_HDR",
    "MR_IPR_RUN","MR_IPR_STU_AT_RISK","MR_IPR_STU_ELIGIBLE","MR_IPR_VIEW_ATT","MR_IPR_VIEW_ATT_IT","MR_IPR_VIEW_DET","MR_IPR_VIEW_HDR","MR_MARK_SUBS","MR_PRINT_HDR","MR_RC_STU_AT_RISK","MR_RC_STU_ATT_VIEW",
    "MR_RC_STU_ELIGIBLE","MR_RC_VIEW_ALT_LANG","MR_RC_VIEW_ATT","MR_RC_VIEW_ATT_INT","MR_RC_VIEW_DET","MR_RC_VIEW_GPA","MR_RC_VIEW_GRD_SC","MR_RC_VIEW_HDR","MR_RC_VIEW_HONOR","MR_RC_VIEW_LTDB",
    "MR_RC_VIEW_MPS","MR_RC_VIEW_SC_MP","MR_RC_VIEW_SP","MR_RC_VIEW_SP_COLS","MR_RC_VIEW_SP_MP","MR_RC_VIEW_STUCMP","MR_SC_COMP_COMS","MR_SC_COMP_CRS","MR_SC_COMP_DET","MR_SC_COMP_DET_ALT_LANG",
    "MR_SC_COMP_HDR","MR_SC_COMP_MRKS","MR_SC_COMP_STU","MR_SC_ST_STANDARD","MR_SC_STU_COMMENT","MR_SC_STU_COMP","MR_SC_STU_CRS_COMM","MR_SC_STU_CRS_COMP","MR_SC_STU_TAKEN","MR_SC_STU_TEA",
    "MR_SC_STU_TEA_XREF","MR_SC_STU_TEXT","MR_SC_STUSTU_TAKEN","MR_SC_TEA_COMP","MR_STATE_COURSES","MR_STU_COMMENTS","MR_STU_CRSEQU_ABS","MR_STU_CRSEQU_CRD","MR_STU_CRSEQU_MARK","MR_STU_GPA","MR_STU_HONOR",
    "MR_STU_OUT_COURSE","MR_STU_TEXT","MR_STU_XFER_BLDGS","MR_STU_XFER_RUNS","MR_TRN_PRINT_HDR","MR_TRN_PRT_STU_BRK","MR_TRN_PRT_STU_DET","MR_TX_CREDIT_SETUP","MR_YEAREND_RUN","PP_MONTH_DAYS",
    "PP_STUDENT_CACHE","PP_STUDENT_TEMP","REG_ACT_PREREQ","REG_ACTIVITY_ADV","REG_ACTIVITY_DET","REG_ACTIVITY_ELIG","REG_ACTIVITY_HDR","REG_ACTIVITY_INEL","REG_ACTIVITY_MP","REG_CAL_DAYS",
    "REG_CAL_DAYS_LEARNING_LOC","REG_CALENDAR","REG_CFG","REG_CFG_ALERT","REG_CFG_ALERT_CODE","REG_CFG_ALERT_DEF_CRIT","REG_CFG_ALERT_DEFINED","REG_CFG_ALERT_UDS_CRIT_KTY","REG_CFG_ALERT_UDS_KTY",
    "REG_CFG_ALERT_USER","REG_CFG_EW_APPLY","REG_CFG_EW_COMBO","REG_CFG_EW_COND","REG_CFG_EW_REQ_ENT","REG_CFG_EW_REQ_FLD","REG_CFG_EW_REQ_WD","REG_CFG_EW_REQUIRE","REG_CYCLE","REG_DISTRICT",
    "REG_DURATION","REG_ENTRY_WITH","REG_EVENT_ACTIVITY","REG_GEO_PLAN_AREA","REG_GEO_ZONE_DATES","REG_GEO_ZONE_DET","REG_GEO_ZONE_HDR","REG_MP_DATES","REG_MP_WEEKS","REG_TRACK","REG_USER_PLAN_AREA",
    "REG_YREND_RUN","REG_YREND_RUN_CAL","REG_YREND_RUN_CRIT","REG_YREND_STUDENTS","REGPROG_YREND_RUN","REGPROG_YREND_TABS","REGTB_SCHOOL_YEAR","SCHD_CFG","SCHD_CFG_DISC_OFF","SCHD_CFG_ELEM_AIN",
    "SCHD_CFG_FOCUS_CRT","SCHD_CFG_HOUSETEAM","SCHD_CFG_HRM_AIN","SCHD_CFG_INTERVAL","SCHD_MS","SCHD_MS_SCHEDULE","SCHD_MSB_MEET_HDR","SCHD_PARAMS","SCHD_PARAMS_SORT","SCHD_PERIOD","SCHD_RUN",
    "SCHD_SCAN_REQUEST","SCHD_STU_PREREQOVER","SCHD_STU_RECOMMEND","SCHD_STU_REQ","SCHD_STU_REQ_MP","SCHD_STU_STATUS","SCHD_TIMETABLE","SCHD_TIMETABLE_HDR","SCHD_UNSCANNED","SCHD_YREND_RUN",
    "SEC_USER","SIF_GUID_ATT_CLASS","SIF_GUID_ATT_CODE","SIF_GUID_ATT_DAILY","SIF_GUID_CALENDAR_SUMMARY","SIF_GUID_REG_EW","SIF_GUID_TERM","SPI_CONFIG_EXTENSION_ENVIRONMENT","SSP_YEAREND_RUN",
    "STATE_OCR_BLDG_CFG","STATE_OCR_BLDG_MARK_TYPE","STATE_OCR_BLDG_RET_EXCLUDED_CALENDAR","STATE_OCR_DETAIL","STATE_OCR_DIST_ATT","STATE_OCR_DIST_CFG","STATE_OCR_DIST_COM","STATE_OCR_DIST_DISC",
    "STATE_OCR_DIST_EXP","STATE_OCR_DIST_LTDB_TEST","STATE_OCR_DIST_STU_DISC_XFER","STATE_OCR_NON_STU_DET","STATE_OCR_QUESTION","STATE_OCR_SUMMARY","Statetb_Ocr_Record_types","TAC_ISSUE",
    "TAC_SEAT_HRM_DET","TAC_SEAT_HRM_HDR","TAC_SEAT_PER_DET","TAC_SEAT_PER_HDR")

    $newDefinition = New-espDefinitionTemplate -InterfaceId "$InterfaceId" -Description "Bulk Table Export"
    
    $headerorder = 0
    $tblShortNamesArray = @()

    Import-Csv "$($HOME)\.config\eSchool\eSchoolDatabase.csv" | Where-Object { $tables -contains $PSItem.tblName } | Group-Object -Property tblName | ForEach-Object {
        $tblName = $PSItem.Name
        $sql_table = "LEFT OUTER JOIN (SELECT '#!#' AS 'RC_RUN') AS [spi_checklist_setup_hdr] ON 1=1 " + $AdditionalSQL #pull from global variable so we can modify local variable without pulling it back into the loop.

        #We need to either APPEND or USE the SCHOOL_YEAR if the table has it.
        if (-Not($DoNotLimitSchoolYear) -and ($tables_with_years -contains $tblName)) {
            if ($sqlspecified) {
                $sql_table += " AND SCHOOL_YEAR = (SELECT CASE WHEN MONTH(GetDate()) > 6 THEN YEAR(GetDate()) + 1 ELSE YEAR(GetDate()) END)"
            } else {
                $sql_table = "$($sql_table) WHERE SCHOOL_YEAR = (SELECT CASE WHEN MONTH(GetDate()) > 6 THEN YEAR(GetDate()) + 1 ELSE YEAR(GetDate()) END)"
            }
        }

        #Get the name and generate a shorter name so its somewhat identifiable when getting errors.
        if ($tblName.IndexOf('_') -ge 1) {
            $tblShortName = $tblName[0]
            $tblName | Select-String '_' -AllMatches | Select-Object -ExpandProperty Matches | ForEach-Object {
                $tblShortName += $tblName[$PSItem.Index + 1]
            }
        } else {
            $tblShortName = $tblName
        }

        if ($tblShortName.length -gt 5) {
            $tblShortName = $tblShortName.SubString(0,5)
        }

        #We need to verify we don't already have an interface ID named the same thing. Stupid eSchool and its stupid 5 character limit.
        if ($tblShortNamesArray -contains $tblShortName) {
            $number = 0
            do {
                $number++
                if ($tblShortName.length -ge 5) {
                    $tblShortName = $tblShortName.SubString(0,4) + "$number"
                } else {
                    $tblShortName = $tblShortName + "$number"
                }
            } until ($tblShortNamesArray -notcontains $tblShortName)
        }

        $tblShortNamesArray += $tblShortName

        $ifaceheader = $tblShortName
        $description = $tblName
        $filename = "$($tblName).csv"

        Write-Verbose "$($ifaceheader),$($description),$($filename)"

        $headerorder++

        $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
            -InterfaceId $InterfaceId `
            -HeaderId $ifaceheader `
            -HeaderOrder $headerorder `
            -FileName "$filename" `
            -TableName "$($tblName.ToLower())" `
            -Description "$description" `
            -AdditionalSql "$($sql_table)" `
            -Delimiter $delimiter
    
        $columns = @()
        $columnNum = 1
        $PSItem.Group | ForEach-Object {
            $columns += New-eSPDefinitionColumn `
                -InterfaceId "$InterfaceId" `
                -HeaderId "$ifaceheader" `
                -TableName "$($tblName.ToLower())" `
                -FieldId "$columnNum" `
                -FieldOrder $columnNum `
                -ColumnName $PSItem.colName `
                -FieldLength 255
            $columnNum++
        }

        #add record delimiter
        $columns += [ordered]@{
            "Edit" = $null
            "InterfaceId" = "$InterfaceId"
            "HeaderId" = "$ifaceheader"
            "FieldId" = "99"
            "FieldOrder" = 99
            "TableName" = "spi_checklist_setup_hdr"
            "TableAlias" = $null
            "ColumnName" = "RC_RUN"
            "ScreenType" = $null
            "ScreenNumber" = $null
            "FormatString" = $null
            "StartPosition" = $null
            "EndPosition" = $null
            "FieldLength" = "3"
            "ValidationTable" = $null
            "CodeColumn" = $null
            "ValidationList" = $null
            "ErrorMessage" = $null
            "ExternalTable" = $null
            "ExternalColumnIn" = $null
            "ExternalColumnOut" = $null
            "Literal" = $null
            "ColumnOverride" = '#!#'
            "Delete" = $False
            "CanDelete" = $True
            "NewRow" = $True
            "InterfaceTranslations" = @("")
        }

        #$newDefinition
        $newDefinition.UploadDownloadDefinition.InterfaceHeaders[$headerorder -1].InterfaceDetails = $columns

    }

    $jsonpayload = $newDefinition | ConvertTo-Json -Depth 99

    Write-Verbose ($jsonpayload)

    if ($Force) {
        Remove-eSPInterfaceId -InterfaceId "$InterfaceId"
    }

    $response = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/SaveUploadDownload" `
        -WebSession $eSchoolSession.Session `
        -Method "POST" `
        -ContentType "application/json; charset=UTF-8" `
        -Body $jsonpayload `
        -MaximumRedirection 0

    if ($response.PageState -eq 1) {
        Write-Warning "Download Definition failed."
        return [PSCustomObject]@{
            'Tables' = $tables -join ','
            'Status' = $False
            'Message' = $($response.ValidationErrorMessages)
        }
    } elseif ($response.PageState -eq 2) {
        Write-Host "Download definition created successfully. You can review it here: $($eSchoolSession.Url)/Utility/UploadDownload?interfaceId=$($InterfaceId)" -ForegroundColor Green
        return [PSCustomObject]@{
            'Tables' = $tables -join ','
            'Status' = $True
            'Message' = $response
        }
    } else {
        throw "Failed."
    }
    
}