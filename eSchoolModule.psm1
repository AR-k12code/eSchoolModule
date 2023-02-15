function Update-eSchoolModule {

     <#
        .SYNOPSIS
        Update the eSchoolModule from Github.
    
    #>

    if (-Not $(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Must run as administrator!" -ErrorAction STOP
    }

    $ModulePath = Get-Module eSchoolModule | Select-Object -ExpandProperty ModuleBase

    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AR-k12code/eSchoolModule/master/eSchoolModule.psd1" -OutFile "$($ModulePath)\eSchoolModule.psd1"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AR-k12code/eSchoolModule/master/eSchoolModule.psm1" -OutFile "$($ModulePath)\eSchoolModule.psm1"

    Import-Module eSchoolModule -Force

}

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

    $username = $config.username
    $password = (New-Object pscredential "user",($config.password | ConvertTo-SecureString)).GetNetworkCredential().Password
    
    #Get Verification Token.
    $response = Invoke-WebRequest `
        -Uri "$($baseUrl)/Account/LogOn" `
        -SessionVariable eSchoolSession

    #Login
    $params = @{
        'UserName' = $username
        'Password' = $password
        '__RequestVerificationToken' = $response.InputFields[0].value
    }

    $response2 = Invoke-WebRequest `
        -Uri "$($baseUrl)/Account/LogOn" `
        -WebSession $eSchoolSession `
        -Method POST `
        -Body $params `

    # if (($response2.ParsedHtml.title -eq "Login") -or ($response2.StatusCode -ne 200)) {
    #     Write-Error "Failed to login."
    # }

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

    $response3 = Invoke-WebRequest `
        -Uri "$($baseUrl)/Account/SetEnvironment/SessionStart" `
        -WebSession $eSchoolSession `
        -Method POST `
        -Body $params2 `
        -ContentType "application/x-www-form-urlencoded"

    #verify we set the environment/selected a valid district.
    try {

        $response4 = Invoke-RestMethod `
            -Uri "$($baseUrl)/Task/TaskAndReportData?includeTaskCount=false&includeReports=false&maximumNumberOfReports=1&includeTasks=false&runningTasksOnly=false" `
            -WebSession $eSchoolSession `
            -MaximumRedirection 0

        Write-Host "Connected to eSchool Server $($fields.'ServerName'.value)" -ForegroundColor Green
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
    } catch {
        Write-Error "Failed to Set Environment."
        Throw
    }   
}

function Disconnect-FromeSchool {
    $ignore = Invoke-RestMethod -uri "$($eSchoolSession.url)/Account/LogOff" -WebSession $eSchoolSession.Session -SkipHttpErrorCheck -MaximumRedirection 99
}

function Assert-eSPSession {

    Param(
        [Parameter(Mandatory=$false)][switch]$Force #sometimes we need to reauthenticate. Especially after bulk creation of Download Definitions.
    )

    Try {
        #attempt to see the task list. If this sends us a redirect then we know the session has expired. Try to authenticate again.
        #even if this is null it won't fail.
        $tasks = Invoke-RestMethod -Uri "$($eschoolSession.Url)/Task/TaskAndReportData?includeTaskCount=true&includeReports=false&maximumNumberOfReports=1&includeTasks=true&runningTasksOnly=false" -MaximumRedirection 0 -WebSession $eschoolSession.session

        if ($Force) {
            $params = $eschoolSession.Params
            Connect-ToeSchool @params
        }
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
        [Parameter(Mandatory=$false)][switch]$Raw,
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
        if ($Raw) {
            #from here you can page through the data and convert to an object reasonably.
            $response = Invoke-WebRequest -Uri "$($eschoolSession.Url)/Reports/$($report.ReportPath)" -WebSession $eschoolSession.Session
            return [System.Text.Encoding]::UTF8.GetString($response.Content) 
            # Then you can .Split("`r`n"), Take [0] + [1..25] | ConvertFrom-CSV -Delimiter '^'
            # then [0] + [26..50] | ConvertFrom-Csv -Delimiter '^'
        } elseif ($AsObject) {
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
                    Write-Progress -Activity "Processing $($task.TaskName)" -Status "Ready" -Completed
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
    Return Building Information
    
    .DESCRIPTION
    By default will only return schools with a default calendar assigned.

    #>

    Param(
        [Parameter(Mandatory=$false)][switch]$All
    )

    Assert-eSPSession

    $params = @()

    if (-Not($All)) {
        $params += New-eSPSearchPredicate -index 0 -TableName reg_building -ColumnName calendar -Operator IsNotNull -DataType Char -Values ''
    }

    $FieldListCounter = 0
    @('abbreviation','principal','phone','calendar','state_code_equiv','street1','street2','city','state','zip','name') | ForEach-Object {
        $params += New-eSPSearchListField -index $FieldListCounter -TableName reg_building -ColumnName "$($PSItem)"
        $FieldListCounter++
    }
    
    return Invoke-eSPExecuteSearch -SearchType BUILDINGDEF -SearchParams $params

}

function Get-eSPStudents {

    <#
    
    .SYNOPSIS
    Return information on students.
    
    #>

    [CmdletBinding(DefaultParametersetName="default")]
    Param(
        [Parameter(Mandatory=$false,ParameterSetName="StudentID")][int]$StudentID, #ID of the Building
        [Parameter(Mandatory=$false,ParameterSetName="default")][int]$Building, #ID of the Building
        [Parameter(Mandatory=$false)]
        [ValidateSet('PK','KA','KF','KP','SS','SM','EE','GG','01','02','03','04','05','06','07','08','09','10','11','12')]
        $Grade,
        [Parameter(Mandatory=$false,ParameterSetName="all")][switch]$InActive,
        [Parameter(Mandatory=$false,ParameterSetName="all")][switch]$Graduated,
        [Parameter(Mandatory=$false,ParameterSetName="all")][switch]$All, #Include Graduated and Inactive.
        [Parameter(Mandatory=$false)]$PageSize = 250,
        [Parameter(Mandatory=$false)]
        [ValidateSet("reg_academic","reg_activity_det","reg_user-R-106","reg_contact_phone","reg_contact","reg_user-R-5050","reg_user-R-5070","reg","med_dental","reg_disability","reg_user-R-5020","reg_user-R-5030","reg_user-R-5000","reg_user-R-5040","reg_user-R-105","reg_emergency","reg_entry_with","med_growth","med_hearing","reg_exclude_honor","schd_ms","reg_legal_info","reg_med_alerts","med_notes","med_issued","reg_personal","schd_stu_status","reg_user-R-5090","reg_user-R-102","reg_ethnicity","reg_notes","reg_stu_contact","reg_travel","reg_programs-arses","reg_programs-arell","reg_programs-argt","reg_programs-ar_sa","reg_programs-arrs")]
        $IncludeTables

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

    if ($grade) {
        $params += New-eSPSearchPredicate -index $index -Table REG -ColumnName GRADE -Operator In -DataType Char -Values "$($grade -join ',')"
        $index++
    }

    if ($StudentID) {
        #when searching for a single student ID lets go ahead and add reg_academic.
        $params += New-eSPSearchPredicate -index $index -Table REG -ColumnName STUDENT_ID -Operator Equal -DataType Int -Values $StudentID
        $IncludeTables += @("reg","reg_academic")
    }

    # Here we need to start adding the SearchListField from REGMAINT. See the document in resources (incomplete).
    if ($includeTables) {

        Write-Verbose "Including additional fields from $($includeTables -join ',')"
        
        $index = 0

        $fields = Receive-eSPAdditionalREGMAINTTables | ConvertFrom-CSV | Where-Object { $includeTables -contains $PSitem.table }

        $fields | ForEach-Object {
            $params += New-eSPSearchListField -index $index -TableName $PSitem.table -ColumnName $PSitem.field
            $index++
        }

    }

    return Invoke-eSPExecuteSearch -SearchType REGMAINT -SearchParams $params -PageSize $PageSize

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

    #simple way to get the districtId required to submit removal of a definition.
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
        [parameter(Mandatory=$true)][ValidateSet("REGMAINT","UPLOADDEF","DUPLICATECONTACT","BUILDINGDEF","STAFFCATALOG","MASTERSCHEDULE",'COURSECAT','MPS','CALENDAR','USER')][string]$SearchType,
        [parameter(Mandatory=$false)]$SearchParams,
        [parameter(Mandatory=$false)][int]$pageSize = 250,
        [parameter(Mandatory=$false)][int]$stopAfterPage
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

        if ($stopAfterPage -ge 1 -and $i -gt $stopAfterPage) {
            break
        }

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
                
                #possible overlap of property names like First_name of student and First_name of Contact. change_uid, etc.
                #I'm willing to go 4 layers deep. After that this needs to be reconsidered.
                try {
                    $rowObject | Add-Member -NotePropertyName "$($ColumnName)" -NotePropertyValue "$($ColumnValue)" -ErrorAction Stop
                } catch {
                    try {
                        $rowObject | Add-Member -NotePropertyName "$($ColumnName)2" -NotePropertyValue "$($ColumnValue)" -ErrorAction Stop
                    } catch {
                        try {
                            $rowObject | Add-Member -NotePropertyName "$($ColumnName)3" -NotePropertyValue "$($ColumnValue)" -ErrorAction Stop
                        } catch {
                            $rowObject | Add-Member -NotePropertyName "$($ColumnName)4" -NotePropertyValue "$($ColumnValue)" -ErrorAction SilentlyContinue
                        }
                    }
                }
            }

            $results.Add($rowObject)
        }

    }

    Write-Progress -Activity "Retrieving" -Status "Ready" -Completed
    return $results

}

function New-eSPSearchPredicate {

    Param(
        [Parameter(Mandatory=$true)]$index = 0,
        [Parameter(Mandatory=$true)]$TableName,
        [Parameter(Mandatory=$true)]$ColumnName,
        [Parameter(Mandatory=$true)][ValidateSet("Equal","In",'IsNotNull')]$Operator = 'Equal',
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
        [Parameter(Mandatory=$false)][ValidateSet("Download","Upload")]$DefinitionType = "Download",
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
            UploadDownload = $DefinitionType -eq "Download" ? "D" : "U"
            DistrictId = 0
            InterfaceId = $InterfaceId
            Description = $Description
            UploadDownloadRaw = $DefinitionType -eq "Download" ? "D" : "U"
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
        [parameter(Mandatory=$false)]$Delimiter = ',',
        [parameter(Mandatory=$false)]$Description = "eSchoolModule Bulk Definition",
        [parameter(Mandatory=$false)]$FilePrefix = '', #Make all files start with this. Something like "GUARD_"
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

    $newDefinition = New-espDefinitionTemplate -InterfaceId "$InterfaceId" -Description "$Description"
    
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
            -FileName "$($FilePrefix)$($filename)" `
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
            'Success' = $False
            'Message' = $($response.ValidationErrorMessages)
        }
    } elseif ($response.PageState -eq 2) {
        Write-Host "Download definition created successfully. You can review it here: $($eSchoolSession.Url)/Utility/UploadDownload?interfaceId=$($InterfaceId)" -ForegroundColor Green
        return [PSCustomObject]@{
            'Tables' = $tables -join ','
            'Success' = $True
            'Message' = $response
        }
    } else {
        throw "Failed."
    }
    
}

function Receive-eSPAdditionalREGMAINTTables {
    <#
    
    .SYNOPSIS
    This is a list of the tables, columns, and description.

    .DESCRIPTION
    This needs to be included in the module instead of separate so we aren't looking for a file.
    Recorded from here: /Search/Student?navigateTo=~%2FStudent%2FRegistration%2FStudentSummary
    
    #>
return @'
table,field,description
reg_academic,pending_grad_plan,Pending Grad Plan
reg_academic,change_uid,Change Uid
reg_academic,curriculum,Curriculum
reg_academic,diploma_type,Diploma Type
reg_academic,modeled_grad_plan,Modeled Grad Plan
reg_academic,advisor,Advisor
reg_academic,act_grad_plan,Actual Graduation Plan
reg_academic,elig_expires_date,Eligibility Restriction Date
reg_academic,change_date_time,Change Date Time
reg_academic,federal_grad_year,Federal Grad Year
reg_academic,promotion,Promotion
reg_academic,elig_effective_dte,Eligibility Effective Date
reg_academic,votec,VoTec
reg_academic,graduation_year,Graduation Year
reg_academic,student_id,Student Id
reg_academic,schd_priority,Scheduling Priority
reg_academic,elig_status,Elig Status
reg_academic,rc_hold_override,Rc Hold Override
reg_academic,hold_report_card,Report Card on Hold
reg_academic,elig_reason,Elig Reason
reg_academic,graduation_date,Graduation Date
reg_academic,disciplinarian,Disciplinarian
reg_academic,graduate_req_group,Graduation Req Group
reg_academic,exp_grad_plan,Expected Graduation Plan
reg_activity_det,start_date,Start Date
reg_activity_det,change_uid,Change Uid
reg_activity_det,school_year,School Year
reg_activity_det,duration,Duration
reg_activity_det,override,Override
reg_activity_det,student_id,Student Id
reg_activity_det,end_date,End Date
reg_activity_det,ineligible,Ineligible
reg_activity_det,activity_comment,Activity Comment
reg_activity_det,activity_status,Activity Status
reg_activity_det,activity_code,Activity Code
reg_activity_det,change_date_time,Change Date Time
reg_activity_det,building,Building
reg_user-R-106,field_value-1,Biliteracy Language 1
reg_user-R-106,field_value-2,Achievement Date 1
reg_user-R-106,field_value-3,Biliteracy Language 2
reg_user-R-106,field_value-4,Achievement Date 2
reg_user-R-106,field_value-5,Biliteracy Language 3
reg_user-R-106,field_value-6,Achievement Date 3
reg_user-R-106,field_value-7,Biliteracy Language 4
reg_user-R-106,field_value-8,Achievement Date 4
reg_user-R-106,field_value-1,Biliteracy Language 1
reg_user-R-106,field_value-2,Achievement Date 1
reg_user-R-106,field_value-3,Biliteracy Language 2
reg_user-R-106,field_value-4,Achievement Date 2
reg_user-R-106,field_value-5,Biliteracy Language 3
reg_user-R-106,field_value-6,Achievement Date 3
reg_user-R-106,field_value-7,Biliteracy Language 4
reg_user-R-106,field_value-8,Achievement Date 4
reg_contact_phone,phone_extension,Phone Extension
reg_contact_phone,change_date_time,Change Date Time
reg_contact_phone,sif_refid,Sif Refid
reg_contact_phone,change_uid,Change Uid
reg_contact_phone,phone_type,Phone Type
reg_contact_phone,phone_listing,Phone Listing
reg_contact_phone,phone,Phone
reg_contact_phone,phone_priority,Phone Priority
reg_contact,login_id,Contact Login Id
reg_contact,email_preference,Contact Email Preference
reg_contact,last_name,Contact Last Name
reg_contact,home_building_type,Contact Home Building Type
reg_contact,employer,Contact Employer
reg_contact,street_number,Contact Street Number
reg_contact,city,Contact City
reg_contact,email,Contact Email
reg_contact,apartment,Contact Apartment
reg_contact,salutation,Contact Salutation
reg_contact,home_language,Contact Home Language
reg_contact,street_name,Contact Street Name
reg_contact,education_level,Contact Education Level
reg_contact,generation,Contact Generation
reg_contact,plan_area_number,Contact Plan Area Number
reg_contact,pwd_chg_date_time,Contact Pwd Chg Date Time
reg_contact,chg_pw_next_login,Contact Chg Pw Next Login
reg_contact,middle_name,Contact Middle Name
reg_contact,street_prefix,Contact Street Prefix
reg_contact,onboard_token_used,Onboard Token Used
reg_contact,title,Contact Title
reg_contact,hac_ldap_flag,Contact Hac Ldap Flag
reg_contact,sif_refid,Contact Sif Refid
reg_contact,state,Contact State
reg_contact,key_used,Key Used
reg_contact,first_name,Contact First Name
reg_contact,zip,Contact Zip
reg_contact,acct_locked_date_time,Contact Acct Locked Date Time
reg_contact,use_for_mailing,Contact Use For Mailing
reg_contact,complex,Contact Complex
reg_contact,development,Contact Development
reg_contact,change_uid,Contact Change Uid
reg_contact,street_type,Contact Street Type
reg_contact,language,Contact Language
reg_contact,street_suffix,Contact Street Suffix
reg_contact,change_date_time,Contact Change Date Time
reg_contact,delivery_point,Contact Delivery Point
reg_contact,acct_locked,Contact Acct Locked
reg_contact,last_login_date,Contact Last Login Date
reg_user-R-5050,field_value-1,Entry/Withdrawal
reg_user-R-5050,field_value-2,Birth Date
reg_user-R-5050,field_value-3,Gender
reg_user-R-5050,field_value-4,State ID
reg_user-R-5050,field_value-5,ELL
reg_user-R-5050,field_value-6,Resident LEA
reg_user-R-5070,field_value-1,Service Type
reg_user-R-5070,field_value-2,Other Service
reg_user-R-5070,field_value-3,Begin Date
reg_user-R-5070,field_value-4,End Date
reg,res_county_code,County of Residence
reg,dist_enroll_date,District Enrollment Date
reg,change_uid,Change Uid
reg,calendar,Calendar
reg,nickname,Nickname
reg,first_name,First Name
reg,house_team,House/Team
reg,family_census,Family/Census Number
reg,homeroom_primary,Primary Homeroom
reg,current_status,Current Status
reg,state_res_building,State Building of Residence
reg,last_name,Last Name
reg,middle_name,Middle Name
reg,birthdate,Birth Date
reg,home_district,District of Residence
reg,grade,Grade
reg,state_enroll_date,State Enrollment Date
reg,counselor,Counselor
reg,alt_district,Alternate District
reg,attending_district,Attending District
reg,us_enroll_date,US Enrollment Date
reg,building_reason,Building Reason
reg,grade_9_date,Date Entered Grade 9
reg,building,Building
reg,gender,Gender
reg,summer_status,Summer Status
reg,change_date_time,Change Date Time
reg,generation,Generation
reg,homeroom_secondary,Secondary Homeroom
reg,alt_building,Alternate Building
reg,home_building,Home Building
reg,building_override,Building Override
reg,student_id,Student ID
reg,language,Home Language
reg,alt_bldg_acct,Alt Accountablility Building
reg,native_language,Native Language
med_dental,initials,Initials
med_dental,location,Location
med_dental,test_date,Test Date
med_dental,student_id,Student Id
med_dental,grade,Grade
med_dental,change_uid,Change Uid
med_dental,change_date_time,Change Date Time
med_dental,status,Status
reg_disability,disability_order,Disability Order
reg_disability,end_date,End Date
reg_disability,student_id,Student Id
reg_disability,change_date_time,Change Date Time
reg_disability,sequence_num,Sequence Num
reg_disability,start_date,Start Date
reg_disability,change_uid,Change Uid
reg_disability,disability,Disability
reg_user-R-5020,field_value-1,Anticipated Services Code
reg_user-R-5030,field_value-1,Development Needs Code
reg_user-R-5000,field_value-50,County
reg_user-R-5000,field_value-51,Primary Disability
reg_user-R-5000,field_value-3,Educational Environment
reg_user-R-5000,field_value-52,Referral Date
reg_user-R-5000,field_value-7,Referral Conference Date
reg_user-R-5000,field_value-8,Evaluation Date
reg_user-R-5000,field_value-9,Annual Review Date
reg_user-R-5000,field_value-48,Person Referring
reg_user-R-5000,field_value-10,Entry Assessment Date
reg_user-R-5000,field_value-11,Entry Soc Emtnl Func Score
reg_user-R-5000,field_value-12,Entry Kldg/Skills Func Score
reg_user-R-5000,field_value-13,Entry Self Help Func Score
reg_user-R-5000,field_value-14,Assessment 1 Date
reg_user-R-5000,field_value-15,Assess1 Soc Emtnl Func Score
reg_user-R-5000,field_value-16,Assess1 Soc Emtnl Func Imprv
reg_user-R-5000,field_value-53,Conference LEA
reg_user-R-5000,field_value-17,Assess1 Kldg/Skills Func Score
reg_user-R-5000,field_value-18,Assess1 Kldg/Skills Func Imprv
reg_user-R-5000,field_value-19,Assess1 Self Help Func Score
reg_user-R-5000,field_value-20,Assess1 Self Help Func Imprv
reg_user-R-5000,field_value-21,Assessment 2 Date
reg_user-R-5000,field_value-22,Assess2 Soc Emtnl Func Score
reg_user-R-5000,field_value-23,Assess2 Soc Emtnl Func Imprv
reg_user-R-5000,field_value-24,Assess2 Kldg/Skills Func Score
reg_user-R-5000,field_value-25,Assess2 Kldg/Skills Func Imprv
reg_user-R-5000,field_value-26,Assess2 Self Help Func Score
reg_user-R-5000,field_value-27,Assess2 Self Help Func Imprv
reg_user-R-5000,field_value-28,Exit Assessment Date
reg_user-R-5000,field_value-29,Exit Soc Emtnl Func Score
reg_user-R-5000,field_value-32,Exit Soc Emtnl Func Imprv
reg_user-R-5000,field_value-30,Exit Kldg/Skills Func Score
reg_user-R-5000,field_value-33,Exit Kldg/Skills Func Imprv
reg_user-R-5000,field_value-31,Exit Self Help Func Score
reg_user-R-5000,field_value-34,Exit Self Help Func Imprv
reg_user-R-5000,field_value-35,Placement Date
reg_user-R-5000,field_value-36,Temporary Student
reg_user-R-5000,field_value-37,Agency Name
reg_user-R-5000,field_value-38,Agency City
reg_user-R-5000,field_value-39,Teacher ID
reg_user-R-5000,field_value-40,Speech ID
reg_user-R-5000,field_value-41,Paraprofessional ID
reg_user-R-5000,field_value-42,Other ID
reg_user-R-5000,field_value-43,Program Type
reg_user-R-5000,field_value-44,New Student School Year
reg_user-R-5000,field_value-45,ELL
reg_user-R-5000,field_value-46,Transition Conference Date
reg_user-R-5000,field_value-47,Transition Code
reg_user-R-5000,field_value-1,Entry/Withdrawal
reg_user-R-5000,field_value-2,Transfer
reg_user-R-5000,field_value-49,Resident LEA
reg_user-R-5040,field_value-1,Related Services Code
reg_user-R-105,field_value-1,ELL Entry/Exit
reg_user-R-105,field_value-2,ESL/ELL Waived Date
reg_user-R-105,field_value-3,ESL/ELL Monitored
reg_user-R-105,field_value-4,ELD Program Type
reg_user-R-105,field_value-5,Core Content Access
reg_user-R-105,field_value-6,Recently Arrived EL
reg_emergency,change_date_time,Change Date Time
reg_emergency,insurance_company,Insurance Company
reg_emergency,dentist_phone,Dentist Phone
reg_emergency,insurance_subscr,Subscriber Name
reg_emergency,student_id,Student Id
reg_emergency,dentist_ext,Dentist Ext
reg_emergency,doctor_name,Physician
reg_emergency,insurance_group,Group Number
reg_emergency,insurance_id,Insurance ID Number
reg_emergency,dentist,Dentist
reg_emergency,doctor_phone,Physician Phone
reg_emergency,doctor_extension,Physician Ext
reg_emergency,change_uid,Change Uid
reg_emergency,insurance_grp_name,Group Name
reg_emergency,hospital_code,Hospital Code
reg_entry_with,entry_wd_type,E/W Entry Withdrawal Type
reg_entry_with,calendar,E/W Calendar
reg_entry_with,entry_date,Entry Date
reg_entry_with,school_year,E/W School Year
reg_entry_with,student_id,E/W Student Id
reg_entry_with,grade,E/W Grade
reg_entry_with,entry_code,Entry Code
reg_entry_with,change_date_time,E/W Change Date Time
reg_entry_with,comments,E/W Comments
reg_entry_with,building,E/W Building
reg_entry_with,withdrawal_date,Withdrawal Date
reg_entry_with,withdrawal_code,Withdrawal Code
reg_entry_with,change_uid,E/W Change Uid
med_growth,percent_height,Percent Height
med_growth,bmi,Bmi
med_growth,initials,Initials
med_growth,weight,Weight
med_growth,an_reading,An Reading
med_growth,blood_pressure_sys_an,Blood Pressure Sys An
med_growth,test_date,Test Date
med_growth,change_uid,Change Uid
med_growth,student_id,Student Id
med_growth,percent_weight,Percent Weight
med_growth,blood_pressure_dia_an,Blood Pressure Dia An
med_growth,percent_bmi,Percent Bmi
med_growth,blood_pressure_sys,Blood Pressure Sys
med_growth,blood_pressure_dia,Blood Pressure Dia
med_growth,height,Height
med_growth,grade,Grade
med_growth,change_date_time,Change Date Time
med_growth,location,Location
med_hearing,change_date_time,Change Date Time
med_hearing,grade,Grade
med_hearing,change_uid,Change Uid
med_hearing,location,Location
med_hearing,student_id,Student Id
med_hearing,test_date,Test Date
med_hearing,left_ear,Left Ear
med_hearing,right_ear,Right Ear
med_hearing,initials,Initials
reg_exclude_honor,change_date_time,Change Date Time
reg_exclude_honor,honor_type,Honor Type
reg_exclude_honor,student_id,Student Id
reg_exclude_honor,change_uid,Change Uid
schd_ms,gender_restriction,Gender Restriction
schd_ms,department,Department
schd_ms,block_type,Block Type
schd_ms,track,Track
schd_ms,votec,Votec
schd_ms,fee,Fee
schd_ms,description,Description
schd_ms,maximum_seats,Maximum Seats
schd_ms,lock,Lock
schd_ms,duration_type,Duration Type
schd_ms,classify_num_or_per,Classify Num Or Per
schd_ms,state_crs_equiv,State Crs Equiv
schd_ms,course_section,Course Section
schd_ms,subj_area_credit,Subj Area Credit
schd_ms,nces_code,Nces Code
schd_ms,study_hall,Study Hall
schd_ms,school_year,School Year
schd_ms,summer_school,Summer School
schd_ms,average_type,Average ID
schd_ms,classify_stus_max,Classify Stus Max
schd_ms,course_credit_basis,Course Credit Basis
schd_ms,building,Building
schd_ms,course,Course
schd_ms,category_type,Category Type
schd_ms,change_uid,Change Uid
schd_ms,same_teacher,Same Teacher
schd_ms,change_date_time,Change Date Time
reg_legal_info,legal_middle_name,Legal Middle Name
reg_legal_info,change_uid,Change Uid
reg_legal_info,legal_last_name,Legal Last Name
reg_legal_info,change_reason,Change Reason
reg_legal_info,legal_gender,Legal Gender
reg_legal_info,student_id,Student Id
reg_legal_info,legal_first_name,Legal First Name
reg_legal_info,legal_generation,Legal Generation
reg_legal_info,change_date_time,Change Date Time
reg_med_alerts,med_alert_code,Med Alert Code
reg_med_alerts,end_date,End Date
reg_med_alerts,change_uid,Change Uid
reg_med_alerts,change_date_time,Change Date Time
reg_med_alerts,med_alert_comment,Med Alert Comment
reg_med_alerts,sequence_num,Sequence Num
reg_med_alerts,student_id,Student Id
reg_med_alerts,start_date,Start Date
med_notes,change_uid,Change Uid
med_notes,event_type,Event Type
med_notes,event_date,Event Date
med_notes,change_date_time,Change Date Time
med_notes,student_id,Student Id
med_notes,note,Note
med_issued,dose_number,Dose Number
med_issued,student_id,Student Id
med_issued,event_type,Event Type
med_issued,comment,Comment
med_issued,change_date_time,Change Date Time
med_issued,change_uid,Change Uid
med_issued,initials,Initials
med_issued,issued,Issued
med_issued,med_code,Med Code
reg_personal,at_risk,At Risk
reg_personal,esl,ESL
reg_personal,locker_number,Locker Number
reg_personal,homeless_status,Homeless Status
reg_personal,private_college,Private College
reg_personal,show_alerts,Show Comments
reg_personal,fee_status,Fee Status
reg_personal,private_company,Private Company
reg_personal,previous_id_asof,Previous Id Asof
reg_personal,change_uid,Change Uid
reg_personal,section_504_plan,504 Plan
reg_personal,transfer_bldg_from,Building Transferred From
reg_personal,migrant_id,Migrant ID
reg_personal,ell_years,ELL Years
reg_personal,migrant,Migrant
reg_personal,change_date_time,Change Date Time
reg_personal,meal_status,Meal Status
reg_personal,has_iep,IEP
reg_personal,residency_code,Residency
reg_personal,locker_combination,Locker Combination
reg_personal,birth_state,State of Birth
reg_personal,immigrant,Immigrant
reg_personal,ferpa_phone,FERPA Phone
reg_personal,hispanic,Hispanic/Latino Ethnicity
reg_personal,origin_country,Country of Origin
reg_personal,private_individual,Private Individual
reg_personal,birth_city,City of Birth
reg_personal,student_id,Student Id
reg_personal,state_report_id,State Reporting ID
reg_personal,ssn,Social Security Number
reg_personal,private_military,Private Military
reg_personal,iep_integration,IEPPLUS Integration
reg_personal,ethnic_code,Race
reg_personal,citizen_status,Citizen Status
reg_personal,ferpa_name,FERPA Name
reg_personal,private_organizations,Private Organizations
reg_personal,at_risk_last_calc,At Risk Last Calc
reg_personal,birth_country,Country of Birth
reg_personal,ferpa_photo,FERPA Photo
reg_personal,mother_maiden_name,Mother's Maiden Name
reg_personal,ferpa_address,FERPA Address
reg_personal,classification,Classification
reg_personal,academic_dis,Academically Disadvantaged
reg_personal,iep_status,Iep Status
reg_personal,fed_race_ethnic,Fed Race Ethnic
reg_personal,has_ssp,Has Ssp
reg_personal,previous_id,Previous ID
reg_personal,fee_balance,Fee Balance
reg_personal,at_risk_calc_ovr,At Risk Calc Ovr
reg_personal,fee_status_ovr,Override Fee Status
schd_stu_status,building,Building
schd_stu_status,school_year,School Year
schd_stu_status,request_status,Request Status
schd_stu_status,change_date_time,Change Date Time
schd_stu_status,schedule_status,Schedule Status
schd_stu_status,student_id,Student Id
schd_stu_status,schd_interval,Schd Interval
schd_stu_status,change_uid,Change Uid
reg_user-R-5090,field_value-1,Entry/Withdrawal
reg_user-R-5090,field_value-2,ELL
reg_user-R-5090,field_value-3,Assigned Grade
reg_user-R-5090,field_value-4,Medicaid Eligible
reg_user-R-5090,field_value-5,Medicaid Number
reg_user-R-5090,field_value-6,Alternate Portfolio
reg_user-R-5090,field_value-7,Transfer
reg_user-R-5090,field_value-8,Secondary Trans Date
reg_user-R-5090,field_value-9,Referral Date
reg_user-R-5090,field_value-10,Person Referring
reg_user-R-5090,field_value-11,Last Evaluation Date
reg_user-R-5090,field_value-12,Eligibility Determining Date
reg_user-R-5090,field_value-13,Annual Review Date
reg_user-R-5090,field_value-14,Temporary Student
reg_user-R-5090,field_value-31,School Choice
reg_user-R-5090,field_value-32,School Choice Improvement
reg_user-R-5090,field_value-33,School Choice LEA
reg_user-R-5090,field_value-34,Special Ed Teacher
reg_user-R-5090,field_value-35,Therapist (Speech/Other)
reg_user-R-5090,field_value-16,Primary Disability
reg_user-R-5090,field_value-17,Educational Placement
reg_user-R-5090,field_value-18,Resident LEA
reg_user-R-5090,field_value-19,Name of Provider
reg_user-R-5090,field_value-20,Provider LEA
reg_user-R-5090,field_value-21,Speech
reg_user-R-5090,field_value-22,Date Speech Entered
reg_user-R-5090,field_value-23,Date Speech Terminated
reg_user-R-5090,field_value-24,Edu Placement Last Year
reg_user-R-5090,field_value-25,Time Served Unit
reg_user-R-5090,field_value-26,Time Served Amount
reg_user-R-5090,field_value-27,Extended School YR
reg_user-R-5090,field_value-29,Charter School
reg_user-R-5090,field_value-30,Early Childhood Program
reg_user-R-102,field_value-26,ACT 514 Military Dependent
reg_user-R-102,field_value-27,Oyster ID
reg_user-R-102,field_value-29,ACT 514 Military Branch
reg_user-R-102,field_value-30,Medicaid Permission
reg_user-R-102,field_value-18,Title I Eligible
reg_user-R-102,field_value-23,Form 506
reg_user-R-102,field_value-1,Distance/Miles from School
reg_user-R-102,field_value-3,Birth Certificate Number
reg_user-R-102,field_value-9,Birth Verified
reg_user-R-102,field_value-13,Migrant Record
reg_user-R-102,field_value-14,Medicaid Eligibility
reg_user-R-102,field_value-17,Medicaid Number
reg_user-R-102,field_value-24,Transported
reg_user-R-102,field_value-25,Travel Code
reg_user-R-102,field_value-2,Gifted/Talented
reg_user-R-102,field_value-4,Preschool
reg_user-R-102,field_value-5,ADM Part-Time Percentage
reg_user-R-102,field_value-6,Smartcore Waiver
reg_user-R-102,field_value-7,Facility Name
reg_user-R-102,field_value-8,21st CCLC Program
reg_user-R-102,field_value-10,Supp, Services (Do Not Use)
reg_user-R-102,field_value-11,Consolidated School's LEA
reg_user-R-102,field_value-12,Supp, Provider (Do Not Use)
reg_user-R-102,field_value-15,Displaced District
reg_user-R-102,field_value-16,State of Displaced District
reg_user-R-102,field_value-32,SBHC
reg_user-R-102,field_value-33,AAA Activity
reg_user-R-102,field_value-35,CPR Training
reg_user-R-102,field_value-37,New Student Delivered
reg_user-R-102,field_value-39,Student Instructional Option
reg_user-R-102,field_value-28,Twin
reg_user-R-102,field_value-36,Alternate Pathway
reg_user-R-102,field_value-40,Device Access Source
reg_user-R-102,field_value-31,Unaccompanied Youth
reg_user-R-102,field_value-41,Single Parent
reg_user-R-102,field_value-42,Learning Device
reg_user-R-102,field_value-43,Shared Device
reg_user-R-102,field_value-44,Device Serial Number
reg_user-R-102,field_value-34,Title III Eligible
reg_user-R-102,field_value-38,Internet Access
reg_user-R-102,field_value-45,Internet Type
reg_user-R-102,field_value-46,Internet Performance
reg_user-R-102,field_value-47,Internet Access Barrier
reg_ethnicity,change_date_time,Change Date Time
reg_ethnicity,student_id,Student Id
reg_ethnicity,ethnicity_order,Ethnicity Order
reg_ethnicity,change_uid,Change Uid
reg_ethnicity,percentage,Percentage
reg_ethnicity,ethnic_code,Ethnic Code
reg_notes,student_id,Student Id
reg_notes,appointment_id,Appointment Id
reg_notes,student_alert_type,Student Alert Type
reg_notes,entry_date_time,Entry Date Time
reg_notes,private_flag,Private Flag
reg_notes,note_text,Note Text
reg_notes,change_date_time,Change Date Time
reg_notes,publish_to_web,Publish To Web
reg_notes,sensitive,Sensitive
reg_notes,note_type,Note Type
reg_notes,entry_uid,Entry Uid
reg_notes,change_uid,Change Uid
reg_stu_contact,mail_rc,Mail Rc
reg_stu_contact,cust_guard,Cust Guard
reg_stu_contact,contact_priority,Contact Priority
reg_stu_contact,mail_disc,Mail Disc
reg_stu_contact,mail_att,Mail Att
reg_stu_contact,legal_guard,Legal Guard
reg_stu_contact,mail_med,Mail Med
reg_stu_contact,transport_to,Transport To
reg_stu_contact,mail_fees,Mail Fees
reg_stu_contact,change_date_time,Change Date Time
reg_stu_contact,relation_code,Relation Code
reg_stu_contact,mail_reg,Mail Reg
reg_stu_contact,web_access,Web Access
reg_stu_contact,contact_type,Contact Type
reg_stu_contact,mail_ssp,Mail Ssp
reg_stu_contact,student_id,Student Id
reg_stu_contact,transport_from,Transport From
reg_stu_contact,mail_ipr,Mail Ipr
reg_stu_contact,living_with,Living With
reg_stu_contact,upd_stu_eo_info,Upd Stu Eo Info
reg_stu_contact,change_uid,Change Uid
reg_stu_contact,mail_schd,Mail Schd
reg_stu_contact,comments,Comments
reg_travel,change_date_time,Change Date Time
reg_travel,change_uid,Change Uid
reg_travel,shuttle_stop,Shuttle Stop
reg_travel,travel_type,Travel Type
reg_travel,tuesday,Tuesday
reg_travel,friday,Friday
reg_travel,stop_number,Stop Number
reg_travel,transport_distance,Transport Distance
reg_travel,wednesday,Wednesday
reg_travel,bus_number,Bus Number
reg_travel,start_date,Start Date
reg_travel,student_id,Student Id
reg_travel,travel_trip,Travel Trip
reg_travel,sunday,Sunday
reg_travel,thursday,Thursday
reg_travel,stop_description,Stop Description
reg_travel,saturday,Saturday
reg_travel,stop_time,Stop Time
reg_travel,travel_segment,Travel Segment
reg_travel,travel_direction,Travel Direction
reg_travel,bus_route,Bus Route
reg_travel,monday,Monday
reg_travel,end_date,End Date
reg_programs-arses,start_date-1,Meal Status Start Date
reg_programs-arses,summer_school-1,Meal Status Summer School
reg_programs-arses,program_value-1,Meal Status
reg_programs-arses,end_date-1,Meal Status End Date
reg_programs-arell,start_date-1,ELL Entry/Exit Start Date
reg_programs-arell,summer_school-1,ELL Entry/Exit Summer School
reg_programs-arell,program_value-1,ELL Entry/Exit
reg_programs-arell,end_date-1,ELL Entry/Exit End Date
reg_programs-argt,start_date-1,Gifted/Talented Start Date
reg_programs-argt,summer_school-1,Gifted/Talented Summer School
reg_programs-argt,program_value-1,Gifted/Talented
reg_programs-argt,end_date-1,Gifted/Talented End Date
reg_programs-ar_sa,start_date-1,School Age Program Start Date
reg_programs-ar_sa,summer_school-1,School Age Program Summer School
reg_programs-ar_sa,entry_reason-1,School Age Program Entry Reason
reg_programs-ar_sa,program_value-1,School Age Program
reg_programs-ar_sa,end_date-1,School Age Program End Date
reg_programs-ar_sa,withdrawal_reason-1,School Age Program Withdrawal Reason
reg_programs-arrs,start_date-1,Residency Start Date
reg_programs-arrs,start_date-2,Send/Receive District LEA Start Date
reg_programs-arrs,start_date-3,Send/Receive Building LEA Start Date
reg_programs-arrs,summer_school-1,Residency Summer School
reg_programs-arrs,summer_school-2,Send/Receive District LEA Summer School
reg_programs-arrs,summer_school-3,Send/Receive Building LEA Summer School
reg_programs-arrs,program_value-1,Residency
reg_programs-arrs,program_value-2,Send/Receive District LEA
reg_programs-arrs,program_value-3,Send/Receive Building LEA
reg_programs-arrs,end_date-1,Residency End Date
reg_programs-arrs,end_date-2,Send/Receive District LEA End Date
reg_programs-arrs,end_date-3,Send/Receive Building LEA End Date
'@
}

function Get-eSPStaffCatalog {

    <#
    
    .SYNOPSIS
    Return Staff Catalog Information
    
    #>

    Param(
        [Parameter(Mandatory=$false)][int]$Building
    )

    Assert-eSPSession

    #Fields
    $params = @()
    $index = 0
    @("staff_name","active","house_team","is_advisor","is_teacher","is_primary_bldg","phone","room","homeroom_secondary") | ForEach-Object {
        $params += New-eSPSearchListField -index $index -TableName reg_staff_bldgs -ColumnName $PSitem
        $index++
    }

    @("gender","title_code","fms_department","ssn","staff_id","fms_empl_number","birthdate","fms_location","esp_login_id","login_id","sub_login_id","first_name","last_name","maiden_name","middle_name","staff_state_id","email") | ForEach-Object {
        $params += New-eSPSearchListField -index $index -TableName reg_staff -ColumnName $PSitem
        $index++
    }

    #Filters
    $index = 0
    if ($Building) {
        $params += New-eSPSearchPredicate -index 0 -TableName reg_staff_bldgs -ColumnName building -Operator Equal -DataType Int -Values "$Building"
        $index++
    }

    #otherwise you end up with inactive building assignments. How is that useful?
    $params += New-eSPSearchPredicate -index $index -TableName reg_staff_bldgs -ColumnName active -Operator Equal -DataType Char -Values Y

    $response = Invoke-eSPExecuteSearch -SearchType STAFFCATALOG -SearchParams $params
    
    return $response
}

function Get-eSPMasterSchedule {

    <#
    
    .SYNOPSIS
    Get Master Schedule Information
    
    #>

    Param(
        [Parameter(Mandatory=$false)]$Building,
        [Parameter(Mandatory=$false)]$SectionKey,
        [Parameter(Mandatory=$false)]$StaffID
    )



    $schedules = Invoke-eSPExecuteSearch -SearchType MASTERSCHEDULE

    return $schedules
}

function Get-eSPSecUsers {

    <#
    
    .SYNOPSIS
    Return User Security Accounts
    
    #>

    Param(
        [Parameter(Mandatory=$false)]$Force
    )

    $params = @()
    $params += New-eSPSearchPredicate -index 0 -TableName SEC_USER -ColumnName USER_OR_ROLE -Operator Equal -DataType Char -Values U

    $index = 0
    @("def_building_ovr","role_id") | ForEach-Object {
        $params += New-eSPSearchListField -index $index -TableName sec_user_role -ColumnName $PSItem
        $index++
    }
    
    $("email","department","may_impersonate","teacher_account") | ForEach-Object {
        $params += New-eSPSearchListField -index $index -TableName sec_user -ColumnName $PSItem
        $index++
    }

    $users = Invoke-eSPExecuteSearch -SearchType USER -SearchParams $params

    return $users

}


function Get-eSPSecRoles {

    <#
    
    .SYNOPSIS
    Return Security Roles
    
    #>

    Param(
        [Parameter(Mandatory=$false)]$Force
    )

    $params = @()
    $params += New-eSPSearchPredicate -index 0 -TableName SEC_USER -ColumnName USER_OR_ROLE -Operator Equal -DataType Char -Values R

    $roles = Invoke-eSPExecuteSearch -SearchType USER -SearchParams $params

    return $roles

}

function New-eSPEmailDefinitions {
    <#

    .SYNOPSIS
    This function will create the Upload and Download Definitions used to fix upload definitions.
    Download Definition : EMLDL, Upload Definition : EMLUP,EMLAC

    #>

    <# 

    Download Definition

    #>

    Param(
        [Parameter(Mandatory=$false)][switch]$Force
    )

    Assert-eSPSession

    $newDefinition = New-espDefinitionTemplate -InterfaceId ESMD0 -Description "eSchoolModule - Email Download Definition"

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
        -InterfaceId "ESMD0" `
        -HeaderId 1 `
        -HeaderOrder 1 `
        -FileName "student_email_download.csv" `
        -TableName "reg_contact" `
        -Description "eSchoolModule - Email Download Definition" `
        -AdditionalSql 'INNER JOIN reg_stu_contact ON reg_stu_contact.contact_id = reg_contact.contact_id INNER JOIN reg ON reg.student_id = reg_stu_contact.student_id'
        
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
        $columns += New-eSPDefinitionColumn -InterfaceID 'ESMD0' -HeaderID 1 -TableName $($PSitem.table) -FieldId $columnNum -FieldOrder $columnNum -ColumnName $($PSitem.column) -FieldLength $($PSItem.length)
        $columnNum++
    }

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails = $columns

    $jsonpayload = $newDefinition | ConvertTo-Json -depth 6

    Write-Verbose ($jsonpayload)
 
    #attempt to delete existing if its there already
    Remove-eSPInterfaceId -InterfaceId "ESMD0"

    $response = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/SaveUploadDownload" `
        -WebSession $eSchoolSession.Session `
        -Method "POST" `
        -ContentType "application/json; charset=UTF-8" `
        -Body $jsonpayload -MaximumRedirection 0

    <#
        Upload Definition
    #>

    $newDefinition = New-espDefinitionTemplate -InterfaceId ESMU0 -Description "eSchoolModule - Email Upload Definition" -DefinitionType Upload

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
        -InterfaceId "ESMU0" `
        -HeaderId 1 `
        -HeaderOrder 1 `
        -FileName "student_email_upload.csv" `
        -TableName "reg_contact" `
        -Description "Automated Student Email Upload Definition"
        
    $rows = @(
        @{ table = "reg_contact"; column = "CONTACT_ID"; length = 20 },
        @{ table = "reg_contact"; column = "EMAIL"; length = 250 }
    )

    $columns = @()
    $columnNum = 1
    $rows | ForEach-Object {
        $columns += New-eSPDefinitionColumn -InterfaceID 'ESMU0' -HeaderID 1 -TableName $($PSitem.table) -FieldId $columnNum -FieldOrder $columnNum -ColumnName $($PSitem.column) -FieldLength $($PSItem.length)
        $columnNum++
    }

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails = $columns

    $jsonpayload = $newDefinition | ConvertTo-Json -depth 6

    Write-Verbose ($jsonpayload)
 
    #attempt to delete existing if its there already
    Remove-eSPInterfaceId -InterfaceId "ESMU0"

    $response2 = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/SaveUploadDownload" `
        -WebSession $eSchoolSession.Session `
        -Method "POST" `
        -ContentType "application/json; charset=UTF-8" `
        -Body $jsonpayload -MaximumRedirection 0


    <#
        Web Access Upload Definition.
    #>

    $newDefinition = New-espDefinitionTemplate -InterfaceId ESMU1 -Description "eSchoolModule - Web Access Upload Definition" -DefinitionType Upload

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
        -InterfaceId "ESMU1" `
        -HeaderId 1 `
        -HeaderOrder 1 `
        -FileName "webaccess_upload.csv" `
        -TableName "reg_stu_contact" `
        -Description "Automated Student Web Access Upload Definition"
    
    $rows = @(
        @{ table = "reg_stu_contact"; column = "CONTACT_ID"; length = 20 },
        @{ table = "reg_stu_contact"; column = "STUDENT_ID"; length = 20 },
        @{ table = "reg_stu_contact"; column = "WEB_ACCESS"; length = 1 },
        @{ table = "reg_stu_contact"; column = "CONTACT_TYPE"; length = 1 }
    )

    $columns = @()
    $columnNum = 1
    $rows | ForEach-Object {
        $columns += New-eSPDefinitionColumn -InterfaceID 'ESMU1' -HeaderID 1 -TableName $($PSitem.table) -FieldId $columnNum -FieldOrder $columnNum -ColumnName $($PSitem.column) -FieldLength $($PSItem.length)
        $columnNum++
    }

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails = $columns
    
    $jsonpayload = $newDefinition | ConvertTo-Json -depth 6

    Write-Verbose ($jsonpayload)
 
    #attempt to delete existing if its there already
    Remove-eSPInterfaceId -InterfaceId "ESMU1"

    $response2 = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/SaveUploadDownload" `
        -WebSession $eSchoolSession.Session `
        -Method "POST" `
        -ContentType "application/json; charset=UTF-8" `
        -Body $jsonpayload -MaximumRedirection 0


}

function New-eSPGuardianDefinitions {

    <#
    
    .SYNOPSIS
    Create the Upload/Download definitions required to dedupe Guardians.
    
    #>

    Assert-eSPSession

    #bulk download the 4 tables needed.
    New-eSPBulkDownloadDefinition `
        -Tables @("REG","REG_STU_CONTACT","REG_CONTACT","REG_CONTACT_PHONE") `
        -InterfaceId "ESMD1" `
        -DoNotLimitSchoolYear `
        -Delimiter '|' `
        -Description "eSchoolModule - Guardian Duplication Data" `
        -FilePrefix "GUARD_" `
        -Force

    $newDefinition = New-eSPDefinitionTemplate `
        -DefinitionType Upload `
        -InterfaceId "ESMU2" `
        -Description "eSchoolModule - Move Duplicate Guardian Priority"

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
        -InterfaceId "ESMU2" `
        -HeaderId 1 `
        -HeaderOrder 1 `
        -FileName "duplicate_guardians_to_99.csv" `
        -TableName "reg_stu_contact" `
        -Description "eSchoolModule - Move Duplicate Guardian Priority"

    $index = 1
    @("CONTACT_ID","STUDENT_ID","CONTACT_PRIORITY","CONTACT_TYPE") | ForEach-Object {
        $newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails +=	New-eSPDefinitionColumn `
            -InterfaceId "ESMU2" `
            -HeaderId 1 `
            -TableName "reg_stu_contact" `
            -FieldId $index `
            -FieldOrder $index `
            -ColumnName "$PSitem" `
            -FieldLength 255
        $index++
    }
    
    #Upload Existing Contacts in the Place of the Duplicate.
    New-eSPDefinition -Definition $newDefinition

    $newDefinition = New-eSPDefinitionTemplate `
        -DefinitionType Upload `
        -InterfaceId "ESMU3" `
        -Description "eSchoolModule - Connect Duplicate Guardians"

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
        -InterfaceId "ESMU3" `
        -HeaderId 1 `
        -HeaderOrder 1 `
        -FileName "duplicate_guardians_fix.csv" `
        -TableName "reg_stu_contact" `
        -Description "eSchoolModule - Connect Duplicate Guardians"

    $index = 1
    @("CONTACT_ID","COMMENTS","CONTACT_PRIORITY","CONTACT_TYPE","CUST_GUARD","DISTRICT","LEGAL_GUARD","LIVING_WITH","MAIL_ATT","MAIL_DISC","MAIL_FEES","MAIL_IPR","MAIL_MED","MAIL_RC","MAIL_REG","MAIL_SCHD","MAIL_SSP","RELATION_CODE","STUDENT_ID","TRANSPORT_FROM","TRANSPORT_TO","UPD_STU_EO_INFO","WEB_ACCESS") | ForEach-Object {
        $newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails +=	New-eSPDefinitionColumn `
            -InterfaceId "ESMU3" `
            -HeaderId 1 `
            -TableName "reg_stu_contact" `
            -FieldId $index `
            -FieldOrder $index `
            -ColumnName "$PSitem" `
            -FieldLength 255
        $index++
    }
    
    New-eSPDefinition -Definition $newDefinition

    #Since we are trying to merge records we should also create an upload definition for Phone Numbers.
    
    New-eSPDefinition -Definition $newDefinition

    $newDefinition = New-eSPDefinitionTemplate `
        -DefinitionType Upload `
        -InterfaceId "ESMU4" `
        -Description "eSchoolModule - Merge Duplicate Guardian Phone Numbers"

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
        -InterfaceId "ESMU4" `
        -HeaderId 1 `
        -HeaderOrder 1 `
        -FileName "duplicate_guardian_phone_numbers.csv" `
        -TableName "reg_contact_phone" `
        -Description "eSchoolModule - Merge Duplicate Guardian Phone Numbers"

    $index = 1
    @("CONTACT_ID","DISTRICT","PHONE","PHONE_EXTENSION","PHONE_LISTING","PHONE_PRIORITY","PHONE_TYPE","SIF_REFID") | ForEach-Object {
        $newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails +=	New-eSPDefinitionColumn `
            -InterfaceId "ESMU4" `
            -HeaderId 1 `
            -TableName "reg_contact_phone" `
            -FieldId $index `
            -FieldOrder $index `
            -ColumnName "$PSitem" `
            -FieldLength 255
        $index++
    }
    
    New-eSPDefinition -Definition $newDefinition
}
