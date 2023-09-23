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
        $baseUrl = "https://eschool23.esp.k12.ar.us/eSchoolPLUS"
    }

    $username = $config.username
    $password = (New-Object pscredential "user",($config.password | ConvertTo-SecureString)).GetNetworkCredential().Password
    
    Write-Verbose "$($baseUrl)/Account/LogOn"

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

    Write-Verbose "$($baseUrl)/Account/SetEnvironment/SessionStart"

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
            Server = $($fields.'ServerName'.value)
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
        [Parameter(Mandatory=$true,ParameterSetName="FileName",ValueFromPipelineByPropertyName=$true)][Alias('RawFileName')][string]$FileName, #Download an exact named file.
        [Parameter(Mandatory=$true,ParameterSetName="NameLike")][string]$NameLike, #Download the latest file that matches. Example would be HomeAccessPasswords* where there are possibly hundreds of unknown files.
        [Parameter(Mandatory=$false)][string]$OutFile,
        [Parameter(Mandatory=$false)][switch]$AsObject,
        [Parameter(Mandatory=$false)][switch]$Raw,
        [Parameter(Mandatory=$false)][string]$Delimeter = ',' #This could be Pipe or whatever the eSchool Definition uses.
    )

    Begin {
        Assert-eSPSession

        $latestFileList = Get-eSPFileList
    }

    Process {

        if ($FileName) {
            $report = $latestFileList | Where-Object { $PSItem.RawFileName -eq "$($FileName)" }
        } else {
            $report = $latestFileList | Where-Object { $PSitem.RawFileName -LIKE "$($NameLike)*" } | Select-Object -First 1
        }

        if (-Not($OutFile)) {
            $OutFile = $($report.RawFileName)
        }

        Write-Verbose ("$($eschoolSession.Url)/ReportViewer/FileStream?fileName=$($report.RawFileName)")

        try {  
            if ($Raw) {
                #from here you can page through the data and convert to an object reasonably.
                $response = Invoke-WebRequest -Uri "$($eschoolSession.Url)/ReportViewer/FileStream?fileName=$($report.RawFileName)" -WebSession $eschoolSession.Session
                
                #Encoding.CodePage is not returned with the response from eSchool. You must use 1252 instead of UTF8.
                switch ($response.Headers['Content-Type']) {
                    'text/plain' { return $response.Content }
                    'application/octet-stream' { return [System.Text.Encoding]::GetEncoding(1252).GetString($response.Content) }
                    'application/pdf' { Throw "PDF files are not supported as raw." }
                    default { Throw "Unrecognized content-type. $($response.Headers['Content-Type'])" }
                }

                # Then you can .Split("`r`n"), Take [0] + [1..25] | ConvertFrom-CSV -Delimiter '^'
                # then [0] + [26..50] | ConvertFrom-Csv -Delimiter '^'
            } elseif ($AsObject) {
                $response = Invoke-WebRequest -Uri "$($eschoolSession.Url)/ReportViewer/FileStream?fileName=$($report.RawFileName)" -WebSession $eschoolSession.Session
                return [System.Text.Encoding]::GetEncoding(1252).GetString($response.Content) | ConvertFrom-CSV -Delimiter $Delimeter
            } else {
                Invoke-WebRequest -Uri "$($eschoolSession.Url)/ReportViewer/FileStream?fileName=$($report.RawFileName)" -WebSession $eschoolSession.Session -OutFile $OutFile
            }
        } catch {
            Throw "$PSItem"
        }

        return [PSCustomObject]@{
            Name = $($report.RawFileName)
            Path = Get-ChildItem $OutFile
        }
    }

}

function Submit-eSPFile {
    <#
    .SYNOPSIS
    Upload File to eSchool
    
    #>

    Param(
        [parameter(Mandatory=$true,HelpMessage="File Path",Position=0)]$InFile
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

function Remove-eSPFile {

    <#
    
    .SYNOPSIS
    Delete a file from the user directory.
    
    #>

    Param(
        [Parameter(Mandatory=$true,Position=0)][string]$FileName
    )

    Assert-eSPSession

    $response = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Task/DeleteTasksAndReports" `
        -Method "POST" `
        -WebSession $eSchoolSession.session `
        -ContentType "application/json; charset=UTF-8" `
        -Body "{`"reportsToDelete`":[`"$($FileName)`"],`"tasksToDelete`":[]}"

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

    #All Arkansas Servers are Central Time. This will ensure that all date comparisons are compared to Central Time.
    $dateTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date), 'Central Standard Time')

    $params = [ordered]@{
        'SearchType' = 'download_filter'
        'SortType' = ''
        'InterfaceId' = $InterfaceID
        'StartDate' = '07/01/2019'
        'ImportDirectory' = 'UD'
        'TxtImportDirectory' = ''
        'TaskScheduler.CurrentTask.Classname' = 'LTDB21_4.CRunDownload'
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

    $dateTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date), 'Central Standard Time')

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
        'TaskScheduler.CurrentTask.Classname' = 'LTDB21_4.CRunUpload'
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
        'TaskScheduler.CurrentTask.ScheduledTimeTime' = $dateTime.ToString("hh:mm tt") #Set forward 1 minute(s) "03:45 PM"
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

    # $eSchoolDatabase = Get-ChildItem "$($HOME)\.config\eSchool\eSchoolDatabase.csv" -File

    # if (-Not($eSchoolDatabase)) {
    #     Write-Error "Missing definitions. They must be downloaded first. Use Get-eSPDefinitionsUpdates first."
    #     Throw "Missing definitions"
    # }

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

    Receive-eSPBulkDefitionFields | ConvertFrom-CSV | Where-Object { $tables -contains $PSItem.tblName } | Group-Object -Property tblName | ForEach-Object {
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
    Download Definition : ESMD0, Upload Definition : ESMU0,ESMU1

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

function New-eSPHACUploadDefinition {
    <#

    .SYNOPSIS
    This function will create the Upload and Download Definitions used to fix HAC usernames.
    
    #>
    
    Param(
        [Parameter(Mandatory=$false)][switch]$Force
    )

    Assert-eSPSession

    <#
        Upload Definition
    #>

    $newDefinition = New-espDefinitionTemplate -InterfaceId ESMU5 -Description "eSchoolModule - HAC LoginID" -DefinitionType Upload

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
        -InterfaceId "ESMU5" `
        -HeaderId 1 `
        -HeaderOrder 1 `
        -FileName "hac_loginids.csv" `
        -TableName "reg_contact" `
        -Description "HAC Login IDs Upload Definition"
        
    $rows = @(
        @{ table = "reg_contact"; column = "CONTACT_ID"; length = 20 },
        @{ table = "reg_contact"; column = "LOGIN_ID"; length = 250 }
    )

    $columns = @()
    $columnNum = 1
    $rows | ForEach-Object {
        $columns += New-eSPDefinitionColumn -InterfaceID 'ESMU5' -HeaderID 1 -TableName $($PSitem.table) -FieldId $columnNum -FieldOrder $columnNum -ColumnName $($PSitem.column) -FieldLength $($PSItem.length)
        $columnNum++
    }

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails = $columns

    $jsonpayload = $newDefinition | ConvertTo-Json -depth 6

    Write-Verbose ($jsonpayload)
 
    #attempt to delete existing if its there already
    Remove-eSPInterfaceId -InterfaceId "ESMU5"

    $response2 = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/SaveUploadDownload" `
        -WebSession $eSchoolSession.Session `
        -Method "POST" `
        -ContentType "application/json; charset=UTF-8" `
        -Body $jsonpayload -MaximumRedirection 0

}

function New-eSPAttUploadDefinitions {

    <#
    
    .SYNOPSIS
    Create the upload definitions required to upload attendance.
    
    #>

    Assert-eSPSession

    $newDefinition = New-eSPDefinitionTemplate `
        -DefinitionType Upload `
        -InterfaceId "ESMU6" `
        -Description "eSchoolModule - Upload Attendance"

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
        -InterfaceId "ESMU6" `
        -HeaderId 1 `
        -HeaderOrder 1 `
        -FileName "attendance_upload.csv" `
        -TableName "att_bottomline" `
        -Description "eSchoolModule - ATT_BOTTOMLINE"

    $index = 1
    @("STUDENT_ID","BUILDING","ATTENDANCE_CODE","ATTENDANCE_DATE","ATTENDANCE_PERIOD","ATT_COMMENT","SCHOOL_YEAR","SOURCE","SEQUENCE_NUM","SUMMER_SCHOOL","MINUTES_ABSENT") | ForEach-Object {
        $newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails +=	New-eSPDefinitionColumn `
            -InterfaceId "ESMU6" `
            -HeaderId 1 `
            -TableName "att_bottomline" `
            -FieldId $index `
            -FieldOrder $index `
            -ColumnName "$PSitem" `
            -FieldLength 255
        $index++
    }

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
        -InterfaceId "ESMU6" `
        -HeaderId 2 `
        -HeaderOrder 2 `
        -FileName "attendance_upload.csv" `
        -TableName "att_audit_trail" `
        -Description "eSchoolModule - ATT_AUDIT_TRAIL"

    $index = 1
    @("STUDENT_ID","BUILDING","ATTENDANCE_CODE","ATTENDANCE_DATE","ATTENDANCE_PERIOD","ATT_COMMENT","SCHOOL_YEAR","SOURCE","SEQUENCE_NUM","SUMMER_SCHOOL","MINUTES_ABSENT","ENTRY_DATE_TIME","ENTRY_USER","ENTRY_ORDER_NUM","BOTTOMLINE") | ForEach-Object {
        $newDefinition.UploadDownloadDefinition.InterfaceHeaders[1].InterfaceDetails +=	New-eSPDefinitionColumn `
            -InterfaceId "ESMU6" `
            -HeaderId 2 `
            -TableName "att_audit_trail" `
            -FieldId $index `
            -FieldOrder $index `
            -ColumnName "$PSitem" `
            -FieldLength 255
        $index++
    }
    
    #Upload Existing Contacts in the Place of the Duplicate.
    New-eSPDefinition -Definition $newDefinition -Verbose

}

function New-eSPMealStatusDefinitions {
<#
    .SYNOPSIS
    This will create the definitions ESMD2 and ESMU7 for the Meal Status Upload/Download.

    .DESCRIPTION
    
#>

$newDefinition = New-eSPDefinitionTemplate `
    -DefinitionType Download `
    -InterfaceId "ESMD2" `
    -Description "eSchoolModule - Meal Status"

$newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
    -InterfaceId "ESMD2" `
    -HeaderId 1 `
    -HeaderOrder 1 `
    -FileName "esp_meal_status.csv" `
    -TableName "reg_programs" `
    -Description "eSchoolModule - Meal Status" `
    -AdditionalSQL 'LEFT JOIN REG ON REG_PROGRAMS.STUDENT_ID = REG.STUDENT_ID WHERE REG_PROGRAMS.PROGRAM_ID = ''ARSES'' AND REG.CURRENT_STATUS = ''A'' AND REG_PROGRAMS.START_DATE > DATEADD(year, -2, GETDATE())'

$index = 1
@("DISTRICT","PROGRAM_ID","FIELD_NUMBER","STUDENT_ID","START_DATE","SUMMER_SCHOOL","ENTRY_REASON","PROGRAM_VALUE","END_DATE","WITHDRAWAL_REASON","PROGRAM_OVERRIDE","CHANGE_DATE_TIME","CHANGE_UID") | ForEach-Object {
    $newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails +=	New-eSPDefinitionColumn `
        -InterfaceId "ESMD2" `
        -HeaderId 1 `
        -TableName "reg_programs" `
        -FieldId $index `
        -FieldOrder $index `
        -ColumnName "$PSitem" `
        -FieldLength 255
    $index++
}

New-eSPDefinition -Definition $newDefinition -Verbose


#Upload Definition
$newDefinition = New-eSPDefinitionTemplate -InterfaceId ESMU7 -Description "eSchoolModule - Upload Meal Status" -DefinitionType Upload

$newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
    -InterfaceId "ESMU7" `
    -HeaderId 1 `
    -HeaderOrder 1 `
    -FileName "meal_status_upload.csv" `
    -TableName "reg_programs" `
    -Description "Meal Status Upload"

    $rows = @(
        @{ table = "reg_programs"; column = "STUDENT_ID"; length = 10 },
        @{ table = "reg_programs"; column = "PROGRAM_ID"; length = 5 },
        @{ table = "reg_programs"; column = "PROGRAM_VALUE"; length = 2 },
        @{ table = "reg_programs"; column = "FIELD_NUMBER"; length = 1 },
        @{ table = "reg_programs"; column = "START_DATE"; length = 10 },
        @{ table = "reg_programs"; column = "END_DATE"; length = 10 },
        @{ table = "reg_programs"; column = "SUMMER_SCHOOL"; length = 1 },
        @{ table = "reg_programs"; column = "PROGRAM_OVERRIDE"; length = 1 }
    )

    $columns = @()
    $columnNum = 1
    $rows | ForEach-Object {
        $columns += New-eSPDefinitionColumn -InterfaceID 'ESMU7' -HeaderID 1 -TableName $($PSitem.table) -FieldId $columnNum -FieldOrder $columnNum -ColumnName $($PSitem.column) -FieldLength $($PSItem.length)
        $columnNum++
    }

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails = $columns

New-eSPDefinition -Definition $newDefinition

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

function Receive-eSPBulkDefitionFields {

return @'
tblName,colName,Active
schd_ms_house_team,DISTRICT,True
schd_ms_house_team,SECTION_KEY,True
schd_ms_house_team,HOUSE_TEAM,True
schd_ms_house_team,CHANGE_DATE_TIME,True
schd_ms_house_team,CHANGE_UID,True
schd_ms_cycle,DISTRICT,True
schd_ms_cycle,SECTION_KEY,True
schd_ms_cycle,COURSE_SESSION,True
schd_ms_cycle,CYCLE_CODE,True
schd_ms_cycle,CHANGE_DATE_TIME,True
schd_ms_cycle,CHANGE_UID,True
schd_ms_block,DISTRICT,True
schd_ms_block,BLOCK_SECTION,True
schd_ms_block,COURSE,True
schd_ms_block,BLOCKETTE_SECTION,True
schd_ms_block,MANDATORY,True
schd_ms_block,CHANGE_DATE_TIME,True
schd_ms_block,CHANGE_UID,True
schd_ms_bldg_type,DISTRICT,True
schd_ms_bldg_type,SECTION_KEY,True
schd_ms_bldg_type,COURSE_SESSION,True
schd_ms_bldg_type,BLDG_TYPE,True
schd_ms_bldg_type,CHANGE_DATE_TIME,True
schd_ms_bldg_type,CHANGE_UID,True
schd_ms,DISTRICT,True
schd_ms,SCHOOL_YEAR,True
schd_ms,SUMMER_SCHOOL,True
schd_ms,BUILDING,True
schd_ms,COURSE,True
schd_ms,COURSE_SECTION,True
schd_ms,SECTION_KEY,True
schd_ms,DESCRIPTION,True
schd_ms,STUDY_HALL,True
schd_ms,MAXIMUM_SEATS,True
schd_ms,DEPARTMENT,True
schd_ms,VOTEC,True
schd_ms,FEE,True
schd_ms,GENDER_RESTRICTION,True
schd_ms,BLOCK_TYPE,True
schd_ms,TRACK,True
schd_ms,DURATION_TYPE,True
schd_ms,SUBJ_AREA_CREDIT,True
schd_ms,AVERAGE_TYPE,True
schd_ms,STATE_CRS_EQUIV,True
schd_ms,SAME_TEACHER,True
schd_ms,LOCK,True
schd_ms,COURSE_CREDIT_BASIS,True
schd_ms,NCES_CODE,True
schd_ms,CATEGORY_TYPE,True
schd_ms,CLASSIFY_STUS_MAX,True
schd_ms,CLASSIFY_NUM_OR_PER,True
schd_ms,ROW_IDENTITY,True
schd_ms,CHANGE_DATE_TIME,True
schd_ms,CHANGE_UID,True
schd_ms_gpa,DISTRICT,True
schd_ms_gpa,SECTION_KEY,True
schd_ms_gpa,COURSE_SESSION,True
schd_ms_gpa,GPA_TYPE,True
schd_ms_gpa,GPA_LEVEL,True
schd_ms_gpa,CHANGE_DATE_TIME,True
schd_ms_gpa,CHANGE_UID,True
schd_distcrs_sections_override,DISTRICT,True
schd_distcrs_sections_override,BUILDING,True
schd_distcrs_sections_override,COURSE,True
schd_distcrs_sections_override,PAGE_SECTION,True
schd_distcrs_sections_override,BLDG_OVERRIDDEN,True
schd_distcrs_sections_override,CHANGE_DATE_TIME,True
schd_distcrs_sections_override,CHANGE_UID,True
schd_distcrs_bldg_types,DISTRICT,True
schd_distcrs_bldg_types,BUILDING,True
schd_distcrs_bldg_types,COURSE,True
schd_distcrs_bldg_types,BUILDING_TYPE,True
schd_distcrs_bldg_types,ACTIVE,True
schd_distcrs_bldg_types,CHANGE_DATE_TIME,True
schd_distcrs_bldg_types,CHANGE_UID,True
schd_crs_msb_hdr,DISTRICT,True
schd_crs_msb_hdr,BUILDING,True
schd_crs_msb_hdr,COURSE,True
schd_crs_msb_hdr,NUMBER_REQUESTS,True
schd_crs_msb_hdr,AVERAGE_CLASS_SIZE,True
schd_crs_msb_hdr,NUMBER_SECTIONS,True
schd_crs_msb_hdr,SECTIONS_SAME,True
schd_crs_msb_hdr,COURSE_LENGTH,True
schd_crs_msb_hdr,DURATION_TYPE,True
schd_crs_msb_hdr,SPAN,True
schd_crs_msb_hdr,SAME_TEACHER,True
schd_crs_msb_hdr,SAME_PERIOD,True
schd_crs_msb_hdr,CHANGE_DATE_TIME,True
schd_crs_msb_hdr,CHANGE_UID,True
schd_crs_msb_det,DISTRICT,True
schd_crs_msb_det,BUILDING,True
schd_crs_msb_det,COURSE,True
schd_crs_msb_det,COURSE_SECTION,True
schd_crs_msb_det,MEETING_CODE,True
schd_crs_msb_det,STAFF_TYPE,True
schd_crs_msb_det,STAFF_RESOURCE,True
schd_crs_msb_det,ROOM_TYPE,True
schd_crs_msb_det,ROOM_RESOURCE,True
schd_crs_msb_det,MAXIMUM_SEATS,True
schd_crs_msb_det,CHANGE_DATE_TIME,True
schd_crs_msb_det,CHANGE_UID,True
schd_ms_grade,DISTRICT,True
schd_ms_grade,SECTION_KEY,True
schd_ms_grade,RESTRICT_GRADE,True
schd_ms_grade,ROW_IDENTITY,True
schd_ms_grade,CHANGE_DATE_TIME,True
schd_ms_grade,CHANGE_UID,True
schd_crs_mark_type,DISTRICT,True
schd_crs_mark_type,BUILDING,True
schd_crs_mark_type,COURSE,True
schd_crs_mark_type,MARK_TYPE,True
schd_crs_mark_type,CHANGE_DATE_TIME,True
schd_crs_mark_type,CHANGE_UID,True
schd_crs_group_hdr,DISTRICT,True
schd_crs_group_hdr,BUILDING,True
schd_crs_group_hdr,COURSE_GROUP,True
schd_crs_group_hdr,DESCRIPTION,True
schd_crs_group_hdr,CHANGE_DATE_TIME,True
schd_crs_group_hdr,CHANGE_UID,True
schd_crs_group_det,DISTRICT,True
schd_crs_group_det,BUILDING,True
schd_crs_group_det,COURSE_GROUP,True
schd_crs_group_det,COURSE_BUILDING,True
schd_crs_group_det,COURSE,True
schd_crs_group_det,CHANGE_DATE_TIME,True
schd_crs_group_det,CHANGE_UID,True
Schd_crs_bldg_type,DISTRICT,True
Schd_crs_bldg_type,BUILDING,True
Schd_crs_bldg_type,COURSE,True
Schd_crs_bldg_type,BLDG_TYPE,True
Schd_crs_bldg_type,CHANGE_DATE_TIME,True
Schd_crs_bldg_type,CHANGE_UID,True
schd_course_user,DISTRICT,True
schd_course_user,BUILDING,True
schd_course_user,COURSE,True
schd_course_user,SCREEN_NUMBER,True
schd_course_user,FIELD_NUMBER,True
schd_course_user,LIST_SEQUENCE,True
schd_course_user,FIELD_VALUE,True
schd_course_user,CHANGE_DATE_TIME,True
schd_course_user,CHANGE_UID,True
schd_crs_msb_combo,DISTRICT,True
schd_crs_msb_combo,BUILDING,True
schd_crs_msb_combo,COMBINATION_NUMBER,True
schd_crs_msb_combo,COMBINATION_COURSE,True
schd_crs_msb_combo,CHANGE_DATE_TIME,True
schd_crs_msb_combo,CHANGE_UID,True
sif_guid_att_code,DISTRICT,True
sif_guid_att_code,BUILDING,True
sif_guid_att_code,SCHOOL_YEAR,True
sif_guid_att_code,SUMMER_SCHOOL,True
sif_guid_att_code,ATTENDANCE_CODE,True
sif_guid_att_code,SIF_REFID,True
sif_guid_att_code,CHANGE_DATE_TIME,True
sif_guid_att_code,CHANGE_UID,True
sectb_subpackage,DISTRICT,True
sectb_subpackage,SUBPACKAGE,True
sectb_subpackage,DESCRIPTION,True
sectb_subpackage,RESERVED,True
sectb_subpackage,CHANGE_DATE_TIME,True
sectb_subpackage,CHANGE_UID,True
sectb_resource,DISTRICT,True
sectb_resource,PACKAGE,True
sectb_resource,SUBPACKAGE,True
sectb_resource,FEATURE,True
sectb_resource,DESCRIPTION,True
sectb_resource,RESERVED,True
sectb_resource,BLDG_LIST_REQUIRED,True
sectb_resource,ADVANCED_FEATURE,True
sectb_resource,CHANGE_DATE_TIME,True
sectb_resource,CHANGE_UID,True
sectb_package,DISTRICT,True
sectb_package,PACKAGE,True
sectb_package,DESCRIPTION,True
sectb_package,RESERVED,True
sectb_package,IS_ADVANCED_FEATURE,True
sectb_package,LICENSE_KEY,True
sectb_package,IS_VALID,True
sectb_package,CHANGE_DATE_TIME,True
sectb_package,CHANGE_UID,True
sec_user_role,DISTRICT,True
sec_user_role,LOGIN_ID,True
sec_user_role,ROLE_ID,True
sec_user_role,DEF_BUILDING_OVR,True
sec_user_role,CHANGE_DATE_TIME,True
sec_user_role,CHANGE_UID,True
spi_news_bldg,DISTRICT,True
spi_news_bldg,NEWS_ID,True
spi_news_bldg,BUILDING,True
spi_news_bldg,CHANGE_DATE_TIME,True
spi_news_bldg,CHANGE_UID,True
spi_news,DISTRICT,True
spi_news,NEWS_ID,True
spi_news,NEWS_DATE,True
spi_news,NEWS_HEADLINE,True
spi_news,NEWS_TEXT,True
spi_news,EXPIRATION_DATE,True
spi_news,REQUIRED_READING,True
spi_news,FOR_OFFICE_EMPLOYEES,True
spi_news,FOR_TEACHERS,True
spi_news,FOR_PARENTS,True
spi_news,CHANGE_DATE_TIME,True
spi_news,CHANGE_UID,True
SPI_HAC_NEWS_BLDG,DISTRICT,True
SPI_HAC_NEWS_BLDG,NEWS_ID,True
SPI_HAC_NEWS_BLDG,BUILDING,True
SPI_HAC_NEWS_BLDG,CHANGE_DATE_TIME,True
SPI_HAC_NEWS_BLDG,CHANGE_UID,True
SPI_HAC_NEWS,DISTRICT,True
SPI_HAC_NEWS,NEWS_ID,True
SPI_HAC_NEWS,ADMIN_OR_TEACHER,True
SPI_HAC_NEWS,HEADLINE,True
SPI_HAC_NEWS,NEWS_TEXT,True
SPI_HAC_NEWS,EFFECTIVE_DATE,True
SPI_HAC_NEWS,EXPIRATION_DATE,True
SPI_HAC_NEWS,FOR_PARENTS,True
SPI_HAC_NEWS,FOR_STUDENTS,True
SPI_HAC_NEWS,STAFF_ID,True
SPI_HAC_NEWS,SECTION_KEY,True
SPI_HAC_NEWS,PRINT_COURSE_INFO,True
SPI_HAC_NEWS,CHANGE_DATE_TIME,True
SPI_HAC_NEWS,CHANGE_UID,True
spi_checklist_setup_hdr,DISTRICT,True
spi_checklist_setup_hdr,BUILDING,True
spi_checklist_setup_hdr,CHECKLIST_CODE,True
spi_checklist_setup_hdr,CHECKLIST_RUN_WHEN,True
spi_checklist_setup_hdr,RC_RUN,True
spi_checklist_setup_hdr,CHECKLIST_DESCRIPTION,True
spi_checklist_setup_hdr,PACKAGE,True
spi_checklist_setup_hdr,NOTE_TEXT,True
spi_checklist_setup_hdr,CHANGE_DATE_TIME,True
spi_checklist_setup_hdr,CHANGE_UID,True
tac_cfg,DISTRICT,True
tac_cfg,BUILDING,True
tac_cfg,TEA_OVR_GB_AVG,True
tac_cfg,SUB_OVR_GB_AVG,True
tac_cfg,SHOW_ALL_TAB,True
tac_cfg,DEFAULT_TAB_TYPE,True
tac_cfg,DEFAULT_TAB,True
tac_cfg,TEA_ISSUES,True
tac_cfg,SUB_ISSUES,True
tac_cfg,TEA_CONDUCT_REFER,True
tac_cfg,SUB_CONDUCT_REFER,True
tac_cfg,SET_ROLES_ON_REFER,True
tac_cfg,SET_TYPE_ON_REFER,True
tac_cfg,DEFAULT_ISSUE_TYPE,True
tac_cfg,TEA_DISABLE_STD,True
tac_cfg,TEA_DISABLE_RUBRIC,True
tac_cfg,TEA_PUBLIC_RUBRIC,True
tac_cfg,TEA_PERFORMANCEPLUS,True
tac_cfg,SUB_PERFORMANCEPLUS,True
tac_cfg,FREE_TEXT_OPTION,True
tac_cfg,TEA_STU_ACCESS,True
tac_cfg,SUB_STU_ACCESS,True
tac_cfg,TEA_MEDALERTS,True
tac_cfg,SUB_MEDALERTS,True
tac_cfg,DISC_REFER,True
tac_cfg,SSP_REFER,True
tac_cfg,TEA_EFP_BP,True
tac_cfg,SUB_EFP_BP,True
tac_cfg,AUTO_PUBLISH_SCORES,True
tac_cfg,TEACHER_EXTRA_CREDIT_CREATION,True
tac_cfg,POINTS,True
tac_cfg,POINTS_OVERRIDE,True
tac_cfg,WEIGHT,True
tac_cfg,WEIGHT_OVERRIDE,True
tac_cfg,PUBLISH,True
tac_cfg,PUBLISH_OVERRIDE,True
tac_cfg,CHANGE_DATE_TIME,True
tac_cfg,CHANGE_UID,True
sms_user_screen,DISTRICT,True
sms_user_screen,SCREEN_TYPE,True
sms_user_screen,SCREEN_NUMBER,True
sms_user_screen,LIST_TYPE,True
sms_user_screen,COLUMNS,True
sms_user_screen,DESCRIPTION,True
sms_user_screen,REQUIRED_SCREEN,True
sms_user_screen,SEC_PACKAGE,True
sms_user_screen,SEC_SUBPACKAGE,True
sms_user_screen,SEC_FEATURE,True
sms_user_screen,RESERVED,True
sms_user_screen,STATE_FLAG,True
sms_user_screen,CHANGE_DATE_TIME,True
sms_user_screen,CHANGE_UID,True
sms_user_fields,DISTRICT,True
sms_user_fields,SCREEN_TYPE,True
sms_user_fields,SCREEN_NUMBER,True
sms_user_fields,FIELD_NUMBER,True
sms_user_fields,FIELD_LABEL,True
sms_user_fields,STATE_CODE_EQUIV,True
sms_user_fields,FIELD_ORDER,True
sms_user_fields,REQUIRED_FIELD,True
sms_user_fields,FIELD_TYPE,True
sms_user_fields,DATA_TYPE,True
sms_user_fields,NUMBER_TYPE,True
sms_user_fields,DATA_LENGTH,True
sms_user_fields,FIELD_SCALE,True
sms_user_fields,FIELD_PRECISION,True
sms_user_fields,DEFAULT_VALUE,True
sms_user_fields,DEFAULT_TABLE,True
sms_user_fields,DEFAULT_COLUMN,True
sms_user_fields,VALIDATION_LIST,True
sms_user_fields,VALIDATION_TABLE,True
sms_user_fields,CODE_COLUMN,True
sms_user_fields,DESCRIPTION_COLUMN,True
sms_user_fields,SPI_TABLE,True
sms_user_fields,SPI_COLUMN,True
sms_user_fields,SPI_SCREEN_NUMBER,True
sms_user_fields,SPI_FIELD_NUMBER,True
sms_user_fields,SPI_FIELD_TYPE,True
sms_user_fields,INCLUDE_PERFPLUS,True
sms_user_fields,SEC_PACKAGE,True
sms_user_fields,SEC_SUBPACKAGE,True
sms_user_fields,SEC_FEATURE,True
sms_user_fields,CHANGE_DATE_TIME,True
sms_user_fields,CHANGE_UID,True
sms_cfg,REPORT_CLEANUP,True
sms_cfg,CHANGE_DATE_TIME,True
sms_cfg,CHANGE_UID,True
sif_guid_student,DISTRICT,True
sif_guid_student,STUDENT_ID,True
sif_guid_student,SIF_REFID,True
sif_guid_student,CHANGE_DATE_TIME,True
sif_guid_student,CHANGE_UID,True
sif_guid_stu_sess,DISTRICT,True
sif_guid_stu_sess,STUDENT_ID,True
sif_guid_stu_sess,SECTION_KEY,True
sif_guid_stu_sess,COURSE_SESSION,True
sif_guid_stu_sess,DATE_RANGE_KEY,True
sif_guid_stu_sess,SIF_REFID,True
sif_guid_stu_sess,CHANGE_DATE_TIME,True
sif_guid_stu_sess,CHANGE_UID,True
sif_guid_att_daily,DISTRICT,True
sif_guid_att_daily,SCHOOL_YEAR,True
sif_guid_att_daily,SUMMER_SCHOOL,True
sif_guid_att_daily,BUILDING,True
sif_guid_att_daily,STUDENT_ID,True
sif_guid_att_daily,ATTENDANCE_DATE,True
sif_guid_att_daily,ATTENDANCE_PERIOD,True
sif_guid_att_daily,SEQUENCE_NUM,True
sif_guid_att_daily,SIF_REFID,True
sif_guid_att_daily,CHANGE_DATE_TIME,True
sif_guid_att_daily,CHANGE_UID,True
sif_guid_crs_sess,DISTRICT,True
sif_guid_crs_sess,SECTION_KEY,True
sif_guid_crs_sess,COURSE_SESSION,True
sif_guid_crs_sess,SIF_REFID,True
sif_guid_crs_sess,CHANGE_DATE_TIME,True
sif_guid_crs_sess,CHANGE_UID,True
schd_crs_msb_patrn,DISTRICT,True
schd_crs_msb_patrn,BUILDING,True
schd_crs_msb_patrn,COURSE,True
schd_crs_msb_patrn,COURSE_SECTION,True
schd_crs_msb_patrn,SEM_OR_MP,True
schd_crs_msb_patrn,PATTERN,True
schd_crs_msb_patrn,CHANGE_DATE_TIME,True
schd_crs_msb_patrn,CHANGE_UID,True
sif_guid_contact,DISTRICT,True
sif_guid_contact,CONTACT_ID,True
sif_guid_contact,STUDENT_ID,True
sif_guid_contact,CONTACT_TYPE,True
sif_guid_contact,SIF_REFID,True
sif_guid_contact,SIF_CONTACT_ID,True
sif_guid_contact,CHANGE_DATE_TIME,True
sif_guid_contact,CHANGE_UID,True
tactb_issue_action,DISTRICT,True
tactb_issue_action,CODE,True
tactb_issue_action,DESCRIPTION,True
tactb_issue_action,STATE_CODE_EQUIV,True
tactb_issue_action,ACTIVE,True
tactb_issue_action,CHANGE_DATE_TIME,True
tactb_issue_action,CHANGE_UID,True
tactb_issue,DISTRICT,True
tactb_issue,CODE,True
tactb_issue,DESCRIPTION,True
tactb_issue,USE_IN_CLASS,True
tactb_issue,USE_IN_REFER,True
tactb_issue,DISC_REFER,True
tactb_issue,SSP_REFER,True
tactb_issue,SSP_REFER_TAG,True
tactb_issue,STATE_CODE_EQUIV,True
tactb_issue,ACTIVE,True
tactb_issue,CHANGE_DATE_TIME,True
tactb_issue,CHANGE_UID,True
tac_seat_per_hdr,DISTRICT,True
tac_seat_per_hdr,BUILDING,True
tac_seat_per_hdr,SCHOOL_YEAR,True
tac_seat_per_hdr,SUMMER_SCHOOL,True
tac_seat_per_hdr,PERIOD_LIST,True
tac_seat_per_hdr,LAYOUT_TYPE,True
tac_seat_per_hdr,NUM_GRID_COLS,True
tac_seat_per_hdr,NUM_GRID_ROWS,True
tac_seat_per_hdr,CHANGE_DATE_TIME,True
tac_seat_per_hdr,CHANGE_UID,True
tac_seat_per_det,DISTRICT,True
tac_seat_per_det,BUILDING,True
tac_seat_per_det,SCHOOL_YEAR,True
tac_seat_per_det,SUMMER_SCHOOL,True
tac_seat_per_det,PERIOD_LIST,True
tac_seat_per_det,STUDENT_ID,True
tac_seat_per_det,HORIZONTAL_POS,True
tac_seat_per_det,VERTICAL_POS,True
tac_seat_per_det,GRID_ROW_LOCATION,True
tac_seat_per_det,GRID_COL_LOCATION,True
tac_seat_per_det,CHANGE_DATE_TIME,True
tac_seat_per_det,CHANGE_UID,True
tac_seat_hrm_hdr,DISTRICT,True
tac_seat_hrm_hdr,BUILDING,True
tac_seat_hrm_hdr,SCHOOL_YEAR,True
tac_seat_hrm_hdr,SUMMER_SCHOOL,True
tac_seat_hrm_hdr,HOMEROOM_TYPE,True
tac_seat_hrm_hdr,HOMEROOM,True
tac_seat_hrm_hdr,LAYOUT_TYPE,True
tac_seat_hrm_hdr,NUM_GRID_COLS,True
tac_seat_hrm_hdr,NUM_GRID_ROWS,True
tac_seat_hrm_hdr,CHANGE_DATE_TIME,True
tac_seat_hrm_hdr,CHANGE_UID,True
tac_seat_hrm_det,DISTRICT,True
tac_seat_hrm_det,BUILDING,True
tac_seat_hrm_det,SCHOOL_YEAR,True
tac_seat_hrm_det,SUMMER_SCHOOL,True
tac_seat_hrm_det,HOMEROOM_TYPE,True
tac_seat_hrm_det,HOMEROOM,True
tac_seat_hrm_det,STUDENT_ID,True
tac_seat_hrm_det,HORIZONTAL_POS,True
tac_seat_hrm_det,VERTICAL_POS,True
tac_seat_hrm_det,GRID_ROW_LOCATION,True
tac_seat_hrm_det,GRID_COL_LOCATION,True
tac_seat_hrm_det,CHANGE_DATE_TIME,True
tac_seat_hrm_det,CHANGE_UID,True
sms_user_table,DISTRICT,True
sms_user_table,TABLE_NAME,True
sms_user_table,PACKAGE,True
sms_user_table,TABLE_DESCR,True
sms_user_table,CHANGE_DATE_TIME,True
sms_user_table,CHANGE_UID,True
tactb_issue_location,DISTRICT,True
tactb_issue_location,CODE,True
tactb_issue_location,DESCRIPTION,True
tactb_issue_location,DISC_CODE,True
tactb_issue_location,STATE_CODE_EQUIV,True
tactb_issue_location,ACTIVE,True
tactb_issue_location,CHANGE_DATE_TIME,True
tactb_issue_location,CHANGE_UID,True
tac_seat_crs_det,DISTRICT,True
tac_seat_crs_det,SECTION_KEY,True
tac_seat_crs_det,COURSE_SESSION,True
tac_seat_crs_det,STUDENT_ID,True
tac_seat_crs_det,HORIZONTAL_POS,True
tac_seat_crs_det,VERTICAL_POS,True
tac_seat_crs_det,GRID_ROW_LOCATION,True
tac_seat_crs_det,GRID_COL_LOCATION,True
tac_seat_crs_det,CHANGE_DATE_TIME,True
tac_seat_crs_det,CHANGE_UID,True
tac_messages,DISTRICT,True
tac_messages,STAFF_ID,True
tac_messages,MSG_DATE,True
tac_messages,MSG_SEQUENCE,True
tac_messages,BUILDING,True
tac_messages,MSG_TYPE,True
tac_messages,MESSAGE_BODY,True
tac_messages,STUDENT_ID,True
tac_messages,SECTION_KEY,True
tac_messages,COURSE_SESSION,True
tac_messages,SCHD_RESOLVED,True
tac_messages,MESSAGE_DATE1,True
tac_messages,MESSAGE_DATE2,True
tac_messages,CHANGE_DATE_TIME,True
tac_messages,CHANGE_UID,True
TAC_LUNCH_TYPES,DISTRICT,True
TAC_LUNCH_TYPES,BUILDING,True
TAC_LUNCH_TYPES,LUNCH_TYPE,True
TAC_LUNCH_TYPES,DESCRIPTION,True
TAC_LUNCH_TYPES,ACTIVE,True
TAC_LUNCH_TYPES,CHANGE_DATE_TIME,True
TAC_LUNCH_TYPES,CHANGE_UID,True
sif_guid_reg_ew,DISTRICT,True
sif_guid_reg_ew,STUDENT_ID,True
sif_guid_reg_ew,ENTRY_WD_TYPE,True
sif_guid_reg_ew,SCHOOL_YEAR,True
sif_guid_reg_ew,ENTRY_DATE,True
sif_guid_reg_ew,SIF_REFID,True
sif_guid_reg_ew,CHANGE_DATE_TIME,True
sif_guid_reg_ew,CHANGE_UID,True
tac_issue_student,DISTRICT,True
tac_issue_student,ISSUE_ID,True
tac_issue_student,STUDENT_ID,True
tac_issue_student,STUDENT_ROLE,True
tac_issue_student,ADMIN_ROLE,True
tac_issue_student,COMMENTS,True
tac_issue_student,CHANGE_DATE_TIME,True
tac_issue_student,CHANGE_UID,True
tac_issue_refer,DISTRICT,True
tac_issue_refer,ISSUE_ID,True
tac_issue_refer,REFER_DATE,True
tac_issue_refer,REFER_SEQUENCE,True
tac_issue_refer,REFER_STATUS,True
tac_issue_refer,REFER_STAFF_ID,True
tac_issue_refer,DISC_INCIDENT_ID,True
tac_issue_refer,COMMENTS,True
tac_issue_refer,CHANGE_DATE_TIME,True
tac_issue_refer,CHANGE_UID,True
tac_issue,DISTRICT,True
tac_issue,SCHOOL_YEAR,True
tac_issue,SUMMER_SCHOOL,True
tac_issue,BUILDING,True
tac_issue,STAFF_ID,True
tac_issue,ISSUE_ID,True
tac_issue,ISSUE_CODE,True
tac_issue,ISSUE_DATE,True
tac_issue,ISSUE_TIME,True
tac_issue,LOCATION,True
tac_issue,ISSUE_STATUS,True
tac_issue,ISSUE_SOURCE,True
tac_issue,ISSUE_SOURCE_DETAIL,True
tac_issue,COURSE_SESSION,True
tac_issue,ISSUE_RESOLVED,True
tac_issue,COMMENTS,True
tac_issue,CHANGE_DATE_TIME,True
tac_issue,CHANGE_UID,True
statetb_submissions,DISTRICT,True
statetb_submissions,STATE,True
statetb_submissions,CODE,True
statetb_submissions,DESCRIPTION,True
statetb_submissions,START_DATE,True
statetb_submissions,END_DATE,True
statetb_submissions,ACTIVE,True
statetb_submissions,CHANGE_DATE_TIME,True
statetb_submissions,CHANGE_UID,True
schd_ms_honors,DISTRICT,True
schd_ms_honors,SECTION_KEY,True
schd_ms_honors,COURSE_SESSION,True
schd_ms_honors,HONOR_TYPE,True
schd_ms_honors,HONOR_LEVEL,True
schd_ms_honors,CHANGE_DATE_TIME,True
schd_ms_honors,CHANGE_UID,True
statetb_record_types,DISTRICT,True
statetb_record_types,STATE,True
statetb_record_types,RECORD_TYPE,True
statetb_record_types,DESCRIPTION,True
statetb_record_types,TABLE_NAME,True
statetb_record_types,ACTIVE,True
statetb_record_types,STUDENTSEARCH,True
statetb_record_types,SORTORDER,True
statetb_record_types,SUBMISSIONS,True
statetb_record_types,DOWNLOAD_TYPES,True
statetb_record_types,DISTRICTSEARCH,True
statetb_record_types,COURSESEARCH,True
statetb_record_types,STAFFSEARCH,True
statetb_record_types,CHANGE_DATE_TIME,True
statetb_record_types,CHANGE_UID,True
STATETB_DEF_CLASS,DISTRICT,True
STATETB_DEF_CLASS,CODE,True
STATETB_DEF_CLASS,DESCRIPTION,True
STATETB_DEF_CLASS,STATE_CODE_EQUIV,True
STATETB_DEF_CLASS,ACTIVE,True
STATETB_DEF_CLASS,CHANGE_DATE_TIME,True
STATETB_DEF_CLASS,CHANGE_UID,True
state_vld_results,DISTRICT,True
state_vld_results,RULE_ID,True
state_vld_results,STUDENT_ID,True
state_vld_results,EXCLUDE,True
state_vld_results,ERROR_MESSAGE,True
state_vld_results,CHANGE_DATE_TIME,True
state_vld_results,CHANGE_UID,True
sif_guid_course,DISTRICT,True
sif_guid_course,BUILDING,True
sif_guid_course,COURSE,True
sif_guid_course,SIF_REFID,True
sif_guid_course,CHANGE_DATE_TIME,True
sif_guid_course,CHANGE_UID,True
ssptb_plan_type,DISTRICT,True
ssptb_plan_type,PLAN_TYPE,True
ssptb_plan_type,DESCRIPTION,True
ssptb_plan_type,ACTIVE,True
ssptb_plan_type,CHANGE_DATE_TIME,True
ssptb_plan_type,CHANGE_UID,True
statetb_staff_role,DISTRICT,True
statetb_staff_role,CODE,True
statetb_staff_role,DESCRIPTION,True
statetb_staff_role,STATE_CODE_EQUIV,True
statetb_staff_role,ACTIVE,True
statetb_staff_role,CHANGE_DATE_TIME,True
statetb_staff_role,CHANGE_UID,True
ssptb_goal,DISTRICT,True
ssptb_goal,CODE,True
ssptb_goal,DESCRIPTION,True
ssptb_goal,HAC_STUDENT,True
ssptb_goal,HAC_PARENT,True
ssptb_goal,ACTIVE,True
ssptb_goal,CHANGE_DATE_TIME,True
ssptb_goal,CHANGE_UID,True
tac_lunch_counts,DISTRICT,True
tac_lunch_counts,BUILDING,True
tac_lunch_counts,LUNCH_TYPE,True
tac_lunch_counts,STAFF_ID,True
tac_lunch_counts,TEACHER,True
tac_lunch_counts,LUNCH_DATE,True
tac_lunch_counts,LUNCH_COUNT,True
tac_lunch_counts,CHANGE_DATE_TIME,True
tac_lunch_counts,CHANGE_UID,True
TAC_ISSUE_REFER_SSP,DISTRICT,True
TAC_ISSUE_REFER_SSP,ISSUE_ID,True
TAC_ISSUE_REFER_SSP,REFER_DATE,True
TAC_ISSUE_REFER_SSP,REFER_SEQUENCE,True
TAC_ISSUE_REFER_SSP,REFER_STATUS,True
TAC_ISSUE_REFER_SSP,REFER_TO,True
TAC_ISSUE_REFER_SSP,REFER_COORDINATOR,True
TAC_ISSUE_REFER_SSP,SSP_PLAN_NUM,True
TAC_ISSUE_REFER_SSP,SSP_QUAL_REASON,True
TAC_ISSUE_REFER_SSP,SSP_QUAL_REASON_START,True
TAC_ISSUE_REFER_SSP,COMMENTS,True
TAC_ISSUE_REFER_SSP,CHANGE_DATE_TIME,True
TAC_ISSUE_REFER_SSP,CHANGE_UID,True
ssp_stu_plan_user,DISTRICT,True
ssp_stu_plan_user,STUDENT_ID,True
ssp_stu_plan_user,PLAN_NUM,True
ssp_stu_plan_user,FIELD_NUMBER,True
ssp_stu_plan_user,FIELD_VALUE,True
ssp_stu_plan_user,CHANGE_DATE_TIME,True
ssp_stu_plan_user,CHANGE_UID,True
ssptb_role_eval,DISTRICT,True
ssptb_role_eval,CODE,True
ssptb_role_eval,DESCRIPTION,True
ssptb_role_eval,ACTIVE,True
ssptb_role_eval,CHANGE_DATE_TIME,True
ssptb_role_eval,CHANGE_UID,True
ssptb_goal_level,DISTRICT,True
ssptb_goal_level,LEVEL_CODE,True
ssptb_goal_level,DESCRIPTION,True
ssptb_goal_level,ACTIVE,True
ssptb_goal_level,CHANGE_DATE_TIME,True
ssptb_goal_level,CHANGE_UID,True
ssptb_objective,DISTRICT,True
ssptb_objective,CODE,True
ssptb_objective,DESCRIPTION,True
ssptb_objective,ACTIVE,True
ssptb_objective,CHANGE_DATE_TIME,True
ssptb_objective,CHANGE_UID,True
ssp_stu_objective,DISTRICT,True
ssp_stu_objective,STUDENT_ID,True
ssp_stu_objective,PLAN_NUM,True
ssp_stu_objective,GOAL,True
ssp_stu_objective,OBJECTIVE,True
ssp_stu_objective,SEQUENCE_NUM,True
ssp_stu_objective,COMMENT,True
ssp_stu_objective,COMMENT_ORDER,True
ssp_stu_objective,COMPLETION_DATE,True
ssp_stu_objective,CHANGE_DATE_TIME,True
ssp_stu_objective,CHANGE_UID,True
ssptb_ais_type,DISTRICT,True
ssptb_ais_type,CODE,True
ssptb_ais_type,DESCRIPTION,True
ssptb_ais_type,ACTIVE,True
ssptb_ais_type,CHANGE_DATE_TIME,True
ssptb_ais_type,CHANGE_UID,True
ssptb_ais_level,DISTRICT,True
ssptb_ais_level,CODE,True
ssptb_ais_level,DESCRIPTION,True
ssptb_ais_level,ACTIVE,True
ssptb_ais_level,CHANGE_DATE_TIME,True
ssptb_ais_level,CHANGE_UID,True
ssp_stu_int_prog,DISTRICT,True
ssp_stu_int_prog,STUDENT_ID,True
ssp_stu_int_prog,PLAN_NUM,True
ssp_stu_int_prog,INTERVENTION,True
ssp_stu_int_prog,ENTRY_DATE,True
ssp_stu_int_prog,MARK_TYPE,True
ssp_stu_int_prog,MARK_VALUE,True
ssp_stu_int_prog,CHANGE_DATE_TIME,True
ssp_stu_int_prog,CHANGE_UID,True
ssp_stu_int_freq_dt,DISTRICT,True
ssp_stu_int_freq_dt,STUDENT_ID,True
ssp_stu_int_freq_dt,PLAN_NUM,True
ssp_stu_int_freq_dt,INTERVENTION,True
ssp_stu_int_freq_dt,ENTRY_DATE,True
ssp_stu_int_freq_dt,CHANGE_DATE_TIME,True
ssp_stu_int_freq_dt,CHANGE_UID,True
ssp_stu_int_comm,DISTRICT,True
ssp_stu_int_comm,STUDENT_ID,True
ssp_stu_int_comm,PLAN_NUM,True
ssp_stu_int_comm,INTERVENTION,True
ssp_stu_int_comm,COMMENT_TYPE,True
ssp_stu_int_comm,SEQUENCE_NUM,True
ssp_stu_int_comm,COMMENT,True
ssp_stu_int_comm,COMMENT_ORDER,True
ssp_stu_int_comm,ENTRY_DATE,True
ssp_stu_int_comm,SENSITIVE_FLAG,True
ssp_stu_int_comm,CHANGE_DATE_TIME,True
ssp_stu_int_comm,CHANGE_UID,True
ssp_stu_int,DISTRICT,True
ssp_stu_int,STUDENT_ID,True
ssp_stu_int,PLAN_NUM,True
ssp_stu_int,INTERVENTION,True
ssp_stu_int,START_DATE,True
ssp_stu_int,COMPLETION_DATE,True
ssp_stu_int,SENSITIVE_FLAG,True
ssp_stu_int,LEVEL,True
ssp_stu_int,ROLE_EVALUATOR,True
ssp_stu_int,FREQUENCY,True
ssp_stu_int,FREQ_WEEKDAY,True
ssp_stu_int,CHANGE_DATE_TIME,True
ssp_stu_int,CHANGE_UID,True
ssp_stu_plan,DISTRICT,True
ssp_stu_plan,STUDENT_ID,True
ssp_stu_plan,PLAN_NUM,True
ssp_stu_plan,PLAN_DATE,True
ssp_stu_plan,PLAN_TITLE,True
ssp_stu_plan,COMPLETION_DATE,True
ssp_stu_plan,STATUS,True
ssp_stu_plan,SENSITIVE_FLAG,True
ssp_stu_plan,PLAN_TYPE,True
ssp_stu_plan,PLAN_MANAGER,True
ssp_stu_plan,QUALIFICATIONS,True
ssp_stu_plan,COMPLETION_NOTES,True
ssp_stu_plan,CHANGE_DATE_TIME,True
ssp_stu_plan,CHANGE_UID,True
ssp_stu_at_risk,DISTRICT,True
ssp_stu_at_risk,STUDENT_ID,True
ssp_stu_at_risk,QUAL_REASON,True
ssp_stu_at_risk,START_DATE,True
ssp_stu_at_risk,END_DATE,True
ssp_stu_at_risk,PLAN_NUM,True
ssp_stu_at_risk,PLAN_DATE,True
ssp_stu_at_risk,CHANGE_DATE_TIME,True
ssp_stu_at_risk,CHANGE_UID,True
ssp_rsn_temp_parent_goal_obj,DISTRICT,True
ssp_rsn_temp_parent_goal_obj,QUAL_REASON,True
ssp_rsn_temp_parent_goal_obj,GRADE,True
ssp_rsn_temp_parent_goal_obj,GOAL,True
ssp_rsn_temp_parent_goal_obj,OBJECTIVE,True
ssp_rsn_temp_parent_goal_obj,SEQUENCE_NUM,True
ssp_rsn_temp_parent_goal_obj,COMMENT,True
ssp_rsn_temp_parent_goal_obj,CHANGE_DATE_TIME,True
ssp_rsn_temp_parent_goal_obj,CHANGE_UID,True
ssp_rsn_temp_parent_goal,DISTRICT,True
ssp_rsn_temp_parent_goal,QUAL_REASON,True
ssp_rsn_temp_parent_goal,GRADE,True
ssp_rsn_temp_parent_goal,GOAL,True
ssp_rsn_temp_parent_goal,COMMENT,True
ssp_rsn_temp_parent_goal,CHANGE_DATE_TIME,True
ssp_rsn_temp_parent_goal,CHANGE_UID,True
ssp_rsn_temp_int,DISTRICT,True
ssp_rsn_temp_int,QUAL_REASON,True
ssp_rsn_temp_int,GRADE,True
ssp_rsn_temp_int,INTERVENTION,True
ssp_rsn_temp_int,SENSITIVE_FLAG,True
ssp_rsn_temp_int,LEVEL,True
ssp_rsn_temp_int,ROLE_EVALUATOR,True
ssp_rsn_temp_int,FREQUENCY,True
ssp_rsn_temp_int,FREQ_WEEKDAY,True
ssp_rsn_temp_int,STAFF_ID,True
ssp_rsn_temp_int,CHANGE_DATE_TIME,True
ssp_rsn_temp_int,CHANGE_UID,True
ssp_rsn_temp_goal_obj,DISTRICT,True
ssp_rsn_temp_goal_obj,QUAL_REASON,True
ssp_rsn_temp_goal_obj,GRADE,True
ssp_rsn_temp_goal_obj,GOAL,True
ssp_rsn_temp_goal_obj,OBJECTIVE,True
ssp_rsn_temp_goal_obj,SEQUENCE_NUM,True
ssp_rsn_temp_goal_obj,COMMENT,True
ssp_rsn_temp_goal_obj,CHANGE_DATE_TIME,True
ssp_rsn_temp_goal_obj,CHANGE_UID,True
sec_user,DISTRICT,True
sec_user,LOGIN_ID,True
sec_user,USER_OR_ROLE,True
sec_user,LOGIN_NAME,True
sec_user,BUILDING,True
sec_user,DEPARTMENT,True
sec_user,EMAIL,True
sec_user,SCHOOL_YEAR,True
sec_user,SUMMER_SCHOOL,True
sec_user,USE_MENU_CACHE,True
sec_user,MAY_IMPERSONATE,True
sec_user,HAS_READ_NEWS,True
sec_user,INITIALS,True
sec_user,LOCAL_LOGIN_ID,True
sec_user,TEACHER_ACCOUNT,True
sec_user,CHANGE_DATE_TIME,True
sec_user,CHANGE_UID,True
patb_guardian,DISTRICT,True
patb_guardian,CODE,True
patb_guardian,DESCRIPTION,True
patb_guardian,STATE_CODE_EQUIV,True
patb_guardian,ACTIVE,True
patb_guardian,CHANGE_DATE_TIME,True
patb_guardian,CHANGE_UID,True
ssp_stu_goal,DISTRICT,True
ssp_stu_goal,STUDENT_ID,True
ssp_stu_goal,PLAN_NUM,True
ssp_stu_goal,GOAL,True
ssp_stu_goal,COMPLETION_DATE,True
ssp_stu_goal,COMMENT,True
ssp_stu_goal,GOAL_LEVEL,True
ssp_stu_goal,GOAL_DETAIL,True
ssp_stu_goal,BASELINE,True
ssp_stu_goal,ENTERED_BY,True
ssp_stu_goal,CHANGE_DATE_TIME,True
ssp_stu_goal,CHANGE_UID,True
ssp_stu_goal_user,DISTRICT,True
ssp_stu_goal_user,STUDENT_ID,True
ssp_stu_goal_user,PLAN_NUM,True
ssp_stu_goal_user,GOAL,True
ssp_stu_goal_user,FIELD_NUMBER,True
ssp_stu_goal_user,FIELD_VALUE,True
ssp_stu_goal_user,CHANGE_DATE_TIME,True
ssp_stu_goal_user,CHANGE_UID,True
ssp_stu_calc,DISTRICT,True
ssp_stu_calc,STUDENT_ID,True
ssp_stu_calc,LTDB_CALC_DATE,True
ssp_stu_calc,ATT_CALC_DATE,True
ssp_stu_calc,REG_CALC_DATE,True
ssp_stu_calc,MR_CALC_DATE,True
ssp_stu_calc,DISC_CALC_DATE,True
ssp_stu_calc,CHANGE_DATE_TIME,True
ssp_stu_calc,CHANGE_UID,True
schdtb_credit_basis_pesc_code,DISTRICT,True
schdtb_credit_basis_pesc_code,CODE,True
schdtb_credit_basis_pesc_code,DESCRIPTION,True
schdtb_credit_basis_pesc_code,CHANGE_DATE_TIME,True
schdtb_credit_basis_pesc_code,CHANGE_UID,True
patb_gifted,DISTRICT,True
patb_gifted,CODE,True
patb_gifted,DESCRIPTION,True
patb_gifted,STATE_CODE_EQUIV,True
patb_gifted,ACTIVE,True
patb_gifted,CHANGE_DATE_TIME,True
patb_gifted,CHANGE_UID,True
patb_eng_prof,DISTRICT,True
patb_eng_prof,CODE,True
patb_eng_prof,DESCRIPTION,True
patb_eng_prof,STATE_CODE_EQUIV,True
patb_eng_prof,ACTIVE,True
patb_eng_prof,CHANGE_DATE_TIME,True
patb_eng_prof,CHANGE_UID,True
patb_cte_status,DISTRICT,True
patb_cte_status,CODE,True
patb_cte_status,DESCRIPTION,True
patb_cte_status,STATE_CODE_EQUIV,True
patb_cte_status,ACTIVE,True
patb_cte_status,CHANGE_DATE_TIME,True
patb_cte_status,CHANGE_UID,True
ssptb_plan_status,DISTRICT,True
ssptb_plan_status,CODE,True
ssptb_plan_status,DESCRIPTION,True
ssptb_plan_status,ACTIVE,True
ssptb_plan_status,CHANGE_DATE_TIME,True
ssptb_plan_status,CHANGE_UID,True
PATB_CRS_LENGTH,DISTRICT,True
PATB_CRS_LENGTH,CODE,True
PATB_CRS_LENGTH,DESCRIPTION,True
PATB_CRS_LENGTH,STATE_CODE_EQUIV,True
PATB_CRS_LENGTH,ACTIVE,True
PATB_CRS_LENGTH,CHANGE_DATE_TIME,True
PATB_CRS_LENGTH,CHANGE_UID,True
PATB_CRS_DELIVER,DISTRICT,True
PATB_CRS_DELIVER,CODE,True
PATB_CRS_DELIVER,DESCRIPTION,True
PATB_CRS_DELIVER,STATE_CODE_EQUIV,True
PATB_CRS_DELIVER,ACTIVE,True
PATB_CRS_DELIVER,CHANGE_DATE_TIME,True
PATB_CRS_DELIVER,CHANGE_UID,True
patb_credential,DISTRICT,True
patb_credential,CODE,True
patb_credential,DESCRIPTION,True
patb_credential,STATE_CODE_EQUIV,True
patb_credential,ACTIVE,True
patb_credential,CHANGE_DATE_TIME,True
patb_credential,CHANGE_UID,True
patb_delivery_code,DISTRICT,True
patb_delivery_code,CODE,True
patb_delivery_code,DESCRIPTION,True
patb_delivery_code,STATE_CODE_EQUIV,True
patb_delivery_code,ACTIVE,True
patb_delivery_code,CHANGE_DATE_TIME,True
patb_delivery_code,CHANGE_UID,True
patb_cip_code,DISTRICT,True
patb_cip_code,CODE,True
patb_cip_code,DESCRIPTION,True
patb_cip_code,STATE_CODE_EQUIV,True
patb_cip_code,ACTIVE,True
patb_cip_code,CHANGE_DATE_TIME,True
patb_cip_code,CHANGE_UID,True
ssp_rsn_temp_hdr,DISTRICT,True
ssp_rsn_temp_hdr,QUAL_REASON,True
ssp_rsn_temp_hdr,GRADE,True
ssp_rsn_temp_hdr,CHANGE_DATE_TIME,True
ssp_rsn_temp_hdr,CHANGE_UID,True
patb_adjudication,DISTRICT,True
patb_adjudication,CODE,True
patb_adjudication,DESCRIPTION,True
patb_adjudication,ACTIVE,True
patb_adjudication,CHANGE_DATE_TIME,True
patb_adjudication,CHANGE_UID,True
pa_stu_snap_down,DISTRICT,True
pa_stu_snap_down,SCHOOL_YEAR,True
pa_stu_snap_down,PERIOD,True
pa_stu_snap_down,STUDENT_ID,True
pa_stu_snap_down,STATE_ID,True
pa_stu_snap_down,SNAPSHOT_DATE,True
pa_stu_snap_down,LOCATION,True
pa_stu_snap_down,SCHOOL_YEAR_DATE,True
pa_stu_snap_down,SOCIAL_SECURE,True
pa_stu_snap_down,GRADE,True
pa_stu_snap_down,HOMEROOM,True
pa_stu_snap_down,BIRTHDATE,True
pa_stu_snap_down,GENDER,True
pa_stu_snap_down,ADDRESS1,True
pa_stu_snap_down,ADDRESS2,True
pa_stu_snap_down,CITY,True
pa_stu_snap_down,STATE,True
pa_stu_snap_down,ZIPCODE,True
pa_stu_snap_down,GUARDIAN_RELATION,True
pa_stu_snap_down,ETHNIC_CODE,True
pa_stu_snap_down,ECO_STATUS,True
pa_stu_snap_down,SPECIAL_ED,True
pa_stu_snap_down,LEP_PART,True
pa_stu_snap_down,REPEAT_LAST_YEAR,True
pa_stu_snap_down,EXPECTED_POST_GRAD,True
pa_stu_snap_down,GRAD_STATUS,True
pa_stu_snap_down,STATUS,True
pa_stu_snap_down,PLAN_504,True
pa_stu_snap_down,FOREIGN_EXCHANGE,True
pa_stu_snap_down,GIFTED,True
pa_stu_snap_down,POVERTY,True
pa_stu_snap_down,DIPLOMA_TYPE,True
pa_stu_snap_down,STATE_ENTRY,True
pa_stu_snap_down,US_ENTRY,True
pa_stu_snap_down,HOMELESS,True
pa_stu_snap_down,MIGRANT,True
pa_stu_snap_down,ENGLISH_PROF,True
pa_stu_snap_down,DIST_RESIDENCE,True
pa_stu_snap_down,SINGLE_PARENT,True
pa_stu_snap_down,EDU_DISADV,True
pa_stu_snap_down,HOME_LANGUAGE,True
pa_stu_snap_down,YEARS_US_SCHOOLS,True
pa_stu_snap_down,GENERATION_CODE,True
pa_stu_snap_down,FOOD_ELIGIBLE,True
pa_stu_snap_down,LNAME,True
pa_stu_snap_down,FNAME,True
pa_stu_snap_down,BIRTH_COUNTRY,True
pa_stu_snap_down,MNAME,True
pa_stu_snap_down,BIRTH_VERIFY,True
pa_stu_snap_down,IMMIGRANT,True
pa_stu_snap_down,HOME_LOCATION,True
pa_stu_snap_down,DISPLACED_HOME,True
pa_stu_snap_down,BIRTH_CITY,True
pa_stu_snap_down,BIRTH_STATE,True
pa_stu_snap_down,COURSE_STUDY,True
pa_stu_snap_down,HOME_COUNTY,True
pa_stu_snap_down,FIPS_COUNTY,True
pa_stu_snap_down,FUNDING_DISTRICT,True
pa_stu_snap_down,FAMILY_NUMBER,True
pa_stu_snap_down,SHORT_LAST,True
pa_stu_snap_down,SHORT_FIRST,True
pa_stu_snap_down,SHORT_MIDDLE,True
pa_stu_snap_down,HOME_PHONE,True
pa_stu_snap_down,PRIM_GUARDIAN,True
pa_stu_snap_down,GUARDIAN_PHONE,True
pa_stu_snap_down,NATIVE_LANG,True
pa_stu_snap_down,CHALLENGE_TYPE,True
pa_stu_snap_down,EXP_GRAD,True
pa_stu_snap_down,ALT_STUID,True
pa_stu_snap_down,GRADE9_ENTRY,True
pa_stu_snap_down,DISTRICT_ENTRY,True
pa_stu_snap_down,SCHOOL_ENTRY,True
pa_stu_snap_down,PREK_PROGRAM,True
pa_stu_snap_down,CHANGE_DATE_TIME,True
pa_stu_snap_down,CHANGE_UID,True
pa_stu_down,DISTRICT,True
pa_stu_down,SCHOOL_YEAR,True
pa_stu_down,PERIOD,True
pa_stu_down,STUDENT_ID,True
pa_stu_down,STATE_ID,True
pa_stu_down,LOCATION,True
pa_stu_down,SCHOOL_YEAR_DATE,True
pa_stu_down,SOCIAL_SECURE,True
pa_stu_down,GRADE,True
pa_stu_down,HOMEROOM,True
pa_stu_down,BIRTHDATE,True
pa_stu_down,GENDER,True
pa_stu_down,ADDRESS1,True
pa_stu_down,ADDRESS2,True
pa_stu_down,CITY,True
pa_stu_down,STATE,True
pa_stu_down,ZIPCODE,True
pa_stu_down,GUARDIAN_RELATION,True
pa_stu_down,ETHNIC_CODE,True
pa_stu_down,ECO_STATUS,True
pa_stu_down,SPECIAL_ED,True
pa_stu_down,LEP_PART,True
pa_stu_down,REPEAT_LAST_YEAR,True
pa_stu_down,GRAD_STATUS,True
pa_stu_down,STATUS,True
pa_stu_down,PLAN_504,True
pa_stu_down,FOREIGN_EXCHANGE,True
pa_stu_down,GIFTED,True
pa_stu_down,POVERTY,True
pa_stu_down,DIPLOMA_TYPE,True
pa_stu_down,STATE_ENTRY,True
pa_stu_down,US_ENTRY,True
pa_stu_down,HOMELESS,True
pa_stu_down,MIGRANT,True
pa_stu_down,ENGLISH_PROF,True
pa_stu_down,DIST_RESIDENCE,True
pa_stu_down,SINGLE_PARENT,True
pa_stu_down,EDU_DISADV,True
pa_stu_down,HOME_LANGUAGE,True
pa_stu_down,YEARS_US_SCHOOLS,True
pa_stu_down,GENERATION_CODE,True
pa_stu_down,FOOD_ELIGIBLE,True
pa_stu_down,LNAME,True
pa_stu_down,FNAME,True
pa_stu_down,BIRTH_COUNTRY,True
pa_stu_down,MNAME,True
pa_stu_down,BIRTH_VERIFY,True
pa_stu_down,IMMIGRANT,True
pa_stu_down,HOME_LOCATION,True
pa_stu_down,DISPLACED_HOME,True
pa_stu_down,BIRTH_CITY,True
pa_stu_down,BIRTH_STATE,True
pa_stu_down,COURSE_STUDY,True
pa_stu_down,HOME_COUNTY,True
pa_stu_down,FIPS_COUNTY,True
pa_stu_down,FUNDING_DISTRICT,True
pa_stu_down,FAMILY_NUMBER,True
pa_stu_down,SHORT_LAST,True
pa_stu_down,SHORT_FIRST,True
pa_stu_down,SHORT_MIDDLE,True
pa_stu_down,HOME_PHONE,True
pa_stu_down,PRIM_GUARDIAN,True
pa_stu_down,GUARDIAN_PHONE,True
pa_stu_down,NATIVE_LANG,True
pa_stu_down,CHALLENGE_TYPE,True
pa_stu_down,EXP_GRAD,True
pa_stu_down,ALT_STUID,True
pa_stu_down,GRADE9_ENTRY,True
pa_stu_down,DISTRICT_ENTRY,True
pa_stu_down,SCHOOL_ENTRY,True
pa_stu_down,PREK_PROGRAM,True
pa_stu_down,CHANGE_DATE_TIME,True
pa_stu_down,CHANGE_UID,True
schd_timetable,DISTRICT,True
schd_timetable,SCHOOL_YEAR,True
schd_timetable,SUMMER_SCHOOL,True
schd_timetable,BUILDING,True
schd_timetable,BELL_SCHD,True
schd_timetable,TIMESLOT,True
schd_timetable,CYCLE,True
schd_timetable,START_TIME,True
schd_timetable,END_TIME,True
schd_timetable,PERIOD,True
schd_timetable,PARENT_CYCLE_DAY,True
schd_timetable,LUNCH_TIME,True
schd_timetable,CHANGE_DATE_TIME,True
schd_timetable,CHANGE_UID,True
patb_birth_verif,DISTRICT,True
patb_birth_verif,CODE,True
patb_birth_verif,DESCRIPTION,True
patb_birth_verif,STATE_CODE_EQUIV,True
patb_birth_verif,ACTIVE,True
patb_birth_verif,CHANGE_DATE_TIME,True
patb_birth_verif,CHANGE_UID,True
patb_assault_type,DISTRICT,True
patb_assault_type,CODE,True
patb_assault_type,DESCRIPTION,True
patb_assault_type,ACTIVE,True
patb_assault_type,CHANGE_DATE_TIME,True
patb_assault_type,CHANGE_UID,True
REG_IEP_STATUS,ID,True
REG_IEP_STATUS,DISTRICT,True
REG_IEP_STATUS,STUDENT_ID,True
REG_IEP_STATUS,IEPPLUS_ID,True
REG_IEP_STATUS,STATUS_DESCRIPTION,True
REG_IEP_STATUS,START_DATE,True
REG_IEP_STATUS,EXIT_DATE,True
REG_IEP_STATUS,EXIT_REASON,True
medtb_vis_exam_ark,DISTRICT,True
medtb_vis_exam_ark,FOLLOWUP_CODE,True
medtb_vis_exam_ark,DESCRIPTION,True
medtb_vis_exam_ark,CONFIRMED_NORMAL,True
medtb_vis_exam_ark,ACTIVE,True
medtb_vis_exam_ark,CHANGE_DATE_TIME,True
medtb_vis_exam_ark,CHANGE_UID,True
STATETB_OCR_COUNT_TYPE,DISTRICT,True
STATETB_OCR_COUNT_TYPE,SECTION,True
STATETB_OCR_COUNT_TYPE,ORDER_NUMBER,True
STATETB_OCR_COUNT_TYPE,SEQUENCE,True
STATETB_OCR_COUNT_TYPE,COUNT_TYPE,True
STATETB_OCR_COUNT_TYPE,CHANGE_DATE_TIME,True
STATETB_OCR_COUNT_TYPE,CHANGE_UID,True
MEDTB_PERCENTS_ARK,DISTRICT,True
MEDTB_PERCENTS_ARK,AGE,True
MEDTB_PERCENTS_ARK,GENDER,True
MEDTB_PERCENTS_ARK,PERCENTILE,True
MEDTB_PERCENTS_ARK,HEIGHT,True
MEDTB_PERCENTS_ARK,WEIGHT,True
MEDTB_PERCENTS_ARK,BMI,True
MEDTB_PERCENTS_ARK,ACTIVE,True
MEDTB_PERCENTS_ARK,CHANGE_DATE_TIME,True
MEDTB_PERCENTS_ARK,CHANGE_UID,True
API_CALLER_CFG,CALLER_ID,True
API_CALLER_CFG,DISTRICT,True
API_CALLER_CFG,SUMMER_SCHOOL,True
API_CALLER_CFG,CALLER_NAME,True
API_CALLER_CFG,AUTH_TOKEN,True
API_CALLER_CFG,LOG_LEVEL,True
API_CALLER_CFG,MIN_DELTA_CALC_MINUTES,True
API_CALLER_CFG,INCLUDE_OUT_OF_DISTRICT_BLDGS,True
API_CALLER_CFG,INCLUDE_PREREG_STUDENTS,True
API_CALLER_CFG,ACTIVE,True
API_CALLER_CFG,CHANGE_DATE_TIME,True
API_CALLER_CFG,CHANGE_UID,True
API_CALLER_CFG,SIGNATURE_METHOD,True
API_CALLER_CFG,AUTHENTICATION_METHOD,True
SMS_USER_SCREEN_COMB_HDR,DISTRICT,True
SMS_USER_SCREEN_COMB_HDR,COMBINED_SCREEN_TYPE,True
SMS_USER_SCREEN_COMB_HDR,COMBINED_SCREEN_NUMBER,True
SMS_USER_SCREEN_COMB_HDR,DESCRIPTION,True
SMS_USER_SCREEN_COMB_HDR,SEC_PACKAGE,True
SMS_USER_SCREEN_COMB_HDR,SEC_SUBPACKAGE,True
SMS_USER_SCREEN_COMB_HDR,SEC_FEATURE,True
SMS_USER_SCREEN_COMB_HDR,RESERVED,True
SMS_USER_SCREEN_COMB_HDR,CHANGE_DATE_TIME,True
SMS_USER_SCREEN_COMB_HDR,CHANGE_UID,True
SMS_USER_SCREEN_COMB_DET,DISTRICT,True
SMS_USER_SCREEN_COMB_DET,COMBINED_SCREEN_TYPE,True
SMS_USER_SCREEN_COMB_DET,COMBINED_SCREEN_NUMBER,True
SMS_USER_SCREEN_COMB_DET,SCREEN_TYPE,True
SMS_USER_SCREEN_COMB_DET,SCREEN_NUMBER,True
SMS_USER_SCREEN_COMB_DET,SCREEN_ORDER,True
SMS_USER_SCREEN_COMB_DET,HIDE_ON_MENU,True
SMS_USER_SCREEN_COMB_DET,CHANGE_DATE_TIME,True
SMS_USER_SCREEN_COMB_DET,CHANGE_UID,True
PRCH_STU_STATUS,DISTRICT,True
PRCH_STU_STATUS,STUDENT_ID,True
PRCH_STU_STATUS,PESC_FILE_LOC,True
PRCH_STU_STATUS,PENDING_UPLOAD,True
PRCH_STU_STATUS,LAST_UPLOAD_ATT,True
PRCH_STU_STATUS,LAST_UPLOAD_SUC,True
PRCH_STU_STATUS,UPLOAD_RESPONSE,True
PRCH_STU_STATUS,UPLOAD_MESSAGE,True
PRCH_STU_STATUS,CHANGE_DATE_TIME,True
PRCH_STU_STATUS,CHANGE_UID,True
reg_classification,DISTRICT,True
reg_classification,STUDENT_ID,True
reg_classification,CLASSIFICATION_CODE,True
reg_classification,CLASSIFICATION_ORDER,True
reg_classification,CHANGE_DATE_TIME,True
reg_classification,CHANGE_UID,True
REGTB_GENDER_IDENTITY,DISTRICT,True
REGTB_GENDER_IDENTITY,CODE,True
REGTB_GENDER_IDENTITY,DESCRIPTION,True
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_01,True
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_02,True
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_03,True
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_04,True
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_05,True
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_06,True
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_07,True
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_08,True
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_09,True
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_10,True
REGTB_GENDER_IDENTITY,FED_CODE_EQUIV,True
REGTB_GENDER_IDENTITY,ACTIVE,True
REGTB_GENDER_IDENTITY,CHANGE_DATE_TIME,True
REGTB_GENDER_IDENTITY,CHANGE_UID,True
reg_staff_hispanic,DISTRICT,True
reg_staff_hispanic,STAFF_ID,True
reg_staff_hispanic,HISPANIC_CODE,True
reg_staff_hispanic,CHANGE_DATE_TIME,True
reg_staff_hispanic,CHANGE_UID,True
MED_VITALS,ROW_IDENTITY,True
MED_VITALS,MED_OFFICE_ROW_IDENTITY,True
MED_VITALS,CHANGE_DATE_TIME,True
MED_VITALS,CHANGE_UID,True
MED_VITALS,TIME_VITALS_TAKEN,True
MED_VITALS,BLOOD_PRESSURE_SYS,True
MED_VITALS,BLOOD_PRESSURE_DIA,True
MED_VITALS,PULSE,True
MED_VITALS,TEMPERATURE,True
MED_VITALS,TEMPERATURE_METHOD,True
MED_VITALS,RESPIRATION,True
MED_VITALS,PULSE_OXIMETER,True
MEDTB_TEMP_METHOD,CHANGE_DATE_TIME,True
MEDTB_TEMP_METHOD,CHANGE_UID,True
MEDTB_TEMP_METHOD,DISTRICT,True
MEDTB_TEMP_METHOD,CODE,True
MEDTB_TEMP_METHOD,DESCRIPTION,True
MEDTB_TEMP_METHOD,STATE_CODE_EQUIV,True
MEDTB_TEMP_METHOD,ACTIVE,True
REGTB_LEARNING_LOCATION,DISTRICT,True
REGTB_LEARNING_LOCATION,CODE,True
REGTB_LEARNING_LOCATION,DESCRIPTION,True
REGTB_LEARNING_LOCATION,STATE_CODE_EQUIV,True
REGTB_LEARNING_LOCATION,ACTIVE,True
REGTB_LEARNING_LOCATION,CHANGE_DATE_TIME,True
REGTB_LEARNING_LOCATION,CHANGE_UID,True
patb_grad_stat,DISTRICT,True
patb_grad_stat,CODE,True
patb_grad_stat,DESCRIPTION,True
patb_grad_stat,STATE_CODE_EQUIV,True
patb_grad_stat,ACTIVE,True
patb_grad_stat,CHANGE_DATE_TIME,True
patb_grad_stat,CHANGE_UID,True
PESCTB_STU_STATUS,DISTRICT,True
PESCTB_STU_STATUS,STUDENT_ID,True
PESCTB_STU_STATUS,REPORT_ID,True
PESCTB_STU_STATUS,DATASET_ID,True
PESCTB_STU_STATUS,CHANGE_DATE_TIME,True
PESCTB_STU_STATUS,CHANGE_UID,True
PESCTB_DIPLO_XWALK,DISTRICT,True
PESCTB_DIPLO_XWALK,CODE,True
PESCTB_DIPLO_XWALK,ACADEMICAWARDLEVEL,True
PESCTB_DIPLO_XWALK,DIPLOMATYPE,True
PESCTB_DIPLO_XWALK,CHANGE_DATE_TIME,True
PESCTB_DIPLO_XWALK,CHANGE_UID,True
PESCTB_GEND_XWALK,DISTRICT,True
PESCTB_GEND_XWALK,CODE,True
PESCTB_GEND_XWALK,PESCCODE,True
PESCTB_GEND_XWALK,CHANGE_DATE_TIME,True
PESCTB_GEND_XWALK,CHANGE_UID,True
PESCTB_GPA_XWALK,DISTRICT,True
PESCTB_GPA_XWALK,CODE,True
PESCTB_GPA_XWALK,PESCCODE,True
PESCTB_GPA_XWALK,CHANGE_DATE_TIME,True
PESCTB_GPA_XWALK,CHANGE_UID,True
PESCTB_GRADE_XWALK,DISTRICT,True
PESCTB_GRADE_XWALK,CODE,True
PESCTB_GRADE_XWALK,PESCCODE,True
PESCTB_GRADE_XWALK,CHANGE_DATE_TIME,True
PESCTB_GRADE_XWALK,CHANGE_UID,True
ARTB_SE_REASON_NOT_ACCESSED,DISTRICT,True
ARTB_SE_REASON_NOT_ACCESSED,CODE,True
ARTB_SE_REASON_NOT_ACCESSED,DESCRIPTION,True
ARTB_SE_REASON_NOT_ACCESSED,STATE_CODE_EQUIV,True
ARTB_SE_REASON_NOT_ACCESSED,ACTIVE,True
ARTB_SE_REASON_NOT_ACCESSED,CHANGE_DATE_TIME,True
ARTB_SE_REASON_NOT_ACCESSED,CHANGE_UID,True
PESCTB_SHOT_XWALK,DISTRICT,True
PESCTB_SHOT_XWALK,CODE,True
PESCTB_SHOT_XWALK,PESCCODE,True
PESCTB_SHOT_XWALK,PESC_DESC_HELP,True
PESCTB_SHOT_XWALK,CHANGE_DATE_TIME,True
PESCTB_SHOT_XWALK,CHANGE_UID,True
ssp_stu_obj_user,DISTRICT,True
ssp_stu_obj_user,STUDENT_ID,True
ssp_stu_obj_user,PLAN_NUM,True
ssp_stu_obj_user,GOAL,True
ssp_stu_obj_user,SEQUENCE_NUMBER,True
ssp_stu_obj_user,FIELD_NUMBER,True
ssp_stu_obj_user,FIELD_VALUE,True
ssp_stu_obj_user,CHANGE_DATE_TIME,True
ssp_stu_obj_user,CHANGE_UID,True
ssp_rsn_temp_goal,DISTRICT,True
ssp_rsn_temp_goal,QUAL_REASON,True
ssp_rsn_temp_goal,GRADE,True
ssp_rsn_temp_goal,GOAL,True
ssp_rsn_temp_goal,COMMENT,True
ssp_rsn_temp_goal,GOAL_MANAGER,True
ssp_rsn_temp_goal,GOAL_LEVEL,True
ssp_rsn_temp_goal,GOAL_DETAIL,True
ssp_rsn_temp_goal,BASELINE,True
ssp_rsn_temp_goal,CHANGE_DATE_TIME,True
ssp_rsn_temp_goal,CHANGE_UID,True
PESC_TEST_CODE,DISTRICT,True
PESC_TEST_CODE,TEST_CODE,True
PESC_TEST_CODE,TEST_NAME,True
PESC_TEST_CODE,CHANGE_DATE_TIME,True
PESC_TEST_CODE,CHANGE_UID,True
PESC_SUBTEST_CODE,DISTRICT,True
PESC_SUBTEST_CODE,SUBTEST_CODE,True
PESC_SUBTEST_CODE,SUBTEST_NAME,True
PESC_SUBTEST_CODE,CHANGE_DATE_TIME,True
PESC_SUBTEST_CODE,CHANGE_UID,True
mrtb_subj_area_sub,DISTRICT,True
mrtb_subj_area_sub,CODE,True
mrtb_subj_area_sub,DESCRIPTION,True
mrtb_subj_area_sub,CHANGE_DATE_TIME,True
mrtb_subj_area_sub,CHANGE_UID,True
mrtb_st_crs_flags,DISTRICT,True
mrtb_st_crs_flags,FLAG,True
mrtb_st_crs_flags,LABEL,True
mrtb_st_crs_flags,CHANGE_DATE_TIME,True
mrtb_st_crs_flags,CHANGE_UID,True
PESCTB_SUFFIX_XWALK,DISTRICT,True
PESCTB_SUFFIX_XWALK,CODE,True
PESCTB_SUFFIX_XWALK,PESCCODE,True
PESCTB_SUFFIX_XWALK,CHANGE_DATE_TIME,True
PESCTB_SUFFIX_XWALK,CHANGE_UID,True
mrtb_level_hdr_pesc_code,DISTRICT,True
mrtb_level_hdr_pesc_code,CODE,True
mrtb_level_hdr_pesc_code,DESCRIPTION,True
mrtb_level_hdr_pesc_code,CHANGE_DATE_TIME,True
mrtb_level_hdr_pesc_code,CHANGE_UID,True
mrtb_gb_category,DISTRICT,True
mrtb_gb_category,CODE,True
mrtb_gb_category,DESCRIPTION,True
mrtb_gb_category,CATEGORY_ID,True
mrtb_gb_category,CHANGE_DATE_TIME,True
mrtb_gb_category,CHANGE_UID,True
mr_trn_view_hdr,DISTRICT,True
mr_trn_view_hdr,BUILDING,True
mr_trn_view_hdr,TYPE,True
mr_trn_view_hdr,GRADE,True
mr_trn_view_hdr,GROUP_BY,True
mr_trn_view_hdr,DISPLAY_ATTCREDIT,True
mr_trn_view_hdr,DISPLAY_ERNCREDIT,True
mr_trn_view_hdr,DISPLAY_CRSLEVEL,True
mr_trn_view_hdr,DISPLAY_CRSTYPE,True
mr_trn_view_hdr,STU_ADDRESS_TYPE,True
mr_trn_view_hdr,PRINT_BLDG_INFO,True
mr_trn_view_hdr,PRINT_STU_DATA,True
mr_trn_view_hdr,PRINT_CREDIT_SUM,True
mr_trn_view_hdr,CRS_AREA_GPA,True
mr_trn_view_hdr,PRINT_CLASS_RANK,True
mr_trn_view_hdr,PRINT_COMMENTS,True
mr_trn_view_hdr,PRINT_ACTIVITIES,True
mr_trn_view_hdr,PRINT_GRAD_REQ,True
mr_trn_view_hdr,CEEB_NUMBER,True
mr_trn_view_hdr,HEADER_TEXT,True
mr_trn_view_hdr,FOOTER_TEXT,True
mr_trn_view_hdr,REPORT_TEMPLATE,True
mr_trn_view_hdr,CHANGE_DATE_TIME,True
mr_trn_view_hdr,CHANGE_UID,True
mr_trn_prt_stu_req,DISTRICT,True
mr_trn_prt_stu_req,MR_TRN_PRINT_KEY,True
mr_trn_prt_stu_req,STUDENT_ID,True
mr_trn_prt_stu_req,REQ_GROUP,True
mr_trn_prt_stu_req,GRADUATION_YEAR,True
mr_trn_prt_stu_req,REQUIRE_CODE01,True
mr_trn_prt_stu_req,REQUIRE_CODE02,True
mr_trn_prt_stu_req,REQUIRE_CODE03,True
mr_trn_prt_stu_req,REQUIRE_CODE04,True
mr_trn_prt_stu_req,REQUIRE_CODE05,True
mr_trn_prt_stu_req,REQUIRE_CODE06,True
mr_trn_prt_stu_req,REQUIRE_CODE07,True
mr_trn_prt_stu_req,REQUIRE_CODE08,True
mr_trn_prt_stu_req,REQUIRE_CODE09,True
mr_trn_prt_stu_req,REQUIRE_CODE10,True
mr_trn_prt_stu_req,REQUIRE_CODE11,True
mr_trn_prt_stu_req,REQUIRE_CODE12,True
mr_trn_prt_stu_req,REQUIRE_CODE13,True
mr_trn_prt_stu_req,REQUIRE_CODE14,True
mr_trn_prt_stu_req,REQUIRE_CODE15,True
mr_trn_prt_stu_req,REQUIRE_CODE16,True
mr_trn_prt_stu_req,REQUIRE_CODE17,True
mr_trn_prt_stu_req,REQUIRE_CODE18,True
mr_trn_prt_stu_req,REQUIRE_CODE19,True
mr_trn_prt_stu_req,REQUIRE_CODE20,True
mr_trn_prt_stu_req,REQUIRE_CODE21,True
mr_trn_prt_stu_req,REQUIRE_CODE22,True
mr_trn_prt_stu_req,REQUIRE_CODE23,True
mr_trn_prt_stu_req,REQUIRE_CODE24,True
mr_trn_prt_stu_req,REQUIRE_CODE25,True
mr_trn_prt_stu_req,REQUIRE_CODE26,True
mr_trn_prt_stu_req,REQUIRE_CODE27,True
mr_trn_prt_stu_req,REQUIRE_CODE28,True
mr_trn_prt_stu_req,REQUIRE_CODE29,True
mr_trn_prt_stu_req,REQUIRE_CODE30,True
mr_trn_prt_stu_req,REQUIRE_DESC01,True
mr_trn_prt_stu_req,REQUIRE_DESC02,True
mr_trn_prt_stu_req,REQUIRE_DESC03,True
mr_trn_prt_stu_req,REQUIRE_DESC04,True
mr_trn_prt_stu_req,REQUIRE_DESC05,True
mr_trn_prt_stu_req,REQUIRE_DESC06,True
mr_trn_prt_stu_req,REQUIRE_DESC07,True
mr_trn_prt_stu_req,REQUIRE_DESC08,True
mr_trn_prt_stu_req,REQUIRE_DESC09,True
mr_trn_prt_stu_req,REQUIRE_DESC10,True
mr_trn_prt_stu_req,REQUIRE_DESC11,True
mr_trn_prt_stu_req,REQUIRE_DESC12,True
mr_trn_prt_stu_req,REQUIRE_DESC13,True
mr_trn_prt_stu_req,REQUIRE_DESC14,True
mr_trn_prt_stu_req,REQUIRE_DESC15,True
mr_trn_prt_stu_req,REQUIRE_DESC16,True
mr_trn_prt_stu_req,REQUIRE_DESC17,True
mr_trn_prt_stu_req,REQUIRE_DESC18,True
mr_trn_prt_stu_req,REQUIRE_DESC19,True
mr_trn_prt_stu_req,REQUIRE_DESC20,True
mr_trn_prt_stu_req,REQUIRE_DESC21,True
mr_trn_prt_stu_req,REQUIRE_DESC22,True
mr_trn_prt_stu_req,REQUIRE_DESC23,True
mr_trn_prt_stu_req,REQUIRE_DESC24,True
mr_trn_prt_stu_req,REQUIRE_DESC25,True
mr_trn_prt_stu_req,REQUIRE_DESC26,True
mr_trn_prt_stu_req,REQUIRE_DESC27,True
mr_trn_prt_stu_req,REQUIRE_DESC28,True
mr_trn_prt_stu_req,REQUIRE_DESC29,True
mr_trn_prt_stu_req,REQUIRE_DESC30,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT01,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT02,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT03,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT04,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT05,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT06,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT07,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT08,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT09,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT10,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT11,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT12,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT13,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT14,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT15,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT16,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT17,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT18,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT19,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT20,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT21,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT22,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT23,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT24,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT25,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT26,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT27,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT28,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT29,True
mr_trn_prt_stu_req,SUBJ_AREA_CREDIT30,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS01,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS02,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS03,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS04,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS05,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS06,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS07,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS08,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS09,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS10,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS11,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS12,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS13,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS14,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS15,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS16,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS17,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS18,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS19,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS20,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS21,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS22,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS23,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS24,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS25,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS26,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS27,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS28,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS29,True
mr_trn_prt_stu_req,CUR_ATT_CREDITS30,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS01,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS02,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS03,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS04,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS05,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS06,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS07,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS08,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS09,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS10,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS11,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS12,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS13,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS14,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS15,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS16,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS17,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS18,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS19,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS20,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS21,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS22,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS23,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS24,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS25,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS26,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS27,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS28,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS29,True
mr_trn_prt_stu_req,CUR_EARN_CREDITS30,True
mr_trn_prt_stu_req,CHANGE_DATE_TIME,True
mr_trn_prt_stu_req,CHANGE_UID,True
PESCTB_TERM_XWALK,DISTRICT,True
PESCTB_TERM_XWALK,BUILDING,True
PESCTB_TERM_XWALK,RUNTERMYEAR,True
PESCTB_TERM_XWALK,PESCCODE,True
PESCTB_TERM_XWALK,CHANGE_DATE_TIME,True
PESCTB_TERM_XWALK,CHANGE_UID,True
mr_trn_prt_stu_hdr,DISTRICT,True
mr_trn_prt_stu_hdr,TRN_PRINT_KEY,True
mr_trn_prt_stu_hdr,STUDENT_ID,True
mr_trn_prt_stu_hdr,STUDENT_NAME,True
mr_trn_prt_stu_hdr,BUILDING,True
mr_trn_prt_stu_hdr,GRADE,True
mr_trn_prt_stu_hdr,TRACK,True
mr_trn_prt_stu_hdr,COUNSELOR,True
mr_trn_prt_stu_hdr,HOUSE_TEAM,True
mr_trn_prt_stu_hdr,HOMEROOM_PRIMARY,True
mr_trn_prt_stu_hdr,BIRTHDATE,True
mr_trn_prt_stu_hdr,GRADUATION_YEAR,True
mr_trn_prt_stu_hdr,GRADUATION_DATE,True
mr_trn_prt_stu_hdr,GENDER,True
mr_trn_prt_stu_hdr,GUARDIAN_NAME,True
mr_trn_prt_stu_hdr,PHONE,True
mr_trn_prt_stu_hdr,APARTMENT,True
mr_trn_prt_stu_hdr,COMPLEX,True
mr_trn_prt_stu_hdr,STREET_NUMBER,True
mr_trn_prt_stu_hdr,STREET_PREFIX,True
mr_trn_prt_stu_hdr,STREET_NAME,True
mr_trn_prt_stu_hdr,STREET_SUFFIX,True
mr_trn_prt_stu_hdr,STREET_TYPE,True
mr_trn_prt_stu_hdr,CITY,True
mr_trn_prt_stu_hdr,STATE,True
mr_trn_prt_stu_hdr,ZIP,True
mr_trn_prt_stu_hdr,DAILY_ATT_DESCR_01,True
mr_trn_prt_stu_hdr,DAILY_ATT_DESCR_02,True
mr_trn_prt_stu_hdr,DAILY_ATT_DESCR_03,True
mr_trn_prt_stu_hdr,DAILY_ATT_DESCR_04,True
mr_trn_prt_stu_hdr,DAILY_ATT_DESCR_05,True
mr_trn_prt_stu_hdr,DAILY_ATT_DESCR_06,True
mr_trn_prt_stu_hdr,DAILY_ATT_DESCR_07,True
mr_trn_prt_stu_hdr,DAILY_ATT_DESCR_08,True
mr_trn_prt_stu_hdr,DAILY_ATT_DESCR_09,True
mr_trn_prt_stu_hdr,DAILY_ATT_DESCR_10,True
mr_trn_prt_stu_hdr,DAILY_ATT_TOT_01,True
mr_trn_prt_stu_hdr,DAILY_ATT_TOT_02,True
mr_trn_prt_stu_hdr,DAILY_ATT_TOT_03,True
mr_trn_prt_stu_hdr,DAILY_ATT_TOT_04,True
mr_trn_prt_stu_hdr,DAILY_ATT_TOT_05,True
mr_trn_prt_stu_hdr,DAILY_ATT_TOT_06,True
mr_trn_prt_stu_hdr,DAILY_ATT_TOT_07,True
mr_trn_prt_stu_hdr,DAILY_ATT_TOT_08,True
mr_trn_prt_stu_hdr,DAILY_ATT_TOT_09,True
mr_trn_prt_stu_hdr,DAILY_ATT_TOT_10,True
mr_trn_prt_stu_hdr,GPA_TYPE_01,True
mr_trn_prt_stu_hdr,GPA_TYPE_02,True
mr_trn_prt_stu_hdr,GPA_TYPE_03,True
mr_trn_prt_stu_hdr,GPA_TYPE_04,True
mr_trn_prt_stu_hdr,GPA_TYPE_05,True
mr_trn_prt_stu_hdr,GPA_TYPE_06,True
mr_trn_prt_stu_hdr,GPA_TYPE_07,True
mr_trn_prt_stu_hdr,GPA_TYPE_08,True
mr_trn_prt_stu_hdr,GPA_TYPE_09,True
mr_trn_prt_stu_hdr,GPA_TYPE_10,True
mr_trn_prt_stu_hdr,GPA_DESCR_01,True
mr_trn_prt_stu_hdr,GPA_DESCR_02,True
mr_trn_prt_stu_hdr,GPA_DESCR_03,True
mr_trn_prt_stu_hdr,GPA_DESCR_04,True
mr_trn_prt_stu_hdr,GPA_DESCR_05,True
mr_trn_prt_stu_hdr,GPA_DESCR_06,True
mr_trn_prt_stu_hdr,GPA_DESCR_07,True
mr_trn_prt_stu_hdr,GPA_DESCR_08,True
mr_trn_prt_stu_hdr,GPA_DESCR_09,True
mr_trn_prt_stu_hdr,GPA_DESCR_10,True
mr_trn_prt_stu_hdr,GPA_CUM_01,True
mr_trn_prt_stu_hdr,GPA_CUM_02,True
mr_trn_prt_stu_hdr,GPA_CUM_03,True
mr_trn_prt_stu_hdr,GPA_CUM_04,True
mr_trn_prt_stu_hdr,GPA_CUM_05,True
mr_trn_prt_stu_hdr,GPA_CUM_06,True
mr_trn_prt_stu_hdr,GPA_CUM_07,True
mr_trn_prt_stu_hdr,GPA_CUM_08,True
mr_trn_prt_stu_hdr,GPA_CUM_09,True
mr_trn_prt_stu_hdr,GPA_CUM_10,True
mr_trn_prt_stu_hdr,GPA_RANK_01,True
mr_trn_prt_stu_hdr,GPA_RANK_02,True
mr_trn_prt_stu_hdr,GPA_RANK_03,True
mr_trn_prt_stu_hdr,GPA_RANK_04,True
mr_trn_prt_stu_hdr,GPA_RANK_05,True
mr_trn_prt_stu_hdr,GPA_RANK_06,True
mr_trn_prt_stu_hdr,GPA_RANK_07,True
mr_trn_prt_stu_hdr,GPA_RANK_08,True
mr_trn_prt_stu_hdr,GPA_RANK_09,True
mr_trn_prt_stu_hdr,GPA_RANK_10,True
mr_trn_prt_stu_hdr,GPA_PERCENTILE_01,True
mr_trn_prt_stu_hdr,GPA_PERCENTILE_02,True
mr_trn_prt_stu_hdr,GPA_PERCENTILE_03,True
mr_trn_prt_stu_hdr,GPA_PERCENTILE_04,True
mr_trn_prt_stu_hdr,GPA_PERCENTILE_05,True
mr_trn_prt_stu_hdr,GPA_PERCENTILE_06,True
mr_trn_prt_stu_hdr,GPA_PERCENTILE_07,True
mr_trn_prt_stu_hdr,GPA_PERCENTILE_08,True
mr_trn_prt_stu_hdr,GPA_PERCENTILE_09,True
mr_trn_prt_stu_hdr,GPA_PERCENTILE_10,True
mr_trn_prt_stu_hdr,GPA_DECILE_01,True
mr_trn_prt_stu_hdr,GPA_DECILE_02,True
mr_trn_prt_stu_hdr,GPA_DECILE_03,True
mr_trn_prt_stu_hdr,GPA_DECILE_04,True
mr_trn_prt_stu_hdr,GPA_DECILE_05,True
mr_trn_prt_stu_hdr,GPA_DECILE_06,True
mr_trn_prt_stu_hdr,GPA_DECILE_07,True
mr_trn_prt_stu_hdr,GPA_DECILE_08,True
mr_trn_prt_stu_hdr,GPA_DECILE_09,True
mr_trn_prt_stu_hdr,GPA_DECILE_10,True
mr_trn_prt_stu_hdr,GPA_QUARTILE_01,True
mr_trn_prt_stu_hdr,GPA_QUARTILE_02,True
mr_trn_prt_stu_hdr,GPA_QUARTILE_03,True
mr_trn_prt_stu_hdr,GPA_QUARTILE_04,True
mr_trn_prt_stu_hdr,GPA_QUARTILE_05,True
mr_trn_prt_stu_hdr,GPA_QUARTILE_06,True
mr_trn_prt_stu_hdr,GPA_QUARTILE_07,True
mr_trn_prt_stu_hdr,GPA_QUARTILE_08,True
mr_trn_prt_stu_hdr,GPA_QUARTILE_09,True
mr_trn_prt_stu_hdr,GPA_QUARTILE_10,True
mr_trn_prt_stu_hdr,GPA_QUINTILE_01,True
mr_trn_prt_stu_hdr,GPA_QUINTILE_02,True
mr_trn_prt_stu_hdr,GPA_QUINTILE_03,True
mr_trn_prt_stu_hdr,GPA_QUINTILE_04,True
mr_trn_prt_stu_hdr,GPA_QUINTILE_05,True
mr_trn_prt_stu_hdr,GPA_QUINTILE_06,True
mr_trn_prt_stu_hdr,GPA_QUINTILE_07,True
mr_trn_prt_stu_hdr,GPA_QUINTILE_08,True
mr_trn_prt_stu_hdr,GPA_QUINTILE_09,True
mr_trn_prt_stu_hdr,GPA_QUINTILE_10,True
mr_trn_prt_stu_hdr,GPA_CLASS_SIZE_01,True
mr_trn_prt_stu_hdr,GPA_CLASS_SIZE_02,True
mr_trn_prt_stu_hdr,GPA_CLASS_SIZE_03,True
mr_trn_prt_stu_hdr,GPA_CLASS_SIZE_04,True
mr_trn_prt_stu_hdr,GPA_CLASS_SIZE_05,True
mr_trn_prt_stu_hdr,GPA_CLASS_SIZE_06,True
mr_trn_prt_stu_hdr,GPA_CLASS_SIZE_07,True
mr_trn_prt_stu_hdr,GPA_CLASS_SIZE_08,True
mr_trn_prt_stu_hdr,GPA_CLASS_SIZE_09,True
mr_trn_prt_stu_hdr,GPA_CLASS_SIZE_10,True
mr_trn_prt_stu_hdr,REPORT_TEMPLATE,True
mr_trn_prt_stu_hdr,GENDER_IDENTITY,True
mr_trn_prt_stu_hdr,CHANGE_DATE_TIME,True
mr_trn_prt_stu_hdr,CHANGE_UID,True
mr_trn_prt_stu_det,DISTRICT,True
mr_trn_prt_stu_det,MR_TRN_PRINT_KEY,True
mr_trn_prt_stu_det,STUDENT_ID,True
mr_trn_prt_stu_det,SECTION_KEY,True
mr_trn_prt_stu_det,COURSE_BUILDING,True
mr_trn_prt_stu_det,COURSE,True
mr_trn_prt_stu_det,COURSE_SECTION,True
mr_trn_prt_stu_det,COURSE_SESSION,True
mr_trn_prt_stu_det,RUN_TERM_YEAR,True
mr_trn_prt_stu_det,SCHOOL_YEAR,True
mr_trn_prt_stu_det,STUDENT_GRADE,True
mr_trn_prt_stu_det,DESCRIPTION,True
mr_trn_prt_stu_det,CRS_PERIOD,True
mr_trn_prt_stu_det,COURSE_LEVEL,True
mr_trn_prt_stu_det,PRIMARY_STAFF_ID,True
mr_trn_prt_stu_det,STAFF_NAME,True
mr_trn_prt_stu_det,ROOM_ID,True
mr_trn_prt_stu_det,ATTEMPTED_CREDIT,True
mr_trn_prt_stu_det,EARNED_CREDIT,True
mr_trn_prt_stu_det,DEPARTMENT,True
mr_trn_prt_stu_det,DEPT_DESCR,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_01,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_02,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_03,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_04,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_05,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_06,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_07,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_08,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_09,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_10,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_11,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_12,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_13,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_14,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_15,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_16,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_17,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_18,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_19,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_20,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_21,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_22,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_23,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_24,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_25,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_26,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_27,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_28,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_29,True
mr_trn_prt_stu_det,TRN_DATA_VALUE_30,True
mr_trn_prt_stu_det,CHANGE_DATE_TIME,True
mr_trn_prt_stu_det,CHANGE_UID,True
PESCTB_SCORE_XWALK,DISTRICT,True
PESCTB_SCORE_XWALK,CODE,True
PESCTB_SCORE_XWALK,PESCCODE,True
PESCTB_SCORE_XWALK,CHANGE_DATE_TIME,True
PESCTB_SCORE_XWALK,CHANGE_UID,True
Mr_trn_prt_stu_brk,DISTRICT,True
Mr_trn_prt_stu_brk,MR_TRN_PRINT_KEY,True
Mr_trn_prt_stu_brk,STUDENT_ID,True
Mr_trn_prt_stu_brk,SCHOOL_YEAR,True
Mr_trn_prt_stu_brk,RUN_TERM_YEAR,True
Mr_trn_prt_stu_brk,DISPLAY_YEAR,True
Mr_trn_prt_stu_brk,STUDENT_GRADE,True
Mr_trn_prt_stu_brk,CUR_GPA,True
Mr_trn_prt_stu_brk,CUM_GPA,True
Mr_trn_prt_stu_brk,BUILDING,True
Mr_trn_prt_stu_brk,BLDG_NAME,True
Mr_trn_prt_stu_brk,CHANGE_DATE_TIME,True
Mr_trn_prt_stu_brk,CHANGE_UID,True
Mr_trn_prt_stu_ltd,DISTRICT,True
Mr_trn_prt_stu_ltd,MR_TRN_PRINT_KEY,True
Mr_trn_prt_stu_ltd,STUDENT_ID,True
Mr_trn_prt_stu_ltd,TEST_CODE,True
Mr_trn_prt_stu_ltd,TEST_DATE,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_01,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_02,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_03,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_04,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_05,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_06,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_07,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_08,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_09,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_10,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_11,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_12,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_13,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_14,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_15,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_16,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_17,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_18,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_19,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_20,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_21,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_22,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_23,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_24,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_25,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_26,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_27,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_28,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_29,True
Mr_trn_prt_stu_ltd,LTDB_TITLE_30,True
Mr_trn_prt_stu_ltd,SCORE01,True
Mr_trn_prt_stu_ltd,SCORE02,True
Mr_trn_prt_stu_ltd,SCORE03,True
Mr_trn_prt_stu_ltd,SCORE04,True
Mr_trn_prt_stu_ltd,SCORE05,True
Mr_trn_prt_stu_ltd,SCORE06,True
Mr_trn_prt_stu_ltd,SCORE07,True
Mr_trn_prt_stu_ltd,SCORE08,True
Mr_trn_prt_stu_ltd,SCORE09,True
Mr_trn_prt_stu_ltd,SCORE10,True
Mr_trn_prt_stu_ltd,SCORE11,True
Mr_trn_prt_stu_ltd,SCORE12,True
Mr_trn_prt_stu_ltd,SCORE13,True
Mr_trn_prt_stu_ltd,SCORE14,True
Mr_trn_prt_stu_ltd,SCORE15,True
Mr_trn_prt_stu_ltd,SCORE16,True
Mr_trn_prt_stu_ltd,SCORE17,True
Mr_trn_prt_stu_ltd,SCORE18,True
Mr_trn_prt_stu_ltd,SCORE19,True
Mr_trn_prt_stu_ltd,SCORE20,True
Mr_trn_prt_stu_ltd,SCORE21,True
Mr_trn_prt_stu_ltd,SCORE22,True
Mr_trn_prt_stu_ltd,SCORE23,True
Mr_trn_prt_stu_ltd,SCORE24,True
Mr_trn_prt_stu_ltd,SCORE25,True
Mr_trn_prt_stu_ltd,SCORE26,True
Mr_trn_prt_stu_ltd,SCORE27,True
Mr_trn_prt_stu_ltd,SCORE28,True
Mr_trn_prt_stu_ltd,SCORE29,True
Mr_trn_prt_stu_ltd,SCORE30,True
Mr_trn_prt_stu_ltd,TEST_DATE01,True
Mr_trn_prt_stu_ltd,TEST_DATE02,True
Mr_trn_prt_stu_ltd,TEST_DATE03,True
Mr_trn_prt_stu_ltd,TEST_DATE04,True
Mr_trn_prt_stu_ltd,TEST_DATE05,True
Mr_trn_prt_stu_ltd,TEST_DATE06,True
Mr_trn_prt_stu_ltd,TEST_DATE07,True
Mr_trn_prt_stu_ltd,TEST_DATE08,True
Mr_trn_prt_stu_ltd,TEST_DATE09,True
Mr_trn_prt_stu_ltd,TEST_DATE10,True
Mr_trn_prt_stu_ltd,TEST_DATE11,True
Mr_trn_prt_stu_ltd,TEST_DATE12,True
Mr_trn_prt_stu_ltd,TEST_DATE13,True
Mr_trn_prt_stu_ltd,TEST_DATE14,True
Mr_trn_prt_stu_ltd,TEST_DATE15,True
Mr_trn_prt_stu_ltd,TEST_DATE16,True
Mr_trn_prt_stu_ltd,TEST_DATE17,True
Mr_trn_prt_stu_ltd,TEST_DATE18,True
Mr_trn_prt_stu_ltd,TEST_DATE19,True
Mr_trn_prt_stu_ltd,TEST_DATE20,True
Mr_trn_prt_stu_ltd,TEST_DATE21,True
Mr_trn_prt_stu_ltd,TEST_DATE22,True
Mr_trn_prt_stu_ltd,TEST_DATE23,True
Mr_trn_prt_stu_ltd,TEST_DATE24,True
Mr_trn_prt_stu_ltd,TEST_DATE25,True
Mr_trn_prt_stu_ltd,TEST_DATE26,True
Mr_trn_prt_stu_ltd,TEST_DATE27,True
Mr_trn_prt_stu_ltd,TEST_DATE28,True
Mr_trn_prt_stu_ltd,TEST_DATE29,True
Mr_trn_prt_stu_ltd,TEST_DATE30,True
Mr_trn_prt_stu_ltd,CHANGE_DATE_TIME,True
Mr_trn_prt_stu_ltd,CHANGE_UID,True
Mr_trn_prt_crs_ud,DISTRICT,True
Mr_trn_prt_crs_ud,MR_TRN_PRINT_KEY,True
Mr_trn_prt_crs_ud,SECTION_KEY,True
Mr_trn_prt_crs_ud,FIELD_LABEL01,True
Mr_trn_prt_crs_ud,FIELD_LABEL02,True
Mr_trn_prt_crs_ud,FIELD_LABEL03,True
Mr_trn_prt_crs_ud,FIELD_LABEL04,True
Mr_trn_prt_crs_ud,FIELD_LABEL05,True
Mr_trn_prt_crs_ud,FIELD_LABEL06,True
Mr_trn_prt_crs_ud,FIELD_LABEL07,True
Mr_trn_prt_crs_ud,FIELD_LABEL08,True
Mr_trn_prt_crs_ud,FIELD_LABEL09,True
Mr_trn_prt_crs_ud,FIELD_LABEL10,True
Mr_trn_prt_crs_ud,FIELD_VALUE01,True
Mr_trn_prt_crs_ud,FIELD_VALUE02,True
Mr_trn_prt_crs_ud,FIELD_VALUE03,True
Mr_trn_prt_crs_ud,FIELD_VALUE04,True
Mr_trn_prt_crs_ud,FIELD_VALUE05,True
Mr_trn_prt_crs_ud,FIELD_VALUE06,True
Mr_trn_prt_crs_ud,FIELD_VALUE07,True
Mr_trn_prt_crs_ud,FIELD_VALUE08,True
Mr_trn_prt_crs_ud,FIELD_VALUE09,True
Mr_trn_prt_crs_ud,FIELD_VALUE10,True
Mr_trn_prt_crs_ud,CHANGE_DATE_TIME,True
Mr_trn_prt_crs_ud,CHANGE_UID,True
Mr_trn_print_hdr,DISTRICT,True
Mr_trn_print_hdr,SCHOOL_YEAR,True
Mr_trn_print_hdr,BUILDING,True
Mr_trn_print_hdr,GROUP_BY,True
Mr_trn_print_hdr,GRADE,True
Mr_trn_print_hdr,RUN_TERM_YEAR,True
Mr_trn_print_hdr,RUN_DATE,True
Mr_trn_print_hdr,TRN_PRINT_KEY,True
Mr_trn_print_hdr,BLDG_NAME,True
Mr_trn_print_hdr,STREET1,True
Mr_trn_print_hdr,STREET2,True
Mr_trn_print_hdr,CITY,True
Mr_trn_print_hdr,STATE,True
Mr_trn_print_hdr,ZIP,True
Mr_trn_print_hdr,PRINCIPAL,True
Mr_trn_print_hdr,PHONE,True
Mr_trn_print_hdr,CEEB_NUMBER,True
Mr_trn_print_hdr,HEADER_TEXT,True
Mr_trn_print_hdr,FOOTER_TEXT,True
Mr_trn_print_hdr,DATA_TITLE_01,True
Mr_trn_print_hdr,DATA_TITLE_02,True
Mr_trn_print_hdr,DATA_TITLE_03,True
Mr_trn_print_hdr,DATA_TITLE_04,True
Mr_trn_print_hdr,DATA_TITLE_05,True
Mr_trn_print_hdr,DATA_TITLE_06,True
Mr_trn_print_hdr,DATA_TITLE_07,True
Mr_trn_print_hdr,DATA_TITLE_08,True
Mr_trn_print_hdr,DATA_TITLE_09,True
Mr_trn_print_hdr,DATA_TITLE_10,True
Mr_trn_print_hdr,DATA_TITLE_11,True
Mr_trn_print_hdr,DATA_TITLE_12,True
Mr_trn_print_hdr,DATA_TITLE_13,True
Mr_trn_print_hdr,DATA_TITLE_14,True
Mr_trn_print_hdr,DATA_TITLE_15,True
Mr_trn_print_hdr,DATA_TITLE_16,True
Mr_trn_print_hdr,DATA_TITLE_17,True
Mr_trn_print_hdr,DATA_TITLE_18,True
Mr_trn_print_hdr,DATA_TITLE_19,True
Mr_trn_print_hdr,DATA_TITLE_20,True
Mr_trn_print_hdr,DATA_TITLE_21,True
Mr_trn_print_hdr,DATA_TITLE_22,True
Mr_trn_print_hdr,DATA_TITLE_23,True
Mr_trn_print_hdr,DATA_TITLE_24,True
Mr_trn_print_hdr,DATA_TITLE_25,True
Mr_trn_print_hdr,DATA_TITLE_26,True
Mr_trn_print_hdr,DATA_TITLE_27,True
Mr_trn_print_hdr,DATA_TITLE_28,True
Mr_trn_print_hdr,DATA_TITLE_29,True
Mr_trn_print_hdr,DATA_TITLE_30,True
Mr_trn_print_hdr,CHANGE_DATE_TIME,True
Mr_trn_print_hdr,CHANGE_UID,True
Mr_stu_xfer_runs,DISTRICT,True
Mr_stu_xfer_runs,SCHOOL_YEAR,True
Mr_stu_xfer_runs,STUDENT_ID,True
Mr_stu_xfer_runs,TRANSFER_SEQUENCE,True
Mr_stu_xfer_runs,RC_RUN,True
Mr_stu_xfer_runs,CHANGE_DATE_TIME,True
Mr_stu_xfer_runs,CHANGE_UID,True
Mr_trn_prt_stu_com,DISTRICT,True
Mr_trn_prt_stu_com,MR_TRN_PRINT_KEY,True
Mr_trn_prt_stu_com,STUDENT_ID,True
Mr_trn_prt_stu_com,COMMENT01,True
Mr_trn_prt_stu_com,COMMENT02,True
Mr_trn_prt_stu_com,COMMENT03,True
Mr_trn_prt_stu_com,COMMENT04,True
Mr_trn_prt_stu_com,COMMENT05,True
Mr_trn_prt_stu_com,COMMENT06,True
Mr_trn_prt_stu_com,COMMENT07,True
Mr_trn_prt_stu_com,COMMENT08,True
Mr_trn_prt_stu_com,COMMENT09,True
Mr_trn_prt_stu_com,COMMENT10,True
Mr_trn_prt_stu_com,COMMENT11,True
Mr_trn_prt_stu_com,COMMENT12,True
Mr_trn_prt_stu_com,COMMENT13,True
Mr_trn_prt_stu_com,COMMENT14,True
Mr_trn_prt_stu_com,COMMENT15,True
Mr_trn_prt_stu_com,COMMENT16,True
Mr_trn_prt_stu_com,COMMENT17,True
Mr_trn_prt_stu_com,COMMENT18,True
Mr_trn_prt_stu_com,COMMENT19,True
Mr_trn_prt_stu_com,COMMENT20,True
Mr_trn_prt_stu_com,COMMENT21,True
Mr_trn_prt_stu_com,COMMENT22,True
Mr_trn_prt_stu_com,COMMENT23,True
Mr_trn_prt_stu_com,COMMENT24,True
Mr_trn_prt_stu_com,COMMENT25,True
Mr_trn_prt_stu_com,COMMENT26,True
Mr_trn_prt_stu_com,COMMENT27,True
Mr_trn_prt_stu_com,COMMENT28,True
Mr_trn_prt_stu_com,COMMENT29,True
Mr_trn_prt_stu_com,COMMENT30,True
Mr_trn_prt_stu_com,CHANGE_DATE_TIME,True
Mr_trn_prt_stu_com,CHANGE_UID,True
mr_stu_user,DISTRICT,True
mr_stu_user,SECTION_KEY,True
mr_stu_user,COURSE_SESSION,True
mr_stu_user,STUDENT_ID,True
mr_stu_user,SCREEN_NUMBER,True
mr_stu_user,FIELD_NUMBER,True
mr_stu_user,FIELD_VALUE,True
mr_stu_user,CHANGE_DATE_TIME,True
mr_stu_user,CHANGE_UID,True
mrtb_markovr_reason,DISTRICT,True
mrtb_markovr_reason,CODE,True
mrtb_markovr_reason,DESCRIPTION,True
mrtb_markovr_reason,CHANGE_DATE_TIME,True
mrtb_markovr_reason,CHANGE_UID,True
Mr_trn_prt_stu_act,DISTRICT,True
Mr_trn_prt_stu_act,MR_TRN_PRINT_KEY,True
Mr_trn_prt_stu_act,STUDENT_ID,True
Mr_trn_prt_stu_act,ACTIVITY01,True
Mr_trn_prt_stu_act,ACTIVITY02,True
Mr_trn_prt_stu_act,ACTIVITY03,True
Mr_trn_prt_stu_act,ACTIVITY04,True
Mr_trn_prt_stu_act,ACTIVITY05,True
Mr_trn_prt_stu_act,ACTIVITY06,True
Mr_trn_prt_stu_act,ACTIVITY07,True
Mr_trn_prt_stu_act,ACTIVITY08,True
Mr_trn_prt_stu_act,ACTIVITY09,True
Mr_trn_prt_stu_act,ACTIVITY10,True
Mr_trn_prt_stu_act,ACTIVITY11,True
Mr_trn_prt_stu_act,ACTIVITY12,True
Mr_trn_prt_stu_act,ACTIVITY13,True
Mr_trn_prt_stu_act,ACTIVITY14,True
Mr_trn_prt_stu_act,ACTIVITY15,True
Mr_trn_prt_stu_act,ACTIVITY16,True
Mr_trn_prt_stu_act,ACTIVITY17,True
Mr_trn_prt_stu_act,ACTIVITY18,True
Mr_trn_prt_stu_act,ACTIVITY19,True
Mr_trn_prt_stu_act,ACTIVITY20,True
Mr_trn_prt_stu_act,ACTIVITY21,True
Mr_trn_prt_stu_act,ACTIVITY22,True
Mr_trn_prt_stu_act,ACTIVITY23,True
Mr_trn_prt_stu_act,ACTIVITY24,True
Mr_trn_prt_stu_act,ACTIVITY25,True
Mr_trn_prt_stu_act,ACTIVITY26,True
Mr_trn_prt_stu_act,ACTIVITY27,True
Mr_trn_prt_stu_act,ACTIVITY28,True
Mr_trn_prt_stu_act,ACTIVITY29,True
Mr_trn_prt_stu_act,ACTIVITY30,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS01,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS02,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS03,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS04,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS05,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS06,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS07,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS08,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS09,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS10,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS11,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS12,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS13,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS14,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS15,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS16,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS17,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS18,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS19,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS20,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS21,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS22,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS23,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS24,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS25,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS26,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS27,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS28,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS29,True
Mr_trn_prt_stu_act,ACTIVITY_YEARS30,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS01,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS02,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS03,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS04,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS05,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS06,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS07,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS08,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS09,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS10,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS11,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS12,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS13,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS14,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS15,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS16,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS17,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS18,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS19,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS20,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS21,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS22,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS23,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS24,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS25,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS26,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS27,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS28,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS29,True
Mr_trn_prt_stu_act,ACTIVITY_COMMENTS30,True
Mr_trn_prt_stu_act,CHANGE_DATE_TIME,True
Mr_trn_prt_stu_act,CHANGE_UID,True
mr_stu_mp_comments,DISTRICT,True
mr_stu_mp_comments,STUDENT_ID,True
mr_stu_mp_comments,SECTION_KEY,True
mr_stu_mp_comments,COURSE_SESSION,True
mr_stu_mp_comments,MARKING_PERIOD,True
mr_stu_mp_comments,COMMENT_TYPE,True
mr_stu_mp_comments,CODE,True
mr_stu_mp_comments,CHANGE_DATE_TIME,True
mr_stu_mp_comments,CHANGE_UID,True
mr_stu_mp,DISTRICT,True
mr_stu_mp,STUDENT_ID,True
mr_stu_mp,SECTION_KEY,True
mr_stu_mp,COURSE_SESSION,True
mr_stu_mp,MARKING_PERIOD,True
mr_stu_mp,ATT_CREDIT,True
mr_stu_mp,ATT_OVERRIDE,True
mr_stu_mp,ATT_OVR_REASON,True
mr_stu_mp,EARN_CREDIT,True
mr_stu_mp,EARN_OVERRIDE,True
mr_stu_mp,ERN_OVR_REASON,True
mr_stu_mp,TRAIL_FLAG,True
mr_stu_mp,CHANGE_DATE_TIME,True
mr_stu_mp,CHANGE_UID,True
mr_stu_marks,DISTRICT,True
mr_stu_marks,STUDENT_ID,True
mr_stu_marks,SECTION_KEY,True
mr_stu_marks,COURSE_SESSION,True
mr_stu_marks,MARKING_PERIOD,True
mr_stu_marks,MARK_TYPE,True
mr_stu_marks,MARK_VALUE,True
mr_stu_marks,OVERRIDE,True
mr_stu_marks,RAW_MARK_VALUE,True
mr_stu_marks,OVERRIDE_REASON,True
mr_stu_marks,OVERRIDE_NOTES,True
mr_stu_marks,ROW_IDENTITY,True
mr_stu_marks,CHANGE_DATE_TIME,True
mr_stu_marks,CHANGE_UID,True
Mr_stu_xfer_bldgs,DISTRICT,True
Mr_stu_xfer_bldgs,SCHOOL_YEAR,True
Mr_stu_xfer_bldgs,STUDENT_ID,True
Mr_stu_xfer_bldgs,BUILDING,True
Mr_stu_xfer_bldgs,TRANSFER_SEQUENCE,True
Mr_stu_xfer_bldgs,STATE_BUILDING,True
Mr_stu_xfer_bldgs,BUILDING_NAME,True
Mr_stu_xfer_bldgs,GRADE,True
Mr_stu_xfer_bldgs,ABBREVIATION,True
Mr_stu_xfer_bldgs,STREET1,True
Mr_stu_xfer_bldgs,STREET2,True
Mr_stu_xfer_bldgs,CITY,True
Mr_stu_xfer_bldgs,STATE,True
Mr_stu_xfer_bldgs,ZIP_CODE,True
Mr_stu_xfer_bldgs,COUNTRY,True
Mr_stu_xfer_bldgs,PHONE,True
Mr_stu_xfer_bldgs,FAX,True
Mr_stu_xfer_bldgs,PRINCIPAL,True
Mr_stu_xfer_bldgs,BUILDING_TYPE,True
Mr_stu_xfer_bldgs,TRANSFER_COMMENT,True
Mr_stu_xfer_bldgs,STATE_CODE_EQUIV,True
Mr_stu_xfer_bldgs,ENTRY_DATE,True
Mr_stu_xfer_bldgs,WITHDRAWAL_DATE,True
Mr_stu_xfer_bldgs,ROW_IDENTITY,True
Mr_stu_xfer_bldgs,CHANGE_DATE_TIME,True
Mr_stu_xfer_bldgs,CHANGE_UID,True
Mr_rc_view_grd_sc,DISTRICT,True
Mr_rc_view_grd_sc,SCHOOL_YEAR,True
Mr_rc_view_grd_sc,BUILDING,True
Mr_rc_view_grd_sc,VIEW_TYPE,True
Mr_rc_view_grd_sc,RC_RUN,True
Mr_rc_view_grd_sc,GRADE,True
Mr_rc_view_grd_sc,VIEW_ORDER,True
Mr_rc_view_grd_sc,LABEL,True
Mr_rc_view_grd_sc,GRADING_SCALE_TYPE,True
Mr_rc_view_grd_sc,CHANGE_DATE_TIME,True
Mr_rc_view_grd_sc,CHANGE_UID,True
Mr_rc_view_det,DISTRICT,True
Mr_rc_view_det,SCHOOL_YEAR,True
Mr_rc_view_det,BUILDING,True
Mr_rc_view_det,VIEW_TYPE,True
Mr_rc_view_det,RC_RUN,True
Mr_rc_view_det,GRADE,True
Mr_rc_view_det,VIEW_SEQUENCE,True
Mr_rc_view_det,VIEW_ORDER,True
Mr_rc_view_det,TITLE,True
Mr_rc_view_det,SLOT_TYPE,True
Mr_rc_view_det,SLOT_CODE,True
Mr_rc_view_det,CHANGE_DATE_TIME,True
Mr_rc_view_det,CHANGE_UID,True
Mr_rc_view_att_int,DISTRICT,True
Mr_rc_view_att_int,SCHOOL_YEAR,True
Mr_rc_view_att_int,BUILDING,True
Mr_rc_view_att_int,VIEW_TYPE,True
Mr_rc_view_att_int,RC_RUN,True
Mr_rc_view_att_int,GRADE,True
Mr_rc_view_att_int,VIEW_ORDER,True
Mr_rc_view_att_int,ATT_VIEW_INTERVAL,True
Mr_rc_view_att_int,CHANGE_DATE_TIME,True
Mr_rc_view_att_int,CHANGE_UID,True
Mr_rc_view_att,DISTRICT,True
Mr_rc_view_att,SCHOOL_YEAR,True
Mr_rc_view_att,BUILDING,True
Mr_rc_view_att,VIEW_TYPE,True
Mr_rc_view_att,RC_RUN,True
Mr_rc_view_att,GRADE,True
Mr_rc_view_att,ATT_VIEW_TYPE,True
Mr_rc_view_att,VIEW_ORDER,True
Mr_rc_view_att,ATT_TITLE,True
Mr_rc_view_att,ATT_VIEW_INTERVAL,True
Mr_rc_view_att,ATT_VIEW_SUM_BY,True
Mr_rc_view_att,ATT_VIEW_CODE_GRP,True
Mr_rc_view_att,CHANGE_DATE_TIME,True
Mr_rc_view_att,CHANGE_UID,True
Mr_rc_taken,DISTRICT,True
Mr_rc_taken,SECTION_KEY,True
Mr_rc_taken,COURSE_SESSION,True
Mr_rc_taken,MARKING_PERIOD,True
Mr_rc_taken,CHANGE_DATE_TIME,True
Mr_rc_taken,CHANGE_UID,True
mr_stu_rubric_comp_score,DISTRICT,True
mr_stu_rubric_comp_score,RUBRIC_NUMBER,True
mr_stu_rubric_comp_score,BUILDING,True
mr_stu_rubric_comp_score,COMPETENCY_GROUP,True
mr_stu_rubric_comp_score,STAFF_ID,True
mr_stu_rubric_comp_score,ASMT_NUMBER,True
mr_stu_rubric_comp_score,CRITERIA_NUMBER,True
mr_stu_rubric_comp_score,STUDENT_ID,True
mr_stu_rubric_comp_score,RUBRIC_SCORE,True
mr_stu_rubric_comp_score,CHANGE_DATE_TIME,True
mr_stu_rubric_comp_score,CHANGE_UID,True
MR_RC_STU_AT_RISK,DISTRICT,True
MR_RC_STU_AT_RISK,SCHOOL_YEAR,True
MR_RC_STU_AT_RISK,SUMMER_SCHOOL,True
MR_RC_STU_AT_RISK,BUILDING,True
MR_RC_STU_AT_RISK,STUDENT_ID,True
MR_RC_STU_AT_RISK,HONOR_TYPE,True
MR_RC_STU_AT_RISK,RC_RUN,True
MR_RC_STU_AT_RISK,AT_RISK_REASON,True
MR_RC_STU_AT_RISK,EXPIRE_YEAR,True
MR_RC_STU_AT_RISK,EXPIRE_RUN_TERM,True
MR_RC_STU_AT_RISK,CHANGE_DATE_TIME,True
MR_RC_STU_AT_RISK,CHANGE_UID,True
MR_RC_STU_AT_RISK,PLAN_NUM,True
Mr_print_stu_stucp,MR_PRINT_KEY,True
Mr_print_stu_stucp,STUDENT_ID,True
Mr_print_stu_stucp,COMP_BUILDING,True
Mr_print_stu_stucp,COMPETENCY_GROUP,True
Mr_print_stu_stucp,GROUP_DESCRIPTION,True
Mr_print_stu_stucp,GROUP_SEQUENCE,True
Mr_print_stu_stucp,COMPETENCY_NUMBER,True
Mr_print_stu_stucp,COMP_SEQUENCE,True
Mr_print_stu_stucp,DESCRIPTION,True
Mr_print_stu_stucp,STAFF_ID,True
Mr_print_stu_stucp,STAFF_NAME,True
Mr_print_stu_stucp,FORMAT_LEVEL,True
Mr_print_stu_stucp,HEADING_ONLY,True
Mr_print_stu_stucp,SC_DATA_VALUE_01,True
Mr_print_stu_stucp,SC_DATA_VALUE_02,True
Mr_print_stu_stucp,SC_DATA_VALUE_03,True
Mr_print_stu_stucp,SC_DATA_VALUE_04,True
Mr_print_stu_stucp,SC_DATA_VALUE_05,True
Mr_print_stu_stucp,SC_DATA_VALUE_06,True
Mr_print_stu_stucp,SC_DATA_VALUE_07,True
Mr_print_stu_stucp,SC_DATA_VALUE_08,True
Mr_print_stu_stucp,SC_DATA_VALUE_09,True
Mr_print_stu_stucp,SC_DATA_VALUE_10,True
Mr_print_stu_stucp,SC_DATA_VALUE_11,True
Mr_print_stu_stucp,SC_DATA_VALUE_12,True
Mr_print_stu_stucp,SC_DATA_VALUE_13,True
Mr_print_stu_stucp,SC_DATA_VALUE_14,True
Mr_print_stu_stucp,SC_DATA_VALUE_15,True
Mr_print_stu_stucp,SC_DATA_VALUE_16,True
Mr_print_stu_stucp,SC_DATA_VALUE_17,True
Mr_print_stu_stucp,SC_DATA_VALUE_18,True
Mr_print_stu_stucp,SC_DATA_VALUE_19,True
Mr_print_stu_stucp,SC_DATA_VALUE_20,True
Mr_print_stu_stucp,SC_DATA_VALUE_21,True
Mr_print_stu_stucp,SC_DATA_VALUE_22,True
Mr_print_stu_stucp,SC_DATA_VALUE_23,True
Mr_print_stu_stucp,SC_DATA_VALUE_24,True
Mr_print_stu_stucp,SC_DATA_VALUE_25,True
Mr_print_stu_stucp,SC_DATA_VALUE_26,True
Mr_print_stu_stucp,SC_DATA_VALUE_27,True
Mr_print_stu_stucp,SC_DATA_VALUE_28,True
Mr_print_stu_stucp,SC_DATA_VALUE_29,True
Mr_print_stu_stucp,SC_DATA_VALUE_30,True
Mr_print_stu_stucp,SC_COMM_DESCR_01,True
Mr_print_stu_stucp,SC_COMM_DESCR_02,True
Mr_print_stu_stucp,SC_COMM_DESCR_03,True
Mr_print_stu_stucp,SC_COMM_DESCR_04,True
Mr_print_stu_stucp,SC_COMM_DESCR_05,True
Mr_print_stu_stucp,SC_COMM_DESCR_06,True
Mr_print_stu_stucp,SC_COMM_DESCR_07,True
Mr_print_stu_stucp,SC_COMM_DESCR_08,True
Mr_print_stu_stucp,SC_COMM_DESCR_09,True
Mr_print_stu_stucp,SC_COMM_DESCR_10,True
Mr_print_stu_stucp,SC_COMM_DESCR_11,True
Mr_print_stu_stucp,SC_COMM_DESCR_12,True
Mr_print_stu_stucp,SC_COMM_DESCR_13,True
Mr_print_stu_stucp,SC_COMM_DESCR_14,True
Mr_print_stu_stucp,SC_COMM_DESCR_15,True
Mr_print_stu_stucp,SC_COMM_DESCR_16,True
Mr_print_stu_stucp,SC_COMM_DESCR_17,True
Mr_print_stu_stucp,SC_COMM_DESCR_18,True
Mr_print_stu_stucp,SC_COMM_DESCR_19,True
Mr_print_stu_stucp,SC_COMM_DESCR_20,True
Mr_print_stu_stucp,SC_COMM_DESCR_21,True
Mr_print_stu_stucp,SC_COMM_DESCR_22,True
Mr_print_stu_stucp,SC_COMM_DESCR_23,True
Mr_print_stu_stucp,SC_COMM_DESCR_24,True
Mr_print_stu_stucp,SC_COMM_DESCR_25,True
Mr_print_stu_stucp,SC_COMM_DESCR_26,True
Mr_print_stu_stucp,SC_COMM_DESCR_27,True
Mr_print_stu_stucp,SC_COMM_DESCR_28,True
Mr_print_stu_stucp,SC_COMM_DESCR_29,True
Mr_print_stu_stucp,SC_COMM_DESCR_30,True
Mr_print_stu_stucp,CHANGE_DATE_TIME,True
Mr_print_stu_stucp,CHANGE_UID,True
Mr_stu_honor,DISTRICT,True
Mr_stu_honor,SCHOOL_YEAR,True
Mr_stu_honor,BUILDING,True
Mr_stu_honor,STUDENT_ID,True
Mr_stu_honor,HONOR_TYPE,True
Mr_stu_honor,RC_RUN,True
Mr_stu_honor,QUALIFIED,True
Mr_stu_honor,DISQUAL_REASON,True
Mr_stu_honor,HONOR_GPA,True
Mr_stu_honor,HONOR_CREDIT,True
Mr_stu_honor,HONOR_POINTS,True
Mr_stu_honor,CHANGE_DATE_TIME,True
Mr_stu_honor,CHANGE_UID,True
mr_stu_rubric_score,DISTRICT,True
mr_stu_rubric_score,RUBRIC_NUMBER,True
mr_stu_rubric_score,SECTION_KEY,True
mr_stu_rubric_score,COURSE_SESSION,True
mr_stu_rubric_score,ASMT_NUMBER,True
mr_stu_rubric_score,CRITERIA_NUMBER,True
mr_stu_rubric_score,STUDENT_ID,True
mr_stu_rubric_score,RUBRIC_SCORE,True
mr_stu_rubric_score,CHANGE_DATE_TIME,True
mr_stu_rubric_score,CHANGE_UID,True
Mr_print_stu_ltdb,MR_PRINT_KEY,True
Mr_print_stu_ltdb,STUDENT_ID,True
Mr_print_stu_ltdb,LTDB_TITLE_01,True
Mr_print_stu_ltdb,LTDB_TITLE_02,True
Mr_print_stu_ltdb,LTDB_TITLE_03,True
Mr_print_stu_ltdb,LTDB_TITLE_04,True
Mr_print_stu_ltdb,LTDB_TITLE_05,True
Mr_print_stu_ltdb,LTDB_TITLE_06,True
Mr_print_stu_ltdb,LTDB_TITLE_07,True
Mr_print_stu_ltdb,LTDB_TITLE_08,True
Mr_print_stu_ltdb,LTDB_TITLE_09,True
Mr_print_stu_ltdb,LTDB_TITLE_10,True
Mr_print_stu_ltdb,LTDB_TITLE_11,True
Mr_print_stu_ltdb,LTDB_TITLE_12,True
Mr_print_stu_ltdb,LTDB_TITLE_13,True
Mr_print_stu_ltdb,LTDB_TITLE_14,True
Mr_print_stu_ltdb,LTDB_TITLE_15,True
Mr_print_stu_ltdb,LTDB_TITLE_16,True
Mr_print_stu_ltdb,LTDB_TITLE_17,True
Mr_print_stu_ltdb,LTDB_TITLE_18,True
Mr_print_stu_ltdb,LTDB_TITLE_19,True
Mr_print_stu_ltdb,LTDB_TITLE_20,True
Mr_print_stu_ltdb,LTDB_TITLE_21,True
Mr_print_stu_ltdb,LTDB_TITLE_22,True
Mr_print_stu_ltdb,LTDB_TITLE_23,True
Mr_print_stu_ltdb,LTDB_TITLE_24,True
Mr_print_stu_ltdb,LTDB_TITLE_25,True
Mr_print_stu_ltdb,LTDB_TITLE_26,True
Mr_print_stu_ltdb,LTDB_TITLE_27,True
Mr_print_stu_ltdb,LTDB_TITLE_28,True
Mr_print_stu_ltdb,LTDB_TITLE_29,True
Mr_print_stu_ltdb,LTDB_TITLE_30,True
Mr_print_stu_ltdb,SCORE_01,True
Mr_print_stu_ltdb,SCORE_02,True
Mr_print_stu_ltdb,SCORE_03,True
Mr_print_stu_ltdb,SCORE_04,True
Mr_print_stu_ltdb,SCORE_05,True
Mr_print_stu_ltdb,SCORE_06,True
Mr_print_stu_ltdb,SCORE_07,True
Mr_print_stu_ltdb,SCORE_08,True
Mr_print_stu_ltdb,SCORE_09,True
Mr_print_stu_ltdb,SCORE_10,True
Mr_print_stu_ltdb,SCORE_11,True
Mr_print_stu_ltdb,SCORE_12,True
Mr_print_stu_ltdb,SCORE_13,True
Mr_print_stu_ltdb,SCORE_14,True
Mr_print_stu_ltdb,SCORE_15,True
Mr_print_stu_ltdb,SCORE_16,True
Mr_print_stu_ltdb,SCORE_17,True
Mr_print_stu_ltdb,SCORE_18,True
Mr_print_stu_ltdb,SCORE_19,True
Mr_print_stu_ltdb,SCORE_20,True
Mr_print_stu_ltdb,SCORE_21,True
Mr_print_stu_ltdb,SCORE_22,True
Mr_print_stu_ltdb,SCORE_23,True
Mr_print_stu_ltdb,SCORE_24,True
Mr_print_stu_ltdb,SCORE_25,True
Mr_print_stu_ltdb,SCORE_26,True
Mr_print_stu_ltdb,SCORE_27,True
Mr_print_stu_ltdb,SCORE_28,True
Mr_print_stu_ltdb,SCORE_29,True
Mr_print_stu_ltdb,SCORE_30,True
Mr_print_stu_ltdb,TEST_DATE_01,True
Mr_print_stu_ltdb,TEST_DATE_02,True
Mr_print_stu_ltdb,TEST_DATE_03,True
Mr_print_stu_ltdb,TEST_DATE_04,True
Mr_print_stu_ltdb,TEST_DATE_05,True
Mr_print_stu_ltdb,TEST_DATE_06,True
Mr_print_stu_ltdb,TEST_DATE_07,True
Mr_print_stu_ltdb,TEST_DATE_08,True
Mr_print_stu_ltdb,TEST_DATE_09,True
Mr_print_stu_ltdb,TEST_DATE_10,True
Mr_print_stu_ltdb,TEST_DATE_11,True
Mr_print_stu_ltdb,TEST_DATE_12,True
Mr_print_stu_ltdb,TEST_DATE_13,True
Mr_print_stu_ltdb,TEST_DATE_14,True
Mr_print_stu_ltdb,TEST_DATE_15,True
Mr_print_stu_ltdb,TEST_DATE_16,True
Mr_print_stu_ltdb,TEST_DATE_17,True
Mr_print_stu_ltdb,TEST_DATE_18,True
Mr_print_stu_ltdb,TEST_DATE_19,True
Mr_print_stu_ltdb,TEST_DATE_20,True
Mr_print_stu_ltdb,TEST_DATE_21,True
Mr_print_stu_ltdb,TEST_DATE_22,True
Mr_print_stu_ltdb,TEST_DATE_23,True
Mr_print_stu_ltdb,TEST_DATE_24,True
Mr_print_stu_ltdb,TEST_DATE_25,True
Mr_print_stu_ltdb,TEST_DATE_26,True
Mr_print_stu_ltdb,TEST_DATE_27,True
Mr_print_stu_ltdb,TEST_DATE_28,True
Mr_print_stu_ltdb,TEST_DATE_29,True
Mr_print_stu_ltdb,TEST_DATE_30,True
Mr_print_stu_ltdb,CHANGE_DATE_TIME,True
Mr_print_stu_ltdb,CHANGE_UID,True
mr_rc_stu_eligible,DISTRICT,True
mr_rc_stu_eligible,SCHOOL_YEAR,True
mr_rc_stu_eligible,SUMMER_SCHOOL,True
mr_rc_stu_eligible,BUILDING,True
mr_rc_stu_eligible,STUDENT_ID,True
mr_rc_stu_eligible,HONOR_TYPE,True
mr_rc_stu_eligible,RC_RUN,True
mr_rc_stu_eligible,ELIGIBILITY_CODE,True
mr_rc_stu_eligible,EFFECTIVE_DATE,True
mr_rc_stu_eligible,EXPIRATION_DATE,True
mr_rc_stu_eligible,DISQUAL_REASON,True
mr_rc_stu_eligible,CHANGE_DATE_TIME,True
mr_rc_stu_eligible,CHANGE_UID,True
mr_print_stu_hdr,MR_PRINT_KEY,True
mr_print_stu_hdr,STUDENT_ID,True
mr_print_stu_hdr,STUDENT_NAME,True
mr_print_stu_hdr,BUILDING,True
mr_print_stu_hdr,GRADE,True
mr_print_stu_hdr,TRACK,True
mr_print_stu_hdr,COUNSELOR,True
mr_print_stu_hdr,HOUSE_TEAM,True
mr_print_stu_hdr,HOMEROOM_PRIMARY,True
mr_print_stu_hdr,RANK_NUM_CURR,True
mr_print_stu_hdr,RANK_NUM_CUM,True
mr_print_stu_hdr,RANK_OUT_OF,True
mr_print_stu_hdr,DAILY_ATT_DESCR_01,True
mr_print_stu_hdr,DAILY_ATT_DESCR_02,True
mr_print_stu_hdr,DAILY_ATT_DESCR_03,True
mr_print_stu_hdr,DAILY_ATT_DESCR_04,True
mr_print_stu_hdr,DAILY_ATT_DESCR_05,True
mr_print_stu_hdr,DAILY_ATT_DESCR_06,True
mr_print_stu_hdr,DAILY_ATT_DESCR_07,True
mr_print_stu_hdr,DAILY_ATT_DESCR_08,True
mr_print_stu_hdr,DAILY_ATT_DESCR_09,True
mr_print_stu_hdr,DAILY_ATT_DESCR_10,True
mr_print_stu_hdr,DAILY_ATT_CURR_01,True
mr_print_stu_hdr,DAILY_ATT_CURR_02,True
mr_print_stu_hdr,DAILY_ATT_CURR_03,True
mr_print_stu_hdr,DAILY_ATT_CURR_04,True
mr_print_stu_hdr,DAILY_ATT_CURR_05,True
mr_print_stu_hdr,DAILY_ATT_CURR_06,True
mr_print_stu_hdr,DAILY_ATT_CURR_07,True
mr_print_stu_hdr,DAILY_ATT_CURR_08,True
mr_print_stu_hdr,DAILY_ATT_CURR_09,True
mr_print_stu_hdr,DAILY_ATT_CURR_10,True
mr_print_stu_hdr,DAILY_ATT_YTD_01,True
mr_print_stu_hdr,DAILY_ATT_YTD_02,True
mr_print_stu_hdr,DAILY_ATT_YTD_03,True
mr_print_stu_hdr,DAILY_ATT_YTD_04,True
mr_print_stu_hdr,DAILY_ATT_YTD_05,True
mr_print_stu_hdr,DAILY_ATT_YTD_06,True
mr_print_stu_hdr,DAILY_ATT_YTD_07,True
mr_print_stu_hdr,DAILY_ATT_YTD_08,True
mr_print_stu_hdr,DAILY_ATT_YTD_09,True
mr_print_stu_hdr,DAILY_ATT_YTD_10,True
mr_print_stu_hdr,CREDIT_HONOR,True
mr_print_stu_hdr,CREDIT_SEM,True
mr_print_stu_hdr,CREDIT_CUM,True
mr_print_stu_hdr,CREDIT_ATT_CUR,True
mr_print_stu_hdr,CREDIT_ATT_SEM,True
mr_print_stu_hdr,CREDIT_ATT_CUM,True
mr_print_stu_hdr,GPA_HONOR,True
mr_print_stu_hdr,GPA_SEM,True
mr_print_stu_hdr,GPA_CUM,True
mr_print_stu_hdr,HONOR_TYPE_01,True
mr_print_stu_hdr,HONOR_TYPE_02,True
mr_print_stu_hdr,HONOR_TYPE_03,True
mr_print_stu_hdr,HONOR_TYPE_04,True
mr_print_stu_hdr,HONOR_TYPE_05,True
mr_print_stu_hdr,HONOR_TYPE_06,True
mr_print_stu_hdr,HONOR_TYPE_07,True
mr_print_stu_hdr,HONOR_TYPE_08,True
mr_print_stu_hdr,HONOR_TYPE_09,True
mr_print_stu_hdr,HONOR_TYPE_10,True
mr_print_stu_hdr,HONOR_MSG_01,True
mr_print_stu_hdr,HONOR_MSG_02,True
mr_print_stu_hdr,HONOR_MSG_03,True
mr_print_stu_hdr,HONOR_MSG_04,True
mr_print_stu_hdr,HONOR_MSG_05,True
mr_print_stu_hdr,HONOR_MSG_06,True
mr_print_stu_hdr,HONOR_MSG_07,True
mr_print_stu_hdr,HONOR_MSG_08,True
mr_print_stu_hdr,HONOR_MSG_09,True
mr_print_stu_hdr,HONOR_MSG_10,True
mr_print_stu_hdr,HONOR_GPA_01,True
mr_print_stu_hdr,HONOR_GPA_02,True
mr_print_stu_hdr,HONOR_GPA_03,True
mr_print_stu_hdr,HONOR_GPA_04,True
mr_print_stu_hdr,HONOR_GPA_05,True
mr_print_stu_hdr,HONOR_GPA_06,True
mr_print_stu_hdr,HONOR_GPA_07,True
mr_print_stu_hdr,HONOR_GPA_08,True
mr_print_stu_hdr,HONOR_GPA_09,True
mr_print_stu_hdr,HONOR_GPA_10,True
mr_print_stu_hdr,HONOR_CREDIT_01,True
mr_print_stu_hdr,HONOR_CREDIT_02,True
mr_print_stu_hdr,HONOR_CREDIT_03,True
mr_print_stu_hdr,HONOR_CREDIT_04,True
mr_print_stu_hdr,HONOR_CREDIT_05,True
mr_print_stu_hdr,HONOR_CREDIT_06,True
mr_print_stu_hdr,HONOR_CREDIT_07,True
mr_print_stu_hdr,HONOR_CREDIT_08,True
mr_print_stu_hdr,HONOR_CREDIT_09,True
mr_print_stu_hdr,HONOR_CREDIT_10,True
mr_print_stu_hdr,HONOR_QUALIFIED_01,True
mr_print_stu_hdr,HONOR_QUALIFIED_02,True
mr_print_stu_hdr,HONOR_QUALIFIED_03,True
mr_print_stu_hdr,HONOR_QUALIFIED_04,True
mr_print_stu_hdr,HONOR_QUALIFIED_05,True
mr_print_stu_hdr,HONOR_QUALIFIED_06,True
mr_print_stu_hdr,HONOR_QUALIFIED_07,True
mr_print_stu_hdr,HONOR_QUALIFIED_08,True
mr_print_stu_hdr,HONOR_QUALIFIED_09,True
mr_print_stu_hdr,HONOR_QUALIFIED_10,True
mr_print_stu_hdr,REPORT_TEMPLATE,True
mr_print_stu_hdr,CHANGE_DATE_TIME,True
mr_print_stu_hdr,CHANGE_UID,True
Mr_print_stu_crscp,MR_PRINT_KEY,True
Mr_print_stu_crscp,STUDENT_ID,True
Mr_print_stu_crscp,COURSE_BUILDING,True
Mr_print_stu_crscp,COURSE,True
Mr_print_stu_crscp,COMPETENCY_GROUP,True
Mr_print_stu_crscp,COMPETENCY_NUMBER,True
Mr_print_stu_crscp,SEQUENCE_NUMBER,True
Mr_print_stu_crscp,DESCRIPTION,True
Mr_print_stu_crscp,FORMAT_LEVEL,True
Mr_print_stu_crscp,HEADING_ONLY,True
Mr_print_stu_crscp,SC_DATA_VALUE_01,True
Mr_print_stu_crscp,SC_DATA_VALUE_02,True
Mr_print_stu_crscp,SC_DATA_VALUE_03,True
Mr_print_stu_crscp,SC_DATA_VALUE_04,True
Mr_print_stu_crscp,SC_DATA_VALUE_05,True
Mr_print_stu_crscp,SC_DATA_VALUE_06,True
Mr_print_stu_crscp,SC_DATA_VALUE_07,True
Mr_print_stu_crscp,SC_DATA_VALUE_08,True
Mr_print_stu_crscp,SC_DATA_VALUE_09,True
Mr_print_stu_crscp,SC_DATA_VALUE_10,True
Mr_print_stu_crscp,SC_DATA_VALUE_11,True
Mr_print_stu_crscp,SC_DATA_VALUE_12,True
Mr_print_stu_crscp,SC_DATA_VALUE_13,True
Mr_print_stu_crscp,SC_DATA_VALUE_14,True
Mr_print_stu_crscp,SC_DATA_VALUE_15,True
Mr_print_stu_crscp,SC_DATA_VALUE_16,True
Mr_print_stu_crscp,SC_DATA_VALUE_17,True
Mr_print_stu_crscp,SC_DATA_VALUE_18,True
Mr_print_stu_crscp,SC_DATA_VALUE_19,True
Mr_print_stu_crscp,SC_DATA_VALUE_20,True
Mr_print_stu_crscp,SC_DATA_VALUE_21,True
Mr_print_stu_crscp,SC_DATA_VALUE_22,True
Mr_print_stu_crscp,SC_DATA_VALUE_23,True
Mr_print_stu_crscp,SC_DATA_VALUE_24,True
Mr_print_stu_crscp,SC_DATA_VALUE_25,True
Mr_print_stu_crscp,SC_DATA_VALUE_26,True
Mr_print_stu_crscp,SC_DATA_VALUE_27,True
Mr_print_stu_crscp,SC_DATA_VALUE_28,True
Mr_print_stu_crscp,SC_DATA_VALUE_29,True
Mr_print_stu_crscp,SC_DATA_VALUE_30,True
Mr_print_stu_crscp,SC_COMM_DESCR_01,True
Mr_print_stu_crscp,SC_COMM_DESCR_02,True
Mr_print_stu_crscp,SC_COMM_DESCR_03,True
Mr_print_stu_crscp,SC_COMM_DESCR_04,True
Mr_print_stu_crscp,SC_COMM_DESCR_05,True
Mr_print_stu_crscp,SC_COMM_DESCR_06,True
Mr_print_stu_crscp,SC_COMM_DESCR_07,True
Mr_print_stu_crscp,SC_COMM_DESCR_08,True
Mr_print_stu_crscp,SC_COMM_DESCR_09,True
Mr_print_stu_crscp,SC_COMM_DESCR_10,True
Mr_print_stu_crscp,SC_COMM_DESCR_11,True
Mr_print_stu_crscp,SC_COMM_DESCR_12,True
Mr_print_stu_crscp,SC_COMM_DESCR_13,True
Mr_print_stu_crscp,SC_COMM_DESCR_14,True
Mr_print_stu_crscp,SC_COMM_DESCR_15,True
Mr_print_stu_crscp,SC_COMM_DESCR_16,True
Mr_print_stu_crscp,SC_COMM_DESCR_17,True
Mr_print_stu_crscp,SC_COMM_DESCR_18,True
Mr_print_stu_crscp,SC_COMM_DESCR_19,True
Mr_print_stu_crscp,SC_COMM_DESCR_20,True
Mr_print_stu_crscp,SC_COMM_DESCR_21,True
Mr_print_stu_crscp,SC_COMM_DESCR_22,True
Mr_print_stu_crscp,SC_COMM_DESCR_23,True
Mr_print_stu_crscp,SC_COMM_DESCR_24,True
Mr_print_stu_crscp,SC_COMM_DESCR_25,True
Mr_print_stu_crscp,SC_COMM_DESCR_26,True
Mr_print_stu_crscp,SC_COMM_DESCR_27,True
Mr_print_stu_crscp,SC_COMM_DESCR_28,True
Mr_print_stu_crscp,SC_COMM_DESCR_29,True
Mr_print_stu_crscp,SC_COMM_DESCR_30,True
Mr_print_stu_crscp,CHANGE_DATE_TIME,True
Mr_print_stu_crscp,CHANGE_UID,True
Mr_print_stu_comm,MR_PRINT_KEY,True
Mr_print_stu_comm,STUDENT_ID,True
Mr_print_stu_comm,SECTION_KEY,True
Mr_print_stu_comm,COURSE_SESSION,True
Mr_print_stu_comm,MR_DATA_DESCR_01,True
Mr_print_stu_comm,MR_DATA_DESCR_02,True
Mr_print_stu_comm,MR_DATA_DESCR_03,True
Mr_print_stu_comm,MR_DATA_DESCR_04,True
Mr_print_stu_comm,MR_DATA_DESCR_05,True
Mr_print_stu_comm,MR_DATA_DESCR_06,True
Mr_print_stu_comm,MR_DATA_DESCR_07,True
Mr_print_stu_comm,MR_DATA_DESCR_08,True
Mr_print_stu_comm,MR_DATA_DESCR_09,True
Mr_print_stu_comm,MR_DATA_DESCR_10,True
Mr_print_stu_comm,MR_DATA_DESCR_11,True
Mr_print_stu_comm,MR_DATA_DESCR_12,True
Mr_print_stu_comm,MR_DATA_DESCR_13,True
Mr_print_stu_comm,MR_DATA_DESCR_14,True
Mr_print_stu_comm,MR_DATA_DESCR_15,True
Mr_print_stu_comm,MR_DATA_DESCR_16,True
Mr_print_stu_comm,MR_DATA_DESCR_17,True
Mr_print_stu_comm,MR_DATA_DESCR_18,True
Mr_print_stu_comm,MR_DATA_DESCR_19,True
Mr_print_stu_comm,MR_DATA_DESCR_20,True
Mr_print_stu_comm,MR_DATA_DESCR_21,True
Mr_print_stu_comm,MR_DATA_DESCR_22,True
Mr_print_stu_comm,MR_DATA_DESCR_23,True
Mr_print_stu_comm,MR_DATA_DESCR_24,True
Mr_print_stu_comm,MR_DATA_DESCR_25,True
Mr_print_stu_comm,MR_DATA_DESCR_26,True
Mr_print_stu_comm,MR_DATA_DESCR_27,True
Mr_print_stu_comm,MR_DATA_DESCR_28,True
Mr_print_stu_comm,MR_DATA_DESCR_29,True
Mr_print_stu_comm,MR_DATA_DESCR_30,True
Mr_print_stu_comm,CHANGE_DATE_TIME,True
Mr_print_stu_comm,CHANGE_UID,True
Mr_print_stu_prog,MR_PRINT_KEY,True
Mr_print_stu_prog,STUDENT_ID,True
Mr_print_stu_prog,PROGRAM_ID,True
Mr_print_stu_prog,FIELD_NUMBER,True
Mr_print_stu_prog,VIEW_ORDER,True
Mr_print_stu_prog,PROGRAM_LABEL,True
Mr_print_stu_prog,PROGRAM_VALUE_01,True
Mr_print_stu_prog,PROGRAM_VALUE_02,True
Mr_print_stu_prog,PROGRAM_VALUE_03,True
Mr_print_stu_prog,PROGRAM_VALUE_04,True
Mr_print_stu_prog,PROGRAM_VALUE_05,True
Mr_print_stu_prog,PROGRAM_VALUE_06,True
Mr_print_stu_prog,PROGRAM_VALUE_07,True
Mr_print_stu_prog,PROGRAM_VALUE_08,True
Mr_print_stu_prog,PROGRAM_VALUE_09,True
Mr_print_stu_prog,PROGRAM_VALUE_10,True
Mr_print_stu_prog,PROGRAM_VALUE_11,True
Mr_print_stu_prog,PROGRAM_VALUE_12,True
Mr_print_stu_prog,CHANGE_DATE_TIME,True
Mr_print_stu_prog,CHANGE_UID,True
Mr_print_gd_scale,MR_PRINT_KEY,True
Mr_print_gd_scale,STUDENT_ID,True
Mr_print_gd_scale,PRINT_ORDER,True
Mr_print_gd_scale,GRADING_SCALE_TYPE,True
Mr_print_gd_scale,GRADING_SCALE_DESC,True
Mr_print_gd_scale,MARK_01,True
Mr_print_gd_scale,MARK_02,True
Mr_print_gd_scale,MARK_03,True
Mr_print_gd_scale,MARK_04,True
Mr_print_gd_scale,MARK_05,True
Mr_print_gd_scale,MARK_06,True
Mr_print_gd_scale,MARK_07,True
Mr_print_gd_scale,MARK_08,True
Mr_print_gd_scale,MARK_09,True
Mr_print_gd_scale,MARK_10,True
Mr_print_gd_scale,MARK_11,True
Mr_print_gd_scale,MARK_12,True
Mr_print_gd_scale,MARK_13,True
Mr_print_gd_scale,MARK_14,True
Mr_print_gd_scale,MARK_15,True
Mr_print_gd_scale,MARK_16,True
Mr_print_gd_scale,MARK_17,True
Mr_print_gd_scale,MARK_18,True
Mr_print_gd_scale,MARK_19,True
Mr_print_gd_scale,MARK_20,True
Mr_print_gd_scale,MARK_21,True
Mr_print_gd_scale,MARK_22,True
Mr_print_gd_scale,MARK_23,True
Mr_print_gd_scale,MARK_24,True
Mr_print_gd_scale,MARK_25,True
Mr_print_gd_scale,MARK_26,True
Mr_print_gd_scale,MARK_27,True
Mr_print_gd_scale,MARK_28,True
Mr_print_gd_scale,MARK_29,True
Mr_print_gd_scale,MARK_30,True
Mr_print_gd_scale,MARK_DESCR_01,True
Mr_print_gd_scale,MARK_DESCR_02,True
Mr_print_gd_scale,MARK_DESCR_03,True
Mr_print_gd_scale,MARK_DESCR_04,True
Mr_print_gd_scale,MARK_DESCR_05,True
Mr_print_gd_scale,MARK_DESCR_06,True
Mr_print_gd_scale,MARK_DESCR_07,True
Mr_print_gd_scale,MARK_DESCR_08,True
Mr_print_gd_scale,MARK_DESCR_09,True
Mr_print_gd_scale,MARK_DESCR_10,True
Mr_print_gd_scale,MARK_DESCR_11,True
Mr_print_gd_scale,MARK_DESCR_12,True
Mr_print_gd_scale,MARK_DESCR_13,True
Mr_print_gd_scale,MARK_DESCR_14,True
Mr_print_gd_scale,MARK_DESCR_15,True
Mr_print_gd_scale,MARK_DESCR_16,True
Mr_print_gd_scale,MARK_DESCR_17,True
Mr_print_gd_scale,MARK_DESCR_18,True
Mr_print_gd_scale,MARK_DESCR_19,True
Mr_print_gd_scale,MARK_DESCR_20,True
Mr_print_gd_scale,MARK_DESCR_21,True
Mr_print_gd_scale,MARK_DESCR_22,True
Mr_print_gd_scale,MARK_DESCR_23,True
Mr_print_gd_scale,MARK_DESCR_24,True
Mr_print_gd_scale,MARK_DESCR_25,True
Mr_print_gd_scale,MARK_DESCR_26,True
Mr_print_gd_scale,MARK_DESCR_27,True
Mr_print_gd_scale,MARK_DESCR_28,True
Mr_print_gd_scale,MARK_DESCR_29,True
Mr_print_gd_scale,MARK_DESCR_30,True
Mr_print_gd_scale,CHANGE_DATE_TIME,True
Mr_print_gd_scale,CHANGE_UID,True
mr_print_stu_det,MR_PRINT_KEY,True
mr_print_stu_det,STUDENT_ID,True
mr_print_stu_det,SECTION_KEY,True
mr_print_stu_det,COURSE_BUILDING,True
mr_print_stu_det,COURSE,True
mr_print_stu_det,COURSE_SECTION,True
mr_print_stu_det,COURSE_SESSION,True
mr_print_stu_det,DESCRIPTION,True
mr_print_stu_det,CRS_PERIOD,True
mr_print_stu_det,PRIMARY_STAFF_ID,True
mr_print_stu_det,STAFF_NAME,True
mr_print_stu_det,ROOM_ID,True
mr_print_stu_det,ATTEMPTED_CREDIT,True
mr_print_stu_det,ATT_OVERRIDE,True
mr_print_stu_det,ATT_OVR_REASON,True
mr_print_stu_det,EARNED_CREDIT,True
mr_print_stu_det,EARN_OVERRIDE,True
mr_print_stu_det,EARN_OVR_REASON,True
mr_print_stu_det,MR_DATA_VALUE_01,True
mr_print_stu_det,MR_DATA_VALUE_02,True
mr_print_stu_det,MR_DATA_VALUE_03,True
mr_print_stu_det,MR_DATA_VALUE_04,True
mr_print_stu_det,MR_DATA_VALUE_05,True
mr_print_stu_det,MR_DATA_VALUE_06,True
mr_print_stu_det,MR_DATA_VALUE_07,True
mr_print_stu_det,MR_DATA_VALUE_08,True
mr_print_stu_det,MR_DATA_VALUE_09,True
mr_print_stu_det,MR_DATA_VALUE_10,True
mr_print_stu_det,MR_DATA_VALUE_11,True
mr_print_stu_det,MR_DATA_VALUE_12,True
mr_print_stu_det,MR_DATA_VALUE_13,True
mr_print_stu_det,MR_DATA_VALUE_14,True
mr_print_stu_det,MR_DATA_VALUE_15,True
mr_print_stu_det,MR_DATA_VALUE_16,True
mr_print_stu_det,MR_DATA_VALUE_17,True
mr_print_stu_det,MR_DATA_VALUE_18,True
mr_print_stu_det,MR_DATA_VALUE_19,True
mr_print_stu_det,MR_DATA_VALUE_20,True
mr_print_stu_det,MR_DATA_VALUE_21,True
mr_print_stu_det,MR_DATA_VALUE_22,True
mr_print_stu_det,MR_DATA_VALUE_23,True
mr_print_stu_det,MR_DATA_VALUE_24,True
mr_print_stu_det,MR_DATA_VALUE_25,True
mr_print_stu_det,MR_DATA_VALUE_26,True
mr_print_stu_det,MR_DATA_VALUE_27,True
mr_print_stu_det,MR_DATA_VALUE_28,True
mr_print_stu_det,MR_DATA_VALUE_29,True
mr_print_stu_det,MR_DATA_VALUE_30,True
mr_print_stu_det,CHANGE_DATE_TIME,True
mr_print_stu_det,CHANGE_UID,True
mr_mark_types,DISTRICT,True
mr_mark_types,BUILDING,True
mr_mark_types,MARK_TYPE,True
mr_mark_types,MARK_ORDER,True
mr_mark_types,MARK_WHEN,True
mr_mark_types,DESCRIPTION,True
mr_mark_types,INCLUDE_AS_DEFAULT,True
mr_mark_types,REQUIRED,True
mr_mark_types,ACTIVE,True
mr_mark_types,TWS_ACCESS,True
mr_mark_types,RECEIVE_GB_RESULT,True
mr_mark_types,INCLUDE_PERFPLUS,True
mr_mark_types,ROW_IDENTITY,True
mr_mark_types,CHANGE_DATE_TIME,True
mr_mark_types,CHANGE_UID,True
mr_mark_subs,DISTRICT,True
mr_mark_subs,SCHOOL_YEAR,True
mr_mark_subs,BUILDING,True
mr_mark_subs,LOW_RANGE,True
mr_mark_subs,HIGH_RANGE,True
mr_mark_subs,REPLACE_MARK,True
mr_mark_subs,CHANGE_DATE_TIME,True
mr_mark_subs,CHANGE_UID,True
Mr_print_hdr,DISTRICT,True
Mr_print_hdr,SCHOOL_YEAR,True
Mr_print_hdr,BUILDING,True
Mr_print_hdr,RC_RUN,True
Mr_print_hdr,GRADE,True
Mr_print_hdr,AS_OF_DATE,True
Mr_print_hdr,RUN_DATE,True
Mr_print_hdr,HEADER_TEXT,True
Mr_print_hdr,FOOTER_TEXT,True
Mr_print_hdr,MR_DATA_TITLE_01,True
Mr_print_hdr,MR_DATA_TITLE_02,True
Mr_print_hdr,MR_DATA_TITLE_03,True
Mr_print_hdr,MR_DATA_TITLE_04,True
Mr_print_hdr,MR_DATA_TITLE_05,True
Mr_print_hdr,MR_DATA_TITLE_06,True
Mr_print_hdr,MR_DATA_TITLE_07,True
Mr_print_hdr,MR_DATA_TITLE_08,True
Mr_print_hdr,MR_DATA_TITLE_09,True
Mr_print_hdr,MR_DATA_TITLE_10,True
Mr_print_hdr,MR_DATA_TITLE_11,True
Mr_print_hdr,MR_DATA_TITLE_12,True
Mr_print_hdr,MR_DATA_TITLE_13,True
Mr_print_hdr,MR_DATA_TITLE_14,True
Mr_print_hdr,MR_DATA_TITLE_15,True
Mr_print_hdr,MR_DATA_TITLE_16,True
Mr_print_hdr,MR_DATA_TITLE_17,True
Mr_print_hdr,MR_DATA_TITLE_18,True
Mr_print_hdr,MR_DATA_TITLE_19,True
Mr_print_hdr,MR_DATA_TITLE_20,True
Mr_print_hdr,MR_DATA_TITLE_21,True
Mr_print_hdr,MR_DATA_TITLE_22,True
Mr_print_hdr,MR_DATA_TITLE_23,True
Mr_print_hdr,MR_DATA_TITLE_24,True
Mr_print_hdr,MR_DATA_TITLE_25,True
Mr_print_hdr,MR_DATA_TITLE_26,True
Mr_print_hdr,MR_DATA_TITLE_27,True
Mr_print_hdr,MR_DATA_TITLE_28,True
Mr_print_hdr,MR_DATA_TITLE_29,True
Mr_print_hdr,MR_DATA_TITLE_30,True
Mr_print_hdr,MR_SC_TITLE_01,True
Mr_print_hdr,MR_SC_TITLE_02,True
Mr_print_hdr,MR_SC_TITLE_03,True
Mr_print_hdr,MR_SC_TITLE_04,True
Mr_print_hdr,MR_SC_TITLE_05,True
Mr_print_hdr,MR_SC_TITLE_06,True
Mr_print_hdr,MR_SC_TITLE_07,True
Mr_print_hdr,MR_SC_TITLE_08,True
Mr_print_hdr,MR_SC_TITLE_09,True
Mr_print_hdr,MR_SC_TITLE_10,True
Mr_print_hdr,MR_SC_TITLE_11,True
Mr_print_hdr,MR_SC_TITLE_12,True
Mr_print_hdr,MR_SC_TITLE_13,True
Mr_print_hdr,MR_SC_TITLE_14,True
Mr_print_hdr,MR_SC_TITLE_15,True
Mr_print_hdr,MR_SC_TITLE_16,True
Mr_print_hdr,MR_SC_TITLE_17,True
Mr_print_hdr,MR_SC_TITLE_18,True
Mr_print_hdr,MR_SC_TITLE_19,True
Mr_print_hdr,MR_SC_TITLE_20,True
Mr_print_hdr,MR_SC_TITLE_21,True
Mr_print_hdr,MR_SC_TITLE_22,True
Mr_print_hdr,MR_SC_TITLE_23,True
Mr_print_hdr,MR_SC_TITLE_24,True
Mr_print_hdr,MR_SC_TITLE_25,True
Mr_print_hdr,MR_SC_TITLE_26,True
Mr_print_hdr,MR_SC_TITLE_27,True
Mr_print_hdr,MR_SC_TITLE_28,True
Mr_print_hdr,MR_SC_TITLE_29,True
Mr_print_hdr,MR_SC_TITLE_30,True
Mr_print_hdr,PROGRAM_TITLE_01,True
Mr_print_hdr,PROGRAM_TITLE_02,True
Mr_print_hdr,PROGRAM_TITLE_03,True
Mr_print_hdr,PROGRAM_TITLE_04,True
Mr_print_hdr,PROGRAM_TITLE_05,True
Mr_print_hdr,PROGRAM_TITLE_06,True
Mr_print_hdr,PROGRAM_TITLE_07,True
Mr_print_hdr,PROGRAM_TITLE_08,True
Mr_print_hdr,PROGRAM_TITLE_09,True
Mr_print_hdr,PROGRAM_TITLE_10,True
Mr_print_hdr,PROGRAM_TITLE_11,True
Mr_print_hdr,PROGRAM_TITLE_12,True
Mr_print_hdr,MR_PRINT_KEY,True
Mr_print_hdr,CHANGE_DATE_TIME,True
Mr_print_hdr,CHANGE_UID,True
mr_level_det,DISTRICT,True
mr_level_det,BUILDING,True
mr_level_det,LEVEL_NUMBER,True
mr_level_det,MARK,True
mr_level_det,NUMERIC_VALUE,True
mr_level_det,POINT_VALUE,True
mr_level_det,PASSING_MARK,True
mr_level_det,RC_PRINT_VALUE,True
mr_level_det,TRN_PRINT_VALUE,True
mr_level_det,IPR_PRINT_VALUE,True
mr_level_det,ADDON_POINTS,True
mr_level_det,WEIGHT_BY_CRED,True
mr_level_det,AVERAGE_USAGE,True
mr_level_det,STATE_CODE_EQUIV,True
mr_level_det,COLOR_LEVEL,True
mr_level_det,ROW_IDENTITY,True
mr_level_det,CHANGE_DATE_TIME,True
mr_level_det,CHANGE_UID,True
mr_ipr_view_hdr,DISTRICT,True
mr_ipr_view_hdr,SCHOOL_YEAR,True
mr_ipr_view_hdr,BUILDING,True
mr_ipr_view_hdr,VIEW_TYPE,True
mr_ipr_view_hdr,GRADE,True
mr_ipr_view_hdr,REPORT_TEMPLATE,True
mr_ipr_view_hdr,PRINT_DROPPED_CRS,True
mr_ipr_view_hdr,PRINT_LEGEND,True
mr_ipr_view_hdr,PRINT_MBS,True
mr_ipr_view_hdr,HEADER_TEXT,True
mr_ipr_view_hdr,FOOTER_TEXT,True
mr_ipr_view_hdr,CHANGE_DATE_TIME,True
mr_ipr_view_hdr,CHANGE_UID,True
Mr_ipr_view_det,DISTRICT,True
Mr_ipr_view_det,SCHOOL_YEAR,True
Mr_ipr_view_det,BUILDING,True
Mr_ipr_view_det,VIEW_TYPE,True
Mr_ipr_view_det,GRADE,True
Mr_ipr_view_det,VIEW_SEQUENCE,True
Mr_ipr_view_det,VIEW_ORDER,True
Mr_ipr_view_det,SLOT_TYPE,True
Mr_ipr_view_det,SLOT_CODE,True
Mr_ipr_view_det,TITLE,True
Mr_ipr_view_det,CHANGE_DATE_TIME,True
Mr_ipr_view_det,CHANGE_UID,True
mr_level_marks,DISTRICT,True
mr_level_marks,BUILDING,True
mr_level_marks,MARK,True
mr_level_marks,DISPLAY_ORDER,True
mr_level_marks,ACTIVE,True
mr_level_marks,STATE_CODE_EQUIV,True
mr_level_marks,COURSE_COMPLETED,True
mr_level_marks,CHANGE_DATE_TIME,True
mr_level_marks,CHANGE_UID,True
Mr_ipr_view_att,DISTRICT,True
Mr_ipr_view_att,SCHOOL_YEAR,True
Mr_ipr_view_att,BUILDING,True
Mr_ipr_view_att,VIEW_TYPE,True
Mr_ipr_view_att,GRADE,True
Mr_ipr_view_att,ATT_VIEW_TYPE,True
Mr_ipr_view_att,VIEW_ORDER,True
Mr_ipr_view_att,ATT_TITLE,True
Mr_ipr_view_att,ATT_VIEW_INTERVAL,True
Mr_ipr_view_att,ATT_VIEW_SUM_BY,True
Mr_ipr_view_att,ATT_VIEW_CODE_GRP,True
Mr_ipr_view_att,CHANGE_DATE_TIME,True
Mr_ipr_view_att,CHANGE_UID,True
Mr_ipr_taken,DISTRICT,True
Mr_ipr_taken,SECTION_KEY,True
Mr_ipr_taken,COURSE_SESSION,True
Mr_ipr_taken,RUN_DATE,True
Mr_ipr_taken,CHANGE_DATE_TIME,True
Mr_ipr_taken,CHANGE_UID,True
Mr_ipr_stu_message,DISTRICT,True
Mr_ipr_stu_message,STUDENT_ID,True
Mr_ipr_stu_message,SECTION_KEY,True
Mr_ipr_stu_message,COURSE_SESSION,True
Mr_ipr_stu_message,IPR_DATE,True
Mr_ipr_stu_message,MESSAGE_ORDER,True
Mr_ipr_stu_message,MESSAGE_VALUE,True
Mr_ipr_stu_message,CHANGE_DATE_TIME,True
Mr_ipr_stu_message,CHANGE_UID,True
Mr_ipr_stu_marks,DISTRICT,True
Mr_ipr_stu_marks,STUDENT_ID,True
Mr_ipr_stu_marks,SECTION_KEY,True
Mr_ipr_stu_marks,COURSE_SESSION,True
Mr_ipr_stu_marks,IPR_DATE,True
Mr_ipr_stu_marks,MARK_TYPE,True
Mr_ipr_stu_marks,MARK_VALUE,True
Mr_ipr_stu_marks,CHANGE_DATE_TIME,True
Mr_ipr_stu_marks,CHANGE_UID,True
tac_seat_crs_hdr,DISTRICT,True
tac_seat_crs_hdr,SECTION_KEY,True
tac_seat_crs_hdr,COURSE_SESSION,True
tac_seat_crs_hdr,LAYOUT_TYPE,True
tac_seat_crs_hdr,NUM_GRID_COLS,True
tac_seat_crs_hdr,NUM_GRID_ROWS,True
tac_seat_crs_hdr,CHANGE_DATE_TIME,True
tac_seat_crs_hdr,CHANGE_UID,True
mr_ipr_stu_eligible,DISTRICT,True
mr_ipr_stu_eligible,SCHOOL_YEAR,True
mr_ipr_stu_eligible,SUMMER_SCHOOL,True
mr_ipr_stu_eligible,BUILDING,True
mr_ipr_stu_eligible,STUDENT_ID,True
mr_ipr_stu_eligible,IPR_DATE,True
mr_ipr_stu_eligible,DISQUAL_REASON,True
mr_ipr_stu_eligible,ELIG_TYPE,True
mr_ipr_stu_eligible,ELIGIBILITY_CODE,True
mr_ipr_stu_eligible,EFFECTIVE_DATE,True
mr_ipr_stu_eligible,EXPIRATION_DATE,True
mr_ipr_stu_eligible,CHANGE_DATE_TIME,True
mr_ipr_stu_eligible,CHANGE_UID,True
Mr_ipr_stu_com,DISTRICT,True
Mr_ipr_stu_com,STUDENT_ID,True
Mr_ipr_stu_com,SECTION_KEY,True
Mr_ipr_stu_com,COURSE_SESSION,True
Mr_ipr_stu_com,IPR_DATE,True
Mr_ipr_stu_com,COMMENT_TYPE,True
Mr_ipr_stu_com,COMMENT_VALUE,True
Mr_ipr_stu_com,CHANGE_DATE_TIME,True
Mr_ipr_stu_com,CHANGE_UID,True
mr_ipr_stu_at_risk,DISTRICT,True
mr_ipr_stu_at_risk,SCHOOL_YEAR,True
mr_ipr_stu_at_risk,SUMMER_SCHOOL,True
mr_ipr_stu_at_risk,BUILDING,True
mr_ipr_stu_at_risk,STUDENT_ID,True
mr_ipr_stu_at_risk,IPR_DATE,True
mr_ipr_stu_at_risk,AT_RISK_TYPE,True
mr_ipr_stu_at_risk,DISQUAL_REASON,True
mr_ipr_stu_at_risk,AT_RISK_REASON,True
mr_ipr_stu_at_risk,EFFECTIVE_DATE,True
mr_ipr_stu_at_risk,EXPIRATION_DATE,True
mr_ipr_stu_at_risk,PLAN_NUM,True
mr_ipr_stu_at_risk,CHANGE_DATE_TIME,True
mr_ipr_stu_at_risk,CHANGE_UID,True
Mr_ipr_stu_abs,DISTRICT,True
Mr_ipr_stu_abs,STUDENT_ID,True
Mr_ipr_stu_abs,SECTION_KEY,True
Mr_ipr_stu_abs,COURSE_SESSION,True
Mr_ipr_stu_abs,IPR_DATE,True
Mr_ipr_stu_abs,ABSENCE_TYPE,True
Mr_ipr_stu_abs,ABSENCE_VALUE,True
Mr_ipr_stu_abs,OVERRIDE,True
Mr_ipr_stu_abs,CHANGE_DATE_TIME,True
Mr_ipr_stu_abs,CHANGE_UID,True
mr_ipr_run,DISTRICT,True
mr_ipr_run,SCHOOL_YEAR,True
mr_ipr_run,BUILDING,True
mr_ipr_run,TRACK,True
mr_ipr_run,RUN_DATE,True
mr_ipr_run,ELIGIBILITY,True
mr_ipr_run,CHANGE_DATE_TIME,True
mr_ipr_run,CHANGE_UID,True
mr_ipr_view_att_it,DISTRICT,True
mr_ipr_view_att_it,SCHOOL_YEAR,True
mr_ipr_view_att_it,BUILDING,True
mr_ipr_view_att_it,VIEW_TYPE,True
mr_ipr_view_att_it,GRADE,True
mr_ipr_view_att_it,VIEW_ORDER,True
mr_ipr_view_att_it,ATT_VIEW_INTERVAL,True
mr_ipr_view_att_it,CHANGE_DATE_TIME,True
mr_ipr_view_att_it,CHANGE_UID,True
mr_ipr_stu_hdr,DISTRICT,True
mr_ipr_stu_hdr,STUDENT_ID,True
mr_ipr_stu_hdr,SECTION_KEY,True
mr_ipr_stu_hdr,COURSE_SESSION,True
mr_ipr_stu_hdr,IPR_DATE,True
mr_ipr_stu_hdr,INDIVIDUAL_IPR,True
mr_ipr_stu_hdr,CHANGE_DATE_TIME,True
mr_ipr_stu_hdr,CHANGE_UID,True
mr_ipr_prt_stu_det,IPR_PRINT_KEY,True
mr_ipr_prt_stu_det,STUDENT_ID,True
mr_ipr_prt_stu_det,SECTION_KEY,True
mr_ipr_prt_stu_det,COURSE_BUILDING,True
mr_ipr_prt_stu_det,COURSE,True
mr_ipr_prt_stu_det,COURSE_SECTION,True
mr_ipr_prt_stu_det,COURSE_SESSION,True
mr_ipr_prt_stu_det,DESCRIPTION,True
mr_ipr_prt_stu_det,CRS_PERIOD,True
mr_ipr_prt_stu_det,PRIMARY_STAFF_ID,True
mr_ipr_prt_stu_det,STAFF_NAME,True
mr_ipr_prt_stu_det,ROOM_ID,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_01,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_02,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_03,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_04,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_05,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_06,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_07,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_08,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_09,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_10,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_11,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_12,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_13,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_14,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_15,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_16,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_17,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_18,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_19,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_20,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_21,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_22,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_23,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_24,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_25,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_26,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_27,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_28,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_29,True
mr_ipr_prt_stu_det,IPR_DATA_VALUE_30,True
mr_ipr_prt_stu_det,CHANGE_DATE_TIME,True
mr_ipr_prt_stu_det,CHANGE_UID,True
Mr_ipr_prt_stu_com,IPR_PRINT_KEY,True
Mr_ipr_prt_stu_com,STUDENT_ID,True
Mr_ipr_prt_stu_com,SECTION_KEY,True
Mr_ipr_prt_stu_com,COURSE_SESSION,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_01,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_02,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_03,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_04,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_05,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_06,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_07,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_08,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_09,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_10,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_11,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_12,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_13,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_14,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_15,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_16,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_17,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_18,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_19,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_20,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_21,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_22,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_23,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_24,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_25,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_26,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_27,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_28,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_29,True
Mr_ipr_prt_stu_com,IPR_DATA_DESCR_30,True
Mr_ipr_prt_stu_com,CHANGE_DATE_TIME,True
Mr_ipr_prt_stu_com,CHANGE_UID,True
mr_ipr_elig_setup,DISTRICT,True
mr_ipr_elig_setup,BUILDING,True
mr_ipr_elig_setup,ELIG_TYPE,True
mr_ipr_elig_setup,DESCRIPTION,True
mr_ipr_elig_setup,PROCESSING_ORDER,True
mr_ipr_elig_setup,MINIMUM_COURSES,True
mr_ipr_elig_setup,INCLUDE_NOT_ENDED,True
mr_ipr_elig_setup,INCLUDE_BLANK_MARK,True
mr_ipr_elig_setup,DISQUAL_BLANK_MARK,True
mr_ipr_elig_setup,MAX_BLANK_MARK,True
mr_ipr_elig_setup,ACTIVE,True
mr_ipr_elig_setup,ELIG_INCLUDE_PRIOR,True
mr_ipr_elig_setup,ELIGIBILITY_CODE,True
mr_ipr_elig_setup,ELIG_DURATION,True
mr_ipr_elig_setup,ELIG_DURATION_DAYS,True
mr_ipr_elig_setup,USE_AT_RISK,True
mr_ipr_elig_setup,AT_RISK_REASON,True
mr_ipr_elig_setup,AT_RISK_DURATION,True
mr_ipr_elig_setup,AT_RISK_DAYS,True
mr_ipr_elig_setup,CHANGE_DATE_TIME,True
mr_ipr_elig_setup,CHANGE_UID,True
mr_honor_setup,DISTRICT,True
mr_honor_setup,BUILDING,True
mr_honor_setup,HONOR_TYPE,True
mr_honor_setup,DESCRIPTION,True
mr_honor_setup,HONOR_GROUP,True
mr_honor_setup,PROCESSING_ORDER,True
mr_honor_setup,PROCESS_GPA,True
mr_honor_setup,CURRENT_OR_YTD_GPA,True
mr_honor_setup,MINIMUM_GPA,True
mr_honor_setup,MAXIMUM_GPA,True
mr_honor_setup,GPA_PRECISION,True
mr_honor_setup,MINIMUM_COURSES,True
mr_honor_setup,INCLUDE_NOT_ENDED,True
mr_honor_setup,INCLUDE_NON_HR_CRS,True
mr_honor_setup,MINIMUM_ERN_CREDIT,True
mr_honor_setup,MINIMUM_ATT_CREDIT,True
mr_honor_setup,ATT_CREDIT_TO_USE,True
mr_honor_setup,USE_PARTIAL_CREDIT,True
mr_honor_setup,INCLUDE_NON_HR_CRD,True
mr_honor_setup,INCLUDE_BLANK_MARK,True
mr_honor_setup,DISQUAL_BLANK_MARK,True
mr_honor_setup,MAX_BLANK_MARK,True
mr_honor_setup,INCLUDE_AS_DEFAULT,True
mr_honor_setup,HONOR_MESSAGE,True
mr_honor_setup,ACTIVE,True
mr_honor_setup,ELIG_INCLUDE_PRIOR,True
mr_honor_setup,ELIGIBILITY_CODE,True
mr_honor_setup,ELIG_DURATION,True
mr_honor_setup,ELIG_DURATION_DAYS,True
mr_honor_setup,AT_RISK_REASON,True
mr_honor_setup,AT_RISK_RESET_NUM,True
mr_honor_setup,AT_RISK_RESET_TYPE,True
mr_honor_setup,OPTION_TYPE,True
mr_honor_setup,CHANGE_DATE_TIME,True
mr_honor_setup,CHANGE_UID,True
mr_grad_req_hdr,DISTRICT,True
mr_grad_req_hdr,REQ_GROUP,True
mr_grad_req_hdr,STU_GRAD_YEAR,True
mr_grad_req_hdr,RETAKE_COURSE_RULE,True
mr_grad_req_hdr,WAIVED,True
mr_grad_req_hdr,CHANGE_DATE_TIME,True
mr_grad_req_hdr,CHANGE_UID,True
Mr_grad_req_focus,DISTRICT,True
Mr_grad_req_focus,REQ_GROUP,True
Mr_grad_req_focus,STU_GRAD_YEAR,True
Mr_grad_req_focus,REQUIRE_CODE,True
Mr_grad_req_focus,MAJOR_CRITERIA,True
Mr_grad_req_focus,MINOR_CRITERIA,True
Mr_grad_req_focus,CREDIT,True
Mr_grad_req_focus,CHANGE_DATE_TIME,True
Mr_grad_req_focus,CHANGE_UID,True
mr_grad_req_det,DISTRICT,True
mr_grad_req_det,REQ_GROUP,True
mr_grad_req_det,STU_GRAD_YEAR,True
mr_grad_req_det,REQUIRE_CODE,True
mr_grad_req_det,REQ_ORDER,True
mr_grad_req_det,CREDIT,True
mr_grad_req_det,MIN_MARK_VALUE,True
mr_grad_req_det,REQ_VALUE,True
mr_grad_req_det,REQ_UNITS,True
mr_grad_req_det,CHANGE_DATE_TIME,True
mr_grad_req_det,CHANGE_UID,True
mr_gpa_setup,DISTRICT,True
mr_gpa_setup,GPA_TYPE,True
mr_gpa_setup,DESCRIPTION,True
mr_gpa_setup,ISSUE_GPA,True
mr_gpa_setup,ATT_CREDIT_TO_USE,True
mr_gpa_setup,USE_PARTIAL,True
mr_gpa_setup,COURSE_NOT_ENDED,True
mr_gpa_setup,BLANK_MARKS,True
mr_gpa_setup,INCLUDE_AS_DEFAULT,True
mr_gpa_setup,ACTIVE,True
mr_gpa_setup,GPA_PRECISION,True
mr_gpa_setup,RANK_INACTIVES,True
mr_gpa_setup,STATE_CRS_EQUIV,True
mr_gpa_setup,ADD_ON_POINTS,True
mr_gpa_setup,DISTRICT_WIDE_RANK,True
mr_gpa_setup,INCLUDE_PERFPLUS,True
mr_gpa_setup,DISPLAY_RANK,True
mr_gpa_setup,DISPLAY_PERCENTILE,True
mr_gpa_setup,DISPLAY_DECILE,True
mr_gpa_setup,DISPLAY_QUARTILE,True
mr_gpa_setup,DISPLAY_QUINTILE,True
mr_gpa_setup,RANK_ON_GPA,True
mr_gpa_setup,PERCENTILE_MODE,True
mr_gpa_setup,PERCENTILE_RANK_TYPE,True
mr_gpa_setup,CHANGE_DATE_TIME,True
mr_gpa_setup,CHANGE_UID,True
Mr_gb_stu_score,DISTRICT,True
Mr_gb_stu_score,SECTION_KEY,True
Mr_gb_stu_score,COURSE_SESSION,True
Mr_gb_stu_score,ASMT_NUMBER,True
Mr_gb_stu_score,STUDENT_ID,True
Mr_gb_stu_score,ASMT_SCORE,True
Mr_gb_stu_score,ASMT_EXCEPTION,True
Mr_gb_stu_score,ASMT_ALPHA_MARK,True
Mr_gb_stu_score,EXCLUDE_LOWEST,True
Mr_gb_stu_score,CHANGE_DATE_TIME,True
Mr_gb_stu_score,CHANGE_UID,True
mr_gb_stu_scale,DISTRICT,True
mr_gb_stu_scale,SECTION_KEY,True
mr_gb_stu_scale,COURSE_SESSION,True
mr_gb_stu_scale,MARKING_PERIOD,True
mr_gb_stu_scale,STUDENT_ID,True
mr_gb_stu_scale,SCALE,True
mr_gb_stu_scale,CHANGE_DATE_TIME,True
mr_gb_stu_scale,CHANGE_UID,True
mr_ipr_prt_stu_hdr,IPR_PRINT_KEY,True
mr_ipr_prt_stu_hdr,STUDENT_ID,True
mr_ipr_prt_stu_hdr,STUDENT_NAME,True
mr_ipr_prt_stu_hdr,BUILDING,True
mr_ipr_prt_stu_hdr,GRADE,True
mr_ipr_prt_stu_hdr,TRACK,True
mr_ipr_prt_stu_hdr,COUNSELOR,True
mr_ipr_prt_stu_hdr,HOUSE_TEAM,True
mr_ipr_prt_stu_hdr,HOMEROOM_PRIMARY,True
mr_ipr_prt_stu_hdr,DAILY_ATT_DESCR_01,True
mr_ipr_prt_stu_hdr,DAILY_ATT_DESCR_02,True
mr_ipr_prt_stu_hdr,DAILY_ATT_DESCR_03,True
mr_ipr_prt_stu_hdr,DAILY_ATT_DESCR_04,True
mr_ipr_prt_stu_hdr,DAILY_ATT_DESCR_05,True
mr_ipr_prt_stu_hdr,DAILY_ATT_DESCR_06,True
mr_ipr_prt_stu_hdr,DAILY_ATT_DESCR_07,True
mr_ipr_prt_stu_hdr,DAILY_ATT_DESCR_08,True
mr_ipr_prt_stu_hdr,DAILY_ATT_DESCR_09,True
mr_ipr_prt_stu_hdr,DAILY_ATT_DESCR_10,True
mr_ipr_prt_stu_hdr,DAILY_ATT_CURR_01,True
mr_ipr_prt_stu_hdr,DAILY_ATT_CURR_02,True
mr_ipr_prt_stu_hdr,DAILY_ATT_CURR_03,True
mr_ipr_prt_stu_hdr,DAILY_ATT_CURR_04,True
mr_ipr_prt_stu_hdr,DAILY_ATT_CURR_05,True
mr_ipr_prt_stu_hdr,DAILY_ATT_CURR_06,True
mr_ipr_prt_stu_hdr,DAILY_ATT_CURR_07,True
mr_ipr_prt_stu_hdr,DAILY_ATT_CURR_08,True
mr_ipr_prt_stu_hdr,DAILY_ATT_CURR_09,True
mr_ipr_prt_stu_hdr,DAILY_ATT_CURR_10,True
mr_ipr_prt_stu_hdr,DAILY_ATT_YTD_01,True
mr_ipr_prt_stu_hdr,DAILY_ATT_YTD_02,True
mr_ipr_prt_stu_hdr,DAILY_ATT_YTD_03,True
mr_ipr_prt_stu_hdr,DAILY_ATT_YTD_04,True
mr_ipr_prt_stu_hdr,DAILY_ATT_YTD_05,True
mr_ipr_prt_stu_hdr,DAILY_ATT_YTD_06,True
mr_ipr_prt_stu_hdr,DAILY_ATT_YTD_07,True
mr_ipr_prt_stu_hdr,DAILY_ATT_YTD_08,True
mr_ipr_prt_stu_hdr,DAILY_ATT_YTD_09,True
mr_ipr_prt_stu_hdr,DAILY_ATT_YTD_10,True
mr_ipr_prt_stu_hdr,REPORT_TEMPLATE,True
mr_ipr_prt_stu_hdr,CHANGE_DATE_TIME,True
mr_ipr_prt_stu_hdr,CHANGE_UID,True
mr_gb_stu_comps_stu_notes,DISTRICT,True
mr_gb_stu_comps_stu_notes,BUILDING,True
mr_gb_stu_comps_stu_notes,COMPETENCY_GROUP,True
mr_gb_stu_comps_stu_notes,STAFF_ID,True
mr_gb_stu_comps_stu_notes,STUDENT_ID,True
mr_gb_stu_comps_stu_notes,NOTE_DATE,True
mr_gb_stu_comps_stu_notes,STU_NOTES,True
mr_gb_stu_comps_stu_notes,PUBLISH_NOTE,True
mr_gb_stu_comps_stu_notes,CHANGE_DATE_TIME,True
mr_gb_stu_comps_stu_notes,CHANGE_UID,True
mr_gb_stu_comps_stu_asmt_cmt,DISTRICT,True
mr_gb_stu_comps_stu_asmt_cmt,BUILDING,True
mr_gb_stu_comps_stu_asmt_cmt,COMPETENCY_GROUP,True
mr_gb_stu_comps_stu_asmt_cmt,STAFF_ID,True
mr_gb_stu_comps_stu_asmt_cmt,ASMT_NUMBER,True
mr_gb_stu_comps_stu_asmt_cmt,STUDENT_ID,True
mr_gb_stu_comps_stu_asmt_cmt,COMMENT_CODE,True
mr_gb_stu_comps_stu_asmt_cmt,COMMENT_TEXT,True
mr_gb_stu_comps_stu_asmt_cmt,PUBLISH,True
mr_gb_stu_comps_stu_asmt_cmt,CHANGE_DATE_TIME,True
mr_gb_stu_comps_stu_asmt_cmt,CHANGE_UID,True
mr_gb_stu_comp_stu_score,DISTRICT,True
mr_gb_stu_comp_stu_score,BUILDING,True
mr_gb_stu_comp_stu_score,STAFF_ID,True
mr_gb_stu_comp_stu_score,COMPETENCY_GROUP,True
mr_gb_stu_comp_stu_score,ASMT_NUMBER,True
mr_gb_stu_comp_stu_score,STUDENT_ID,True
mr_gb_stu_comp_stu_score,ASMT_SCORE,True
mr_gb_stu_comp_stu_score,ASMT_EXCEPTION,True
mr_gb_stu_comp_stu_score,ASMT_ALPHA_MARK,True
mr_gb_stu_comp_stu_score,EXCLUDE_LOWEST,True
mr_gb_stu_comp_stu_score,CHANGE_DATE_TIME,True
mr_gb_stu_comp_stu_score,CHANGE_UID,True
Mr_sc_stu_comp,DISTRICT,True
Mr_sc_stu_comp,SCHOOL_YEAR,True
Mr_sc_stu_comp,STUDENT_ID,True
Mr_sc_stu_comp,COMPETENCY_GROUP,True
Mr_sc_stu_comp,COMPETENCY_NUMBER,True
Mr_sc_stu_comp,MARKING_PERIOD,True
Mr_sc_stu_comp,BUILDING,True
Mr_sc_stu_comp,MARK_TYPE,True
Mr_sc_stu_comp,MARK_VALUE,True
Mr_sc_stu_comp,MARK_OVERRIDE,True
Mr_sc_stu_comp,CHANGE_DATE_TIME,True
Mr_sc_stu_comp,CHANGE_UID,True
Mr_gb_stu_notes,DISTRICT,True
Mr_gb_stu_notes,SECTION_KEY,True
Mr_gb_stu_notes,COURSE_SESSION,True
Mr_gb_stu_notes,STUDENT_ID,True
Mr_gb_stu_notes,NOTE_DATE,True
Mr_gb_stu_notes,STU_NOTES,True
Mr_gb_stu_notes,PUBLISH_NOTE,True
Mr_gb_stu_notes,CHANGE_DATE_TIME,True
Mr_gb_stu_notes,CHANGE_UID,True
Mr_sc_stu_crs_comm,DISTRICT,True
Mr_sc_stu_crs_comm,SCHOOL_YEAR,True
Mr_sc_stu_crs_comm,STUDENT_ID,True
Mr_sc_stu_crs_comm,BUILDING,True
Mr_sc_stu_crs_comm,COURSE,True
Mr_sc_stu_crs_comm,COMPETENCY_GROUP,True
Mr_sc_stu_crs_comm,COMPETENCY_NUMBER,True
Mr_sc_stu_crs_comm,MARKING_PERIOD,True
Mr_sc_stu_crs_comm,COMMENT_TYPE,True
Mr_sc_stu_crs_comm,CODE,True
Mr_sc_stu_crs_comm,CHANGE_DATE_TIME,True
Mr_sc_stu_crs_comm,CHANGE_UID,True
mr_sc_st_standard,DISTRICT,True
mr_sc_st_standard,STATE,True
mr_sc_st_standard,DOCUMENT_NAME,True
mr_sc_st_standard,SUBJECT,True
mr_sc_st_standard,SCHOOL_YEAR,True
mr_sc_st_standard,GRADE,True
mr_sc_st_standard,GUID,True
mr_sc_st_standard,STATE_STANDARD_NUM,True
mr_sc_st_standard,LEVEL_NUMBER,True
mr_sc_st_standard,NUM_OF_CHILDREN,True
mr_sc_st_standard,LABEL,True
mr_sc_st_standard,TITLE,True
mr_sc_st_standard,DESCRIPTION,True
mr_sc_st_standard,PARENT_GUID,True
mr_sc_st_standard,LOW_GRADE,True
mr_sc_st_standard,HIGH_GRADE,True
mr_sc_st_standard,AB_GUID,True
mr_sc_st_standard,PP_GUID,True
mr_sc_st_standard,PP_PARENT_GUID,True
mr_sc_st_standard,PP_ID,True
mr_sc_st_standard,PP_PARENT_ID,True
mr_sc_st_standard,RESERVED,True
mr_sc_st_standard,CHANGE_DATE_TIME,True
mr_sc_st_standard,CHANGE_UID,True
mr_sc_crsstu_taken,DISTRICT,True
mr_sc_crsstu_taken,SECTION_KEY,True
mr_sc_crsstu_taken,COURSE_SESSION,True
mr_sc_crsstu_taken,COMPETENCY_GROUP,True
mr_sc_crsstu_taken,MARKING_PERIOD,True
mr_sc_crsstu_taken,STUDENT_ID,True
mr_sc_crsstu_taken,CHANGE_DATE_TIME,True
mr_sc_crsstu_taken,CHANGE_UID,True
Mr_ipr_prt_stu_msg,IPR_PRINT_KEY,True
Mr_ipr_prt_stu_msg,STUDENT_ID,True
Mr_ipr_prt_stu_msg,SECTION_KEY,True
Mr_ipr_prt_stu_msg,COURSE_SESSION,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_01,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_02,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_03,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_04,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_05,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_06,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_07,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_08,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_09,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_10,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_11,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_12,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_13,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_14,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_15,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_16,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_17,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_18,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_19,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_20,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_21,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_22,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_23,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_24,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_25,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_26,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_27,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_28,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_29,True
Mr_ipr_prt_stu_msg,IPR_MESSAGE_30,True
Mr_ipr_prt_stu_msg,CHANGE_DATE_TIME,True
Mr_ipr_prt_stu_msg,CHANGE_UID,True
Mr_sc_comp_stu,DISTRICT,True
Mr_sc_comp_stu,BUILDING,True
Mr_sc_comp_stu,SCHOOL_YEAR,True
Mr_sc_comp_stu,COMPETENCY_GROUP,True
Mr_sc_comp_stu,SEQUENCE_NUMBER,True
Mr_sc_comp_stu,AND_OR_FLAG,True
Mr_sc_comp_stu,TABLE_NAME,True
Mr_sc_comp_stu,SCREEN_TYPE,True
Mr_sc_comp_stu,SCREEN_NUMBER,True
Mr_sc_comp_stu,COLUMN_NAME,True
Mr_sc_comp_stu,FIELD_NUMBER,True
Mr_sc_comp_stu,OPERATOR,True
Mr_sc_comp_stu,SEARCH_VALUE,True
Mr_sc_comp_stu,CHANGE_DATE_TIME,True
Mr_sc_comp_stu,CHANGE_UID,True
Mr_sc_stu_comment,DISTRICT,True
Mr_sc_stu_comment,SCHOOL_YEAR,True
Mr_sc_stu_comment,STUDENT_ID,True
Mr_sc_stu_comment,COMPETENCY_GROUP,True
Mr_sc_stu_comment,COMPETENCY_NUMBER,True
Mr_sc_stu_comment,MARKING_PERIOD,True
Mr_sc_stu_comment,BUILDING,True
Mr_sc_stu_comment,COMMENT_TYPE,True
Mr_sc_stu_comment,CODE,True
Mr_sc_stu_comment,CHANGE_DATE_TIME,True
Mr_sc_stu_comment,CHANGE_UID,True
mr_sc_comp_hdr,DISTRICT,True
mr_sc_comp_hdr,SCHOOL_YEAR,True
mr_sc_comp_hdr,DISTR_OR_BLDG,True
mr_sc_comp_hdr,COMPETENCY_GROUP,True
mr_sc_comp_hdr,BUILDING,True
mr_sc_comp_hdr,BUILDING_TYPE,True
mr_sc_comp_hdr,DESCRIPTION,True
mr_sc_comp_hdr,SEQUENCE_ORDER,True
mr_sc_comp_hdr,COMPETENCY_TYPE,True
mr_sc_comp_hdr,CHANGE_DATE_TIME,True
mr_sc_comp_hdr,CHANGE_UID,True
mr_sc_comp_det,DISTRICT,True
mr_sc_comp_det,BUILDING,True
mr_sc_comp_det,SCHOOL_YEAR,True
mr_sc_comp_det,COMPETENCY_GROUP,True
mr_sc_comp_det,COMPETENCY_NUMBER,True
mr_sc_comp_det,DESCRIPTION,True
mr_sc_comp_det,SEQUENCE_NUMBER,True
mr_sc_comp_det,FORMAT_LEVEL,True
mr_sc_comp_det,HEADING_ONLY,True
mr_sc_comp_det,GRADING_SCALE,True
mr_sc_comp_det,USE_DEFAULT_MARK,True
mr_sc_comp_det,STATE_STANDARD_NUM,True
mr_sc_comp_det,ACCUMULATOR_TYPE,True
mr_sc_comp_det,CHANGE_DATE_TIME,True
mr_sc_comp_det,CHANGE_UID,True
Mr_sc_crs_taken,DISTRICT,True
Mr_sc_crs_taken,SECTION_KEY,True
Mr_sc_crs_taken,COURSE_SESSION,True
Mr_sc_crs_taken,COMPETENCY_GROUP,True
Mr_sc_crs_taken,MARKING_PERIOD,True
Mr_sc_crs_taken,CHANGE_DATE_TIME,True
Mr_sc_crs_taken,CHANGE_UID,True
mr_req_areas,DISTRICT,True
mr_req_areas,CODE,True
mr_req_areas,DESCRIPTION,True
mr_req_areas,AREA_TYPE,True
mr_req_areas,STATE_CODE_EQUIV,True
mr_req_areas,ACTIVE,True
mr_req_areas,CHANGE_DATE_TIME,True
mr_req_areas,CHANGE_UID,True
Mr_rc_view_stucmp,DISTRICT,True
Mr_rc_view_stucmp,SCHOOL_YEAR,True
Mr_rc_view_stucmp,BUILDING,True
Mr_rc_view_stucmp,VIEW_TYPE,True
Mr_rc_view_stucmp,RC_RUN,True
Mr_rc_view_stucmp,GRADE,True
Mr_rc_view_stucmp,VIEW_SEQUENCE,True
Mr_rc_view_stucmp,VIEW_ORDER,True
Mr_rc_view_stucmp,TITLE,True
Mr_rc_view_stucmp,SLOT_TYPE,True
Mr_rc_view_stucmp,SLOT_CODE,True
Mr_rc_view_stucmp,CHANGE_DATE_TIME,True
Mr_rc_view_stucmp,CHANGE_UID,True
Mr_rc_view_sp_mp,DISTRICT,True
Mr_rc_view_sp_mp,SCHOOL_YEAR,True
Mr_rc_view_sp_mp,BUILDING,True
Mr_rc_view_sp_mp,VIEW_TYPE,True
Mr_rc_view_sp_mp,RC_RUN,True
Mr_rc_view_sp_mp,GRADE,True
Mr_rc_view_sp_mp,PROGRAM_ID,True
Mr_rc_view_sp_mp,FIELD_NUMBER,True
Mr_rc_view_sp_mp,COLUMN_NUMBER,True
Mr_rc_view_sp_mp,SEARCH_MP,True
Mr_rc_view_sp_mp,CHANGE_DATE_TIME,True
Mr_rc_view_sp_mp,CHANGE_UID,True
Mr_sc_comp_mrks,DISTRICT,True
Mr_sc_comp_mrks,BUILDING,True
Mr_sc_comp_mrks,SCHOOL_YEAR,True
Mr_sc_comp_mrks,COMPETENCY_GROUP,True
Mr_sc_comp_mrks,COMPETENCY_NUMBER,True
Mr_sc_comp_mrks,MARK_TYPE,True
Mr_sc_comp_mrks,CHANGE_DATE_TIME,True
Mr_sc_comp_mrks,CHANGE_UID,True
Mr_rc_view_sp_cols,DISTRICT,True
Mr_rc_view_sp_cols,SCHOOL_YEAR,True
Mr_rc_view_sp_cols,BUILDING,True
Mr_rc_view_sp_cols,VIEW_TYPE,True
Mr_rc_view_sp_cols,RC_RUN,True
Mr_rc_view_sp_cols,GRADE,True
Mr_rc_view_sp_cols,COLUMN_NUMBER,True
Mr_rc_view_sp_cols,TITLE,True
Mr_rc_view_sp_cols,CHANGE_DATE_TIME,True
Mr_rc_view_sp_cols,CHANGE_UID,True
Mr_rc_view_sp,DISTRICT,True
Mr_rc_view_sp,SCHOOL_YEAR,True
Mr_rc_view_sp,BUILDING,True
Mr_rc_view_sp,VIEW_TYPE,True
Mr_rc_view_sp,RC_RUN,True
Mr_rc_view_sp,GRADE,True
Mr_rc_view_sp,VIEW_ORDER,True
Mr_rc_view_sp,LABEL,True
Mr_rc_view_sp,PROGRAM_ID,True
Mr_rc_view_sp,FIELD_NUMBER,True
Mr_rc_view_sp,PRINT_TYPE,True
Mr_rc_view_sp,CHANGE_DATE_TIME,True
Mr_rc_view_sp,CHANGE_UID,True
Mr_rc_view_sc_mp,DISTRICT,True
Mr_rc_view_sc_mp,SCHOOL_YEAR,True
Mr_rc_view_sc_mp,BUILDING,True
Mr_rc_view_sc_mp,VIEW_TYPE,True
Mr_rc_view_sc_mp,RC_RUN,True
Mr_rc_view_sc_mp,GRADE,True
Mr_rc_view_sc_mp,VIEW_SEQUENCE,True
Mr_rc_view_sc_mp,MARKING_PERIOD,True
Mr_rc_view_sc_mp,CHANGE_DATE_TIME,True
Mr_rc_view_sc_mp,CHANGE_UID,True
Mr_rc_view_ltdb,DISTRICT,True
Mr_rc_view_ltdb,SCHOOL_YEAR,True
Mr_rc_view_ltdb,BUILDING,True
Mr_rc_view_ltdb,VIEW_TYPE,True
Mr_rc_view_ltdb,RC_RUN,True
Mr_rc_view_ltdb,GRADE,True
Mr_rc_view_ltdb,VIEW_ORDER,True
Mr_rc_view_ltdb,LABEL,True
Mr_rc_view_ltdb,TEST_CODE,True
Mr_rc_view_ltdb,TEST_LEVEL,True
Mr_rc_view_ltdb,TEST_FORM,True
Mr_rc_view_ltdb,SUBTEST,True
Mr_rc_view_ltdb,SCORE_CODE,True
Mr_rc_view_ltdb,PRINT_TYPE,True
Mr_rc_view_ltdb,PRINT_NUMBER,True
Mr_rc_view_ltdb,CHANGE_DATE_TIME,True
Mr_rc_view_ltdb,CHANGE_UID,True
Mr_rc_view_honor,DISTRICT,True
Mr_rc_view_honor,SCHOOL_YEAR,True
Mr_rc_view_honor,BUILDING,True
Mr_rc_view_honor,VIEW_TYPE,True
Mr_rc_view_honor,RC_RUN,True
Mr_rc_view_honor,GRADE,True
Mr_rc_view_honor,HONOR_SEQUENCE,True
Mr_rc_view_honor,HONOR_GPA_TYPE,True
Mr_rc_view_honor,CHANGE_DATE_TIME,True
Mr_rc_view_honor,CHANGE_UID,True
mr_level_hdr,DISTRICT,True
mr_level_hdr,BUILDING,True
mr_level_hdr,LEVEL_NUMBER,True
mr_level_hdr,DESCRIPTION,True
mr_level_hdr,ACTIVE,True
mr_level_hdr,PESC_CODE,True
mr_level_hdr,ROW_IDENTITY,True
mr_level_hdr,CHANGE_DATE_TIME,True
mr_level_hdr,CHANGE_UID,True
mr_gb_stu_comp_cat_avg,DISTRICT,True
mr_gb_stu_comp_cat_avg,BUILDING,True
mr_gb_stu_comp_cat_avg,COMPETENCY_GROUP,True
mr_gb_stu_comp_cat_avg,STAFF_ID,True
mr_gb_stu_comp_cat_avg,CATEGORY,True
mr_gb_stu_comp_cat_avg,MARKING_PERIOD,True
mr_gb_stu_comp_cat_avg,STUDENT_ID,True
mr_gb_stu_comp_cat_avg,OVERRIDE_AVERAGE,True
mr_gb_stu_comp_cat_avg,CHANGE_DATE_TIME,True
mr_gb_stu_comp_cat_avg,CHANGE_UID,True
mr_gb_stu_comp_accumulated_avg,DISTRICT,True
mr_gb_stu_comp_accumulated_avg,BUILDING,True
mr_gb_stu_comp_accumulated_avg,COMPETENCY_GROUP,True
mr_gb_stu_comp_accumulated_avg,STAFF_ID,True
mr_gb_stu_comp_accumulated_avg,COMPETENCY_NUMBER,True
mr_gb_stu_comp_accumulated_avg,MARKING_PERIOD,True
mr_gb_stu_comp_accumulated_avg,STUDENT_ID,True
mr_gb_stu_comp_accumulated_avg,OVERRIDE_AVERAGE,True
mr_gb_stu_comp_accumulated_avg,AVG_OR_RC_VALUE,True
mr_gb_stu_comp_accumulated_avg,RC_VALUE,True
mr_gb_stu_comp_accumulated_avg,CHANGE_DATE_TIME,True
mr_gb_stu_comp_accumulated_avg,CHANGE_UID,True
mr_gb_stu_asmt_cmt,DISTRICT,True
mr_gb_stu_asmt_cmt,SECTION_KEY,True
mr_gb_stu_asmt_cmt,COURSE_SESSION,True
mr_gb_stu_asmt_cmt,ASMT_NUMBER,True
mr_gb_stu_asmt_cmt,STUDENT_ID,True
mr_gb_stu_asmt_cmt,COMMENT_CODE,True
mr_gb_stu_asmt_cmt,COMMENT_TEXT,True
mr_gb_stu_asmt_cmt,PUBLISH,True
mr_gb_stu_asmt_cmt,CHANGE_DATE_TIME,True
mr_gb_stu_asmt_cmt,CHANGE_UID,True
mr_gb_stu_alias,DISTRICT,True
mr_gb_stu_alias,SECTION_KEY,True
mr_gb_stu_alias,COURSE_SESSION,True
mr_gb_stu_alias,STUDENT_ID,True
mr_gb_stu_alias,ALIAS_NAME,True
mr_gb_stu_alias,DISPLAY_ORDER,True
mr_gb_stu_alias,CHANGE_DATE_TIME,True
mr_gb_stu_alias,CHANGE_UID,True
Mr_gb_session_prop,DISTRICT,True
Mr_gb_session_prop,SECTION_KEY,True
Mr_gb_session_prop,COURSE_SESSION,True
Mr_gb_session_prop,USE_TOTAL_POINTS,True
Mr_gb_session_prop,USE_CAT_WEIGHT,True
Mr_gb_session_prop,ROUND_TRUNC,True
Mr_gb_session_prop,DEFAULT_SCALE,True
Mr_gb_session_prop,CHANGE_DATE_TIME,True
Mr_gb_session_prop,CHANGE_UID,True
mr_rc_view_hdr,DISTRICT,True
mr_rc_view_hdr,SCHOOL_YEAR,True
mr_rc_view_hdr,BUILDING,True
mr_rc_view_hdr,VIEW_TYPE,True
mr_rc_view_hdr,RC_RUN,True
mr_rc_view_hdr,GRADE,True
mr_rc_view_hdr,REPORT_TEMPLATE,True
mr_rc_view_hdr,RANK_GPA_TYPE,True
mr_rc_view_hdr,PRINT_CLASS_RANK,True
mr_rc_view_hdr,PRINT_HONOR_MSG,True
mr_rc_view_hdr,PRINT_DROPPED_CRS,True
mr_rc_view_hdr,PRINT_LEGEND,True
mr_rc_view_hdr,PRINT_MBS,True
mr_rc_view_hdr,HEADER_TEXT,True
mr_rc_view_hdr,FOOTER_TEXT,True
mr_rc_view_hdr,CREDIT_TO_PRINT,True
mr_rc_view_hdr,USE_RC_HOLD,True
mr_rc_view_hdr,HOLD_HEADER_TEXT,True
mr_rc_view_hdr,HOLD_FOOTER_TEXT,True
mr_rc_view_hdr,CURRENT_GPA,True
mr_rc_view_hdr,SEMESTER_GPA,True
mr_rc_view_hdr,CUMULATIVE_GPA,True
mr_rc_view_hdr,CURRENT_CREDIT,True
mr_rc_view_hdr,SEMESTER_CREDIT,True
mr_rc_view_hdr,CUMULATIVE_CREDIT,True
mr_rc_view_hdr,ALT_CURRENT_LBL,True
mr_rc_view_hdr,ALT_SEMESTER_LBL,True
mr_rc_view_hdr,ALT_CUMULATIVE_LBL,True
mr_rc_view_hdr,CHANGE_DATE_TIME,True
mr_rc_view_hdr,CHANGE_UID,True
mr_gb_rubric_perf_lvl,DISTRICT,True
mr_gb_rubric_perf_lvl,RUBRIC_NUMBER,True
mr_gb_rubric_perf_lvl,PERF_LVL_NUMBER,True
mr_gb_rubric_perf_lvl,DESCRIPTION,True
mr_gb_rubric_perf_lvl,PERF_LVL_ORDER,True
mr_gb_rubric_perf_lvl,CHANGE_DATE_TIME,True
mr_gb_rubric_perf_lvl,CHANGE_UID,True
Mr_rc_view_mps,DISTRICT,True
Mr_rc_view_mps,SCHOOL_YEAR,True
Mr_rc_view_mps,BUILDING,True
Mr_rc_view_mps,VIEW_TYPE,True
Mr_rc_view_mps,RC_RUN,True
Mr_rc_view_mps,GRADE,True
Mr_rc_view_mps,VIEW_SEQUENCE,True
Mr_rc_view_mps,MARKING_PERIOD,True
Mr_rc_view_mps,CHANGE_DATE_TIME,True
Mr_rc_view_mps,CHANGE_UID,True
mr_gb_rubric_det,DISTRICT,True
mr_gb_rubric_det,RUBRIC_NUMBER,True
mr_gb_rubric_det,CRITERIA_NUMBER,True
mr_gb_rubric_det,PERF_LVL_NUMBER,True
mr_gb_rubric_det,DESCRIPTION,True
mr_gb_rubric_det,MAX_POINTS,True
mr_gb_rubric_det,CHANGE_DATE_TIME,True
mr_gb_rubric_det,CHANGE_UID,True
mr_gb_rubric_crit,DISTRICT,True
mr_gb_rubric_crit,RUBRIC_NUMBER,True
mr_gb_rubric_crit,CRITERIA_NUMBER,True
mr_gb_rubric_crit,DESCRIPTION,True
mr_gb_rubric_crit,CRITERIA_ORDER,True
mr_gb_rubric_crit,COMPETENCY_GROUP,True
mr_gb_rubric_crit,COMPETENCY_NUMBER,True
mr_gb_rubric_crit,CHANGE_DATE_TIME,True
mr_gb_rubric_crit,CHANGE_UID,True
mr_gb_mp_mark,DISTRICT,True
mr_gb_mp_mark,SECTION_KEY,True
mr_gb_mp_mark,COURSE_SESSION,True
mr_gb_mp_mark,MARK_TYPE,True
mr_gb_mp_mark,MARKING_PERIOD,True
mr_gb_mp_mark,OVERRIDE,True
mr_gb_mp_mark,ROUND_TRUNC,True
mr_gb_mp_mark,CHANGE_DATE_TIME,True
mr_gb_mp_mark,CHANGE_UID,True
mr_gb_scale,DISTRICT,True
mr_gb_scale,SCHOOL_YEAR,True
mr_gb_scale,BUILDING,True
mr_gb_scale,SCALE,True
mr_gb_scale,DESCRIPTION,True
mr_gb_scale,LONG_DESCRIPTION,True
mr_gb_scale,DEFAULT_SCALE,True
mr_gb_scale,CHANGE_DATE_TIME,True
mr_gb_scale,CHANGE_UID,True
mr_gb_ipr_avg,DISTRICT,True
mr_gb_ipr_avg,SECTION_KEY,True
mr_gb_ipr_avg,COURSE_SESSION,True
mr_gb_ipr_avg,MARK_TYPE,True
mr_gb_ipr_avg,IPR_DATE,True
mr_gb_ipr_avg,MARKING_PERIOD,True
mr_gb_ipr_avg,STUDENT_ID,True
mr_gb_ipr_avg,OVERRIDE_AVERAGE,True
mr_gb_ipr_avg,CHANGE_DATE_TIME,True
mr_gb_ipr_avg,CHANGE_UID,True
mr_gb_category_type_hdr,DISTRICT,True
mr_gb_category_type_hdr,BUILDING,True
mr_gb_category_type_hdr,SCHOOL_YEAR,True
mr_gb_category_type_hdr,DURATION_TYPE,True
mr_gb_category_type_hdr,CATEGORY_TYPE,True
mr_gb_category_type_hdr,DESCRIPTION,True
mr_gb_category_type_hdr,USE_TOTAL_POINTS,True
mr_gb_category_type_hdr,ROUND_TRUNC,True
mr_gb_category_type_hdr,DEFAULT_SCALE,True
mr_gb_category_type_hdr,ACTIVE,True
mr_gb_category_type_hdr,CHANGE_DATE_TIME,True
mr_gb_category_type_hdr,CHANGE_UID,True
mr_gb_rubric_hdr,DISTRICT,True
mr_gb_rubric_hdr,RUBRIC_NUMBER,True
mr_gb_rubric_hdr,DESCRIPTION,True
mr_gb_rubric_hdr,NUMBER_OF_CRITERIA,True
mr_gb_rubric_hdr,NUMBER_OF_PERF_LEVEL,True
mr_gb_rubric_hdr,RUBRIC_TYPE,True
mr_gb_rubric_hdr,RUBRIC_STYLE,True
mr_gb_rubric_hdr,RUBRIC_MODE,True
mr_gb_rubric_hdr,AUTHOR,True
mr_gb_rubric_hdr,DESC_DETAIL,True
mr_gb_rubric_hdr,TEMPLATE,True
mr_gb_rubric_hdr,ACTIVE,True
mr_gb_rubric_hdr,CHANGE_DATE_TIME,True
mr_gb_rubric_hdr,CHANGE_UID,True
mr_gb_category_type_det,DISTRICT,True
mr_gb_category_type_det,BUILDING,True
mr_gb_category_type_det,SCHOOL_YEAR,True
mr_gb_category_type_det,DURATION_TYPE,True
mr_gb_category_type_det,CATEGORY_TYPE,True
mr_gb_category_type_det,CATEGORY,True
mr_gb_category_type_det,MARK_TYPE,True
mr_gb_category_type_det,MARKING_PERIODS,True
mr_gb_category_type_det,CATEGORY_WEIGHT,True
mr_gb_category_type_det,DROP_LOWEST,True
mr_gb_category_type_det,EXCLUDE_MISSING,True
mr_gb_category_type_det,CALCULATION,True
mr_gb_category_type_det,CHANGE_DATE_TIME,True
mr_gb_category_type_det,CHANGE_UID,True
mr_gb_cat_stu_comp,DISTRICT,True
mr_gb_cat_stu_comp,BUILDING,True
mr_gb_cat_stu_comp,COMPETENCY_GROUP,True
mr_gb_cat_stu_comp,STAFF_ID,True
mr_gb_cat_stu_comp,CATEGORY,True
mr_gb_cat_stu_comp,CHANGE_DATE_TIME,True
mr_gb_cat_stu_comp,CHANGE_UID,True
Mr_gb_cat_session,DISTRICT,True
Mr_gb_cat_session,SECTION_KEY,True
Mr_gb_cat_session,COURSE_SESSION,True
Mr_gb_cat_session,CATEGORY,True
Mr_gb_cat_session,MARKING_PERIOD,True
Mr_gb_cat_session,CATEGORY_WEIGHT,True
Mr_gb_cat_session,DROP_LOWEST,True
Mr_gb_cat_session,EXCLUDE_MISSING,True
Mr_gb_cat_session,CHANGE_DATE_TIME,True
Mr_gb_cat_session,CHANGE_UID,True
mr_gb_cat_sess_mark,DISTRICT,True
mr_gb_cat_sess_mark,SECTION_KEY,True
mr_gb_cat_sess_mark,COURSE_SESSION,True
mr_gb_cat_sess_mark,MARK_TYPE,True
mr_gb_cat_sess_mark,MARKING_PERIOD,True
mr_gb_cat_sess_mark,CATEGORY,True
mr_gb_cat_sess_mark,CATEGORY_WEIGHT,True
mr_gb_cat_sess_mark,DROP_LOWEST,True
mr_gb_cat_sess_mark,EXCLUDE_MISSING,True
mr_gb_cat_sess_mark,CHANGE_DATE_TIME,True
mr_gb_cat_sess_mark,CHANGE_UID,True
mr_gb_avg_calc,DISTRICT,True
mr_gb_avg_calc,SECTION_KEY,True
mr_gb_avg_calc,COURSE_SESSION,True
mr_gb_avg_calc,AVERAGE_ID,True
mr_gb_avg_calc,AVERAGE_SEQUENCE,True
mr_gb_avg_calc,CALC_TYPE,True
mr_gb_avg_calc,MARK_TYPE,True
mr_gb_avg_calc,MARK_TYPE_MP,True
mr_gb_avg_calc,PERCENT_WEIGHT,True
mr_gb_avg_calc,CHANGE_DATE_TIME,True
mr_gb_avg_calc,CHANGE_UID,True
mr_gb_mark_avg,DISTRICT,True
mr_gb_mark_avg,SECTION_KEY,True
mr_gb_mark_avg,COURSE_SESSION,True
mr_gb_mark_avg,MARK_TYPE,True
mr_gb_mark_avg,MARKING_PERIOD,True
mr_gb_mark_avg,STUDENT_ID,True
mr_gb_mark_avg,OVERRIDE_AVERAGE,True
mr_gb_mark_avg,CHANGE_DATE_TIME,True
mr_gb_mark_avg,CHANGE_UID,True
mr_gb_asmt_stu_comp_attach,DISTRICT,True
mr_gb_asmt_stu_comp_attach,SCHOOL_YEAR,True
mr_gb_asmt_stu_comp_attach,COMPETENCY_GROUP,True
mr_gb_asmt_stu_comp_attach,BUILDING,True
mr_gb_asmt_stu_comp_attach,STAFF_ID,True
mr_gb_asmt_stu_comp_attach,ASMT_NUMBER,True
mr_gb_asmt_stu_comp_attach,ATTACHMENT_NAME,True
mr_gb_asmt_stu_comp_attach,ATTACHMENT_DATA,True
mr_gb_asmt_stu_comp_attach,CHANGE_DATE_TIME,True
mr_gb_asmt_stu_comp_attach,CHANGE_UID,True
mr_gb_asmt_stu_comp,DISTRICT,True
mr_gb_asmt_stu_comp,BUILDING,True
mr_gb_asmt_stu_comp,COMPETENCY_GROUP,True
mr_gb_asmt_stu_comp,STAFF_ID,True
mr_gb_asmt_stu_comp,ASMT_NUMBER,True
mr_gb_asmt_stu_comp,CATEGORY,True
mr_gb_asmt_stu_comp,EXTRA_CREDIT,True
mr_gb_asmt_stu_comp,ASSIGN_DATE,True
mr_gb_asmt_stu_comp,DUE_DATE,True
mr_gb_asmt_stu_comp,DESCRIPTION,True
mr_gb_asmt_stu_comp,DESC_DETAIL,True
mr_gb_asmt_stu_comp,POINTS,True
mr_gb_asmt_stu_comp,WEIGHT,True
mr_gb_asmt_stu_comp,PUBLISH_ASMT,True
mr_gb_asmt_stu_comp,PUBLISH_SCORES,True
mr_gb_asmt_stu_comp,RUBRIC_NUMBER,True
mr_gb_asmt_stu_comp,USE_RUBRIC,True
mr_gb_asmt_stu_comp,CHANGE_DATE_TIME,True
mr_gb_asmt_stu_comp,CHANGE_UID,True
mr_gb_asmt_comp,DISTRICT,True
mr_gb_asmt_comp,SECTION_KEY,True
mr_gb_asmt_comp,COURSE_SESSION,True
mr_gb_asmt_comp,ASMT_NUMBER,True
mr_gb_asmt_comp,COMPETENCY_GROUP,True
mr_gb_asmt_comp,COMPETENCY_NUMBER,True
mr_gb_asmt_comp,RUBRIC_NUMBER,True
mr_gb_asmt_comp,CRITERIA_NUMBER,True
mr_gb_asmt_comp,CHANGE_DATE_TIME,True
mr_gb_asmt_comp,CHANGE_UID,True
Mr_sc_comp_crs,DISTRICT,True
Mr_sc_comp_crs,BUILDING,True
Mr_sc_comp_crs,SCHOOL_YEAR,True
Mr_sc_comp_crs,COMPETENCY_GROUP,True
Mr_sc_comp_crs,COURSE_BUILDING,True
Mr_sc_comp_crs,COURSE,True
Mr_sc_comp_crs,CHANGE_DATE_TIME,True
Mr_sc_comp_crs,CHANGE_UID,True
mr_gb_accumulated_avg,DISTRICT,True
mr_gb_accumulated_avg,SECTION_KEY,True
mr_gb_accumulated_avg,COURSE_SESSION,True
mr_gb_accumulated_avg,COMPETENCY_GROUP,True
mr_gb_accumulated_avg,COMPETENCY_NUMBER,True
mr_gb_accumulated_avg,MARKING_PERIOD,True
mr_gb_accumulated_avg,STUDENT_ID,True
mr_gb_accumulated_avg,OVERRIDE_AVERAGE,True
mr_gb_accumulated_avg,AVG_OR_RC_VALUE,True
mr_gb_accumulated_avg,RC_VALUE,True
mr_gb_accumulated_avg,CHANGE_DATE_TIME,True
mr_gb_accumulated_avg,CHANGE_UID,True
Mr_crsequ_setup_mk,DISTRICT,True
Mr_crsequ_setup_mk,SCHOOL_YEAR,True
Mr_crsequ_setup_mk,BUILDING,True
Mr_crsequ_setup_mk,MARK_TYPE_STATE,True
Mr_crsequ_setup_mk,MARK_TYPE_LOCAL,True
Mr_crsequ_setup_mk,CHANGE_DATE_TIME,True
Mr_crsequ_setup_mk,CHANGE_UID,True
Mr_crsequ_setup_ab,DISTRICT,True
Mr_crsequ_setup_ab,SCHOOL_YEAR,True
Mr_crsequ_setup_ab,BUILDING,True
Mr_crsequ_setup_ab,ABSENCE_TYPE,True
Mr_crsequ_setup_ab,CHANGE_DATE_TIME,True
Mr_crsequ_setup_ab,CHANGE_UID,True
Mr_crsequ_setup,DISTRICT,True
Mr_crsequ_setup,SCHOOL_YEAR,True
Mr_crsequ_setup,BUILDING,True
Mr_crsequ_setup,CRSEQU_FULL_YEAR,True
Mr_crsequ_setup,CRSEQU_TWO_PART,True
Mr_crsequ_setup,CRSEQU_THREE_PART,True
Mr_crsequ_setup,CRSEQU_FOUR_PART,True
Mr_crsequ_setup,RETAKE_RULE,True
Mr_crsequ_setup,RETAKE_LEVEL,True
Mr_crsequ_setup,CALC_GRAD_REQ,True
Mr_crsequ_setup,CALC_CREDIT,True
Mr_crsequ_setup,RC_WAREHOUSE,True
Mr_crsequ_setup,TRN_WAREHOUSE,True
Mr_crsequ_setup,CHANGE_DATE_TIME,True
Mr_crsequ_setup,CHANGE_UID,True
mr_crsequ_hdr,DISTRICT,True
mr_crsequ_hdr,SCHOOL_YEAR,True
mr_crsequ_hdr,BUILDING,True
mr_crsequ_hdr,STATE_CODE,True
mr_crsequ_hdr,NEEDS_RECALC,True
mr_crsequ_hdr,ERROR_REASON,True
mr_crsequ_hdr,CHANGE_DATE_TIME,True
mr_crsequ_hdr,CHANGE_UID,True
mr_crsequ_det,DISTRICT,True
mr_crsequ_det,SCHOOL_YEAR,True
mr_crsequ_det,BUILDING,True
mr_crsequ_det,STATE_ID,True
mr_crsequ_det,COURSE,True
mr_crsequ_det,COURSE_SECTION,True
mr_crsequ_det,EQUIV_PARTS,True
mr_crsequ_det,EQUIV_SEQUENCE,True
mr_crsequ_det,CHANGE_DATE_TIME,True
mr_crsequ_det,CHANGE_UID,True
mr_gb_cat_avg,DISTRICT,True
mr_gb_cat_avg,SECTION_KEY,True
mr_gb_cat_avg,COURSE_SESSION,True
mr_gb_cat_avg,CATEGORY,True
mr_gb_cat_avg,MARKING_PERIOD,True
mr_gb_cat_avg,STUDENT_ID,True
mr_gb_cat_avg,OVERRIDE_AVERAGE,True
mr_gb_cat_avg,CHANGE_DATE_TIME,True
mr_gb_cat_avg,CHANGE_UID,True
Mr_credit_setup_gd,DISTRICT,True
Mr_credit_setup_gd,SCHOOL_YEAR,True
Mr_credit_setup_gd,BUILDING,True
Mr_credit_setup_gd,GRADE,True
Mr_credit_setup_gd,CHANGE_DATE_TIME,True
Mr_credit_setup_gd,CHANGE_UID,True
mr_gb_asmt_stu_comp_comp,DISTRICT,True
mr_gb_asmt_stu_comp_comp,BUILDING,True
mr_gb_asmt_stu_comp_comp,STAFF_ID,True
mr_gb_asmt_stu_comp_comp,ASMT_NUMBER,True
mr_gb_asmt_stu_comp_comp,COMPETENCY_GROUP,True
mr_gb_asmt_stu_comp_comp,COMPETENCY_NUMBER,True
mr_gb_asmt_stu_comp_comp,RUBRIC_NUMBER,True
mr_gb_asmt_stu_comp_comp,CRITERIA_NUMBER,True
mr_gb_asmt_stu_comp_comp,CHANGE_DATE_TIME,True
mr_gb_asmt_stu_comp_comp,CHANGE_UID,True
mr_credit_setup,DISTRICT,True
mr_credit_setup,SCHOOL_YEAR,True
mr_credit_setup,BUILDING,True
mr_credit_setup,USE_STATUS_T,True
mr_credit_setup,USE_STATUS_O,True
mr_credit_setup,COURSE_ENDED,True
mr_credit_setup,LIMIT_STU_GRADE,True
mr_credit_setup,LIMIT_CRS_GRADE,True
mr_credit_setup,ISSUE_PARTIAL,True
mr_credit_setup,USE_CRS_AVG_RULE,True
mr_credit_setup,AVG_MARK_TYPE,True
mr_credit_setup,AVG_PASS_RULE,True
mr_credit_setup,MIN_FAILING_MARK,True
mr_credit_setup,CHECK_ABSENCES,True
mr_credit_setup,ABS_TYPE,True
mr_credit_setup,ABS_TOTAL,True
mr_credit_setup,ABS_CRDOVR_REASON,True
mr_credit_setup,CHANGE_DATE_TIME,True
mr_credit_setup,CHANGE_UID,True
mr_crdovr_reason,DISTRICT,True
mr_crdovr_reason,CODE,True
mr_crdovr_reason,DESCRIPTION,True
mr_crdovr_reason,CHANGE_DATE_TIME,True
mr_crdovr_reason,CHANGE_UID,True
Mr_gb_asmt,DISTRICT,True
Mr_gb_asmt,SECTION_KEY,True
Mr_gb_asmt,COURSE_SESSION,True
Mr_gb_asmt,ASMT_NUMBER,True
Mr_gb_asmt,CRS_ASMT_NUMBER,True
Mr_gb_asmt,CATEGORY,True
Mr_gb_asmt,EXTRA_CREDIT,True
Mr_gb_asmt,ASSIGN_DATE,True
Mr_gb_asmt,DUE_DATE,True
Mr_gb_asmt,DESCRIPTION,True
Mr_gb_asmt,DESC_DETAIL,True
Mr_gb_asmt,POINTS,True
Mr_gb_asmt,WEIGHT,True
Mr_gb_asmt,PUBLISH_ASMT,True
Mr_gb_asmt,PUBLISH_SCORES,True
Mr_gb_asmt,RUBRIC_NUMBER,True
Mr_gb_asmt,USE_RUBRIC,True
Mr_gb_asmt,CANNOT_DROP,True
Mr_gb_asmt,HIGHLIGHT_POINTS,True
Mr_gb_asmt,POINTS_THRESHOLD,True
Mr_gb_asmt,HIGHLIGHT_PURPLE,True
Mr_gb_asmt,UC_STUDENT_WORK_TYPE,True
Mr_gb_asmt,CHANGE_DATE_TIME,True
Mr_gb_asmt,CHANGE_UID,True
Mr_credit_setup_mk,DISTRICT,True
Mr_credit_setup_mk,SCHOOL_YEAR,True
Mr_credit_setup_mk,BUILDING,True
Mr_credit_setup_mk,MARK_TYPE,True
Mr_credit_setup_mk,CHANGE_DATE_TIME,True
Mr_credit_setup_mk,CHANGE_UID,True
Mr_class_size,DISTRICT,True
Mr_class_size,SCHOOL_YEAR,True
Mr_class_size,GPA_TYPE,True
Mr_class_size,RUN_TERM_YEAR,True
Mr_class_size,BUILDING,True
Mr_class_size,GRADE,True
Mr_class_size,CLASS_SIZE,True
Mr_class_size,CHANGE_DATE_TIME,True
Mr_class_size,CHANGE_UID,True
mr_cfg,DISTRICT,True
mr_cfg,BUILDING,True
mr_cfg,CURRENT_RC_RUN,True
mr_cfg,INCLUDE_XFER_IN_RC,True
mr_cfg,DISPLAY_MBS_BLDG,True
mr_cfg,MAINTAIN_ATTEND,True
mr_cfg,PROCESS_IPR,True
mr_cfg,USE_LANG_TEMPLATE,True
mr_cfg,DATA_SOURCE_FILE,True
mr_cfg,PROGRAM_SCREEN,True
mr_cfg,REG_USER_SCREEN,True
mr_cfg,NOTIFY_DWNLD_PATH,True
mr_cfg,EMAIL_OPTION,True
mr_cfg,RETURN_EMAIL,True
mr_cfg,RET_EMAIL_MISSUB,True
mr_cfg,TEA_IPR_MNT,True
mr_cfg,SUB_IPR_MNT,True
mr_cfg,TEA_IPR_STU_SUMM,True
mr_cfg,SUB_IPR_STU_SUMM,True
mr_cfg,TEA_RC_MNT,True
mr_cfg,SUB_RC_MNT,True
mr_cfg,TEA_RC_STU_SUMM,True
mr_cfg,SUB_RC_STU_SUMM,True
mr_cfg,TEA_SC_MNT,True
mr_cfg,SUB_SC_MNT,True
mr_cfg,TEA_SC_STU_SUMM,True
mr_cfg,SUB_SC_STU_SUMM,True
mr_cfg,TEA_GB_DEFINE,True
mr_cfg,TEA_GB_SCORE,True
mr_cfg,SUB_GB_DEFINE,True
mr_cfg,SUB_GB_SCORE,True
mr_cfg,PROCESS_SC,True
mr_cfg,SC_COMMENT_LINES,True
mr_cfg,GB_ENTRY_B4_ENRLMT,True
mr_cfg,TAC_CHANGE_CREDIT,True
mr_cfg,GB_ALLOW_TEA_SCALE,True
mr_cfg,GB_LIMIT_CATEGORIES,True
mr_cfg,GB_LIMIT_DROP_SCORE,True
mr_cfg,GB_LIMIT_MISS_MARKS,True
mr_cfg,GB_ALLOW_OVR_WEIGHT,True
mr_cfg,GB_ALLOW_TRUNC_RND,True
mr_cfg,ASMT_DATE_VAL,True
mr_cfg,VALIDATE_TRANSFER,True
mr_cfg,MP_CRS_CREDIT_OVR,True
mr_cfg,TEA_GB_VIEW,True
mr_cfg,SUB_GB_VIEW,True
mr_cfg,TEA_PRINT_RC,True
mr_cfg,SUB_PRINT_RC,True
mr_cfg,TEA_TRANSCRIPT,True
mr_cfg,SUB_TRANSCRIPT,True
mr_cfg,TEA_GB_SUM_VIEW,True
mr_cfg,SUB_GB_SUM_VIEW,True
mr_cfg,USE_RC_HOLD,True
mr_cfg,STATUS_REASON,True
mr_cfg,OVERALL_BALANCE,True
mr_cfg,OVERALL_BAL_REASON,True
mr_cfg,COURSE_BALANCE,True
mr_cfg,COURSE_BAL_REASON,True
mr_cfg,STUDENT_BALANCE,True
mr_cfg,STUDENT_BAL_REASON,True
mr_cfg,ACTIVITY_BALANCE,True
mr_cfg,ACTIVITY_BAL_REASON,True
mr_cfg,ALLOW_COURSE_FREE_TEXT,True
mr_cfg,MAX_COURSE_FREE_TEXT_CHARACTERS,True
mr_cfg,SECONDARY_TEACHER_ACCESS,True
mr_cfg,CHANGE_DATE_TIME,True
mr_cfg,CHANGE_UID,True
mr_average_setup,DISTRICT,True
mr_average_setup,SCHOOL_YEAR,True
mr_average_setup,BUILDING,True
mr_average_setup,AVERAGE_TYPE,True
mr_average_setup,AVERAGE_ID,True
mr_average_setup,AVERAGE_SEQUENCE,True
mr_average_setup,MARK_TYPE,True
mr_average_setup,DURATION,True
mr_average_setup,MARK_TYPE_MP,True
mr_average_setup,CALC_AT_MP,True
mr_average_setup,USE_GRADEBOOK,True
mr_average_setup,USE_STATUS_T,True
mr_average_setup,USE_STATUS_O,True
mr_average_setup,COURSE_ENDED,True
mr_average_setup,BLANK_MARKS,True
mr_average_setup,AVERAGE_PASS_FAIL,True
mr_average_setup,AVERAGE_REGULAR,True
mr_average_setup,STATE_CRS_EQUIV,True
mr_average_setup,USE_RAW_AVERAGES,True
mr_average_setup,CHANGE_DATE_TIME,True
mr_average_setup,CHANGE_UID,True
mr_average_calc,DISTRICT,True
mr_average_calc,SCHOOL_YEAR,True
mr_average_calc,BUILDING,True
mr_average_calc,AVERAGE_ID,True
mr_average_calc,AVERAGE_SEQUENCE,True
mr_average_calc,CALC_TYPE,True
mr_average_calc,MARK_TYPE,True
mr_average_calc,MARK_TYPE_MP,True
mr_average_calc,PERCENT_WEIGHT,True
mr_average_calc,EXEMPT_STATUS,True
mr_average_calc,CHANGE_DATE_TIME,True
mr_average_calc,CHANGE_UID,True
mr_absence_types,DISTRICT,True
mr_absence_types,BUILDING,True
mr_absence_types,ABSENCE_TYPE,True
mr_absence_types,ABSENCE_ORDER,True
mr_absence_types,ABSENCE_WHEN,True
mr_absence_types,DESCRIPTION,True
mr_absence_types,SUM_TO_YEARLY,True
mr_absence_types,YEARLY_TYPE,True
mr_absence_types,ACTIVE,True
mr_absence_types,TWS_ACCESS,True
mr_absence_types,MULTI_PERIOD_RULE,True
mr_absence_types,CHANGE_DATE_TIME,True
mr_absence_types,CHANGE_UID,True
mr_comment_types,DISTRICT,True
mr_comment_types,BUILDING,True
mr_comment_types,COMMENT_TYPE,True
mr_comment_types,COMMENT_ORDER,True
mr_comment_types,DESCRIPTION,True
mr_comment_types,ACTIVE,True
mr_comment_types,REQUIRED,True
mr_comment_types,USAGE,True
mr_comment_types,RC_USAGE,True
mr_comment_types,IPR_USAGE,True
mr_comment_types,SC_USAGE,True
mr_comment_types,TWS_ACCESS,True
mr_comment_types,CHANGE_DATE_TIME,True
mr_comment_types,CHANGE_UID,True
med_stu_letter,DISTRICT,True
med_stu_letter,STUDENT_ID,True
med_stu_letter,CRIT_NUMBER,True
med_stu_letter,CALC_DATE,True
med_stu_letter,SERIES_CODE,True
med_stu_letter,DATE_PRINTED,True
med_stu_letter,NOTIFICATION_DATE,True
med_stu_letter,SERIES_REASON,True
med_stu_letter,CHANGE_DATE_TIME,True
med_stu_letter,CHANGE_UID,True
med_shot_det,DISTRICT,True
med_shot_det,STUDENT_ID,True
med_shot_det,SHOT_CODE,True
med_shot_det,SHOT_DATE,True
med_shot_det,SHOT_ORDER,True
med_shot_det,SOURCE_DOC,True
med_shot_det,SIGNED_DOC,True
med_shot_det,WARNING_STATUS,True
med_shot_det,OVERRIDE,True
med_shot_det,ROW_IDENTITY,True
med_shot_det,CHANGE_DATE_TIME,True
med_shot_det,CHANGE_UID,True
med_shot,DISTRICT,True
med_shot,STUDENT_ID,True
med_shot,SHOT_CODE,True
med_shot,EXEMPT,True
med_shot,COMMENT,True
med_shot,OVERRIDE,True
med_shot,HAD_DISEASE,True
med_shot,DISEASE_DATE,True
med_shot,CHANGE_DATE_TIME,True
med_shot,CHANGE_UID,True
med_series_det,DISTRICT,True
med_series_det,STUDENT_ID,True
med_series_det,SERIES_CODE,True
med_series_det,SERIES_DATE,True
med_series_det,CHANGE_DATE_TIME,True
med_series_det,CHANGE_UID,True
REG_CAL_DAYS_LEARNING_LOC,DISTRICT,True
REG_CAL_DAYS_LEARNING_LOC,BUILDING,True
REG_CAL_DAYS_LEARNING_LOC,SCHOOL_YEAR,True
REG_CAL_DAYS_LEARNING_LOC,SUMMER_SCHOOL,True
REG_CAL_DAYS_LEARNING_LOC,TRACK,True
REG_CAL_DAYS_LEARNING_LOC,CALENDAR,True
REG_CAL_DAYS_LEARNING_LOC,CAL_DATE,True
REG_CAL_DAYS_LEARNING_LOC,LEARNING_LOCATION,True
REG_CAL_DAYS_LEARNING_LOC,CHANGE_DATE_TIME,True
REG_CAL_DAYS_LEARNING_LOC,CHANGE_UID,True
REG_CAL_DAYS_LEARNING_LOC,ROW_IDENTITY,True
REG_CAL_DAYS_LEARNING_LOC,LOCATION_TYPE,True
mr_comments,DISTRICT,True
mr_comments,BUILDING,True
mr_comments,CODE,True
mr_comments,IPR_USAGE,True
mr_comments,SC_USAGE,True
mr_comments,RC_USAGE,True
mr_comments,FT_USAGE,True
mr_comments,DESCRIPTION,True
mr_comments,CHANGE_DATE_TIME,True
mr_comments,CHANGE_UID,True
med_scoliosis,DISTRICT,True
med_scoliosis,STUDENT_ID,True
med_scoliosis,TEST_DATE,True
med_scoliosis,GRADE,True
med_scoliosis,LOCATION,True
med_scoliosis,STATUS,True
med_scoliosis,INITIALS,True
med_scoliosis,ROW_IDENTITY,True
med_scoliosis,CHANGE_DATE_TIME,True
med_scoliosis,CHANGE_UID,True
med_required,DISTRICT,True
med_required,STUDENT_ID,True
med_required,MED_CODE,True
med_required,START_DATE,True
med_required,END_DATE,True
med_required,DOSE_NUMBER,True
med_required,DOSE_TIME,True
med_required,PHYSICIAN_NAME,True
med_required,DOSE_COMMENT,True
med_required,CHANGE_DATE_TIME,True
med_required,CHANGE_UID,True
med_referral,DISTRICT,True
med_referral,STUDENT_ID,True
med_referral,TEST_TYPE,True
med_referral,TEST_DATE,True
med_referral,SEQUENCE_NUMBER,True
med_referral,REFERRAL_CODE,True
med_referral,REFERRAL_DATE,True
med_referral,FOLLOW_UP_CODE,True
med_referral,FOLLOW_UP_DATE,True
med_referral,DOCTOR_NAME,True
med_referral,COMMENT,True
med_referral,ROW_IDENTITY,True
med_referral,CHANGE_DATE_TIME,True
med_referral,CHANGE_UID,True
med_physical_exam,DISTRICT,True
med_physical_exam,STUDENT_ID,True
med_physical_exam,TEST_DATE,True
med_physical_exam,TEST_TYPE,True
med_physical_exam,TEST_RESULT,True
med_physical_exam,CHANGE_DATE_TIME,True
med_physical_exam,CHANGE_UID,True
med_physical,DISTRICT,True
med_physical,STUDENT_ID,True
med_physical,TEST_DATE,True
med_physical,GRADE,True
med_physical,LOCATION,True
med_physical,PULSE,True
med_physical,BLOOD_PRESSURE_SYS,True
med_physical,BLOOD_PRESSURE_DIA,True
med_physical,ATHLETIC_STATUS,True
med_physical,CLEARED_STATUS,True
med_physical,INITIALS,True
med_physical,ROW_IDENTITY,True
med_physical,CHANGE_DATE_TIME,True
med_physical,CHANGE_UID,True
med_office_schd,DISTRICT,True
med_office_schd,STUDENT_ID,True
med_office_schd,START_DATE,True
med_office_schd,END_DATE,True
med_office_schd,SCHEDULED_TIME,True
med_office_schd,SEQUENCE_NUMBER,True
med_office_schd,VISIT_REASON,True
med_office_schd,TREATMENT_CODE,True
med_office_schd,OUTCOME,True
med_office_schd,CHANGE_DATE_TIME,True
med_office_schd,CHANGE_UID,True
med_office_det,DISTRICT,True
med_office_det,STUDENT_ID,True
med_office_det,OFFICE_DATE_IN,True
med_office_det,SEQUENCE_NUM,True
med_office_det,VISIT_REASON,True
med_office_det,TREATMENT_CODE,True
med_office_det,OUTCOME,True
med_office_det,CHANGE_DATE_TIME,True
med_office_det,CHANGE_UID,True
mr_credit_setup_ab,DISTRICT,True
mr_credit_setup_ab,SCHOOL_YEAR,True
mr_credit_setup_ab,BUILDING,True
mr_credit_setup_ab,ABS_TYPE,True
mr_credit_setup_ab,ABS_TOTAL,True
mr_credit_setup_ab,PER_MP_TERM_YR,True
mr_credit_setup_ab,REVOKE_TERM_COURSE,True
mr_credit_setup_ab,CHANGE_DATE_TIME,True
mr_credit_setup_ab,CHANGE_UID,True
med_notes,DISTRICT,True
med_notes,STUDENT_ID,True
med_notes,EVENT_TYPE,True
med_notes,EVENT_DATE,True
med_notes,NOTE,True
med_notes,CHANGE_DATE_TIME,True
med_notes,CHANGE_UID,True
med_issued,DISTRICT,True
med_issued,STUDENT_ID,True
med_issued,ISSUED,True
med_issued,MED_CODE,True
med_issued,DOSE_NUMBER,True
med_issued,EVENT_TYPE,True
med_issued,COMMENT,True
med_issued,INITIALS,True
med_issued,CHANGE_DATE_TIME,True
med_issued,CHANGE_UID,True
med_hearing_det,DISTRICT,True
med_hearing_det,STUDENT_ID,True
med_hearing_det,TEST_DATE,True
med_hearing_det,DECIBEL,True
med_hearing_det,FREQUENCY,True
med_hearing_det,RIGHT_EAR,True
med_hearing_det,LEFT_EAR,True
med_hearing_det,CHANGE_DATE_TIME,True
med_hearing_det,CHANGE_UID,True
med_series,DISTRICT,True
med_series,STUDENT_ID,True
med_series,SERIES_CODE,True
med_series,SERIES_EXEMPTION,True
med_series,TOTAL_DOSES,True
med_series,SERIES_STATUS,True
med_series,CALC_DATE,True
med_series,OVERRIDE,True
med_series,COMMENT,True
med_series,NUMBER_LETTERS,True
med_series,HAD_DISEASE,True
med_series,DISEASE_DATE,True
med_series,CHANGE_DATE_TIME,True
med_series,CHANGE_UID,True
med_series,NUMBER_NOTIFICATIONS,True
med_screening,DISTRICT,True
med_screening,STUDENT_ID,True
med_screening,EXAM_CODE,True
med_screening,TEST_DATE,True
med_screening,GRADE,True
med_screening,LOCATION,True
med_screening,STATUS,True
med_screening,INITIALS,True
med_screening,ROW_IDENTITY,True
med_screening,CHANGE_DATE_TIME,True
med_screening,CHANGE_UID,True
med_growth,DISTRICT,True
med_growth,STUDENT_ID,True
med_growth,TEST_DATE,True
med_growth,GRADE,True
med_growth,LOCATION,True
med_growth,HEIGHT,True
med_growth,PERCENT_HEIGHT,True
med_growth,WEIGHT,True
med_growth,PERCENT_WEIGHT,True
med_growth,BMI,True
med_growth,PERCENT_BMI,True
med_growth,AN_READING,True
med_growth,BLOOD_PRESSURE_DIA,True
med_growth,BLOOD_PRESSURE_SYS_AN,True
med_growth,BLOOD_PRESSURE_DIA_AN,True
med_growth,BLOOD_PRESSURE_SYS,True
med_growth,INITIALS,True
med_growth,ROW_IDENTITY,True
med_growth,CHANGE_DATE_TIME,True
med_growth,CHANGE_UID,True
med_general,DISTRICT,True
med_general,STUDENT_ID,True
med_general,IMMUNE_STATUS,True
med_general,IMMUNE_EXEMPT,True
med_general,CALC_DATE,True
med_general,OVERRIDE,True
med_general,GROUP_CODE,True
med_general,GRACE_PERIOD_DATE,True
med_general,COMMENT,True
med_general,IMM_ALERT,True
med_general,ALERT_END_DATE,True
med_general,ALERT_OVERRIDE,True
med_general,CHANGE_DATE_TIME,True
med_general,CHANGE_UID,True
Mr_print_stu_sctxt,MR_PRINT_KEY,True
Mr_print_stu_sctxt,STUDENT_ID,True
Mr_print_stu_sctxt,MARKING_PERIOD,True
Mr_print_stu_sctxt,STAFF_01,True
Mr_print_stu_sctxt,STAFF_02,True
Mr_print_stu_sctxt,STAFF_03,True
Mr_print_stu_sctxt,STAFF_04,True
Mr_print_stu_sctxt,STAFF_05,True
Mr_print_stu_sctxt,STAFF_06,True
Mr_print_stu_sctxt,STAFF_07,True
Mr_print_stu_sctxt,STAFF_08,True
Mr_print_stu_sctxt,STAFF_09,True
Mr_print_stu_sctxt,STAFF_10,True
Mr_print_stu_sctxt,STAFF_NAME_01,True
Mr_print_stu_sctxt,STAFF_NAME_02,True
Mr_print_stu_sctxt,STAFF_NAME_03,True
Mr_print_stu_sctxt,STAFF_NAME_04,True
Mr_print_stu_sctxt,STAFF_NAME_05,True
Mr_print_stu_sctxt,STAFF_NAME_06,True
Mr_print_stu_sctxt,STAFF_NAME_07,True
Mr_print_stu_sctxt,STAFF_NAME_08,True
Mr_print_stu_sctxt,STAFF_NAME_09,True
Mr_print_stu_sctxt,STAFF_NAME_10,True
Mr_print_stu_sctxt,STAFF_COMMENT_01,True
Mr_print_stu_sctxt,STAFF_COMMENT_02,True
Mr_print_stu_sctxt,STAFF_COMMENT_03,True
Mr_print_stu_sctxt,STAFF_COMMENT_04,True
Mr_print_stu_sctxt,STAFF_COMMENT_05,True
Mr_print_stu_sctxt,STAFF_COMMENT_06,True
Mr_print_stu_sctxt,STAFF_COMMENT_07,True
Mr_print_stu_sctxt,STAFF_COMMENT_08,True
Mr_print_stu_sctxt,STAFF_COMMENT_09,True
Mr_print_stu_sctxt,STAFF_COMMENT_10,True
Mr_print_stu_sctxt,CHANGE_DATE_TIME,True
Mr_print_stu_sctxt,CHANGE_UID,True
med_office,DISTRICT,True
med_office,STUDENT_ID,True
med_office,OFFICE_DATE_IN,True
med_office,OFFICE_DATE_OUT,True
med_office,ROOM_ID,True
med_office,COMMENT,True
med_office,INITIALS,True
med_office,ROW_IDENTITY,True
med_office,CHANGE_DATE_TIME,True
med_office,CHANGE_UID,True
MEDTB_VISION_EXAM_TYPE,DISTRICT,True
MEDTB_VISION_EXAM_TYPE,CODE,True
MEDTB_VISION_EXAM_TYPE,DESCRIPTION,True
MEDTB_VISION_EXAM_TYPE,STATE_CODE_EQUIV,True
MEDTB_VISION_EXAM_TYPE,ACTIVE,True
MEDTB_VISION_EXAM_TYPE,CHANGE_DATE_TIME,True
MEDTB_VISION_EXAM_TYPE,CHANGE_UID,True
medtb_vaccination_pesc_code,DISTRICT,True
medtb_vaccination_pesc_code,CODE,True
medtb_vaccination_pesc_code,DESCRIPTION,True
medtb_vaccination_pesc_code,CHANGE_DATE_TIME,True
medtb_vaccination_pesc_code,CHANGE_UID,True
medtb_treatment,DISTRICT,True
medtb_treatment,CODE,True
medtb_treatment,DESCRIPTION,True
medtb_treatment,MEDICAID_CODE,True
medtb_treatment,STATE_CODE_EQUIV,True
medtb_treatment,ACTIVE,True
medtb_treatment,CHANGE_DATE_TIME,True
medtb_treatment,CHANGE_UID,True
medtb_status,DISTRICT,True
medtb_status,CODE,True
medtb_status,DESCRIPTION,True
medtb_status,STATE_CODE_EQUIV,True
medtb_status,ACTIVE,True
medtb_status,CHANGE_DATE_TIME,True
medtb_status,CHANGE_UID,True
med_dental,DISTRICT,True
med_dental,STUDENT_ID,True
med_dental,TEST_DATE,True
med_dental,GRADE,True
med_dental,LOCATION,True
med_dental,STATUS,True
med_dental,INITIALS,True
med_dental,ROW_IDENTITY,True
med_dental,CHANGE_DATE_TIME,True
med_dental,CHANGE_UID,True
medtb_shot,DISTRICT,True
medtb_shot,CODE,True
medtb_shot,DESCRIPTION,True
medtb_shot,SHOT_ORDER,True
medtb_shot,AUTO_GENERATE,True
medtb_shot,LIVE_VIRUS,True
medtb_shot,SHOT_REQUIREMENT,True
medtb_shot,SERIES_FLAG,True
medtb_shot,LICENSING_DATE,True
medtb_shot,STATE_CODE_EQUIV,True
medtb_shot,PESC_CODE,True
medtb_shot,ACTIVE,True
medtb_shot,CHANGE_DATE_TIME,True
medtb_shot,CHANGE_UID,True
medtb_screening,DISTRICT,True
medtb_screening,CODE,True
medtb_screening,DESCRIPTION,True
medtb_screening,STATE_CODE_EQUIV,True
medtb_screening,ACTIVE,True
medtb_screening,CHANGE_DATE_TIME,True
medtb_screening,CHANGE_UID,True
medtb_refer,DISTRICT,True
medtb_refer,CODE,True
medtb_refer,DESCRIPTION,True
medtb_refer,DENTAL,True
medtb_refer,GROWTH,True
medtb_refer,HEARING,True
medtb_refer,IMMUN,True
medtb_refer,OFFICE,True
medtb_refer,OTHER,True
medtb_refer,PHYSICAL,True
medtb_refer,SCOLIOSIS,True
medtb_refer,VISION,True
medtb_refer,STATE_CODE_EQUIV,True
medtb_refer,ACTIVE,True
medtb_refer,CHANGE_DATE_TIME,True
medtb_refer,CHANGE_UID,True
med_user,DISTRICT,True
med_user,STUDENT_ID,True
med_user,SCREEN_NUMBER,True
med_user,FIELD_NUMBER,True
med_user,FIELD_VALUE,True
med_user,CHANGE_DATE_TIME,True
med_user,CHANGE_UID,True
medtb_percents,DISTRICT,True
medtb_percents,AGE,True
medtb_percents,GENDER,True
medtb_percents,PERCENTILE,True
medtb_percents,HEIGHT,True
medtb_percents,WEIGHT,True
medtb_percents,BMI,True
medtb_percents,ACTIVE,True
medtb_percents,CHANGE_DATE_TIME,True
medtb_percents,CHANGE_UID,True
medtb_medicine,DISTRICT,True
medtb_medicine,CODE,True
medtb_medicine,DESCRIPTION,True
medtb_medicine,PRN,True
medtb_medicine,MEDICAID_CODE,True
medtb_medicine,STATE_CODE_EQUIV,True
medtb_medicine,ACTIVE,True
medtb_medicine,CHANGE_DATE_TIME,True
medtb_medicine,CHANGE_UID,True
medtb_source_doc,DISTRICT,True
medtb_source_doc,CODE,True
medtb_source_doc,DESCRIPTION,True
medtb_source_doc,STATE_CODE_EQUIV,True
medtb_source_doc,ACTIVE,True
medtb_source_doc,CHANGE_DATE_TIME,True
medtb_source_doc,CHANGE_UID,True
medtb_location,DISTRICT,True
medtb_location,CODE,True
medtb_location,DESCRIPTION,True
medtb_location,STATE_CODE_EQUIV,True
medtb_location,ACTIVE,True
medtb_location,CHANGE_DATE_TIME,True
medtb_location,CHANGE_UID,True
medtb_frequency,DISTRICT,True
medtb_frequency,FREQUENCY_LEVEL,True
medtb_frequency,SEQUENCE_NUMBER,True
medtb_frequency,ACTIVE,True
medtb_frequency,CHANGE_DATE_TIME,True
medtb_frequency,CHANGE_UID,True
medtb_followup,DISTRICT,True
medtb_followup,CODE,True
medtb_followup,DESCRIPTION,True
medtb_followup,DENTAL,True
medtb_followup,GROWTH,True
medtb_followup,HEARING,True
medtb_followup,IMMUN,True
medtb_followup,OFFICE,True
medtb_followup,OTHER,True
medtb_followup,PHYSICAL,True
medtb_followup,SCOLIOSIS,True
medtb_followup,VISION,True
medtb_followup,STATE_CODE_EQUIV,True
medtb_followup,ACTIVE,True
medtb_followup,CHANGE_DATE_TIME,True
medtb_followup,CHANGE_UID,True
med_hearing,DISTRICT,True
med_hearing,STUDENT_ID,True
med_hearing,TEST_DATE,True
med_hearing,GRADE,True
med_hearing,LOCATION,True
med_hearing,RIGHT_EAR,True
med_hearing,LEFT_EAR,True
med_hearing,INITIALS,True
med_hearing,ROW_IDENTITY,True
med_hearing,CHANGE_DATE_TIME,True
med_hearing,CHANGE_UID,True
medtb_exam,DISTRICT,True
medtb_exam,CODE,True
medtb_exam,DESCRIPTION,True
medtb_exam,ACTIVE_NORMAL,True
medtb_exam,ACTIVE_ATHLETIC,True
medtb_exam,SEQ_NUMBER,True
medtb_exam,STATE_CODE_EQUIV,True
medtb_exam,ACTIVE,True
medtb_exam,CHANGE_DATE_TIME,True
medtb_exam,CHANGE_UID,True
medtb_decibel,DISTRICT,True
medtb_decibel,DECIBEL_LEVEL,True
medtb_decibel,SEQUENCE_NUMBER,True
medtb_decibel,ACTIVE,True
medtb_decibel,CHANGE_DATE_TIME,True
medtb_decibel,CHANGE_UID,True
menu_items,DISTRICT,True
menu_items,PARENT_MENU,True
menu_items,SEQUENCE,True
menu_items,MENU_ID,True
menu_items,DESCRIPTION,True
menu_items,TARGET,True
menu_items,PAGE,True
menu_items,SEC_PACKAGE,True
menu_items,SEC_SUBPACKAGE,True
menu_items,SEC_FEATURE,True
menu_items,RESERVED,True
menu_items,CHANGE_DATE_TIME,True
menu_items,CHANGE_UID,True
medtb_alt_dose,DISTRICT,True
medtb_alt_dose,SERIES_CODE,True
medtb_alt_dose,ALT_NUMBER,True
medtb_alt_dose,DESCRIPTION,True
medtb_alt_dose,ACTIVE,True
medtb_alt_dose,CHANGE_DATE_TIME,True
medtb_alt_dose,CHANGE_UID,True
med_vision,DISTRICT,True
med_vision,STUDENT_ID,True
med_vision,TEST_DATE,True
med_vision,GRADE,True
med_vision,LOCATION,True
med_vision,LENS,True
med_vision,RIGHT_EYE,True
med_vision,LEFT_EYE,True
med_vision,MUSCLE,True
med_vision,MUSCLE_LEFT,True
med_vision,COLOR_BLIND,True
med_vision,PLUS_LENS,True
med_vision,BINOC,True
med_vision,INITIALS,True
med_vision,TEST_TYPE,True
med_vision,STEREOPSIS,True
med_vision,NEAR_FAR_TYPE,True
med_vision,ROW_IDENTITY,True
med_vision,CHANGE_DATE_TIME,True
med_vision,CHANGE_UID,True
ltdbtb_test_pesc_code,DISTRICT,True
ltdbtb_test_pesc_code,CODE,True
ltdbtb_test_pesc_code,DESCRIPTION,True
ltdbtb_test_pesc_code,STATE_CODE_EQUIV,True
ltdbtb_test_pesc_code,ACTIVE,True
ltdbtb_test_pesc_code,CHANGE_DATE_TIME,True
ltdbtb_test_pesc_code,CHANGE_UID,True
ltdbtb_subtest_pesc_code,DISTRICT,True
ltdbtb_subtest_pesc_code,CODE,True
ltdbtb_subtest_pesc_code,DESCRIPTION,True
ltdbtb_subtest_pesc_code,STATE_CODE_EQUIV,True
ltdbtb_subtest_pesc_code,ACTIVE,True
ltdbtb_subtest_pesc_code,CHANGE_DATE_TIME,True
ltdbtb_subtest_pesc_code,CHANGE_UID,True
medtb_outcome,DISTRICT,True
medtb_outcome,CODE,True
medtb_outcome,DESCRIPTION,True
medtb_outcome,STATE_CODE_EQUIV,True
medtb_outcome,ACTIVE,True
medtb_outcome,CHANGE_DATE_TIME,True
medtb_outcome,CHANGE_UID,True
ltdbtb_score_type,DISTRICT,True
ltdbtb_score_type,CODE,True
ltdbtb_score_type,DESCRIPTION,True
ltdbtb_score_type,STATE_CODE_EQUIV,True
ltdbtb_score_type,ACTIVE,True
ltdbtb_score_type,CHANGE_DATE_TIME,True
ltdbtb_score_type,CHANGE_UID,True
mr_level_honor,DISTRICT,True
mr_level_honor,BUILDING,True
mr_level_honor,LEVEL_NUMBER,True
mr_level_honor,MARK,True
mr_level_honor,HONOR_TYPE,True
mr_level_honor,CHANGE_DATE_TIME,True
mr_level_honor,CHANGE_UID,True
medtb_bmi_status,DISTRICT,True
medtb_bmi_status,CODE,True
medtb_bmi_status,DESCRIPTION,True
medtb_bmi_status,MIN_BMI,True
medtb_bmi_status,MAX_BMI,True
medtb_bmi_status,ACTIVE,True
medtb_bmi_status,CHANGE_DATE_TIME,True
medtb_bmi_status,CHANGE_UID,True
MR_SC_GD_SCALE_HDR,DISTRICT,True
MR_SC_GD_SCALE_HDR,BUILDING,True
MR_SC_GD_SCALE_HDR,GRADING_SCALE_TYPE,True
MR_SC_GD_SCALE_HDR,DESCRIPTION,True
MR_SC_GD_SCALE_HDR,DEFAULT_MARK,True
MR_SC_GD_SCALE_HDR,CHANGE_DATE_TIME,True
MR_SC_GD_SCALE_HDR,CHANGE_UID,True
HAC_BUILDING_CFG,DISTRICT,True
HAC_BUILDING_CFG,BUILDING,True
HAC_BUILDING_CFG,CONFIG_TYPE,True
HAC_BUILDING_CFG,ENABLE_HAC,True
HAC_BUILDING_CFG,BUILDING_LOGO,True
HAC_BUILDING_CFG,LOGO_HEADER_COLOR,True
HAC_BUILDING_CFG,LOGO_TEXT_COLOR,True
HAC_BUILDING_CFG,FIRST_PAGE,True
HAC_BUILDING_CFG,SHOW_PERSONAL,True
HAC_BUILDING_CFG,UPD_EMAIL,True
HAC_BUILDING_CFG,UPD_PHONE,True
HAC_BUILDING_CFG,SHOW_EMERGENCY,True
HAC_BUILDING_CFG,UPD_EMERGENCY,True
HAC_BUILDING_CFG,SHOW_CONTACT,True
HAC_BUILDING_CFG,SHOW_FERPA,True
HAC_BUILDING_CFG,UPD_FERPA,True
HAC_BUILDING_CFG,FERPA_EXPLANATION,True
HAC_BUILDING_CFG,SHOW_TRANSPORT,True
HAC_BUILDING_CFG,SHOW_SCHEDULE,True
HAC_BUILDING_CFG,SHOW_SCHD_GRID,True
HAC_BUILDING_CFG,SHOW_DROPPED_CRS,True
HAC_BUILDING_CFG,SHOW_REQUESTS,True
HAC_BUILDING_CFG,SHOW_ATTENDANCE,True
HAC_BUILDING_CFG,SHOW_DISCIPLINE,True
HAC_BUILDING_CFG,CURRENT_YEAR_DISC_ONLY,True
HAC_BUILDING_CFG,SHOW_ASSIGN,True
HAC_BUILDING_CFG,AVG_MARK_TYPE,True
HAC_BUILDING_CFG,INC_UNPUB_AVG,True
HAC_BUILDING_CFG,SHOW_CLASS_AVG,True
HAC_BUILDING_CFG,SHOW_ATTACHMENTS,True
HAC_BUILDING_CFG,DEF_CLASSWORK_VIEW,True
HAC_BUILDING_CFG,SHOW_IPR,True
HAC_BUILDING_CFG,SHOW_RC,True
HAC_BUILDING_CFG,SHOW_STU_COMP,True
HAC_BUILDING_CFG,SHOW_CRS_COMP,True
HAC_BUILDING_CFG,SHOW_LTDB,True
HAC_BUILDING_CFG,SHOW_EMAIL,True
HAC_BUILDING_CFG,SHOW_TRANSCRIPT,True
HAC_BUILDING_CFG,SHOW_CAREER_PLANNER,True
HAC_BUILDING_CFG,REQUEST_BY,True
HAC_BUILDING_CFG,REQUEST_YEAR,True
HAC_BUILDING_CFG,REQUEST_INTERVAL,True
HAC_BUILDING_CFG,PREREQ_CHK_REQ,True
HAC_BUILDING_CFG,SHOW_SUCCESS_PLAN,True
HAC_BUILDING_CFG,SHOW_SENS_PLAN,True
HAC_BUILDING_CFG,SHOW_SENS_INT,True
HAC_BUILDING_CFG,SHOW_SENS_INT_COMM,True
HAC_BUILDING_CFG,UPD_SSP_PARENT_GOAL,True
HAC_BUILDING_CFG,UPD_SSP_STUDENT_GOAL,True
HAC_BUILDING_CFG,SHOW_HONOR_ROLL_CREDIT,True
HAC_BUILDING_CFG,SHOW_HONOR_ROLL_GPA,True
HAC_BUILDING_CFG,SHOW_HONOR_MESSAGE,True
HAC_BUILDING_CFG,SHOW_REQUEST_ENTRY,True
HAC_BUILDING_CFG,MIN_CREDIT_REQ,True
HAC_BUILDING_CFG,MAX_CREDIT_REQ,True
HAC_BUILDING_CFG,SHOW_RC_ATTENDANCE,True
HAC_BUILDING_CFG,RC_HOLD_MESSAGE,True
HAC_BUILDING_CFG,SHOW_EO,True
HAC_BUILDING_CFG,SHOW_PERFORMANCEPLUS,True
HAC_BUILDING_CFG,SHOW_AVG_INHDR,True
HAC_BUILDING_CFG,HDR_AVG_MARKTYPE,True
HAC_BUILDING_CFG,SHOW_LAST_UPDDT,True
HAC_BUILDING_CFG,HDR_SHORT_DESC,True
HAC_BUILDING_CFG,AVG_TOOLTIP_DESC,True
HAC_BUILDING_CFG,HIDE_PERCENTAGE,True
HAC_BUILDING_CFG,HIDE_OVERALL_AVG,True
HAC_BUILDING_CFG,HIDE_COMP_SCORE,True
HAC_BUILDING_CFG,SHOW_SDE,True
HAC_BUILDING_CFG,SHOW_FEES,True
HAC_BUILDING_CFG,ENABLE_ONLINE_PAYMENT,True
HAC_BUILDING_CFG,SHOW_CALENDAR,True
HAC_BUILDING_CFG,AVG_ON_HOME_PAGE,True
HAC_BUILDING_CFG,HELP_URL,True
HAC_BUILDING_CFG,SHOW_IEP,True
HAC_BUILDING_CFG,SHOW_GIFTED,True
HAC_BUILDING_CFG,SHOW_504PLAN,True
HAC_BUILDING_CFG,SHOW_IEP_INVITATION,True
HAC_BUILDING_CFG,SHOW_EVAL_RPT,True
HAC_BUILDING_CFG,SHOW_IEP_PROGRESS,True
HAC_BUILDING_CFG,IEP_LIVING_WITH_ONLY,True
HAC_BUILDING_CFG,SHOW_WEEK_VIEW,True
HAC_BUILDING_CFG,SHOW_WEEK_VIEW_DISC,True
HAC_BUILDING_CFG,SHOW_WEEK_VIEW_FEES,True
HAC_BUILDING_CFG,SHOW_WEEK_VIEW_ATT,True
HAC_BUILDING_CFG,SHOW_WEEK_VIEW_CRS,True
HAC_BUILDING_CFG,SHOW_WEEK_VIEW_COMP,True
HAC_BUILDING_CFG,SHOW_REQUEST_ALTERNATE,True
HAC_BUILDING_CFG,AVERAGE_DISPLAY_TYPE,True
HAC_BUILDING_CFG,SHOW_RC_PRINT,True
HAC_BUILDING_CFG,SHOW_GENDER,True
HAC_BUILDING_CFG,SHOW_STUDENT_ID,True
HAC_BUILDING_CFG,SHOW_HOMEROOM,True
HAC_BUILDING_CFG,SHOW_HOMEROOM_TEACHER,True
HAC_BUILDING_CFG,SHOW_COUNSELOR,True
HAC_BUILDING_CFG,SHOW_HOUSE_TEAM,True
HAC_BUILDING_CFG,SHOW_LOCKER_NO,True
HAC_BUILDING_CFG,SHOW_LOCKER_COMBO,True
HAC_BUILDING_CFG,CHANGE_DATE_TIME,True
HAC_BUILDING_CFG,CHANGE_UID,True
HAC_BUILDING_CFG,SHOW_LEARNING_LOCATION,True
medtb_exempt,DISTRICT,True
medtb_exempt,CODE,True
medtb_exempt,DESCRIPTION,True
medtb_exempt,STATE_CODE_EQUIV,True
medtb_exempt,ACTIVE,True
medtb_exempt,CHANGE_DATE_TIME,True
medtb_exempt,CHANGE_UID,True
ltdbtb_score_pesc_code,DISTRICT,True
ltdbtb_score_pesc_code,CODE,True
ltdbtb_score_pesc_code,DESCRIPTION,True
ltdbtb_score_pesc_code,STATE_CODE_EQUIV,True
ltdbtb_score_pesc_code,ACTIVE,True
ltdbtb_score_pesc_code,CHANGE_DATE_TIME,True
ltdbtb_score_pesc_code,CHANGE_UID,True
Med_cfg,DISTRICT,True
Med_cfg,BUILDING,True
Med_cfg,AUTO_CREATE,True
Med_cfg,CALL_MAINT,True
Med_cfg,RESET_COUNT,True
Med_cfg,PRT_LTR_MER_FILE,True
Med_cfg,OTHER_LANGUAGE,True
Med_cfg,USER_SCREEN,True
Med_cfg,MED_SCREEN,True
Med_cfg,USE_MONTH_YEAR,True
Med_cfg,USE_WARNING_STATUS,True
Med_cfg,PRIOR_DAYS_UPDATE,True
Med_cfg,ALLOW_NOTES_UPDATE,True
Med_cfg,EXAM_PRI_DAYS_UPD,True
Med_cfg,USE_LAST,True
Med_cfg,NOTIFY_DWNLD_PATH,True
Med_cfg,EMAIL_OPTION,True
Med_cfg,RETURN_EMAIL,True
Med_cfg,USE_HOME_ROOM,True
Med_cfg,USE_OUTCOME,True
Med_cfg,VALID_NURSE_INIT,True
Med_cfg,INIT_OTH_NURSE_LOG,True
Med_cfg,USE_VALIDATE_SAVE,True
Med_cfg,DEFAULT_TO_SAVE,True
Med_cfg,USE_IMMUN_ALERTS,True
Med_cfg,IMM_GRACE_PERIOD,True
Med_cfg,GRACE_ENTRY_DATE,True
Med_cfg,CLEAR_EXP_DATE,True
Med_cfg,IMM_PARENT_ALERTS,True
Med_cfg,IMM_INT_EMAILS,True
Med_cfg,SUBJECT_LINE,True
Med_cfg,FROM_EMAIL,True
Med_cfg,HEADER_TEXT,True
Med_cfg,FOOTER_TEXT,True
Med_cfg,DEFAULT_MARGIN_ERR,True
Med_cfg,CHANGE_DATE_TIME,True
Med_cfg,CHANGE_UID,True
mr_level_gpa,DISTRICT,True
mr_level_gpa,BUILDING,True
mr_level_gpa,LEVEL_NUMBER,True
mr_level_gpa,MARK,True
mr_level_gpa,GPA_TYPE,True
mr_level_gpa,CHANGE_DATE_TIME,True
mr_level_gpa,CHANGE_UID,True
medtb_visit,DISTRICT,True
medtb_visit,CODE,True
medtb_visit,DESCRIPTION,True
medtb_visit,STATE_CODE_EQUIV,True
medtb_visit,ACTIVE,True
medtb_visit,CHANGE_DATE_TIME,True
medtb_visit,CHANGE_UID,True
mr_stu_hdr_subj,DISTRICT,True
mr_stu_hdr_subj,STUDENT_ID,True
mr_stu_hdr_subj,SECTION_KEY,True
mr_stu_hdr_subj,COURSE_SESSION,True
mr_stu_hdr_subj,SUBJECT_AREA,True
mr_stu_hdr_subj,VALUE,True
mr_stu_hdr_subj,OVERRIDE,True
mr_stu_hdr_subj,CHANGE_DATE_TIME,True
mr_stu_hdr_subj,CHANGE_UID,True
mr_stu_hdr,DISTRICT,True
mr_stu_hdr,STUDENT_ID,True
mr_stu_hdr,SECTION_KEY,True
mr_stu_hdr,COURSE_SESSION,True
mr_stu_hdr,RC_STATUS,True
mr_stu_hdr,ATT_CREDIT,True
mr_stu_hdr,ATT_OVERRIDE,True
mr_stu_hdr,ATT_OVR_REASON,True
mr_stu_hdr,EARN_CREDIT,True
mr_stu_hdr,EARN_OVERRIDE,True
mr_stu_hdr,ERN_OVR_REASON,True
mr_stu_hdr,STATE_CRS_EQUIV,True
mr_stu_hdr,ROW_IDENTITY,True
mr_stu_hdr,CHANGE_DATE_TIME,True
mr_stu_hdr,CHANGE_UID,True
SPITB_SEARCH_FAV_CATEGORY,DISTRICT,True
SPITB_SEARCH_FAV_CATEGORY,CODE,True
SPITB_SEARCH_FAV_CATEGORY,DESCRIPTION,True
SPITB_SEARCH_FAV_CATEGORY,ACTIVE,True
SPITB_SEARCH_FAV_CATEGORY,RESERVED,True
SPITB_SEARCH_FAV_CATEGORY,CHANGE_DATE_TIME,True
SPITB_SEARCH_FAV_CATEGORY,CHANGE_UID,True
mr_stu_grad_area,DISTRICT,True
mr_stu_grad_area,STUDENT_ID,True
mr_stu_grad_area,SECTION_KEY,True
mr_stu_grad_area,COURSE_SESSION,True
mr_stu_grad_area,REQUIRE_CODE,True
mr_stu_grad_area,CODE_OVERRIDE,True
mr_stu_grad_area,SUBJ_AREA_CREDIT,True
mr_stu_grad_area,CREDIT_OVERRIDE,True
mr_stu_grad_area,WAIVED,True
mr_stu_grad_area,CHANGE_DATE_TIME,True
mr_stu_grad_area,CHANGE_UID,True
medtb_lens,DISTRICT,True
medtb_lens,CODE,True
medtb_lens,DESCRIPTION,True
medtb_lens,STATE_CODE_EQUIV,True
medtb_lens,ACTIVE,True
medtb_lens,CHANGE_DATE_TIME,True
medtb_lens,CHANGE_UID,True
MR_GB_ALPHA_MARKS,DISTRICT,True
MR_GB_ALPHA_MARKS,BUILDING,True
MR_GB_ALPHA_MARKS,CODE,True
MR_GB_ALPHA_MARKS,DESCRIPTION,True
MR_GB_ALPHA_MARKS,EXCLUDE,True
MR_GB_ALPHA_MARKS,PERCENT_VALUE,True
MR_GB_ALPHA_MARKS,CHANGE_DATE_TIME,True
MR_GB_ALPHA_MARKS,CHANGE_UID,True
MR_GB_ALPHA_MARKS,SGY_EQUIV,True
MR_GB_ALPHA_MARKS,IMS_EQUIV,True
mr_stu_crsequ_mark,DISTRICT,True
mr_stu_crsequ_mark,SCHOOL_YEAR,True
mr_stu_crsequ_mark,BUILDING,True
mr_stu_crsequ_mark,STUDENT_ID,True
mr_stu_crsequ_mark,STATE_ID,True
mr_stu_crsequ_mark,SECTION_KEY,True
mr_stu_crsequ_mark,COURSE_SESSION,True
mr_stu_crsequ_mark,DEST_MARK_TYPE,True
mr_stu_crsequ_mark,DESTINATION_MP,True
mr_stu_crsequ_mark,SOURCE_MARK_TYPE,True
mr_stu_crsequ_mark,SOURCE_MP,True
mr_stu_crsequ_mark,MARK_VALUE,True
mr_stu_crsequ_mark,CHANGE_DATE_TIME,True
mr_stu_crsequ_mark,CHANGE_UID,True
mr_stu_crsequ_crd,DISTRICT,True
mr_stu_crsequ_crd,SCHOOL_YEAR,True
mr_stu_crsequ_crd,BUILDING,True
mr_stu_crsequ_crd,STUDENT_ID,True
mr_stu_crsequ_crd,STATE_ID,True
mr_stu_crsequ_crd,SECTION_KEY,True
mr_stu_crsequ_crd,COURSE_SESSION,True
mr_stu_crsequ_crd,EQUIV_SEQUENCE,True
mr_stu_crsequ_crd,ATT_CREDIT,True
mr_stu_crsequ_crd,EARN_OVERRIDE,True
mr_stu_crsequ_crd,EARN_CREDIT,True
mr_stu_crsequ_crd,CHANGE_DATE_TIME,True
mr_stu_crsequ_crd,CHANGE_UID,True
mr_stu_crsequ_abs,DISTRICT,True
mr_stu_crsequ_abs,SCHOOL_YEAR,True
mr_stu_crsequ_abs,BUILDING,True
mr_stu_crsequ_abs,STUDENT_ID,True
mr_stu_crsequ_abs,STATE_ID,True
mr_stu_crsequ_abs,SECTION_KEY,True
mr_stu_crsequ_abs,COURSE_SESSION,True
mr_stu_crsequ_abs,ABSENCE_TYPE,True
mr_stu_crsequ_abs,MARKING_PERIOD,True
mr_stu_crsequ_abs,ABSENCE_VALUE,True
mr_stu_crsequ_abs,CHANGE_DATE_TIME,True
mr_stu_crsequ_abs,CHANGE_UID,True
Mr_stu_comments,DISTRICT,True
Mr_stu_comments,SCHOOL_YEAR,True
Mr_stu_comments,BUILDING,True
Mr_stu_comments,STUDENT_ID,True
Mr_stu_comments,SEQUENCE_NUM,True
Mr_stu_comments,TRN_COMMENT,True
Mr_stu_comments,EXCLUDE,True
Mr_stu_comments,CHANGE_DATE_TIME,True
Mr_stu_comments,CHANGE_UID,True
mr_stu_bldg_type,DISTRICT,True
mr_stu_bldg_type,STUDENT_ID,True
mr_stu_bldg_type,SECTION_KEY,True
mr_stu_bldg_type,COURSE_SESSION,True
mr_stu_bldg_type,BLDG_TYPE,True
mr_stu_bldg_type,CHANGE_DATE_TIME,True
mr_stu_bldg_type,CHANGE_UID,True
mr_stu_gpa,DISTRICT,True
mr_stu_gpa,STUDENT_ID,True
mr_stu_gpa,GPA_TYPE,True
mr_stu_gpa,SCHOOL_YEAR,True
mr_stu_gpa,RUN_TERM_YEAR,True
mr_stu_gpa,BUILDING,True
mr_stu_gpa,GRADE,True
mr_stu_gpa,NEEDS_RECALC,True
mr_stu_gpa,OVERRIDE,True
mr_stu_gpa,CUR_GPA_CALC_DATE,True
mr_stu_gpa,CUR_GPA,True
mr_stu_gpa,CUR_QUALITY_POINTS,True
mr_stu_gpa,CUR_ADD_ON_POINTS,True
mr_stu_gpa,CUR_ATT_CREDIT,True
mr_stu_gpa,CUR_EARN_CREDIT,True
mr_stu_gpa,CUR_RNK_CALC_DATE,True
mr_stu_gpa,CUR_RANK,True
mr_stu_gpa,CUR_PERCENTILE,True
mr_stu_gpa,CUR_DECILE,True
mr_stu_gpa,CUR_QUINTILE,True
mr_stu_gpa,CUR_QUARTILE,True
mr_stu_gpa,CUR_RANK_GPA,True
mr_stu_gpa,CUM_GPA_CALC_DATE,True
mr_stu_gpa,CUM_GPA,True
mr_stu_gpa,CUM_QUALITY_POINTS,True
mr_stu_gpa,CUM_ADD_ON_POINTS,True
mr_stu_gpa,CUM_ATT_CREDIT,True
mr_stu_gpa,CUM_EARN_CREDIT,True
mr_stu_gpa,CUM_RNK_CALC_DATE,True
mr_stu_gpa,CUM_RANK,True
mr_stu_gpa,CUM_PERCENTILE,True
mr_stu_gpa,CUM_DECILE,True
mr_stu_gpa,CUM_QUINTILE,True
mr_stu_gpa,CUM_QUARTILE,True
mr_stu_gpa,CUM_RANK_GPA,True
mr_stu_gpa,CUR_RANK_QUAL_PTS,True
mr_stu_gpa,CUM_RANK_QUAL_PTS,True
mr_stu_gpa,BLDG_OVERRIDE,True
mr_stu_gpa,CHANGE_DATE_TIME,True
mr_stu_gpa,CHANGE_UID,True
MR_GB_COMMENT,DISTRICT,True
MR_GB_COMMENT,BUILDING,True
MR_GB_COMMENT,CODE,True
MR_GB_COMMENT,DESCRIPTION,True
MR_GB_COMMENT,CHANGE_DATE_TIME,True
MR_GB_COMMENT,CHANGE_UID,True
Mr_sc_tea_comp,DISTRICT,True
Mr_sc_tea_comp,BUILDING,True
Mr_sc_tea_comp,SCHOOL_YEAR,True
Mr_sc_tea_comp,COMPETENCY_GROUP,True
Mr_sc_tea_comp,DEFAULT_ASSIGNMENT,True
Mr_sc_tea_comp,STAFF_ID,True
Mr_sc_tea_comp,CHANGE_DATE_TIME,True
Mr_sc_tea_comp,CHANGE_UID,True
mr_sc_stustu_taken,DISTRICT,True
mr_sc_stustu_taken,BUILDING,True
mr_sc_stustu_taken,SCHOOL_YEAR,True
mr_sc_stustu_taken,COMPETENCY_GROUP,True
mr_sc_stustu_taken,STAFF_ID,True
mr_sc_stustu_taken,MARKING_PERIOD,True
mr_sc_stustu_taken,STUDENT_ID,True
mr_sc_stustu_taken,CHANGE_DATE_TIME,True
mr_sc_stustu_taken,CHANGE_UID,True
Mr_sc_stu_text,DISTRICT,True
Mr_sc_stu_text,BUILDING,True
Mr_sc_stu_text,SCHOOL_YEAR,True
Mr_sc_stu_text,STUDENT_ID,True
Mr_sc_stu_text,STAFF_ID,True
Mr_sc_stu_text,MARKING_PERIOD,True
Mr_sc_stu_text,STUDENT_TEXT,True
Mr_sc_stu_text,CHANGE_DATE_TIME,True
Mr_sc_stu_text,CHANGE_UID,True
mr_gb_cat_bld,DISTRICT,True
mr_gb_cat_bld,BUILDING,True
mr_gb_cat_bld,CODE,True
mr_gb_cat_bld,CHANGE_DATE_TIME,True
mr_gb_cat_bld,CHANGE_UID,True
Mr_sc_stu_taken,DISTRICT,True
Mr_sc_stu_taken,BUILDING,True
Mr_sc_stu_taken,SCHOOL_YEAR,True
Mr_sc_stu_taken,COMPETENCY_GROUP,True
Mr_sc_stu_taken,STAFF_ID,True
Mr_sc_stu_taken,MARKING_PERIOD,True
Mr_sc_stu_taken,CHANGE_DATE_TIME,True
Mr_sc_stu_taken,CHANGE_UID,True
mr_stu_absences,DISTRICT,True
mr_stu_absences,STUDENT_ID,True
mr_stu_absences,SECTION_KEY,True
mr_stu_absences,COURSE_SESSION,True
mr_stu_absences,MARKING_PERIOD,True
mr_stu_absences,ABSENCE_TYPE,True
mr_stu_absences,ABSENCE_VALUE,True
mr_stu_absences,OVERRIDE,True
mr_stu_absences,CHANGE_DATE_TIME,True
mr_stu_absences,CHANGE_UID,True
regtb_ethnicity,DISTRICT,True
regtb_ethnicity,CODE,True
regtb_ethnicity,DESCRIPTION,True
regtb_ethnicity,STATE_CODE_EQUIV,True
regtb_ethnicity,FEDERAL_CODE_EQUIV,True
regtb_ethnicity,ACTIVE,True
regtb_ethnicity,SIF_CODE,True
regtb_ethnicity,SIF2_CODE,True
regtb_ethnicity,CHANGE_DATE_TIME,True
regtb_ethnicity,CHANGE_UID,True
regtb_entry,DISTRICT,True
regtb_entry,CODE,True
regtb_entry,DESCRIPTION,True
regtb_entry,STATE_CODE_EQUIV,True
regtb_entry,ACTIVE,True
regtb_entry,SIF_CODE,True
regtb_entry,SIF2_CODE,True
regtb_entry,CHANGE_DATE_TIME,True
regtb_entry,CHANGE_UID,True
regtb_elig_status,DISTRICT,True
regtb_elig_status,CODE,True
regtb_elig_status,DESCRIPTION,True
regtb_elig_status,PRIORITY,True
regtb_elig_status,ELIGIBLE_FLAG,True
regtb_elig_status,ACTIVE,True
regtb_elig_status,CHANGE_DATE_TIME,True
regtb_elig_status,CHANGE_UID,True
regtb_elig_reason,DISTRICT,True
regtb_elig_reason,CODE,True
regtb_elig_reason,DESCRIPTION,True
regtb_elig_reason,PRIORITY,True
regtb_elig_reason,ELIGIBLE_FLAG,True
regtb_elig_reason,ACTIVE,True
regtb_elig_reason,CHANGE_DATE_TIME,True
regtb_elig_reason,CHANGE_UID,True
mr_sc_stu_tea,DISTRICT,True
mr_sc_stu_tea,BUILDING,True
mr_sc_stu_tea,SCHOOL_YEAR,True
mr_sc_stu_tea,STUDENT_ID,True
mr_sc_stu_tea,COMPETENCY_GROUP,True
mr_sc_stu_tea,STAFF_ID,True
mr_sc_stu_tea,OVERRIDE,True
mr_sc_stu_tea,CHANGE_DATE_TIME,True
mr_sc_stu_tea,CHANGE_UID,True
Mr_stu_grad,DISTRICT,True
Mr_stu_grad,STUDENT_ID,True
Mr_stu_grad,REQUIRE_CODE,True
Mr_stu_grad,SUBJ_AREA_CREDIT,True
Mr_stu_grad,CUR_ATT_CREDITS,True
Mr_stu_grad,CUR_EARN_CREDITS,True
Mr_stu_grad,SUBJ_AREA_CRD_WAV,True
Mr_stu_grad,CUR_ATT_CRD_WAV,True
Mr_stu_grad,CUR_EARN_CRD_WAV,True
Mr_stu_grad,CHANGE_DATE_TIME,True
Mr_stu_grad,CHANGE_UID,True
Mr_sc_stu_crs_comp,DISTRICT,True
Mr_sc_stu_crs_comp,SCHOOL_YEAR,True
Mr_sc_stu_crs_comp,STUDENT_ID,True
Mr_sc_stu_crs_comp,BUILDING,True
Mr_sc_stu_crs_comp,COURSE,True
Mr_sc_stu_crs_comp,COMPETENCY_GROUP,True
Mr_sc_stu_crs_comp,COMPETENCY_NUMBER,True
Mr_sc_stu_crs_comp,MARKING_PERIOD,True
Mr_sc_stu_crs_comp,MARK_TYPE,True
Mr_sc_stu_crs_comp,MARK_VALUE,True
Mr_sc_stu_crs_comp,MARK_OVERRIDE,True
Mr_sc_stu_crs_comp,CHANGE_DATE_TIME,True
Mr_sc_stu_crs_comp,CHANGE_UID,True
mr_state_courses,DISTRICT,True
mr_state_courses,SCHOOL_YEAR,True
mr_state_courses,STATE_CODE,True
mr_state_courses,DESCRIPTION,True
mr_state_courses,ABBREV_COURSE_NAME,True
mr_state_courses,FLAG_01,True
mr_state_courses,FLAG_02,True
mr_state_courses,FLAG_03,True
mr_state_courses,FLAG_04,True
mr_state_courses,FLAG_05,True
mr_state_courses,FLAG_06,True
mr_state_courses,FLAG_07,True
mr_state_courses,FLAG_08,True
mr_state_courses,FLAG_09,True
mr_state_courses,FLAG_10,True
mr_state_courses,ACTIVE,True
mr_state_courses,CHANGE_DATE_TIME,True
mr_state_courses,CHANGE_UID,True
regtb_department,DISTRICT,True
regtb_department,CODE,True
regtb_department,DESCRIPTION,True
regtb_department,DEPT_ORDER,True
regtb_department,STATE_CODE_EQUIV,True
regtb_department,PERF_PLUS_CODE,True
regtb_department,ACTIVE,True
regtb_department,SIF_CODE,True
regtb_department,SIF2_CODE,True
regtb_department,ROW_IDENTITY,True
regtb_department,CHANGE_DATE_TIME,True
regtb_department,CHANGE_UID,True
Mr_stu_grad_value,DISTRICT,True
Mr_stu_grad_value,STUDENT_ID,True
Mr_stu_grad_value,REQUIRE_CODE,True
Mr_stu_grad_value,VALUE,True
Mr_stu_grad_value,CHANGE_DATE_TIME,True
Mr_stu_grad_value,CHANGE_UID,True
regtb_edu_level,DISTRICT,True
regtb_edu_level,CODE,True
regtb_edu_level,DESCRIPTION,True
regtb_edu_level,STATE_CODE_EQUIV,True
regtb_edu_level,ACTIVE,True
regtb_edu_level,CHANGE_DATE_TIME,True
regtb_edu_level,CHANGE_UID,True
regtb_country,DISTRICT,True
regtb_country,CODE,True
regtb_country,DESCRIPTION,True
regtb_country,STATE_CODE_EQUIV,True
regtb_country,ACTIVE,True
regtb_country,CHANGE_DATE_TIME,True
regtb_country,CHANGE_UID,True
regtb_diplomas,DISTRICT,True
regtb_diplomas,CODE,True
regtb_diplomas,DESCRIPTION,True
regtb_diplomas,TRANSCRIPT_DESCRIPTION,True
regtb_diplomas,STATE_CODE_EQUIV,True
regtb_diplomas,ACTIVE,True
regtb_diplomas,CHANGE_DATE_TIME,True
regtb_diplomas,CHANGE_UID,True
regtb_complex_type,DISTRICT,True
regtb_complex_type,CODE,True
regtb_complex_type,DESCRIPTION,True
regtb_complex_type,ACTIVE,True
regtb_complex_type,CHANGE_DATE_TIME,True
regtb_complex_type,CHANGE_UID,True
regtb_complex,DISTRICT,True
regtb_complex,CODE,True
regtb_complex,DESCRIPTION,True
regtb_complex,TYPE,True
regtb_complex,ACTIVE,True
regtb_complex,CHANGE_DATE_TIME,True
regtb_complex,CHANGE_UID,True
regtb_classify,DISTRICT,True
regtb_classify,CODE,True
regtb_classify,DESCRIPTION,True
regtb_classify,SCHEDULING_WEIGHT,True
regtb_classify,STATE_CODE_EQUIV,True
regtb_classify,ACTIVE,True
regtb_classify,CHANGE_DATE_TIME,True
regtb_classify,CHANGE_UID,True
regtb_cc_mark_type,DISTRICT,True
regtb_cc_mark_type,MARK_NO,True
regtb_cc_mark_type,MARK_TYPE,True
regtb_cc_mark_type,CHANGE_DATE_TIME,True
regtb_cc_mark_type,CHANGE_UID,True
regtb_cc_bldg_type,DISTRICT,True
regtb_cc_bldg_type,CODE,True
regtb_cc_bldg_type,SCHOOL_TYPE,True
regtb_cc_bldg_type,CHANGE_DATE_TIME,True
regtb_cc_bldg_type,CHANGE_UID,True
regtb_county,DISTRICT,True
regtb_county,CODE,True
regtb_county,DESCRIPTION,True
regtb_county,STATE_CODE_EQUIV,True
regtb_county,ACTIVE,True
regtb_county,CHANGE_DATE_TIME,True
regtb_county,CHANGE_UID,True
schd_course_subj,DISTRICT,True
schd_course_subj,BUILDING,True
schd_course_subj,COURSE,True
schd_course_subj,SUBJECT_AREA,True
schd_course_subj,SUBJ_ORDER,True
schd_course_subj,SUB_AREA,True
schd_course_subj,CHANGE_DATE_TIME,True
schd_course_subj,CHANGE_UID,True
schd_course_seq,DISTRICT,True
schd_course_seq,BUILDING,True
schd_course_seq,SEQUENCE_NUM,True
schd_course_seq,COURSE_OR_GROUP_A,True
schd_course_seq,SEQUENCE_A,True
schd_course_seq,SEQUENCE_TYPE,True
schd_course_seq,COURSE_OR_GROUP_B,True
schd_course_seq,SEQUENCE_B,True
schd_course_seq,IS_VALID,True
schd_course_seq,ERROR_MESSAGE,True
schd_course_seq,PREREQ_MIN_MARK,True
schd_course_seq,PREREQ_MARK_TYPE,True
schd_course_seq,CHANGE_DATE_TIME,True
schd_course_seq,CHANGE_UID,True
schd_course_qualify,DISTRICT,True
schd_course_qualify,BUILDING,True
schd_course_qualify,COURSE,True
schd_course_qualify,QUALIFICATION,True
schd_course_qualify,CHANGE_DATE_TIME,True
schd_course_qualify,CHANGE_UID,True
schd_course_honors,DISTRICT,True
schd_course_honors,BUILDING,True
schd_course_honors,COURSE,True
schd_course_honors,HONOR_TYPE,True
schd_course_honors,HONOR_LEVEL,True
schd_course_honors,CHANGE_DATE_TIME,True
schd_course_honors,CHANGE_UID,True
regtb_day_type,DISTRICT,True
regtb_day_type,CODE,True
regtb_day_type,DESCRIPTION,True
regtb_day_type,STATE_CODE_EQUIV,True
regtb_day_type,ACTIVE,True
regtb_day_type,CHANGE_DATE_TIME,True
regtb_day_type,CHANGE_UID,True
regtb_bldg_reason,DISTRICT,True
regtb_bldg_reason,CODE,True
regtb_bldg_reason,DESCRIPTION,True
regtb_bldg_reason,ACTIVE,True
regtb_bldg_reason,SIF_CODE,True
regtb_bldg_reason,SIF2_CODE,True
regtb_bldg_reason,CHANGE_DATE_TIME,True
regtb_bldg_reason,CHANGE_UID,True
schd_course_subj_tag,DISTRICT,True
schd_course_subj_tag,BUILDING,True
schd_course_subj_tag,COURSE,True
schd_course_subj_tag,SUBJECT_AREA,True
schd_course_subj_tag,TAG,True
schd_course_subj_tag,CHANGE_DATE_TIME,True
schd_course_subj_tag,CHANGE_UID,True
regtb_disability,DISTRICT,True
regtb_disability,CODE,True
regtb_disability,DESCRIPTION,True
regtb_disability,STATE_CODE_EQUIV,True
regtb_disability,SENSITIVE,True
regtb_disability,ACTIVE,True
regtb_disability,CHANGE_DATE_TIME,True
regtb_disability,CHANGE_UID,True
regtb_appt_type,DISTRICT,True
regtb_appt_type,CODE,True
regtb_appt_type,DESCRIPTION,True
regtb_appt_type,LINK_PATH,True
regtb_appt_type,ACTIVE,True
regtb_appt_type,CHANGE_DATE_TIME,True
regtb_appt_type,CHANGE_UID,True
regtb_citizenship,DISTRICT,True
regtb_citizenship,CODE,True
regtb_citizenship,DESCRIPTION,True
regtb_citizenship,STATE_CODE_EQUIV,True
regtb_citizenship,ACTIVE,True
regtb_citizenship,CHANGE_DATE_TIME,True
regtb_citizenship,CHANGE_UID,True
reg_yrend_update,DISTRICT,True
reg_yrend_update,RUN_PROCESS,True
reg_yrend_update,CRITERION,True
reg_yrend_update,LINE_NUMBER,True
reg_yrend_update,TABLE_NAME,True
reg_yrend_update,COLUMN_NAME,True
reg_yrend_update,NEW_VALUE,True
reg_yrend_update,CHANGE_DATE_TIME,True
reg_yrend_update,CHANGE_UID,True
regtb_curr_code,DISTRICT,True
regtb_curr_code,CODE,True
regtb_curr_code,DESCRIPTION,True
regtb_curr_code,STATE_CODE_EQUIV,True
regtb_curr_code,ACTIVE,True
regtb_curr_code,CHANGE_DATE_TIME,True
regtb_curr_code,CHANGE_UID,True
reg_yrend_select,DISTRICT,True
reg_yrend_select,RUN_PROCESS,True
reg_yrend_select,CRITERION,True
reg_yrend_select,LINE_NUMBER,True
reg_yrend_select,AND_OR_FLAG,True
reg_yrend_select,TABLE_NAME,True
reg_yrend_select,COLUMN_NAME,True
reg_yrend_select,OPERATOR,True
reg_yrend_select,SEARCH_VALUE1,True
reg_yrend_select,SEARCH_VALUE2,True
reg_yrend_select,CHANGE_DATE_TIME,True
reg_yrend_select,CHANGE_UID,True
regtb_attachment_category,DISTRICT,True
regtb_attachment_category,ATTACHMENT_CATEGORY,True
regtb_attachment_category,DESCRIPTION,True
regtb_attachment_category,SEC_PACKAGE,True
regtb_attachment_category,SEC_SUBPACKAGE,True
regtb_attachment_category,SEC_FEATURE,True
regtb_attachment_category,ACTIVE,True
regtb_attachment_category,CHANGE_DATE_TIME,True
regtb_attachment_category,CHANGE_UID,True
regtb_at_risk_reason,DISTRICT,True
regtb_at_risk_reason,CODE,True
regtb_at_risk_reason,DESCRIPTION,True
regtb_at_risk_reason,USE_SSP,True
regtb_at_risk_reason,USE_AT_RISK,True
regtb_at_risk_reason,ACTIVE,True
regtb_at_risk_reason,CHANGE_DATE_TIME,True
regtb_at_risk_reason,CHANGE_UID,True
reg_user_staff_bld,DISTRICT,True
reg_user_staff_bld,BUILDING,True
reg_user_staff_bld,STAFF_ID,True
reg_user_staff_bld,SCREEN_NUMBER,True
reg_user_staff_bld,LIST_SEQUENCE,True
reg_user_staff_bld,FIELD_NUMBER,True
reg_user_staff_bld,FIELD_VALUE,True
reg_user_staff_bld,CHANGE_DATE_TIME,True
reg_user_staff_bld,CHANGE_UID,True
reg_user_staff,DISTRICT,True
reg_user_staff,STAFF_ID,True
reg_user_staff,SCREEN_NUMBER,True
reg_user_staff,LIST_SEQUENCE,True
reg_user_staff,FIELD_NUMBER,True
reg_user_staff,FIELD_VALUE,True
reg_user_staff,ROW_IDENTITY,True
reg_user_staff,CHANGE_DATE_TIME,True
reg_user_staff,CHANGE_UID,True
regtb_academic_dis,DISTRICT,True
regtb_academic_dis,CODE,True
regtb_academic_dis,DESCRIPTION,True
regtb_academic_dis,STATE_CODE_EQUIV,True
regtb_academic_dis,ACTIVE,True
regtb_academic_dis,CHANGE_DATE_TIME,True
regtb_academic_dis,CHANGE_UID,True
regtb_bldg_types,DISTRICT,True
regtb_bldg_types,CODE,True
regtb_bldg_types,DESCRIPTION,True
regtb_bldg_types,STATE_CODE_EQUIV,True
regtb_bldg_types,ACTIVE,True
regtb_bldg_types,CHANGE_DATE_TIME,True
regtb_bldg_types,CHANGE_UID,True
reg_track,DISTRICT,True
reg_track,SCHOOL_YEAR,True
reg_track,BUILDING,True
reg_track,CODE,True
reg_track,DESCRIPTION,True
reg_track,START_DATE,True
reg_track,END_DATE,True
reg_track,CHANGE_DATE_TIME,True
reg_track,CHANGE_UID,True
reg_yrend_criteria,DISTRICT,True
reg_yrend_criteria,RUN_PROCESS,True
reg_yrend_criteria,CRITERION,True
reg_yrend_criteria,SEQUENCE,True
reg_yrend_criteria,DESCRIPTION,True
reg_yrend_criteria,STUDENT_STATUS,True
reg_yrend_criteria,ROLLOVER_ENTRY,True
reg_yrend_criteria,ROLLOVER_WITH,True
reg_yrend_criteria,CHANGE_DATE_TIME,True
reg_yrend_criteria,CHANGE_UID,True
reg_summer_school,DISTRICT,True
reg_summer_school,STUDENT_ID,True
reg_summer_school,BUILDING,True
reg_summer_school,GRADE,True
reg_summer_school,TRACK,True
reg_summer_school,CALENDAR,True
reg_summer_school,COUNSELOR,True
reg_summer_school,HOUSE_TEAM,True
reg_summer_school,HOMEROOM_PRIMARY,True
reg_summer_school,HOMEROOM_SECONDARY,True
reg_summer_school,CHANGE_DATE_TIME,True
reg_summer_school,CHANGE_UID,True
reg_stu_contact_alert,DISTRICT,True
reg_stu_contact_alert,STUDENT_ID,True
reg_stu_contact_alert,CONTACT_ID,True
reg_stu_contact_alert,ALERT_TYPE,True
reg_stu_contact_alert,SIGNUP_DATE,True
reg_stu_contact_alert,LAST_ALERT_DATE,True
reg_stu_contact_alert,NEXT_ALERT_DATE,True
reg_stu_contact_alert,SCHEDULE_TYPE,True
reg_stu_contact_alert,SCHD_INTERVAL,True
reg_stu_contact_alert,SCHD_DOW,True
reg_stu_contact_alert,NOTIFICATION_TYPE,True
reg_stu_contact_alert,CHANGE_DATE_TIME,True
reg_stu_contact_alert,CHANGE_UID,True
reg_user_district,DISTRICT,True
reg_user_district,SCREEN_NUMBER,True
reg_user_district,FIELD_NUMBER,True
reg_user_district,LIST_SEQUENCE,True
reg_user_district,FIELD_VALUE,True
reg_user_district,CHANGE_DATE_TIME,True
reg_user_district,CHANGE_UID,True
reg_stu_at_risk,DISTRICT,True
reg_stu_at_risk,STUDENT_ID,True
reg_stu_at_risk,FACTOR_CODE,True
reg_stu_at_risk,FACTOR_STATUS,True
reg_stu_at_risk,STATUS_OVR,True
reg_stu_at_risk,CHANGE_DATE_TIME,True
reg_stu_at_risk,CHANGE_UID,True
reg_user,DISTRICT,True
reg_user,STUDENT_ID,True
reg_user,SCREEN_NUMBER,True
reg_user,FIELD_NUMBER,True
reg_user,LIST_SEQUENCE,True
reg_user,FIELD_VALUE,True
reg_user,ROW_IDENTITY,True
reg_user,CHANGE_DATE_TIME,True
reg_user,CHANGE_UID,True
reg_staff_qualify,DISTRICT,True
reg_staff_qualify,STAFF_ID,True
reg_staff_qualify,QUALIFICATION,True
reg_staff_qualify,EXPIRATION_DATE,True
reg_staff_qualify,CHANGE_DATE_TIME,True
reg_staff_qualify,CHANGE_UID,True
reg_travel,DISTRICT,True
reg_travel,STUDENT_ID,True
reg_travel,TRAVEL_DIRECTION,True
reg_travel,TRAVEL_TRIP,True
reg_travel,START_DATE,True
reg_travel,END_DATE,True
reg_travel,TRAVEL_SEGMENT,True
reg_travel,SUNDAY,True
reg_travel,MONDAY,True
reg_travel,TUESDAY,True
reg_travel,WEDNESDAY,True
reg_travel,THURSDAY,True
reg_travel,FRIDAY,True
reg_travel,SATURDAY,True
reg_travel,TRAVEL_TYPE,True
reg_travel,TRANSPORT_DISTANCE,True
reg_travel,BUS_NUMBER,True
reg_travel,BUS_ROUTE,True
reg_travel,STOP_NUMBER,True
reg_travel,STOP_TIME,True
reg_travel,STOP_DESCRIPTION,True
reg_travel,SHUTTLE_STOP,True
reg_travel,ROW_IDENTITY,True
reg_travel,CHANGE_DATE_TIME,True
reg_travel,CHANGE_UID,True
reg_staff_bldgs,DISTRICT,True
reg_staff_bldgs,BUILDING,True
reg_staff_bldgs,STAFF_ID,True
reg_staff_bldgs,STAFF_NAME,True
reg_staff_bldgs,INITIALS,True
reg_staff_bldgs,IS_COUNSELOR,True
reg_staff_bldgs,IS_TEACHER,True
reg_staff_bldgs,IS_ADVISOR,True
reg_staff_bldgs,HOMEROOM_PRIMARY,True
reg_staff_bldgs,HOMEROOM_SECONDARY,True
reg_staff_bldgs,ROOM,True
reg_staff_bldgs,HOUSE_TEAM,True
reg_staff_bldgs,DEPARTMENT,True
reg_staff_bldgs,PHONE,True
reg_staff_bldgs,PHONE_EXTENSION,True
reg_staff_bldgs,ACTIVE,True
reg_staff_bldgs,IS_PRIMARY_BLDG,True
reg_staff_bldgs,GROUP_CODE,True
reg_staff_bldgs,MAXIMUM_CONTIGUOUS,True
reg_staff_bldgs,MAXIMUM_PER_DAY,True
reg_staff_bldgs,ALLOW_OVERRIDE,True
reg_staff_bldgs,REGULAR_YEAR,True
reg_staff_bldgs,SUMMER_SCHOOL,True
reg_staff_bldgs,TAKE_LUNCH_COUNTS,True
reg_staff_bldgs,ROW_IDENTITY,True
reg_staff_bldgs,CHANGE_DATE_TIME,True
reg_staff_bldgs,CHANGE_UID,True
reg_staff_address,DISTRICT,True
reg_staff_address,STAFF_ID,True
reg_staff_address,APARTMENT,True
reg_staff_address,COMPLEX,True
reg_staff_address,STREET_NUMBER,True
reg_staff_address,STREET_PREFIX,True
reg_staff_address,STREET_NAME,True
reg_staff_address,STREET_SUFFIX,True
reg_staff_address,STREET_TYPE,True
reg_staff_address,CITY,True
reg_staff_address,STATE,True
reg_staff_address,ZIP,True
reg_staff_address,DELIVERY_POINT,True
reg_staff_address,CHANGE_DATE_TIME,True
reg_staff_address,CHANGE_UID,True
reg_state,DISTRICT,True
reg_state,CODE,True
reg_state,DESCRIPTION,True
reg_state,STU_WITHDRAW_RULE,True
reg_state,STATE_CODE_EQUIV,True
reg_state,ACTIVE,True
reg_state,CHANGE_DATE_TIME,True
reg_state,CHANGE_UID,True
reg_staff,DISTRICT,True
reg_staff,STAFF_ID,True
reg_staff,FIRST_NAME,True
reg_staff,MIDDLE_NAME,True
reg_staff,LAST_NAME,True
reg_staff,MAIDEN_NAME,True
reg_staff,TITLE_CODE,True
reg_staff,EMAIL,True
reg_staff,SSN,True
reg_staff,FMS_DEPARTMENT,True
reg_staff,FMS_EMPL_NUMBER,True
reg_staff,FMS_LOCATION,True
reg_staff,TEACHER_LOAD,True
reg_staff,LOGIN_ID,True
reg_staff,SUB_LOGIN_ID,True
reg_staff,SUB_EXPIRATION,True
reg_staff,GENDER,True
reg_staff,PRIM_ETHNIC_CODE,True
reg_staff,HISPANIC,True
reg_staff,FED_RACE_ETHNIC,True
reg_staff,BIRTHDATE,True
reg_staff,STAFF_STATE_ID,True
reg_staff,ESP_LOGIN_ID,True
reg_staff,ROW_IDENTITY,True
reg_staff,CHANGE_DATE_TIME,True
reg_staff,CHANGE_UID,True
reg_staff,GENDER_IDENTITY,True
reg_staff_ethnic,DISTRICT,True
reg_staff_ethnic,STAFF_ID,True
reg_staff_ethnic,ETHNIC_CODE,True
reg_staff_ethnic,ETHNICITY_ORDER,True
reg_staff_ethnic,PERCENTAGE,True
reg_staff_ethnic,CHANGE_DATE_TIME,True
reg_staff_ethnic,CHANGE_UID,True
reg_program_setup,DISTRICT,True
reg_program_setup,PROGRAM_ID,True
reg_program_setup,DESCRIPTION,True
reg_program_setup,SEC_PACKAGE,True
reg_program_setup,SEC_SUBPACKAGE,True
reg_program_setup,SEC_FEATURE,True
reg_program_setup,START_DATE,True
reg_program_setup,END_DATE,True
reg_program_setup,INSTRUCT_HOURS,True
reg_program_setup,INSTRUCT_HOUR_UNIT,True
reg_program_setup,RESERVED,True
reg_program_setup,RULES_LOCKED,True
reg_program_setup,CHANGE_DATE_TIME,True
reg_program_setup,CHANGE_UID,True
reg_program_column,DISTRICT,True
reg_program_column,PROGRAM_ID,True
reg_program_column,FIELD_NUMBER,True
reg_program_column,FIELD_ORDER,True
reg_program_column,FIELD_LEVEL,True
reg_program_column,TABLE_NAME,True
reg_program_column,SCREEN_NUMBER,True
reg_program_column,COLUMN_NAME,True
reg_program_column,LINK_DATES_TO,True
reg_program_column,LINK_TYPE,True
reg_program_column,LABEL,True
reg_program_column,SCREEN_TYPE,True
reg_program_column,DATA_TYPE,True
reg_program_column,DATA_SIZE,True
reg_program_column,ADD_DEFAULT,True
reg_program_column,VALIDATION_LIST,True
reg_program_column,VALIDATION_TABLE,True
reg_program_column,CODE_COLUMN,True
reg_program_column,DESCRIPTION_COLUMN,True
reg_program_column,STATE_CODE_EQUIV,True
reg_program_column,USE_REASONS,True
reg_program_column,USE_OVERRIDE,True
reg_program_column,YREND_INACTIVES,True
reg_program_column,INACTIVE_SRC_RESET,True
reg_program_column,INACTIVE_WD_CODE,True
reg_program_column,YREND_ACTIVES,True
reg_program_column,ACTIVE_SRC_RESET,True
reg_program_column,ACTIVE_WD_CODE,True
reg_program_column,YREND_ENTRY_DATE,True
reg_program_column,YREND_ACTPRES,True
reg_program_column,SEC_PACKAGE,True
reg_program_column,SEC_SUBPACKAGE,True
reg_program_column,SEC_FEATURE,True
reg_program_column,YREND_LOCKED,True
reg_program_column,CHANGE_DATE_TIME,True
reg_program_column,CHANGE_UID,True
reg_personal,DISTRICT,True
reg_personal,STUDENT_ID,True
reg_personal,SSN,True
reg_personal,BIRTH_CITY,True
reg_personal,BIRTH_STATE,True
reg_personal,BIRTH_COUNTRY,True
reg_personal,MEAL_STATUS,True
reg_personal,CLASSIFICATION,True
reg_personal,LOCKER_NUMBER,True
reg_personal,LOCKER_COMBINATION,True
reg_personal,COMMENTS,True
reg_personal,ETHNIC_CODE,True
reg_personal,HISPANIC,True
reg_personal,FED_RACE_ETHNIC,True
reg_personal,RESIDENCY_CODE,True
reg_personal,STATE_REPORT_ID,True
reg_personal,PREVIOUS_ID,True
reg_personal,PREVIOUS_ID_ASOF,True
reg_personal,SHOW_ALERTS,True
reg_personal,MIGRANT,True
reg_personal,AT_RISK,True
reg_personal,ESL,True
reg_personal,HAS_IEP,True
reg_personal,IEP_STATUS,True
reg_personal,SECTION_504_PLAN,True
reg_personal,HOMELESS_STATUS,True
reg_personal,MIGRANT_ID,True
reg_personal,CITIZEN_STATUS,True
reg_personal,MOTHER_MAIDEN_NAME,True
reg_personal,FEE_STATUS,True
reg_personal,FEE_STATUS_OVR,True
reg_personal,FEE_BALANCE,True
reg_personal,FERPA_NAME,True
reg_personal,FERPA_ADDRESS,True
reg_personal,FERPA_PHONE,True
reg_personal,FERPA_PHOTO,True
reg_personal,TRANSFER_BLDG_FROM,True
reg_personal,ACADEMIC_DIS,True
reg_personal,HAS_SSP,True
reg_personal,IEP_INTEGRATION,True
reg_personal,FOSTER_CARE,True
reg_personal,ORIGIN_COUNTRY,True
reg_personal,ELL_YEARS,True
reg_personal,IMMIGRANT,True
reg_personal,AT_RISK_CALC_OVR,True
reg_personal,AT_RISK_LAST_CALC,True
reg_personal,PRIVATE_MILITARY,True
reg_personal,PRIVATE_COLLEGE,True
reg_personal,PRIVATE_COMPANY,True
reg_personal,PRIVATE_ORGANIZATIONS,True
reg_personal,PRIVATE_INDIVIDUAL,True
reg_personal,CHANGE_DATE_TIME,True
reg_personal,CHANGE_UID,True
reg_notes,DISTRICT,True
reg_notes,STUDENT_ID,True
reg_notes,NOTE_TYPE,True
reg_notes,ENTRY_DATE_TIME,True
reg_notes,ENTRY_UID,True
reg_notes,NOTE_TEXT,True
reg_notes,SENSITIVE,True
reg_notes,PRIVATE_FLAG,True
reg_notes,PUBLISH_TO_WEB,True
reg_notes,APPOINTMENT_ID,True
reg_notes,CHANGE_DATE_TIME,True
reg_notes,CHANGE_UID,True
reg_notes,STUDENT_ALERT_TYPE,True
reg_yrend_students,DISTRICT,True
reg_yrend_students,STUDENT_ID,True
reg_yrend_students,RUN_PROCESS,True
reg_yrend_students,SCHOOL_YEAR,True
reg_yrend_students,REG_ROLLOVER,True
reg_yrend_students,REG_CRITERION,True
reg_yrend_students,WAS_PREREG,True
reg_yrend_students,CHANGE_DATE_TIME,True
reg_yrend_students,CHANGE_UID,True
reg_room,DISTRICT,True
reg_room,BUILDING,True
reg_room,ROOM_ID,True
reg_room,DESCRIPTION,True
reg_room,ROOM_TYPE,True
reg_room,MAX_STUDENTS,True
reg_room,ROOM_AVAILABLE,True
reg_room,HANDICAPPED_ACCESS,True
reg_room,COMPUTERS_COUNT,True
reg_room,PHONE,True
reg_room,PHONE_EXTENSION,True
reg_room,COMMENTS,True
reg_room,GROUP_CODE,True
reg_room,REGULAR_YEAR,True
reg_room,SUMMER_SCHOOL,True
reg_room,STATE_CODE_EQUIV,True
reg_room,ROW_IDENTITY,True
reg_room,CHANGE_DATE_TIME,True
reg_room,CHANGE_UID,True
reg_mp_dates,DISTRICT,True
reg_mp_dates,BUILDING,True
reg_mp_dates,SCHOOL_YEAR,True
reg_mp_dates,TRACK,True
reg_mp_dates,MARKING_PERIOD,True
reg_mp_dates,START_DATE,True
reg_mp_dates,END_DATE,True
reg_mp_dates,ROW_IDENTITY,True
reg_mp_dates,CHANGE_DATE_TIME,True
reg_mp_dates,CHANGE_UID,True
reg_med_procedure,DISTRICT,True
reg_med_procedure,STUDENT_ID,True
reg_med_procedure,CODE,True
reg_med_procedure,PROCEDURE_DATE,True
reg_med_procedure,STATUS_CODE,True
reg_med_procedure,CHANGE_DATE_TIME,True
reg_med_procedure,CHANGE_UID,True
reg_med_alerts,DISTRICT,True
reg_med_alerts,STUDENT_ID,True
reg_med_alerts,MED_ALERT_CODE,True
reg_med_alerts,SEQUENCE_NUM,True
reg_med_alerts,MED_ALERT_COMMENT,True
reg_med_alerts,START_DATE,True
reg_med_alerts,END_DATE,True
reg_med_alerts,ROW_IDENTITY,True
reg_med_alerts,CHANGE_DATE_TIME,True
reg_med_alerts,CHANGE_UID,True
reg_map_stu_geocode,DISTRICT,True
reg_map_stu_geocode,STUDENT_ID,True
reg_map_stu_geocode,LATITUDE,True
reg_map_stu_geocode,LONGITUDE,True
reg_map_stu_geocode,CHANGE_DATE_TIME,True
reg_map_stu_geocode,CHANGE_UID,True
reg_next_year,DISTRICT,True
reg_next_year,STUDENT_ID,True
reg_next_year,BUILDING,True
reg_next_year,HOME_BUILDING,True
reg_next_year,BUILDING_OVERRIDE,True
reg_next_year,BUILDING_REASON,True
reg_next_year,GRADE,True
reg_next_year,COUNSELOR,True
reg_next_year,HOMEROOM_PRIMARY,True
reg_next_year,HOMEROOM_SECONDARY,True
reg_next_year,HOUSE_TEAM,True
reg_next_year,TRACK,True
reg_next_year,CHANGE_DATE_TIME,True
reg_next_year,CHANGE_UID,True
reg_locker,DISTRICT,True
reg_locker,BUILDING,True
reg_locker,LOCKER_ID,True
reg_locker,LOCKER_DESC,True
reg_locker,SERIAL_NUM,True
reg_locker,LOCATION,True
reg_locker,IS_LOCKED,True
reg_locker,MAX_ASSIGNED,True
reg_locker,HOMEROOM,True
reg_locker,GRADE,True
reg_locker,GENDER,True
reg_locker,HOUSE_TEAM,True
reg_locker,IN_SERVICE,True
reg_locker,CURRENT_COMBO,True
reg_locker,CHANGE_DATE_TIME,True
reg_locker,CHANGE_UID,True
reg_user_building,DISTRICT,True
reg_user_building,BUILDING,True
reg_user_building,SCREEN_NUMBER,True
reg_user_building,FIELD_NUMBER,True
reg_user_building,LIST_SEQUENCE,True
reg_user_building,FIELD_VALUE,True
reg_user_building,CHANGE_DATE_TIME,True
reg_user_building,CHANGE_UID,True
reg_hold_rc_status,DISTRICT,True
reg_hold_rc_status,STUDENT_ID,True
reg_hold_rc_status,CODE,True
reg_hold_rc_status,FREE_TEXT,True
reg_hold_rc_status,CALCULATED,True
reg_hold_rc_status,CHANGE_DATE_TIME,True
reg_hold_rc_status,CHANGE_UID,True
reg_hispanic,DISTRICT,True
reg_hispanic,STUDENT_ID,True
reg_hispanic,HISPANIC_CODE,True
reg_hispanic,CHANGE_DATE_TIME,True
reg_hispanic,CHANGE_UID,True
schd_ms_mark_types,DISTRICT,True
schd_ms_mark_types,SECTION_KEY,True
schd_ms_mark_types,COURSE_SESSION,True
schd_ms_mark_types,MARK_TYPE,True
schd_ms_mark_types,CHANGE_DATE_TIME,True
schd_ms_mark_types,CHANGE_UID,True
sec_user_resource,DISTRICT,True
sec_user_resource,LOGIN_ID,True
sec_user_resource,ROLE_ID,True
sec_user_resource,PACKAGE,True
sec_user_resource,SUBPACKAGE,True
sec_user_resource,FEATURE,True
sec_user_resource,BUILDING,True
sec_user_resource,ACCESS_TYPE,True
sec_user_resource,CHANGE_DATE_TIME,True
sec_user_resource,CHANGE_UID,True
sec_user_building,DISTRICT,True
sec_user_building,LOGIN_ID,True
sec_user_building,BUILDING,True
sec_user_building,CHANGE_DATE_TIME,True
sec_user_building,CHANGE_UID,True
reg_immunization,DISTRICT,True
reg_immunization,STUDENT_ID,True
reg_immunization,CODE,True
reg_immunization,STATUS_CODE,True
reg_immunization,CHANGE_DATE_TIME,True
reg_immunization,CHANGE_UID,True
schdtb_sif_credit_type,DISTRICT,True
schdtb_sif_credit_type,CODE,True
schdtb_sif_credit_type,DESCRIPTION,True
schdtb_sif_credit_type,ACTIVE,True
schdtb_sif_credit_type,CHANGE_DATE_TIME,True
schdtb_sif_credit_type,CHANGE_UID,True
schdtb_credit_basis,DISTRICT,True
schdtb_credit_basis,CODE,True
schdtb_credit_basis,DESCRIPTION,True
schdtb_credit_basis,ACTIVE,True
schdtb_credit_basis,PESC_CODE,True
schdtb_credit_basis,CHANGE_DATE_TIME,True
schdtb_credit_basis,CHANGE_UID,True
schdtb_course_nces_code,DISTRICT,True
schdtb_course_nces_code,CODE,True
schdtb_course_nces_code,DESCRIPTION,True
schdtb_course_nces_code,STATE_CODE_EQUIV,True
schdtb_course_nces_code,ACTIVE,True
schdtb_course_nces_code,CHANGE_DATE_TIME,True
schdtb_course_nces_code,CHANGE_UID,True
reg_locker_combo,DISTRICT,True
reg_locker_combo,BUILDING,True
reg_locker_combo,LOCKER_ID,True
reg_locker_combo,COMBO_SEQUENCE,True
reg_locker_combo,COMBINATION,True
reg_locker_combo,CHANGE_DATE_TIME,True
reg_locker_combo,CHANGE_UID,True
Schd_unscanned,DISTRICT,True
Schd_unscanned,SCHOOL_YEAR,True
Schd_unscanned,SUMMER_SCHOOL,True
Schd_unscanned,BUILDING,True
Schd_unscanned,SCAN_GUID,True
Schd_unscanned,STUDENT_ID,True
Schd_unscanned,GRADE,True
Schd_unscanned,POSTED,True
Schd_unscanned,PAGE_NUMBER,True
Schd_unscanned,CHANGE_DATE_TIME,True
Schd_unscanned,CHANGE_UID,True
schd_timetable_hdr,DISTRICT,True
schd_timetable_hdr,SCHOOL_YEAR,True
schd_timetable_hdr,SUMMER_SCHOOL,True
schd_timetable_hdr,BUILDING,True
schd_timetable_hdr,BELL_SCHD,True
schd_timetable_hdr,HOUSE_TEAM,True
schd_timetable_hdr,CHANGE_DATE_TIME,True
schd_timetable_hdr,CHANGE_UID,True
schd_stu_status,DISTRICT,True
schd_stu_status,SCHOOL_YEAR,True
schd_stu_status,BUILDING,True
schd_stu_status,STUDENT_ID,True
schd_stu_status,SCHD_INTERVAL,True
schd_stu_status,SCHEDULE_STATUS,True
schd_stu_status,REQUEST_STATUS,True
schd_stu_status,NUMBER_SINGLETONS,True
schd_stu_status,NUMBER_DOUBLETONS,True
schd_stu_status,NUMBER_MULTISESS,True
schd_stu_status,NUMBER_BLOCKS,True
schd_stu_status,CHANGE_DATE_TIME,True
schd_stu_status,CHANGE_UID,True
reg_stu_contact,DISTRICT,True
reg_stu_contact,STUDENT_ID,True
reg_stu_contact,CONTACT_ID,True
reg_stu_contact,CONTACT_TYPE,True
reg_stu_contact,CONTACT_PRIORITY,True
reg_stu_contact,RELATION_CODE,True
reg_stu_contact,LIVING_WITH,True
reg_stu_contact,WEB_ACCESS,True
reg_stu_contact,COMMENTS,True
reg_stu_contact,TRANSPORT_TO,True
reg_stu_contact,TRANSPORT_FROM,True
reg_stu_contact,MAIL_ATT,True
reg_stu_contact,MAIL_DISC,True
reg_stu_contact,MAIL_FEES,True
reg_stu_contact,MAIL_IPR,True
reg_stu_contact,MAIL_MED,True
reg_stu_contact,MAIL_RC,True
reg_stu_contact,MAIL_REG,True
reg_stu_contact,MAIL_SCHD,True
reg_stu_contact,MAIL_SSP,True
reg_stu_contact,LEGAL_GUARD,True
reg_stu_contact,CUST_GUARD,True
reg_stu_contact,UPD_STU_EO_INFO,True
reg_stu_contact,ROW_IDENTITY,True
reg_stu_contact,CHANGE_DATE_TIME,True
reg_stu_contact,CHANGE_UID,True
schdtb_sif_instructional_level,DISTRICT,True
schdtb_sif_instructional_level,CODE,True
schdtb_sif_instructional_level,DESCRIPTION,True
schdtb_sif_instructional_level,ACTIVE,True
schdtb_sif_instructional_level,STATE_CODE_EQUIV,True
schdtb_sif_instructional_level,CHANGE_DATE_TIME,True
schdtb_sif_instructional_level,CHANGE_UID,True
schd_stu_req,DISTRICT,True
schd_stu_req,SCHOOL_YEAR,True
schd_stu_req,BUILDING,True
schd_stu_req,STUDENT_ID,True
schd_stu_req,SCHD_INTERVAL,True
schd_stu_req,COURSE,True
schd_stu_req,COURSE_SECTION,True
schd_stu_req,TEACHER_OVERLOAD,True
schd_stu_req,REQUEST_TYPE,True
schd_stu_req,IS_LOCKED,True
schd_stu_req,ALT_TO_REQUEST,True
schd_stu_req,ALTERNATE_SEQUENCE,True
schd_stu_req,RETAKE,True
schd_stu_req,CHANGE_DATE_TIME,True
schd_stu_req,CHANGE_UID,True
SCHD_STU_RECOMMEND,DISTRICT,True
SCHD_STU_RECOMMEND,SCHOOL_YEAR,True
SCHD_STU_RECOMMEND,BUILDING,True
SCHD_STU_RECOMMEND,STUDENT_ID,True
SCHD_STU_RECOMMEND,COURSE,True
SCHD_STU_RECOMMEND,STAFF_ID,True
SCHD_STU_RECOMMEND,SECTION_KEY,True
SCHD_STU_RECOMMEND,PRIORITY,True
SCHD_STU_RECOMMEND,ENROLL_COURSE,True
SCHD_STU_RECOMMEND,CHANGE_DATE_TIME,True
SCHD_STU_RECOMMEND,CHANGE_UID,True
schd_stu_prereqover,DISTRICT,True
schd_stu_prereqover,SCHOOL_YEAR,True
schd_stu_prereqover,BUILDING,True
schd_stu_prereqover,STUDENT_ID,True
schd_stu_prereqover,COURSE,True
schd_stu_prereqover,CHANGE_DATE_TIME,True
schd_stu_prereqover,CHANGE_UID,True
schd_stu_crs_dates,DISTRICT,True
schd_stu_crs_dates,STUDENT_ID,True
schd_stu_crs_dates,SECTION_KEY,True
schd_stu_crs_dates,MODELED,True
schd_stu_crs_dates,DATE_RANGE_KEY,True
schd_stu_crs_dates,DATE_ADDED,True
schd_stu_crs_dates,DATE_DROPPED,True
schd_stu_crs_dates,RESOLVED_CONFLICT,True
schd_stu_crs_dates,MR_UNGRADED,True
schd_stu_crs_dates,MR_FIRST_MP,True
schd_stu_crs_dates,MR_LAST_MP,True
schd_stu_crs_dates,MR_LAST_MARK_BY,True
schd_stu_crs_dates,FROM_SECTION_KEY,True
schd_stu_crs_dates,FROM_RANGE_KEY,True
schd_stu_crs_dates,TO_SECTION_KEY,True
schd_stu_crs_dates,TO_RANGE_KEY,True
schd_stu_crs_dates,ROW_IDENTITY,True
schd_stu_crs_dates,CHANGE_DATE_TIME,True
schd_stu_crs_dates,CHANGE_UID,True
schd_stu_course,DISTRICT,True
schd_stu_course,STUDENT_ID,True
schd_stu_course,SECTION_KEY,True
schd_stu_course,MODELED,True
schd_stu_course,COURSE_STATUS,True
schd_stu_course,MODEL_VAL_TYPE,True
schd_stu_course,RETAKE,True
schd_stu_course,CHANGE_DATE_TIME,True
schd_stu_course,CHANGE_UID,True
schd_stu_conf_cyc,DISTRICT,True
schd_stu_conf_cyc,STUDENT_ID,True
schd_stu_conf_cyc,SECTION_KEY,True
schd_stu_conf_cyc,MODELED,True
schd_stu_conf_cyc,DATE_RANGE_KEY,True
schd_stu_conf_cyc,COURSE_SESSION,True
schd_stu_conf_cyc,CYCLE_CODE,True
schd_stu_conf_cyc,CHANGE_DATE_TIME,True
schd_stu_conf_cyc,CHANGE_UID,True
reg_mp_weeks,DISTRICT,True
reg_mp_weeks,BUILDING,True
reg_mp_weeks,SCHOOL_YEAR,True
reg_mp_weeks,MARKING_PERIOD,True
reg_mp_weeks,MP_ORDER,True
reg_mp_weeks,DURATION_TYPE,True
reg_mp_weeks,DESCRIPTION,True
reg_mp_weeks,START_WEEK_NUMBER,True
reg_mp_weeks,END_WEEK_NUMBER,True
reg_mp_weeks,SCHD_INTERVAL,True
reg_mp_weeks,TERM,True
reg_mp_weeks,RC_RUN,True
reg_mp_weeks,STATE_CODE_EQUIV,True
reg_mp_weeks,CHANGE_DATE_TIME,True
reg_mp_weeks,CHANGE_UID,True
Schd_scan_request,DISTRICT,True
Schd_scan_request,SCHOOL_YEAR,True
Schd_scan_request,SUMMER_SCHOOL,True
Schd_scan_request,BUILDING,True
Schd_scan_request,SCAN_GUID,True
Schd_scan_request,COURSE,True
Schd_scan_request,GRADE,True
Schd_scan_request,SEQUENCE_NUMBER,True
Schd_scan_request,PAGE_NUMBER,True
Schd_scan_request,LINE_NUMBER,True
Schd_scan_request,CHANGE_DATE_TIME,True
Schd_scan_request,CHANGE_UID,True
Schd_run,DISTRICT,True
Schd_run,BUILDING,True
Schd_run,SCHOOL_YEAR,True
Schd_run,RUN_KEY,True
Schd_run,RUN_LABEL,True
Schd_run,RUN_STATUS,True
Schd_run,RUN_DATE_TIME,True
Schd_run,CHANGE_DATE_TIME,True
Schd_run,CHANGE_UID,True
schd_course_grade,DISTRICT,True
schd_course_grade,BUILDING,True
schd_course_grade,COURSE,True
schd_course_grade,RESTRICT_GRADE,True
schd_course_grade,CHANGE_DATE_TIME,True
schd_course_grade,CHANGE_UID,True
schd_course_gpa,DISTRICT,True
schd_course_gpa,BUILDING,True
schd_course_gpa,COURSE,True
schd_course_gpa,GPA_TYPE,True
schd_course_gpa,GPA_LEVEL,True
schd_course_gpa,CHANGE_DATE_TIME,True
schd_course_gpa,CHANGE_UID,True
reg_programs,DISTRICT,True
reg_programs,PROGRAM_ID,True
reg_programs,FIELD_NUMBER,True
reg_programs,STUDENT_ID,True
reg_programs,START_DATE,True
reg_programs,SUMMER_SCHOOL,True
reg_programs,ENTRY_REASON,True
reg_programs,PROGRAM_VALUE,True
reg_programs,END_DATE,True
reg_programs,WITHDRAWAL_REASON,True
reg_programs,PROGRAM_OVERRIDE,True
reg_programs,CHANGE_DATE_TIME,True
reg_programs,CHANGE_UID,True
schd_cnflct_matrix,DISTRICT,True
schd_cnflct_matrix,BUILDING,True
schd_cnflct_matrix,MATRIX_TYPE,True
schd_cnflct_matrix,SCHD_INTERVAL,True
schd_cnflct_matrix,COURSE1,True
schd_cnflct_matrix,COURSE2,True
schd_cnflct_matrix,NUMBER_CONFLICTS,True
schd_cnflct_matrix,CHANGE_DATE_TIME,True
schd_cnflct_matrix,CHANGE_UID,True
schd_cfg_interval,DISTRICT,True
schd_cfg_interval,SCHOOL_YEAR,True
schd_cfg_interval,BUILDING,True
schd_cfg_interval,SCHD_INTERVAL,True
schd_cfg_interval,DESCRIPTION,True
schd_cfg_interval,CHANGE_DATE_TIME,True
schd_cfg_interval,CHANGE_UID,True
schd_stu_conf_mp,DISTRICT,True
schd_stu_conf_mp,STUDENT_ID,True
schd_stu_conf_mp,SECTION_KEY,True
schd_stu_conf_mp,MODELED,True
schd_stu_conf_mp,DATE_RANGE_KEY,True
schd_stu_conf_mp,COURSE_SESSION,True
schd_stu_conf_mp,MARKING_PERIOD,True
schd_stu_conf_mp,CHANGE_DATE_TIME,True
schd_stu_conf_mp,CHANGE_UID,True
schd_cfg_disc_off,DISTRICT,True
schd_cfg_disc_off,SCHOOL_YEAR,True
schd_cfg_disc_off,SUMMER_SCHOOL,True
schd_cfg_disc_off,BUILDING,True
schd_cfg_disc_off,OFFENSE_CODE,True
schd_cfg_disc_off,CHANGE_DATE_TIME,True
schd_cfg_disc_off,CHANGE_UID,True
schd_cfg,DISTRICT,True
schd_cfg,SCHOOL_YEAR,True
schd_cfg,SUMMER_SCHOOL,True
schd_cfg,BUILDING,True
schd_cfg,MAXIMUM_TIMESLOTS,True
schd_cfg,DEF_ADD_DATE_CODE,True
schd_cfg,DEFAULT_ADD_DATE,True
schd_cfg,CURRENT_INTERVAL,True
schd_cfg,DATE_CHECK,True
schd_cfg,IN_PROGRESS,True
schd_cfg,DISPLAY_MSE_BLDG,True
schd_cfg,OUTPUT_FILE_PATH,True
schd_cfg,MAX_SCAN_GUID,True
schd_cfg,TRAIL_MARKS,True
schd_cfg,MULTIPLE_BELL_SCHD,True
schd_cfg,DEFAULT_DURATION,True
schd_cfg,DEFAULT_MAX_SEATS,True
schd_cfg,DEFAULT_MARKS_ARE,True
schd_cfg,TEA_SCHD_STU_SUMM,True
schd_cfg,SUB_SCHD_STU_SUMM,True
schd_cfg,TEA_SCHD_STU_REC,True
schd_cfg,SUB_SCHD_STU_REC,True
schd_cfg,TAC_LIMIT_REC_NUM,True
schd_cfg,TAC_LIMIT_REC_DEPT,True
schd_cfg,PREREQ_CRS_BLDG,True
schd_cfg,PREREQ_CHK_REQ,True
schd_cfg,PREREQ_CHK_SCHD,True
schd_cfg,PREREQ_CRS_TOOK,True
schd_cfg,DEFAULT_NOMARKS_FIRST_DAYS,True
schd_cfg,DEFAULT_UNGRADED_LAST_DAYS,True
schd_cfg,DEFAULT_FIRST_NEXT,True
schd_cfg,DEFAULT_LAST_PREVIOUS,True
schd_cfg,LAST_ISSUED_BY,True
schd_cfg,USE_UNGRADED,True
schd_cfg,USE_FOCUS,True
schd_cfg,MAX_FOCUS_PERCENT,True
schd_cfg,REQ_CRS_STAFF_DATE_ENTRY,True
schd_cfg,CHANGE_DATE_TIME,True
schd_cfg,CHANGE_UID,True
schd_course_block,DISTRICT,True
schd_course_block,BUILDING,True
schd_course_block,BLOCK_COURSE,True
schd_course_block,BLOCKETTE_COURSE,True
schd_course_block,SAME_SECTION,True
schd_course_block,MANDATORY,True
schd_course_block,CHANGE_DATE_TIME,True
schd_course_block,CHANGE_UID,True
schd_course,DISTRICT,True
schd_course,BUILDING,True
schd_course,COURSE,True
schd_course,BUILDING_TYPE,True
schd_course,DIST_LEVEL,True
schd_course,DESCRIPTION,True
schd_course,LONG_DESCRIPTION,True
schd_course,DEPARTMENT,True
schd_course,HOUSE_TEAM,True
schd_course,STUDY_HALL,True
schd_course,REGULAR_SCHOOL,True
schd_course,SUMMER_SCHOOL,True
schd_course,VOTEC,True
schd_course,ACTIVE_STATUS,True
schd_course,SIMPLE_TALLY,True
schd_course,CONFLICT_MATRIX,True
schd_course,GENDER_RESTRICTION,True
schd_course,ALTERNATE_COURSE,True
schd_course,CREDIT,True
schd_course,FEE,True
schd_course,PRIORITY,True
schd_course,SEMESTER_WEIGHT,True
schd_course,BLOCK_TYPE,True
schd_course,SCAN_COURSE,True
schd_course,TAKE_ATTENDANCE,True
schd_course,RECEIVE_MARK,True
schd_course,COURSE_LEVEL,True
schd_course,SUBJ_AREA_CREDIT,True
schd_course,REC_NEXT_COURSE,True
schd_course,REQUEST_FROM_HAC,True
schd_course,SAME_TEACHER,True
schd_course,INCLD_PASSING_TIME,True
schd_course,COURSE_CREDIT_BASIS,True
schd_course,NCES_CODE,True
schd_course,INCLD_CURRICULUM_CONNECTOR,True
schd_course,MIN_GRADE,True
schd_course,MAX_GRADE,True
schd_course,CLASSIFY_STUS_MAX,True
schd_course,CLASSIFY_NUM_OR_PER,True
schd_course,SIF_CREDIT_TYPE,True
schd_course,SIF_INSTRUCTIONAL_LEVEL,True
schd_course,ROW_IDENTITY,True
schd_course,CHANGE_DATE_TIME,True
schd_course,CHANGE_UID,True
regtb_travel,DISTRICT,True
regtb_travel,CODE,True
regtb_travel,DESCRIPTION,True
regtb_travel,ACTIVE,True
regtb_travel,SIF_CODE,True
regtb_travel,SIF2_CODE,True
regtb_travel,CHANGE_DATE_TIME,True
regtb_travel,CHANGE_UID,True
regtb_title,DISTRICT,True
regtb_title,CODE,True
regtb_title,DESCRIPTION,True
regtb_title,ACTIVE,True
regtb_title,CHANGE_DATE_TIME,True
regtb_title,CHANGE_UID,True
regtb_state_bldg,DISTRICT,True
regtb_state_bldg,CODE,True
regtb_state_bldg,DESCRIPTION,True
regtb_state_bldg,STATE_CODE_EQUIV,True
regtb_state_bldg,ACTIVE,True
regtb_state_bldg,CHANGE_DATE_TIME,True
regtb_state_bldg,CHANGE_UID,True
regtb_state_bldg,LOCAL_BUILDING,True
regtb_st_type,DISTRICT,True
regtb_st_type,CODE,True
regtb_st_type,DESCRIPTION,True
regtb_st_type,ACTIVE,True
regtb_st_type,CHANGE_DATE_TIME,True
regtb_st_type,CHANGE_UID,True
regtb_st_suffix,DISTRICT,True
regtb_st_suffix,CODE,True
regtb_st_suffix,DESCRIPTION,True
regtb_st_suffix,ACTIVE,True
regtb_st_suffix,CHANGE_DATE_TIME,True
regtb_st_suffix,CHANGE_UID,True
regtb_st_prefix,DISTRICT,True
regtb_st_prefix,CODE,True
regtb_st_prefix,DESCRIPTION,True
regtb_st_prefix,ACTIVE,True
regtb_st_prefix,CHANGE_DATE_TIME,True
regtb_st_prefix,CHANGE_UID,True
regtb_withdrawal,DISTRICT,True
regtb_withdrawal,CODE,True
regtb_withdrawal,DESCRIPTION,True
regtb_withdrawal,STATE_CODE_EQUIV,True
regtb_withdrawal,ACTIVE,True
regtb_withdrawal,SIF_CODE,True
regtb_withdrawal,SIF2_CODE,True
regtb_withdrawal,DROPOUT_CODE,True
regtb_withdrawal,STUDENT_EXIT,True
regtb_withdrawal,CHANGE_DATE_TIME,True
regtb_withdrawal,CHANGE_UID,True
regtb_school_year,DISTRICT,True
regtb_school_year,SCHOOL_YEAR,True
regtb_school_year,DISPLAY_YEAR,True
regtb_school_year,ACTIVE,True
regtb_school_year,CHANGE_DATE_TIME,True
regtb_school_year,CHANGE_UID,True
regtb_room_type,DISTRICT,True
regtb_room_type,CODE,True
regtb_room_type,DESCRIPTION,True
regtb_room_type,STATE_CODE_EQUIV,True
regtb_room_type,ACTIVE,True
regtb_room_type,CHANGE_DATE_TIME,True
regtb_room_type,CHANGE_UID,True
regtb_req_group,DISTRICT,True
regtb_req_group,CODE,True
regtb_req_group,DESCRIPTION,True
regtb_req_group,IMAGE_FILE_NAME,True
regtb_req_group,GRAD_OR_SUPP,True
regtb_req_group,STATE_CODE_EQUIV,True
regtb_req_group,ROW_IDENTITY,True
regtb_req_group,CHANGE_DATE_TIME,True
regtb_req_group,CHANGE_UID,True
regtb_relation_pesc_code,DISTRICT,True
regtb_relation_pesc_code,CODE,True
regtb_relation_pesc_code,DESCRIPTION,True
regtb_relation_pesc_code,CHANGE_DATE_TIME,True
regtb_relation_pesc_code,CHANGE_UID,True
regtb_relation,DISTRICT,True
regtb_relation,CODE,True
regtb_relation,DESCRIPTION,True
regtb_relation,STATE_CODE_EQUIV,True
regtb_relation,ACTIVE,True
regtb_relation,SIF_CODE,True
regtb_relation,SIF2_CODE,True
regtb_relation,PESC_CODE,True
regtb_relation,CHANGE_DATE_TIME,True
regtb_relation,CHANGE_UID,True
schd_allocation,DISTRICT,True
schd_allocation,BUILDING,True
schd_allocation,GROUP_TYPE,True
schd_allocation,GROUP_CODE,True
schd_allocation,PERIOD,True
schd_allocation,MARKING_PERIOD,True
schd_allocation,CYCLE,True
schd_allocation,ALLOCATIONS,True
schd_allocation,CHANGE_DATE_TIME,True
schd_allocation,CHANGE_UID,True
schd_stu_req_mp,DISTRICT,True
schd_stu_req_mp,SCHOOL_YEAR,True
schd_stu_req_mp,BUILDING,True
schd_stu_req_mp,STUDENT_ID,True
schd_stu_req_mp,SCHD_INTERVAL,True
schd_stu_req_mp,COURSE,True
schd_stu_req_mp,MARKING_PERIOD,True
schd_stu_req_mp,CHANGE_DATE_TIME,True
schd_stu_req_mp,CHANGE_UID,True
regtb_prog_with,DISTRICT,True
regtb_prog_with,CODE,True
regtb_prog_with,DESCRIPTION,True
regtb_prog_with,STATE_CODE_EQUIV,True
regtb_prog_with,ACTIVE,True
regtb_prog_with,CHANGE_DATE_TIME,True
regtb_prog_with,CHANGE_UID,True
regtb_residency,DISTRICT,True
regtb_residency,CODE,True
regtb_residency,DESCRIPTION,True
regtb_residency,STATE_CODE_EQUIV,True
regtb_residency,ACTIVE,True
regtb_residency,SIF_CODE,True
regtb_residency,SIF2_CODE,True
regtb_residency,CHANGE_DATE_TIME,True
regtb_residency,CHANGE_UID,True
regtb_phone,DISTRICT,True
regtb_phone,CODE,True
regtb_phone,DESCRIPTION,True
regtb_phone,ACTIVE,True
regtb_phone,STATE_CODE_EQUIV,True
regtb_phone,SIF_CODE,True
regtb_phone,SIF2_CODE,True
regtb_phone,CHANGE_DATE_TIME,True
regtb_phone,CHANGE_UID,True
regtb_pesc_code,DISTRICT,True
regtb_pesc_code,CODE,True
regtb_pesc_code,DESCRIPTION,True
regtb_pesc_code,STATE,True
regtb_pesc_code,STATE_CODE_EQUIV,True
regtb_pesc_code,ACTIVE,True
regtb_pesc_code,CHANGE_DATE_TIME,True
regtb_pesc_code,CHANGE_UID,True
regtb_note_type,DISTRICT,True
regtb_note_type,CODE,True
regtb_note_type,DESCRIPTION,True
regtb_note_type,SENSITIVE,True
regtb_note_type,ACTIVE,True
regtb_note_type,CHANGE_DATE_TIME,True
regtb_note_type,CHANGE_UID,True
regtb_medic_alert,DISTRICT,True
regtb_medic_alert,CODE,True
regtb_medic_alert,DESCRIPTION,True
regtb_medic_alert,STATE_CODE_EQUIV,True
regtb_medic_alert,SENSITIVE,True
regtb_medic_alert,ACTIVE,True
regtb_medic_alert,ROW_IDENTITY,True
regtb_medic_alert,CHANGE_DATE_TIME,True
regtb_medic_alert,CHANGE_UID,True
regtb_med_proc,DISTRICT,True
regtb_med_proc,CODE,True
regtb_med_proc,DESCRIPTION,True
regtb_med_proc,STATE_CODE_EQUIV,True
regtb_med_proc,ACTIVE,True
regtb_med_proc,CHANGE_DATE_TIME,True
regtb_med_proc,CHANGE_UID,True
regtb_proc_status,DISTRICT,True
regtb_proc_status,CODE,True
regtb_proc_status,DESCRIPTION,True
regtb_proc_status,ACTIVE,True
regtb_proc_status,CHANGE_DATE_TIME,True
regtb_proc_status,CHANGE_UID,True
regtb_language,DISTRICT,True
regtb_language,CODE,True
regtb_language,DESCRIPTION,True
regtb_language,STATE_CODE_EQUIV,True
regtb_language,ACTIVE,True
regtb_language,ALTERNATE_LANGUAGE,True
regtb_language,HAC_LANGUAGE,True
regtb_language,SIF_CODE,True
regtb_language,SIF2_CODE,True
regtb_language,CHANGE_DATE_TIME,True
regtb_language,CHANGE_UID,True
regtb_language,USE_IN_HOME,True
regtb_language,USE_IN_NATIVE,True
regtb_immuns,DISTRICT,True
regtb_immuns,CODE,True
regtb_immuns,DESCRIPTION,True
regtb_immuns,STATE_CODE_EQUIV,True
regtb_immuns,ACTIVE,True
regtb_immuns,CHANGE_DATE_TIME,True
regtb_immuns,CHANGE_UID,True
regtb_immun_status,DISTRICT,True
regtb_immun_status,CODE,True
regtb_immun_status,DESCRIPTION,True
regtb_immun_status,STATE_CODE_EQUIV,True
regtb_immun_status,ACTIVE,True
regtb_immun_status,CHANGE_DATE_TIME,True
regtb_immun_status,CHANGE_UID,True
regtb_iep_status,DISTRICT,True
regtb_iep_status,CODE,True
regtb_iep_status,DESCRIPTION,True
regtb_iep_status,STATE_CODE_EQUIV,True
regtb_iep_status,ACTIVE,True
regtb_iep_status,CHANGE_DATE_TIME,True
regtb_iep_status,CHANGE_UID,True
regtb_house_team,DISTRICT,True
regtb_house_team,CODE,True
regtb_house_team,DESCRIPTION,True
regtb_house_team,STATE_CODE_EQUIV,True
regtb_house_team,ACTIVE,True
regtb_house_team,CHANGE_DATE_TIME,True
regtb_house_team,CHANGE_UID,True
regtb_prog_entry,DISTRICT,True
regtb_prog_entry,CODE,True
regtb_prog_entry,DESCRIPTION,True
regtb_prog_entry,STATE_CODE_EQUIV,True
regtb_prog_entry,ACTIVE,True
regtb_prog_entry,CHANGE_DATE_TIME,True
regtb_prog_entry,CHANGE_UID,True
regtb_homeless,DISTRICT,True
regtb_homeless,CODE,True
regtb_homeless,DESCRIPTION,True
regtb_homeless,STATE_CODE_EQUIV,True
regtb_homeless,SIF2_CODE,True
regtb_homeless,ACTIVE,True
regtb_homeless,CHANGE_DATE_TIME,True
regtb_homeless,CHANGE_UID,True
schd_cfg_houseteam,DISTRICT,True
schd_cfg_houseteam,SCHOOL_YEAR,True
schd_cfg_houseteam,SUMMER_SCHOOL,True
schd_cfg_houseteam,BUILDING,True
schd_cfg_houseteam,HOUSE_TEAM,True
schd_cfg_houseteam,CHANGE_DATE_TIME,True
schd_cfg_houseteam,CHANGE_UID,True
regtb_home_bldg_type,DISTRICT,True
regtb_home_bldg_type,CODE,True
regtb_home_bldg_type,DESCRIPTION,True
regtb_home_bldg_type,ACTIVE,True
regtb_home_bldg_type,CHANGE_DATE_TIME,True
regtb_home_bldg_type,CHANGE_UID,True
regtb_hold_rc_code,DISTRICT,True
regtb_hold_rc_code,CODE,True
regtb_hold_rc_code,DESCRIPTION,True
regtb_hold_rc_code,ACTIVE,True
regtb_hold_rc_code,CHANGE_DATE_TIME,True
regtb_hold_rc_code,CHANGE_UID,True
regtb_hispanic,DISTRICT,True
regtb_hispanic,CODE,True
regtb_hispanic,DESCRIPTION,True
regtb_hispanic,STATE_CODE_EQUIV,True
regtb_hispanic,ACTIVE,True
regtb_hispanic,CHANGE_DATE_TIME,True
regtb_hispanic,CHANGE_UID,True
schd_stu_user,DISTRICT,True
schd_stu_user,SECTION_KEY,True
schd_stu_user,DATE_RANGE_KEY,True
schd_stu_user,STUDENT_ID,True
schd_stu_user,SCREEN_NUMBER,True
schd_stu_user,FIELD_NUMBER,True
schd_stu_user,FIELD_VALUE,True
schd_stu_user,CHANGE_DATE_TIME,True
schd_stu_user,CHANGE_UID,True
regtb_generation,DISTRICT,True
regtb_generation,CODE,True
regtb_generation,STATE_CODE_EQUIV,True
regtb_generation,ACTIVE,True
regtb_generation,CHANGE_DATE_TIME,True
regtb_generation,CHANGE_UID,True
reg_grade,DISTRICT,True
reg_grade,CODE,True
reg_grade,DESCRIPTION,True
reg_grade,NEXT_GRADE,True
reg_grade,YEARS_TILL_GRAD,True
reg_grade,STATE_CODE_EQUIV,True
reg_grade,FEDERAL_CODE_EQUIV,True
reg_grade,ACTIVE,True
reg_grade,SIF_CODE,True
reg_grade,SIF2_CODE,True
reg_grade,PESC_CODE,True
reg_grade,GRADE_ORDER,True
reg_grade,GRAD_PLAN_LABEL,True
reg_grade,CHANGE_DATE_TIME,True
reg_grade,CHANGE_UID,True
reg_grade,CEDS_CODE,True
reg_geo_zone_hdr,DISTRICT,True
reg_geo_zone_hdr,SCHOOL_YEAR,True
reg_geo_zone_hdr,ZONE_NUMBER,True
reg_geo_zone_hdr,DESCRIPTION,True
reg_geo_zone_hdr,CHANGE_DATE_TIME,True
reg_geo_zone_hdr,CHANGE_UID,True
reg_geo_zone_det,DISTRICT,True
reg_geo_zone_det,SCHOOL_YEAR,True
reg_geo_zone_det,ZONE_NUMBER,True
reg_geo_zone_det,BUILDING,True
reg_geo_zone_det,HOME_BUILDING_TYPE,True
reg_geo_zone_det,GRADE,True
reg_geo_zone_det,HOME_BUILDING,True
reg_geo_zone_det,CHANGE_DATE_TIME,True
reg_geo_zone_det,CHANGE_UID,True
reg_geo_stu_plan,DISTRICT,True
reg_geo_stu_plan,STUDENT_ID,True
reg_geo_stu_plan,PLAN_AREA_NUMBER,True
reg_geo_stu_plan,BUILDING,True
reg_geo_stu_plan,NEXT_BUILDING,True
reg_geo_stu_plan,CHANGE_DATE_TIME,True
reg_geo_stu_plan,CHANGE_UID,True
regtb_grad_plans,DISTRICT,True
regtb_grad_plans,CODE,True
regtb_grad_plans,DESCRIPTION,True
regtb_grad_plans,STATE_CODE_EQUIV,True
regtb_grad_plans,EXPECTED,True
regtb_grad_plans,ACTUAL,True
regtb_grad_plans,ACTIVE,True
regtb_grad_plans,CHANGE_DATE_TIME,True
regtb_grad_plans,CHANGE_UID,True
regtb_qualify,DISTRICT,True
regtb_qualify,CODE,True
regtb_qualify,DESCRIPTION,True
regtb_qualify,ACTIVE,True
regtb_qualify,CHANGE_DATE_TIME,True
regtb_qualify,CHANGE_UID,True
reg_exclude_rank,DISTRICT,True
reg_exclude_rank,STUDENT_ID,True
reg_exclude_rank,RANK_TYPE,True
reg_exclude_rank,INCLUDE_CLASS_SIZE,True
reg_exclude_rank,CHANGE_DATE_TIME,True
reg_exclude_rank,CHANGE_UID,True
reg_exclude_honor,DISTRICT,True
reg_exclude_honor,STUDENT_ID,True
reg_exclude_honor,HONOR_TYPE,True
reg_exclude_honor,CHANGE_DATE_TIME,True
reg_exclude_honor,CHANGE_UID,True
regtb_hospital,DISTRICT,True
regtb_hospital,CODE,True
regtb_hospital,DESCRIPTION,True
regtb_hospital,ACTIVE,True
regtb_hospital,CHANGE_DATE_TIME,True
regtb_hospital,CHANGE_UID,True
reg_ethnicity,DISTRICT,True
reg_ethnicity,STUDENT_ID,True
reg_ethnicity,ETHNIC_CODE,True
reg_ethnicity,ETHNICITY_ORDER,True
reg_ethnicity,PERCENTAGE,True
reg_ethnicity,CHANGE_DATE_TIME,True
reg_ethnicity,CHANGE_UID,True
reg_emergency,DISTRICT,True
reg_emergency,STUDENT_ID,True
reg_emergency,DOCTOR_NAME,True
reg_emergency,DOCTOR_PHONE,True
reg_emergency,DOCTOR_EXTENSION,True
reg_emergency,HOSPITAL_CODE,True
reg_emergency,INSURANCE_COMPANY,True
reg_emergency,INSURANCE_ID,True
reg_emergency,INSURANCE_GROUP,True
reg_emergency,INSURANCE_GRP_NAME,True
reg_emergency,INSURANCE_SUBSCR,True
reg_emergency,CHANGE_DATE_TIME,True
reg_emergency,CHANGE_UID,True
reg_emergency,DENTIST,True
reg_emergency,DENTIST_PHONE,True
reg_emergency,DENTIST_EXT,True
reg_duration,DISTRICT,True
reg_duration,SCHOOL_YEAR,True
reg_duration,BUILDING,True
reg_duration,CODE,True
reg_duration,DESCRIPTION,True
reg_duration,SUMMER_SCHOOL,True
reg_duration,NUMBER_WEEKS,True
reg_duration,NUMBER_IN_YEAR,True
reg_duration,CHANGE_DATE_TIME,True
reg_duration,CHANGE_UID,True
reg_district,DISTRICT,True
reg_district,NAME,True
reg_district,VALIDATION_ONLY,True
reg_district,SCHOOL_YEAR,True
reg_district,SUMMER_SCHOOL_YEAR,True
reg_district,ADDRESS_FORMAT,True
reg_district,STREET1,True
reg_district,STREET2,True
reg_district,CITY,True
reg_district,STATE,True
reg_district,ZIP,True
reg_district,PHONE,True
reg_district,SUPERINTENDENT,True
reg_district,EMAIL,True
reg_district,ALPHANUMERIC_IDS,True
reg_district,STUDENT_ID_LENGTH,True
reg_district,ZERO_FILL_IDS,True
reg_district,AUTO_ASSIGN,True
reg_district,OVERIDE_AUTO_ASSGN,True
reg_district,STARTING_ID,True
reg_district,HIGHEST_ID_USED,True
reg_district,SHOW_SSN,True
reg_district,TRANSPORT_STUDENT,True
reg_district,ST_ID_REQUIRED,True
reg_district,ST_ID_LABEL,True
reg_district,ST_ID_LENGTH,True
reg_district,ST_ID_ENFORCE_LEN,True
reg_district,CHANGE_ID_IN_PRIOR,True
reg_district,ID_ON_STATE_REPORT,True
reg_district,ST_AUTO_ASSIGN,True
reg_district,ST_ID_PREFIX,True
reg_district,ST_STARTING_ID,True
reg_district,ST_MAX_ID_ALLOWED,True
reg_district,ST_HIGHEST_ID_USED,True
reg_district,ST_ID_INCLUDE,True
reg_district,ST_AUTO_ASSIGN_OV,True
reg_district,FMS_DEPARTMENT,True
reg_district,FMS_HOME_ORGN,True
reg_district,FMS_PROGRAM,True
reg_district,AGGREGATE,True
reg_district,LIST_MAX,True
reg_district,ETHNICITY_REQUIRED,True
reg_district,USE_ETHNIC_PERCENT,True
reg_district,USE_DIS_DATES,True
reg_district,USE_ALERT_DATES,True
reg_district,STATE_CODE_EQUIV,True
reg_district,AUDIT_UPDATES,True
reg_district,AUDIT_DELETE_ONLY,True
reg_district,AUDIT_CLEAR_INT,True
reg_district,LANGUAGE_REQUIRED,True
reg_district,SPECIAL_ED_TABLE,True
reg_district,SPECIAL_ED_SCR_NUM,True
reg_district,SPECIAL_ED_COLUMN,True
reg_district,IEPPLUS_INTEGRATION,True
reg_district,PARAM_KEY,True
reg_district,CRN_FROM_TAC,True
reg_district,SHOW_RES_BLDG,True
reg_district,ALT_ATTENDANCE_AGE,True
reg_district,ALT_ATT_GRADES,True
reg_district,CUTOFF_DATE,True
reg_district,EW_MEMBERSHIP,True
reg_district,ROLL_ENTRY_RULE,True
reg_district,ROLL_WD_RULE,True
reg_district,USE_RANK_CLASS_SIZE_EXCLUDE,True
reg_district,INCLUDE_IEP,True
reg_district,INCLUDE_GIFTED,True
reg_district,INCLUDE_504,True
reg_district,MIN_AGE_CITATION,True
reg_district,LOCKOUT_USERS,True
reg_district,DISABLE_SCHEDULED_TASKS,True
reg_district,FIRSTWAVE_ID,True
reg_district,SHOW_USERVOICE,True
reg_district,EMAIL_DELIMITER,True
reg_district,ALLOW_USERS_TO_SET_THEMES,True
reg_district,AUTO_GENERATE_FAMILY_NUMBER,True
reg_district,LOG_HAC_LOGINS,True
reg_district,LOG_TAC_LOGINS,True
reg_district,LOG_TAC_PUBLISH_EVENTS,True
reg_district,MULTIPLE_CLASSIFICATIONS,True
reg_district,CURRENT_KEY,True
reg_district,PREVIOUS_KEY,True
reg_district,COMPROMISED,True
reg_district,CHANGE_DATE_TIME,True
reg_district,CHANGE_UID,True
reg_district,HIDE_GENDER_IDENTITY,True
reg_geo_plan_area,DISTRICT,True
reg_geo_plan_area,SCHOOL_YEAR,True
reg_geo_plan_area,PLAN_AREA_NUMBER,True
reg_geo_plan_area,ZONE_NUMBER,True
reg_geo_plan_area,DEVELOPMENT,True
reg_geo_plan_area,STREET_PREFIX,True
reg_geo_plan_area,STREET_NAME,True
reg_geo_plan_area,STREET_TYPE,True
reg_geo_plan_area,STREET_SUFFIX,True
reg_geo_plan_area,COMPLEX,True
reg_geo_plan_area,APARTMENT_REQ,True
reg_geo_plan_area,ODD_START_ST_NUM,True
reg_geo_plan_area,ODD_END_ST_NUM,True
reg_geo_plan_area,EVEN_START_ST_NUM,True
reg_geo_plan_area,EVEN_END_ST_NUM,True
reg_geo_plan_area,CITY,True
reg_geo_plan_area,STATE,True
reg_geo_plan_area,ODD_ZIP,True
reg_geo_plan_area,ODD_ZIP_PLUS4,True
reg_geo_plan_area,EVEN_ZIP,True
reg_geo_plan_area,EVEN_ZIP_PLUS4,True
reg_geo_plan_area,START_LATITUDE,True
reg_geo_plan_area,START_LONGITUDE,True
reg_geo_plan_area,END_LATITUDE,True
reg_geo_plan_area,END_LONGITUDE,True
reg_geo_plan_area,HOME_DISTRICT,True
reg_geo_plan_area,EXTERNAL_ID_CODE,True
reg_geo_plan_area,CHANGE_DATE_TIME,True
reg_geo_plan_area,CHANGE_UID,True
reg_exclude_ipr,DISTRICT,True
reg_exclude_ipr,STUDENT_ID,True
reg_exclude_ipr,ELIG_TYPE,True
reg_exclude_ipr,CHANGE_DATE_TIME,True
reg_exclude_ipr,CHANGE_UID,True
regtb_meal_status,DISTRICT,True
regtb_meal_status,CODE,True
regtb_meal_status,DESCRIPTION,True
regtb_meal_status,STATE_CODE_EQUIV,True
regtb_meal_status,ACTIVE,True
regtb_meal_status,SIF_CODE,True
regtb_meal_status,SIF2_CODE,True
regtb_meal_status,CHANGE_DATE_TIME,True
regtb_meal_status,CHANGE_UID,True
reg_contact_phone,DISTRICT,True
reg_contact_phone,CONTACT_ID,True
reg_contact_phone,PHONE_TYPE,True
reg_contact_phone,PHONE_LISTING,True
reg_contact_phone,PHONE,True
reg_contact_phone,PHONE_EXTENSION,True
reg_contact_phone,SIF_REFID,True
reg_contact_phone,PHONE_PRIORITY,True
reg_contact_phone,CHANGE_DATE_TIME,True
reg_contact_phone,CHANGE_UID,True
reg_cfg,DISTRICT,True
reg_cfg,BUILDING,True
reg_cfg,SCHOOL_YEAR,True
reg_cfg,AUTO_ASSIGN,True
reg_cfg,OVERIDE_AUTO_ASSGN,True
reg_cfg,STARTING_ID,True
reg_cfg,MAX_ID_ALLOWED,True
reg_cfg,HIGHEST_ID_USED,True
reg_cfg,DEFAULT_ENTRY_CODE,True
reg_cfg,DEFAULT_ENTRY_DATE,True
reg_cfg,YEAREND_WD_CODE,True
reg_cfg,YEAREND_ENTRY_CODE,True
reg_cfg,DROP_OUT_CODE,True
reg_cfg,EMAIL,True
reg_cfg,YEAR_ROUND,True
reg_cfg,PHOTO_PATH,True
reg_cfg,PHOTO_EXTENSION,True
reg_cfg,ST_ID_PREFIX,True
reg_cfg,ST_STARTING_ID,True
reg_cfg,ST_MAX_ID_ALLOWED,True
reg_cfg,ST_HIGHEST_ID_USED,True
reg_cfg,ST_AUTO_ASSIGN_OV,True
reg_cfg,TEA_PERS_STU_SUMM,True
reg_cfg,SUB_PERS_STU_SUMM,True
reg_cfg,TEA_EMERG_STU_SUMM,True
reg_cfg,SUB_EMERG_STU_SUMM,True
reg_cfg,TEA_STUDENT_SEARCH,True
reg_cfg,SUB_STUDENT_SEARCH,True
reg_cfg,TEA_VIEW_IEP,True
reg_cfg,SUB_VIEW_IEP,True
reg_cfg,TEA_VIEW_GIFTED,True
reg_cfg,SUB_VIEW_GIFTED,True
reg_cfg,TEA_VIEW_504,True
reg_cfg,SUB_VIEW_504,True
reg_cfg,LOCKER_ASSIGN,True
reg_cfg,AUTO_LOCKER_ASSIGN,True
reg_cfg,REGISTRAR_EMAIL,True
reg_cfg,MAX_WITH_BACKDATE,True
reg_cfg,MSG_NEW_STUD,True
reg_cfg,MSG_NEW_PR_STUD,True
reg_cfg,MSG_PRIM_HOMEROOM,True
reg_cfg,MSG_SEC_HOMEROOM,True
reg_cfg,MSG_STU_COUNS,True
reg_cfg,MSG_SUMMER_COUNS,True
reg_cfg,MSG_EW_REENTRY,True
reg_cfg,MSG_EW_CHG_BLDG,True
reg_cfg,CHANGE_DATE_TIME,True
reg_cfg,CHANGE_UID,True
reg_cfg,PHOTO_DIRECTORY,True
reg_calendar,DISTRICT,True
reg_calendar,BUILDING,True
reg_calendar,SCHOOL_YEAR,True
reg_calendar,SUMMER_SCHOOL,True
reg_calendar,TRACK,True
reg_calendar,CALENDAR,True
reg_calendar,DESCRIPTION,True
reg_calendar,DEF_MEM_VALUE,True
reg_calendar,FIRST_DAY,True
reg_calendar,LAST_DAY,True
reg_calendar,SUNDAY,True
reg_calendar,MONDAY,True
reg_calendar,TUESDAY,True
reg_calendar,WEDNESDAY,True
reg_calendar,THURSDAY,True
reg_calendar,FRIDAY,True
reg_calendar,SATURDAY,True
reg_calendar,DAYS_IN_CYCLE,True
reg_calendar,FIRST_DAY_CYCLE,True
reg_calendar,DAYS_IN_CALENDAR,True
reg_calendar,DAYS_IN_MEMBERSHIP,True
reg_calendar,STATE_CODE_EQUIV,True
reg_calendar,ROW_IDENTITY,True
reg_calendar,CHANGE_DATE_TIME,True
reg_calendar,CHANGE_UID,True
regtb_grade_pesc_code,DISTRICT,True
regtb_grade_pesc_code,CODE,True
regtb_grade_pesc_code,DESCRIPTION,True
regtb_grade_pesc_code,CHANGE_DATE_TIME,True
regtb_grade_pesc_code,CHANGE_UID,True
reg_disability,DISTRICT,True
reg_disability,STUDENT_ID,True
reg_disability,DISABILITY,True
reg_disability,SEQUENCE_NUM,True
reg_disability,DISABILITY_ORDER,True
reg_disability,START_DATE,True
reg_disability,END_DATE,True
reg_disability,CHANGE_DATE_TIME,True
reg_disability,CHANGE_UID,True
reg_building,DISTRICT,True
reg_building,BUILDING,True
reg_building,NAME,True
reg_building,TRANSFER_BUILDING,True
reg_building,ABBREVIATION,True
reg_building,STREET1,True
reg_building,STREET2,True
reg_building,CITY,True
reg_building,STATE,True
reg_building,ZIP,True
reg_building,PHONE,True
reg_building,FAX,True
reg_building,PRINCIPAL,True
reg_building,CALENDAR,True
reg_building,BUILDING_TYPE,True
reg_building,DEFAULT_ZIP,True
reg_building,STATE_CODE_EQUIV,True
reg_building,COUNTY_CODE,True
reg_building,OUT_OF_DISTRICT,True
reg_building,PESC_CODE,True
reg_building,CHANGE_DATE_TIME,True
reg_building,CHANGE_UID,True
reg_appointment,DISTRICT,True
reg_appointment,APPOINTMENT_ID,True
reg_appointment,BUILDING,True
reg_appointment,STUDENT_ID,True
reg_appointment,DATE_ENTERED,True
reg_appointment,ENTRY_UID,True
reg_appointment,APPT_START_TIME,True
reg_appointment,APPT_END_TIME,True
reg_appointment,APPT_TYPE,True
reg_appointment,APPT_REASON,True
reg_appointment,STAFF_ID,True
reg_appointment,PERIOD,True
reg_appointment,KEPT_APPT,True
reg_appointment,INCLUDE_STUDENT_NOTE,True
reg_appointment,CHANGE_DATE_TIME,True
reg_appointment,CHANGE_UID,True
reg_contact,DISTRICT,True
reg_contact,CONTACT_ID,True
reg_contact,TITLE,True
reg_contact,SALUTATION,True
reg_contact,FIRST_NAME,True
reg_contact,MIDDLE_NAME,True
reg_contact,LAST_NAME,True
reg_contact,GENERATION,True
reg_contact,LANGUAGE,True
reg_contact,HOME_LANGUAGE,True
reg_contact,USE_FOR_MAILING,True
reg_contact,EMPLOYER,True
reg_contact,DEVELOPMENT,True
reg_contact,APARTMENT,True
reg_contact,COMPLEX,True
reg_contact,STREET_NUMBER,True
reg_contact,STREET_PREFIX,True
reg_contact,STREET_NAME,True
reg_contact,STREET_SUFFIX,True
reg_contact,STREET_TYPE,True
reg_contact,CITY,True
reg_contact,STATE,True
reg_contact,ZIP,True
reg_contact,PLAN_AREA_NUMBER,True
reg_contact,HOME_BUILDING_TYPE,True
reg_contact,EMAIL,True
reg_contact,EMAIL_PREFERENCE,True
reg_contact,DELIVERY_POINT,True
reg_contact,LOGIN_ID,True
reg_contact,WEB_PASSWORD,True
reg_contact,PWD_CHG_DATE_TIME,True
reg_contact,LAST_LOGIN_DATE,True
reg_contact,EDUCATION_LEVEL,True
reg_contact,SIF_REFID,True
reg_contact,HAC_LDAP_FLAG,True
reg_contact,ACCT_LOCKED,True
reg_contact,ACCT_LOCKED_DATE_TIME,True
reg_contact,CHG_PW_NEXT_LOGIN,True
reg_contact,ONBOARD_TOKEN,True
reg_contact,ONBOARD_TOKEN_USED,True
reg_contact,ROW_IDENTITY,True
reg_contact,KEY_USED,True
reg_contact,CONTACT_KEY,True
reg_contact,CHANGE_DATE_TIME,True
reg_contact,CHANGE_UID,True
reg_activity_hdr,DISTRICT,True
reg_activity_hdr,SCHOOL_YEAR,True
reg_activity_hdr,BUILDING,True
reg_activity_hdr,ACTIVITY_CODE,True
reg_activity_hdr,DESCRIPTION,True
reg_activity_hdr,MODERATOR,True
reg_activity_hdr,MAX_ENROLLMENT,True
reg_activity_hdr,CURRENT_ENROLLMENT,True
reg_activity_hdr,EXCEED_MAXIMUM,True
reg_activity_hdr,STATE_CODE_EQUIV,True
reg_activity_hdr,ROW_IDENTITY,True
reg_activity_hdr,CHANGE_DATE_TIME,True
reg_activity_hdr,CHANGE_UID,True
reg_activity_det,DISTRICT,True
reg_activity_det,SCHOOL_YEAR,True
reg_activity_det,BUILDING,True
reg_activity_det,ACTIVITY_CODE,True
reg_activity_det,STUDENT_ID,True
reg_activity_det,ACTIVITY_STATUS,True
reg_activity_det,INELIGIBLE,True
reg_activity_det,OVERRIDE,True
reg_activity_det,START_DATE,True
reg_activity_det,END_DATE,True
reg_activity_det,DURATION,True
reg_activity_det,ACTIVITY_COMMENT,True
reg_activity_det,ROW_IDENTITY,True
reg_activity_det,CHANGE_DATE_TIME,True
reg_activity_det,CHANGE_UID,True
reg_cal_days,DISTRICT,True
reg_cal_days,BUILDING,True
reg_cal_days,SCHOOL_YEAR,True
reg_cal_days,SUMMER_SCHOOL,True
reg_cal_days,TRACK,True
reg_cal_days,CALENDAR,True
reg_cal_days,CAL_DATE,True
reg_cal_days,CYCLE_FLAG,True
reg_cal_days,CYCLE_CODE,True
reg_cal_days,MEMBERSHIP_DAY,True
reg_cal_days,MEMBERSHIP_VALUE,True
reg_cal_days,TAKE_ATTENDANCE,True
reg_cal_days,INCLUDE_TOTALS,True
reg_cal_days,DAY_TYPE,True
reg_cal_days,DAY_NUMBER,True
reg_cal_days,DAY_IN_MEMBERSHIP,True
reg_cal_days,ALTERNATE_CYCLE,True
reg_cal_days,WEEK_NUMBER,True
reg_cal_days,INSTRUCT_TIME,True
reg_cal_days,ROW_IDENTITY,True
reg_cal_days,CHANGE_DATE_TIME,True
reg_cal_days,CHANGE_UID,True
reg_building_grade,DISTRICT,True
reg_building_grade,BUILDING,True
reg_building_grade,GRADE,True
reg_building_grade,CHANGE_DATE_TIME,True
reg_building_grade,CHANGE_UID,True
pa_program_down,DISTRICT,True
pa_program_down,SCHOOL_YEAR,True
pa_program_down,PERIOD,True
pa_program_down,STUDENT_ID,True
pa_program_down,STATE_ID,True
pa_program_down,LOCATION,True
pa_program_down,SCHOOL_YEAR_DATE,True
pa_program_down,PROGRAMS_CODE,True
pa_program_down,BEGINNING_DATE,True
pa_program_down,ENDING_DATE,True
pa_program_down,PROGRAM_INTENSITY,True
pa_program_down,CHANGE_DATE_TIME,True
pa_program_down,CHANGE_UID,True
pa_enroll_down,DISTRICT,True
pa_enroll_down,SCHOOL_YEAR,True
pa_enroll_down,PERIOD,True
pa_enroll_down,STUDENT_ID,True
pa_enroll_down,STATE_ID,True
pa_enroll_down,LOCATION,True
pa_enroll_down,SCHOOL_YEAR_DATE,True
pa_enroll_down,ACTIVITY_DATE,True
pa_enroll_down,ENROLLMENT_DATE,True
pa_enroll_down,ENROLLMENT_CODE,True
pa_enroll_down,GRADE,True
pa_enroll_down,RESIDENCE,True
pa_enroll_down,CHANGE_DATE_TIME,True
pa_enroll_down,CHANGE_UID,True
reg_entry_with,DISTRICT,True
reg_entry_with,STUDENT_ID,True
reg_entry_with,ENTRY_WD_TYPE,True
reg_entry_with,SCHOOL_YEAR,True
reg_entry_with,ENTRY_DATE,True
reg_entry_with,ENTRY_CODE,True
reg_entry_with,BUILDING,True
reg_entry_with,GRADE,True
reg_entry_with,TRACK,True
reg_entry_with,CALENDAR,True
reg_entry_with,WITHDRAWAL_DATE,True
reg_entry_with,WITHDRAWAL_CODE,True
reg_entry_with,COMMENTS,True
reg_entry_with,ROW_IDENTITY,True
reg_entry_with,CHANGE_DATE_TIME,True
reg_entry_with,CHANGE_UID,True
reg_activity_inel,DISTRICT,True
reg_activity_inel,SCHOOL_YEAR,True
reg_activity_inel,BUILDING,True
reg_activity_inel,STUDENT_ID,True
reg_activity_inel,ACTIVITY_CODE,True
reg_activity_inel,NOTIFICATION_DATE,True
reg_activity_inel,TRIGGER_EVENT,True
reg_activity_inel,ATTENDANCE_DATE,True
reg_activity_inel,ATTENDANCE_PERIOD,True
reg_activity_inel,INELIGIBILITY_CODE,True
reg_activity_inel,SOURCE,True
reg_activity_inel,INVALID_EVENT,True
reg_activity_inel,CHANGE_DATE_TIME,True
reg_activity_inel,CHANGE_UID,True
reg_act_prereq,DISTRICT,True
reg_act_prereq,SCHOOL_YEAR,True
reg_act_prereq,BUILDING,True
reg_act_prereq,ACTIVITY_CODE,True
reg_act_prereq,SEQUENCE_NUM,True
reg_act_prereq,AND_OR_FLAG,True
reg_act_prereq,TABLE_NAME,True
reg_act_prereq,COLUMN_NAME,True
reg_act_prereq,OPERATOR,True
reg_act_prereq,LOW_VALUE,True
reg_act_prereq,HIGH_VALUE,True
reg_act_prereq,CHANGE_DATE_TIME,True
reg_act_prereq,CHANGE_UID,True
reg_academic_supp,DISTRICT,True
reg_academic_supp,STUDENT_ID,True
reg_academic_supp,SUPP_TYPE,True
reg_academic_supp,SUPP_REQ_GROUP,True
reg_academic_supp,CHANGE_DATE_TIME,True
reg_academic_supp,CHANGE_UID,True
reg_academic,DISTRICT,True
reg_academic,STUDENT_ID,True
reg_academic,GRADUATION_YEAR,True
reg_academic,GRADUATION_DATE,True
reg_academic,PROMOTION,True
reg_academic,CURRICULUM,True
reg_academic,SCHD_PRIORITY,True
reg_academic,GRADUATE_REQ_GROUP,True
reg_academic,MODELED_GRAD_PLAN,True
reg_academic,PENDING_GRAD_PLAN,True
reg_academic,EXP_GRAD_PLAN,True
reg_academic,ACT_GRAD_PLAN,True
reg_academic,DIPLOMA_TYPE,True
reg_academic,ELIG_STATUS,True
reg_academic,ELIG_REASON,True
reg_academic,ELIG_EFFECTIVE_DTE,True
reg_academic,ELIG_EXPIRES_DATE,True
reg_academic,HOLD_REPORT_CARD,True
reg_academic,RC_HOLD_OVERRIDE,True
reg_academic,VOTEC,True
reg_academic,ADVISOR,True
reg_academic,DISCIPLINARIAN,True
reg_academic,FEDERAL_GRAD_YEAR,True
reg_academic,ROW_IDENTITY,True
reg_academic,CHANGE_DATE_TIME,True
reg_academic,CHANGE_UID,True
reg,DISTRICT,True
reg,STUDENT_ID,True
reg,FIRST_NAME,True
reg,MIDDLE_NAME,True
reg,LAST_NAME,True
reg,GENERATION,True
reg,BUILDING,True
reg,HOME_BUILDING,True
reg,BUILDING_OVERRIDE,True
reg,BUILDING_REASON,True
reg,GRADE,True
reg,GENDER,True
reg,LANGUAGE,True
reg,NATIVE_LANGUAGE,True
reg,CALENDAR,True
reg,TRACK,True
reg,CURRENT_STATUS,True
reg,SUMMER_STATUS,True
reg,COUNSELOR,True
reg,HOUSE_TEAM,True
reg,HOMEROOM_PRIMARY,True
reg,HOMEROOM_SECONDARY,True
reg,BIRTHDATE,True
reg,FAMILY_CENSUS,True
reg,ALT_BUILDING,True
reg,ALT_DISTRICT,True
reg,NICKNAME,True
reg,HOME_DISTRICT,True
reg,ATTENDING_DISTRICT,True
reg,ALT_BLDG_ACCT,True
reg,DIST_ENROLL_DATE,True
reg,STATE_ENROLL_DATE,True
reg,US_ENROLL_DATE,True
reg,STUDENT_GUID,True
reg,RES_COUNTY_CODE,True
reg,STATE_RES_BUILDING,True
reg,GRADE_9_DATE,True
reg,GENDER_IDENTITY,True
reg,CHANGE_DATE_TIME,True
reg,CHANGE_UID,True
patb_weap_detect,DISTRICT,True
patb_weap_detect,CODE,True
patb_weap_detect,DESCRIPTION,True
patb_weap_detect,ACTIVE,True
patb_weap_detect,CHANGE_DATE_TIME,True
patb_weap_detect,CHANGE_UID,True
pa_course_down,DISTRICT,True
pa_course_down,STATE_DISTRICT,True
pa_course_down,SCHOOL_YEAR,True
pa_course_down,PERIOD,True
pa_course_down,LOCATION,True
pa_course_down,LOCAL_BUILDING,True
pa_course_down,SCHOOL_YEAR_DATE,True
pa_course_down,STATE_COURSE,True
pa_course_down,LOCAL_COURSE,True
pa_course_down,COURSE_NAME,True
pa_course_down,COURSE_LENGTH,True
pa_course_down,CREDIT,True
pa_course_down,HONORS_INDICATOR,True
pa_course_down,SEMESTER,True
pa_course_down,REQ_INDICATOR,True
pa_course_down,DUAL_CREDIT,True
pa_course_down,ADV_PLACEMENT,True
pa_course_down,CAREER_TECH,True
pa_course_down,GIFTED,True
pa_course_down,INTL_BACC,True
pa_course_down,CHANGE_DATE_TIME,True
pa_course_down,CHANGE_UID,True
patb_stu_status,DISTRICT,True
patb_stu_status,CODE,True
patb_stu_status,DESCRIPTION,True
patb_stu_status,STATE_CODE_EQUIV,True
patb_stu_status,ACTIVE,True
patb_stu_status,CHANGE_DATE_TIME,True
patb_stu_status,CHANGE_UID,True
REG_ACTIVITY_ADV,DISTRICT,True
REG_ACTIVITY_ADV,SCHOOL_YEAR,True
REG_ACTIVITY_ADV,BUILDING,True
REG_ACTIVITY_ADV,ACTIVITY_CODE,True
REG_ACTIVITY_ADV,STAFF_ID,True
REG_ACTIVITY_ADV,ROW_IDENTITY,True
REG_ACTIVITY_ADV,CHANGE_DATE_TIME,True
REG_ACTIVITY_ADV,CHANGE_UID,True
patb_status,DISTRICT,True
patb_status,CODE,True
patb_status,DESCRIPTION,True
patb_status,ACTIVE,True
patb_status,CHANGE_DATE_TIME,True
patb_status,CHANGE_UID,True
patb_spec_ed,DISTRICT,True
patb_spec_ed,CODE,True
patb_spec_ed,DESCRIPTION,True
patb_spec_ed,STATE_CODE_EQUIV,True
patb_spec_ed,ACTIVE,True
patb_spec_ed,CHANGE_DATE_TIME,True
patb_spec_ed,CHANGE_UID,True
reg_cycle,DISTRICT,True
reg_cycle,SCHOOL_YEAR,True
reg_cycle,SUMMER_SCHOOL,True
reg_cycle,BUILDING,True
reg_cycle,CYCLE_ORDER,True
reg_cycle,CODE,True
reg_cycle,DESCRIPTION,True
reg_cycle,ALTERNATE_CYCLE,True
reg_cycle,CHANGE_DATE_TIME,True
reg_cycle,CHANGE_UID,True
PATB_SEMESTER,DISTRICT,True
PATB_SEMESTER,CODE,True
PATB_SEMESTER,DESCRIPTION,True
PATB_SEMESTER,STATE_CODE_EQUIV,True
PATB_SEMESTER,ACTIVE,True
PATB_SEMESTER,CHANGE_DATE_TIME,True
PATB_SEMESTER,CHANGE_UID,True
patb_remedial,DISTRICT,True
patb_remedial,CODE,True
patb_remedial,DESCRIPTION,True
patb_remedial,ACTIVE,True
patb_remedial,CHANGE_DATE_TIME,True
patb_remedial,CHANGE_UID,True
patb_par_involve,DISTRICT,True
patb_par_involve,CODE,True
patb_par_involve,DESCRIPTION,True
patb_par_involve,ACTIVE,True
patb_par_involve,CHANGE_DATE_TIME,True
patb_par_involve,CHANGE_UID,True
patb_other_fire,DISTRICT,True
patb_other_fire,CODE,True
patb_other_fire,DESCRIPTION,True
patb_other_fire,ACTIVE,True
patb_other_fire,CHANGE_DATE_TIME,True
patb_other_fire,CHANGE_UID,True
pa_course_inst_down,DISTRICT,True
pa_course_inst_down,STATE_DISTRICT,True
pa_course_inst_down,SCHOOL_YEAR,True
pa_course_inst_down,PERIOD,True
pa_course_inst_down,LOCATION,True
pa_course_inst_down,LOCAL_BUILDING,True
pa_course_inst_down,SCHOOL_YEAR_DATE,True
pa_course_inst_down,STATE_COURSE,True
pa_course_inst_down,LOCAL_COURSE,True
pa_course_inst_down,LOCAL_SECTION,True
pa_course_inst_down,INSTRUCTOR_ID,True
pa_course_inst_down,SEMESTER,True
pa_course_inst_down,LANGUAGE,True
pa_course_inst_down,CHANGE_DATE_TIME,True
pa_course_inst_down,CHANGE_UID,True
patb_suicide,DISTRICT,True
patb_suicide,CODE,True
patb_suicide,DESCRIPTION,True
patb_suicide,ACTIVE,True
patb_suicide,CHANGE_DATE_TIME,True
patb_suicide,CHANGE_UID,True
patb_lep_part,DISTRICT,True
patb_lep_part,CODE,True
patb_lep_part,DESCRIPTION,True
patb_lep_part,STATE_CODE_EQUIV,True
patb_lep_part,ACTIVE,True
patb_lep_part,CHANGE_DATE_TIME,True
patb_lep_part,CHANGE_UID,True
ltdb_test,DISTRICT,True
ltdb_test,TEST_CODE,True
ltdb_test,TEST_LEVEL,True
ltdb_test,TEST_FORM,True
ltdb_test,TEST_KEY,True
ltdb_test,DESCRIPTION,True
ltdb_test,DISPLAY,True
ltdb_test,SEC_PACKAGE,True
ltdb_test,SEC_SUBPACKAGE,True
ltdb_test,SEC_FEATURE,True
ltdb_test,TEACHER_DISPLAY,True
ltdb_test,SUB_DISPLAY,True
ltdb_test,INCLUDE_PERFPLUS,True
ltdb_test,PESC_CODE,True
ltdb_test,CHANGE_DATE_TIME,True
ltdb_test,CHANGE_UID,True
patb_sex_offender,DISTRICT,True
patb_sex_offender,CODE,True
patb_sex_offender,DESCRIPTION,True
patb_sex_offender,ACTIVE,True
patb_sex_offender,CHANGE_DATE_TIME,True
patb_sex_offender,CHANGE_UID,True
ltdb_subtest,DISTRICT,True
ltdb_subtest,TEST_CODE,True
ltdb_subtest,TEST_LEVEL,True
ltdb_subtest,TEST_FORM,True
ltdb_subtest,TEST_KEY,True
ltdb_subtest,SUBTEST,True
ltdb_subtest,DESCRIPTION,True
ltdb_subtest,SUBTEST_ORDER,True
ltdb_subtest,DISPLAY,True
ltdb_subtest,STATE_CODE_EQUIV,True
ltdb_subtest,PESC_CODE,True
ltdb_subtest,CHANGE_DATE_TIME,True
ltdb_subtest,CHANGE_UID,True
ltdb_stu_trk_data,DISTRICT,True
ltdb_stu_trk_data,TEST_CODE,True
ltdb_stu_trk_data,TEST_LEVEL,True
ltdb_stu_trk_data,TEST_FORM,True
ltdb_stu_trk_data,TEST_KEY,True
ltdb_stu_trk_data,STUDENT_ID,True
ltdb_stu_trk_data,TEST_DATE,True
ltdb_stu_trk_data,FIELD_NUMBER,True
ltdb_stu_trk_data,FIELD_VALUE,True
ltdb_stu_trk_data,CHANGE_DATE_TIME,True
ltdb_stu_trk_data,CHANGE_UID,True
ltdb_stu_tracking,DISTRICT,True
ltdb_stu_tracking,TEST_CODE,True
ltdb_stu_tracking,TEST_LEVEL,True
ltdb_stu_tracking,TEST_FORM,True
ltdb_stu_tracking,TEST_KEY,True
ltdb_stu_tracking,FIELD_NUMBER,True
ltdb_stu_tracking,FIELD_ORDER,True
ltdb_stu_tracking,SOURCE,True
ltdb_stu_tracking,PROGRAM_FIELD,True
ltdb_stu_tracking,EXTERNAL_CODE,True
ltdb_stu_tracking,FIELD_LABEL,True
ltdb_stu_tracking,CHANGE_DATE_TIME,True
ltdb_stu_tracking,CHANGE_UID,True
patb_other_weap,DISTRICT,True
patb_other_weap,CODE,True
patb_other_weap,DESCRIPTION,True
patb_other_weap,ACTIVE,True
patb_other_weap,CHANGE_DATE_TIME,True
patb_other_weap,CHANGE_UID,True
LTDB_STU_AT_RISK,DISTRICT,True
LTDB_STU_AT_RISK,TEST_CODE,True
LTDB_STU_AT_RISK,TEST_LEVEL,True
LTDB_STU_AT_RISK,TEST_FORM,True
LTDB_STU_AT_RISK,TEST_KEY,True
LTDB_STU_AT_RISK,STUDENT_ID,True
LTDB_STU_AT_RISK,TEST_DATE,True
LTDB_STU_AT_RISK,SUBTEST,True
LTDB_STU_AT_RISK,SCORE_CODE,True
LTDB_STU_AT_RISK,SCORE,True
LTDB_STU_AT_RISK,QUALIFICATION,True
LTDB_STU_AT_RISK,QUAL_REASON,True
LTDB_STU_AT_RISK,TEST_CODE2,True
LTDB_STU_AT_RISK,TEST_LEVEL2,True
LTDB_STU_AT_RISK,TEST_FORM2,True
LTDB_STU_AT_RISK,TEST_KEY2,True
LTDB_STU_AT_RISK,TEST_DATE2,True
LTDB_STU_AT_RISK,SUBTEST2,True
LTDB_STU_AT_RISK,SCORE_CODE2,True
LTDB_STU_AT_RISK,SCORE2,True
LTDB_STU_AT_RISK,BUILDING,True
LTDB_STU_AT_RISK,GRADE,True
LTDB_STU_AT_RISK,AT_RISK,True
LTDB_STU_AT_RISK,START_DATE,True
LTDB_STU_AT_RISK,END_DATE,True
LTDB_STU_AT_RISK,PLAN_NUM,True
LTDB_STU_AT_RISK,PLAN_DATE,True
LTDB_STU_AT_RISK,CHANGE_DATE_TIME,True
LTDB_STU_AT_RISK,CHANGE_UID,True
patb_occ_time,DISTRICT,True
patb_occ_time,CODE,True
patb_occ_time,DESCRIPTION,True
patb_occ_time,ACTIVE,True
patb_occ_time,CHANGE_DATE_TIME,True
patb_occ_time,CHANGE_UID,True
ltdb_interface_stu,DISTRICT,True
ltdb_interface_stu,INTERFACE_ID,True
ltdb_interface_stu,STUDENT_ID,True
ltdb_interface_stu,DATE_ADDED,True
ltdb_interface_stu,DATE_DELETED,True
ltdb_interface_stu,DATE_CHANGED,True
ltdb_interface_stu,CHANGE_DATE_TIME,True
ltdb_interface_stu,CHANGE_UID,True
ltdb_import_trn,district,True
ltdb_import_trn,interface_id,True
ltdb_import_trn,description,True
ltdb_import_trn,test_code,True
ltdb_import_trn,test_level,True
ltdb_import_trn,test_form,True
ltdb_import_trn,test_key,True
ltdb_import_trn,field_id,True
ltdb_import_trn,translation_id,True
ltdb_import_trn,old_value,True
ltdb_import_trn,new_value,True
ltdb_import_trn,change_date_time,True
ltdb_import_trn,change_uid,True
ltdb_test_tracking,DISTRICT,True
ltdb_test_tracking,TEST_CODE,True
ltdb_test_tracking,TEST_LEVEL,True
ltdb_test_tracking,TEST_FORM,True
ltdb_test_tracking,TEST_KEY,True
ltdb_test_tracking,FIELD_NUMBER,True
ltdb_test_tracking,FIELD_ORDER,True
ltdb_test_tracking,FIELD_LABEL,True
ltdb_test_tracking,FIELD_DATA,True
ltdb_test_tracking,CHANGE_DATE_TIME,True
ltdb_test_tracking,CHANGE_UID,True
pa_stu_course_down,DISTRICT,True
pa_stu_course_down,STATE_DISTRICT,True
pa_stu_course_down,SCHOOL_YEAR,True
pa_stu_course_down,PERIOD,True
pa_stu_course_down,LOCATION,True
pa_stu_course_down,LOCAL_BUILDING,True
pa_stu_course_down,SCHOOL_YEAR_DATE,True
pa_stu_course_down,STATE_COURSE,True
pa_stu_course_down,LOCAL_COURSE,True
pa_stu_course_down,LOCAL_SECTION,True
pa_stu_course_down,STUDENT_ID,True
pa_stu_course_down,STATE_ID,True
pa_stu_course_down,ENROLL_PERIOD,True
pa_stu_course_down,EFFECTIVE_DATE,True
pa_stu_course_down,ENROLLMENT_CODE,True
pa_stu_course_down,REQ_SEQUENCE,True
pa_stu_course_down,SEMESTER,True
pa_stu_course_down,COURSE_DELIVERY,True
pa_stu_course_down,CHANGE_DATE_TIME,True
pa_stu_course_down,CHANGE_UID,True
Ltdb_group_hdr,DISTRICT,True
Ltdb_group_hdr,SCHOOL_YEAR,True
Ltdb_group_hdr,GROUP_CODE,True
Ltdb_group_hdr,DESCRIPTION,True
Ltdb_group_hdr,ACTIVE,True
Ltdb_group_hdr,CHANGE_DATE_TIME,True
Ltdb_group_hdr,CHANGE_UID,True
Ltdb_group_det,DISTRICT,True
Ltdb_group_det,SCHOOL_YEAR,True
Ltdb_group_det,GROUP_CODE,True
Ltdb_group_det,SECTION_KEY,True
Ltdb_group_det,MARKING_PERIOD,True
Ltdb_group_det,MARK_TYPE,True
Ltdb_group_det,ACTIVE,True
Ltdb_group_det,CHANGE_DATE_TIME,True
Ltdb_group_det,CHANGE_UID,True
booktb_type,DISTRICT,True
booktb_type,CODE,True
booktb_type,DESCRIPTION,True
booktb_type,CHANGE_DATE_TIME,True
booktb_type,CHANGE_UID,True
booktb_publisher,DISTRICT,True
booktb_publisher,CODE,True
booktb_publisher,DESCRIPTION,True
booktb_publisher,CHANGE_DATE_TIME,True
booktb_publisher,CHANGE_UID,True
ltdb_import_hdr,district,True
ltdb_import_hdr,interface_id,True
ltdb_import_hdr,description,True
ltdb_import_hdr,test_code,True
ltdb_import_hdr,test_level,True
ltdb_import_hdr,test_form,True
ltdb_import_hdr,test_key,True
ltdb_import_hdr,filename,True
ltdb_import_hdr,last_run_date,True
ltdb_import_hdr,delimit_char,True
ltdb_import_hdr,additional_sql,True
ltdb_import_hdr,change_date_time,True
ltdb_import_hdr,change_uid,True
booktb_mlc,DISTRICT,True
booktb_mlc,CODE,True
booktb_mlc,DESCRIPTION,True
booktb_mlc,ACTIVE,True
booktb_mlc,CHANGE_DATE_TIME,True
booktb_mlc,CHANGE_UID,True
booktb_depository,DISTRICT,True
booktb_depository,CODE,True
booktb_depository,DESCRIPTION,True
booktb_depository,CHANGE_DATE_TIME,True
booktb_depository,CHANGE_UID,True
booktb_adoption,DISTRICT,True
booktb_adoption,CODE,True
booktb_adoption,DESCRIPTION,True
booktb_adoption,CHANGE_DATE_TIME,True
booktb_adoption,CHANGE_UID,True
book_textbook,DISTRICT,True
book_textbook,ISBN_CODE,True
book_textbook,BOOK_TYPE,True
book_textbook,MLC_CODE,True
book_textbook,BOOK_TITLE,True
book_textbook,AUTHOR,True
book_textbook,PUBLISHER_CODE,True
book_textbook,COPYRIGHT_YEAR,True
book_textbook,UNIT_COST,True
book_textbook,ADOPTION_YEAR,True
book_textbook,EXPIRATION_YEAR,True
book_textbook,ADOPTION_STATUS,True
book_textbook,QUOTA_PERCENT,True
book_textbook,USABLE_ON_HAND,True
book_textbook,WORN_OUT,True
book_textbook,PAID_FOR,True
book_textbook,AMOUNT_FINES,True
book_textbook,REPORTED_SURPLUS,True
book_textbook,BOOKS_ON_ORDER,True
book_textbook,ISBN_CODE_OTHER,True
book_textbook,DEPOSITORY_CODE,True
book_textbook,BOOK_TYPE_RELATED,True
book_textbook,BOOKS_ON_PURCHASE,True
book_textbook,SUBJECT_DESC,True
book_textbook,ST_ADOPTION_CODE,True
book_textbook,GRADE_LEVEL,True
book_textbook,ACTIVE,True
book_textbook,OK_TO_ORDER,True
book_textbook,LOCAL_FLAG,True
book_textbook,EXTENDED_DESC,True
book_textbook,CHANGE_DATE_TIME,True
book_textbook,CHANGE_UID,True
ltdb_stu_subtest,DISTRICT,True
ltdb_stu_subtest,TEST_CODE,True
ltdb_stu_subtest,TEST_LEVEL,True
ltdb_stu_subtest,TEST_FORM,True
ltdb_stu_subtest,TEST_KEY,True
ltdb_stu_subtest,STUDENT_ID,True
ltdb_stu_subtest,TEST_DATE,True
ltdb_stu_subtest,SUBTEST,True
ltdb_stu_subtest,SCORE_CODE,True
ltdb_stu_subtest,SCORE,True
ltdb_stu_subtest,CHANGE_DATE_TIME,True
ltdb_stu_subtest,CHANGE_UID,True
book_req_det,DISTRICT,True
book_req_det,ORDER_NUMBER,True
book_req_det,LINE_NUMBER,True
book_req_det,ISBN_CODE,True
book_req_det,BOOK_TYPE,True
book_req_det,ORDERED,True
book_req_det,SHIPPED,True
book_req_det,SHIPPED_TO_DATE,True
book_req_det,RECEIVED,True
book_req_det,RECEIVED_TO_DATE,True
book_req_det,LAST_DATE_SHIPPED,True
book_req_det,LAST_DATE_RECEIVED,True
book_req_det,LAST_QTY_SHIPPED,True
book_req_det,LAST_QTY_RECEIVED,True
book_req_det,CHANGE_DATE_TIME,True
book_req_det,CHANGE_UID,True
book_mlc_course,DISTRICT,True
book_mlc_course,COURSE,True
book_mlc_course,MLC_CODE,True
book_mlc_course,STATE_COURSE,True
book_mlc_course,CHANGE_DATE_TIME,True
book_mlc_course,CHANGE_UID,True
book_bookmaster,DISTRICT,True
book_bookmaster,ISBN_CODE,True
book_bookmaster,BUILDING,True
book_bookmaster,BOOK_TYPE,True
book_bookmaster,USABLE_ON_HAND,True
book_bookmaster,WORN_OUT,True
book_bookmaster,PAID_FOR,True
book_bookmaster,AMOUNT_FINES,True
book_bookmaster,REPORTED_SURPLUS,True
book_bookmaster,BOOKS_ON_ORDER,True
book_bookmaster,ALLOCATED,True
book_bookmaster,PURCHASE_ORDER,True
book_bookmaster,REQUESTS,True
book_bookmaster,CHANGE_DATE_TIME,True
book_bookmaster,CHANGE_UID,True
ltdb_import_det,DISTRICT,True
ltdb_import_det,INTERFACE_ID,True
ltdb_import_det,TEST_CODE,True
ltdb_import_det,TEST_LEVEL,True
ltdb_import_det,TEST_FORM,True
ltdb_import_det,TEST_KEY,True
ltdb_import_det,FIELD_ID,True
ltdb_import_det,FIELD_ORDER,True
ltdb_import_det,TABLE_NAME,True
ltdb_import_det,COLUMN_NAME,True
ltdb_import_det,SUBTEST,True
ltdb_import_det,SCORE_CODE,True
ltdb_import_det,FORMAT_STRING,True
ltdb_import_det,START_POSITION,True
ltdb_import_det,END_POSITION,True
ltdb_import_det,MAP_FIELD,True
ltdb_import_det,MAP_SCORE,True
ltdb_import_det,FIELD_LENGTH,True
ltdb_import_det,VALIDATION_TABLE,True
ltdb_import_det,CODE_COLUMN,True
ltdb_import_det,VALIDATION_LIST,True
ltdb_import_det,ERROR_MESSAGE,True
ltdb_import_det,EXTERNAL_TABLE,True
ltdb_import_det,EXTERNAL_COL_IN,True
ltdb_import_det,EXTERNAL_COL_OUT,True
ltdb_import_det,LITERAL,True
ltdb_import_det,SKIP_BLANK_VALUES,True
ltdb_import_det,SKIP_SPECIFIC_VALUES,True
ltdb_import_det,CHANGE_DATE_TIME,True
ltdb_import_det,CHANGE_UID,True
booktb_adj_comment,DISTRICT,True
booktb_adj_comment,CODE,True
booktb_adj_comment,DESCRIPTION,True
booktb_adj_comment,ACTIVE,True
booktb_adj_comment,CHANGE_DATE_TIME,True
booktb_adj_comment,CHANGE_UID,True
atttb_state_grp,DISTRICT,True
atttb_state_grp,CODE,True
atttb_state_grp,DESCRIPTION,True
atttb_state_grp,ACTIVE,True
atttb_state_grp,CHANGE_DATE_TIME,True
atttb_state_grp,CHANGE_UID,True
atttb_sif_type,DISTRICT,True
atttb_sif_type,CODE,True
atttb_sif_type,DESCRIPTION,True
atttb_sif_type,ACTIVE,True
atttb_sif_type,CHANGE_DATE_TIME,True
atttb_sif_type,CHANGE_UID,True
atttb_sif_status,DISTRICT,True
atttb_sif_status,CODE,True
atttb_sif_status,DESCRIPTION,True
atttb_sif_status,ACTIVE,True
atttb_sif_status,CHANGE_DATE_TIME,True
atttb_sif_status,CHANGE_UID,True
atttb_ineligible,DISTRICT,True
atttb_ineligible,CODE,True
atttb_ineligible,DESCRIPTION,True
atttb_ineligible,ACTIVE,True
atttb_ineligible,CHANGE_DATE_TIME,True
atttb_ineligible,CHANGE_UID,True
Att_view_per,DISTRICT,True
Att_view_per,SCHOOL_YEAR,True
Att_view_per,SUMMER_SCHOOL,True
Att_view_per,BUILDING,True
Att_view_per,VIEW_TYPE,True
Att_view_per,CRITERIA,True
Att_view_per,ATTENDANCE_PERIOD,True
Att_view_per,CHANGE_DATE_TIME,True
Att_view_per,CHANGE_UID,True
att_view_mse_bldg,DISTRICT,True
att_view_mse_bldg,SCHOOL_YEAR,True
att_view_mse_bldg,SUMMER_SCHOOL,True
att_view_mse_bldg,BUILDING,True
att_view_mse_bldg,VIEW_TYPE,True
att_view_mse_bldg,MSE_BUILDING,True
att_view_mse_bldg,CHANGE_DATE_TIME,True
att_view_mse_bldg,CHANGE_UID,True
ssp_qual_hdr,DISTRICT,True
ssp_qual_hdr,QUALIFICATION,True
ssp_qual_hdr,DESCRIPTION,True
ssp_qual_hdr,QUAL_REASON,True
ssp_qual_hdr,CHANGE_DATE_TIME,True
ssp_qual_hdr,CHANGE_UID,True
ltdb_import_def,district,True
ltdb_import_def,interface_id,True
ltdb_import_def,description,True
ltdb_import_def,change_date_time,True
ltdb_import_def,change_uid,True
ssp_parent_objective,DISTRICT,True
ssp_parent_objective,STUDENT_ID,True
ssp_parent_objective,PLAN_NUM,True
ssp_parent_objective,GOAL,True
ssp_parent_objective,OBJECTIVE,True
ssp_parent_objective,SEQUENCE_NUM,True
ssp_parent_objective,COMMENT,True
ssp_parent_objective,COMMENT_ORDER,True
ssp_parent_objective,COMPLETION_DATE,True
ssp_parent_objective,CHANGE_DATE_TIME,True
ssp_parent_objective,CHANGE_UID,True
ltdb_stu_test,DISTRICT,True
ltdb_stu_test,TEST_CODE,True
ltdb_stu_test,TEST_LEVEL,True
ltdb_stu_test,TEST_FORM,True
ltdb_stu_test,TEST_KEY,True
ltdb_stu_test,STUDENT_ID,True
ltdb_stu_test,TEST_DATE,True
ltdb_stu_test,TRANSCRIPT_PRINT,True
ltdb_stu_test,BUILDING,True
ltdb_stu_test,GRADE,True
ltdb_stu_test,AGE,True
ltdb_stu_test,CHANGE_DATE_TIME,True
ltdb_stu_test,CHANGE_UID,True
SSP_INTERVENTION,DISTRICT,True
SSP_INTERVENTION,INTERVENTION,True
SSP_INTERVENTION,DESCRIPTION,True
SSP_INTERVENTION,INTERVEN_TYPE,True
SSP_INTERVENTION,FREQUENCY,True
SSP_INTERVENTION,FREQ_WEEKDAY,True
SSP_INTERVENTION,STATE_COURSE_EQUIV,True
SSP_INTERVENTION,ACTIVE,True
SSP_INTERVENTION,CHANGE_DATE_TIME,True
SSP_INTERVENTION,CHANGE_UID,True
SSP_COORDINATOR,DISTRICT,True
SSP_COORDINATOR,BUILDING,True
SSP_COORDINATOR,REFER_SEQUENCE,True
SSP_COORDINATOR,SSP_REFER_TAG,True
SSP_COORDINATOR,REFER_TO,True
SSP_COORDINATOR,REFER_SEQ_ORDER,True
SSP_COORDINATOR,LOGIN_ID,True
SSP_COORDINATOR,USE_FILTER,True
SSP_COORDINATOR,CHANGE_DATE_TIME,True
SSP_COORDINATOR,CHANGE_UID,True
ssp_qual_det,DISTRICT,True
ssp_qual_det,QUALIFICATION,True
ssp_qual_det,QUAL_REASON,True
ssp_qual_det,QUAL_TYPE,True
ssp_qual_det,SEQUENCE_NUM,True
ssp_qual_det,START_DATE,True
ssp_qual_det,END_DATE,True
ssp_qual_det,TEST_CODE,True
ssp_qual_det,TEST_LEVEL,True
ssp_qual_det,TEST_FORM,True
ssp_qual_det,SUBTEST,True
ssp_qual_det,GRADE,True
ssp_qual_det,SCORE_CODE,True
ssp_qual_det,CONDITION,True
ssp_qual_det,QUAL_VALUE,True
ssp_qual_det,AIS_QUALIFIER,True
ssp_qual_det,CHANGE_DATE_TIME,True
ssp_qual_det,CHANGE_UID,True
atttb_district_grp,DISTRICT,True
atttb_district_grp,CODE,True
atttb_district_grp,DESCRIPTION,True
atttb_district_grp,ACTIVE,True
atttb_district_grp,CHANGE_DATE_TIME,True
atttb_district_grp,CHANGE_UID,True
book_req_hdr,DISTRICT,True
book_req_hdr,ORDER_NUMBER,True
book_req_hdr,REQUESTOR,True
book_req_hdr,BUILDING,True
book_req_hdr,DATE_ENTERED,True
book_req_hdr,DATE_PRINTED,True
book_req_hdr,DATE_SENT,True
book_req_hdr,STATUS,True
book_req_hdr,LAST_SHIPPED,True
book_req_hdr,LAST_RECEIVED,True
book_req_hdr,DATE_CLOSED,True
book_req_hdr,SCREEN_ENTRY,True
book_req_hdr,NOTES,True
book_req_hdr,TRANSFER_FROM,True
book_req_hdr,NEXT_YEAR_REQ,True
book_req_hdr,REF_ORDER_NUMBER,True
book_req_hdr,CHANGE_DATE_TIME,True
book_req_hdr,CHANGE_UID,True
ssp_parent_goal,DISTRICT,True
ssp_parent_goal,STUDENT_ID,True
ssp_parent_goal,PLAN_NUM,True
ssp_parent_goal,GOAL,True
ssp_parent_goal,COMPLETION_DATE,True
ssp_parent_goal,COMMENT,True
ssp_parent_goal,ENTERED_BY,True
ssp_parent_goal,CHANGE_DATE_TIME,True
ssp_parent_goal,CHANGE_UID,True
schd_params_sort,DISTRICT,True
schd_params_sort,SCHOOL_YEAR,True
schd_params_sort,SUMMER_SCHOOL,True
schd_params_sort,BUILDING,True
schd_params_sort,SORT_ORDER,True
schd_params_sort,ORDER_CODE,True
schd_params_sort,CHANGE_DATE_TIME,True
schd_params_sort,CHANGE_UID,True
schd_params,DISTRICT,True
schd_params,SCHOOL_YEAR,True
schd_params,SUMMER_SCHOOL,True
schd_params,BUILDING,True
schd_params,OVERRIDE_SEATS,True
schd_params,OVERRIDE_HOUSETEAM,True
schd_params,IGNORED_PRIORITIES,True
schd_params,STUDENT_ALT,True
schd_params,COURSE_ALT,True
schd_params,STUDENT_COURSE_ALT,True
schd_params,SCHD_INTERVAL,True
schd_params,PRESERVE_SCHEDULE,True
schd_params,BALANCE_CRITERIA,True
schd_params,MAXIMUM_TRIES,True
schd_params,USE_BALANCING,True
schd_params,MAXIMUM_IMBALANCE,True
schd_params,MAXIMUM_RESHUFFLE,True
schd_params,MAXIMUM_RESCHEDULE,True
schd_params,SECONDS_TIMEOUT,True
schd_params,MATCH_PERIODS_ONLY,True
schd_params,CHANGE_DATE_TIME,True
schd_params,CHANGE_UID,True
schd_msb_meet_per,DISTRICT,True
schd_msb_meet_per,MEETING_KEY,True
schd_msb_meet_per,SEQUENCE_NUM,True
schd_msb_meet_per,PERIOD,True
schd_msb_meet_per,CHANGE_DATE_TIME,True
schd_msb_meet_per,CHANGE_UID,True
book_assign,DISTRICT,True
book_assign,BAR_CODE,True
book_assign,ISBN_CODE,True
book_assign,BOOK_TYPE,True
book_assign,BUILDING,True
book_assign,ASSIGNED_TO,True
book_assign,DATE_ASSIGNED,True
book_assign,WHO_HAS_BOOK,True
book_assign,PENDING_TRANSFER,True
book_assign,STATUS,True
book_assign,CHANGE_DATE_TIME,True
book_assign,CHANGE_UID,True
schd_msb_meet_hdr,DISTRICT,True
schd_msb_meet_hdr,SCHOOL_YEAR,True
schd_msb_meet_hdr,BUILDING,True
schd_msb_meet_hdr,MEETING_CODE,True
schd_msb_meet_hdr,MEETING_KEY,True
schd_msb_meet_hdr,DESCRIPTION,True
schd_msb_meet_hdr,CHANGE_DATE_TIME,True
schd_msb_meet_hdr,CHANGE_UID,True
schd_msb_meet_cyc,DISTRICT,True
schd_msb_meet_cyc,MEETING_KEY,True
schd_msb_meet_cyc,SEQUENCE_NUM,True
schd_msb_meet_cyc,CYCLE_CODE,True
schd_msb_meet_cyc,CHANGE_DATE_TIME,True
schd_msb_meet_cyc,CHANGE_UID,True
schd_rec_taken,DISTRICT,True
schd_rec_taken,SECTION_KEY,True
schd_rec_taken,LOGIN_ID,True
schd_rec_taken,CHANGE_DATE_TIME,True
schd_rec_taken,CHANGE_UID,True
schd_period,DISTRICT,True
schd_period,SCHOOL_YEAR,True
schd_period,SUMMER_SCHOOL,True
schd_period,BUILDING,True
schd_period,CODE,True
schd_period,DESCRIPTION,True
schd_period,PERIOD_ORDER,True
schd_period,STANDARD_PERIOD,True
schd_period,STATE_CODE_EQUIV,True
schd_period,ROW_IDENTITY,True
schd_period,CHANGE_DATE_TIME,True
schd_period,CHANGE_UID,True
schd_ms_subj,DISTRICT,True
schd_ms_subj,SECTION_KEY,True
schd_ms_subj,COURSE_SESSION,True
schd_ms_subj,SUBJECT_AREA,True
schd_ms_subj,SUBJ_ORDER,True
schd_ms_subj,SUB_AREA,True
schd_ms_subj,ROW_IDENTITY,True
schd_ms_subj,CHANGE_DATE_TIME,True
schd_ms_subj,CHANGE_UID,True
schd_ms_study_seat,DISTRICT,True
schd_ms_study_seat,SECTION_KEY,True
schd_ms_study_seat,COURSE_SESSION,True
schd_ms_study_seat,MARKING_PERIOD,True
schd_ms_study_seat,CYCLE_CODE,True
schd_ms_study_seat,USED_SEATS,True
schd_ms_study_seat,CHANGE_DATE_TIME,True
schd_ms_study_seat,CHANGE_UID,True
SCHD_MS_STAFF_USER,DISTRICT,True
SCHD_MS_STAFF_USER,SECTION_KEY,True
SCHD_MS_STAFF_USER,COURSE_SESSION,True
SCHD_MS_STAFF_USER,STAFF_ID,True
SCHD_MS_STAFF_USER,FIELD_NUMBER,True
SCHD_MS_STAFF_USER,START_DATE,True
SCHD_MS_STAFF_USER,SEQUENCE,True
SCHD_MS_STAFF_USER,END_DATE,True
SCHD_MS_STAFF_USER,FIELD_VALUE,True
SCHD_MS_STAFF_USER,CHANGE_DATE_TIME,True
SCHD_MS_STAFF_USER,CHANGE_UID,True
SCHD_MS_STAFF_DATE,DISTRICT,True
SCHD_MS_STAFF_DATE,SECTION_KEY,True
SCHD_MS_STAFF_DATE,COURSE_SESSION,True
SCHD_MS_STAFF_DATE,STAFF_ID,True
SCHD_MS_STAFF_DATE,START_DATE,True
SCHD_MS_STAFF_DATE,SEQUENCE,True
SCHD_MS_STAFF_DATE,END_DATE,True
SCHD_MS_STAFF_DATE,PRIMARY_SECONDARY,True
SCHD_MS_STAFF_DATE,COTEACHER,True
SCHD_MS_STAFF_DATE,CHANGE_DATE_TIME,True
SCHD_MS_STAFF_DATE,CHANGE_UID,True
schd_ms_staff,DISTRICT,True
schd_ms_staff,SECTION_KEY,True
schd_ms_staff,COURSE_SESSION,True
schd_ms_staff,STAFF_ID,True
schd_ms_staff,ROW_IDENTITY,True
schd_ms_staff,CHANGE_DATE_TIME,True
schd_ms_staff,CHANGE_UID,True
schd_ms_subj_tag,DISTRICT,True
schd_ms_subj_tag,SECTION_KEY,True
schd_ms_subj_tag,COURSE_SESSION,True
schd_ms_subj_tag,SUBJECT_AREA,True
schd_ms_subj_tag,TAG,True
schd_ms_subj_tag,CHANGE_DATE_TIME,True
schd_ms_subj_tag,CHANGE_UID,True
schd_ms_qualify,DISTRICT,True
schd_ms_qualify,SECTION_KEY,True
schd_ms_qualify,QUALIFICATION,True
schd_ms_qualify,CHANGE_DATE_TIME,True
schd_ms_qualify,CHANGE_UID,True
schd_ms_mp,DISTRICT,True
schd_ms_mp,SECTION_KEY,True
schd_ms_mp,COURSE_SESSION,True
schd_ms_mp,MARKING_PERIOD,True
schd_ms_mp,USED_SEATS,True
schd_ms_mp,CLASSIFICATION_WEIGHT,True
schd_ms_mp,ROW_IDENTITY,True
schd_ms_mp,CHANGE_DATE_TIME,True
schd_ms_mp,CHANGE_UID,True
feetb_unit_descr,DISTRICT,True
feetb_unit_descr,SCHOOL_YEAR,True
feetb_unit_descr,CODE,True
feetb_unit_descr,DESCRIPTION,True
feetb_unit_descr,CHANGE_DATE_TIME,True
feetb_unit_descr,CHANGE_UID,True
feetb_sub_category,DISTRICT,True
feetb_sub_category,SCHOOL_YEAR,True
feetb_sub_category,CODE,True
feetb_sub_category,DESCRIPTION,True
feetb_sub_category,CHANGE_DATE_TIME,True
feetb_sub_category,CHANGE_UID,True
feetb_stu_status,DISTRICT,True
feetb_stu_status,SCHOOL_YEAR,True
feetb_stu_status,CODE,True
feetb_stu_status,DESCRIPTION,True
feetb_stu_status,THRESHOLD_AMOUNT,True
feetb_stu_status,CHANGE_DATE_TIME,True
feetb_stu_status,CHANGE_UID,True
schd_ms_user,DISTRICT,True
schd_ms_user,SECTION_KEY,True
schd_ms_user,SCREEN_NUMBER,True
schd_ms_user,FIELD_NUMBER,True
schd_ms_user,LIST_SEQUENCE,True
schd_ms_user,FIELD_VALUE,True
schd_ms_user,CHANGE_DATE_TIME,True
schd_ms_user,CHANGE_UID,True
feetb_category,DISTRICT,True
feetb_category,SCHOOL_YEAR,True
feetb_category,CODE,True
feetb_category,DESCRIPTION,True
feetb_category,CHANGE_DATE_TIME,True
feetb_category,CHANGE_UID,True
schd_ms_session,DISTRICT,True
schd_ms_session,SECTION_KEY,True
schd_ms_session,COURSE_SESSION,True
schd_ms_session,DESCRIPTION,True
schd_ms_session,START_PERIOD,True
schd_ms_session,END_PERIOD,True
schd_ms_session,TAKE_ATTENDANCE,True
schd_ms_session,RECEIVE_MARK,True
schd_ms_session,CREDIT,True
schd_ms_session,PRIMARY_STAFF_ID,True
schd_ms_session,ROOM_ID,True
schd_ms_session,COURSE_LEVEL,True
schd_ms_session,INCLD_PASSING_TIME,True
schd_ms_session,USE_FOCUS,True
schd_ms_session,ROW_IDENTITY,True
schd_ms_session,CHANGE_DATE_TIME,True
schd_ms_session,CHANGE_UID,True
fee_stu_payment,DISTRICT,True
fee_stu_payment,PAYMENT_ID,True
fee_stu_payment,SCHOOL_YEAR,True
fee_stu_payment,SUMMER_SCHOOL,True
fee_stu_payment,BUILDING,True
fee_stu_payment,STUDENT_ID,True
fee_stu_payment,PAYMENT_ID_DISPLAY,True
fee_stu_payment,PAYMENT_DATE,True
fee_stu_payment,REVERSE_FLAG,True
fee_stu_payment,PAYMENT_TYPE_CODE,True
fee_stu_payment,REFERENCE_NUMBER,True
fee_stu_payment,COMMENT,True
fee_stu_payment,TOTAL_PAID,True
fee_stu_payment,CHANGE_DATE_TIME,True
fee_stu_payment,CHANGE_UID,True
fee_stu_item,DISTRICT,True
fee_stu_item,TRACKING_NUMBER,True
fee_stu_item,SCHOOL_YEAR,True
fee_stu_item,SUMMER_SCHOOL,True
fee_stu_item,BUILDING,True
fee_stu_item,STUDENT_ID,True
fee_stu_item,DATE_CREATED,True
fee_stu_item,ITEM_CODE,True
fee_stu_item,TRACKING_NUMBER_DISPLAY,True
fee_stu_item,TEXTBOOK_CODE,True
fee_stu_item,DESCRIPTION,True
fee_stu_item,FEE_GROUP_CODE,True
fee_stu_item,SEQUENCE_ORDER,True
fee_stu_item,QUANTITY,True
fee_stu_item,UNIT_COST,True
fee_stu_item,UNIT_COST_OVR,True
fee_stu_item,TOTAL_PAID,True
fee_stu_item,TOTAL_CREDIT_APPLY,True
fee_stu_item,TOTAL_REFUND,True
fee_stu_item,BALANCE,True
fee_stu_item,REFUND_PRT_CHECK,True
fee_stu_item,PRORATED_ADD,True
fee_stu_item,PRORATED_DROP,True
fee_stu_item,PRORATED_RESOLVED,True
fee_stu_item,PRORATED_CLEAR,True
fee_stu_item,FEE_SUB_CATEGORY,True
fee_stu_item,CHANGE_DATE_TIME,True
fee_stu_item,CHANGE_UID,True
fee_stu_group,DISTRICT,True
fee_stu_group,SCHOOL_YEAR,True
fee_stu_group,SUMMER_SCHOOL,True
fee_stu_group,BUILDING,True
fee_stu_group,FEE_GROUP_CODE,True
fee_stu_group,STUDENT_ID,True
fee_stu_group,CHANGE_DATE_TIME,True
fee_stu_group,CHANGE_UID,True
schd_msb_meet_det,DISTRICT,True
schd_msb_meet_det,MEETING_KEY,True
schd_msb_meet_det,SEQUENCE_NUM,True
schd_msb_meet_det,JOIN_CONDITION,True
schd_msb_meet_det,CYCLES_SELECTED,True
schd_msb_meet_det,PERIODS_SELECTED,True
schd_msb_meet_det,CHANGE_DATE_TIME,True
schd_msb_meet_det,CHANGE_UID,True
schd_resource,DISTRICT,True
schd_resource,BUILDING,True
schd_resource,GROUP_TYPE,True
schd_resource,GROUP_CODE,True
schd_resource,GROUP_DESCRIPTION,True
schd_resource,CHANGE_DATE_TIME,True
schd_resource,CHANGE_UID,True
fee_group_hdr,DISTRICT,True
fee_group_hdr,SCHOOL_YEAR,True
fee_group_hdr,SUMMER_SCHOOL,True
fee_group_hdr,BUILDING,True
fee_group_hdr,FEE_GROUP_CODE,True
fee_group_hdr,DESCRIPTION,True
fee_group_hdr,FEE_TYPE,True
fee_group_hdr,REDUCED_RATE,True
fee_group_hdr,FREQUENCY,True
fee_group_hdr,COURSE_OR_ACTIVITY,True
fee_group_hdr,CHANGE_DATE_TIME,True
fee_group_hdr,CHANGE_UID,True
fee_group_det,DISTRICT,True
fee_group_det,SCHOOL_YEAR,True
fee_group_det,SUMMER_SCHOOL,True
fee_group_det,BUILDING,True
fee_group_det,FEE_GROUP_CODE,True
fee_group_det,SEQUENCE_ORDER,True
fee_group_det,ITEM_CODE,True
fee_group_det,TEXTBOOK_CODE,True
fee_group_det,DESCRIPTION,True
fee_group_det,QUANTITY,True
fee_group_det,UNIT_COST,True
fee_group_det,CAN_PRORATE,True
fee_group_det,STAFF_ID_RESTR,True
fee_group_det,CRS_SECTION_RESTR,True
fee_group_det,COMMENT,True
fee_group_det,CHANGE_DATE_TIME,True
fee_group_det,CHANGE_UID,True
fee_group_crit,DISTRICT,True
fee_group_crit,SCHOOL_YEAR,True
fee_group_crit,SUMMER_SCHOOL,True
fee_group_crit,BUILDING,True
fee_group_crit,FEE_GROUP_CODE,True
fee_group_crit,SEQUENCE_NUM,True
fee_group_crit,AND_OR_FLAG,True
fee_group_crit,TABLE_NAME,True
fee_group_crit,SCREEN_TYPE,True
fee_group_crit,SCREEN_NUMBER,True
fee_group_crit,COLUMN_NAME,True
fee_group_crit,FIELD_NUMBER,True
fee_group_crit,OPERATOR,True
fee_group_crit,SEARCH_VALUE,True
fee_group_crit,CHANGE_DATE_TIME,True
fee_group_crit,CHANGE_UID,True
disctb_wit_subcode,DISTRICT,True
disctb_wit_subcode,CODE,True
disctb_wit_subcode,DESCRIPTION,True
disctb_wit_subcode,ACTIVE,True
disctb_wit_subcode,CHANGE_DATE_TIME,True
disctb_wit_subcode,CHANGE_UID,True
fee_stu_audit,DISTRICT,True
fee_stu_audit,AUDIT_NUMBER,True
fee_stu_audit,SCHOOL_YEAR,True
fee_stu_audit,SUMMER_SCHOOL,True
fee_stu_audit,BUILDING,True
fee_stu_audit,STUDENT_ID,True
fee_stu_audit,DATE_CREATED,True
fee_stu_audit,TRACKING_NUMBER,True
fee_stu_audit,ACTION_CODE,True
fee_stu_audit,PAYMENT_ID,True
fee_stu_audit,QUANTITY,True
fee_stu_audit,UNIT_COST,True
fee_stu_audit,COST_AMOUNT,True
fee_stu_audit,CREDIT_AMOUNT,True
fee_stu_audit,COMMENT,True
fee_stu_audit,CHANGE_DATE_TIME,True
fee_stu_audit,CHANGE_UID,True
fee_item,DISTRICT,True
fee_item,SCHOOL_YEAR,True
fee_item,BUILDING,True
fee_item,ITEM_CODE,True
fee_item,FEE_TYPE,True
fee_item,DESCRIPTION,True
fee_item,UNIT_COST,True
fee_item,UNIT_DESCR_CODE,True
fee_item,PRIORITY,True
fee_item,CAN_PRORATE,True
fee_item,FEE_CATEGORY,True
fee_item,FEE_SUB_CATEGORY,True
fee_item,CHANGE_DATE_TIME,True
fee_item,CHANGE_UID,True
feetb_payment,DISTRICT,True
feetb_payment,SCHOOL_YEAR,True
feetb_payment,CODE,True
feetb_payment,DESCRIPTION,True
feetb_payment,CHANGE_DATE_TIME,True
feetb_payment,CHANGE_UID,True
disctb_vic_reason,DISTRICT,True
disctb_vic_reason,CODE,True
disctb_vic_reason,DESCRIPTION,True
disctb_vic_reason,STATE_CODE_EQUIV,True
disctb_vic_reason,ACTIVE,True
disctb_vic_reason,CHANGE_DATE_TIME,True
disctb_vic_reason,CHANGE_UID,True
fee_textbook,DISTRICT,True
fee_textbook,SCHOOL_YEAR,True
fee_textbook,BUILDING,True
fee_textbook,TEXTBOOK_CODE,True
fee_textbook,DEPARTMENT,True
fee_textbook,DESCRIPTION,True
fee_textbook,UNIT_COST,True
fee_textbook,ISBN,True
fee_textbook,PUBLISHER,True
fee_textbook,COMMENT,True
fee_textbook,CHANGE_DATE_TIME,True
fee_textbook,CHANGE_UID,True
disctb_vic_code,DISTRICT,True
disctb_vic_code,CODE,True
disctb_vic_code,DESCRIPTION,True
disctb_vic_code,STATE_CODE_EQUIV,True
disctb_vic_code,ACTIVE,True
disctb_vic_code,CHANGE_DATE_TIME,True
disctb_vic_code,CHANGE_UID,True
disctb_vic_action,DISTRICT,True
disctb_vic_action,CODE,True
disctb_vic_action,DESCRIPTION,True
disctb_vic_action,STATE_CODE_EQUIV,True
disctb_vic_action,ACTIVE,True
disctb_vic_action,CHANGE_DATE_TIME,True
disctb_vic_action,CHANGE_UID,True
disctb_timeframe,DISTRICT,True
disctb_timeframe,CODE,True
disctb_timeframe,DESCRIPTION,True
disctb_timeframe,STATE_CODE_EQUIV,True
disctb_timeframe,ACTIVE,True
disctb_timeframe,CHANGE_DATE_TIME,True
disctb_timeframe,CHANGE_UID,True
disctb_vic_subcode,DISTRICT,True
disctb_vic_subcode,CODE,True
disctb_vic_subcode,DESCRIPTION,True
disctb_vic_subcode,ACTIVE,True
disctb_vic_subcode,CHANGE_DATE_TIME,True
disctb_vic_subcode,CHANGE_UID,True
disctb_reason,DISTRICT,True
disctb_reason,CODE,True
disctb_reason,DESCRIPTION,True
disctb_reason,STATE_CODE_EQUIV,True
disctb_reason,ACTIVE,True
disctb_reason,CHANGE_DATE_TIME,True
disctb_reason,CHANGE_UID,True
disctb_police_act,DISTRICT,True
disctb_police_act,CODE,True
disctb_police_act,DESCRIPTION,True
disctb_police_act,ACTIVE,True
disctb_police_act,STATE_CODE_EQUIV,True
disctb_police_act,CHANGE_DATE_TIME,True
disctb_police_act,CHANGE_UID,True
disctb_off_subcode,DISTRICT,True
disctb_off_subcode,CODE,True
disctb_off_subcode,DESCRIPTION,True
disctb_off_subcode,ACTIVE,True
disctb_off_subcode,CHANGE_DATE_TIME,True
disctb_off_subcode,CHANGE_UID,True
disctb_wit_code,DISTRICT,True
disctb_wit_code,CODE,True
disctb_wit_code,DESCRIPTION,True
disctb_wit_code,ACTIVE,True
disctb_wit_code,CHANGE_DATE_TIME,True
disctb_wit_code,CHANGE_UID,True
disctb_weapon,DISTRICT,True
disctb_weapon,CODE,True
disctb_weapon,DESCRIPTION,True
disctb_weapon,STATE_CODE_EQUIV,True
disctb_weapon,ACTIVE,True
disctb_weapon,SEVERITY_ORDER,True
disctb_weapon,CHANGE_DATE_TIME,True
disctb_weapon,CHANGE_UID,True
disctb_referral,DISTRICT,True
disctb_referral,CODE,True
disctb_referral,DESCRIPTION,True
disctb_referral,ACTIVE,True
disctb_referral,CHANGE_DATE_TIME,True
disctb_referral,CHANGE_UID,True
disctb_location,DISTRICT,True
disctb_location,CODE,True
disctb_location,DESCRIPTION,True
disctb_location,STATE_CODE_EQUIV,True
disctb_location,ACTIVE,True
disctb_location,CHANGE_DATE_TIME,True
disctb_location,CHANGE_UID,True
disctb_injury,DISTRICT,True
disctb_injury,CODE,True
disctb_injury,DESCRIPTION,True
disctb_injury,STATE_CODE_EQUIV,True
disctb_injury,ACTIVE,True
disctb_injury,CHANGE_DATE_TIME,True
disctb_injury,CHANGE_UID,True
disctb_off_action,DISTRICT,True
disctb_off_action,CODE,True
disctb_off_action,DESCRIPTION,True
disctb_off_action,LEVEL_NUMBER,True
disctb_off_action,ATTENDANCE_CODE,True
disctb_off_action,CARRYOVER,True
disctb_off_action,STATE_CODE_EQUIV,True
disctb_off_action,ACTIVE,True
disctb_off_action,SEVERITY_LEVEL,True
disctb_off_action,SIF_CODE,True
disctb_off_action,CHANGE_DATE_TIME,True
disctb_off_action,CHANGE_UID,True
disctb_inc_subcode,DISTRICT,True
disctb_inc_subcode,CODE,True
disctb_inc_subcode,DESCRIPTION,True
disctb_inc_subcode,ACTIVE,True
disctb_inc_subcode,CHANGE_DATE_TIME,True
disctb_inc_subcode,CHANGE_UID,True
disctb_disposition,DISTRICT,True
disctb_disposition,CODE,True
disctb_disposition,DESCRIPTION,True
disctb_disposition,STATE_CODE_EQUIV,True
disctb_disposition,ACTIVE,True
disctb_disposition,CHANGE_DATE_TIME,True
disctb_disposition,CHANGE_UID,True
disctb_conviction,DISTRICT,True
disctb_conviction,CODE,True
disctb_conviction,DESCRIPTION,True
disctb_conviction,ACTIVE,True
disctb_conviction,CHANGE_DATE_TIME,True
disctb_conviction,CHANGE_UID,True
disctb_vic_disp,DISTRICT,True
disctb_vic_disp,CODE,True
disctb_vic_disp,DESCRIPTION,True
disctb_vic_disp,STATE_CODE_EQUIV,True
disctb_vic_disp,ACTIVE,True
disctb_vic_disp,CHANGE_DATE_TIME,True
disctb_vic_disp,CHANGE_UID,True
disctb_act_outcome,DISTRICT,True
disctb_act_outcome,CODE,True
disctb_act_outcome,DESCRIPTION,True
disctb_act_outcome,STATE_CODE_EQUIV,True
disctb_act_outcome,ACTIVE,True
disctb_act_outcome,CHANGE_DATE_TIME,True
disctb_act_outcome,CHANGE_UID,True
disc_witness,DISTRICT,True
disc_witness,SCHOOL_YEAR,True
disc_witness,SUMMER_SCHOOL,True
disc_witness,BUILDING,True
disc_witness,INCIDENT_ID,True
disc_witness,WITNESS,True
disc_witness,WITNESS_CODE,True
disc_witness,WITNESS_SUBCODE,True
disc_witness,IS_STUDENT,True
disc_witness,PERSON_ID,True
disc_witness,GUARDIAN_NOTIFIED,True
disc_witness,NOTIFY_DATE,True
disc_witness,HOW_NOTIFIED,True
disc_witness,REFERRED_TO,True
disc_witness,ROW_IDENTITY,True
disc_witness,CHANGE_DATE_TIME,True
disc_witness,CHANGE_UID,True
schd_restriction,DISTRICT,True
schd_restriction,BUILDING,True
schd_restriction,GROUP_TYPE,True
schd_restriction,RESOURCE_ID,True
schd_restriction,PERIOD,True
schd_restriction,MARKING_PERIOD,True
schd_restriction,CYCLE,True
schd_restriction,CHANGE_DATE_TIME,True
schd_restriction,CHANGE_UID,True
disc_victim_action,DISTRICT,True
disc_victim_action,SCHOOL_YEAR,True
disc_victim_action,SUMMER_SCHOOL,True
disc_victim_action,BUILDING,True
disc_victim_action,INCIDENT_ID,True
disc_victim_action,VICTIM,True
disc_victim_action,ACTION_NUMBER,True
disc_victim_action,ACTION_CODE,True
disc_victim_action,SCHD_DURATION,True
disc_victim_action,ACTUAL_DURATION,True
disc_victim_action,REASON_CODE,True
disc_victim_action,DISPOSITION_CODE,True
disc_victim_action,START_DATE,True
disc_victim_action,END_DATE,True
disc_victim_action,RESP_BUILDING,True
disc_victim_action,DATE_DETERMINED,True
disc_victim_action,ACTION_OUTCOME,True
disc_victim_action,CHANGE_DATE_TIME,True
disc_victim_action,CHANGE_UID,True
disc_victim,DISTRICT,True
disc_victim,SCHOOL_YEAR,True
disc_victim,SUMMER_SCHOOL,True
disc_victim,BUILDING,True
disc_victim,INCIDENT_ID,True
disc_victim,VICTIM,True
disc_victim,VICTIM_CODE,True
disc_victim,VICTIM_SUBCODE,True
disc_victim,IS_STUDENT,True
disc_victim,PERSON_ID,True
disc_victim,HOSPITAL_CODE,True
disc_victim,DOCTOR,True
disc_victim,GUARDIAN_NOTIFIED,True
disc_victim,NOTIFY_DATE,True
disc_victim,HOW_NOTIFIED,True
disc_victim,REFERRED_TO,True
disc_victim,ROW_IDENTITY,True
disc_victim,CHANGE_DATE_TIME,True
disc_victim,CHANGE_UID,True
disc_user,DISTRICT,True
disc_user,SCHOOL_YEAR,True
disc_user,SUMMER_SCHOOL,True
disc_user,BUILDING,True
disc_user,INCIDENT_ID,True
disc_user,SCREEN_TYPE,True
disc_user,OFF_VIC_WIT_ID,True
disc_user,SCREEN_NUMBER,True
disc_user,FIELD_NUMBER,True
disc_user,FIELD_VALUE,True
disc_user,CHANGE_DATE_TIME,True
disc_user,CHANGE_UID,True
disc_stu_rollover,DISTRICT,True
disc_stu_rollover,STUDENT_ID,True
disc_stu_rollover,FIRST_NAME,True
disc_stu_rollover,MIDDLE_NAME,True
disc_stu_rollover,LAST_NAME,True
disc_stu_rollover,GENERATION,True
disc_stu_rollover,APARTMENT,True
disc_stu_rollover,COMPLEX,True
disc_stu_rollover,STREET_NUMBER,True
disc_stu_rollover,STREET_NAME,True
disc_stu_rollover,CITY,True
disc_stu_rollover,STATE,True
disc_stu_rollover,ZIP,True
disc_stu_rollover,PHONE,True
disc_stu_rollover,PHONE_EXTENSION,True
disc_stu_rollover,BIRTHDATE,True
disc_stu_rollover,GRADE,True
disc_stu_rollover,GENDER,True
disc_stu_rollover,ETHNIC_CODE,True
disc_stu_rollover,HISPANIC,True
disc_stu_rollover,FED_RACE_ETHNIC,True
disc_stu_rollover,CLASSIFICATION,True
disc_stu_rollover,STAFF_MEMBER,True
disc_stu_rollover,BUILDING,True
disc_stu_rollover,CHANGE_DATE_TIME,True
disc_stu_rollover,CHANGE_UID,True
disc_stu_eligible,DISTRICT,True
disc_stu_eligible,SCHOOL_YEAR,True
disc_stu_eligible,SUMMER_SCHOOL,True
disc_stu_eligible,BUILDING,True
disc_stu_eligible,DATE_RUN,True
disc_stu_eligible,RUN_NUMBER,True
disc_stu_eligible,STUDENT_ID,True
disc_stu_eligible,CRITERION,True
disc_stu_eligible,ELIGIBILITY_CODE,True
disc_stu_eligible,EFFECTIVE_DATE,True
disc_stu_eligible,EXPIRATION_DATE,True
disc_stu_eligible,CHANGE_DATE_TIME,True
disc_stu_eligible,CHANGE_UID,True
DISC_STU_AT_RISK,DISTRICT,True
DISC_STU_AT_RISK,SCHOOL_YEAR,True
DISC_STU_AT_RISK,SUMMER_SCHOOL,True
DISC_STU_AT_RISK,BUILDING,True
DISC_STU_AT_RISK,DATE_RUN,True
DISC_STU_AT_RISK,RUN_NUMBER,True
DISC_STU_AT_RISK,STUDENT_ID,True
DISC_STU_AT_RISK,CRITERION,True
DISC_STU_AT_RISK,AT_RISK_REASON,True
DISC_STU_AT_RISK,EFFECTIVE_DATE,True
DISC_STU_AT_RISK,EXPIRATION_DATE,True
DISC_STU_AT_RISK,PLAN_NUM,True
DISC_STU_AT_RISK,CHANGE_DATE_TIME,True
DISC_STU_AT_RISK,CHANGE_UID,True
disc_victim_injury,DISTRICT,True
disc_victim_injury,SCHOOL_YEAR,True
disc_victim_injury,SUMMER_SCHOOL,True
disc_victim_injury,BUILDING,True
disc_victim_injury,INCIDENT_ID,True
disc_victim_injury,VICTIM,True
disc_victim_injury,INJURY_CODE,True
disc_victim_injury,CHANGE_DATE_TIME,True
disc_victim_injury,CHANGE_UID,True
disctb_drug,DISTRICT,True
disctb_drug,CODE,True
disctb_drug,DESCRIPTION,True
disctb_drug,STATE_CODE_EQUIV,True
disctb_drug,ACTIVE,True
disctb_drug,CHANGE_DATE_TIME,True
disctb_drug,CHANGE_UID,True
disc_off_weapon,DISTRICT,True
disc_off_weapon,SCHOOL_YEAR,True
disc_off_weapon,SUMMER_SCHOOL,True
disc_off_weapon,BUILDING,True
disc_off_weapon,INCIDENT_ID,True
disc_off_weapon,OFFENDER,True
disc_off_weapon,WEAPON_CODE,True
disc_off_weapon,WEAPON_COUNT,True
disc_off_weapon,CHANGE_DATE_TIME,True
disc_off_weapon,CHANGE_UID,True
disctb_magistrate,DISTRICT,True
disctb_magistrate,CODE,True
disctb_magistrate,NAME,True
disctb_magistrate,STREET1,True
disctb_magistrate,STREET2,True
disctb_magistrate,CITY,True
disctb_magistrate,STATE,True
disctb_magistrate,ZIP,True
disctb_magistrate,PHONE,True
disctb_magistrate,FINE_BOTH,True
disctb_magistrate,ACTIVE,True
disctb_magistrate,CHANGE_DATE_TIME,True
disctb_magistrate,CHANGE_UID,True
disctb_charge,DISTRICT,True
disctb_charge,CODE,True
disctb_charge,DESCRIPTION,True
disctb_charge,ACTIVE,True
disctb_charge,CHANGE_DATE_TIME,True
disctb_charge,CHANGE_UID,True
disc_off_drug,DISTRICT,True
disc_off_drug,SCHOOL_YEAR,True
disc_off_drug,SUMMER_SCHOOL,True
disc_off_drug,BUILDING,True
disc_off_drug,INCIDENT_ID,True
disc_off_drug,OFFENDER,True
disc_off_drug,DRUG_CODE,True
disc_off_drug,CHANGE_DATE_TIME,True
disc_off_drug,CHANGE_UID,True
disc_off_convict,DISTRICT,True
disc_off_convict,SCHOOL_YEAR,True
disc_off_convict,SUMMER_SCHOOL,True
disc_off_convict,BUILDING,True
disc_off_convict,INCIDENT_ID,True
disc_off_convict,OFFENDER,True
disc_off_convict,CONVICTION_CODE,True
disc_off_convict,CHANGE_DATE_TIME,True
disc_off_convict,CHANGE_UID,True
disc_off_code,DISTRICT,True
disc_off_code,SCHOOL_YEAR,True
disc_off_code,SUMMER_SCHOOL,True
disc_off_code,BUILDING,True
disc_off_code,INCIDENT_ID,True
disc_off_code,OFFENDER,True
disc_off_code,OFFENSE_CODE,True
disc_off_code,OFFENSE_COMMENT,True
disc_off_code,CHANGE_DATE_TIME,True
disc_off_code,CHANGE_UID,True
disc_off_charge,DISTRICT,True
disc_off_charge,SCHOOL_YEAR,True
disc_off_charge,SUMMER_SCHOOL,True
disc_off_charge,BUILDING,True
disc_off_charge,INCIDENT_ID,True
disc_off_charge,OFFENDER,True
disc_off_charge,CHARGE_CODE,True
disc_off_charge,CHANGE_DATE_TIME,True
disc_off_charge,CHANGE_UID,True
disc_off_action,DISTRICT,True
disc_off_action,SCHOOL_YEAR,True
disc_off_action,SUMMER_SCHOOL,True
disc_off_action,BUILDING,True
disc_off_action,INCIDENT_ID,True
disc_off_action,OFFENDER,True
disc_off_action,ACTION_NUMBER,True
disc_off_action,ACTION_CODE,True
disc_off_action,SCHD_DURATION,True
disc_off_action,ACTUAL_DURATION,True
disc_off_action,REASON_CODE,True
disc_off_action,DISPOSITION_CODE,True
disc_off_action,START_DATE,True
disc_off_action,END_DATE,True
disc_off_action,TOTAL_OCCURRENCES,True
disc_off_action,RESP_BUILDING,True
disc_off_action,ASSIGN_BUILDING,True
disc_off_action,DATE_DETERMINED,True
disc_off_action,ACTION_OUTCOME,True
disc_off_action,YEAREND_CARRY_OVER,True
disc_off_action,ROW_IDENTITY,True
disc_off_action,CHANGE_DATE_TIME,True
disc_off_action,CHANGE_UID,True
disc_off_fine,DISTRICT,True
disc_off_fine,SCHOOL_YEAR,True
disc_off_fine,SUMMER_SCHOOL,True
disc_off_fine,BUILDING,True
disc_off_fine,INCIDENT_ID,True
disc_off_fine,OFFENDER,True
disc_off_fine,ACTION_NUMBER,True
disc_off_fine,PERSON_ID,True
disc_off_fine,IS_STUDENT,True
disc_off_fine,FINE_CODE,True
disc_off_fine,ISSUED_DATE,True
disc_off_fine,FINE_AMOUNT,True
disc_off_fine,PAID_DATE,True
disc_off_fine,COST,True
disc_off_fine,CITATION_NUMBER,True
disc_off_fine,STU_CITATION_NUM,True
disc_off_fine,MAGISTRATE_NUMBER,True
disc_off_fine,CHANGE_DATE_TIME,True
disc_off_fine,CHANGE_UID,True
disc_notes,DISTRICT,True
disc_notes,SCHOOL_YEAR,True
disc_notes,SUMMER_SCHOOL,True
disc_notes,BUILDING,True
disc_notes,INCIDENT_ID,True
disc_notes,NOTE_TYPE,True
disc_notes,OFF_VIC_WIT_ID,True
disc_notes,PAGE_NUMBER,True
disc_notes,NOTE_TEXT,True
disc_notes,PRIVATE,True
disc_notes,CHANGE_DATE_TIME,True
disc_notes,CHANGE_UID,True
disc_non_student,DISTRICT,True
disc_non_student,NON_STUDENT_ID,True
disc_non_student,FIRST_NAME,True
disc_non_student,MIDDLE_NAME,True
disc_non_student,LAST_NAME,True
disc_non_student,GENERATION,True
disc_non_student,APARTMENT,True
disc_non_student,COMPLEX,True
disc_non_student,STREET_NUMBER,True
disc_non_student,STREET_NAME,True
disc_non_student,CITY,True
disc_non_student,STATE,True
disc_non_student,ZIP,True
disc_non_student,PHONE,True
disc_non_student,PHONE_EXTENSION,True
disc_non_student,BIRTHDATE,True
disc_non_student,GRADE,True
disc_non_student,GENDER,True
disc_non_student,ETHNIC_CODE,True
disc_non_student,HISPANIC,True
disc_non_student,FED_RACE_ETHNIC,True
disc_non_student,CLASSIFICATION,True
disc_non_student,STAFF_MEMBER,True
disc_non_student,BUILDING,True
disc_non_student,PERSON_DIST_CODE,True
disc_non_student,ROW_IDENTITY,True
disc_non_student,CHANGE_DATE_TIME,True
disc_non_student,CHANGE_UID,True
disc_ltr_header,DISTRICT,True
disc_ltr_header,SCHOOL_YEAR,True
disc_ltr_header,SUMMER_SCHOOL,True
disc_ltr_header,BUILDING,True
disc_ltr_header,DATE_RUN,True
disc_ltr_header,RUN_NUMBER,True
disc_ltr_header,DATE_FROM,True
disc_ltr_header,DATE_THRU,True
disc_ltr_header,DATE_PRINTED,True
disc_ltr_header,LETTER_COUNT,True
disc_ltr_header,CHANGE_DATE_TIME,True
disc_ltr_header,CHANGE_UID,True
disc_ltr_header,DATE_NOTIFICATION_SENT,True
disc_offender,DISTRICT,True
disc_offender,SCHOOL_YEAR,True
disc_offender,SUMMER_SCHOOL,True
disc_offender,BUILDING,True
disc_offender,INCIDENT_ID,True
disc_offender,OFFENDER,True
disc_offender,IS_STUDENT,True
disc_offender,PERSON_ID,True
disc_offender,GUARDIAN_NOTIFIED,True
disc_offender,NOTIFY_DATE,True
disc_offender,HOW_NOTIFIED,True
disc_offender,REFERRED_TO,True
disc_offender,POLICE_ACTION,True
disc_offender,CHARGES_FILED_BY,True
disc_offender,CHARGES_FILED_WITH,True
disc_offender,RESP_ADMIN,True
disc_offender,ROW_IDENTITY,True
disc_offender,CHANGE_DATE_TIME,True
disc_offender,CHANGE_UID,True
disc_ltr_detail,DISTRICT,True
disc_ltr_detail,SCHOOL_YEAR,True
disc_ltr_detail,SUMMER_SCHOOL,True
disc_ltr_detail,BUILDING,True
disc_ltr_detail,DATE_RUN,True
disc_ltr_detail,RUN_NUMBER,True
disc_ltr_detail,STUDENT_ID,True
disc_ltr_detail,CRITERION,True
disc_ltr_detail,LETTER_RESET,True
disc_ltr_detail,OFFENSE_COUNT,True
disc_ltr_detail,ACTION_COUNT,True
disc_ltr_detail,PRINT_DONE,True
disc_ltr_detail,CHANGE_DATE_TIME,True
disc_ltr_detail,CHANGE_UID,True
disc_ltr_detail,NOTIFICATION_SENT,True
disc_ltr_crit_elig,DISTRICT,True
disc_ltr_crit_elig,SCHOOL_YEAR,True
disc_ltr_crit_elig,SUMMER_SCHOOL,True
disc_ltr_crit_elig,BUILDING,True
disc_ltr_crit_elig,CRITERION,True
disc_ltr_crit_elig,SEQUENCE_ORDER,True
disc_ltr_crit_elig,CURRENT_ELIG_STATUS,True
disc_ltr_crit_elig,ELIGIBILITY_CODE,True
disc_ltr_crit_elig,CHANGE_DATE_TIME,True
disc_ltr_crit_elig,CHANGE_UID,True
disc_ltr_crit_act,DISTRICT,True
disc_ltr_crit_act,SCHOOL_YEAR,True
disc_ltr_crit_act,SUMMER_SCHOOL,True
disc_ltr_crit_act,BUILDING,True
disc_ltr_crit_act,CRITERION,True
disc_ltr_crit_act,ACTION_CODE,True
disc_ltr_crit_act,CHANGE_DATE_TIME,True
disc_ltr_crit_act,CHANGE_UID,True
disc_ltr_crit,DISTRICT,True
disc_ltr_crit,SCHOOL_YEAR,True
disc_ltr_crit,SUMMER_SCHOOL,True
disc_ltr_crit,BUILDING,True
disc_ltr_crit,CRITERION,True
disc_ltr_crit,DESCRIPTION,True
disc_ltr_crit,OFFENSE_COUNT_MIN,True
disc_ltr_crit,OFFENSE_COUNT_MAX,True
disc_ltr_crit,ACTION_COUNT_MIN,True
disc_ltr_crit,ACTION_COUNT_MAX,True
disc_ltr_crit,LETTER_COUNT_TYPE,True
disc_ltr_crit,MAXIMUM_LETTERS,True
disc_ltr_crit,RESET_COUNT,True
disc_ltr_crit,LINES_OF_DETAIL,True
disc_ltr_crit,INCIDENTS_TO_PRINT,True
disc_ltr_crit,USE_ELIGIBILITY,True
disc_ltr_crit,ELIG_INCLUDE_PRIOR,True
disc_ltr_crit,ELIGIBILITY_CODE,True
disc_ltr_crit,ELIG_DURATION,True
disc_ltr_crit,ELIG_DURATION_DAYS,True
disc_ltr_crit,USE_AT_RISK,True
disc_ltr_crit,AT_RISK_REASON,True
disc_ltr_crit,AT_RISK_DURATION,True
disc_ltr_crit,AT_RISK_DAYS,True
disc_ltr_crit,CHANGE_DATE_TIME,True
disc_ltr_crit,CHANGE_UID,True
disc_link_issue,DISTRICT,True
disc_link_issue,SCHOOL_YEAR,True
disc_link_issue,SUMMER_SCHOOL,True
disc_link_issue,BUILDING,True
disc_link_issue,INCIDENT_ID,True
disc_link_issue,ISSUE_ID,True
disc_link_issue,CHANGE_DATE_TIME,True
disc_link_issue,CHANGE_UID,True
disc_off_subcode,DISTRICT,True
disc_off_subcode,SCHOOL_YEAR,True
disc_off_subcode,SUMMER_SCHOOL,True
disc_off_subcode,BUILDING,True
disc_off_subcode,INCIDENT_ID,True
disc_off_subcode,OFFENDER,True
disc_off_subcode,OFFENSE_SUBCODE,True
disc_off_subcode,CHANGE_DATE_TIME,True
disc_off_subcode,CHANGE_UID,True
disc_incident,DISTRICT,True
disc_incident,SCHOOL_YEAR,True
disc_incident,SUMMER_SCHOOL,True
disc_incident,BUILDING,True
disc_incident,INCIDENT_ID,True
disc_incident,INCIDENT_CODE,True
disc_incident,INCIDENT_SUBCODE,True
disc_incident,INCIDENT_DATE,True
disc_incident,INCIDENT_TIME,True
disc_incident,INCIDENT_TIME_FRAME,True
disc_incident,LOCATION,True
disc_incident,IS_STUDENT,True
disc_incident,PERSON_ID,True
disc_incident,REPORTED_TO,True
disc_incident,GANG_RELATED,True
disc_incident,POLICE_NOTIFIED,True
disc_incident,POLICE_NOTIFY_DATE,True
disc_incident,POLICE_DEPARTMENT,True
disc_incident,COMPLAINT_NUMBER,True
disc_incident,OFFICER_NAME,True
disc_incident,BADGE_NUMBER,True
disc_incident,COMMENTS,True
disc_incident,LONG_COMMENT,True
disc_incident,INCIDENT_GUID,True
disc_incident,INCIDENT_LOCKED,True
disc_incident,ROW_IDENTITY,True
disc_incident,CHANGE_DATE_TIME,True
disc_incident,CHANGE_UID,True
disc_district_tot,DISTRICT,True
disc_district_tot,TOTAL_CODE,True
disc_district_tot,TOTAL_LABEL,True
disc_district_tot,TOTAL_SUFFIX,True
disc_district_tot,WARNING_THRESHOLD,True
disc_district_tot,CHANGE_DATE_TIME,True
disc_district_tot,CHANGE_UID,True
disc_district_cfg,DISTRICT,True
disc_district_cfg,PRIVATE_NOTES,True
disc_district_cfg,TRACK_OCCURRENCES,True
disc_district_cfg,MULTIPLE_OFFENSES,True
disc_district_cfg,CURRENT_YEAR_SUM,True
disc_district_cfg,OFFENSE_ACT_TOTALS,True
disc_district_cfg,OFF_ACT_PREV_LST,True
disc_district_cfg,OFF_ACT_PREV_DET,True
disc_district_cfg,OFF_ACT_TOTAL_CNT,True
disc_district_cfg,INCIDENT_LOCKING,True
disc_district_cfg,ENFORCE_ACT_LEVELS,True
disc_district_cfg,RESPONSIBLE_ADMIN,True
disc_district_cfg,RESP_ADMIN_REQ,True
disc_district_cfg,AUTOCALC_END_DATE,True
disc_district_cfg,DEFAULT_SCHEDULED_DURATION,True
disc_district_cfg,USE_LONG_DESCRIPTION,True
disc_district_cfg,DEFAULT_INCIDENT_DATE,True
disc_district_cfg,LIMIT_OFFENDER_CODE,True
disc_district_cfg,CHANGE_DATE_TIME,True
disc_district_cfg,CHANGE_UID,True
disc_incident_code,DISTRICT,True
disc_incident_code,CODE,True
disc_incident_code,DESCRIPTION,True
disc_incident_code,LEVEL_MIN,True
disc_incident_code,LEVEL_MAX,True
disc_incident_code,STATE_CODE_EQUIV,True
disc_incident_code,SEVERITY_ORDER,True
disc_incident_code,ACTIVE,True
disc_incident_code,CHANGE_DATE_TIME,True
disc_incident_code,CHANGE_UID,True
disc_cfg,DISTRICT,True
disc_cfg,BUILDING,True
disc_cfg,FORM_LTR_FILENAME,True
disc_cfg,USE_MULTI_LANGUAGE,True
disc_cfg,PROGRAM_SCREEN,True
disc_cfg,REG_USER_SCREEN,True
disc_cfg,NOTIFY_DWNLD_PATH,True
disc_cfg,EMAIL_OPTION,True
disc_cfg,RETURN_EMAIL,True
disc_cfg,MAGISTRATE_NUMBER,True
disc_cfg,REFERRAL_RPT_HEADER,True
disc_cfg,REFERRAL_RPT_FOOTER,True
disc_cfg,ENABLE_ATTENDANCE,True
disc_cfg,CHANGE_DATE_TIME,True
disc_cfg,CHANGE_UID,True
disc_att_notify,DISTRICT,True
disc_att_notify,SCHOOL_YEAR,True
disc_att_notify,SUMMER_SCHOOL,True
disc_att_notify,BUILDING,True
disc_att_notify,STUDENT_ID,True
disc_att_notify,NOTIFY_CRITERIA,True
disc_att_notify,REPORT_CYCLE_DATE,True
disc_att_notify,TRIGGER_DATE,True
disc_att_notify,INCIDENT_ID,True
disc_att_notify,INVALID_NOTIFY,True
disc_att_notify,PUBLISHED,True
disc_att_notify,CHANGE_DATE_TIME,True
disc_att_notify,CHANGE_UID,True
disc_act_user,DISTRICT,True
disc_act_user,SCHOOL_YEAR,True
disc_act_user,SUMMER_SCHOOL,True
disc_act_user,BUILDING,True
disc_act_user,INCIDENT_ID,True
disc_act_user,ACTION_NUMBER,True
disc_act_user,SCREEN_TYPE,True
disc_act_user,OFF_VIC_WIT_ID,True
disc_act_user,SCREEN_NUMBER,True
disc_act_user,FIELD_NUMBER,True
disc_act_user,FIELD_VALUE,True
disc_act_user,CHANGE_DATE_TIME,True
disc_act_user,CHANGE_UID,True
cp_view_hdr,DISTRICT,True
cp_view_hdr,BUILDING,True
cp_view_hdr,STU_GRAD_YEAR,True
cp_view_hdr,VIEW_TYPE,True
cp_view_hdr,SHOW_CRS_DESCR,True
cp_view_hdr,SHOW_CRS_NUMBER,True
cp_view_hdr,SHOW_CRS_SECTION,True
cp_view_hdr,SHOW_ATT_CREDIT,True
cp_view_hdr,SHOW_EARN_CREDIT,True
cp_view_hdr,SHOW_SUBJ_CREDIT,True
cp_view_hdr,CHANGE_DATE_TIME,True
cp_view_hdr,CHANGE_UID,True
disc_print_citation,DISTRICT,True
disc_print_citation,PRINT_RUN,True
disc_print_citation,SEQUENCE_NUMBER,True
disc_print_citation,CITATION_NUMBER,True
disc_print_citation,SCHOOL_YEAR,True
disc_print_citation,SUMMER_SCHOOL,True
disc_print_citation,BUILDING,True
disc_print_citation,MAGISTRATE_NUMBER,True
disc_print_citation,INCIDENT_ID,True
disc_print_citation,DEFENDANT_ID,True
disc_print_citation,STUDENT_ID,True
disc_print_citation,UNLAWFUL_DATES,True
disc_print_citation,FINE,True
disc_print_citation,COSTS,True
disc_print_citation,TOTAL_DUE,True
disc_print_citation,CITY_TOWN_BORO,True
disc_print_citation,LOCATION,True
disc_print_citation,COUNTY_CODE,True
disc_print_citation,DATE_FILED,True
disc_print_citation,STATION_ADDRESS,True
disc_print_citation,CHANGE_DATE_TIME,True
disc_print_citation,CHANGE_UID,True
cp_stu_grad_area,DISTRICT,True
cp_stu_grad_area,STUDENT_ID,True
cp_stu_grad_area,SECTION_KEY,True
cp_stu_grad_area,COURSE_SESSION,True
cp_stu_grad_area,PLAN_MODE,True
cp_stu_grad_area,REQ_GROUP,True
cp_stu_grad_area,REQUIRE_CODE,True
cp_stu_grad_area,CODE_OVERRIDE,True
cp_stu_grad_area,SUBJ_AREA_CREDIT,True
cp_stu_grad_area,CREDIT_OVERRIDE,True
cp_stu_grad_area,CHANGE_DATE_TIME,True
cp_stu_grad_area,CHANGE_UID,True
cp_stu_grad,DISTRICT,True
cp_stu_grad,STUDENT_ID,True
cp_stu_grad,PLAN_MODE,True
cp_stu_grad,REQ_GROUP,True
cp_stu_grad,REQUIRE_CODE,True
cp_stu_grad,SUBJ_AREA_CREDIT,True
cp_stu_grad,CUR_ATT_CREDITS,True
cp_stu_grad,CUR_EARN_CREDITS,True
cp_stu_grad,CP_SCHD_CREDITS,True
cp_stu_grad,CHANGE_DATE_TIME,True
cp_stu_grad,CHANGE_UID,True
cp_stu_future_req,DISTRICT,True
cp_stu_future_req,STUDENT_ID,True
cp_stu_future_req,PLAN_MODE,True
cp_stu_future_req,SCHOOL_YEAR,True
cp_stu_future_req,BUILDING,True
cp_stu_future_req,REQ_GROUP,True
cp_stu_future_req,COURSE,True
cp_stu_future_req,REQUIRE_CODE,True
cp_stu_future_req,CODE_OVERRIDE,True
cp_stu_future_req,SUBJ_AREA_CREDIT,True
cp_stu_future_req,CHANGE_DATE_TIME,True
cp_stu_future_req,CHANGE_UID,True
cp_stu_course_ovr,DISTRICT,True
cp_stu_course_ovr,STUDENT_ID,True
cp_stu_course_ovr,BUILDING,True
cp_stu_course_ovr,COURSE,True
cp_stu_course_ovr,CHANGE_DATE_TIME,True
cp_stu_course_ovr,CHANGE_UID,True
Att_view_int,DISTRICT,True
Att_view_int,SCHOOL_YEAR,True
Att_view_int,SUMMER_SCHOOL,True
Att_view_int,BUILDING,True
Att_view_int,VIEW_TYPE,True
Att_view_int,ATT_INTERVAL,True
Att_view_int,CHANGE_DATE_TIME,True
Att_view_int,CHANGE_UID,True
att_view_hdr,DISTRICT,True
att_view_hdr,SCHOOL_YEAR,True
att_view_hdr,SUMMER_SCHOOL,True
att_view_hdr,BUILDING,True
att_view_hdr,VIEW_TYPE,True
att_view_hdr,DESCRIPTION,True
att_view_hdr,CRITERIA_TYPE,True
att_view_hdr,LAST_DAY_CALCED,True
att_view_hdr,ATT_TOTALS_UNITS,True
att_view_hdr,DAY_UNITS,True
att_view_hdr,INCLUDE_PERFPLUS,True
att_view_hdr,INCLD_PASSING_TIME,True
att_view_hdr,MAX_PASSING_TIME,True
att_view_hdr,SEPARATE_BUILDINGS,True
att_view_hdr,CHANGE_DATE_TIME,True
att_view_hdr,CHANGE_UID,True
Att_view_det,DISTRICT,True
Att_view_det,SCHOOL_YEAR,True
Att_view_det,SUMMER_SCHOOL,True
Att_view_det,BUILDING,True
Att_view_det,VIEW_TYPE,True
Att_view_det,CRITERIA,True
Att_view_det,CALENDAR,True
Att_view_det,MIN_OCCURRENCE,True
Att_view_det,MAX_OCCURRENCE,True
Att_view_det,CONSECUTIVE_ABS,True
Att_view_det,SAME_ABS,True
Att_view_det,ATT_CODE_CONVERT,True
Att_view_det,ATT_CODE_VALUE,True
Att_view_det,PERCENT_ABSENT,True
Att_view_det,USE_SCHD_PERIODS,True
Att_view_det,USE_ALL_PERIODS,True
Att_view_det,CHANGE_DATE_TIME,True
Att_view_det,CHANGE_UID,True
Att_view_det,LOCATION_TYPE,True
Att_view_cyc,DISTRICT,True
Att_view_cyc,SCHOOL_YEAR,True
Att_view_cyc,SUMMER_SCHOOL,True
Att_view_cyc,BUILDING,True
Att_view_cyc,VIEW_TYPE,True
Att_view_cyc,CRITERIA,True
Att_view_cyc,CYCLE,True
Att_view_cyc,CHANGE_DATE_TIME,True
Att_view_cyc,CHANGE_UID,True
Att_view_abs,DISTRICT,True
Att_view_abs,SCHOOL_YEAR,True
Att_view_abs,SUMMER_SCHOOL,True
Att_view_abs,BUILDING,True
Att_view_abs,VIEW_TYPE,True
Att_view_abs,CRITERIA,True
Att_view_abs,ATTENDANCE_CODE,True
Att_view_abs,CHANGE_DATE_TIME,True
Att_view_abs,CHANGE_UID,True
Att_tws_taken,DISTRICT,True
Att_tws_taken,SCHOOL_YEAR,True
Att_tws_taken,SUMMER_SCHOOL,True
Att_tws_taken,BUILDING,True
Att_tws_taken,ATTENDANCE_DATE,True
Att_tws_taken,PERIOD_KEY,True
Att_tws_taken,ATTENDANCE_PERIOD,True
Att_tws_taken,CHANGE_DATE_TIME,True
Att_tws_taken,CHANGE_UID,True
Att_stu_int_memb,DISTRICT,True
Att_stu_int_memb,SCHOOL_YEAR,True
Att_stu_int_memb,BUILDING,True
Att_stu_int_memb,SUMMER_SCHOOL,True
Att_stu_int_memb,STUDENT_ID,True
Att_stu_int_memb,ATND_INTERVAL,True
Att_stu_int_memb,TOTAL_MEMBERSHIP,True
Att_stu_int_memb,CHANGE_DATE_TIME,True
Att_stu_int_memb,CHANGE_UID,True
Att_stu_int_group,DISTRICT,True
Att_stu_int_group,SCHOOL_YEAR,True
Att_stu_int_group,BUILDING,True
Att_stu_int_group,SUMMER_SCHOOL,True
Att_stu_int_group,STUDENT_ID,True
Att_stu_int_group,VIEW_TYPE,True
Att_stu_int_group,ATND_INTERVAL,True
Att_stu_int_group,INTERVAL_TYPE,True
Att_stu_int_group,INTERVAL_CODE,True
Att_stu_int_group,ATT_CODE_VALUE,True
Att_stu_int_group,CHANGE_DATE_TIME,True
Att_stu_int_group,CHANGE_UID,True
Att_stu_int_crit,DISTRICT,True
Att_stu_int_crit,SCHOOL_YEAR,True
Att_stu_int_crit,BUILDING,True
Att_stu_int_crit,SUMMER_SCHOOL,True
Att_stu_int_crit,STUDENT_ID,True
Att_stu_int_crit,VIEW_TYPE,True
Att_stu_int_crit,CRITERIA,True
Att_stu_int_crit,ATND_INTERVAL,True
Att_stu_int_crit,TOTAL_DAY_TIME,True
Att_stu_int_crit,STUDENT_SCHD_TIME,True
Att_stu_int_crit,STU_UNSCHD_TIME,True
Att_stu_int_crit,PRESENT_TIME,True
Att_stu_int_crit,ABSENT_TIME,True
Att_stu_int_crit,CHANGE_DATE_TIME,True
Att_stu_int_crit,CHANGE_UID,True
att_stu_eligible,DISTRICT,True
att_stu_eligible,SCHOOL_YEAR,True
att_stu_eligible,BUILDING,True
att_stu_eligible,STUDENT_ID,True
att_stu_eligible,NOTIFY_CRITERIA,True
att_stu_eligible,REPORT_CYCLE_DATE,True
att_stu_eligible,TRIGGER_DATE,True
att_stu_eligible,ELIGIBILITY_CODE,True
att_stu_eligible,EFFECTIVE_DATE,True
att_stu_eligible,EXPIRATION_DATE,True
att_stu_eligible,CHANGE_DATE_TIME,True
att_stu_eligible,CHANGE_UID,True
att_stu_day_totals,DISTRICT,True
att_stu_day_totals,SCHOOL_YEAR,True
att_stu_day_totals,BUILDING,True
att_stu_day_totals,SUMMER_SCHOOL,True
att_stu_day_totals,STUDENT_ID,True
att_stu_day_totals,ATTENDANCE_DATE,True
att_stu_day_totals,VIEW_TYPE,True
att_stu_day_totals,CRITERIA,True
att_stu_day_totals,ATTENDANCE_CODE,True
att_stu_day_totals,ATT_CODE_VALUE,True
att_stu_day_totals,TOTAL_DAY_TIME,True
att_stu_day_totals,STUDENT_SCHD_TIME,True
att_stu_day_totals,STU_UNSCHD_TIME,True
att_stu_day_totals,PRESENT_TIME,True
att_stu_day_totals,ABSENT_TIME,True
att_stu_day_totals,ROW_IDENTITY,True
att_stu_day_totals,CHANGE_DATE_TIME,True
att_stu_day_totals,CHANGE_UID,True
att_stu_day_totals,LOCATION_TYPE,True
att_stu_day_totals,MAX_DAY_TIME,True
cp_stu_plan_alert,DISTRICT,True
cp_stu_plan_alert,STUDENT_ID,True
cp_stu_plan_alert,REQ_GROUP,True
cp_stu_plan_alert,ALERT_CODE,True
cp_stu_plan_alert,REQUIRE_CODE,True
cp_stu_plan_alert,BUILDING,True
cp_stu_plan_alert,COURSE,True
cp_stu_plan_alert,CREDIT,True
cp_stu_plan_alert,CREDIT_NEEDED,True
cp_stu_plan_alert,CHANGE_DATE_TIME,True
cp_stu_plan_alert,CHANGE_UID,True
att_stu_day_tot_last,DISTRICT,True
att_stu_day_tot_last,VIEW_TYPE,True
att_stu_day_tot_last,STUDENT_ID,True
att_stu_day_tot_last,BUILDING,True
att_stu_day_tot_last,LAST_CALC_DATE,True
att_stu_day_tot_last,CHANGE_DATE_TIME,True
att_stu_day_tot_last,CHANGE_UID,True
att_stu_at_risk,DISTRICT,True
att_stu_at_risk,SCHOOL_YEAR,True
att_stu_at_risk,BUILDING,True
att_stu_at_risk,STUDENT_ID,True
att_stu_at_risk,NOTIFY_CRITERIA,True
att_stu_at_risk,REPORT_CYCLE_DATE,True
att_stu_at_risk,TRIGGER_DATE,True
att_stu_at_risk,AT_RISK_REASON,True
att_stu_at_risk,EFFECTIVE_DATE,True
att_stu_at_risk,EXPIRATION_DATE,True
att_stu_at_risk,PLAN_NUM,True
att_stu_at_risk,CHANGE_DATE_TIME,True
att_stu_at_risk,CHANGE_UID,True
AR_DOWN_EIS1,DISTRICT,True
AR_DOWN_EIS1,SCHOOL_YEAR,True
AR_DOWN_EIS1,FISCAL_YEAR,True
AR_DOWN_EIS1,CYCLE,True
AR_DOWN_EIS1,DISTRICT_LEA,True
AR_DOWN_EIS1,SSN,True
AR_DOWN_EIS1,STUDENT_ID,True
AR_DOWN_EIS1,STUDENT_STATE_ID,True
AR_DOWN_EIS1,FIRST_NAME,True
AR_DOWN_EIS1,MIDDLE_NAME,True
AR_DOWN_EIS1,LAST_NAME,True
AR_DOWN_EIS1,BIRTHDATE,True
AR_DOWN_EIS1,RACE,True
AR_DOWN_EIS1,GENDER,True
AR_DOWN_EIS1,GRADE,True
AR_DOWN_EIS1,ELL,True
AR_DOWN_EIS1,RES_LEA,True
AR_DOWN_EIS1,ENTRY_DATE,True
AR_DOWN_EIS1,WITHDRAWAL_DATE,True
AR_DOWN_EIS1,WITHDRAWAL_CODE,True
AR_DOWN_EIS1,CHANGE_DATE_TIME,True
AR_DOWN_EIS1,CHANGE_UID,True
AR_DOWN_ALE_DAYS,DISTRICT,True
AR_DOWN_ALE_DAYS,SCHOOL_YEAR,True
AR_DOWN_ALE_DAYS,FISCAL_YEAR,True
AR_DOWN_ALE_DAYS,CYCLE,True
AR_DOWN_ALE_DAYS,SCHOOL_LEA,True
AR_DOWN_ALE_DAYS,SSN,True
AR_DOWN_ALE_DAYS,STUDENT_ID,True
AR_DOWN_ALE_DAYS,STUDENT_STATE_ID,True
AR_DOWN_ALE_DAYS,START_DATE,True
AR_DOWN_ALE_DAYS,QUARTER1_ALE,True
AR_DOWN_ALE_DAYS,QUARTER2_ALE,True
AR_DOWN_ALE_DAYS,QUARTER3_ALE,True
AR_DOWN_ALE_DAYS,QUARTER4_ALE,True
AR_DOWN_ALE_DAYS,CHANGE_DATE_TIME,True
AR_DOWN_ALE_DAYS,CHANGE_UID,True
disc_occurrence,DISTRICT,True
disc_occurrence,SCHOOL_YEAR,True
disc_occurrence,SUMMER_SCHOOL,True
disc_occurrence,BUILDING,True
disc_occurrence,INCIDENT_ID,True
disc_occurrence,OFFENDER,True
disc_occurrence,ACTION_NUMBER,True
disc_occurrence,OCCURRENCE,True
disc_occurrence,SCHD_START_DATE,True
disc_occurrence,ACTUAL_START_DATE,True
disc_occurrence,SCHD_START_TIME,True
disc_occurrence,SCHD_END_TIME,True
disc_occurrence,ACTUAL_START_TIME,True
disc_occurrence,ACTUAL_END_TIME,True
disc_occurrence,CHANGE_DATE_TIME,True
disc_occurrence,CHANGE_UID,True
att_period,DISTRICT,True
att_period,SCHOOL_YEAR,True
att_period,SUMMER_SCHOOL,True
att_period,BUILDING,True
att_period,ATTENDANCE_PERIOD,True
att_period,DESCRIPTION,True
att_period,ATT_PERIOD_ORDER,True
att_period,PERIOD_VALUE,True
att_period,START_TIME,True
att_period,END_TIME,True
att_period,INC_IN_ATT_VIEW,True
att_period,ROW_IDENTITY,True
att_period,CHANGE_DATE_TIME,True
att_period,CHANGE_UID,True
att_notify_stu_hdr,DISTRICT,True
att_notify_stu_hdr,SCHOOL_YEAR,True
att_notify_stu_hdr,BUILDING,True
att_notify_stu_hdr,STUDENT_ID,True
att_notify_stu_hdr,NOTIFY_CRITERIA,True
att_notify_stu_hdr,REPORT_CYCLE_DATE,True
att_notify_stu_hdr,TRIGGER_DATE,True
att_notify_stu_hdr,EVALUATION_CODE,True
att_notify_stu_hdr,PUBLISHED,True
att_notify_stu_hdr,INVALID_NOTIFY,True
att_notify_stu_hdr,CHANGE_DATE_TIME,True
att_notify_stu_hdr,CHANGE_UID,True
att_notify_stu_hdr,PUBLISHED_NOTIFICATION,True
disctb_notified,DISTRICT,True
disctb_notified,CODE,True
disctb_notified,DESCRIPTION,True
disctb_notified,ACTIVE,True
disctb_notified,CHANGE_DATE_TIME,True
disctb_notified,CHANGE_UID,True
disc_district_act,DISTRICT,True
disc_district_act,TOTAL_CODE,True
disc_district_act,ACTION_CODE,True
disc_district_act,CHANGE_DATE_TIME,True
disc_district_act,CHANGE_UID,True
Att_notify_lang,DISTRICT,True
Att_notify_lang,SCHOOL_YEAR,True
Att_notify_lang,SUMMER_SCHOOL,True
Att_notify_lang,BUILDING,True
Att_notify_lang,LANGUAGE_CODE,True
Att_notify_lang,CHANGE_DATE_TIME,True
Att_notify_lang,CHANGE_UID,True
AR_DOWN_EMPLOYEE,DISTRICT,True
AR_DOWN_EMPLOYEE,SCHOOL_YEAR,True
AR_DOWN_EMPLOYEE,FISCAL_YEAR,True
AR_DOWN_EMPLOYEE,CYCLE,True
AR_DOWN_EMPLOYEE,LEA,True
AR_DOWN_EMPLOYEE,SSN,True
AR_DOWN_EMPLOYEE,TEACH_ID,True
AR_DOWN_EMPLOYEE,STAFF_ID,True
AR_DOWN_EMPLOYEE,FNAME,True
AR_DOWN_EMPLOYEE,MNAME,True
AR_DOWN_EMPLOYEE,LNAME,True
AR_DOWN_EMPLOYEE,CHANGE_DATE_TIME,True
AR_DOWN_EMPLOYEE,CHANGE_UID,True
AR_CLASS_DOWN,DISTRICT,True
AR_CLASS_DOWN,SCHOOL_YEAR,True
AR_CLASS_DOWN,FISCAL_YEAR,True
AR_CLASS_DOWN,CYCLE,True
AR_CLASS_DOWN,SCHOOL_LEA,True
AR_CLASS_DOWN,COURSE_NUM,True
AR_CLASS_DOWN,COURSE_SECT,True
AR_CLASS_DOWN,COURSE_DESC,True
AR_CLASS_DOWN,COURSE_CREDIT,True
AR_CLASS_DOWN,DIST_LEARN,True
AR_CLASS_DOWN,SPEC_ED,True
AR_CLASS_DOWN,COLL_CREDIT,True
AR_CLASS_DOWN,INSTITUTION,True
AR_CLASS_DOWN,STAFF_SSN,True
AR_CLASS_DOWN,STAFF_STATE_ID,True
AR_CLASS_DOWN,HIGH_QUAL,True
AR_CLASS_DOWN,ALT_ENVN,True
AR_CLASS_DOWN,COURSE_MIN,True
AR_CLASS_DOWN,KG_OVERFLG,True
AR_CLASS_DOWN,LEA_OUT_DIST,True
AR_CLASS_DOWN,MARK_PERIOD,True
AR_CLASS_DOWN,DIST_LEARN_PROV,True
AR_CLASS_DOWN,CHANGE_DATE_TIME,True
AR_CLASS_DOWN,CHANGE_UID,True
att_notify_crit_cd,DISTRICT,True
att_notify_crit_cd,SCHOOL_YEAR,True
att_notify_crit_cd,SUMMER_SCHOOL,True
att_notify_crit_cd,BUILDING,True
att_notify_crit_cd,NOTIFY_CRITERIA,True
att_notify_crit_cd,EVALUATION_CODE,True
att_notify_crit_cd,CHANGE_DATE_TIME,True
att_notify_crit_cd,CHANGE_UID,True
att_notify_crit,DISTRICT,True
att_notify_crit,SCHOOL_YEAR,True
att_notify_crit,SUMMER_SCHOOL,True
att_notify_crit,BUILDING,True
att_notify_crit,NOTIFY_CRITERIA,True
att_notify_crit,DESCRIPTION,True
att_notify_crit,NOTIFICATION_ORDER,True
att_notify_crit,NOTIFY_GROUP,True
att_notify_crit,EMAIL_STAFF,True
att_notify_crit,REPORT_CYCLE_TYPE,True
att_notify_crit,INTERVAL_TYPE,True
att_notify_crit,SUNDAY,True
att_notify_crit,MONDAY,True
att_notify_crit,TUESDAY,True
att_notify_crit,WEDNESDAY,True
att_notify_crit,THURSDAY,True
att_notify_crit,FRIDAY,True
att_notify_crit,SATURDAY,True
att_notify_crit,EVALUATION_TYPE,True
att_notify_crit,EVALUATION_SOURCE,True
att_notify_crit,EVAL_VIEW_TYPE,True
att_notify_crit,DETAIL_DATE_RANGE,True
att_notify_crit,DATE_ORDER,True
att_notify_crit,SEND_LETTER,True
att_notify_crit,MIN_ABS_TYPE,True
att_notify_crit,MAX_ABS_TYPE,True
att_notify_crit,MIN_OVERALL_ABS,True
att_notify_crit,MAX_OVERALL_ABS,True
att_notify_crit,OVERALL_ABS_BY,True
att_notify_crit,MIN_ABSENCE,True
att_notify_crit,MAX_ABSENCE,True
att_notify_crit,ABSENCE_PATTERN,True
att_notify_crit,MIN_DAY,True
att_notify_crit,MAX_DAY,True
att_notify_crit,DAY_PATTERN,True
att_notify_crit,MIN_PERCENT_DAY,True
att_notify_crit,MAX_PERCENT_DAY,True
att_notify_crit,CALC_SELECTION,True
att_notify_crit,USE_ELIGIBILITY,True
att_notify_crit,ELIG_INCLUDE_PRIOR,True
att_notify_crit,ELIGIBILITY_CODE,True
att_notify_crit,ELIG_DURATION,True
att_notify_crit,ELIG_DURATION_DAYS,True
att_notify_crit,MAX_LETTER,True
att_notify_crit,USE_DISCIPLINE,True
att_notify_crit,IS_STUDENT,True
att_notify_crit,PERSON_ID,True
att_notify_crit,INCIDENT_CODE,True
att_notify_crit,ACTION_CODE,True
att_notify_crit,INCLUDE_FINE,True
att_notify_crit,USE_AT_RISK,True
att_notify_crit,AT_RISK_REASON,True
att_notify_crit,AT_RISK_DURATION,True
att_notify_crit,AT_RISK_DAYS,True
att_notify_crit,CHANGE_DATE_TIME,True
att_notify_crit,CHANGE_UID,True
att_interval,DISTRICT,True
att_interval,SCHOOL_YEAR,True
att_interval,BUILDING,True
att_interval,SUMMER_SCHOOL,True
att_interval,ATND_INTERVAL,True
att_interval,DESCRIPTION,True
att_interval,ATT_INTERVAL_ORDER,True
att_interval,INTERVAL_TYPE,True
att_interval,BEGIN_SPAN,True
att_interval,END_SPAN,True
att_interval,SUM_BY_ATT_CODE,True
att_interval,SUM_BY_DISTR_GRP,True
att_interval,SUM_BY_STATE_GRP,True
att_interval,STATE_CODE_EQUIV,True
att_interval,CHANGE_DATE_TIME,True
att_interval,CHANGE_UID,True
att_code_building,DISTRICT,True
att_code_building,SCHOOL_YEAR,True
att_code_building,SUMMER_SCHOOL,True
att_code_building,BUILDING,True
att_code_building,ATTENDANCE_CODE,True
att_code_building,CHANGE_DATE_TIME,True
att_code_building,CHANGE_UID,True
att_code,DISTRICT,True
att_code,SCHOOL_YEAR,True
att_code,SUMMER_SCHOOL,True
att_code,ATTENDANCE_CODE,True
att_code,DESCRIPTION,True
att_code,COLOR,True
att_code,USE_DISMISS_TIME,True
att_code,USE_ARRIVE_TIME,True
att_code,DISTRICT_GROUP,True
att_code,STATE_GROUP,True
att_code,SIF_TYPE,True
att_code,SIF_STATUS,True
att_code,SIF_PRECEDENCE,True
att_code,INCLUDE_PERFPLUS,True
att_code,ALT_ATTENDANCE_CODE,True
att_code,STATE_CODE_EQUIV,True
att_code,CHANGE_DATE_TIME,True
att_code,CHANGE_UID,True
att_notify_crit_pd,DISTRICT,True
att_notify_crit_pd,SCHOOL_YEAR,True
att_notify_crit_pd,SUMMER_SCHOOL,True
att_notify_crit_pd,BUILDING,True
att_notify_crit_pd,NOTIFY_CRITERIA,True
att_notify_crit_pd,ATTENDANCE_PERIOD,True
att_notify_crit_pd,CHANGE_DATE_TIME,True
att_notify_crit_pd,CHANGE_UID,True
att_notify_stu_det,DISTRICT,True
att_notify_stu_det,SCHOOL_YEAR,True
att_notify_stu_det,BUILDING,True
att_notify_stu_det,STUDENT_ID,True
att_notify_stu_det,NOTIFY_CRITERIA,True
att_notify_stu_det,REPORT_CYCLE_DATE,True
att_notify_stu_det,TRIGGER_DATE,True
att_notify_stu_det,ATTENDANCE_DATE,True
att_notify_stu_det,ATTENDANCE_PERIOD,True
att_notify_stu_det,SEQUENCE_NUM,True
att_notify_stu_det,EVALUATION_CODE,True
att_notify_stu_det,INVALID_NOTIFY,True
att_notify_stu_det,ATTENDANCE_COUNT,True
att_notify_stu_det,ABSENCE_TYPE,True
att_notify_stu_det,ABSENCE_VALUE,True
att_notify_stu_det,SECTION_KEY,True
att_notify_stu_det,INCIDENT_ID,True
att_notify_stu_det,ACTION_NUMBER,True
att_notify_stu_det,CHANGE_DATE_TIME,True
att_notify_stu_det,CHANGE_UID,True
att_cfg_codes,DISTRICT,True
att_cfg_codes,SCHOOL_YEAR,True
att_cfg_codes,SUMMER_SCHOOL,True
att_cfg_codes,BUILDING,True
att_cfg_codes,ATTENDANCE_CODE,True
att_cfg_codes,CHANGE_DATE_TIME,True
att_cfg_codes,CHANGE_UID,True
att_cfg,DISTRICT,True
att_cfg,SCHOOL_YEAR,True
att_cfg,SUMMER_SCHOOL,True
att_cfg,BUILDING,True
att_cfg,PERIOD_TYPE,True
att_cfg,USE_TIMETABLE,True
att_cfg,BOTTOM_LINE_TYPE,True
att_cfg,POSITIVE_ATND,True
att_cfg,AUDIT_TYPE,True
att_cfg,DEFAULT_ABS_CODE,True
att_cfg,DEFAULT_TAR_CODE,True
att_cfg,DEFAULT_PRE_CODE,True
att_cfg,USE_LANG_TEMPLATE,True
att_cfg,DATA_SOURCE_FILE,True
att_cfg,PROGRAM_SCREEN,True
att_cfg,REG_USER_SCREEN,True
att_cfg,NOTIFY_DWNLD_PATH,True
att_cfg,EMAIL_OPTION,True
att_cfg,RETURN_EMAIL,True
att_cfg,RET_EMAIL_MISSUB,True
att_cfg,TWS_TAKE_ATT,True
att_cfg,TWS_ALT_ABS,True
att_cfg,TWS_NUM_VIEW_DAYS,True
att_cfg,TWS_NUM_MNT_DAYS,True
att_cfg,TWS_ATT_STU_SUMM,True
att_cfg,DEF_TAC_ABS_CODE,True
att_cfg,DEF_TAC_TAR_CODE,True
att_cfg,DEF_TAC_PRES_CODE,True
att_cfg,ATT_LOCK_DATE,True
att_cfg,CODE_LIST_TEACH_SUBST,True
att_cfg,SIF_VIEW,True
att_cfg,CHANGE_DATE_TIME,True
att_cfg,CHANGE_UID,True
att_bottomline,DISTRICT,True
att_bottomline,SCHOOL_YEAR,True
att_bottomline,SUMMER_SCHOOL,True
att_bottomline,BUILDING,True
att_bottomline,STUDENT_ID,True
att_bottomline,ATTENDANCE_DATE,True
att_bottomline,ATTENDANCE_PERIOD,True
att_bottomline,SEQUENCE_NUM,True
att_bottomline,SOURCE,True
att_bottomline,ATTENDANCE_CODE,True
att_bottomline,DISMISS_TIME,True
att_bottomline,ARRIVE_TIME,True
att_bottomline,MINUTES_ABSENT,True
att_bottomline,ATT_COMMENT,True
att_bottomline,ROW_IDENTITY,True
att_bottomline,CHANGE_DATE_TIME,True
att_bottomline,CHANGE_UID,True
att_cfg_periods,DISTRICT,True
att_cfg_periods,SCHOOL_YEAR,True
att_cfg_periods,SUMMER_SCHOOL,True
att_cfg_periods,BUILDING,True
att_cfg_periods,ATTENDANCE_PERIOD,True
att_cfg_periods,CHANGE_DATE_TIME,True
att_cfg_periods,CHANGE_UID,True
att_audit_trail,DISTRICT,True
att_audit_trail,SCHOOL_YEAR,True
att_audit_trail,SUMMER_SCHOOL,True
att_audit_trail,BUILDING,True
att_audit_trail,ATTENDANCE_DATE,True
att_audit_trail,STUDENT_ID,True
att_audit_trail,ATTENDANCE_PERIOD,True
att_audit_trail,SEQUENCE_NUM,True
att_audit_trail,ENTRY_ORDER_NUM,True
att_audit_trail,SOURCE,True
att_audit_trail,ATTENDANCE_CODE,True
att_audit_trail,DISMISS_TIME,True
att_audit_trail,ARRIVE_TIME,True
att_audit_trail,MINUTES_ABSENT,True
att_audit_trail,BOTTOMLINE,True
att_audit_trail,ENTRY_DATE_TIME,True
att_audit_trail,ENTRY_USER,True
att_audit_trail,ATT_COMMENT,True
att_audit_trail,CHANGE_DATE_TIME,True
att_audit_trail,CHANGE_UID,True
disc_ltr_crit_off,DISTRICT,True
disc_ltr_crit_off,SCHOOL_YEAR,True
disc_ltr_crit_off,SUMMER_SCHOOL,True
disc_ltr_crit_off,BUILDING,True
disc_ltr_crit_off,CRITERION,True
disc_ltr_crit_off,OFFENSE_CODE,True
disc_ltr_crit_off,CHANGE_DATE_TIME,True
disc_ltr_crit_off,CHANGE_UID,True
Att_cfg_miss_sub,DISTRICT,True
Att_cfg_miss_sub,SCHOOL_YEAR,True
Att_cfg_miss_sub,SUMMER_SCHOOL,True
Att_cfg_miss_sub,BUILDING,True
Att_cfg_miss_sub,LOGIN_ID,True
Att_cfg_miss_sub,CHANGE_DATE_TIME,True
Att_cfg_miss_sub,CHANGE_UID,True
ARTB_SE_TITLE_CODE,DISTRICT,True
ARTB_SE_TITLE_CODE,CODE,True
ARTB_SE_TITLE_CODE,DESCRIPTION,True
ARTB_SE_TITLE_CODE,STATE_CODE_EQUIV,True
ARTB_SE_TITLE_CODE,ACTIVE,True
ARTB_SE_TITLE_CODE,CHANGE_DATE_TIME,True
ARTB_SE_TITLE_CODE,CHANGE_UID,True
ARTB_SE_RFC_REASON,DISTRICT,True
ARTB_SE_RFC_REASON,CODE,True
ARTB_SE_RFC_REASON,DESCRIPTION,True
ARTB_SE_RFC_REASON,STATE_CODE_EQUIV,True
ARTB_SE_RFC_REASON,ACTIVE,True
ARTB_SE_RFC_REASON,CHANGE_DATE_TIME,True
ARTB_SE_RFC_REASON,CHANGE_UID,True
ARTB_SE_REFERRAL,DISTRICT,True
ARTB_SE_REFERRAL,SCHOOL_YEAR,True
ARTB_SE_REFERRAL,SUMMER_SCHOOL,True
ARTB_SE_REFERRAL,STUDENT_ID,True
ARTB_SE_REFERRAL,REFERRAL_ID,True
ARTB_SE_REFERRAL,BUILDING,True
ARTB_SE_REFERRAL,RESIDENT_LEA,True
ARTB_SE_REFERRAL,PRIVATE_SCHOOL,True
ARTB_SE_REFERRAL,PRIVATE_SCHOOL_NAME,True
ARTB_SE_REFERRAL,ELL,True
ARTB_SE_REFERRAL,TRANS_PART_C,True
ARTB_SE_REFERRAL,PART_C_B_CONCURRENT,True
ARTB_SE_REFERRAL,REFERRAL_DATE,True
ARTB_SE_REFERRAL,PARENT_EVAL_DATE,True
ARTB_SE_REFERRAL,EVAL_DATE,True
ARTB_SE_REFERRAL,EVAL_REASON,True
ARTB_SE_REFERRAL,EVAL_OT_REASON,True
ARTB_SE_REFERRAL,ELIGIBILITY_DET_DATE,True
ARTB_SE_REFERRAL,EDD_30_DAY_CODE,True
ARTB_SE_REFERRAL,EDD_OT_REASON,True
ARTB_SE_REFERRAL,EDD_3RD_DOB_CODE,True
ARTB_SE_REFERRAL,EDD3_OT_REASON,True
ARTB_SE_REFERRAL,TEMP_IEP_3RD_BDAY,True
ARTB_SE_REFERRAL,SPED_PLACEMENT,True
ARTB_SE_REFERRAL,EARLY_INTERV_SERV,True
ARTB_SE_REFERRAL,PARENT_PLACE_DATE,True
ARTB_SE_REFERRAL,RFC_REASON,True
ARTB_SE_REFERRAL,CMP_OTHER,True
ARTB_SE_REFERRAL,REF_COMPLETE,True
ARTB_SE_REFERRAL,CHANGE_DATE_TIME,True
ARTB_SE_REFERRAL,CHANGE_UID,True
ARTB_SE_PROG_TYPE,DISTRICT,True
ARTB_SE_PROG_TYPE,CODE,True
ARTB_SE_PROG_TYPE,DESCRIPTION,True
ARTB_SE_PROG_TYPE,STATE_CODE_EQUIV,True
ARTB_SE_PROG_TYPE,ACTIVE,True
ARTB_SE_PROG_TYPE,CHANGE_DATE_TIME,True
ARTB_SE_PROG_TYPE,CHANGE_UID,True
ARTB_SE_INT_SERV,DISTRICT,True
ARTB_SE_INT_SERV,CODE,True
ARTB_SE_INT_SERV,DESCRIPTION,True
ARTB_SE_INT_SERV,STATE_CODE_EQUIV,True
ARTB_SE_INT_SERV,ACTIVE,True
ARTB_SE_INT_SERV,CHANGE_DATE_TIME,True
ARTB_SE_INT_SERV,CHANGE_UID,True
ARTB_SE_GRADE_LVL,DISTRICT,True
ARTB_SE_GRADE_LVL,CODE,True
ARTB_SE_GRADE_LVL,DESCRIPTION,True
ARTB_SE_GRADE_LVL,STATE_CODE_EQUIV,True
ARTB_SE_GRADE_LVL,ACTIVE,True
ARTB_SE_GRADE_LVL,CHANGE_DATE_TIME,True
ARTB_SE_GRADE_LVL,CHANGE_UID,True
ARTB_SE_FUNC_SCORE,DISTRICT,True
ARTB_SE_FUNC_SCORE,CODE,True
ARTB_SE_FUNC_SCORE,DESCRIPTION,True
ARTB_SE_FUNC_SCORE,STATE_CODE_EQUIV,True
ARTB_SE_FUNC_SCORE,ACTIVE,True
ARTB_SE_FUNC_SCORE,CHANGE_DATE_TIME,True
ARTB_SE_FUNC_SCORE,CHANGE_UID,True
ARTB_SE_FUNC_IMP,DISTRICT,True
ARTB_SE_FUNC_IMP,CODE,True
ARTB_SE_FUNC_IMP,DESCRIPTION,True
ARTB_SE_FUNC_IMP,STATE_CODE_EQUIV,True
ARTB_SE_FUNC_IMP,ACTIVE,True
ARTB_SE_FUNC_IMP,CHANGE_DATE_TIME,True
ARTB_SE_FUNC_IMP,CHANGE_UID,True
ARTB_SE_EVL_EXCEED,DISTRICT,True
ARTB_SE_EVL_EXCEED,CODE,True
ARTB_SE_EVL_EXCEED,DESCRIPTION,True
ARTB_SE_EVL_EXCEED,STATE_CODE_EQUIV,True
ARTB_SE_EVL_EXCEED,ACTIVE,True
ARTB_SE_EVL_EXCEED,CHANGE_DATE_TIME,True
ARTB_SE_EVL_EXCEED,CHANGE_UID,True
ARTB_SE_EVAL_CODE,DISTRICT,True
ARTB_SE_EVAL_CODE,CODE,True
ARTB_SE_EVAL_CODE,DESCRIPTION,True
ARTB_SE_EVAL_CODE,STATE_CODE_EQUIV,True
ARTB_SE_EVAL_CODE,ACTIVE,True
ARTB_SE_EVAL_CODE,CHANGE_DATE_TIME,True
ARTB_SE_EVAL_CODE,CHANGE_UID,True
ARTB_SE_EDU_PLACE,DISTRICT,True
ARTB_SE_EDU_PLACE,CODE,True
ARTB_SE_EDU_PLACE,DESCRIPTION,True
ARTB_SE_EDU_PLACE,STATE_CODE_EQUIV,True
ARTB_SE_EDU_PLACE,ACTIVE,True
ARTB_SE_EDU_PLACE,CHANGE_DATE_TIME,True
ARTB_SE_EDU_PLACE,CHANGE_UID,True
ARTB_SE_EDU_NEEDS,DISTRICT,True
ARTB_SE_EDU_NEEDS,CODE,True
ARTB_SE_EDU_NEEDS,DESCRIPTION,True
ARTB_SE_EDU_NEEDS,STATE_CODE_EQUIV,True
ARTB_SE_EDU_NEEDS,ACTIVE,True
ARTB_SE_EDU_NEEDS,CHANGE_DATE_TIME,True
ARTB_SE_EDU_NEEDS,CHANGE_UID,True
ARTB_SE_TRANS_CODE,DISTRICT,True
ARTB_SE_TRANS_CODE,CODE,True
ARTB_SE_TRANS_CODE,DESCRIPTION,True
ARTB_SE_TRANS_CODE,STATE_CODE_EQUIV,True
ARTB_SE_TRANS_CODE,ACTIVE,True
ARTB_SE_TRANS_CODE,CHANGE_DATE_TIME,True
ARTB_SE_TRANS_CODE,CHANGE_UID,True
ARTB_SE_EDD_REASON,DISTRICT,True
ARTB_SE_EDD_REASON,CODE,True
ARTB_SE_EDD_REASON,DESCRIPTION,True
ARTB_SE_EDD_REASON,STATE_CODE_EQUIV,True
ARTB_SE_EDD_REASON,ACTIVE,True
ARTB_SE_EDD_REASON,CHANGE_DATE_TIME,True
ARTB_SE_EDD_REASON,CHANGE_UID,True
ARTB_SE_EDD_3RD,DISTRICT,True
ARTB_SE_EDD_3RD,CODE,True
ARTB_SE_EDD_3RD,DESCRIPTION,True
ARTB_SE_EDD_3RD,STATE_CODE_EQUIV,True
ARTB_SE_EDD_3RD,ACTIVE,True
ARTB_SE_EDD_3RD,CHANGE_DATE_TIME,True
ARTB_SE_EDD_3RD,CHANGE_UID,True
ARTB_SE_DEV_NEEDS,DISTRICT,True
ARTB_SE_DEV_NEEDS,CODE,True
ARTB_SE_DEV_NEEDS,DESCRIPTION,True
ARTB_SE_DEV_NEEDS,STATE_CODE_EQUIV,True
ARTB_SE_DEV_NEEDS,ACTIVE,True
ARTB_SE_DEV_NEEDS,CHANGE_DATE_TIME,True
ARTB_SE_DEV_NEEDS,CHANGE_UID,True
ARTB_SE_CERT_STAT,DISTRICT,True
ARTB_SE_CERT_STAT,CODE,True
ARTB_SE_CERT_STAT,DESCRIPTION,True
ARTB_SE_CERT_STAT,STATE_CODE_EQUIV,True
ARTB_SE_CERT_STAT,ACTIVE,True
ARTB_SE_CERT_STAT,CHANGE_DATE_TIME,True
ARTB_SE_CERT_STAT,CHANGE_UID,True
ARTB_SCHOOL_GRADE,DISTRICT,True
ARTB_SCHOOL_GRADE,CODE,True
ARTB_SCHOOL_GRADE,DESCRIPTION,True
ARTB_SCHOOL_GRADE,ACTIVE,True
ARTB_SCHOOL_GRADE,CHANGE_DATE_TIME,True
ARTB_SCHOOL_GRADE,CHANGE_UID,True
ARTB_SE_EDU_ENVIRN,DISTRICT,True
ARTB_SE_EDU_ENVIRN,CODE,True
ARTB_SE_EDU_ENVIRN,DESCRIPTION,True
ARTB_SE_EDU_ENVIRN,STATE_CODE_EQUIV,True
ARTB_SE_EDU_ENVIRN,ACTIVE,True
ARTB_SE_EDU_ENVIRN,CHANGE_DATE_TIME,True
ARTB_SE_EDU_ENVIRN,CHANGE_UID,True
ARTB_SA_DISAB,DISTRICT,True
ARTB_SA_DISAB,CODE,True
ARTB_SA_DISAB,DESCRIPTION,True
ARTB_SA_DISAB,STATE_CODE_EQUIV,True
ARTB_SA_DISAB,ACTIVE,True
ARTB_SA_DISAB,CHANGE_DATE_TIME,True
ARTB_SA_DISAB,CHANGE_UID,True
ARTB_SA_ANTIC_SVC,DISTRICT,True
ARTB_SA_ANTIC_SVC,CODE,True
ARTB_SA_ANTIC_SVC,DESCRIPTION,True
ARTB_SA_ANTIC_SVC,STATE_CODE_EQUIV,True
ARTB_SA_ANTIC_SVC,ACTIVE,True
ARTB_SA_ANTIC_SVC,CHANGE_DATE_TIME,True
ARTB_SA_ANTIC_SVC,CHANGE_UID,True
ARTB_RPT_PERIODS,DISTRICT,True
ARTB_RPT_PERIODS,CODE,True
ARTB_RPT_PERIODS,DESCRIPTION,True
ARTB_RPT_PERIODS,END_DATE,True
ARTB_RPT_PERIODS,ACTIVE,True
ARTB_RPT_PERIODS,CHANGE_DATE_TIME,True
ARTB_RPT_PERIODS,CHANGE_UID,True
ARTB_TUITION,DISTRICT,True
ARTB_TUITION,CODE,True
ARTB_TUITION,DESCRIPTION,True
ARTB_TUITION,STATE_CODE_EQUIV,True
ARTB_TUITION,ACTIVE,True
ARTB_TUITION,CHANGE_DATE_TIME,True
ARTB_TUITION,CHANGE_UID,True
ARTB_OUT_DIST,DISTRICT,True
ARTB_OUT_DIST,CODE,True
ARTB_OUT_DIST,DESCRIPTION,True
ARTB_OUT_DIST,STATE_CODE_EQUIV,True
ARTB_OUT_DIST,ACTIVE,True
ARTB_OUT_DIST,CHANGE_DATE_TIME,True
ARTB_OUT_DIST,CHANGE_UID,True
ARTB_OTHERDISTRICT,DISTRICT,True
ARTB_OTHERDISTRICT,NAME,True
ARTB_OTHERDISTRICT,STATE_CODE_EQUIV,True
ARTB_OTHERDISTRICT,STATE,True
ARTB_OTHERDISTRICT,CHANGE_DATE_TIME,True
ARTB_OTHERDISTRICT,CHANGE_UID,True
ARTB_SA_RELATE_SVC,DISTRICT,True
ARTB_SA_RELATE_SVC,CODE,True
ARTB_SA_RELATE_SVC,DESCRIPTION,True
ARTB_SA_RELATE_SVC,STATE_CODE_EQUIV,True
ARTB_SA_RELATE_SVC,ACTIVE,True
ARTB_SA_RELATE_SVC,CHANGE_DATE_TIME,True
ARTB_SA_RELATE_SVC,CHANGE_UID,True
ARTB_INSTITUTIONS,DISTRICT,True
ARTB_INSTITUTIONS,CODE,True
ARTB_INSTITUTIONS,DESCRIPTION,True
ARTB_INSTITUTIONS,STATE_CODE_EQUIV,True
ARTB_INSTITUTIONS,ACTIVE,True
ARTB_INSTITUTIONS,CHANGE_DATE_TIME,True
ARTB_INSTITUTIONS,CHANGE_UID,True
ARTB_EC_RELATE_SVC,DISTRICT,True
ARTB_EC_RELATE_SVC,CODE,True
ARTB_EC_RELATE_SVC,DESCRIPTION,True
ARTB_EC_RELATE_SVC,STATE_CODE_EQUIV,True
ARTB_EC_RELATE_SVC,ACTIVE,True
ARTB_EC_RELATE_SVC,CHANGE_DATE_TIME,True
ARTB_EC_RELATE_SVC,CHANGE_UID,True
ARTB_EC_DISAB,DISTRICT,True
ARTB_EC_DISAB,CODE,True
ARTB_EC_DISAB,DESCRIPTION,True
ARTB_EC_DISAB,STATE_CODE_EQUIV,True
ARTB_EC_DISAB,ACTIVE,True
ARTB_EC_DISAB,CHANGE_DATE_TIME,True
ARTB_EC_DISAB,CHANGE_UID,True
ARTB_EC_ANTIC_SVC,DISTRICT,True
ARTB_EC_ANTIC_SVC,CODE,True
ARTB_EC_ANTIC_SVC,DESCRIPTION,True
ARTB_EC_ANTIC_SVC,STATE_CODE_EQUIV,True
ARTB_EC_ANTIC_SVC,ACTIVE,True
ARTB_EC_ANTIC_SVC,CHANGE_DATE_TIME,True
ARTB_EC_ANTIC_SVC,CHANGE_UID,True
ARTB_SE_STAF_DISAB,DISTRICT,True
ARTB_SE_STAF_DISAB,CODE,True
ARTB_SE_STAF_DISAB,DESCRIPTION,True
ARTB_SE_STAF_DISAB,STATE_CODE_EQUIV,True
ARTB_SE_STAF_DISAB,SENSITIVE,True
ARTB_SE_STAF_DISAB,ACTIVE,True
ARTB_SE_STAF_DISAB,CHANGE_DATE_TIME,True
ARTB_SE_STAF_DISAB,CHANGE_UID,True
ARTB_LEPMONITORED,DISTRICT,True
ARTB_LEPMONITORED,CODE,True
ARTB_LEPMONITORED,DESCRIPTION,True
ARTB_LEPMONITORED,STATE_CODE_EQUIV,True
ARTB_LEPMONITORED,ACTIVE,True
ARTB_LEPMONITORED,CHANGE_DATE_TIME,True
ARTB_LEPMONITORED,CHANGE_UID,True
ARTB_DIST_LEARN,DISTRICT,True
ARTB_DIST_LEARN,CODE,True
ARTB_DIST_LEARN,DESCRIPTION,True
ARTB_DIST_LEARN,STATE_CODE_EQUIV,True
ARTB_DIST_LEARN,ACTIVE,True
ARTB_DIST_LEARN,CHANGE_DATE_TIME,True
ARTB_DIST_LEARN,CHANGE_UID,True
ARTB_21CCLC,DISTRICT,True
ARTB_21CCLC,CODE,True
ARTB_21CCLC,DESCRIPTION,True
ARTB_21CCLC,STATE_CODE_EQUIV,True
ARTB_21CCLC,ACTIVE,True
ARTB_21CCLC,CHANGE_DATE_TIME,True
ARTB_21CCLC,CHANGE_UID,True
SCHD_MS_ALT_LANG,DISTRICT,True
SCHD_MS_ALT_LANG,SECTION_KEY,True
SCHD_MS_ALT_LANG,COURSE_SESSION,True
SCHD_MS_ALT_LANG,LANGUAGE,True
SCHD_MS_ALT_LANG,DESCRIPTION,True
SCHD_MS_ALT_LANG,CHANGE_DATE_TIME,True
SCHD_MS_ALT_LANG,CHANGE_UID,True
REG_GROUP_HDR,DISTRICT,True
REG_GROUP_HDR,GROUP_CODE,True
REG_GROUP_HDR,DESCRIPTION,True
REG_GROUP_HDR,CHANGE_DATE_TIME,True
REG_GROUP_HDR,CHANGE_UID,True
MED_SERIES_SCHED,DISTRICT,True
MED_SERIES_SCHED,SERIES_SCHEDULE,True
MED_SERIES_SCHED,DOSE_NUMBER,True
MED_SERIES_SCHED,DESCRIPTION,True
MED_SERIES_SCHED,SERIES_CODE,True
MED_SERIES_SCHED,EVENT_DOSE,True
MED_SERIES_SCHED,TIME_EVENTS,True
MED_SERIES_SCHED,TIME_EVENTS_UNITS,True
MED_SERIES_SCHED,OVERDUE_MS,True
MED_SERIES_SCHED,OVERDUE_MS_UNITS,True
MED_SERIES_SCHED,TIME_BIRTH,True
MED_SERIES_SCHED,UNITS_TIME_BIRTH,True
MED_SERIES_SCHED,OVERDUE_RS,True
MED_SERIES_SCHED,OVERDUE_RS_UNITS,True
MED_SERIES_SCHED,NOT_BEFORE,True
MED_SERIES_SCHED,NOT_BEFORE_UNITS,True
MED_SERIES_SCHED,EXCEPTIONS,True
MED_SERIES_SCHED,EXCEPTIONS_DOSE,True
MED_SERIES_SCHED,GIVEN_AFTER,True
MED_SERIES_SCHED,GIVEN_AFTER_UNITS,True
MED_SERIES_SCHED,EXPIRES_AFTER,True
MED_SERIES_SCHED,EXPIRES_UNITS,True
MED_SERIES_SCHED,EXPIRES_CODE,True
MED_SERIES_SCHED,NOT_UNTIL_DOSE,True
MED_SERIES_SCHED,NOT_UNTIL_TIME,True
MED_SERIES_SCHED,NOT_UNTIL_UNITS,True
MED_SERIES_SCHED,CHANGE_DATE_TIME,True
MED_SERIES_SCHED,CHANGE_UID,True
ARTB_DIST_LRNPROV,DISTRICT,True
ARTB_DIST_LRNPROV,CODE,True
ARTB_DIST_LRNPROV,DESCRIPTION,True
ARTB_DIST_LRNPROV,STATE_CODE_EQUIV,True
ARTB_DIST_LRNPROV,ACTIVE,True
ARTB_DIST_LRNPROV,CHANGE_DATE_TIME,True
ARTB_DIST_LRNPROV,CHANGE_UID,True
REGTB_TRANSPORT_CODE,DISTRICT,True
REGTB_TRANSPORT_CODE,CODE,True
REGTB_TRANSPORT_CODE,DESCRIPTION,True
REGTB_TRANSPORT_CODE,STATE_CODE_EQUIV,True
REGTB_TRANSPORT_CODE,ACTIVE,True
REGTB_TRANSPORT_CODE,CHANGE_DATE_TIME,True
REGTB_TRANSPORT_CODE,CHANGE_UID,True
ltdb_interface_det,DISTRICT,True
ltdb_interface_det,INTERFACE_ID,True
ltdb_interface_det,HEADER_ID,True
ltdb_interface_det,FIELD_ID,True
ltdb_interface_det,FIELD_ORDER,True
ltdb_interface_det,TABLE_NAME,True
ltdb_interface_det,TABLE_ALIAS,True
ltdb_interface_det,COLUMN_NAME,True
ltdb_interface_det,SCREEN_TYPE,True
ltdb_interface_det,SCREEN_NUMBER,True
ltdb_interface_det,FORMAT_STRING,True
ltdb_interface_det,START_POSITION,True
ltdb_interface_det,END_POSITION,True
ltdb_interface_det,FIELD_LENGTH,True
ltdb_interface_det,VALIDATION_TABLE,True
ltdb_interface_det,CODE_COLUMN,True
ltdb_interface_det,VALIDATION_LIST,True
ltdb_interface_det,ERROR_MESSAGE,True
ltdb_interface_det,EXTERNAL_TABLE,True
ltdb_interface_det,EXTERNAL_COL_IN,True
ltdb_interface_det,EXTERNAL_COL_OUT,True
ltdb_interface_det,LITERAL,True
ltdb_interface_det,COLUMN_OVERRIDE,True
ltdb_interface_det,CHANGE_DATE_TIME,True
ltdb_interface_det,CHANGE_UID,True
CP_CFG,DISTRICT,True
CP_CFG,BUILDING,True
CP_CFG,BLDG_HANDBOOK_LINK,True
CP_CFG,STUDENT_PLAN_TEXT,True
CP_CFG,CHANGE_DATE_TIME,True
CP_CFG,CHANGE_UID,True
ltdb_interface_hdr,DISTRICT,True
ltdb_interface_hdr,INTERFACE_ID,True
ltdb_interface_hdr,HEADER_ID,True
ltdb_interface_hdr,HEADER_ORDER,True
ltdb_interface_hdr,DESCRIPTION,True
ltdb_interface_hdr,FILENAME,True
ltdb_interface_hdr,LAST_RUN_DATE,True
ltdb_interface_hdr,DELIMIT_CHAR,True
ltdb_interface_hdr,USE_CHANGE_FLAG,True
ltdb_interface_hdr,TABLE_AFFECTED,True
ltdb_interface_hdr,ADDITIONAL_SQL,True
ltdb_interface_hdr,COLUMN_HEADERS,True
ltdb_interface_hdr,CHANGE_DATE_TIME,True
ltdb_interface_hdr,CHANGE_UID,True
ltdb_interface_def,DISTRICT,True
ltdb_interface_def,INTERFACE_ID,True
ltdb_interface_def,DESCRIPTION,True
ltdb_interface_def,UPLOAD_DOWNLOAD,True
ltdb_interface_def,CHANGE_DATE_TIME,True
ltdb_interface_def,CHANGE_UID,True
Med_imm_crit,DISTRICT,True
Med_imm_crit,CRITERIA_NUMBER,True
Med_imm_crit,DESCRIPTION,True
Med_imm_crit,MAX_LETTERS,True
Med_imm_crit,CHANGE_DATE_TIME,True
Med_imm_crit,CHANGE_UID,True
SSP_CFG,DISTRICT,True
SSP_CFG,BUILDING,True
SSP_CFG,TEA_STU_SUMM,True
SSP_CFG,SUB_STU_SUMM,True
SSP_CFG,TEA_SENS_PLAN,True
SSP_CFG,SUB_SENS_PLAN,True
SSP_CFG,TEA_SENS_INT,True
SSP_CFG,SUB_SENS_INT,True
SSP_CFG,TEA_SENS_INT_COMM,True
SSP_CFG,SUB_SENS_INT_COMM,True
SSP_CFG,TEA_INT_MNT,True
SSP_CFG,SUB_INT_MNT,True
SSP_CFG,TEA_GOAL_VIEW,True
SSP_CFG,SUB_GOAL_VIEW,True
SSP_CFG,TEA_GOAL_MNT,True
SSP_CFG,SUB_GOAL_MNT,True
SSP_CFG,TEA_GOAL_ACCESS,True
SSP_CFG,SUB_GOAL_ACCESS,True
SSP_CFG,TEA_INT_ACCESS,True
SSP_CFG,SUB_INT_ACCESS,True
SSP_CFG,CHANGE_DATE_TIME,True
SSP_CFG,CHANGE_UID,True
SSP_MARK_TYPES,DISTRICT,True
SSP_MARK_TYPES,MARK_TYPE,True
SSP_MARK_TYPES,MARK_ORDER,True
SSP_MARK_TYPES,DESCRIPTION,True
SSP_MARK_TYPES,ACTIVE,True
SSP_MARK_TYPES,DEFAULT_GRADE_SCALE,True
SSP_MARK_TYPES,CHANGE_DATE_TIME,True
SSP_MARK_TYPES,CHANGE_UID,True
ARTB_DISTRICTS,DISTRICT,True
ARTB_DISTRICTS,CODE,True
ARTB_DISTRICTS,DESCRIPTION,True
ARTB_DISTRICTS,STATE_CODE_EQUIV,True
ARTB_DISTRICTS,ACTIVE,True
ARTB_DISTRICTS,CHANGE_DATE_TIME,True
ARTB_DISTRICTS,CHANGE_UID,True
SCHD_MS_HRM_AIN,DISTRICT,True
SCHD_MS_HRM_AIN,SECTION_KEY,True
SCHD_MS_HRM_AIN,HRM_SCHD_PRIMARY_HOMEROOM,True
SCHD_MS_HRM_AIN,CHANGE_DATE_TIME,True
SCHD_MS_HRM_AIN,CHANGE_UID,True
REG_STAFF_BLDGS_HRM_AIN,DISTRICT,True
REG_STAFF_BLDGS_HRM_AIN,BUILDING,True
REG_STAFF_BLDGS_HRM_AIN,STAFF_ID,True
REG_STAFF_BLDGS_HRM_AIN,NEXT_YEAR_PRIMARY_HRM,True
REG_STAFF_BLDGS_HRM_AIN,CHANGE_DATE_TIME,True
REG_STAFF_BLDGS_HRM_AIN,CHANGE_UID,True
SPI_EVENT,DISTRICT,True
SPI_EVENT,LOGIN_ID,True
SPI_EVENT,EVENT_DATE_TIME,True
SPI_EVENT,EVENT_TYPE,True
SPI_EVENT,SECTION_KEY,True
SPI_EVENT,COURSE_SESSION,True
SPI_EVENT,ASMT_NUMBER,True
SPI_EVENT,CHANGE_DATE_TIME,True
SPI_EVENT,CHANGE_UID,True
ARTB_RESIDENT,DISTRICT,True
ARTB_RESIDENT,CODE,True
ARTB_RESIDENT,DESCRIPTION,True
ARTB_RESIDENT,STATE_CODE_EQUIV,True
ARTB_RESIDENT,ACTIVE,True
ARTB_RESIDENT,CHANGE_DATE_TIME,True
ARTB_RESIDENT,CHANGE_UID,True
reg_legal_info,DISTRICT,True
reg_legal_info,STUDENT_ID,True
reg_legal_info,LEGAL_FIRST_NAME,True
reg_legal_info,LEGAL_MIDDLE_NAME,True
reg_legal_info,LEGAL_LAST_NAME,True
reg_legal_info,LEGAL_GENERATION,True
reg_legal_info,LEGAL_GENDER,True
reg_legal_info,CHANGE_REASON,True
reg_legal_info,CHANGE_DATE_TIME,True
reg_legal_info,CHANGE_UID,True
LTDB_VIEW_HDR,DISTRICT,True
LTDB_VIEW_HDR,VIEW_CODE,True
LTDB_VIEW_HDR,DESCRIPTION,True
LTDB_VIEW_HDR,CHANGE_DATE_TIME,True
LTDB_VIEW_HDR,CHANGE_UID,True
LTDB_VIEW_DET,DISTRICT,True
LTDB_VIEW_DET,VIEW_CODE,True
LTDB_VIEW_DET,TEST_CODE,True
LTDB_VIEW_DET,TEST_LEVEL,True
LTDB_VIEW_DET,TEST_FORM,True
LTDB_VIEW_DET,TEST_KEY,True
LTDB_VIEW_DET,SUBTEST,True
LTDB_VIEW_DET,SCORE_CODE,True
LTDB_VIEW_DET,SCORE_ORDER,True
LTDB_VIEW_DET,SCORE_LABEL,True
LTDB_VIEW_DET,SCORE_SELECT,True
LTDB_VIEW_DET,RANGE1_HIGH_LIMIT,True
LTDB_VIEW_DET,RANGE2_HIGH_LIMIT,True
LTDB_VIEW_DET,CHANGE_DATE_TIME,True
LTDB_VIEW_DET,CHANGE_UID,True
SSP_GD_SCALE_HDR,DISTRICT,True
SSP_GD_SCALE_HDR,GRADING_SCALE_TYPE,True
SSP_GD_SCALE_HDR,DESCRIPTION,True
SSP_GD_SCALE_HDR,DEFAULT_MARK,True
SSP_GD_SCALE_HDR,CHANGE_DATE_TIME,True
SSP_GD_SCALE_HDR,CHANGE_UID,True
att_notify_elig_cd,DISTRICT,True
att_notify_elig_cd,SCHOOL_YEAR,True
att_notify_elig_cd,SUMMER_SCHOOL,True
att_notify_elig_cd,BUILDING,True
att_notify_elig_cd,NOTIFY_CRITERIA,True
att_notify_elig_cd,SEQUENCE_ORDER,True
att_notify_elig_cd,CURRENT_ELIG_STAT,True
att_notify_elig_cd,ELIGIBILITY_CODE,True
att_notify_elig_cd,CHANGE_DATE_TIME,True
att_notify_elig_cd,CHANGE_UID,True
SCHD_CFG_HRM_AIN,DISTRICT,True
SCHD_CFG_HRM_AIN,SCHOOL_YEAR,True
SCHD_CFG_HRM_AIN,SUMMER_SCHOOL,True
SCHD_CFG_HRM_AIN,BUILDING,True
SCHD_CFG_HRM_AIN,SCHD_BY_PRIMARY_HRM,True
SCHD_CFG_HRM_AIN,CHANGE_DATE_TIME,True
SCHD_CFG_HRM_AIN,CHANGE_UID,True
regtb_name_chgrsn,DISTRICT,True
regtb_name_chgrsn,CODE,True
regtb_name_chgrsn,DESCRIPTION,True
regtb_name_chgrsn,STATE_CODE_EQUIV,True
regtb_name_chgrsn,ACTIVE,True
regtb_name_chgrsn,CHANGE_DATE_TIME,True
regtb_name_chgrsn,CHANGE_UID,True
att_notify_group,DISTRICT,True
att_notify_group,SCHOOL_YEAR,True
att_notify_group,SUMMER_SCHOOL,True
att_notify_group,BUILDING,True
att_notify_group,NOTIFY_GROUP,True
att_notify_group,DESCRIPTION,True
att_notify_group,CHANGE_DATE_TIME,True
att_notify_group,CHANGE_UID,True
STATE_TASK_LOG_DET,DISTRICT,True
STATE_TASK_LOG_DET,PARAM_KEY,True
STATE_TASK_LOG_DET,RUN_NUMBER,True
STATE_TASK_LOG_DET,KEY_VALUE01,True
STATE_TASK_LOG_DET,KEY_VALUE02,True
STATE_TASK_LOG_DET,KEY_VALUE03,True
STATE_TASK_LOG_DET,KEY_VALUE04,True
STATE_TASK_LOG_DET,KEY_VALUE05,True
STATE_TASK_LOG_DET,KEY_VALUE06,True
STATE_TASK_LOG_DET,KEY_VALUE07,True
STATE_TASK_LOG_DET,KEY_VALUE08,True
STATE_TASK_LOG_DET,KEY_VALUE09,True
STATE_TASK_LOG_DET,KEY_VALUE10,True
STATE_TASK_LOG_DET,MESSAGE_INDEX,True
STATE_TASK_LOG_DET,MESSAGE_TYPE,True
STATE_TASK_LOG_DET,MESSAGE,True
STATE_TASK_LOG_DET,CHANGE_DATE_TIME,True
STATE_TASK_LOG_DET,CHANGE_UID,True
'@

}
