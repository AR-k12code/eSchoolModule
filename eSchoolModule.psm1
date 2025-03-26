function Update-eSchoolModule {

     <#
        .SYNOPSIS
        Update the eSchoolModule from Github.
    
    #>

    Param(
        [Parameter(Mandatory = $false)][Switch]$Dev
    )

    if (-Not $(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Must run as administrator!" -ErrorAction STOP
    }

    $ModulePath = Get-Module eSchoolModule | Select-Object -ExpandProperty ModuleBase

    if ($Dev) {
        Write-Host "Updating eSchoolModule from CAMTech Repository."
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/carbm1/eSchoolModule/master/eSchoolModule.psd1" -OutFile "$($ModulePath)\eSchoolModule.psd1"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/carbm1/eSchoolModule/master/eSchoolModule.psm1" -OutFile "$($ModulePath)\eSchoolModule.psm1"
    } else {
        Write-Host "Updating eSchoolModule from ARK12-Code Repository."
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AR-k12code/eSchoolModule/master/eSchoolModule.psd1" -OutFile "$($ModulePath)\eSchoolModule.psd1"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AR-k12code/eSchoolModule/master/eSchoolModule.psm1" -OutFile "$($ModulePath)\eSchoolModule.psm1"
    }

    #This should force a reload of the module. Sometimes you need to actually close and open a new terminal.
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
        [Parameter(Mandatory = $false)]
        [ValidateScript( {
                if ($_ -notmatch '^[a-zA-Z]+[a-zA-Z0-9]*$') {
                    throw "You must specify a ConfigName that starts with a letter and does not contain any spaces, otherwise the Configuration could break."
                } else {
                    $true
                }
            })]
        [String]$ConfigName = "DefaultConfig",
        [Parameter(Mandatory = $true)][String]$username
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
        [Parameter(Mandatory = $true)][String]$ConfigName
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
        [Parameter(Mandatory = $false)][String]$ConfigName="DefaultConfig",
        [Parameter(Mandatory = $false)][securestring]$Password
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
        [Parameter(Mandatory=$false)][String]$ConfigName = "DefaultConfig",
        [Parameter(Mandatory=$false)][Switch]$TrainingSite,
        [Parameter(Mandatory=$false)][String]$Database
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
        $baseUrl = "https://eschool22.esptrn.k12.ar.us/eSchoolPLUS"
    } else {
        $baseUrl = "https://eschool23.esp.k12.ar.us/eSchoolPLUS"
    }

    $username = $config.username
    $password = (New-Object pscredential "user",($config.password | ConvertTo-SecureString)).GetNetworkCredential().Password
    
    Write-Verbose "$($baseUrl)/Account/LogOn"

    #Get Verification Token.
    $response = Invoke-WebRequest `
        -Uri "$($baseUrl)/Account/LogOn" `
        -SessionVariable eSchoolSession `
        -TimeoutSec 10

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
        -TimeoutSec 10

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
        -ContentType "application/x-www-form-urlencoded" `
        -TimeoutSec 10

    #verify we set the environment/selected a valid district.
    try {

        $response4 = Invoke-RestMethod `
            -Uri "$($baseUrl)/Task/TaskAndReportData?includeTaskCount=false&includeReports=false&maximumNumberOfReports=1&includeTasks=false&runningTasksOnly=false" `
            -WebSession $eSchoolSession `
            -MaximumRedirection 0 `
            -TimeoutSec 10

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
        [Parameter(Mandatory=$false)][Switch]$Force #sometimes we need to reauthenticate. Especially after bulk creation of Download Definitions.
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
        Select-Object -Property DisplayName,
            RawFileName,
            FileExtension,
            @{ Name = 'ModifiedDate'; Expression = { (Get-Date "$($PSitem.ModifiedDate)") }},
            ReportSize,
            @{ Name = 'FileSize'; Expression = { ConvertTo-FileSizeString $PSitem.ReportSize } },
            ReportPath |
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
        [Parameter(Mandatory=$true,ParameterSetName="FileName",ValueFromPipelineByPropertyName=$true,Position=0)][Alias('RawFileName')][String]$FileName, #Download an exact named file.
        [Parameter(Mandatory=$true,ParameterSetName="NameLike")][String]$NameLike, #Download the latest file that matches. Example would be HomeAccessPasswords* where there are possibly hundreds of unknown files.
        [Parameter(Mandatory=$false)][String]$OutFile,
        [Parameter(Mandatory=$false)][Switch]$AsObject,
        [Parameter(Mandatory=$false)][Switch]$Raw,
        [Parameter(Mandatory=$false)][String]$Delimeter = ',' #This could be Pipe or whatever the eSchool Definition uses.
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

                if ($report.FileExtension -eq '.jsonl') {
                    $response = Invoke-WebRequest -Uri "$($eschoolSession.Url)/ReportViewer/FileStream?fileName=$($report.RawFileName)" -WebSession $eschoolSession.Session
                    #in order to convert from JSONL we have to split the string on `n and exclude the top row called CODE.
                    $content = [System.Text.Encoding]::GetEncoding(1252).GetString($response.Content)
                    $jsonl = $content.split("`n") | Select-Object -Skip 1
                    if ($jsonl) {
                        return $jsonl | ConvertFrom-Json
                    } else {
                        Write-Warning "No data found in $($report.RawFileName)."
                        return $null
                    }
                } else {
                    $response = Invoke-WebRequest -Uri "$($eschoolSession.Url)/ReportViewer/FileStream?fileName=$($report.RawFileName)" -WebSession $eschoolSession.Session
                    return [System.Text.Encoding]::GetEncoding(1252).GetString($response.Content) | ConvertFrom-CSV -Delimiter $Delimeter
                }
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
        [Parameter(Mandatory=$true,HelpMessage="File Path",Position=0)]$InFile
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
        [Parameter(Mandatory=$true,Position=0)][String]$FileName
    )

    Assert-eSPSession

    $params = @{
        'reportsToDelete' = @($FileName)
        'tasksToDelete' = @()
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Task/DeleteTasksAndReports" `
            -Method "POST" `
            -WebSession $eSchoolSession.session `
            -ContentType "application/json; charset=UTF-8" `
            -Body $params
    } catch {
        Write-Error "Failed to delete $($FileName). $_" -ErrorAction Stop
    }

    if ($reponse.Reports | Where-Object -Property RawFileName -eq $FileName) {
        Write-Error "Failed to delete $FileName." -ErrorAction Stop
    } else {
        Write-Host "Successfully deleted $FileName." -ForegroundColor Green
    }

}

function Invoke-eSPDownloadDefinition {
    <#
    
    .SYNOPSIS
    Start a Download Definition
    
    #>

    Param(
        [Parameter(Mandatory=$true)][ValidateScript( { ($PSitem.Length) -eq 5} )][String]$InterfaceID,
        [Parameter(Mandatory=$false)][Switch]$ActiveStudentsOnly,
        [Parameter(Mandatory=$false)][Switch]$Wait #wait until the scheduled task is complete or errored.
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

    # No details are returned besides PageState = 2 for success.
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
        [Parameter(Mandatory=$true)][ValidateScript( { ($PSitem.Length) -eq 5} )][String]$InterfaceID,
        [Parameter(Mandatory=$false)][ValidateSet("R","V")][String][String]$RunMode = 'V',
        [Parameter(Mandatory=$false)][Switch]$DoNotUpdateExistingRecords, #Do you want the upload definition to update existing records?
        [Parameter(Mandatory=$false)][Switch]$InsertNewRecords, #Do you want the upload definition to insert new records?
        [Parameter(Mandatory=$false)][Switch]$UpdateBlankRecords, #Do you want the upload definition to update blank records?
        [Parameter(Mandatory=$false)][switch]$ProgramEndDatePriorToStartDate, #this will close the last vector date to the day before the start date.
        [Parameter(Mandatory=$false)]$ProgramStartDateColumn, #for the ESMU8 its 3.
        [Parameter(Mandatory=$false)][Switch]$ProgramStartDateData,
        [Parameter(Mandatory=$false)][Switch]$Wait #wait until the scheduled task is complete or errored.
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

    if ($ProgramEndDatePriorToStartDate) {

        $params.ProgramDatesEnabled = 'Y'
        $params.ProgramStartDate = 'FSD'
        $params.ProgramEndDate = 'PSD'
        $params.StudWithoutOpenProg = 'USD'

        $params.GridEndDateData = @(
            @{
                Header = "1    -Meal Status Upload"
                DateField = "1"
                promptName = "PROGRAM_END_DATE_FIELD_1"
                value = "1"
            }
        )
    }

    if ($ProgramStartDateColumn) {

        $params.ProgramDatesEnabled = 'Y'
        $params.ProgramStartDate = 'FSD'
        $params.ProgramEndDate = 'PSD'
        $params.StudWithoutOpenProg = 'USD'

        $params.GridStartDateData = @(
            @{
                Header = "1    -Meal Status Upload"
                DateField = "$ProgramStartDateColumn"
                promptName = "PROGRAM_START_DATE_FIELD_1"
                value = "$ProgramStartDateColumn"
            }
        )
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
        [Parameter(Mandatory = $false)][Switch]$ActiveTasksOnly,
        [Parameter(Mandatory = $false)][Switch]$ErrorsOnly,
        [Parameter(Mandatory = $false)][Switch]$SilentErrors
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
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][String]$TaskKey
    )

    Begin {
        Assert-eSPSession
    }

    Process {

        #This always returns the Task List regardless of what we send it.
        $response = Invoke-RestMethod -Uri "$($eschoolSession.Url)/Task/ClearErroredTask" `
            -Method "POST" `
            -WebSession $eschoolSession.Session `
            -ContentType "application/json; charset=UTF-8" `
            -Body "{`"paramKey`":`"$($PSitem.TaskKey)`"}"

    }

}

function Get-eSPSchools {
    <#
    
    .SYNOPSIS
    Return Building Information
    
    .DESCRIPTION
    By default will only return schools with a default calendar assigned.

    #>

    Param(
        [Parameter(Mandatory=$false)][Switch]$All
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
        [Parameter(Mandatory=$false,ParameterSetName="StudentID",Position=0)][Alias('ID')][int]$StudentID, #ID of the Building
        [Parameter(Mandatory=$false,ParameterSetName="default")][int]$Building, #ID of the Building
        [Parameter(Mandatory=$false)]
        [ValidateSet('PK','KA','KF','KP','SS','SM','EE','GG','01','02','03','04','05','06','07','08','09','10','11','12')]
        $Grade,
        [Parameter(Mandatory=$false,ParameterSetName="all")][Switch]$InActive,
        [Parameter(Mandatory=$false,ParameterSetName="all")][Switch]$Graduated,
        [Parameter(Mandatory=$false,ParameterSetName="all")][Switch]$All, #Include Graduated and Inactive.
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

        $fields = Get-eSPAdditionalREGMAINTTables | ConvertFrom-CSV | Where-Object { $includeTables -contains $PSitem.table }

        $fields | ForEach-Object {
            $params += New-eSPSearchListField -index $index -TableName $PSitem.table -ColumnName $PSitem.field
            $index++
        }

    }

    return Invoke-eSPExecuteSearch -SearchType REGMAINT -SearchParams $params -PageSize $PageSize

}

#This should be an alias of Submit-eSPDefinition
# function New-eSPDefinition {
#     Param(
#         [Parameter(Mandatory=$true)]$Definition
#     )

#     $jsonpayload = $Definition | ConvertTo-Json -depth 6

#     Write-Verbose ($jsonpayload)
 
#     #attempt to delete existing if its there already
#     Remove-eSPInterfaceId -InterfaceId "$($Definition.UploadDownloadDefinition.InterfaceId)"

#     $response = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/SaveUploadDownload" `
#         -WebSession $eSchoolSession.Session `
#         -Method "POST" `
#         -ContentType "application/json; charset=UTF-8" `
#         -Body $jsonpayload -MaximumRedirection 0

# }

function Remove-eSPInterfaceId {
    [Alias("Remove-eSPDefinition")]

    Param(
        [Parameter(Mandatory=$true)][Alias("name")]$InterfaceID
    )

    #Find the InterfaceID in eSchool First.
    $definition = Invoke-eSPExecuteSearch -SearchType UPLOADDEF |
        Where-Object -Property district -NE 0 |
        Where-Object -Property interface_id -EQ $InterfaceID

    if ($definition) {
        $jsonPayload = [ordered]@{
            SearchType = "UPLOADDEF"
            Columns = @()
            Deleted = @(
                @{ 
                    Keys = @(
                        @{
                            Key = "district"
                            Value = $definition.district
                        },
                        @{
                            Key = "interface_id"
                            Value = $definition.interface_id
                        }
                    )
                }
            )
        } | ConvertTo-Json -Depth 6

        Write-Verbose ($jsonPayload)
    
        $response = Invoke-RESTMethod -Uri "$($eSchoolSession.Url)/Search/SaveResults" `
            -WebSession $eSchoolSession.Session `
            -Method "POST" `
            -ContentType "application/json; charset=UTF-8" `
            -Body $jsonpayload -MaximumRedirection 0

        if ($response.success -eq $true) {
            Write-Host "Successfully removed $InterfaceID from eSchool."
        } else {
            #throw an exception here.
            Write-Error "Failed to remove $InterfaceID from eSchool." -ErrorAction Stop
        }

    } else {
        #No exception here.
        Write-Warning "Could not find $InterfaceID in eSchool."
    }

}

function Invoke-eSPExecuteSearch {
    <#
    
    .SYNOPSIS
    Execute a Search in eSchool and return structured data.
    
    #>

    Param(
        [Parameter(Mandatory=$true)][ValidateSet("REGMAINT","UPLOADDEF","DUPLICATECONTACT","BUILDINGDEF","STAFFCATALOG","MASTERSCHEDULE",'COURSECAT','MPS','CALENDAR','USER')][String]$SearchType,
        [Parameter(Mandatory=$false)]$SearchParams,
        [Parameter(Mandatory=$false)][int]$pageSize = 250,
        [Parameter(Mandatory=$false)][int]$stopAfterPage
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
        [Parameter(Mandatory=$true)][ValidateSet("Char","VarChar","Int","DateTime")]$DataType = "VarChar",
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
        # [Parameter(Mandatory=$false)][Switch]$UploadDef #if this is an upload definition we need additional information.
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
        [Parameter(Mandatory=$true)][String]$FieldId, #must be a string.
        [Parameter(Mandatory=$true)]$FieldOrder,
        [Parameter(Mandatory=$true)]$TableName,
        [Parameter(Mandatory=$true)]$ColumnName,
        [Parameter(Mandatory=$false)]$FieldLength = 255,
        [Parameter(Mandatory=$false)]$TableAlias = $null,
        [Parameter(Mandatory=$false)]$ColumnOverride = $null
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
        "ColumnOverride" = $ColumnOverride
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
        [Parameter(Mandatory=$true)][array]$Tables, #Which tables do you want to create a download definition for.
        [Parameter(Mandatory=$true)][ValidateScript( { ($PSitem.Length) -eq 5} )]$InterfaceId,
        [Parameter(Mandatory=$false)][String]$AdditionalSQL = $null, #additional SQL
        [Parameter(Mandatory=$false)][Switch]$DoNotLimitSchoolYear, #otherwise all queries are limited to the current school year if the table has the SCHOOL_YEAR in it.
        [Parameter(Mandatory=$false)]$Delimiter = ',',
        [Parameter(Mandatory=$false)]$Description = "eSchoolModule Bulk Definition",
        [Parameter(Mandatory=$false)]$FilePrefix = '', #Make all files start with this. Something like "GUARD_"
        [Parameter(Mandatory=$false)][Switch]$Force, #overwrite existing.
        [Parameter(Mandatory=$false)][Switch]$IncludeSSN #If the table has SSN or FMS_EMPL_NUMBER then include it. Otherwise this is excluded by default.
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
    $tables_with_years = Get-eSPTablesWithYears
    $tables_with_sectionkey = Get-eSPTablesWithSectionKey

    $newDefinition = New-espDefinitionTemplate -InterfaceId "$InterfaceId" -Description "$Description"
    
    $headerorder = 0
    $tblShortNamesArray = @()

    Get-eSPTableDefinitions | Where-Object { $tables -contains $PSItem.tblName } | Group-Object -Property tblName | ForEach-Object {
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

            #Default Limit to Current School Year SECTION_KEYs. This leaves the {{WHERE}} in the SQL template so we can replace it later.
        if (-Not($DoNotLimitSchoolYear) -and ($tables_with_sectionkey -contains $Table)) {
            if ($sqlspecified) {
                $sql_table += " AND SECTION_KEY IN (SELECT SECTION_KEY FROM SCHD_MS WHERE SCHOOL_YEAR = (SELECT CASE WHEN MONTH(GETDATE()) > 6 THEN YEAR(DATEADD(YEAR,1,GETDATE())) ELSE YEAR(GETDATE()) END)) "
            } else {
                $sql_table = "$($sql_table) WHERE SECTION_KEY IN (SELECT SECTION_KEY FROM SCHD_MS WHERE SCHOOL_YEAR = (SELECT CASE WHEN MONTH(GETDATE()) > 6 THEN YEAR(DATEADD(YEAR,1,GETDATE())) ELSE YEAR(GETDATE()) END)) "
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

            if (-Not($IncludeSSN)) {
                if (@('SSN','FMS_EMPL_NUMBER') -contains $PSItem.colName) {
                    return
                }
            }

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

    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 99)
    Submit-eSPDefinition -Definition $newDefinition -Force
    
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
        [Parameter(Mandatory=$false)][Switch]$Force
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

    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 6)
 
    Submit-eSPDefinition -Definition $newDefinition -Force

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

    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 6)
 
    Submit-eSPDefinition -Definition $newDefinition -Force

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
    
    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 6)
 
    Submit-eSPDefinition -Definition $newDefinition -Force

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
    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 6)
    Submit-eSPDefinition -Definition $newDefinition -Force

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
    
    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 6)
    Submit-eSPDefinition -Definition $newDefinition -Force

    #Since we are trying to merge records we should also create an upload definition for Phone Numbers.
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
    
    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 6)
    Submit-eSPDefinition -Definition $newDefinition -Force
}

function New-eSPHACUploadDefinition {
    <#

    .SYNOPSIS
    This function will create the Upload and Download Definitions used to fix HAC usernames.
    
    #>
    
    Param(
        [Parameter(Mandatory=$false)][Switch]$Force
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

    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 6)
    Submit-eSPDefinition -Definition $newDefinition -Force

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
    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 6)
    Submit-eSPDefinition -Definition $newDefinition -Force

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

    #we need REG_PERSONAL for the MEAL_STATUS column.
    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
        -InterfaceId "ESMD2" `
        -HeaderId 2 `
        -HeaderOrder 2 `
        -FileName "esp_meal_status_reg_personal.csv" `
        -TableName "reg_personal" `
        -Description "eSchoolModule - Meal Status" `
        -AdditionalSQL 'LEFT JOIN REG ON REG_PERSONAL.STUDENT_ID = REG.STUDENT_ID WHERE REG.CURRENT_STATUS = ''A'''

    $index = 1
    @("STUDENT_ID","MEAL_STATUS") | ForEach-Object {
        $newDefinition.UploadDownloadDefinition.InterfaceHeaders[1].InterfaceDetails +=	New-eSPDefinitionColumn `
            -InterfaceId "ESMD2" `
            -HeaderId 2 `
            -TableName "reg_personal" `
            -FieldId $index `
            -FieldOrder $index `
            -ColumnName "$PSitem" `
            -FieldLength 255
        $index++
    }

    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 6)
    Submit-eSPDefinition -Definition $newDefinition -Force

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

    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 6)
    Submit-eSPDefinition -Definition $newDefinition -Force

    #Upload Definition - by having the MEAL_STATUS column eSchool will automatically try to do the program/vector dates.
    $newDefinition = New-eSPDefinitionTemplate -InterfaceId ESMU8 -Description "eSchoolModule - Upload Meal Status 2" -DefinitionType Upload

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPInterfaceHeader `
        -InterfaceId "ESMU8" `
        -HeaderId 1 `
        -HeaderOrder 1 `
        -FileName "meal_status_upload_changes.csv" `
        -TableName "reg_personal" `
        -Description "Meal Status Upload"

    $rows = @(
        @{ table = "reg_personal"; column = "STUDENT_ID"; length = 10 },
        @{ table = "reg_personal"; column = "MEAL_STATUS"; length = 2 },
        @{ table = "DUMMY"; column = "DUMMY"; length = 10 },
        @{ table = "DUMMY"; column = "DUMMY"; length = 10 },
        @{ table = "DUMMY"; column = "DUMMY"; length = 10 }
    )

    $columns = @()
    $columnNum = 1
    $rows | ForEach-Object {
        $columns += New-eSPDefinitionColumn -InterfaceID 'ESMU8' -HeaderID 1 -TableName $($PSitem.table) -FieldId $columnNum -FieldOrder $columnNum -ColumnName $($PSitem.column) -FieldLength $($PSItem.length)
        $columnNum++
    }

    $newDefinition.UploadDownloadDefinition.InterfaceHeaders[0].InterfaceDetails = $columns

    Write-Verbose ($newDefinition | ConvertTo-Json -Depth 6)
    Submit-eSPDefinition -Definition $newDefinition -Force

    #Create the ESMD3 definition for the REG_ENTRY_WITH table to get the last 2 years. Filename will be 2YR_REG_ENTRY_WITH.csv
    New-eSPBulkDownloadDefinition -Tables REG_ENTRY_WITH -InterfaceId "ESMD3" -Description "eSchoolModule - REG_ENTRY_WITH" -AdditionalSQL "WHERE SCHOOL_YEAR > DATEPART(year,DATEADD(year, -2, GETDATE()))" -FilePrefix '2YR_' -DoNotLimitSchoolYear -Force

}

function New-eSPJSONLDefinition {
    <#
    
    .SYNOPSIS
    Create a Download Definition that uses JSONL for the file format.

    .DESCRIPTION
    Since eSchool can not properly escape CSV files we need to use a structured data format to retrieve data. JSONL properly escapes data and allows for structured data to be pulled.
    Unfortunately this has two problems. 1. There can only be one definition per table pulled. 2. It dramatically increases the file size.
    But for structured data it is the only option.
    
    .NOTES
    If the table has ROW_IDENTITY you should use it for the WHERE clause.
    If the table is a 1:1 for students then you should use the STUDENT_ID for the WHERE clause.
    We should really use the PK for the table. This might be multiple fields so this can be complicated and will require the table defintions.

    #>
    Param(
        [Parameter(Mandatory=$true)][String]$Table, #Single Table.
        [Parameter(Mandatory=$false)][String]$Columns, #Comma separated string with no spaces, otherwise it will be the columns for the table (excluding SSN and FMS_EMPL_NUMBER by default.)
        [Parameter(Mandatory=$false)][Switch]$PKColumnsOnly, #Primary Key columns only. This is needed to find deleted records.
        [Parameter(Mandatory=$true)][ValidateScript( { ($PSitem.Length) -eq 5} )]$InterfaceId,
        [Parameter(Mandatory=$false)][String]$filename, #If you want to specify the filename, otherwise it will be the InterfaceId since its a 1:1 definition/file.
        [Parameter(Mandatory=$false)][String]$AdditionalSQL = $null, #additional SQL
        [Parameter(Mandatory=$false)][Switch]$DoNotLimitSchoolYear, #otherwise all queries are limited to the current school year if the table has the SCHOOL_YEAR OR SECTION_KEY in it.
        [Parameter(Mandatory=$false)]$Delimiter = ',', #Does not matter here since this returns a single column.
        [Parameter(Mandatory=$false)]$Description = "eSchoolModule JSONL Definition",
        [Parameter(Mandatory=$false)]$FilePrefix = '', #Make all files start with this. Something like "GUARD_"
        [Parameter(Mandatory=$false)][Switch]$Force, #overwrite existing.
        [Parameter(Mandatory=$false)][Switch]$IncludeSSN, #If the table has SSN or FMS_EMPL_NUMBER then include it. Otherwise this is excluded by default.
        [Parameter(Mandatory=$false)][switch]$DoNotSubmit #Do not submit the definition to eSchool. Just return it so we can add more Interface Headers.
    )

    $newDefinition = New-espDefinitionTemplate -InterfaceId "$InterfaceId" -Description "$Description"

    #the first HeaderId will always be the InterfaceId. All others will need to be different.
    $newDefinition.UploadDownloadDefinition.InterfaceHeaders += New-eSPJSONLInterfaceHeader @PSBoundParameters -HeaderId $InterfaceId 

    #this will need to be submitted via the Submit-eSPDefinition function.
    if ($DoNotSubmit) {
        return $newDefinition 
    } else {
        if ($Force) {
            Submit-eSPDefinition -Definition $newDefinition -Force
        } else {
            Submit-eSPDefinition -Definition $newDefinition
        }
    }
        
}

function New-eSPJSONLInterfaceHeader {
    Param(
        [Parameter(Mandatory=$true)][String]$Table, #Single Table.
        [Parameter(Mandatory=$false)]$Columns, #If you want to specify the columns, otherwise it will be the columns for the table (excluding SSN and FMS_EMPL_NUMBER by default.)
        [Parameter(Mandatory=$false)][Switch]$PKColumnsOnly, #Primary Key columns only. This is needed to find deleted records.
        [Parameter(Mandatory=$true)][ValidateScript( { ($PSitem.Length) -eq 5} )]$InterfaceId,
        [Parameter(Mandatory=$false)][String]$filename, #If you want to specify the filename, otherwise it will be the InterfaceId since its a 1:1 definition/file.
        [Parameter(Mandatory=$false)][String]$AdditionalSQL = $null, #additional SQL
        [Parameter(Mandatory=$false)][Switch]$DoNotLimitSchoolYear, #otherwise all queries are limited to the current school year if the table has the SCHOOL_YEAR in it.
        [Parameter(Mandatory=$false)]$Delimiter = ',', #Does not matter here since this returns a single column.
        [Parameter(Mandatory=$false)]$Description = "eSchoolModule JSONL Definition",
        [Parameter(Mandatory=$false)]$FilePrefix = '', #Make all files start with this. Something like "GUARD_"
        [Parameter(Mandatory=$false)][Switch]$Force, #Doesn't apply here but has to be here so I can pass the same params from New-eSPJSONLDefinition.
        [Parameter(Mandatory=$false)][Switch]$IncludeSSN, #If the table has SSN or FMS_EMPL_NUMBER then include it. Otherwise this is excluded by default.
        [Parameter(Mandatory=$false)][switch]$DoNotSubmit, #Does nothing here.
        [Parameter(Mandatory=$true)][String]$HeaderId, #File Header.
        [Parameter(Mandatory=$false)][int]$HeaderOrder = 1
    )

    $newDefinition = New-espDefinitionTemplate -InterfaceId "$InterfaceId" -Description "$Description"

    #Import-CSV ".\resources\eSchool Tables with SCHOOL_YEAR.csv" | Select-Object -ExpandProperty tblName
    $tables_with_years = Get-eSPTablesWithYears
    $tables_with_sectionkey = Get-eSPTablesWithSectionKey

    if (-Not($filename)) {
        $filename = "$($InterfaceId).jsonl"
    }

    # {{MATCH}} = "ROW_IDENTITY = t.ROW_IDENTITY", "AND STUDENT_ID = t.STUDENT_ID", etc.
    # {{WHERE}} = "AND t.SCHOOL_YEAR > 2020"
    $sqlTemplate = 'INNER JOIN REG ON 1=2
    UNION ALL
    SELECT j=
    CONVERT(VARCHAR(8000),(SELECT {{COLUMNS}} FROM {{TABLE}} WHERE 1=1 AND {{MATCH}} FOR JSON PATH, INCLUDE_NULL_VALUES))
    FROM {{TABLE}} t WHERE 1=1 {{WHERE}}'

    #table
    $sqlTemplate = $sqlTemplate -replace '{{TABLE}}',"$($Table)"

    #If columns are specified then just pull that list.
    #Else, if IncludeSSN then pull all columns.
    #Else find all the columns for this table and specify them in the SELECT statement so we can exclude the SSN and FMS_EMPL_NUMBER if needed.
    if ($columns) {
        $columns = $columns -split ',' 
    } elseif ($IncludeSSN) {
        $columns = '*'
    } elseif ($PKColumnsOnly) {
        $columns = Get-eSPTablePrimaryKeys -Table $Table
        #some tables have a no primary keys.
        if (-Not($columns)) {
            #default back to everything but the SSN and FMS_EMPL_NUMBER
            Write-Warning "Table $Table does not contain PRIMARY KEYS. We will use the default columns instead."
            $columns = Get-eSPTableColumns -Table $Table | Where-Object { @('SSN','FMS_EMPL_NUMBER') -notcontains $PSItem }
        }
    } else {
        $columns = Get-eSPTableColumns -Table $Table | Where-Object { @('SSN','FMS_EMPL_NUMBER') -notcontains $PSItem }
    }

    #we need to trim STUDENT_ID from the columns if it is there. Trimming all other fields will need to be done on the client end.
    #There are some tables where the colUserTypeId isn't 175. I don't expect this to be an issue though.
    if ($columns.IndexOf('STUDENT_ID') -ne -1) {
        $columns[$columns.IndexOf('STUDENT_ID')] = 'TRIM(STUDENT_ID) AS STUDENT_ID'
    }

    $sqlTemplate = $sqlTemplate -replace '{{COLUMNS}}',"$($columns -join ',')"

    #MATCH

    # If ROW_IDENTITY exists we use it. Otherwise we need to pull the primary keys for this table to make sure we match exactly.
    if ($columns -contains 'ROW_IDENTITY') {
        $sqlTemplate = $sqlTemplate -replace '{{MATCH}}',"ROW_IDENTITY = t.ROW_IDENTITY"
    } else {
        #We need to pull the primary keys for this table to make sure we match exactly.
        $primaryKeys = Get-eSPTablePrimaryKeys -Table $Table
        
        if ($primaryKeys) {
            $primaryKeysMatch = $primaryKeys | ForEach-Object {
                "$($PSItem) = t.$($PSItem)"
            }
        } else {
            #some tables have no ROW_IDENTIY or PRIMARY KEYS. This is a problem and must be matched on all columns OR a uniquely generated identifying column.
            Write-Warning "Table $Table does not contain ROW_IDENTITY or PRIMARY KEYS. We will match on all columns instead."
            $primaryKeysMatch = Get-eSPTableColumns -Table $Table | ForEach-Object {
                "$($PSItem) = t.$($PSItem)"
            }
            
        }

        $sqlTemplate = $sqlTemplate -replace '{{MATCH}}',"$($primaryKeysMatch -join ' AND ')"
    }

    #WHERE

    #Default Limit to Current School Year. This leaves the {{WHERE}} in the SQL template so we can replace it later.
    if (-Not($DoNotLimitSchoolYear) -and ($tables_with_years -contains $Table)) {
        $sqlTemplate = $sqlTemplate -replace '{{WHERE}}'," AND SCHOOL_YEAR = (SELECT CASE WHEN MONTH(GetDate()) > 6 THEN YEAR(GetDate()) + 1 ELSE YEAR(GetDate()) END) {{WHERE}}"
    }

    #Default Limit to Current School Year SECTION_KEYs. This leaves the {{WHERE}} in the SQL template so we can replace it later.
    if (-Not($DoNotLimitSchoolYear) -and ($tables_with_sectionkey -contains $Table)) {
        $sqlTemplate = $sqlTemplate -replace '{{WHERE}}'," AND SECTION_KEY IN (SELECT SECTION_KEY FROM SCHD_MS WHERE SCHOOL_YEAR = (SELECT CASE WHEN MONTH(GETDATE()) > 6 THEN YEAR(DATEADD(YEAR,1,GETDATE())) ELSE YEAR(GETDATE()) END)) {{WHERE}}"
    }

    if ($AdditionalSQL) {

        #if the incoming SQL does not have an AND then we need to append it to the existing WHERE clause.
        #This is because I keep forgetting to add it. ¯\_(ツ)_/¯
        if ($additionalSQL.Substring(0,3) -eq 'AND') {
            $sqlTemplate = $sqlTemplate -replace '{{WHERE}}'," $AdditionalSQL"
        } else {
            $sqlTemplate = $sqlTemplate -replace '{{WHERE}}'," AND $AdditionalSQL"
        }

    } else {
        $sqlTemplate = $sqlTemplate -replace '{{WHERE}}','' #remove the WHERE clause.
    }

    $eSPJSONInterfaceHeader = New-eSPInterfaceHeader `
        -InterfaceId $InterfaceId `
        -HeaderId $HeaderId `
        -HeaderOrder $HeaderOrder `
        -FileName "$($FilePrefix)$($filename)" `
        -TableName "atttb_state_grp" `
        -Description "$description" `
        -AdditionalSql $sqlTemplate `
        -Delimiter $delimiter
    
    $eSPJSONInterfaceHeader.InterfaceDetails = @(
        (New-eSPDefinitionColumn `
            -InterfaceId "$InterfaceId" `
            -HeaderId $HeaderId `
            -TableName "atttb_state_grp" `
            -FieldId 1 `
            -FieldOrder 1 `
            -ColumnName "CODE" `
            -FieldLength 9999 `
            -ColumnOverride 'j')
    )

    return $eSPJSONInterfaceHeader

}

function Submit-eSPDefinition {
    [Alias("New-eSPDefinition")]
    <#
    
        .SYNOPSIS
        Submit a definition to the eSchool Interface.

        .DESCRIPTION
        This would already be created by New-eSPDownloadDefinition or New-eSPUploadDefinition. This is just a helper function to submit the definition to the eSchool Interface.
    
    #>
    Param(
        [Parameter(Mandatory=$true)][Hashtable]$Definition,
        [Parameter(Mandatory=$false)][Switch]$Force
    )

    Assert-eSPSession
    
    $jsonpayload = $Definition | ConvertTo-Json -Depth 99

    Write-Verbose ($jsonpayload)

    if ($Force) {
        Remove-eSPInterfaceId -InterfaceId "$($Definition.UploadDownloadDefinition.InterfaceId)"
    }

    $response = Invoke-RestMethod -Uri "$($eSchoolSession.Url)/Utility/SaveUploadDownload" `
        -WebSession $eSchoolSession.Session `
        -Method "POST" `
        -ContentType "application/json; charset=UTF-8" `
        -Body $jsonpayload `
        -MaximumRedirection 0 `
        -SkipHttpErrorCheck

    if ($response.PageState -eq 2) {
        Write-Host "Download definition created successfully. You can review it here: $($eSchoolSession.Url)/Utility/UploadDownload?interfaceId=$($Definition.UploadDownloadDefinition.InterfaceId)" -ForegroundColor Green

        Assert-eSPSession -Force #Must reauthenticate.

        return [PSCustomObject]@{
            'Tables' = $table
            'Success' = $True
            'Message' = $response
        }
    } else {
        Write-Error "Download Definition failed. $($response.ValidationErrorMessages)" -ErrorAction Stop
    }

}

function Get-eSPTableNames {

    <#
    
        .SYNOPSIS
        Return an array of tables.
    
    #>
    return (Get-eSPTableDefinitions |
        Select-Object -ExpandProperty tblName
        )
}

function Get-eSPTableColumns {

    <#
    
        .SYNOPSIS
        Return an array of table columns.
    
    #>

    Param(
        [Parameter(Mandatory=$true)]
        [ValidateScript( {
            if ((Get-eSPTableNames) -notcontains $PSitem) {
                throw "Table $PSitem does not exist."
            } else {
                $true
            }
        })]
        [String]$Table
    )

    return (Get-eSPTableDefinitions |
        Where-Object -Property tblName -eq $Table |
        Select-Object -ExpandProperty colName
    )
}

function Get-eSPTablesWithYears {

    <#
    
        .SYNOPSIS
        Return an array of tables with the SCHOOL_YEAR property.
    
    #>
    return (Get-eSPTableDefinitions | 
        Where-Object -Property colName -EQ "SCHOOL_YEAR" |
        Select-Object -ExpandProperty tblName
        )
}

function Get-eSPTablesWithSectionKey {

    <#
    
        .SYNOPSIS
        Return an array of tables with the SECTION_KEY property.
    
    #>
    return (Get-eSPTableDefinitions | 
        Where-Object -Property colName -EQ "SECTION_KEY" |
        Select-Object -ExpandProperty tblName
        )
}


function Get-eSPTablePrimaryKeys {
    <#
    
        .SYNOPSIS
        Get the Primary Keys for a specified table.
    
    #>

    Param(
        [Parameter(Mandatory=$true)]
        [ValidateScript( {
            if ((Get-eSPTableNames) -notcontains $PSitem) {
                throw "Table $PSitem does not exist."
            } else {
                $true
            }
        })]
        [String]$Table
    )

    return (Get-eSPTableDefinitions |
        Where-Object -Property tblName -eq $Table |
        Where-Object -Property colIsIdentity -EQ 1 |
        Select-Object -ExpandProperty colName)

}

function Get-eSPTableDefinitions {
<#

    .SYNOPSIS
    Return the table definitions for eSchool.

    .DESCRIPTION
    We do not want to be reaching back out to github for this information. This is a static list of tables and their columns. It will need to be updated with the module.
    This data must come from the Get-CogSqlData -Page tblDefinitions as it contains the primary keys correctly.

#>

$espDatabase = @'
tblName,colName,colIsIdentity
_tblStateCourses,code,0
_tblStateCourses,descr,0
_tblStateCourses,core,0
API_AUTH_LOG,AUTH_LOG_ID,1
API_AUTH_LOG,CALLER_ID,0
API_AUTH_LOG,NONCE,0
API_AUTH_LOG,AUTH_SUCCESS,0
API_AUTH_LOG,CHANGE_DATE_TIME,0
API_CALLER_CFG,CALLER_ID,1
API_CALLER_CFG,DISTRICT,0
API_CALLER_CFG,SUMMER_SCHOOL,0
API_CALLER_CFG,CALLER_NAME,0
API_CALLER_CFG,AUTH_TOKEN,0
API_CALLER_CFG,LOG_LEVEL,0
API_CALLER_CFG,MIN_DELTA_CALC_MINUTES,0
API_CALLER_CFG,INCLUDE_OUT_OF_DISTRICT_BLDGS,0
API_CALLER_CFG,INCLUDE_PREREG_STUDENTS,0
API_CALLER_CFG,ACTIVE,0
API_CALLER_CFG,CHANGE_DATE_TIME,0
API_CALLER_CFG,CHANGE_UID,0
API_CALLER_CFG,SIGNATURE_METHOD,0
API_CALLER_CFG,AUTHENTICATION_METHOD,0
API_CALLER_CFG,USE_DELTA_FILTER,0
API_CALLER_CFG_OPTIONS,CALLER_ID,1
API_CALLER_CFG_OPTIONS,OPTION_NAME,1
API_CALLER_CFG_OPTIONS,OPTION_VALUE,0
API_CALLER_CFG_OPTIONS,CHANGE_DATE_TIME,0
API_CALLER_CFG_OPTIONS,CHANGE_UID,0
API_CALLER_SECURE_DET,CALLER_ID,1
API_CALLER_SECURE_DET,RULE_ID,1
API_CALLER_SECURE_DET,JSON_LABEL,1
API_CALLER_SECURE_DET,CHANGE_DATE_TIME,0
API_CALLER_SECURE_DET,CHANGE_UID,0
API_CALLER_SUBSCRIBE,CALLER_ID,1
API_CALLER_SUBSCRIBE,RULE_ID,1
API_CALLER_SUBSCRIBE,ADDITIONAL_SQL_JOINS,0
API_CALLER_SUBSCRIBE,ADDITIONAL_SQL_WHERE,0
API_CALLER_SUBSCRIBE,LAST_SINCE_DATETIME,0
API_CALLER_SUBSCRIBE,DELTA_MINUTES,0
API_CALLER_SUBSCRIBE,ACTIVE,0
API_CALLER_SUBSCRIBE,CHANGE_DATE_TIME,0
API_CALLER_SUBSCRIBE,CHANGE_UID,0
API_CALLER_SUBSCRIBE,SCOPE,1
API_DELTA_CACHE,DELTA_ID,1
API_DELTA_CACHE,RULE_ID,0
API_DELTA_CACHE,CALLER_ID,0
API_DELTA_CACHE,ROW_CHECKSUM,0
API_DELTA_CACHE,ROW_UNIQUE_ID,0
API_DELTA_CACHE,RECORD_STATUS,0
API_DELTA_CACHE,CHANGE_DATE_TIME,0
API_DISTRICT_DEFINED,DISTRICT,1
API_DISTRICT_DEFINED,CALLER_ID,1
API_DISTRICT_DEFINED,RULE_ID,1
API_DISTRICT_DEFINED,SCREEN_TYPE,1
API_DISTRICT_DEFINED,SCREEN_NUMBER,1
API_DISTRICT_DEFINED,FIELD_NUMBER,1
API_DISTRICT_DEFINED,DISPLAY_ORDER,0
API_DISTRICT_DEFINED,JSON_LABEL,0
API_DISTRICT_DEFINED,FORMAT_TYPE,0
API_DISTRICT_DEFINED,FORMAT_MASK,0
API_DISTRICT_DEFINED,CHANGE_DATE_TIME,0
API_DISTRICT_DEFINED,CHANGE_UID,0
API_GUID_GB_ASMT,DISTRICT,1
API_GUID_GB_ASMT,SECTION_KEY,1
API_GUID_GB_ASMT,COURSE_SESSION,1
API_GUID_GB_ASMT,ASMT_NUMBER,1
API_GUID_GB_ASMT,API_REFID,0
API_GUID_GB_ASMT,CHANGE_DATE_TIME,0
API_GUID_GB_ASMT,CHANGE_UID,0
API_GUID_GB_SCORE,DISTRICT,1
API_GUID_GB_SCORE,SECTION_KEY,1
API_GUID_GB_SCORE,COURSE_SESSION,1
API_GUID_GB_SCORE,ASMT_NUMBER,1
API_GUID_GB_SCORE,STUDENT_ID,1
API_GUID_GB_SCORE,API_REFID,0
API_GUID_GB_SCORE,CHANGE_DATE_TIME,0
API_GUID_GB_SCORE,CHANGE_UID,0
API_IMS_USER_ROLE,DISTRICT,0
API_IMS_USER_ROLE,TABLE_NAME,0
API_IMS_USER_ROLE,CODE_VALUE,0
API_IMS_USER_ROLE,USER_TYPE,0
API_LOG,LOG_GUID,1
API_LOG,CALLER_ID,0
API_LOG,RULE_ID,0
API_LOG,MESSAGE_ACTION,0
API_LOG,MESSAGE_STATUS,0
API_LOG,REQUEST_QUERYSTRING,0
API_LOG,MESSAGE_DATA,0
API_LOG,MESSAGE_HEADER,0
API_LOG,ERROR_MESSAGE,0
API_LOG,ADDITIONAL_INFO,0
API_LOG,TOTAL_RECORDS,0
API_LOG,RECORDS_THIS_PAGE,0
API_LOG,FILTER_LIMIT,0
API_LOG,FILTER_OFFSET,0
API_LOG,CHANGE_DATE_TIME,0
API_PROGRAMS,DISTRICT,1
API_PROGRAMS,CALLER_ID,1
API_PROGRAMS,PROGRAM_ID,1
API_PROGRAMS,HTTP_METHOD,1
API_PROGRAMS,DO_NOT_TRACK_BEFORE,0
API_PROGRAMS,CHANGE_DATE_TIME,0
API_PROGRAMS,CHANGE_UID,0
API_RULE_DET,RULE_ID,1
API_RULE_DET,JSON_LABEL,1
API_RULE_DET,DESCRIPTION,0
API_RULE_DET,DATA_ORDER,0
API_RULE_DET,DB_COLUMN,0
API_RULE_DET,IS_KEY,0
API_RULE_DET,SUBQUERY_RULE_ID,0
API_RULE_DET,FORMAT_TYPE,0
API_RULE_DET,FORMAT_MASK,0
API_RULE_DET,LITERAL_VALUE,0
API_RULE_DET,IS_SECURED,0
API_RULE_DET,CHANGE_DATE_TIME,0
API_RULE_DET,CHANGE_UID,0
API_RULE_DET,SUBQUERY_SINGLE_QUERY,0
API_RULE_HDR,RULE_ID,1
API_RULE_HDR,DISTRICT,0
API_RULE_HDR,API_VERSION,0
API_RULE_HDR,USE_SUMMER_SCHOOL,1
API_RULE_HDR,RULE_CONTROLLER,0
API_RULE_HDR,RULE_NAME,0
API_RULE_HDR,DESCRIPTION,0
API_RULE_HDR,SQL_VIEW,0
API_RULE_HDR,SQL_ORDER_BY,0
API_RULE_HDR,IS_SUBQUERY,0
API_RULE_HDR,USER_SCREEN_TYPE,0
API_RULE_HDR,SUNGARD_RESERVED,0
API_RULE_HDR,ACTIVE,0
API_RULE_HDR,ACCESS_TYPE,0
API_RULE_HDR,HTTP_METHOD,0
API_RULE_HDR,CUSTOM_CODE,0
API_RULE_HDR,CHANGE_DATE_TIME,0
API_RULE_HDR,CHANGE_UID,0
API_RULE_SUBQUERY_JOIN,PARENT_RULE_ID,1
API_RULE_SUBQUERY_JOIN,PARENT_JSON_LABEL,1
API_RULE_SUBQUERY_JOIN,SUBQUERY_RULE_ID,1
API_RULE_SUBQUERY_JOIN,LINK_SUBQUERY_DB_COLUMN,1
API_RULE_SUBQUERY_JOIN,LINK_PARENT_JSON_LABEL,0
AR_CLASS_DOWN,DISTRICT,1
AR_CLASS_DOWN,SCHOOL_YEAR,1
AR_CLASS_DOWN,FISCAL_YEAR,1
AR_CLASS_DOWN,CYCLE,1
AR_CLASS_DOWN,SCHOOL_LEA,1
AR_CLASS_DOWN,COURSE_NUM,1
AR_CLASS_DOWN,COURSE_SECT,1
AR_CLASS_DOWN,COURSE_DESC,0
AR_CLASS_DOWN,COURSE_CREDIT,0
AR_CLASS_DOWN,DIST_LEARN,0
AR_CLASS_DOWN,SPEC_ED,0
AR_CLASS_DOWN,COLL_CREDIT,0
AR_CLASS_DOWN,INSTITUTION,0
AR_CLASS_DOWN,STAFF_SSN,1
AR_CLASS_DOWN,STAFF_STATE_ID,0
AR_CLASS_DOWN,HIGH_QUAL,0
AR_CLASS_DOWN,ALT_ENVN,0
AR_CLASS_DOWN,COURSE_MIN,0
AR_CLASS_DOWN,KG_OVERFLG,0
AR_CLASS_DOWN,LEA_OUT_DIST,0
AR_CLASS_DOWN,MARK_PERIOD,0
AR_CLASS_DOWN,DIST_LEARN_PROV,0
AR_CLASS_DOWN,CHANGE_DATE_TIME,0
AR_CLASS_DOWN,CHANGE_UID,0
AR_DOWN_ALE_DAYS,DISTRICT,1
AR_DOWN_ALE_DAYS,SCHOOL_YEAR,1
AR_DOWN_ALE_DAYS,FISCAL_YEAR,1
AR_DOWN_ALE_DAYS,CYCLE,1
AR_DOWN_ALE_DAYS,SCHOOL_LEA,1
AR_DOWN_ALE_DAYS,SSN,0
AR_DOWN_ALE_DAYS,STUDENT_ID,1
AR_DOWN_ALE_DAYS,STUDENT_STATE_ID,0
AR_DOWN_ALE_DAYS,START_DATE,1
AR_DOWN_ALE_DAYS,QUARTER1_ALE,0
AR_DOWN_ALE_DAYS,QUARTER2_ALE,0
AR_DOWN_ALE_DAYS,QUARTER3_ALE,0
AR_DOWN_ALE_DAYS,QUARTER4_ALE,0
AR_DOWN_ALE_DAYS,CHANGE_DATE_TIME,0
AR_DOWN_ALE_DAYS,CHANGE_UID,0
AR_DOWN_ATTEND,DISTRICT,1
AR_DOWN_ATTEND,SCHOOL_YEAR,1
AR_DOWN_ATTEND,FY,1
AR_DOWN_ATTEND,CYCLE,1
AR_DOWN_ATTEND,LEA,1
AR_DOWN_ATTEND,SSN,0
AR_DOWN_ATTEND,STUDENT_ID,1
AR_DOWN_ATTEND,STUDENT_STATE_ID,0
AR_DOWN_ATTEND,TRAVEL_CODE,0
AR_DOWN_ATTEND,TRANS_STATUS,0
AR_DOWN_ATTEND,MIN_TO_MAJ,0
AR_DOWN_ATTEND,MAGNET,0
AR_DOWN_ATTEND,START_DATE,1
AR_DOWN_ATTEND,DAYS_PRS_QTR1,0
AR_DOWN_ATTEND,DAYS_ABS_QTR1,0
AR_DOWN_ATTEND,DAYS_PRS_QTR2,0
AR_DOWN_ATTEND,DAYS_ABS_QTR2,0
AR_DOWN_ATTEND,DAYS_PRS_QTR3,0
AR_DOWN_ATTEND,DAYS_ABS_QTR3,0
AR_DOWN_ATTEND,DAYS_PRS_QTR4,0
AR_DOWN_ATTEND,DAYS_ABS_QTR4,0
AR_DOWN_ATTEND,CHANGE_DATE_TIME,0
AR_DOWN_ATTEND,CHANGE_UID,0
AR_DOWN_CAL,DISTRICT,1
AR_DOWN_CAL,SCHOOL_YEAR,1
AR_DOWN_CAL,FISCAL_YEAR,1
AR_DOWN_CAL,CYCLE,1
AR_DOWN_CAL,LEA,1
AR_DOWN_CAL,CAL_DATE,1
AR_DOWN_CAL,MEMBERSHIP_DAY,0
AR_DOWN_CAL,CALENDAR_NUMBER,0
AR_DOWN_CAL,MEMBERSHIP_NUMBER,0
AR_DOWN_CAL,QUARTER,1
AR_DOWN_CAL,SEMESTER,1
AR_DOWN_CAL,DAY_TYPE,0
AR_DOWN_CAL,CHANGE_DATE_TIME,0
AR_DOWN_CAL,CHANGE_UID,0
AR_DOWN_DISCIPLINE,DISTRICT,1
AR_DOWN_DISCIPLINE,SCHOOL_YEAR,1
AR_DOWN_DISCIPLINE,FISCAL_YEAR,1
AR_DOWN_DISCIPLINE,CYCLE,1
AR_DOWN_DISCIPLINE,LEA,1
AR_DOWN_DISCIPLINE,STUDENT_ID,1
AR_DOWN_DISCIPLINE,SSN,0
AR_DOWN_DISCIPLINE,STUDENT_STATE_ID,0
AR_DOWN_DISCIPLINE,INCIDENT_ID,1
AR_DOWN_DISCIPLINE,DISCIPLINE_DATE,0
AR_DOWN_DISCIPLINE,INFRACTION,1
AR_DOWN_DISCIPLINE,ACTION_TAKEN,1
AR_DOWN_DISCIPLINE,SUSPENSION_DAYS,0
AR_DOWN_DISCIPLINE,SHORT_EXPUL,0
AR_DOWN_DISCIPLINE,ALT_PLACE,0
AR_DOWN_DISCIPLINE,STUDENT_STATUS,0
AR_DOWN_DISCIPLINE,CHANGE_DATE_TIME,0
AR_DOWN_DISCIPLINE,CHANGE_UID,0
AR_DOWN_DISTRICT,DISTRICT,1
AR_DOWN_DISTRICT,SCHOOL_YEAR,1
AR_DOWN_DISTRICT,FY,1
AR_DOWN_DISTRICT,CYCLE,1
AR_DOWN_DISTRICT,LEA,1
AR_DOWN_DISTRICT,WEBSITE_ADDR,0
AR_DOWN_DISTRICT,MAIL_ADDR,0
AR_DOWN_DISTRICT,MAIL_CITY,0
AR_DOWN_DISTRICT,MAIL_STATE,0
AR_DOWN_DISTRICT,MAIL_ZIP,0
AR_DOWN_DISTRICT,MAIL_ZIP4,0
AR_DOWN_DISTRICT,SHIP_ADDR,0
AR_DOWN_DISTRICT,SHIP_CITY,0
AR_DOWN_DISTRICT,SHIP_STATE,0
AR_DOWN_DISTRICT,SHIP_ZIP,0
AR_DOWN_DISTRICT,SHIP_ZIP4,0
AR_DOWN_DISTRICT,PHONE_AREA,0
AR_DOWN_DISTRICT,PHONE_PREFIX,0
AR_DOWN_DISTRICT,PHONE_SUFFIX,0
AR_DOWN_DISTRICT,PHONE_EXT,0
AR_DOWN_DISTRICT,FAX_AREA,0
AR_DOWN_DISTRICT,FAX_PREFIX,0
AR_DOWN_DISTRICT,FAX_SUFFIX,0
AR_DOWN_DISTRICT,FAX_EXT,0
AR_DOWN_DISTRICT,SMS_PASSWORD,0
AR_DOWN_DISTRICT,AFR_PASSWORD,0
AR_DOWN_DISTRICT,COOP_LEA,0
AR_DOWN_DISTRICT,SCHBD_COUNT,0
AR_DOWN_DISTRICT,SCHOOL_CHOICE,0
AR_DOWN_DISTRICT,TRANSFER_AGREEMENT,0
AR_DOWN_DISTRICT,BUS_SAFETY,0
AR_DOWN_DISTRICT,MILES_ATH,0
AR_DOWN_DISTRICT,MILES_NONATH,0
AR_DOWN_DISTRICT,INSUR_COM,0
AR_DOWN_DISTRICT,INSUR_PREM,0
AR_DOWN_DISTRICT,DI_SQU_MILES,0
AR_DOWN_DISTRICT,MILLAGE_1,0
AR_DOWN_DISTRICT,MILLAGE_MO_1,0
AR_DOWN_DISTRICT,MILLAGE_CURREXP_1,0
AR_DOWN_DISTRICT,MILLAGE_DEBTSRV_1,0
AR_DOWN_DISTRICT,MILLAGE_FOR_1,0
AR_DOWN_DISTRICT,MILLAGE_AGAINST_1,0
AR_DOWN_DISTRICT,MILLAGE_2,0
AR_DOWN_DISTRICT,MILLAGE_MO_2,0
AR_DOWN_DISTRICT,MILLAGE_CURREXP_2,0
AR_DOWN_DISTRICT,MILLAGE_DEBTSRV_2,0
AR_DOWN_DISTRICT,MILLAGE_FOR_2,0
AR_DOWN_DISTRICT,MILLAGE_AGAINST_2,0
AR_DOWN_DISTRICT,MILLAGE_3,0
AR_DOWN_DISTRICT,MILLAGE_MO_3,0
AR_DOWN_DISTRICT,MILLAGE_CURREXP_3,0
AR_DOWN_DISTRICT,MILLAGE_DEBTSRV_3,0
AR_DOWN_DISTRICT,MILLAGE_FOR_3,0
AR_DOWN_DISTRICT,MILLAGE_AGAINST_3,0
AR_DOWN_DISTRICT,FIREDR_SFTY,0
AR_DOWN_DISTRICT,FIREDR_INSPCT1,0
AR_DOWN_DISTRICT,FIREDR_INSPCT2,0
AR_DOWN_DISTRICT,ACT609_TRANSP,0
AR_DOWN_DISTRICT,ACT214_TRANSP,0
AR_DOWN_DISTRICT,SPED_TRANSP,0
AR_DOWN_DISTRICT,NONPUB_TRANSP,0
AR_DOWN_DISTRICT,DIST_PRIVSCH,0
AR_DOWN_DISTRICT,CYCLE1_DATE,0
AR_DOWN_DISTRICT,CYCLE2_DATE,0
AR_DOWN_DISTRICT,CYCLE3_DATE,0
AR_DOWN_DISTRICT,CYCLE4_DATE,0
AR_DOWN_DISTRICT,CYCLE5_DATE,0
AR_DOWN_DISTRICT,CYCLE6_DATE,0
AR_DOWN_DISTRICT,CYCLE7_DATE,0
AR_DOWN_DISTRICT,CYCLE8_DATE,0
AR_DOWN_DISTRICT,CYCLE9_DATE,0
AR_DOWN_DISTRICT,CHANGE_DATE_TIME,0
AR_DOWN_DISTRICT,CHANGE_UID,0
AR_DOWN_EC,DISTRICT,1
AR_DOWN_EC,SCHOOL_YEAR,1
AR_DOWN_EC,FISCAL_YEAR,1
AR_DOWN_EC,CYCLE,1
AR_DOWN_EC,DISTRICT_LEA,1
AR_DOWN_EC,SSN,0
AR_DOWN_EC,STUDENT_ID,1
AR_DOWN_EC,STUDENT_STATE_ID,0
AR_DOWN_EC,FIRST_NAME,0
AR_DOWN_EC,MIDDLE_NAME,0
AR_DOWN_EC,LAST_NAME,0
AR_DOWN_EC,RACE,0
AR_DOWN_EC,GENDER,0
AR_DOWN_EC,BIRTH_DATE,0
AR_DOWN_EC,TEMP_STUDENT,0
AR_DOWN_EC,RESIDENT_LEA,0
AR_DOWN_EC,PRIMARY_DISABILITY,0
AR_DOWN_EC,EDU_ENVIRONMENT,0
AR_DOWN_EC,PROGRAM_TYPE,0
AR_DOWN_EC,ELL_STATUS,0
AR_DOWN_EC,ENTRY_DATE,0
AR_DOWN_EC,TRANS_CONF_DATE,0
AR_DOWN_EC,TRANS_CODE,0
AR_DOWN_EC,CONF_LEA,0
AR_DOWN_EC,EXIT_STATUS,0
AR_DOWN_EC,EXIT_DATE,0
AR_DOWN_EC,ENTRY_ASSESS_DATE,0
AR_DOWN_EC,ENTRY_SOCIAL_SCORE,0
AR_DOWN_EC,ENTRY_SKIL_SCORE,0
AR_DOWN_EC,ENTRY_SELF_SCORE,0
AR_DOWN_EC,EXIT_ASSESS_DATE,0
AR_DOWN_EC,EXIT_SOC_SCORE,0
AR_DOWN_EC,EXIT_SKIL_SCORE,0
AR_DOWN_EC,EXIT_SELF_SCORE,0
AR_DOWN_EC,EXIT_SOC_IMPRV,0
AR_DOWN_EC,EXIT_SKIL_IMPRV,0
AR_DOWN_EC,EXIT_SELF_IMPRV,0
AR_DOWN_EC,CHANGE_DATE_TIME,0
AR_DOWN_EC,CHANGE_UID,0
AR_DOWN_EIS1,DISTRICT,1
AR_DOWN_EIS1,SCHOOL_YEAR,1
AR_DOWN_EIS1,FISCAL_YEAR,1
AR_DOWN_EIS1,CYCLE,1
AR_DOWN_EIS1,DISTRICT_LEA,1
AR_DOWN_EIS1,SSN,0
AR_DOWN_EIS1,STUDENT_ID,1
AR_DOWN_EIS1,STUDENT_STATE_ID,0
AR_DOWN_EIS1,FIRST_NAME,0
AR_DOWN_EIS1,MIDDLE_NAME,0
AR_DOWN_EIS1,LAST_NAME,0
AR_DOWN_EIS1,BIRTHDATE,0
AR_DOWN_EIS1,RACE,0
AR_DOWN_EIS1,GENDER,0
AR_DOWN_EIS1,GRADE,0
AR_DOWN_EIS1,ELL,0
AR_DOWN_EIS1,RES_LEA,0
AR_DOWN_EIS1,ENTRY_DATE,1
AR_DOWN_EIS1,WITHDRAWAL_DATE,0
AR_DOWN_EIS1,WITHDRAWAL_CODE,0
AR_DOWN_EIS1,CHANGE_DATE_TIME,0
AR_DOWN_EIS1,CHANGE_UID,0
AR_DOWN_EIS2,DISTRICT,1
AR_DOWN_EIS2,SCHOOL_YEAR,1
AR_DOWN_EIS2,FISCAL_YEAR,1
AR_DOWN_EIS2,CYCLE,1
AR_DOWN_EIS2,DISTRICT_LEA,1
AR_DOWN_EIS2,SSN,0
AR_DOWN_EIS2,STUDENT_ID,1
AR_DOWN_EIS2,STUDENT_STATE_ID,0
AR_DOWN_EIS2,SERVICE_TYPE,1
AR_DOWN_EIS2,OTHER_SERVICES,0
AR_DOWN_EIS2,START_DATE,1
AR_DOWN_EIS2,END_DATE,0
AR_DOWN_EIS2,CHANGE_DATE_TIME,0
AR_DOWN_EIS2,CHANGE_UID,0
AR_DOWN_EMPLOYEE,DISTRICT,1
AR_DOWN_EMPLOYEE,SCHOOL_YEAR,1
AR_DOWN_EMPLOYEE,FISCAL_YEAR,1
AR_DOWN_EMPLOYEE,CYCLE,1
AR_DOWN_EMPLOYEE,LEA,1
AR_DOWN_EMPLOYEE,SSN,1
AR_DOWN_EMPLOYEE,TEACH_ID,0
AR_DOWN_EMPLOYEE,STAFF_ID,1
AR_DOWN_EMPLOYEE,FNAME,0
AR_DOWN_EMPLOYEE,MNAME,0
AR_DOWN_EMPLOYEE,LNAME,0
AR_DOWN_EMPLOYEE,CHANGE_DATE_TIME,0
AR_DOWN_EMPLOYEE,CHANGE_UID,0
AR_DOWN_GRADUATE,DISTRICT,1
AR_DOWN_GRADUATE,SCHOOL_YEAR,1
AR_DOWN_GRADUATE,FY,1
AR_DOWN_GRADUATE,CYCLE,1
AR_DOWN_GRADUATE,LEA,1
AR_DOWN_GRADUATE,STUDENT_ID,1
AR_DOWN_GRADUATE,SSN,0
AR_DOWN_GRADUATE,STUDENT_STATE_ID,0
AR_DOWN_GRADUATE,RACE,0
AR_DOWN_GRADUATE,GENDER,0
AR_DOWN_GRADUATE,BIRTH_DATE,0
AR_DOWN_GRADUATE,GRADUATION_DATE,0
AR_DOWN_GRADUATE,CLASS_RANK,0
AR_DOWN_GRADUATE,GRADUATION_AGE,0
AR_DOWN_GRADUATE,STUDENT_DATA,0
AR_DOWN_GRADUATE,CHANGE_DATE_TIME,0
AR_DOWN_GRADUATE,CHANGE_UID,0
AR_DOWN_HEARING,DISTRICT,1
AR_DOWN_HEARING,SCHOOL_YEAR,1
AR_DOWN_HEARING,FY,1
AR_DOWN_HEARING,CYCLE,1
AR_DOWN_HEARING,LEA,1
AR_DOWN_HEARING,STUDENT_ID,1
AR_DOWN_HEARING,GRADE_LEVEL,1
AR_DOWN_HEARING,SCREEN_DATE,1
AR_DOWN_HEARING,SSN,0
AR_DOWN_HEARING,STUDENT_STATE_ID,0
AR_DOWN_HEARING,RIGHT_EAR,0
AR_DOWN_HEARING,LEFT_EAR,0
AR_DOWN_HEARING,REFERRAL,0
AR_DOWN_HEARING,FOLLOW_UP,0
AR_DOWN_HEARING,CHANGE_DATE_TIME,0
AR_DOWN_HEARING,CHANGE_UID,0
AR_DOWN_JOBASSIGN,DISTRICT,1
AR_DOWN_JOBASSIGN,SCHOOL_YEAR,1
AR_DOWN_JOBASSIGN,FY,1
AR_DOWN_JOBASSIGN,CYCLE,1
AR_DOWN_JOBASSIGN,LEA,1
AR_DOWN_JOBASSIGN,SSN,1
AR_DOWN_JOBASSIGN,UNIQ_EMP_ID,1
AR_DOWN_JOBASSIGN,JOB_CODE,1
AR_DOWN_JOBASSIGN,PARAPROF_QUAL,0
AR_DOWN_JOBASSIGN,FTE,0
AR_DOWN_JOBASSIGN,CHANGE_DATE_TIME,0
AR_DOWN_JOBASSIGN,CHANGE_UID,0
AR_DOWN_REFERRAL,DISTRICT,1
AR_DOWN_REFERRAL,SCHOOL_YEAR,1
AR_DOWN_REFERRAL,FISCAL_YEAR,1
AR_DOWN_REFERRAL,CYCLE,1
AR_DOWN_REFERRAL,DISTRICT_LEA,1
AR_DOWN_REFERRAL,STUDENT_ID,1
AR_DOWN_REFERRAL,REFERRAL_ID,1
AR_DOWN_REFERRAL,SSN,0
AR_DOWN_REFERRAL,STUDENT_STATE_ID,0
AR_DOWN_REFERRAL,FIRST_NAME,0
AR_DOWN_REFERRAL,MIDDLE_NAME,0
AR_DOWN_REFERRAL,LAST_NAME,0
AR_DOWN_REFERRAL,BIRTH_DATE,0
AR_DOWN_REFERRAL,ETHNIC_CODE,0
AR_DOWN_REFERRAL,RACE,0
AR_DOWN_REFERRAL,GENDER,0
AR_DOWN_REFERRAL,GRADE_LEVEL,0
AR_DOWN_REFERRAL,ELL_STATUS,0
AR_DOWN_REFERRAL,RESIDENT_LEA,0
AR_DOWN_REFERRAL,PRIVATE_SCHOOL,0
AR_DOWN_REFERRAL,PRIVATE_SCHOOL_NAME,0
AR_DOWN_REFERRAL,BUILDING_CODE,0
AR_DOWN_REFERRAL,PART_C_TO_B,0
AR_DOWN_REFERRAL,PART_C_AND_B,0
AR_DOWN_REFERRAL,REFERRAL_DATE,0
AR_DOWN_REFERRAL,PAR_CONS_EVAL_DATE,0
AR_DOWN_REFERRAL,EVAL_DATE,0
AR_DOWN_REFERRAL,REAS_EVAL_EXC_60,0
AR_DOWN_REFERRAL,OTHER_EVAL_REAS,0
AR_DOWN_REFERRAL,ELIGB_DET_DATE,0
AR_DOWN_REFERRAL,REAS_EDD_EXC_90,0
AR_DOWN_REFERRAL,OTHER_EDD_REAS,0
AR_DOWN_REFERRAL,REAS_EDD_EXC_3RD,0
AR_DOWN_REFERRAL,OTHER_3RD_EDD_REAS,0
AR_DOWN_REFERRAL,TEMP_IEP_SVC,0
AR_DOWN_REFERRAL,SPED_PLACE,0
AR_DOWN_REFERRAL,EARLY_INTER_SVC,0
AR_DOWN_REFERRAL,PAR_CONS_SPED_DATE,0
AR_DOWN_REFERRAL,REFER_COMPLETE,0
AR_DOWN_REFERRAL,REAS_COMPLETE,0
AR_DOWN_REFERRAL,OTHER_COMPLETE_REAS,0
AR_DOWN_REFERRAL,CHANGE_DATE_TIME,0
AR_DOWN_REFERRAL,CHANGE_UID,0
AR_DOWN_REGISTER,DISTRICT,1
AR_DOWN_REGISTER,SCHOOL_YEAR,1
AR_DOWN_REGISTER,STATE_DISTRICT,0
AR_DOWN_REGISTER,FISCAL_YEAR,1
AR_DOWN_REGISTER,CYCLE,1
AR_DOWN_REGISTER,SCHOOL_LEA,1
AR_DOWN_REGISTER,STATE_SCHOOL_LEA,0
AR_DOWN_REGISTER,COURSE_NUMBER,0
AR_DOWN_REGISTER,STATE_COURSE_NUMBER,0
AR_DOWN_REGISTER,COURSE_SECTION,1
AR_DOWN_REGISTER,SSN,0
AR_DOWN_REGISTER,STUDENT_ID,1
AR_DOWN_REGISTER,STUDENT_STATE_ID,0
AR_DOWN_REGISTER,CHANGE_DATE_TIME,0
AR_DOWN_REGISTER,CHANGE_UID,0
AR_DOWN_SCHL_AGE,DISTRICT,1
AR_DOWN_SCHL_AGE,SCHOOL_YEAR,1
AR_DOWN_SCHL_AGE,FY,1
AR_DOWN_SCHL_AGE,CYCLE,1
AR_DOWN_SCHL_AGE,LEA,1
AR_DOWN_SCHL_AGE,SSN,0
AR_DOWN_SCHL_AGE,STUDENT_ID,1
AR_DOWN_SCHL_AGE,STUDENT_STATE_ID,0
AR_DOWN_SCHL_AGE,FNAME,0
AR_DOWN_SCHL_AGE,MNAME,0
AR_DOWN_SCHL_AGE,LNAME,0
AR_DOWN_SCHL_AGE,RACE_ETHNIC,0
AR_DOWN_SCHL_AGE,GENDER,0
AR_DOWN_SCHL_AGE,BIRTH_DATE,0
AR_DOWN_SCHL_AGE,TEMP_STUDENT,0
AR_DOWN_SCHL_AGE,GRADE,0
AR_DOWN_SCHL_AGE,NON_GRADED,0
AR_DOWN_SCHL_AGE,ALT_PORT,0
AR_DOWN_SCHL_AGE,CHARTER_SCH,0
AR_DOWN_SCHL_AGE,BLDG_CODE,0
AR_DOWN_SCHL_AGE,ELL,0
AR_DOWN_SCHL_AGE,SCH_CHOICE,0
AR_DOWN_SCHL_AGE,SCHIMPRV_OUTDIST,0
AR_DOWN_SCHL_AGE,RES_LEA,0
AR_DOWN_SCHL_AGE,PRDS_CD,0
AR_DOWN_SCHL_AGE,FEDPL_CD,0
AR_DOWN_SCHL_AGE,PRIV_PRO,0
AR_DOWN_SCHL_AGE,RESID_LEA,0
AR_DOWN_SCHL_AGE,PRIVPROV_LEA,0
AR_DOWN_SCHL_AGE,STP_DATE,0
AR_DOWN_SCHL_AGE,SPED_EXIT,0
AR_DOWN_SCHL_AGE,FEDPL_PRYR,0
AR_DOWN_SCHL_AGE,EXIT_DATE,0
AR_DOWN_SCHL_AGE,ENTRY_DATE,0
AR_DOWN_SCHL_AGE,CHANGE_DATE_TIME,0
AR_DOWN_SCHL_AGE,CHANGE_UID,0
AR_DOWN_SCHOOL,DISTRICT,1
AR_DOWN_SCHOOL,SCHOOL_YEAR,1
AR_DOWN_SCHOOL,FY,1
AR_DOWN_SCHOOL,CYCLE,1
AR_DOWN_SCHOOL,LEA,1
AR_DOWN_SCHOOL,WEB_ADDR,0
AR_DOWN_SCHOOL,MAIL_ADDR,0
AR_DOWN_SCHOOL,MAIL_CITY,0
AR_DOWN_SCHOOL,MAIL_STATE,0
AR_DOWN_SCHOOL,MAIL_ZIP,0
AR_DOWN_SCHOOL,MAIL_ZIP4,0
AR_DOWN_SCHOOL,SHIP_ADDR,0
AR_DOWN_SCHOOL,SHIP_CITY,0
AR_DOWN_SCHOOL,SHIP_STATE,0
AR_DOWN_SCHOOL,SHIP_ZIP,0
AR_DOWN_SCHOOL,SHIP_ZIP4,0
AR_DOWN_SCHOOL,PHONE_AREA,0
AR_DOWN_SCHOOL,PHONE_PREFIX,0
AR_DOWN_SCHOOL,PHONE_SUFFIX,0
AR_DOWN_SCHOOL,PHONE_EXT,0
AR_DOWN_SCHOOL,FAX_AREA,0
AR_DOWN_SCHOOL,FAX_PREFIX,0
AR_DOWN_SCHOOL,FAX_SUFFIX,0
AR_DOWN_SCHOOL,FAX_EXT,0
AR_DOWN_SCHOOL,ACCRED_NCENTRAL,0
AR_DOWN_SCHOOL,BLOCK_SCHEDULE,0
AR_DOWN_SCHOOL,MINUTES_DAY,0
AR_DOWN_SCHOOL,PRDS_PER_DAY,0
AR_DOWN_SCHOOL,MAGNET,0
AR_DOWN_SCHOOL,ALTERNATIVE,0
AR_DOWN_SCHOOL,SCH_YRROUND,0
AR_DOWN_SCHOOL,SCH_4DAY,0
AR_DOWN_SCHOOL,SCH_NIGHT,0
AR_DOWN_SCHOOL,SERV_LEARN,0
AR_DOWN_SCHOOL,SERV_PROJ,0
AR_DOWN_SCHOOL,SCH_WIDE,0
AR_DOWN_SCHOOL,SCH_FEDPGM,0
AR_DOWN_SCHOOL,SCH_LEVEL,0
AR_DOWN_SCHOOL,SITE_USE,0
AR_DOWN_SCHOOL,STAFFDEV_HOUS,0
AR_DOWN_SCHOOL,LIB_VOLUMES,0
AR_DOWN_SCHOOL,QTR1_BEG,0
AR_DOWN_SCHOOL,QTR1_END,0
AR_DOWN_SCHOOL,QTR1_DAYS,0
AR_DOWN_SCHOOL,QTR2_BEG,0
AR_DOWN_SCHOOL,QTR2_END,0
AR_DOWN_SCHOOL,QTR2_DAYS,0
AR_DOWN_SCHOOL,QTR3_BEG,0
AR_DOWN_SCHOOL,QTR3_END,0
AR_DOWN_SCHOOL,QTR3_DAYS,0
AR_DOWN_SCHOOL,QTR4_BEG,0
AR_DOWN_SCHOOL,QTR4_END,0
AR_DOWN_SCHOOL,QTR4_DAYS,0
AR_DOWN_SCHOOL,FIREDR_MARSHPGM,0
AR_DOWN_SCHOOL,FIREDR_EVPLAN,0
AR_DOWN_SCHOOL,FIREDR_BLDGCK,0
AR_DOWN_SCHOOL,PRESCH_CLSRM,0
AR_DOWN_SCHOOL,HEAD_START,0
AR_DOWN_SCHOOL,ABC,0
AR_DOWN_SCHOOL,HIPPY,0
AR_DOWN_SCHOOL,PRIV_PRESCH,0
AR_DOWN_SCHOOL,DIST_FUND,0
AR_DOWN_SCHOOL,EARLY_CHILD_SPED,0
AR_DOWN_SCHOOL,YOUNG_PRESCH,0
AR_DOWN_SCHOOL,OLD_PRESCH,0
AR_DOWN_SCHOOL,BEFORE_SCH,0
AR_DOWN_SCHOOL,AFTER_SCH_PRG,0
AR_DOWN_SCHOOL,WK_END_PRG,0
AR_DOWN_SCHOOL,SUM_SCH_PRG,0
AR_DOWN_SCHOOL,SAFE_SCH,0
AR_DOWN_SCHOOL,CHANGE_DATE_TIME,0
AR_DOWN_SCHOOL,CHANGE_UID,0
AR_DOWN_SCOLIOSIS,DISTRICT,1
AR_DOWN_SCOLIOSIS,SCHOOL_YEAR,1
AR_DOWN_SCOLIOSIS,FY,1
AR_DOWN_SCOLIOSIS,CYCLE,1
AR_DOWN_SCOLIOSIS,LEA,1
AR_DOWN_SCOLIOSIS,STUDENT_ID,1
AR_DOWN_SCOLIOSIS,GRADE_LEVEL,1
AR_DOWN_SCOLIOSIS,SCREEN_DATE,1
AR_DOWN_SCOLIOSIS,SSN,0
AR_DOWN_SCOLIOSIS,STUDENT_STATE_ID,0
AR_DOWN_SCOLIOSIS,REFERRAL,0
AR_DOWN_SCOLIOSIS,FOLLOW_UP,0
AR_DOWN_SCOLIOSIS,CHANGE_DATE_TIME,0
AR_DOWN_SCOLIOSIS,CHANGE_UID,0
AR_DOWN_SE_STAFF,DISTRICT,1
AR_DOWN_SE_STAFF,SCHOOL_YEAR,1
AR_DOWN_SE_STAFF,FY,1
AR_DOWN_SE_STAFF,CYCLE,1
AR_DOWN_SE_STAFF,LEA,1
AR_DOWN_SE_STAFF,SSN,1
AR_DOWN_SE_STAFF,TEACH_ID,1
AR_DOWN_SE_STAFF,SVPR_CD,1
AR_DOWN_SE_STAFF,SPED_GRD,1
AR_DOWN_SE_STAFF,BLDG_CODE,1
AR_DOWN_SE_STAFF,FNAME,0
AR_DOWN_SE_STAFF,MNAME,0
AR_DOWN_SE_STAFF,LNAME,0
AR_DOWN_SE_STAFF,TECERT_CD,0
AR_DOWN_SE_STAFF,SPED_AIDE,0
AR_DOWN_SE_STAFF,INST_HRS,0
AR_DOWN_SE_STAFF,PRDS_CD,0
AR_DOWN_SE_STAFF,PER_RANGE,0
AR_DOWN_SE_STAFF,CASE_CNT,0
AR_DOWN_SE_STAFF,LIC_END,0
AR_DOWN_SE_STAFF,ST_COURSE,0
AR_DOWN_SE_STAFF,OT_COURSE,0
AR_DOWN_SE_STAFF,CHANGE_DATE_TIME,0
AR_DOWN_SE_STAFF,CHANGE_UID,0
AR_DOWN_STU,DISTRICT,1
AR_DOWN_STU,SCHOOL_YEAR,1
AR_DOWN_STU,FISCAL_YEAR,1
AR_DOWN_STU,CYCLE,1
AR_DOWN_STU,LEA,1
AR_DOWN_STU,SSN,0
AR_DOWN_STU,STUDENT_ID,1
AR_DOWN_STU,STUDENT_STATE_ID,0
AR_DOWN_STU,FIRST_NAME,0
AR_DOWN_STU,MIDDLE_NAME,0
AR_DOWN_STU,LAST_NAME,0
AR_DOWN_STU,RACE,0
AR_DOWN_STU,GENDER,0
AR_DOWN_STU,BIRTHDATE,0
AR_DOWN_STU,DIST_RESIDENCE,0
AR_DOWN_STU,RESIDENT,0
AR_DOWN_STU,GRADE_LEVEL,0
AR_DOWN_STU,PRESCHOOL,0
AR_DOWN_STU,CCLC_21,0
AR_DOWN_STU,ENTRY_CODE,0
AR_DOWN_STU,ENTRY_DATE,0
AR_DOWN_STU,GPA,0
AR_DOWN_STU,SMART_CODE_WAIV,0
AR_DOWN_STU,CONSOLIDATED_LEA,0
AR_DOWN_STU,SCHOOL_CHOICE,0
AR_DOWN_STU,CHOICE_DIST,0
AR_DOWN_STU,CHOICE_OUTSIDE_DIST,0
AR_DOWN_STU,CHOICE_1st_TIME,0
AR_DOWN_STU,CHOICE_LEA,0
AR_DOWN_STU,TUITION,0
AR_DOWN_STU,TUITION_AGREEMENT,0
AR_DOWN_STU,SERVICE_SCHOOL,0
AR_DOWN_STU,LEA_SENDRECEIVE,0
AR_DOWN_STU,SUPP_SERVICE,0
AR_DOWN_STU,SUPP_SERV_PROVIDER,0
AR_DOWN_STU,DISPLACE_DIST,0
AR_DOWN_STU,DISPLACE_STATE,0
AR_DOWN_STU,MEAL_STATUS,0
AR_DOWN_STU,TITLE1_STATUS,0
AR_DOWN_STU,GIFTED_STATUS,0
AR_DOWN_STU,SPEC_ED_STATUS,0
AR_DOWN_STU,HANDICAP_STATUS,0
AR_DOWN_STU,FORMER_ELL,0
AR_DOWN_STU,ELL_ENTRY_DATE,0
AR_DOWN_STU,ELL_EXIT_DATE,0
AR_DOWN_STU,ESL_WAIVE_DATE,0
AR_DOWN_STU,MIGRANT_STATUS,0
AR_DOWN_STU,MARITAL_STATUS,0
AR_DOWN_STU,HOMELESS_YOUTH,0
AR_DOWN_STU,HOMELESS_STATUS,0
AR_DOWN_STU,ORPHAN_STATUS,0
AR_DOWN_STU,FOSTER_CHILD,0
AR_DOWN_STU,ELL_STATUS,0
AR_DOWN_STU,PRIMARY_LANGUAGE,0
AR_DOWN_STU,RETENTION,0
AR_DOWN_STU,MOBILITY,0
AR_DOWN_STU,DROPOUT,0
AR_DOWN_STU,ENROLLMENT_STATUS,0
AR_DOWN_STU,DROPOUT_CODE,0
AR_DOWN_STU,DROPOUT_DATE,0
AR_DOWN_STU,M_TO_M,0
AR_DOWN_STU,PARENT_FNAME,0
AR_DOWN_STU,PARENT_MNAME,0
AR_DOWN_STU,PARENT_LNAME,0
AR_DOWN_STU,MAILING_ADDRESS,0
AR_DOWN_STU,MAILING_CITY,0
AR_DOWN_STU,MAILING_STATE,0
AR_DOWN_STU,MAILING_ZIP,0
AR_DOWN_STU,PHY_ADDRESS,0
AR_DOWN_STU,PHY_CITY,0
AR_DOWN_STU,PHY_STATE,0
AR_DOWN_STU,PHY_ZIP,0
AR_DOWN_STU,CHANGE_DATE_TIME,0
AR_DOWN_STU,CHANGE_UID,0
AR_DOWN_STU_ID,DISTRICT,1
AR_DOWN_STU_ID,SCHOOL_YEAR,1
AR_DOWN_STU_ID,FISCAL_YEAR,1
AR_DOWN_STU_ID,CYCLE,1
AR_DOWN_STU_ID,LEA,1
AR_DOWN_STU_ID,STUDENT_ID,1
AR_DOWN_STU_ID,STUDENT_STATE_ID,0
AR_DOWN_STU_ID,ID_CHANGEDATE,0
AR_DOWN_STU_ID,PREVIOUS_ID,0
AR_DOWN_STU_ID,NEW_ID,0
AR_DOWN_STU_ID,CHANGE_DATE_TIME,0
AR_DOWN_STU_ID,CHANGE_UID,0
AR_DOWN_STUDENT_GRADES,DISTRICT,1
AR_DOWN_STUDENT_GRADES,SCHOOL_YEAR,1
AR_DOWN_STUDENT_GRADES,FY,1
AR_DOWN_STUDENT_GRADES,CYCLE,1
AR_DOWN_STUDENT_GRADES,LEA,1
AR_DOWN_STUDENT_GRADES,STUDENT_ID,1
AR_DOWN_STUDENT_GRADES,SSN,0
AR_DOWN_STUDENT_GRADES,STUDENT_STATE_ID,0
AR_DOWN_STUDENT_GRADES,SECTION_KEY,1
AR_DOWN_STUDENT_GRADES,COURSE,0
AR_DOWN_STUDENT_GRADES,SECTION,0
AR_DOWN_STUDENT_GRADES,DESCRIPTION,0
AR_DOWN_STUDENT_GRADES,SEM1_GRADE,0
AR_DOWN_STUDENT_GRADES,SEM2_GRADE,0
AR_DOWN_STUDENT_GRADES,SEM3_GRADE,0
AR_DOWN_STUDENT_GRADES,SEM4_GRADE,0
AR_DOWN_STUDENT_GRADES,CHANGE_DATE_TIME,0
AR_DOWN_STUDENT_GRADES,CHANGE_UID,0
AR_DOWN_VISION,DISTRICT,1
AR_DOWN_VISION,SCHOOL_YEAR,1
AR_DOWN_VISION,FY,1
AR_DOWN_VISION,CYCLE,1
AR_DOWN_VISION,LEA,1
AR_DOWN_VISION,SSN,0
AR_DOWN_VISION,STUDENT_ID,1
AR_DOWN_VISION,STUDENT_STATE_ID,0
AR_DOWN_VISION,GRADE_LEVEL,1
AR_DOWN_VISION,SCREEN_DATE,1
AR_DOWN_VISION,EXT_EXAM,0
AR_DOWN_VISION,VISION20,0
AR_DOWN_VISION,COLORBLIND,0
AR_DOWN_VISION,FUSION_FAR,0
AR_DOWN_VISION,FUSION,0
AR_DOWN_VISION,LAT_MB,0
AR_DOWN_VISION,LATERAL_FAR,0
AR_DOWN_VISION,VERT_MB,0
AR_DOWN_VISION,PLUS2_LEN,0
AR_DOWN_VISION,REFERRAL,0
AR_DOWN_VISION,FOLLOW_UP,0
AR_DOWN_VISION,CHANGE_DATE_TIME,0
AR_DOWN_VISION,CHANGE_UID,0
ARTB_21CCLC,DISTRICT,1
ARTB_21CCLC,CODE,1
ARTB_21CCLC,DESCRIPTION,0
ARTB_21CCLC,STATE_CODE_EQUIV,0
ARTB_21CCLC,ACTIVE,0
ARTB_21CCLC,CHANGE_DATE_TIME,0
ARTB_21CCLC,CHANGE_UID,0
ARTB_DIST_LEARN,DISTRICT,1
ARTB_DIST_LEARN,CODE,1
ARTB_DIST_LEARN,DESCRIPTION,0
ARTB_DIST_LEARN,STATE_CODE_EQUIV,0
ARTB_DIST_LEARN,ACTIVE,0
ARTB_DIST_LEARN,CHANGE_DATE_TIME,0
ARTB_DIST_LEARN,CHANGE_UID,0
ARTB_DIST_LRNPROV,DISTRICT,1
ARTB_DIST_LRNPROV,CODE,1
ARTB_DIST_LRNPROV,DESCRIPTION,0
ARTB_DIST_LRNPROV,STATE_CODE_EQUIV,0
ARTB_DIST_LRNPROV,ACTIVE,0
ARTB_DIST_LRNPROV,CHANGE_DATE_TIME,0
ARTB_DIST_LRNPROV,CHANGE_UID,0
ARTB_DISTRICTS,DISTRICT,1
ARTB_DISTRICTS,CODE,1
ARTB_DISTRICTS,DESCRIPTION,0
ARTB_DISTRICTS,STATE_CODE_EQUIV,0
ARTB_DISTRICTS,ACTIVE,0
ARTB_DISTRICTS,CHANGE_DATE_TIME,0
ARTB_DISTRICTS,CHANGE_UID,0
ARTB_EC_ANTIC_SVC,DISTRICT,1
ARTB_EC_ANTIC_SVC,CODE,1
ARTB_EC_ANTIC_SVC,DESCRIPTION,0
ARTB_EC_ANTIC_SVC,STATE_CODE_EQUIV,0
ARTB_EC_ANTIC_SVC,ACTIVE,0
ARTB_EC_ANTIC_SVC,CHANGE_DATE_TIME,0
ARTB_EC_ANTIC_SVC,CHANGE_UID,0
ARTB_EC_DISAB,DISTRICT,1
ARTB_EC_DISAB,CODE,1
ARTB_EC_DISAB,DESCRIPTION,0
ARTB_EC_DISAB,STATE_CODE_EQUIV,0
ARTB_EC_DISAB,ACTIVE,0
ARTB_EC_DISAB,CHANGE_DATE_TIME,0
ARTB_EC_DISAB,CHANGE_UID,0
ARTB_EC_RELATE_SVC,DISTRICT,1
ARTB_EC_RELATE_SVC,CODE,1
ARTB_EC_RELATE_SVC,DESCRIPTION,0
ARTB_EC_RELATE_SVC,STATE_CODE_EQUIV,0
ARTB_EC_RELATE_SVC,ACTIVE,0
ARTB_EC_RELATE_SVC,CHANGE_DATE_TIME,0
ARTB_EC_RELATE_SVC,CHANGE_UID,0
ARTB_INSTITUTIONS,DISTRICT,1
ARTB_INSTITUTIONS,CODE,1
ARTB_INSTITUTIONS,DESCRIPTION,0
ARTB_INSTITUTIONS,STATE_CODE_EQUIV,0
ARTB_INSTITUTIONS,ACTIVE,0
ARTB_INSTITUTIONS,CHANGE_DATE_TIME,0
ARTB_INSTITUTIONS,CHANGE_UID,0
ARTB_LEPMONITORED,DISTRICT,1
ARTB_LEPMONITORED,CODE,1
ARTB_LEPMONITORED,DESCRIPTION,0
ARTB_LEPMONITORED,STATE_CODE_EQUIV,0
ARTB_LEPMONITORED,ACTIVE,0
ARTB_LEPMONITORED,CHANGE_DATE_TIME,0
ARTB_LEPMONITORED,CHANGE_UID,0
ARTB_OTHERDISTRICT,DISTRICT,1
ARTB_OTHERDISTRICT,NAME,1
ARTB_OTHERDISTRICT,STATE_CODE_EQUIV,0
ARTB_OTHERDISTRICT,STATE,0
ARTB_OTHERDISTRICT,CHANGE_DATE_TIME,0
ARTB_OTHERDISTRICT,CHANGE_UID,0
ARTB_OUT_DIST,DISTRICT,1
ARTB_OUT_DIST,CODE,1
ARTB_OUT_DIST,DESCRIPTION,0
ARTB_OUT_DIST,STATE_CODE_EQUIV,0
ARTB_OUT_DIST,ACTIVE,0
ARTB_OUT_DIST,CHANGE_DATE_TIME,0
ARTB_OUT_DIST,CHANGE_UID,0
ARTB_RESIDENT,DISTRICT,1
ARTB_RESIDENT,CODE,1
ARTB_RESIDENT,DESCRIPTION,0
ARTB_RESIDENT,STATE_CODE_EQUIV,0
ARTB_RESIDENT,ACTIVE,0
ARTB_RESIDENT,CHANGE_DATE_TIME,0
ARTB_RESIDENT,CHANGE_UID,0
ARTB_RPT_PERIODS,DISTRICT,1
ARTB_RPT_PERIODS,CODE,1
ARTB_RPT_PERIODS,DESCRIPTION,0
ARTB_RPT_PERIODS,END_DATE,0
ARTB_RPT_PERIODS,ACTIVE,0
ARTB_RPT_PERIODS,CHANGE_DATE_TIME,0
ARTB_RPT_PERIODS,CHANGE_UID,0
ARTB_SA_ANTIC_SVC,DISTRICT,1
ARTB_SA_ANTIC_SVC,CODE,1
ARTB_SA_ANTIC_SVC,DESCRIPTION,0
ARTB_SA_ANTIC_SVC,STATE_CODE_EQUIV,0
ARTB_SA_ANTIC_SVC,ACTIVE,0
ARTB_SA_ANTIC_SVC,CHANGE_DATE_TIME,0
ARTB_SA_ANTIC_SVC,CHANGE_UID,0
ARTB_SA_DISAB,DISTRICT,1
ARTB_SA_DISAB,CODE,1
ARTB_SA_DISAB,DESCRIPTION,0
ARTB_SA_DISAB,STATE_CODE_EQUIV,0
ARTB_SA_DISAB,ACTIVE,0
ARTB_SA_DISAB,CHANGE_DATE_TIME,0
ARTB_SA_DISAB,CHANGE_UID,0
ARTB_SA_RELATE_SVC,DISTRICT,1
ARTB_SA_RELATE_SVC,CODE,1
ARTB_SA_RELATE_SVC,DESCRIPTION,0
ARTB_SA_RELATE_SVC,STATE_CODE_EQUIV,0
ARTB_SA_RELATE_SVC,ACTIVE,0
ARTB_SA_RELATE_SVC,CHANGE_DATE_TIME,0
ARTB_SA_RELATE_SVC,CHANGE_UID,0
ARTB_SCHOOL_GRADE,DISTRICT,1
ARTB_SCHOOL_GRADE,CODE,1
ARTB_SCHOOL_GRADE,DESCRIPTION,0
ARTB_SCHOOL_GRADE,ACTIVE,0
ARTB_SCHOOL_GRADE,CHANGE_DATE_TIME,0
ARTB_SCHOOL_GRADE,CHANGE_UID,0
ARTB_SE_CERT_STAT,DISTRICT,1
ARTB_SE_CERT_STAT,CODE,1
ARTB_SE_CERT_STAT,DESCRIPTION,0
ARTB_SE_CERT_STAT,STATE_CODE_EQUIV,0
ARTB_SE_CERT_STAT,ACTIVE,0
ARTB_SE_CERT_STAT,CHANGE_DATE_TIME,0
ARTB_SE_CERT_STAT,CHANGE_UID,0
ARTB_SE_DEV_NEEDS,DISTRICT,1
ARTB_SE_DEV_NEEDS,CODE,1
ARTB_SE_DEV_NEEDS,DESCRIPTION,0
ARTB_SE_DEV_NEEDS,STATE_CODE_EQUIV,0
ARTB_SE_DEV_NEEDS,ACTIVE,0
ARTB_SE_DEV_NEEDS,CHANGE_DATE_TIME,0
ARTB_SE_DEV_NEEDS,CHANGE_UID,0
ARTB_SE_EDD_3RD,DISTRICT,1
ARTB_SE_EDD_3RD,CODE,1
ARTB_SE_EDD_3RD,DESCRIPTION,0
ARTB_SE_EDD_3RD,STATE_CODE_EQUIV,0
ARTB_SE_EDD_3RD,ACTIVE,0
ARTB_SE_EDD_3RD,CHANGE_DATE_TIME,0
ARTB_SE_EDD_3RD,CHANGE_UID,0
ARTB_SE_EDD_REASON,DISTRICT,1
ARTB_SE_EDD_REASON,CODE,1
ARTB_SE_EDD_REASON,DESCRIPTION,0
ARTB_SE_EDD_REASON,STATE_CODE_EQUIV,0
ARTB_SE_EDD_REASON,ACTIVE,0
ARTB_SE_EDD_REASON,CHANGE_DATE_TIME,0
ARTB_SE_EDD_REASON,CHANGE_UID,0
ARTB_SE_EDU_ENVIRN,DISTRICT,1
ARTB_SE_EDU_ENVIRN,CODE,1
ARTB_SE_EDU_ENVIRN,DESCRIPTION,0
ARTB_SE_EDU_ENVIRN,STATE_CODE_EQUIV,0
ARTB_SE_EDU_ENVIRN,ACTIVE,0
ARTB_SE_EDU_ENVIRN,CHANGE_DATE_TIME,0
ARTB_SE_EDU_ENVIRN,CHANGE_UID,0
ARTB_SE_EDU_NEEDS,DISTRICT,1
ARTB_SE_EDU_NEEDS,CODE,1
ARTB_SE_EDU_NEEDS,DESCRIPTION,0
ARTB_SE_EDU_NEEDS,STATE_CODE_EQUIV,0
ARTB_SE_EDU_NEEDS,ACTIVE,0
ARTB_SE_EDU_NEEDS,CHANGE_DATE_TIME,0
ARTB_SE_EDU_NEEDS,CHANGE_UID,0
ARTB_SE_EDU_PLACE,DISTRICT,1
ARTB_SE_EDU_PLACE,CODE,1
ARTB_SE_EDU_PLACE,DESCRIPTION,0
ARTB_SE_EDU_PLACE,STATE_CODE_EQUIV,0
ARTB_SE_EDU_PLACE,ACTIVE,0
ARTB_SE_EDU_PLACE,CHANGE_DATE_TIME,0
ARTB_SE_EDU_PLACE,CHANGE_UID,0
ARTB_SE_EVAL_CODE,DISTRICT,1
ARTB_SE_EVAL_CODE,CODE,1
ARTB_SE_EVAL_CODE,DESCRIPTION,0
ARTB_SE_EVAL_CODE,STATE_CODE_EQUIV,0
ARTB_SE_EVAL_CODE,ACTIVE,0
ARTB_SE_EVAL_CODE,CHANGE_DATE_TIME,0
ARTB_SE_EVAL_CODE,CHANGE_UID,0
ARTB_SE_EVL_EXCEED,DISTRICT,1
ARTB_SE_EVL_EXCEED,CODE,1
ARTB_SE_EVL_EXCEED,DESCRIPTION,0
ARTB_SE_EVL_EXCEED,STATE_CODE_EQUIV,0
ARTB_SE_EVL_EXCEED,ACTIVE,0
ARTB_SE_EVL_EXCEED,CHANGE_DATE_TIME,0
ARTB_SE_EVL_EXCEED,CHANGE_UID,0
ARTB_SE_FUNC_IMP,DISTRICT,1
ARTB_SE_FUNC_IMP,CODE,1
ARTB_SE_FUNC_IMP,DESCRIPTION,0
ARTB_SE_FUNC_IMP,STATE_CODE_EQUIV,0
ARTB_SE_FUNC_IMP,ACTIVE,0
ARTB_SE_FUNC_IMP,CHANGE_DATE_TIME,0
ARTB_SE_FUNC_IMP,CHANGE_UID,0
ARTB_SE_FUNC_SCORE,DISTRICT,1
ARTB_SE_FUNC_SCORE,CODE,1
ARTB_SE_FUNC_SCORE,DESCRIPTION,0
ARTB_SE_FUNC_SCORE,STATE_CODE_EQUIV,0
ARTB_SE_FUNC_SCORE,ACTIVE,0
ARTB_SE_FUNC_SCORE,CHANGE_DATE_TIME,0
ARTB_SE_FUNC_SCORE,CHANGE_UID,0
ARTB_SE_GRADE_LVL,DISTRICT,1
ARTB_SE_GRADE_LVL,CODE,1
ARTB_SE_GRADE_LVL,DESCRIPTION,0
ARTB_SE_GRADE_LVL,STATE_CODE_EQUIV,0
ARTB_SE_GRADE_LVL,ACTIVE,0
ARTB_SE_GRADE_LVL,CHANGE_DATE_TIME,0
ARTB_SE_GRADE_LVL,CHANGE_UID,0
ARTB_SE_INT_SERV,DISTRICT,1
ARTB_SE_INT_SERV,CODE,1
ARTB_SE_INT_SERV,DESCRIPTION,0
ARTB_SE_INT_SERV,STATE_CODE_EQUIV,0
ARTB_SE_INT_SERV,ACTIVE,0
ARTB_SE_INT_SERV,CHANGE_DATE_TIME,0
ARTB_SE_INT_SERV,CHANGE_UID,0
ARTB_SE_PROG_TYPE,DISTRICT,1
ARTB_SE_PROG_TYPE,CODE,1
ARTB_SE_PROG_TYPE,DESCRIPTION,0
ARTB_SE_PROG_TYPE,STATE_CODE_EQUIV,0
ARTB_SE_PROG_TYPE,ACTIVE,0
ARTB_SE_PROG_TYPE,CHANGE_DATE_TIME,0
ARTB_SE_PROG_TYPE,CHANGE_UID,0
ARTB_SE_REASON_NOT_ACCESSED,DISTRICT,1
ARTB_SE_REASON_NOT_ACCESSED,CODE,1
ARTB_SE_REASON_NOT_ACCESSED,DESCRIPTION,0
ARTB_SE_REASON_NOT_ACCESSED,STATE_CODE_EQUIV,0
ARTB_SE_REASON_NOT_ACCESSED,ACTIVE,0
ARTB_SE_REASON_NOT_ACCESSED,CHANGE_DATE_TIME,0
ARTB_SE_REASON_NOT_ACCESSED,CHANGE_UID,0
ARTB_SE_REFERRAL,DISTRICT,1
ARTB_SE_REFERRAL,SCHOOL_YEAR,0
ARTB_SE_REFERRAL,SUMMER_SCHOOL,0
ARTB_SE_REFERRAL,STUDENT_ID,0
ARTB_SE_REFERRAL,REFERRAL_ID,1
ARTB_SE_REFERRAL,BUILDING,0
ARTB_SE_REFERRAL,RESIDENT_LEA,0
ARTB_SE_REFERRAL,PRIVATE_SCHOOL,0
ARTB_SE_REFERRAL,PRIVATE_SCHOOL_NAME,0
ARTB_SE_REFERRAL,ELL,0
ARTB_SE_REFERRAL,TRANS_PART_C,0
ARTB_SE_REFERRAL,PART_C_B_CONCURRENT,0
ARTB_SE_REFERRAL,REFERRAL_DATE,0
ARTB_SE_REFERRAL,PARENT_EVAL_DATE,0
ARTB_SE_REFERRAL,EVAL_DATE,0
ARTB_SE_REFERRAL,EVAL_REASON,0
ARTB_SE_REFERRAL,EVAL_OT_REASON,0
ARTB_SE_REFERRAL,ELIGIBILITY_DET_DATE,0
ARTB_SE_REFERRAL,EDD_30_DAY_CODE,0
ARTB_SE_REFERRAL,EDD_OT_REASON,0
ARTB_SE_REFERRAL,EDD_3RD_DOB_CODE,0
ARTB_SE_REFERRAL,EDD3_OT_REASON,0
ARTB_SE_REFERRAL,TEMP_IEP_3RD_BDAY,0
ARTB_SE_REFERRAL,SPED_PLACEMENT,0
ARTB_SE_REFERRAL,EARLY_INTERV_SERV,0
ARTB_SE_REFERRAL,PARENT_PLACE_DATE,0
ARTB_SE_REFERRAL,RFC_REASON,0
ARTB_SE_REFERRAL,CMP_OTHER,0
ARTB_SE_REFERRAL,REF_COMPLETE,0
ARTB_SE_REFERRAL,CHANGE_DATE_TIME,0
ARTB_SE_REFERRAL,CHANGE_UID,0
ARTB_SE_RFC_REASON,DISTRICT,1
ARTB_SE_RFC_REASON,CODE,1
ARTB_SE_RFC_REASON,DESCRIPTION,0
ARTB_SE_RFC_REASON,STATE_CODE_EQUIV,0
ARTB_SE_RFC_REASON,ACTIVE,0
ARTB_SE_RFC_REASON,CHANGE_DATE_TIME,0
ARTB_SE_RFC_REASON,CHANGE_UID,0
artb_se_staf_disab,DISTRICT,1
artb_se_staf_disab,CODE,1
artb_se_staf_disab,DESCRIPTION,0
artb_se_staf_disab,STATE_CODE_EQUIV,0
artb_se_staf_disab,SENSITIVE,0
artb_se_staf_disab,ACTIVE,0
artb_se_staf_disab,CHANGE_DATE_TIME,0
artb_se_staf_disab,CHANGE_UID,0
ARTB_SE_TITLE_CODE,DISTRICT,1
ARTB_SE_TITLE_CODE,CODE,1
ARTB_SE_TITLE_CODE,DESCRIPTION,0
ARTB_SE_TITLE_CODE,STATE_CODE_EQUIV,0
ARTB_SE_TITLE_CODE,ACTIVE,0
ARTB_SE_TITLE_CODE,CHANGE_DATE_TIME,0
ARTB_SE_TITLE_CODE,CHANGE_UID,0
ARTB_SE_TRANS_CODE,DISTRICT,1
ARTB_SE_TRANS_CODE,CODE,1
ARTB_SE_TRANS_CODE,DESCRIPTION,0
ARTB_SE_TRANS_CODE,STATE_CODE_EQUIV,0
ARTB_SE_TRANS_CODE,ACTIVE,0
ARTB_SE_TRANS_CODE,CHANGE_DATE_TIME,0
ARTB_SE_TRANS_CODE,CHANGE_UID,0
ARTB_TUITION,DISTRICT,1
ARTB_TUITION,CODE,1
ARTB_TUITION,DESCRIPTION,0
ARTB_TUITION,STATE_CODE_EQUIV,0
ARTB_TUITION,ACTIVE,0
ARTB_TUITION,CHANGE_DATE_TIME,0
ARTB_TUITION,CHANGE_UID,0
ATT_AUDIT_TRAIL,DISTRICT,1
ATT_AUDIT_TRAIL,SCHOOL_YEAR,1
ATT_AUDIT_TRAIL,SUMMER_SCHOOL,1
ATT_AUDIT_TRAIL,BUILDING,1
ATT_AUDIT_TRAIL,ATTENDANCE_DATE,1
ATT_AUDIT_TRAIL,STUDENT_ID,1
ATT_AUDIT_TRAIL,ATTENDANCE_PERIOD,1
ATT_AUDIT_TRAIL,SEQUENCE_NUM,1
ATT_AUDIT_TRAIL,ENTRY_ORDER_NUM,1
ATT_AUDIT_TRAIL,SOURCE,1
ATT_AUDIT_TRAIL,ATTENDANCE_CODE,0
ATT_AUDIT_TRAIL,DISMISS_TIME,0
ATT_AUDIT_TRAIL,ARRIVE_TIME,0
ATT_AUDIT_TRAIL,MINUTES_ABSENT,0
ATT_AUDIT_TRAIL,BOTTOMLINE,0
ATT_AUDIT_TRAIL,ENTRY_DATE_TIME,0
ATT_AUDIT_TRAIL,ENTRY_USER,0
ATT_AUDIT_TRAIL,ATT_COMMENT,0
ATT_AUDIT_TRAIL,CHANGE_DATE_TIME,0
ATT_AUDIT_TRAIL,CHANGE_UID,0
ATT_BOTTOMLINE,DISTRICT,1
ATT_BOTTOMLINE,SCHOOL_YEAR,1
ATT_BOTTOMLINE,SUMMER_SCHOOL,1
ATT_BOTTOMLINE,BUILDING,1
ATT_BOTTOMLINE,STUDENT_ID,1
ATT_BOTTOMLINE,ATTENDANCE_DATE,1
ATT_BOTTOMLINE,ATTENDANCE_PERIOD,1
ATT_BOTTOMLINE,SEQUENCE_NUM,1
ATT_BOTTOMLINE,SOURCE,0
ATT_BOTTOMLINE,ATTENDANCE_CODE,0
ATT_BOTTOMLINE,DISMISS_TIME,0
ATT_BOTTOMLINE,ARRIVE_TIME,0
ATT_BOTTOMLINE,MINUTES_ABSENT,0
ATT_BOTTOMLINE,ATT_COMMENT,0
ATT_BOTTOMLINE,ROW_IDENTITY,0
ATT_BOTTOMLINE,CHANGE_DATE_TIME,0
ATT_BOTTOMLINE,CHANGE_UID,0
ATT_CFG,DISTRICT,1
ATT_CFG,SCHOOL_YEAR,1
ATT_CFG,SUMMER_SCHOOL,1
ATT_CFG,BUILDING,1
ATT_CFG,PERIOD_TYPE,0
ATT_CFG,USE_TIMETABLE,0
ATT_CFG,BOTTOM_LINE_TYPE,0
ATT_CFG,POSITIVE_ATND,0
ATT_CFG,AUDIT_TYPE,0
ATT_CFG,DEFAULT_ABS_CODE,0
ATT_CFG,DEFAULT_TAR_CODE,0
ATT_CFG,DEFAULT_PRE_CODE,0
ATT_CFG,USE_LANG_TEMPLATE,0
ATT_CFG,DATA_SOURCE_FILE,0
ATT_CFG,PROGRAM_SCREEN,0
ATT_CFG,REG_USER_SCREEN,0
ATT_CFG,NOTIFY_DWNLD_PATH,0
ATT_CFG,EMAIL_OPTION,0
ATT_CFG,RETURN_EMAIL,0
ATT_CFG,RET_EMAIL_MISSUB,0
ATT_CFG,TWS_TAKE_ATT,0
ATT_CFG,TWS_ALT_ABS,0
ATT_CFG,TWS_NUM_VIEW_DAYS,0
ATT_CFG,TWS_NUM_MNT_DAYS,0
ATT_CFG,TWS_ATT_STU_SUMM,0
ATT_CFG,DEF_TAC_ABS_CODE,0
ATT_CFG,DEF_TAC_TAR_CODE,0
ATT_CFG,DEF_TAC_PRES_CODE,0
ATT_CFG,ATT_LOCK_DATE,0
ATT_CFG,CODE_LIST_TEACH_SUBST,0
ATT_CFG,SIF_VIEW,0
ATT_CFG,CHANGE_DATE_TIME,0
ATT_CFG,CHANGE_UID,0
ATT_CFG,ATT_CHECK_IN,0
ATT_CFG_CODES,DISTRICT,1
ATT_CFG_CODES,SCHOOL_YEAR,1
ATT_CFG_CODES,SUMMER_SCHOOL,1
ATT_CFG_CODES,BUILDING,1
ATT_CFG_CODES,ATTENDANCE_CODE,1
ATT_CFG_CODES,CHANGE_DATE_TIME,0
ATT_CFG_CODES,CHANGE_UID,0
ATT_CFG_MISS_SUB,DISTRICT,1
ATT_CFG_MISS_SUB,SCHOOL_YEAR,1
ATT_CFG_MISS_SUB,SUMMER_SCHOOL,1
ATT_CFG_MISS_SUB,BUILDING,1
ATT_CFG_MISS_SUB,LOGIN_ID,1
ATT_CFG_MISS_SUB,CHANGE_DATE_TIME,0
ATT_CFG_MISS_SUB,CHANGE_UID,0
ATT_CFG_PERIODS,DISTRICT,1
ATT_CFG_PERIODS,SCHOOL_YEAR,1
ATT_CFG_PERIODS,SUMMER_SCHOOL,1
ATT_CFG_PERIODS,BUILDING,1
ATT_CFG_PERIODS,ATTENDANCE_PERIOD,1
ATT_CFG_PERIODS,CHANGE_DATE_TIME,0
ATT_CFG_PERIODS,CHANGE_UID,0
ATT_CODE,DISTRICT,1
ATT_CODE,SCHOOL_YEAR,1
ATT_CODE,SUMMER_SCHOOL,1
ATT_CODE,ATTENDANCE_CODE,1
ATT_CODE,DESCRIPTION,0
ATT_CODE,COLOR,0
ATT_CODE,USE_DISMISS_TIME,0
ATT_CODE,USE_ARRIVE_TIME,0
ATT_CODE,DISTRICT_GROUP,0
ATT_CODE,STATE_GROUP,0
ATT_CODE,SIF_TYPE,0
ATT_CODE,SIF_STATUS,0
ATT_CODE,SIF_PRECEDENCE,0
ATT_CODE,INCLUDE_PERFPLUS,0
ATT_CODE,ALT_ATTENDANCE_CODE,0
ATT_CODE,STATE_CODE_EQUIV,0
ATT_CODE,CHANGE_DATE_TIME,0
ATT_CODE,CHANGE_UID,0
ATT_CODE_BUILDING,DISTRICT,1
ATT_CODE_BUILDING,SCHOOL_YEAR,1
ATT_CODE_BUILDING,SUMMER_SCHOOL,1
ATT_CODE_BUILDING,BUILDING,1
ATT_CODE_BUILDING,ATTENDANCE_CODE,1
ATT_CODE_BUILDING,CHANGE_DATE_TIME,0
ATT_CODE_BUILDING,CHANGE_UID,0
ATT_CONFIG_PERCENT,DISTRICT,1
ATT_CONFIG_PERCENT,SCHOOL_YEAR,1
ATT_CONFIG_PERCENT,SUMMER_SCHOOL,1
ATT_CONFIG_PERCENT,BUILDING,1
ATT_CONFIG_PERCENT,VIEW_TYPE,1
ATT_CONFIG_PERCENT,ATND_INTERVAL,1
ATT_CONFIG_PERCENT,DISPLAY_ORDER,0
ATT_CONFIG_PERCENT,TITLE,0
ATT_CONFIG_PERCENT,DECIMAL_PRECISION,0
ATT_CONFIG_PERCENT,DISPLAY_DETAIL,0
ATT_CONFIG_PERCENT,MINUTES_AS_HOURS,0
ATT_CONFIG_PERCENT,COMBINE_BUILDING,0
ATT_CONFIG_PERCENT,CHANGE_DATE_TIME,0
ATT_CONFIG_PERCENT,CHANGE_UID,0
ATT_COURSE_SEATING,DISTRICT,1
ATT_COURSE_SEATING,SECTION_KEY,1
ATT_COURSE_SEATING,COURSE_SESSION,1
ATT_COURSE_SEATING,GRID_MODE,0
ATT_COURSE_SEATING,GRID_COLS,0
ATT_COURSE_SEATING,GRID_ROWS,0
ATT_COURSE_SEATING,WIDTH,0
ATT_COURSE_SEATING,HEIGHT,0
ATT_COURSE_SEATING,BACKGROUND,0
ATT_COURSE_SEATING,CHANGE_DATE_TIME,0
ATT_COURSE_SEATING,CHANGE_UID,0
ATT_EMERGENCY,DISTRICT,1
ATT_EMERGENCY,BUILDING,1
ATT_EMERGENCY,STUDENT_ID,1
ATT_EMERGENCY,STAFF_ID,0
ATT_EMERGENCY,ROOM,0
ATT_EMERGENCY,ABSENT,0
ATT_EMERGENCY,CHANGE_DATE_TIME,0
ATT_EMERGENCY,CHANGE_UID,0
ATT_EMERGENCY_CFG,DISTRICT,1
ATT_EMERGENCY_CFG,BUILDING,1
ATT_EMERGENCY_CFG,EMERGENCY_ATT,0
ATT_EMERGENCY_CFG,STUDENT_CELL_TYPE,0
ATT_EMERGENCY_CFG,CONTACT_TYPE1,0
ATT_EMERGENCY_CFG,PHONE1_TYPE1,0
ATT_EMERGENCY_CFG,PHONE1_TYPE2,0
ATT_EMERGENCY_CFG,CONTACT_TYPE2,0
ATT_EMERGENCY_CFG,PHONE2_TYPE1,0
ATT_EMERGENCY_CFG,PHONE2_TYPE2,0
ATT_EMERGENCY_CFG,CHANGE_DATE_TIME,0
ATT_EMERGENCY_CFG,CHANGE_UID,0
ATT_HRM_SEATING,DISTRICT,1
ATT_HRM_SEATING,BUILDING,1
ATT_HRM_SEATING,SCHOOL_YEAR,1
ATT_HRM_SEATING,SUMMER_SCHOOL,1
ATT_HRM_SEATING,HOMEROOM_TYPE,1
ATT_HRM_SEATING,HOMEROOM,1
ATT_HRM_SEATING,GRID_MODE,0
ATT_HRM_SEATING,GRID_COLS,0
ATT_HRM_SEATING,GRID_ROWS,0
ATT_HRM_SEATING,WIDTH,0
ATT_HRM_SEATING,HEIGHT,0
ATT_HRM_SEATING,BACKGROUND,0
ATT_HRM_SEATING,CHANGE_DATE_TIME,0
ATT_HRM_SEATING,CHANGE_UID,0
ATT_INTERVAL,DISTRICT,1
ATT_INTERVAL,SCHOOL_YEAR,1
ATT_INTERVAL,BUILDING,1
ATT_INTERVAL,SUMMER_SCHOOL,1
ATT_INTERVAL,ATND_INTERVAL,1
ATT_INTERVAL,DESCRIPTION,0
ATT_INTERVAL,ATT_INTERVAL_ORDER,0
ATT_INTERVAL,INTERVAL_TYPE,0
ATT_INTERVAL,BEGIN_SPAN,0
ATT_INTERVAL,END_SPAN,0
ATT_INTERVAL,SUM_BY_ATT_CODE,0
ATT_INTERVAL,SUM_BY_DISTR_GRP,0
ATT_INTERVAL,SUM_BY_STATE_GRP,0
ATT_INTERVAL,STATE_CODE_EQUIV,0
ATT_INTERVAL,CHANGE_DATE_TIME,0
ATT_INTERVAL,CHANGE_UID,0
ATT_LOCK_DATE,DISTRICT,1
ATT_LOCK_DATE,SCHOOL_YEAR,1
ATT_LOCK_DATE,BUILDING,1
ATT_LOCK_DATE,TRACK,1
ATT_LOCK_DATE,LOCK_DATE,0
ATT_LOCK_DATE,CHANGE_DATE_TIME,0
ATT_LOCK_DATE,CHANGE_UID,0
ATT_NOTIFY_CRIT,DISTRICT,1
ATT_NOTIFY_CRIT,SCHOOL_YEAR,1
ATT_NOTIFY_CRIT,SUMMER_SCHOOL,1
ATT_NOTIFY_CRIT,BUILDING,1
ATT_NOTIFY_CRIT,NOTIFY_CRITERIA,1
ATT_NOTIFY_CRIT,DESCRIPTION,0
ATT_NOTIFY_CRIT,NOTIFICATION_ORDER,0
ATT_NOTIFY_CRIT,NOTIFY_GROUP,0
ATT_NOTIFY_CRIT,EMAIL_STAFF,0
ATT_NOTIFY_CRIT,REPORT_CYCLE_TYPE,0
ATT_NOTIFY_CRIT,INTERVAL_TYPE,0
ATT_NOTIFY_CRIT,SUNDAY,0
ATT_NOTIFY_CRIT,MONDAY,0
ATT_NOTIFY_CRIT,TUESDAY,0
ATT_NOTIFY_CRIT,WEDNESDAY,0
ATT_NOTIFY_CRIT,THURSDAY,0
ATT_NOTIFY_CRIT,FRIDAY,0
ATT_NOTIFY_CRIT,SATURDAY,0
ATT_NOTIFY_CRIT,EVALUATION_TYPE,0
ATT_NOTIFY_CRIT,EVALUATION_SOURCE,0
ATT_NOTIFY_CRIT,EVAL_VIEW_TYPE,0
ATT_NOTIFY_CRIT,DETAIL_DATE_RANGE,0
ATT_NOTIFY_CRIT,DATE_ORDER,0
ATT_NOTIFY_CRIT,SEND_LETTER,0
ATT_NOTIFY_CRIT,MIN_ABS_TYPE,0
ATT_NOTIFY_CRIT,MAX_ABS_TYPE,0
ATT_NOTIFY_CRIT,MIN_OVERALL_ABS,0
ATT_NOTIFY_CRIT,MAX_OVERALL_ABS,0
ATT_NOTIFY_CRIT,OVERALL_ABS_BY,0
ATT_NOTIFY_CRIT,MIN_ABSENCE,0
ATT_NOTIFY_CRIT,MAX_ABSENCE,0
ATT_NOTIFY_CRIT,ABSENCE_PATTERN,0
ATT_NOTIFY_CRIT,MIN_DAY,0
ATT_NOTIFY_CRIT,MAX_DAY,0
ATT_NOTIFY_CRIT,DAY_PATTERN,0
ATT_NOTIFY_CRIT,MIN_PERCENT_DAY,0
ATT_NOTIFY_CRIT,MAX_PERCENT_DAY,0
ATT_NOTIFY_CRIT,CALC_SELECTION,0
ATT_NOTIFY_CRIT,USE_ELIGIBILITY,0
ATT_NOTIFY_CRIT,ELIG_INCLUDE_PRIOR,0
ATT_NOTIFY_CRIT,ELIGIBILITY_CODE,0
ATT_NOTIFY_CRIT,ELIG_DURATION,0
ATT_NOTIFY_CRIT,ELIG_DURATION_DAYS,0
ATT_NOTIFY_CRIT,MAX_LETTER,0
ATT_NOTIFY_CRIT,USE_DISCIPLINE,0
ATT_NOTIFY_CRIT,IS_STUDENT,0
ATT_NOTIFY_CRIT,PERSON_ID,0
ATT_NOTIFY_CRIT,INCIDENT_CODE,0
ATT_NOTIFY_CRIT,ACTION_CODE,0
ATT_NOTIFY_CRIT,INCLUDE_FINE,0
ATT_NOTIFY_CRIT,USE_AT_RISK,0
ATT_NOTIFY_CRIT,AT_RISK_REASON,0
ATT_NOTIFY_CRIT,AT_RISK_DURATION,0
ATT_NOTIFY_CRIT,AT_RISK_DAYS,0
ATT_NOTIFY_CRIT,CHANGE_DATE_TIME,0
ATT_NOTIFY_CRIT,CHANGE_UID,0
ATT_NOTIFY_CRIT_CD,DISTRICT,1
ATT_NOTIFY_CRIT_CD,SCHOOL_YEAR,1
ATT_NOTIFY_CRIT_CD,SUMMER_SCHOOL,1
ATT_NOTIFY_CRIT_CD,BUILDING,1
ATT_NOTIFY_CRIT_CD,NOTIFY_CRITERIA,1
ATT_NOTIFY_CRIT_CD,EVALUATION_CODE,1
ATT_NOTIFY_CRIT_CD,CHANGE_DATE_TIME,0
ATT_NOTIFY_CRIT_CD,CHANGE_UID,0
ATT_NOTIFY_CRIT_PD,DISTRICT,1
ATT_NOTIFY_CRIT_PD,SCHOOL_YEAR,1
ATT_NOTIFY_CRIT_PD,SUMMER_SCHOOL,1
ATT_NOTIFY_CRIT_PD,BUILDING,1
ATT_NOTIFY_CRIT_PD,NOTIFY_CRITERIA,1
ATT_NOTIFY_CRIT_PD,ATTENDANCE_PERIOD,1
ATT_NOTIFY_CRIT_PD,CHANGE_DATE_TIME,0
ATT_NOTIFY_CRIT_PD,CHANGE_UID,0
ATT_NOTIFY_ELIG_CD,DISTRICT,1
ATT_NOTIFY_ELIG_CD,SCHOOL_YEAR,1
ATT_NOTIFY_ELIG_CD,SUMMER_SCHOOL,1
ATT_NOTIFY_ELIG_CD,BUILDING,1
ATT_NOTIFY_ELIG_CD,NOTIFY_CRITERIA,1
ATT_NOTIFY_ELIG_CD,SEQUENCE_ORDER,1
ATT_NOTIFY_ELIG_CD,CURRENT_ELIG_STAT,1
ATT_NOTIFY_ELIG_CD,ELIGIBILITY_CODE,0
ATT_NOTIFY_ELIG_CD,CHANGE_DATE_TIME,0
ATT_NOTIFY_ELIG_CD,CHANGE_UID,0
ATT_NOTIFY_GROUP,DISTRICT,1
ATT_NOTIFY_GROUP,SCHOOL_YEAR,1
ATT_NOTIFY_GROUP,SUMMER_SCHOOL,1
ATT_NOTIFY_GROUP,BUILDING,1
ATT_NOTIFY_GROUP,NOTIFY_GROUP,1
ATT_NOTIFY_GROUP,DESCRIPTION,0
ATT_NOTIFY_GROUP,CHANGE_DATE_TIME,0
ATT_NOTIFY_GROUP,CHANGE_UID,0
ATT_NOTIFY_LANG,DISTRICT,1
ATT_NOTIFY_LANG,SCHOOL_YEAR,1
ATT_NOTIFY_LANG,SUMMER_SCHOOL,1
ATT_NOTIFY_LANG,BUILDING,1
ATT_NOTIFY_LANG,LANGUAGE_CODE,1
ATT_NOTIFY_LANG,CHANGE_DATE_TIME,0
ATT_NOTIFY_LANG,CHANGE_UID,0
ATT_NOTIFY_STU_DET,DISTRICT,1
ATT_NOTIFY_STU_DET,SCHOOL_YEAR,1
ATT_NOTIFY_STU_DET,BUILDING,1
ATT_NOTIFY_STU_DET,STUDENT_ID,1
ATT_NOTIFY_STU_DET,NOTIFY_CRITERIA,1
ATT_NOTIFY_STU_DET,REPORT_CYCLE_DATE,1
ATT_NOTIFY_STU_DET,TRIGGER_DATE,1
ATT_NOTIFY_STU_DET,ATTENDANCE_DATE,1
ATT_NOTIFY_STU_DET,ATTENDANCE_PERIOD,1
ATT_NOTIFY_STU_DET,SEQUENCE_NUM,1
ATT_NOTIFY_STU_DET,EVALUATION_CODE,0
ATT_NOTIFY_STU_DET,INVALID_NOTIFY,0
ATT_NOTIFY_STU_DET,ATTENDANCE_COUNT,0
ATT_NOTIFY_STU_DET,ABSENCE_TYPE,0
ATT_NOTIFY_STU_DET,ABSENCE_VALUE,0
ATT_NOTIFY_STU_DET,SECTION_KEY,0
ATT_NOTIFY_STU_DET,INCIDENT_ID,0
ATT_NOTIFY_STU_DET,ACTION_NUMBER,0
ATT_NOTIFY_STU_DET,CHANGE_DATE_TIME,0
ATT_NOTIFY_STU_DET,CHANGE_UID,0
ATT_NOTIFY_STU_HDR,DISTRICT,1
ATT_NOTIFY_STU_HDR,SCHOOL_YEAR,1
ATT_NOTIFY_STU_HDR,BUILDING,1
ATT_NOTIFY_STU_HDR,STUDENT_ID,1
ATT_NOTIFY_STU_HDR,NOTIFY_CRITERIA,1
ATT_NOTIFY_STU_HDR,REPORT_CYCLE_DATE,1
ATT_NOTIFY_STU_HDR,TRIGGER_DATE,1
ATT_NOTIFY_STU_HDR,EVALUATION_CODE,0
ATT_NOTIFY_STU_HDR,PUBLISHED,0
ATT_NOTIFY_STU_HDR,INVALID_NOTIFY,0
ATT_NOTIFY_STU_HDR,CHANGE_DATE_TIME,0
ATT_NOTIFY_STU_HDR,CHANGE_UID,0
ATT_NOTIFY_STU_HDR,PUBLISHED_NOTIFICATION,0
ATT_PERIOD,DISTRICT,1
ATT_PERIOD,SCHOOL_YEAR,1
ATT_PERIOD,SUMMER_SCHOOL,1
ATT_PERIOD,BUILDING,1
ATT_PERIOD,ATTENDANCE_PERIOD,1
ATT_PERIOD,DESCRIPTION,0
ATT_PERIOD,ATT_PERIOD_ORDER,0
ATT_PERIOD,PERIOD_VALUE,0
ATT_PERIOD,START_TIME,0
ATT_PERIOD,END_TIME,0
ATT_PERIOD,INC_IN_ATT_VIEW,0
ATT_PERIOD,ROW_IDENTITY,0
ATT_PERIOD,CHANGE_DATE_TIME,0
ATT_PERIOD,CHANGE_UID,0
ATT_STU_AT_RISK,DISTRICT,1
ATT_STU_AT_RISK,SCHOOL_YEAR,1
ATT_STU_AT_RISK,BUILDING,1
ATT_STU_AT_RISK,STUDENT_ID,1
ATT_STU_AT_RISK,NOTIFY_CRITERIA,1
ATT_STU_AT_RISK,REPORT_CYCLE_DATE,1
ATT_STU_AT_RISK,TRIGGER_DATE,1
ATT_STU_AT_RISK,AT_RISK_REASON,0
ATT_STU_AT_RISK,EFFECTIVE_DATE,0
ATT_STU_AT_RISK,EXPIRATION_DATE,0
ATT_STU_AT_RISK,PLAN_NUM,0
ATT_STU_AT_RISK,CHANGE_DATE_TIME,0
ATT_STU_AT_RISK,CHANGE_UID,0
ATT_STU_CHECK_IN,DISTRICT,1
ATT_STU_CHECK_IN,SCHOOL_YEAR,1
ATT_STU_CHECK_IN,SUMMER_SCHOOL,1
ATT_STU_CHECK_IN,BUILDING,1
ATT_STU_CHECK_IN,STUDENT_ID,1
ATT_STU_CHECK_IN,ATTENDANCE_DATE,1
ATT_STU_CHECK_IN,ATTENDANCE_KEY,1
ATT_STU_CHECK_IN,SOURCE,0
ATT_STU_CHECK_IN,CHECKIN_DATE,1
ATT_STU_CHECK_IN,VIRTUAL_MEET_ID,0
ATT_STU_CHECK_IN,ROW_IDENTITY,0
ATT_STU_CHECK_IN,CHANGE_DATE_TIME,0
ATT_STU_CHECK_IN,CHANGE_UID,0
ATT_STU_COURSE_SEAT,DISTRICT,1
ATT_STU_COURSE_SEAT,SECTION_KEY,1
ATT_STU_COURSE_SEAT,COURSE_SESSION,1
ATT_STU_COURSE_SEAT,STUDENT_ID,1
ATT_STU_COURSE_SEAT,HAS_SEAT,0
ATT_STU_COURSE_SEAT,SEAT_NUMBER,0
ATT_STU_COURSE_SEAT,POSITION_X,0
ATT_STU_COURSE_SEAT,POSITION_Y,0
ATT_STU_COURSE_SEAT,CHANGE_DATE_TIME,0
ATT_STU_COURSE_SEAT,CHANGE_UID,0
ATT_STU_DAY_TOT_LAST,DISTRICT,1
ATT_STU_DAY_TOT_LAST,VIEW_TYPE,1
ATT_STU_DAY_TOT_LAST,STUDENT_ID,1
ATT_STU_DAY_TOT_LAST,BUILDING,1
ATT_STU_DAY_TOT_LAST,LAST_CALC_DATE,1
ATT_STU_DAY_TOT_LAST,CHANGE_DATE_TIME,0
ATT_STU_DAY_TOT_LAST,CHANGE_UID,0
ATT_STU_DAY_TOTALS,DISTRICT,1
ATT_STU_DAY_TOTALS,SCHOOL_YEAR,1
ATT_STU_DAY_TOTALS,BUILDING,1
ATT_STU_DAY_TOTALS,SUMMER_SCHOOL,1
ATT_STU_DAY_TOTALS,STUDENT_ID,1
ATT_STU_DAY_TOTALS,ATTENDANCE_DATE,1
ATT_STU_DAY_TOTALS,VIEW_TYPE,1
ATT_STU_DAY_TOTALS,CRITERIA,1
ATT_STU_DAY_TOTALS,ATTENDANCE_CODE,0
ATT_STU_DAY_TOTALS,ATT_CODE_VALUE,0
ATT_STU_DAY_TOTALS,TOTAL_DAY_TIME,0
ATT_STU_DAY_TOTALS,STUDENT_SCHD_TIME,0
ATT_STU_DAY_TOTALS,STU_UNSCHD_TIME,0
ATT_STU_DAY_TOTALS,PRESENT_TIME,0
ATT_STU_DAY_TOTALS,ABSENT_TIME,0
ATT_STU_DAY_TOTALS,ROW_IDENTITY,0
ATT_STU_DAY_TOTALS,CHANGE_DATE_TIME,0
ATT_STU_DAY_TOTALS,CHANGE_UID,0
ATT_STU_DAY_TOTALS,LOCATION_TYPE,0
ATT_STU_DAY_TOTALS,MAX_DAY_TIME,0
ATT_STU_DAY_TOTALS_CALC,DISTRICT,1
ATT_STU_DAY_TOTALS_CALC,PARAM_KEY,0
ATT_STU_DAY_TOTALS_CALC,SCHOOL_YEAR,1
ATT_STU_DAY_TOTALS_CALC,BUILDING,1
ATT_STU_DAY_TOTALS_CALC,SUMMER_SCHOOL,1
ATT_STU_DAY_TOTALS_CALC,STUDENT_ID,1
ATT_STU_DAY_TOTALS_CALC,ATTENDANCE_DATE,1
ATT_STU_DAY_TOTALS_CALC,VIEW_TYPE,1
ATT_STU_DAY_TOTALS_CALC,CRITERIA,1
ATT_STU_ELIGIBLE,DISTRICT,1
ATT_STU_ELIGIBLE,SCHOOL_YEAR,1
ATT_STU_ELIGIBLE,BUILDING,1
ATT_STU_ELIGIBLE,STUDENT_ID,1
ATT_STU_ELIGIBLE,NOTIFY_CRITERIA,1
ATT_STU_ELIGIBLE,REPORT_CYCLE_DATE,1
ATT_STU_ELIGIBLE,TRIGGER_DATE,1
ATT_STU_ELIGIBLE,ELIGIBILITY_CODE,0
ATT_STU_ELIGIBLE,EFFECTIVE_DATE,0
ATT_STU_ELIGIBLE,EXPIRATION_DATE,0
ATT_STU_ELIGIBLE,CHANGE_DATE_TIME,0
ATT_STU_ELIGIBLE,CHANGE_UID,0
ATT_STU_EMAIL_MAP,DISTRICT,1
ATT_STU_EMAIL_MAP,STUDENT_ID,1
ATT_STU_EMAIL_MAP,EMAIL,1
ATT_STU_EMAIL_MAP,ROW_IDENTITY,0
ATT_STU_EMAIL_MAP,CHANGE_DATE_TIME,0
ATT_STU_EMAIL_MAP,CHANGE_UID,0
ATT_STU_HRM_SEAT,DISTRICT,1
ATT_STU_HRM_SEAT,BUILDING,1
ATT_STU_HRM_SEAT,SCHOOL_YEAR,1
ATT_STU_HRM_SEAT,SUMMER_SCHOOL,1
ATT_STU_HRM_SEAT,HOMEROOM_TYPE,1
ATT_STU_HRM_SEAT,HOMEROOM,1
ATT_STU_HRM_SEAT,STUDENT_ID,1
ATT_STU_HRM_SEAT,HAS_SEAT,0
ATT_STU_HRM_SEAT,SEAT_NUMBER,0
ATT_STU_HRM_SEAT,POSITION_X,0
ATT_STU_HRM_SEAT,POSITION_Y,0
ATT_STU_HRM_SEAT,CHANGE_DATE_TIME,0
ATT_STU_HRM_SEAT,CHANGE_UID,0
ATT_STU_INT_CRIT,DISTRICT,1
ATT_STU_INT_CRIT,SCHOOL_YEAR,1
ATT_STU_INT_CRIT,BUILDING,1
ATT_STU_INT_CRIT,SUMMER_SCHOOL,1
ATT_STU_INT_CRIT,STUDENT_ID,1
ATT_STU_INT_CRIT,VIEW_TYPE,1
ATT_STU_INT_CRIT,CRITERIA,1
ATT_STU_INT_CRIT,ATND_INTERVAL,1
ATT_STU_INT_CRIT,TOTAL_DAY_TIME,0
ATT_STU_INT_CRIT,STUDENT_SCHD_TIME,0
ATT_STU_INT_CRIT,STU_UNSCHD_TIME,0
ATT_STU_INT_CRIT,PRESENT_TIME,0
ATT_STU_INT_CRIT,ABSENT_TIME,0
ATT_STU_INT_CRIT,CHANGE_DATE_TIME,0
ATT_STU_INT_CRIT,CHANGE_UID,0
ATT_STU_INT_GROUP,DISTRICT,1
ATT_STU_INT_GROUP,SCHOOL_YEAR,1
ATT_STU_INT_GROUP,BUILDING,1
ATT_STU_INT_GROUP,SUMMER_SCHOOL,1
ATT_STU_INT_GROUP,STUDENT_ID,1
ATT_STU_INT_GROUP,VIEW_TYPE,1
ATT_STU_INT_GROUP,ATND_INTERVAL,1
ATT_STU_INT_GROUP,INTERVAL_TYPE,1
ATT_STU_INT_GROUP,INTERVAL_CODE,1
ATT_STU_INT_GROUP,ATT_CODE_VALUE,0
ATT_STU_INT_GROUP,CHANGE_DATE_TIME,0
ATT_STU_INT_GROUP,CHANGE_UID,0
ATT_STU_INT_MEMB,DISTRICT,1
ATT_STU_INT_MEMB,SCHOOL_YEAR,1
ATT_STU_INT_MEMB,BUILDING,1
ATT_STU_INT_MEMB,SUMMER_SCHOOL,1
ATT_STU_INT_MEMB,STUDENT_ID,1
ATT_STU_INT_MEMB,ATND_INTERVAL,1
ATT_STU_INT_MEMB,TOTAL_MEMBERSHIP,0
ATT_STU_INT_MEMB,CHANGE_DATE_TIME,0
ATT_STU_INT_MEMB,CHANGE_UID,0
ATT_TWS_TAKEN,DISTRICT,1
ATT_TWS_TAKEN,SCHOOL_YEAR,1
ATT_TWS_TAKEN,SUMMER_SCHOOL,1
ATT_TWS_TAKEN,BUILDING,1
ATT_TWS_TAKEN,ATTENDANCE_DATE,1
ATT_TWS_TAKEN,PERIOD_KEY,1
ATT_TWS_TAKEN,ATTENDANCE_PERIOD,1
ATT_TWS_TAKEN,CHANGE_DATE_TIME,0
ATT_TWS_TAKEN,CHANGE_UID,0
ATT_VIEW_ABS,DISTRICT,1
ATT_VIEW_ABS,SCHOOL_YEAR,1
ATT_VIEW_ABS,SUMMER_SCHOOL,1
ATT_VIEW_ABS,BUILDING,1
ATT_VIEW_ABS,VIEW_TYPE,1
ATT_VIEW_ABS,CRITERIA,1
ATT_VIEW_ABS,ATTENDANCE_CODE,1
ATT_VIEW_ABS,CHANGE_DATE_TIME,0
ATT_VIEW_ABS,CHANGE_UID,0
ATT_VIEW_CYC,DISTRICT,1
ATT_VIEW_CYC,SCHOOL_YEAR,1
ATT_VIEW_CYC,SUMMER_SCHOOL,1
ATT_VIEW_CYC,BUILDING,1
ATT_VIEW_CYC,VIEW_TYPE,1
ATT_VIEW_CYC,CRITERIA,1
ATT_VIEW_CYC,CYCLE,1
ATT_VIEW_CYC,CHANGE_DATE_TIME,0
ATT_VIEW_CYC,CHANGE_UID,0
ATT_VIEW_DET,DISTRICT,1
ATT_VIEW_DET,SCHOOL_YEAR,1
ATT_VIEW_DET,SUMMER_SCHOOL,1
ATT_VIEW_DET,BUILDING,1
ATT_VIEW_DET,VIEW_TYPE,1
ATT_VIEW_DET,CRITERIA,1
ATT_VIEW_DET,CALENDAR,0
ATT_VIEW_DET,MIN_OCCURRENCE,0
ATT_VIEW_DET,MAX_OCCURRENCE,0
ATT_VIEW_DET,CONSECUTIVE_ABS,0
ATT_VIEW_DET,SAME_ABS,0
ATT_VIEW_DET,ATT_CODE_CONVERT,0
ATT_VIEW_DET,ATT_CODE_VALUE,0
ATT_VIEW_DET,PERCENT_ABSENT,0
ATT_VIEW_DET,USE_SCHD_PERIODS,0
ATT_VIEW_DET,USE_ALL_PERIODS,0
ATT_VIEW_DET,CHANGE_DATE_TIME,0
ATT_VIEW_DET,CHANGE_UID,0
ATT_VIEW_DET,LOCATION_TYPE,0
ATT_VIEW_HDR,DISTRICT,1
ATT_VIEW_HDR,SCHOOL_YEAR,1
ATT_VIEW_HDR,SUMMER_SCHOOL,1
ATT_VIEW_HDR,BUILDING,1
ATT_VIEW_HDR,VIEW_TYPE,1
ATT_VIEW_HDR,DESCRIPTION,0
ATT_VIEW_HDR,CRITERIA_TYPE,0
ATT_VIEW_HDR,LAST_DAY_CALCED,0
ATT_VIEW_HDR,ATT_TOTALS_UNITS,0
ATT_VIEW_HDR,DAY_UNITS,0
ATT_VIEW_HDR,INCLUDE_PERFPLUS,0
ATT_VIEW_HDR,INCLD_PASSING_TIME,0
ATT_VIEW_HDR,MAX_PASSING_TIME,0
ATT_VIEW_HDR,SEPARATE_BUILDINGS,0
ATT_VIEW_HDR,CHANGE_DATE_TIME,0
ATT_VIEW_HDR,CHANGE_UID,0
ATT_VIEW_INT,DISTRICT,1
ATT_VIEW_INT,SCHOOL_YEAR,1
ATT_VIEW_INT,SUMMER_SCHOOL,1
ATT_VIEW_INT,BUILDING,1
ATT_VIEW_INT,VIEW_TYPE,1
ATT_VIEW_INT,ATT_INTERVAL,1
ATT_VIEW_INT,CHANGE_DATE_TIME,0
ATT_VIEW_INT,CHANGE_UID,0
ATT_VIEW_MSE_BLDG,DISTRICT,1
ATT_VIEW_MSE_BLDG,SCHOOL_YEAR,1
ATT_VIEW_MSE_BLDG,SUMMER_SCHOOL,1
ATT_VIEW_MSE_BLDG,BUILDING,1
ATT_VIEW_MSE_BLDG,VIEW_TYPE,1
ATT_VIEW_MSE_BLDG,MSE_BUILDING,1
ATT_VIEW_MSE_BLDG,CHANGE_DATE_TIME,0
ATT_VIEW_MSE_BLDG,CHANGE_UID,0
ATT_VIEW_PER,DISTRICT,1
ATT_VIEW_PER,SCHOOL_YEAR,1
ATT_VIEW_PER,SUMMER_SCHOOL,1
ATT_VIEW_PER,BUILDING,1
ATT_VIEW_PER,VIEW_TYPE,1
ATT_VIEW_PER,CRITERIA,1
ATT_VIEW_PER,ATTENDANCE_PERIOD,1
ATT_VIEW_PER,CHANGE_DATE_TIME,0
ATT_VIEW_PER,CHANGE_UID,0
ATT_VIRTUAL_MEETING_LINKS,DISTRICT,1
ATT_VIRTUAL_MEETING_LINKS,SCHOOL_YEAR,1
ATT_VIRTUAL_MEETING_LINKS,SUMMER_SCHOOL,1
ATT_VIRTUAL_MEETING_LINKS,BUILDING,0
ATT_VIRTUAL_MEETING_LINKS,ATTENDANCE_KEY,1
ATT_VIRTUAL_MEETING_LINKS,VIRTUAL_MEETING_LINK,0
ATT_VIRTUAL_MEETING_LINKS,CHANGE_DATE_TIME,0
ATT_VIRTUAL_MEETING_LINKS,CHANGE_UID,0
ATT_VIRTUAL_MEETING_LINKS,RECORD_TYPE,0
ATT_VIRTUAL_MEETING_LOG,DISTRICT,1
ATT_VIRTUAL_MEETING_LOG,ATTENDANCE_KEY,1
ATT_VIRTUAL_MEETING_LOG,STAFF_LOGIN_ID,0
ATT_VIRTUAL_MEETING_LOG,ATTENDANCE_STATUS,0
ATT_VIRTUAL_MEETING_LOG,ATT_DATE,1
ATT_VIRTUAL_MEETING_LOG,CHANGE_DATE_TIME,0
ATT_VIRTUAL_MEETING_LOG,CHANGE_UID,0
ATT_VIRTUAL_MEETING_UNMAPPED_STUDENTS,DISTRICT,1
ATT_VIRTUAL_MEETING_UNMAPPED_STUDENTS,ATTENDANCE_KEY,1
ATT_VIRTUAL_MEETING_UNMAPPED_STUDENTS,VIRTUAL_MEETING_LINK,0
ATT_VIRTUAL_MEETING_UNMAPPED_STUDENTS,UNMAPPED_EMAIL,1
ATT_VIRTUAL_MEETING_UNMAPPED_STUDENTS,ATT_DATE,1
ATT_VIRTUAL_MEETING_UNMAPPED_STUDENTS,CHECKIN_DATE,0
ATT_VIRTUAL_MEETING_UNMAPPED_STUDENTS,STUDENT_NAME,0
ATT_VIRTUAL_MEETING_UNMAPPED_STUDENTS,CHANGE_DATE_TIME,0
ATT_VIRTUAL_MEETING_UNMAPPED_STUDENTS,CHANGE_UID,0
ATT_YREND_RUN,DISTRICT,1
ATT_YREND_RUN,SCHOOL_YEAR,1
ATT_YREND_RUN,SUMMER_SCHOOL,1
ATT_YREND_RUN,RUN_KEY,1
ATT_YREND_RUN,BUILDING_LIST,0
ATT_YREND_RUN,RUN_DATE,0
ATT_YREND_RUN,RUN_STATUS,0
ATT_YREND_RUN,PURGE_BLDG_YEAR,0
ATT_YREND_RUN,PURGE_DETAIL_YEAR,0
ATT_YREND_RUN,PURGE_STU_NOT_YEAR,0
ATT_YREND_RUN,PURGE_STU_DAY_YEAR,0
ATT_YREND_RUN,PURGE_STU_INT_YEAR,0
ATT_YREND_RUN,RESTORE_KEY,0
ATT_YREND_RUN,CHANGE_DATE_TIME,0
ATT_YREND_RUN,CHANGE_UID,0
ATTTB_DISTRICT_GRP,DISTRICT,1
ATTTB_DISTRICT_GRP,CODE,1
ATTTB_DISTRICT_GRP,DESCRIPTION,0
ATTTB_DISTRICT_GRP,ACTIVE,0
ATTTB_DISTRICT_GRP,CHANGE_DATE_TIME,0
ATTTB_DISTRICT_GRP,CHANGE_UID,0
ATTTB_INELIGIBLE,DISTRICT,1
ATTTB_INELIGIBLE,CODE,1
ATTTB_INELIGIBLE,DESCRIPTION,0
ATTTB_INELIGIBLE,ACTIVE,0
ATTTB_INELIGIBLE,CHANGE_DATE_TIME,0
ATTTB_INELIGIBLE,CHANGE_UID,0
ATTTB_SIF_STATUS,DISTRICT,1
ATTTB_SIF_STATUS,CODE,1
ATTTB_SIF_STATUS,DESCRIPTION,0
ATTTB_SIF_STATUS,ACTIVE,0
ATTTB_SIF_STATUS,CHANGE_DATE_TIME,0
ATTTB_SIF_STATUS,CHANGE_UID,0
ATTTB_SIF_TYPE,DISTRICT,1
ATTTB_SIF_TYPE,CODE,1
ATTTB_SIF_TYPE,DESCRIPTION,0
ATTTB_SIF_TYPE,ACTIVE,0
ATTTB_SIF_TYPE,CHANGE_DATE_TIME,0
ATTTB_SIF_TYPE,CHANGE_UID,0
ATTTB_STATE_GRP,DISTRICT,1
ATTTB_STATE_GRP,CODE,1
ATTTB_STATE_GRP,DESCRIPTION,0
ATTTB_STATE_GRP,ACTIVE,0
ATTTB_STATE_GRP,CHANGE_DATE_TIME,0
ATTTB_STATE_GRP,CHANGE_UID,0
BOOK_ALT_LOCATION,DISTRICT,1
BOOK_ALT_LOCATION,BUILDING,1
BOOK_ALT_LOCATION,HOUSE_TEAM,1
BOOK_ALT_LOCATION,ALT_BUILDING,0
BOOK_ALT_LOCATION,CHANGE_DATE_TIME,0
BOOK_ALT_LOCATION,CHANGE_UID,0
BOOK_ASSIGN,DISTRICT,1
BOOK_ASSIGN,BAR_CODE,1
BOOK_ASSIGN,ISBN_CODE,0
BOOK_ASSIGN,BOOK_TYPE,0
BOOK_ASSIGN,BUILDING,0
BOOK_ASSIGN,ASSIGNED_TO,0
BOOK_ASSIGN,DATE_ASSIGNED,0
BOOK_ASSIGN,WHO_HAS_BOOK,0
BOOK_ASSIGN,PENDING_TRANSFER,0
BOOK_ASSIGN,STATUS,0
BOOK_ASSIGN,CHANGE_DATE_TIME,0
BOOK_ASSIGN,CHANGE_UID,0
BOOK_BLDG_CFG,DISTRICT,1
BOOK_BLDG_CFG,BUILDING,1
BOOK_BLDG_CFG,USE_SCHD_CALC,0
BOOK_BLDG_CFG,FROM_STU_TO_STU,0
BOOK_BLDG_CFG,FROM_STU_TO_TEA,0
BOOK_BLDG_CFG,FROM_STU_TO_BLDG,0
BOOK_BLDG_CFG,FROM_TEA_TO_STU,0
BOOK_BLDG_CFG,FROM_TEA_TO_TEA,0
BOOK_BLDG_CFG,FROM_TEA_TO_BLDG,0
BOOK_BLDG_CFG,FROM_BLDG_TO_STU,0
BOOK_BLDG_CFG,FROM_BLDG_TO_TEA,0
BOOK_BLDG_CFG,CHANGE_DATE_TIME,0
BOOK_BLDG_CFG,CHANGE_UID,0
BOOK_BOOKMASTER,DISTRICT,1
BOOK_BOOKMASTER,ISBN_CODE,1
BOOK_BOOKMASTER,BUILDING,1
BOOK_BOOKMASTER,BOOK_TYPE,1
BOOK_BOOKMASTER,USABLE_ON_HAND,0
BOOK_BOOKMASTER,WORN_OUT,0
BOOK_BOOKMASTER,PAID_FOR,0
BOOK_BOOKMASTER,AMOUNT_FINES,0
BOOK_BOOKMASTER,REPORTED_SURPLUS,0
BOOK_BOOKMASTER,BOOKS_ON_ORDER,0
BOOK_BOOKMASTER,ALLOCATED,0
BOOK_BOOKMASTER,PURCHASE_ORDER,0
BOOK_BOOKMASTER,REQUESTS,0
BOOK_BOOKMASTER,CHANGE_DATE_TIME,0
BOOK_BOOKMASTER,CHANGE_UID,0
BOOK_CFG,DISTRICT,1
BOOK_CFG,USE_WAREHOUSE,0
BOOK_CFG,BUILDING,0
BOOK_CFG,USE_TRANS_LOG,0
BOOK_CFG,USE_STU_TRACK,0
BOOK_CFG,REQ_MAX_LINES,0
BOOK_CFG,AUTO_UPDATE_RECV,0
BOOK_CFG,FROM_STU_TO_STU,0
BOOK_CFG,FROM_STU_TO_TEA,0
BOOK_CFG,FROM_STU_TO_BLDG,0
BOOK_CFG,FROM_STU_TO_WARE,0
BOOK_CFG,FROM_TEA_TO_STU,0
BOOK_CFG,FROM_TEA_TO_TEA,0
BOOK_CFG,FROM_TEA_TO_BLDG,0
BOOK_CFG,FROM_TEA_TO_WARE,0
BOOK_CFG,FROM_BLDG_TO_STU,0
BOOK_CFG,FROM_BLDG_TO_TEA,0
BOOK_CFG,FROM_BLDG_TO_BLDG,0
BOOK_CFG,FROM_BLDG_TO_WARE,0
BOOK_CFG,FROM_WARE_TO_STU,0
BOOK_CFG,FROM_WARE_TO_TEA,0
BOOK_CFG,FROM_WARE_TO_BLDG,0
BOOK_CFG,PRT_DOC_TEXT,0
BOOK_CFG,PRT_DOC_NAME,0
BOOK_CFG,PRT_DOC_TITLE,0
BOOK_CFG,CHANGE_DATE_TIME,0
BOOK_CFG,CHANGE_UID,0
BOOK_DIST,DISTRICT,1
BOOK_DIST,BUILDING,1
BOOK_DIST,ISBN_CODE,1
BOOK_DIST,BOOK_TYPE,1
BOOK_DIST,BAR_CODE_START,0
BOOK_DIST,BAR_CODE_END,0
BOOK_DIST,CREATED,0
BOOK_DIST,CHANGE_DATE_TIME,0
BOOK_DIST,CHANGE_UID,0
BOOK_ENROLL,DISTRICT,1
BOOK_ENROLL,BUILDING,1
BOOK_ENROLL,MLC_CODE,1
BOOK_ENROLL,DESCRIPTION,0
BOOK_ENROLL,STU_MEMBERSHIP,0
BOOK_ENROLL,TEA_MEMBERSHIP,0
BOOK_ENROLL,HIGH_ENROLL,0
BOOK_ENROLL,OLD_VALUE,0
BOOK_ENROLL,CHANGE_FLAG,0
BOOK_ENROLL,STU_HIGH_ENROLL,0
BOOK_ENROLL,HIGH_ENROLL_TEA,0
BOOK_ENROLL,TEA_HIGH_ENROLL,0
BOOK_ENROLL,STU_HIGH_ENR_LOCK,0
BOOK_ENROLL,TEA_HIGH_ENR_LOCK,0
BOOK_ENROLL,CHANGE_DATE_TIME,0
BOOK_ENROLL,CHANGE_UID,0
BOOK_GRADES,DISTRICT,1
BOOK_GRADES,ISBN_CODE,1
BOOK_GRADES,BOOK_TYPE,1
BOOK_GRADES,GRADE_LEVEL,0
BOOK_GRADES,CHANGE_DATE_TIME,0
BOOK_GRADES,CHANGE_UID,0
BOOK_MLC_COURSE,DISTRICT,1
BOOK_MLC_COURSE,COURSE,1
BOOK_MLC_COURSE,MLC_CODE,1
BOOK_MLC_COURSE,STATE_COURSE,0
BOOK_MLC_COURSE,CHANGE_DATE_TIME,0
BOOK_MLC_COURSE,CHANGE_UID,0
BOOK_REQ_DET,DISTRICT,1
BOOK_REQ_DET,ORDER_NUMBER,1
BOOK_REQ_DET,LINE_NUMBER,1
BOOK_REQ_DET,ISBN_CODE,0
BOOK_REQ_DET,BOOK_TYPE,0
BOOK_REQ_DET,ORDERED,0
BOOK_REQ_DET,SHIPPED,0
BOOK_REQ_DET,SHIPPED_TO_DATE,0
BOOK_REQ_DET,RECEIVED,0
BOOK_REQ_DET,RECEIVED_TO_DATE,0
BOOK_REQ_DET,LAST_DATE_SHIPPED,0
BOOK_REQ_DET,LAST_DATE_RECEIVED,0
BOOK_REQ_DET,LAST_QTY_SHIPPED,0
BOOK_REQ_DET,LAST_QTY_RECEIVED,0
BOOK_REQ_DET,CHANGE_DATE_TIME,0
BOOK_REQ_DET,CHANGE_UID,0
BOOK_REQ_HDR,DISTRICT,1
BOOK_REQ_HDR,ORDER_NUMBER,1
BOOK_REQ_HDR,REQUESTOR,0
BOOK_REQ_HDR,BUILDING,0
BOOK_REQ_HDR,DATE_ENTERED,0
BOOK_REQ_HDR,DATE_PRINTED,0
BOOK_REQ_HDR,DATE_SENT,0
BOOK_REQ_HDR,STATUS,0
BOOK_REQ_HDR,LAST_SHIPPED,0
BOOK_REQ_HDR,LAST_RECEIVED,0
BOOK_REQ_HDR,DATE_CLOSED,0
BOOK_REQ_HDR,SCREEN_ENTRY,0
BOOK_REQ_HDR,NOTES,0
BOOK_REQ_HDR,TRANSFER_FROM,0
BOOK_REQ_HDR,NEXT_YEAR_REQ,0
BOOK_REQ_HDR,REF_ORDER_NUMBER,0
BOOK_REQ_HDR,CHANGE_DATE_TIME,0
BOOK_REQ_HDR,CHANGE_UID,0
BOOK_STU_BOOKS,DISTRICT,1
BOOK_STU_BOOKS,BAR_CODE,1
BOOK_STU_BOOKS,STUDENT_ID,0
BOOK_STU_BOOKS,LAST_TRANS_DATE,0
BOOK_STU_BOOKS,BUILDING,0
BOOK_STU_BOOKS,CHANGE_DATE_TIME,0
BOOK_STU_BOOKS,CHANGE_UID,0
BOOK_TEXTBOOK,DISTRICT,1
BOOK_TEXTBOOK,ISBN_CODE,1
BOOK_TEXTBOOK,BOOK_TYPE,1
BOOK_TEXTBOOK,MLC_CODE,0
BOOK_TEXTBOOK,BOOK_TITLE,0
BOOK_TEXTBOOK,AUTHOR,0
BOOK_TEXTBOOK,PUBLISHER_CODE,0
BOOK_TEXTBOOK,COPYRIGHT_YEAR,0
BOOK_TEXTBOOK,UNIT_COST,0
BOOK_TEXTBOOK,ADOPTION_YEAR,0
BOOK_TEXTBOOK,EXPIRATION_YEAR,0
BOOK_TEXTBOOK,ADOPTION_STATUS,0
BOOK_TEXTBOOK,QUOTA_PERCENT,0
BOOK_TEXTBOOK,USABLE_ON_HAND,0
BOOK_TEXTBOOK,WORN_OUT,0
BOOK_TEXTBOOK,PAID_FOR,0
BOOK_TEXTBOOK,AMOUNT_FINES,0
BOOK_TEXTBOOK,REPORTED_SURPLUS,0
BOOK_TEXTBOOK,BOOKS_ON_ORDER,0
BOOK_TEXTBOOK,ISBN_CODE_OTHER,0
BOOK_TEXTBOOK,DEPOSITORY_CODE,0
BOOK_TEXTBOOK,BOOK_TYPE_RELATED,0
BOOK_TEXTBOOK,BOOKS_ON_PURCHASE,0
BOOK_TEXTBOOK,SUBJECT_DESC,0
BOOK_TEXTBOOK,ST_ADOPTION_CODE,0
BOOK_TEXTBOOK,GRADE_LEVEL,0
BOOK_TEXTBOOK,ACTIVE,0
BOOK_TEXTBOOK,OK_TO_ORDER,0
BOOK_TEXTBOOK,LOCAL_FLAG,0
BOOK_TEXTBOOK,EXTENDED_DESC,0
BOOK_TEXTBOOK,CHANGE_DATE_TIME,0
BOOK_TEXTBOOK,CHANGE_UID,0
BOOK_TRANS,DISTRICT,1
BOOK_TRANS,TRANS_NUMBER,1
BOOK_TRANS,ISBN_CODE,0
BOOK_TRANS,BOOK_TYPE,0
BOOK_TRANS,TRANSACTION_DATE,0
BOOK_TRANS,TRANSACTION_CODE,0
BOOK_TRANS,DESCRIPTION,0
BOOK_TRANS,USABLE_ON_HAND,0
BOOK_TRANS,WORN_OUT,0
BOOK_TRANS,PAID_FOR,0
BOOK_TRANS,AMOUNT_FINES,0
BOOK_TRANS,REPORTED_SURPLUS,0
BOOK_TRANS,NUMBER_BOOKS,0
BOOK_TRANS,PREVIOUS_BLDG,0
BOOK_TRANS,NEW_BUILDING,0
BOOK_TRANS,NEW_BOOK_CODE,0
BOOK_TRANS,TRANSFER_CONTROL,0
BOOK_TRANS,ORDERED_BOOKS,0
BOOK_TRANS,ADJ_COMMENT,0
BOOK_TRANS,CHANGE_DATE_TIME,0
BOOK_TRANS,CHANGE_UID,0
BOOK_WAREALTLOC,DISTRICT,1
BOOK_WAREALTLOC,ISBN_CODE,1
BOOK_WAREALTLOC,BUILDING,1
BOOK_WAREALTLOC,BOOK_TYPE,1
BOOK_WAREALTLOC,ALT_LOCATION,1
BOOK_WAREALTLOC,DISPLAY_ORDER,0
BOOK_WAREALTLOC,CHANGE_DATE_TIME,0
BOOK_WAREALTLOC,CHANGE_UID,0
BOOKTB_ADJ_COMMENT,DISTRICT,1
BOOKTB_ADJ_COMMENT,CODE,1
BOOKTB_ADJ_COMMENT,DESCRIPTION,0
BOOKTB_ADJ_COMMENT,ACTIVE,0
BOOKTB_ADJ_COMMENT,CHANGE_DATE_TIME,0
BOOKTB_ADJ_COMMENT,CHANGE_UID,0
BOOKTB_ADOPTION,DISTRICT,1
BOOKTB_ADOPTION,CODE,1
BOOKTB_ADOPTION,DESCRIPTION,0
BOOKTB_ADOPTION,CHANGE_DATE_TIME,0
BOOKTB_ADOPTION,CHANGE_UID,0
BOOKTB_DEPOSITORY,DISTRICT,1
BOOKTB_DEPOSITORY,CODE,1
BOOKTB_DEPOSITORY,DESCRIPTION,0
BOOKTB_DEPOSITORY,CHANGE_DATE_TIME,0
BOOKTB_DEPOSITORY,CHANGE_UID,0
BOOKTB_MLC,DISTRICT,1
BOOKTB_MLC,CODE,1
BOOKTB_MLC,DESCRIPTION,0
BOOKTB_MLC,ACTIVE,0
BOOKTB_MLC,CHANGE_DATE_TIME,0
BOOKTB_MLC,CHANGE_UID,0
BOOKTB_PUBLISHER,DISTRICT,1
BOOKTB_PUBLISHER,CODE,1
BOOKTB_PUBLISHER,DESCRIPTION,0
BOOKTB_PUBLISHER,CHANGE_DATE_TIME,0
BOOKTB_PUBLISHER,CHANGE_UID,0
BOOKTB_TYPE,DISTRICT,1
BOOKTB_TYPE,CODE,1
BOOKTB_TYPE,DESCRIPTION,0
BOOKTB_TYPE,CHANGE_DATE_TIME,0
BOOKTB_TYPE,CHANGE_UID,0
COTB_REPORT_PERIOD,DISTRICT,1
COTB_REPORT_PERIOD,SCHOOL_YEAR,1
COTB_REPORT_PERIOD,COLLECTION_PERIOD,1
COTB_REPORT_PERIOD,DESCRIPTION,0
COTB_REPORT_PERIOD,START_DATE,1
COTB_REPORT_PERIOD,END_DATE,1
COTB_REPORT_PERIOD,CHANGE_DATE_TIME,0
COTB_REPORT_PERIOD,CHANGE_UID,0
CP_CFG,DISTRICT,1
CP_CFG,BUILDING,1
CP_CFG,BLDG_HANDBOOK_LINK,0
CP_CFG,STUDENT_PLAN_TEXT,0
CP_CFG,CHANGE_DATE_TIME,0
CP_CFG,CHANGE_UID,0
CP_GRADPLAN_COURSE,DISTRICT,1
CP_GRADPLAN_COURSE,REQ_GROUP,1
CP_GRADPLAN_COURSE,STU_GRAD_YEAR,1
CP_GRADPLAN_COURSE,GRADE,1
CP_GRADPLAN_COURSE,BUILDING,1
CP_GRADPLAN_COURSE,COURSE_OR_GROUP,1
CP_GRADPLAN_COURSE,CRS_GROUP_FLAG,0
CP_GRADPLAN_COURSE,IS_REQUIRED,0
CP_GRADPLAN_COURSE,CHANGE_DATE_TIME,0
CP_GRADPLAN_COURSE,CHANGE_UID,0
CP_GRADPLAN_GD,DISTRICT,1
CP_GRADPLAN_GD,REQ_GROUP,1
CP_GRADPLAN_GD,STU_GRAD_YEAR,1
CP_GRADPLAN_GD,GRADE,1
CP_GRADPLAN_GD,CHANGE_DATE_TIME,0
CP_GRADPLAN_GD,CHANGE_UID,0
CP_GRADPLAN_HDR,DISTRICT,1
CP_GRADPLAN_HDR,REQ_GROUP,1
CP_GRADPLAN_HDR,STU_GRAD_YEAR,1
CP_GRADPLAN_HDR,CHANGE_DATE_TIME,0
CP_GRADPLAN_HDR,CHANGE_UID,0
CP_GRADPLAN_SUBJ,DISTRICT,1
CP_GRADPLAN_SUBJ,REQ_GROUP,1
CP_GRADPLAN_SUBJ,STU_GRAD_YEAR,1
CP_GRADPLAN_SUBJ,GRADE,1
CP_GRADPLAN_SUBJ,SUBJECT_AREA,1
CP_GRADPLAN_SUBJ,CREDIT,0
CP_GRADPLAN_SUBJ,CRS_GROUP_FLAG,0
CP_GRADPLAN_SUBJ,CHANGE_DATE_TIME,0
CP_GRADPLAN_SUBJ,CHANGE_UID,0
CP_STU_COURSE_OVR,DISTRICT,1
CP_STU_COURSE_OVR,STUDENT_ID,1
CP_STU_COURSE_OVR,BUILDING,1
CP_STU_COURSE_OVR,COURSE,1
CP_STU_COURSE_OVR,CHANGE_DATE_TIME,0
CP_STU_COURSE_OVR,CHANGE_UID,0
CP_STU_FUTURE_REQ,DISTRICT,1
CP_STU_FUTURE_REQ,STUDENT_ID,1
CP_STU_FUTURE_REQ,PLAN_MODE,1
CP_STU_FUTURE_REQ,SCHOOL_YEAR,1
CP_STU_FUTURE_REQ,BUILDING,1
CP_STU_FUTURE_REQ,REQ_GROUP,1
CP_STU_FUTURE_REQ,COURSE,1
CP_STU_FUTURE_REQ,REQUIRE_CODE,1
CP_STU_FUTURE_REQ,CODE_OVERRIDE,0
CP_STU_FUTURE_REQ,SUBJ_AREA_CREDIT,0
CP_STU_FUTURE_REQ,CHANGE_DATE_TIME,0
CP_STU_FUTURE_REQ,CHANGE_UID,0
CP_STU_GRAD,DISTRICT,1
CP_STU_GRAD,STUDENT_ID,1
CP_STU_GRAD,PLAN_MODE,1
CP_STU_GRAD,REQ_GROUP,1
CP_STU_GRAD,REQUIRE_CODE,1
CP_STU_GRAD,SUBJ_AREA_CREDIT,0
CP_STU_GRAD,CUR_ATT_CREDITS,0
CP_STU_GRAD,CUR_EARN_CREDITS,0
CP_STU_GRAD,CP_SCHD_CREDITS,0
CP_STU_GRAD,CHANGE_DATE_TIME,0
CP_STU_GRAD,CHANGE_UID,0
CP_STU_GRAD_AREA,DISTRICT,1
CP_STU_GRAD_AREA,STUDENT_ID,1
CP_STU_GRAD_AREA,SECTION_KEY,1
CP_STU_GRAD_AREA,COURSE_SESSION,1
CP_STU_GRAD_AREA,PLAN_MODE,1
CP_STU_GRAD_AREA,REQ_GROUP,1
CP_STU_GRAD_AREA,REQUIRE_CODE,1
CP_STU_GRAD_AREA,CODE_OVERRIDE,0
CP_STU_GRAD_AREA,SUBJ_AREA_CREDIT,0
CP_STU_GRAD_AREA,CREDIT_OVERRIDE,0
CP_STU_GRAD_AREA,CHANGE_DATE_TIME,0
CP_STU_GRAD_AREA,CHANGE_UID,0
CP_STU_PLAN_ALERT,DISTRICT,1
CP_STU_PLAN_ALERT,STUDENT_ID,1
CP_STU_PLAN_ALERT,REQ_GROUP,1
CP_STU_PLAN_ALERT,ALERT_CODE,1
CP_STU_PLAN_ALERT,REQUIRE_CODE,1
CP_STU_PLAN_ALERT,BUILDING,1
CP_STU_PLAN_ALERT,COURSE,1
CP_STU_PLAN_ALERT,CREDIT,0
CP_STU_PLAN_ALERT,CREDIT_NEEDED,0
CP_STU_PLAN_ALERT,CHANGE_DATE_TIME,0
CP_STU_PLAN_ALERT,CHANGE_UID,0
CP_VIEW_HDR,DISTRICT,1
CP_VIEW_HDR,BUILDING,1
CP_VIEW_HDR,STU_GRAD_YEAR,1
CP_VIEW_HDR,VIEW_TYPE,1
CP_VIEW_HDR,SHOW_CRS_DESCR,0
CP_VIEW_HDR,SHOW_CRS_NUMBER,0
CP_VIEW_HDR,SHOW_CRS_SECTION,0
CP_VIEW_HDR,SHOW_ATT_CREDIT,0
CP_VIEW_HDR,SHOW_EARN_CREDIT,0
CP_VIEW_HDR,SHOW_SUBJ_CREDIT,0
CP_VIEW_HDR,CHANGE_DATE_TIME,0
CP_VIEW_HDR,CHANGE_UID,0
CP_VIEW_LTDB,DISTRICT,1
CP_VIEW_LTDB,BUILDING,1
CP_VIEW_LTDB,STU_GRAD_YEAR,1
CP_VIEW_LTDB,VIEW_TYPE,1
CP_VIEW_LTDB,VIEW_ORDER,1
CP_VIEW_LTDB,LABEL,0
CP_VIEW_LTDB,TEST_CODE,0
CP_VIEW_LTDB,TEST_LEVEL,0
CP_VIEW_LTDB,TEST_FORM,0
CP_VIEW_LTDB,SUBTEST,0
CP_VIEW_LTDB,SCORE_CODE,0
CP_VIEW_LTDB,PRINT_TYPE,0
CP_VIEW_LTDB,PRINT_NUMBER,0
CP_VIEW_LTDB,PRINT_BLANK,0
CP_VIEW_LTDB,GROUP_SCORES,0
CP_VIEW_LTDB,CHANGE_DATE_TIME,0
CP_VIEW_LTDB,CHANGE_UID,0
CP_VIEW_MARKS,DISTRICT,1
CP_VIEW_MARKS,BUILDING,1
CP_VIEW_MARKS,STU_GRAD_YEAR,1
CP_VIEW_MARKS,VIEW_TYPE,1
CP_VIEW_MARKS,VIEW_SEQUENCE,1
CP_VIEW_MARKS,VIEW_ORDER,0
CP_VIEW_MARKS,TITLE,0
CP_VIEW_MARKS,MARK_TYPE,0
CP_VIEW_MARKS,CHANGE_DATE_TIME,0
CP_VIEW_MARKS,CHANGE_UID,0
CP_VIEW_MARKS_MP,DISTRICT,1
CP_VIEW_MARKS_MP,BUILDING,1
CP_VIEW_MARKS_MP,STU_GRAD_YEAR,1
CP_VIEW_MARKS_MP,VIEW_TYPE,1
CP_VIEW_MARKS_MP,VIEW_SEQUENCE,1
CP_VIEW_MARKS_MP,MARKING_PERIOD,1
CP_VIEW_MARKS_MP,CHANGE_DATE_TIME,0
CP_VIEW_MARKS_MP,CHANGE_UID,0
CP_VIEW_WORKSHEET,DISTRICT,1
CP_VIEW_WORKSHEET,BUILDING,1
CP_VIEW_WORKSHEET,STU_GRAD_YEAR,1
CP_VIEW_WORKSHEET,VIEW_TYPE,1
CP_VIEW_WORKSHEET,POST_GRAD_PLANS,0
CP_VIEW_WORKSHEET,GRAD_REQS_LIST,0
CP_VIEW_WORKSHEET,SUPP_REQS_LIST,0
CP_VIEW_WORKSHEET,STU_CAREER_PLAN,0
CP_VIEW_WORKSHEET,STU_SUPP_PLAN,0
CP_VIEW_WORKSHEET,SIGNATURE_LINES,0
CP_VIEW_WORKSHEET,UNASSIGNED_COURSES,0
CP_VIEW_WORKSHEET,HEADER_TEXT,0
CP_VIEW_WORKSHEET,FOOTER_TEXT,0
CP_VIEW_WORKSHEET,CHANGE_DATE_TIME,0
CP_VIEW_WORKSHEET,CHANGE_UID,0
CRN_CFG,DISTRICT,1
CRN_CFG,CRN_SERVER,0
CRN_CFG,GATEWAY_SERVER,0
CRN_CFG,GATEWAY_URL,0
CRN_CFG,AVAILABLE,0
CRN_CFG,CRN_VERSION,0
CRN_CFG,CRN_DESCRIPTION,0
CRN_CFG,ADD_PARAMS,0
CRN_CFG,USE_SSL,0
CRN_CFG,CHANGE_DATE_TIME,0
CRN_CFG,CHANGE_UID,0
DISC_ACT_USER,DISTRICT,0
DISC_ACT_USER,SCHOOL_YEAR,0
DISC_ACT_USER,SUMMER_SCHOOL,0
DISC_ACT_USER,BUILDING,0
DISC_ACT_USER,INCIDENT_ID,1
DISC_ACT_USER,ACTION_NUMBER,1
DISC_ACT_USER,SCREEN_TYPE,1
DISC_ACT_USER,OFF_VIC_WIT_ID,1
DISC_ACT_USER,SCREEN_NUMBER,1
DISC_ACT_USER,FIELD_NUMBER,1
DISC_ACT_USER,FIELD_VALUE,0
DISC_ACT_USER,CHANGE_DATE_TIME,0
DISC_ACT_USER,CHANGE_UID,0
DISC_ATT_NOTIFY,DISTRICT,1
DISC_ATT_NOTIFY,SCHOOL_YEAR,0
DISC_ATT_NOTIFY,SUMMER_SCHOOL,0
DISC_ATT_NOTIFY,BUILDING,0
DISC_ATT_NOTIFY,STUDENT_ID,1
DISC_ATT_NOTIFY,NOTIFY_CRITERIA,1
DISC_ATT_NOTIFY,REPORT_CYCLE_DATE,1
DISC_ATT_NOTIFY,TRIGGER_DATE,1
DISC_ATT_NOTIFY,INCIDENT_ID,1
DISC_ATT_NOTIFY,INVALID_NOTIFY,0
DISC_ATT_NOTIFY,PUBLISHED,0
DISC_ATT_NOTIFY,CHANGE_DATE_TIME,0
DISC_ATT_NOTIFY,CHANGE_UID,0
DISC_CFG,DISTRICT,1
DISC_CFG,BUILDING,1
DISC_CFG,FORM_LTR_FILENAME,0
DISC_CFG,USE_MULTI_LANGUAGE,0
DISC_CFG,PROGRAM_SCREEN,0
DISC_CFG,REG_USER_SCREEN,0
DISC_CFG,NOTIFY_DWNLD_PATH,0
DISC_CFG,EMAIL_OPTION,0
DISC_CFG,RETURN_EMAIL,0
DISC_CFG,MAGISTRATE_NUMBER,0
DISC_CFG,REFERRAL_RPT_HEADER,0
DISC_CFG,REFERRAL_RPT_FOOTER,0
DISC_CFG,ENABLE_ATTENDANCE,0
DISC_CFG,CHANGE_DATE_TIME,0
DISC_CFG,CHANGE_UID,0
DISC_CFG,EDIT_REFERRALS,0
DISC_CFG_LANG,DISTRICT,1
DISC_CFG_LANG,BUILDING,1
DISC_CFG_LANG,LANGUAGE_CODE,1
DISC_CFG_LANG,CHANGE_DATE_TIME,0
DISC_CFG_LANG,CHANGE_UID,0
DISC_DIST_CFG_AUTO_ACTION,DISTRICT,1
DISC_DIST_CFG_AUTO_ACTION,ACTION_CODE,1
DISC_DIST_CFG_AUTO_ACTION,CHANGE_DATE_TIME,0
DISC_DIST_CFG_AUTO_ACTION,CHANGE_UID,0
DISC_DIST_OFF_TOT,DISTRICT,1
DISC_DIST_OFF_TOT,ACT_SUFFIX,1
DISC_DIST_OFF_TOT,ACT_CODE,1
DISC_DIST_OFF_TOT,CHANGE_DATE_TIME,0
DISC_DIST_OFF_TOT,CHANGE_UID,0
DISC_DISTRICT_ACT,DISTRICT,1
DISC_DISTRICT_ACT,TOTAL_CODE,1
DISC_DISTRICT_ACT,ACTION_CODE,1
DISC_DISTRICT_ACT,CHANGE_DATE_TIME,0
DISC_DISTRICT_ACT,CHANGE_UID,0
DISC_DISTRICT_CFG,DISTRICT,1
DISC_DISTRICT_CFG,PRIVATE_NOTES,0
DISC_DISTRICT_CFG,TRACK_OCCURRENCES,0
DISC_DISTRICT_CFG,MULTIPLE_OFFENSES,0
DISC_DISTRICT_CFG,CURRENT_YEAR_SUM,0
DISC_DISTRICT_CFG,OFFENSE_ACT_TOTALS,0
DISC_DISTRICT_CFG,OFF_ACT_PREV_LST,0
DISC_DISTRICT_CFG,OFF_ACT_PREV_DET,0
DISC_DISTRICT_CFG,OFF_ACT_TOTAL_CNT,0
DISC_DISTRICT_CFG,INCIDENT_LOCKING,0
DISC_DISTRICT_CFG,ENFORCE_ACT_LEVELS,0
DISC_DISTRICT_CFG,RESPONSIBLE_ADMIN,0
DISC_DISTRICT_CFG,RESP_ADMIN_REQ,0
DISC_DISTRICT_CFG,AUTOCALC_END_DATE,0
DISC_DISTRICT_CFG,DEFAULT_SCHEDULED_DURATION,0
DISC_DISTRICT_CFG,USE_LONG_DESCRIPTION,0
DISC_DISTRICT_CFG,DEFAULT_INCIDENT_DATE,0
DISC_DISTRICT_CFG,LIMIT_OFFENDER_CODE,0
DISC_DISTRICT_CFG,CHANGE_DATE_TIME,0
DISC_DISTRICT_CFG,CHANGE_UID,0
DISC_DISTRICT_CFG_DETAIL,DISTRICT,1
DISC_DISTRICT_CFG_DETAIL,PAGE,1
DISC_DISTRICT_CFG_DETAIL,PAGE_SECTION,1
DISC_DISTRICT_CFG_DETAIL,QUICKVIEW,0
DISC_DISTRICT_CFG_DETAIL,DISPLAY_ORDER,0
DISC_DISTRICT_CFG_DETAIL,CHANGE_DATE_TIME,0
DISC_DISTRICT_CFG_DETAIL,CHANGE_UID,0
DISC_DISTRICT_CFG_SUMMARY,DISTRICT,1
DISC_DISTRICT_CFG_SUMMARY,SECTION,1
DISC_DISTRICT_CFG_SUMMARY,DISPLAY_ORDER,1
DISC_DISTRICT_CFG_SUMMARY,SCREEN_NUMBER,0
DISC_DISTRICT_CFG_SUMMARY,FIELD,0
DISC_DISTRICT_CFG_SUMMARY,LABEL,0
DISC_DISTRICT_CFG_SUMMARY,CHANGE_DATE_TIME,0
DISC_DISTRICT_CFG_SUMMARY,CHANGE_UID,0
DISC_DISTRICT_COST,DISTRICT,1
DISC_DISTRICT_COST,COST_CODE,1
DISC_DISTRICT_COST,COST_LABEL,0
DISC_DISTRICT_COST,COST_AMOUNT,0
DISC_DISTRICT_COST,PREPRINTED,0
DISC_DISTRICT_COST,STATE_CODE,0
DISC_DISTRICT_COST,CHANGE_DATE_TIME,0
DISC_DISTRICT_COST,CHANGE_UID,0
DISC_DISTRICT_FINE,DISTRICT,1
DISC_DISTRICT_FINE,FINE_CODE,1
DISC_DISTRICT_FINE,FINE_ORDER,1
DISC_DISTRICT_FINE,FINE_LABEL,0
DISC_DISTRICT_FINE,FINE_AMOUNT,0
DISC_DISTRICT_FINE,TIMES_USED,0
DISC_DISTRICT_FINE,FINE_TYPE,0
DISC_DISTRICT_FINE,CHANGE_DATE_TIME,0
DISC_DISTRICT_FINE,CHANGE_UID,0
DISC_DISTRICT_TOT,DISTRICT,1
DISC_DISTRICT_TOT,TOTAL_CODE,1
DISC_DISTRICT_TOT,TOTAL_LABEL,0
DISC_DISTRICT_TOT,TOTAL_SUFFIX,0
DISC_DISTRICT_TOT,WARNING_THRESHOLD,0
DISC_DISTRICT_TOT,CHANGE_DATE_TIME,0
DISC_DISTRICT_TOT,CHANGE_UID,0
DISC_INCIDENT,DISTRICT,1
DISC_INCIDENT,SCHOOL_YEAR,0
DISC_INCIDENT,SUMMER_SCHOOL,0
DISC_INCIDENT,BUILDING,0
DISC_INCIDENT,INCIDENT_ID,1
DISC_INCIDENT,INCIDENT_CODE,0
DISC_INCIDENT,INCIDENT_SUBCODE,0
DISC_INCIDENT,INCIDENT_DATE,0
DISC_INCIDENT,INCIDENT_TIME,0
DISC_INCIDENT,INCIDENT_TIME_FRAME,0
DISC_INCIDENT,LOCATION,0
DISC_INCIDENT,IS_STUDENT,0
DISC_INCIDENT,PERSON_ID,0
DISC_INCIDENT,REPORTED_TO,0
DISC_INCIDENT,GANG_RELATED,0
DISC_INCIDENT,POLICE_NOTIFIED,0
DISC_INCIDENT,POLICE_NOTIFY_DATE,0
DISC_INCIDENT,POLICE_DEPARTMENT,0
DISC_INCIDENT,COMPLAINT_NUMBER,0
DISC_INCIDENT,OFFICER_NAME,0
DISC_INCIDENT,BADGE_NUMBER,0
DISC_INCIDENT,COMMENTS,0
DISC_INCIDENT,LONG_COMMENT,0
DISC_INCIDENT,INCIDENT_GUID,0
DISC_INCIDENT,INCIDENT_LOCKED,0
DISC_INCIDENT,ROW_IDENTITY,0
DISC_INCIDENT,CHANGE_DATE_TIME,0
DISC_INCIDENT,CHANGE_UID,0
DISC_INCIDENT_CODE,DISTRICT,1
DISC_INCIDENT_CODE,CODE,1
DISC_INCIDENT_CODE,DESCRIPTION,0
DISC_INCIDENT_CODE,LEVEL_MIN,0
DISC_INCIDENT_CODE,LEVEL_MAX,0
DISC_INCIDENT_CODE,STATE_CODE_EQUIV,0
DISC_INCIDENT_CODE,SEVERITY_ORDER,0
DISC_INCIDENT_CODE,ACTIVE,0
DISC_INCIDENT_CODE,CHANGE_DATE_TIME,0
DISC_INCIDENT_CODE,CHANGE_UID,0
DISC_LINK_ISSUE,DISTRICT,1
DISC_LINK_ISSUE,SCHOOL_YEAR,0
DISC_LINK_ISSUE,SUMMER_SCHOOL,0
DISC_LINK_ISSUE,BUILDING,0
DISC_LINK_ISSUE,INCIDENT_ID,1
DISC_LINK_ISSUE,ISSUE_ID,1
DISC_LINK_ISSUE,CHANGE_DATE_TIME,0
DISC_LINK_ISSUE,CHANGE_UID,0
DISC_LTR_CRIT,DISTRICT,1
DISC_LTR_CRIT,SCHOOL_YEAR,1
DISC_LTR_CRIT,SUMMER_SCHOOL,1
DISC_LTR_CRIT,BUILDING,1
DISC_LTR_CRIT,CRITERION,1
DISC_LTR_CRIT,DESCRIPTION,0
DISC_LTR_CRIT,OFFENSE_COUNT_MIN,0
DISC_LTR_CRIT,OFFENSE_COUNT_MAX,0
DISC_LTR_CRIT,ACTION_COUNT_MIN,0
DISC_LTR_CRIT,ACTION_COUNT_MAX,0
DISC_LTR_CRIT,LETTER_COUNT_TYPE,0
DISC_LTR_CRIT,MAXIMUM_LETTERS,0
DISC_LTR_CRIT,RESET_COUNT,0
DISC_LTR_CRIT,LINES_OF_DETAIL,0
DISC_LTR_CRIT,INCIDENTS_TO_PRINT,0
DISC_LTR_CRIT,USE_ELIGIBILITY,0
DISC_LTR_CRIT,ELIG_INCLUDE_PRIOR,0
DISC_LTR_CRIT,ELIGIBILITY_CODE,0
DISC_LTR_CRIT,ELIG_DURATION,0
DISC_LTR_CRIT,ELIG_DURATION_DAYS,0
DISC_LTR_CRIT,USE_AT_RISK,0
DISC_LTR_CRIT,AT_RISK_REASON,0
DISC_LTR_CRIT,AT_RISK_DURATION,0
DISC_LTR_CRIT,AT_RISK_DAYS,0
DISC_LTR_CRIT,CHANGE_DATE_TIME,0
DISC_LTR_CRIT,CHANGE_UID,0
DISC_LTR_CRIT_ACT,DISTRICT,1
DISC_LTR_CRIT_ACT,SCHOOL_YEAR,1
DISC_LTR_CRIT_ACT,SUMMER_SCHOOL,1
DISC_LTR_CRIT_ACT,BUILDING,1
DISC_LTR_CRIT_ACT,CRITERION,1
DISC_LTR_CRIT_ACT,ACTION_CODE,1
DISC_LTR_CRIT_ACT,CHANGE_DATE_TIME,0
DISC_LTR_CRIT_ACT,CHANGE_UID,0
DISC_LTR_CRIT_ELIG,DISTRICT,1
DISC_LTR_CRIT_ELIG,SCHOOL_YEAR,1
DISC_LTR_CRIT_ELIG,SUMMER_SCHOOL,1
DISC_LTR_CRIT_ELIG,BUILDING,1
DISC_LTR_CRIT_ELIG,CRITERION,1
DISC_LTR_CRIT_ELIG,SEQUENCE_ORDER,1
DISC_LTR_CRIT_ELIG,CURRENT_ELIG_STATUS,1
DISC_LTR_CRIT_ELIG,ELIGIBILITY_CODE,0
DISC_LTR_CRIT_ELIG,CHANGE_DATE_TIME,0
DISC_LTR_CRIT_ELIG,CHANGE_UID,0
DISC_LTR_CRIT_OFF,DISTRICT,1
DISC_LTR_CRIT_OFF,SCHOOL_YEAR,1
DISC_LTR_CRIT_OFF,SUMMER_SCHOOL,1
DISC_LTR_CRIT_OFF,BUILDING,1
DISC_LTR_CRIT_OFF,CRITERION,1
DISC_LTR_CRIT_OFF,OFFENSE_CODE,1
DISC_LTR_CRIT_OFF,CHANGE_DATE_TIME,0
DISC_LTR_CRIT_OFF,CHANGE_UID,0
DISC_LTR_DETAIL,DISTRICT,1
DISC_LTR_DETAIL,SCHOOL_YEAR,1
DISC_LTR_DETAIL,SUMMER_SCHOOL,1
DISC_LTR_DETAIL,BUILDING,1
DISC_LTR_DETAIL,DATE_RUN,1
DISC_LTR_DETAIL,RUN_NUMBER,1
DISC_LTR_DETAIL,STUDENT_ID,1
DISC_LTR_DETAIL,CRITERION,1
DISC_LTR_DETAIL,LETTER_RESET,1
DISC_LTR_DETAIL,OFFENSE_COUNT,0
DISC_LTR_DETAIL,ACTION_COUNT,0
DISC_LTR_DETAIL,PRINT_DONE,0
DISC_LTR_DETAIL,CHANGE_DATE_TIME,0
DISC_LTR_DETAIL,CHANGE_UID,0
DISC_LTR_DETAIL,NOTIFICATION_SENT,0
DISC_LTR_HEADER,DISTRICT,1
DISC_LTR_HEADER,SCHOOL_YEAR,1
DISC_LTR_HEADER,SUMMER_SCHOOL,1
DISC_LTR_HEADER,BUILDING,1
DISC_LTR_HEADER,DATE_RUN,1
DISC_LTR_HEADER,RUN_NUMBER,1
DISC_LTR_HEADER,DATE_FROM,0
DISC_LTR_HEADER,DATE_THRU,0
DISC_LTR_HEADER,DATE_PRINTED,0
DISC_LTR_HEADER,LETTER_COUNT,0
DISC_LTR_HEADER,CHANGE_DATE_TIME,0
DISC_LTR_HEADER,CHANGE_UID,0
DISC_LTR_HEADER,DATE_NOTIFICATION_SENT,0
DISC_MSG_ACTIONCODE,DISTRICT,1
DISC_MSG_ACTIONCODE,BUILDING,1
DISC_MSG_ACTIONCODE,ACTION_CODE,1
DISC_MSG_ACTIONCODE,CHANGE_DATE_TIME,0
DISC_MSG_ACTIONCODE,CHANGE_UID,0
DISC_NON_STU_RACES,DISTRICT,1
DISC_NON_STU_RACES,NON_STUDENT_ID,1
DISC_NON_STU_RACES,RACE_CODE,1
DISC_NON_STU_RACES,RACE_ORDER,0
DISC_NON_STU_RACES,PERCENTAGE,0
DISC_NON_STU_RACES,CHANGE_DATE_TIME,0
DISC_NON_STU_RACES,CHANGE_UID,0
DISC_NON_STUDENT,DISTRICT,1
DISC_NON_STUDENT,NON_STUDENT_ID,1
DISC_NON_STUDENT,FIRST_NAME,0
DISC_NON_STUDENT,MIDDLE_NAME,0
DISC_NON_STUDENT,LAST_NAME,0
DISC_NON_STUDENT,GENERATION,0
DISC_NON_STUDENT,APARTMENT,0
DISC_NON_STUDENT,COMPLEX,0
DISC_NON_STUDENT,STREET_NUMBER,0
DISC_NON_STUDENT,STREET_NAME,0
DISC_NON_STUDENT,CITY,0
DISC_NON_STUDENT,STATE,0
DISC_NON_STUDENT,ZIP,0
DISC_NON_STUDENT,PHONE,0
DISC_NON_STUDENT,PHONE_EXTENSION,0
DISC_NON_STUDENT,BIRTHDATE,0
DISC_NON_STUDENT,GRADE,0
DISC_NON_STUDENT,GENDER,0
DISC_NON_STUDENT,ETHNIC_CODE,0
DISC_NON_STUDENT,HISPANIC,0
DISC_NON_STUDENT,FED_RACE_ETHNIC,0
DISC_NON_STUDENT,CLASSIFICATION,0
DISC_NON_STUDENT,STAFF_MEMBER,0
DISC_NON_STUDENT,BUILDING,0
DISC_NON_STUDENT,PERSON_DIST_CODE,0
DISC_NON_STUDENT,ROW_IDENTITY,0
DISC_NON_STUDENT,CHANGE_DATE_TIME,0
DISC_NON_STUDENT,CHANGE_UID,0
DISC_NOTES,DISTRICT,1
DISC_NOTES,SCHOOL_YEAR,0
DISC_NOTES,SUMMER_SCHOOL,0
DISC_NOTES,BUILDING,0
DISC_NOTES,INCIDENT_ID,1
DISC_NOTES,NOTE_TYPE,1
DISC_NOTES,OFF_VIC_WIT_ID,1
DISC_NOTES,PAGE_NUMBER,1
DISC_NOTES,NOTE_TEXT,0
DISC_NOTES,PRIVATE,0
DISC_NOTES,CHANGE_DATE_TIME,0
DISC_NOTES,CHANGE_UID,0
DISC_OCCURRENCE,DISTRICT,1
DISC_OCCURRENCE,SCHOOL_YEAR,0
DISC_OCCURRENCE,SUMMER_SCHOOL,0
DISC_OCCURRENCE,BUILDING,0
DISC_OCCURRENCE,INCIDENT_ID,1
DISC_OCCURRENCE,OFFENDER,1
DISC_OCCURRENCE,ACTION_NUMBER,1
DISC_OCCURRENCE,OCCURRENCE,1
DISC_OCCURRENCE,SCHD_START_DATE,0
DISC_OCCURRENCE,ACTUAL_START_DATE,0
DISC_OCCURRENCE,SCHD_START_TIME,0
DISC_OCCURRENCE,SCHD_END_TIME,0
DISC_OCCURRENCE,ACTUAL_START_TIME,0
DISC_OCCURRENCE,ACTUAL_END_TIME,0
DISC_OCCURRENCE,CHANGE_DATE_TIME,0
DISC_OCCURRENCE,CHANGE_UID,0
DISC_OFF_ACTION,DISTRICT,1
DISC_OFF_ACTION,SCHOOL_YEAR,0
DISC_OFF_ACTION,SUMMER_SCHOOL,0
DISC_OFF_ACTION,BUILDING,0
DISC_OFF_ACTION,INCIDENT_ID,1
DISC_OFF_ACTION,OFFENDER,1
DISC_OFF_ACTION,ACTION_NUMBER,1
DISC_OFF_ACTION,ACTION_CODE,0
DISC_OFF_ACTION,SCHD_DURATION,0
DISC_OFF_ACTION,ACTUAL_DURATION,0
DISC_OFF_ACTION,REASON_CODE,0
DISC_OFF_ACTION,DISPOSITION_CODE,0
DISC_OFF_ACTION,START_DATE,0
DISC_OFF_ACTION,END_DATE,0
DISC_OFF_ACTION,TOTAL_OCCURRENCES,0
DISC_OFF_ACTION,RESP_BUILDING,0
DISC_OFF_ACTION,ASSIGN_BUILDING,0
DISC_OFF_ACTION,DATE_DETERMINED,0
DISC_OFF_ACTION,ACTION_OUTCOME,0
DISC_OFF_ACTION,YEAREND_CARRY_OVER,0
DISC_OFF_ACTION,ROW_IDENTITY,0
DISC_OFF_ACTION,CHANGE_DATE_TIME,0
DISC_OFF_ACTION,CHANGE_UID,0
DISC_OFF_CHARGE,DISTRICT,1
DISC_OFF_CHARGE,SCHOOL_YEAR,0
DISC_OFF_CHARGE,SUMMER_SCHOOL,0
DISC_OFF_CHARGE,BUILDING,0
DISC_OFF_CHARGE,INCIDENT_ID,1
DISC_OFF_CHARGE,OFFENDER,1
DISC_OFF_CHARGE,CHARGE_CODE,1
DISC_OFF_CHARGE,CHANGE_DATE_TIME,0
DISC_OFF_CHARGE,CHANGE_UID,0
DISC_OFF_CODE,DISTRICT,1
DISC_OFF_CODE,SCHOOL_YEAR,0
DISC_OFF_CODE,SUMMER_SCHOOL,0
DISC_OFF_CODE,BUILDING,0
DISC_OFF_CODE,INCIDENT_ID,1
DISC_OFF_CODE,OFFENDER,1
DISC_OFF_CODE,OFFENSE_CODE,1
DISC_OFF_CODE,OFFENSE_COMMENT,0
DISC_OFF_CODE,CHANGE_DATE_TIME,0
DISC_OFF_CODE,CHANGE_UID,0
DISC_OFF_CONVICT,DISTRICT,1
DISC_OFF_CONVICT,SCHOOL_YEAR,0
DISC_OFF_CONVICT,SUMMER_SCHOOL,0
DISC_OFF_CONVICT,BUILDING,0
DISC_OFF_CONVICT,INCIDENT_ID,1
DISC_OFF_CONVICT,OFFENDER,1
DISC_OFF_CONVICT,CONVICTION_CODE,1
DISC_OFF_CONVICT,CHANGE_DATE_TIME,0
DISC_OFF_CONVICT,CHANGE_UID,0
DISC_OFF_DRUG,DISTRICT,1
DISC_OFF_DRUG,SCHOOL_YEAR,0
DISC_OFF_DRUG,SUMMER_SCHOOL,0
DISC_OFF_DRUG,BUILDING,0
DISC_OFF_DRUG,INCIDENT_ID,1
DISC_OFF_DRUG,OFFENDER,1
DISC_OFF_DRUG,DRUG_CODE,1
DISC_OFF_DRUG,CHANGE_DATE_TIME,0
DISC_OFF_DRUG,CHANGE_UID,0
DISC_OFF_FINE,DISTRICT,1
DISC_OFF_FINE,SCHOOL_YEAR,0
DISC_OFF_FINE,SUMMER_SCHOOL,0
DISC_OFF_FINE,BUILDING,0
DISC_OFF_FINE,INCIDENT_ID,1
DISC_OFF_FINE,OFFENDER,1
DISC_OFF_FINE,ACTION_NUMBER,1
DISC_OFF_FINE,PERSON_ID,0
DISC_OFF_FINE,IS_STUDENT,0
DISC_OFF_FINE,FINE_CODE,0
DISC_OFF_FINE,ISSUED_DATE,0
DISC_OFF_FINE,FINE_AMOUNT,0
DISC_OFF_FINE,PAID_DATE,0
DISC_OFF_FINE,COST,0
DISC_OFF_FINE,CITATION_NUMBER,0
DISC_OFF_FINE,STU_CITATION_NUM,0
DISC_OFF_FINE,MAGISTRATE_NUMBER,0
DISC_OFF_FINE,CHANGE_DATE_TIME,0
DISC_OFF_FINE,CHANGE_UID,0
DISC_OFF_SUBCODE,DISTRICT,1
DISC_OFF_SUBCODE,SCHOOL_YEAR,0
DISC_OFF_SUBCODE,SUMMER_SCHOOL,0
DISC_OFF_SUBCODE,BUILDING,0
DISC_OFF_SUBCODE,INCIDENT_ID,1
DISC_OFF_SUBCODE,OFFENDER,1
DISC_OFF_SUBCODE,OFFENSE_SUBCODE,1
DISC_OFF_SUBCODE,CHANGE_DATE_TIME,0
DISC_OFF_SUBCODE,CHANGE_UID,0
DISC_OFF_WEAPON,DISTRICT,1
DISC_OFF_WEAPON,SCHOOL_YEAR,0
DISC_OFF_WEAPON,SUMMER_SCHOOL,0
DISC_OFF_WEAPON,BUILDING,0
DISC_OFF_WEAPON,INCIDENT_ID,1
DISC_OFF_WEAPON,OFFENDER,1
DISC_OFF_WEAPON,WEAPON_CODE,1
DISC_OFF_WEAPON,WEAPON_COUNT,0
DISC_OFF_WEAPON,CHANGE_DATE_TIME,0
DISC_OFF_WEAPON,CHANGE_UID,0
DISC_OFFENDER,DISTRICT,1
DISC_OFFENDER,SCHOOL_YEAR,0
DISC_OFFENDER,SUMMER_SCHOOL,0
DISC_OFFENDER,BUILDING,0
DISC_OFFENDER,INCIDENT_ID,1
DISC_OFFENDER,OFFENDER,1
DISC_OFFENDER,IS_STUDENT,0
DISC_OFFENDER,PERSON_ID,0
DISC_OFFENDER,GUARDIAN_NOTIFIED,0
DISC_OFFENDER,NOTIFY_DATE,0
DISC_OFFENDER,HOW_NOTIFIED,0
DISC_OFFENDER,REFERRED_TO,0
DISC_OFFENDER,POLICE_ACTION,0
DISC_OFFENDER,CHARGES_FILED_BY,0
DISC_OFFENDER,CHARGES_FILED_WITH,0
DISC_OFFENDER,RESP_ADMIN,0
DISC_OFFENDER,ROW_IDENTITY,0
DISC_OFFENDER,CHANGE_DATE_TIME,0
DISC_OFFENDER,CHANGE_UID,0
DISC_PRINT_CITATION,DISTRICT,1
DISC_PRINT_CITATION,PRINT_RUN,1
DISC_PRINT_CITATION,SEQUENCE_NUMBER,1
DISC_PRINT_CITATION,CITATION_NUMBER,0
DISC_PRINT_CITATION,SCHOOL_YEAR,0
DISC_PRINT_CITATION,SUMMER_SCHOOL,0
DISC_PRINT_CITATION,BUILDING,0
DISC_PRINT_CITATION,MAGISTRATE_NUMBER,0
DISC_PRINT_CITATION,INCIDENT_ID,0
DISC_PRINT_CITATION,DEFENDANT_ID,0
DISC_PRINT_CITATION,STUDENT_ID,0
DISC_PRINT_CITATION,UNLAWFUL_DATES,0
DISC_PRINT_CITATION,FINE,0
DISC_PRINT_CITATION,COSTS,0
DISC_PRINT_CITATION,TOTAL_DUE,0
DISC_PRINT_CITATION,CITY_TOWN_BORO,0
DISC_PRINT_CITATION,LOCATION,0
DISC_PRINT_CITATION,COUNTY_CODE,0
DISC_PRINT_CITATION,DATE_FILED,0
DISC_PRINT_CITATION,STATION_ADDRESS,0
DISC_PRINT_CITATION,CHANGE_DATE_TIME,0
DISC_PRINT_CITATION,CHANGE_UID,0
DISC_STU_AT_RISK,DISTRICT,1
DISC_STU_AT_RISK,SCHOOL_YEAR,1
DISC_STU_AT_RISK,SUMMER_SCHOOL,1
DISC_STU_AT_RISK,BUILDING,1
DISC_STU_AT_RISK,DATE_RUN,1
DISC_STU_AT_RISK,RUN_NUMBER,1
DISC_STU_AT_RISK,STUDENT_ID,1
DISC_STU_AT_RISK,CRITERION,1
DISC_STU_AT_RISK,AT_RISK_REASON,0
DISC_STU_AT_RISK,EFFECTIVE_DATE,0
DISC_STU_AT_RISK,EXPIRATION_DATE,0
DISC_STU_AT_RISK,PLAN_NUM,0
DISC_STU_AT_RISK,CHANGE_DATE_TIME,0
DISC_STU_AT_RISK,CHANGE_UID,0
DISC_STU_ELIGIBLE,DISTRICT,1
DISC_STU_ELIGIBLE,SCHOOL_YEAR,1
DISC_STU_ELIGIBLE,SUMMER_SCHOOL,1
DISC_STU_ELIGIBLE,BUILDING,1
DISC_STU_ELIGIBLE,DATE_RUN,1
DISC_STU_ELIGIBLE,RUN_NUMBER,1
DISC_STU_ELIGIBLE,STUDENT_ID,1
DISC_STU_ELIGIBLE,CRITERION,1
DISC_STU_ELIGIBLE,ELIGIBILITY_CODE,0
DISC_STU_ELIGIBLE,EFFECTIVE_DATE,0
DISC_STU_ELIGIBLE,EXPIRATION_DATE,0
DISC_STU_ELIGIBLE,CHANGE_DATE_TIME,0
DISC_STU_ELIGIBLE,CHANGE_UID,0
DISC_STU_ROLLOVER,DISTRICT,1
DISC_STU_ROLLOVER,STUDENT_ID,1
DISC_STU_ROLLOVER,FIRST_NAME,0
DISC_STU_ROLLOVER,MIDDLE_NAME,0
DISC_STU_ROLLOVER,LAST_NAME,0
DISC_STU_ROLLOVER,GENERATION,0
DISC_STU_ROLLOVER,APARTMENT,0
DISC_STU_ROLLOVER,COMPLEX,0
DISC_STU_ROLLOVER,STREET_NUMBER,0
DISC_STU_ROLLOVER,STREET_NAME,0
DISC_STU_ROLLOVER,CITY,0
DISC_STU_ROLLOVER,STATE,0
DISC_STU_ROLLOVER,ZIP,0
DISC_STU_ROLLOVER,PHONE,0
DISC_STU_ROLLOVER,PHONE_EXTENSION,0
DISC_STU_ROLLOVER,BIRTHDATE,0
DISC_STU_ROLLOVER,GRADE,0
DISC_STU_ROLLOVER,GENDER,0
DISC_STU_ROLLOVER,ETHNIC_CODE,0
DISC_STU_ROLLOVER,HISPANIC,0
DISC_STU_ROLLOVER,FED_RACE_ETHNIC,0
DISC_STU_ROLLOVER,CLASSIFICATION,0
DISC_STU_ROLLOVER,STAFF_MEMBER,0
DISC_STU_ROLLOVER,BUILDING,0
DISC_STU_ROLLOVER,CHANGE_DATE_TIME,0
DISC_STU_ROLLOVER,CHANGE_UID,0
DISC_USER,DISTRICT,0
DISC_USER,SCHOOL_YEAR,0
DISC_USER,SUMMER_SCHOOL,0
DISC_USER,BUILDING,0
DISC_USER,INCIDENT_ID,1
DISC_USER,SCREEN_TYPE,1
DISC_USER,OFF_VIC_WIT_ID,1
DISC_USER,SCREEN_NUMBER,1
DISC_USER,FIELD_NUMBER,1
DISC_USER,FIELD_VALUE,0
DISC_USER,CHANGE_DATE_TIME,0
DISC_USER,CHANGE_UID,0
DISC_VICTIM,DISTRICT,1
DISC_VICTIM,SCHOOL_YEAR,0
DISC_VICTIM,SUMMER_SCHOOL,0
DISC_VICTIM,BUILDING,0
DISC_VICTIM,INCIDENT_ID,1
DISC_VICTIM,VICTIM,1
DISC_VICTIM,VICTIM_CODE,0
DISC_VICTIM,VICTIM_SUBCODE,0
DISC_VICTIM,IS_STUDENT,0
DISC_VICTIM,PERSON_ID,0
DISC_VICTIM,HOSPITAL_CODE,0
DISC_VICTIM,DOCTOR,0
DISC_VICTIM,GUARDIAN_NOTIFIED,0
DISC_VICTIM,NOTIFY_DATE,0
DISC_VICTIM,HOW_NOTIFIED,0
DISC_VICTIM,REFERRED_TO,0
DISC_VICTIM,ROW_IDENTITY,0
DISC_VICTIM,CHANGE_DATE_TIME,0
DISC_VICTIM,CHANGE_UID,0
DISC_VICTIM_ACTION,DISTRICT,1
DISC_VICTIM_ACTION,SCHOOL_YEAR,0
DISC_VICTIM_ACTION,SUMMER_SCHOOL,0
DISC_VICTIM_ACTION,BUILDING,0
DISC_VICTIM_ACTION,INCIDENT_ID,1
DISC_VICTIM_ACTION,VICTIM,1
DISC_VICTIM_ACTION,ACTION_NUMBER,1
DISC_VICTIM_ACTION,ACTION_CODE,0
DISC_VICTIM_ACTION,SCHD_DURATION,0
DISC_VICTIM_ACTION,ACTUAL_DURATION,0
DISC_VICTIM_ACTION,REASON_CODE,0
DISC_VICTIM_ACTION,DISPOSITION_CODE,0
DISC_VICTIM_ACTION,START_DATE,0
DISC_VICTIM_ACTION,END_DATE,0
DISC_VICTIM_ACTION,RESP_BUILDING,0
DISC_VICTIM_ACTION,DATE_DETERMINED,0
DISC_VICTIM_ACTION,ACTION_OUTCOME,0
DISC_VICTIM_ACTION,CHANGE_DATE_TIME,0
DISC_VICTIM_ACTION,CHANGE_UID,0
DISC_VICTIM_INJURY,DISTRICT,1
DISC_VICTIM_INJURY,SCHOOL_YEAR,0
DISC_VICTIM_INJURY,SUMMER_SCHOOL,0
DISC_VICTIM_INJURY,BUILDING,0
DISC_VICTIM_INJURY,INCIDENT_ID,1
DISC_VICTIM_INJURY,VICTIM,1
DISC_VICTIM_INJURY,INJURY_CODE,1
DISC_VICTIM_INJURY,CHANGE_DATE_TIME,0
DISC_VICTIM_INJURY,CHANGE_UID,0
DISC_WITNESS,DISTRICT,1
DISC_WITNESS,SCHOOL_YEAR,0
DISC_WITNESS,SUMMER_SCHOOL,0
DISC_WITNESS,BUILDING,0
DISC_WITNESS,INCIDENT_ID,1
DISC_WITNESS,WITNESS,1
DISC_WITNESS,WITNESS_CODE,0
DISC_WITNESS,WITNESS_SUBCODE,0
DISC_WITNESS,IS_STUDENT,0
DISC_WITNESS,PERSON_ID,0
DISC_WITNESS,GUARDIAN_NOTIFIED,0
DISC_WITNESS,NOTIFY_DATE,0
DISC_WITNESS,HOW_NOTIFIED,0
DISC_WITNESS,REFERRED_TO,0
DISC_WITNESS,ROW_IDENTITY,0
DISC_WITNESS,CHANGE_DATE_TIME,0
DISC_WITNESS,CHANGE_UID,0
DISC_YEAREND_RUN,DISTRICT,1
DISC_YEAREND_RUN,SCHOOL_YEAR,1
DISC_YEAREND_RUN,SUMMER_SCHOOL,1
DISC_YEAREND_RUN,RUN_KEY,1
DISC_YEAREND_RUN,RUN_DATE,0
DISC_YEAREND_RUN,RUN_STATUS,0
DISC_YEAREND_RUN,CLEAN_DISC_DATA,0
DISC_YEAREND_RUN,COPYCARRY,0
DISC_YEAREND_RUN,BUILDING_LIST,0
DISC_YEAREND_RUN,PURGE_BLD_YEAR,0
DISC_YEAREND_RUN,PURGE_INCIDENTS_YR,0
DISC_YEAREND_RUN,PURGE_LETTERS_YEAR,0
DISC_YEAREND_RUN,RESTORE_KEY,0
DISC_YEAREND_RUN,CHANGE_DATE_TIME,0
DISC_YEAREND_RUN,CHANGE_UID,0
DISCTB_ACT_OUTCOME,DISTRICT,1
DISCTB_ACT_OUTCOME,CODE,1
DISCTB_ACT_OUTCOME,DESCRIPTION,0
DISCTB_ACT_OUTCOME,STATE_CODE_EQUIV,0
DISCTB_ACT_OUTCOME,ACTIVE,0
DISCTB_ACT_OUTCOME,CHANGE_DATE_TIME,0
DISCTB_ACT_OUTCOME,CHANGE_UID,0
DISCTB_CHARGE,DISTRICT,1
DISCTB_CHARGE,CODE,1
DISCTB_CHARGE,DESCRIPTION,0
DISCTB_CHARGE,ACTIVE,0
DISCTB_CHARGE,CHANGE_DATE_TIME,0
DISCTB_CHARGE,CHANGE_UID,0
DISCTB_CONVICTION,DISTRICT,1
DISCTB_CONVICTION,CODE,1
DISCTB_CONVICTION,DESCRIPTION,0
DISCTB_CONVICTION,ACTIVE,0
DISCTB_CONVICTION,CHANGE_DATE_TIME,0
DISCTB_CONVICTION,CHANGE_UID,0
DISCTB_DISPOSITION,DISTRICT,1
DISCTB_DISPOSITION,CODE,1
DISCTB_DISPOSITION,DESCRIPTION,0
DISCTB_DISPOSITION,STATE_CODE_EQUIV,0
DISCTB_DISPOSITION,ACTIVE,0
DISCTB_DISPOSITION,CHANGE_DATE_TIME,0
DISCTB_DISPOSITION,CHANGE_UID,0
DISCTB_DRUG,DISTRICT,1
DISCTB_DRUG,CODE,1
DISCTB_DRUG,DESCRIPTION,0
DISCTB_DRUG,STATE_CODE_EQUIV,0
DISCTB_DRUG,ACTIVE,0
DISCTB_DRUG,CHANGE_DATE_TIME,0
DISCTB_DRUG,CHANGE_UID,0
DISCTB_INC_SUBCODE,DISTRICT,1
DISCTB_INC_SUBCODE,CODE,1
DISCTB_INC_SUBCODE,DESCRIPTION,0
DISCTB_INC_SUBCODE,ACTIVE,0
DISCTB_INC_SUBCODE,CHANGE_DATE_TIME,0
DISCTB_INC_SUBCODE,CHANGE_UID,0
DISCTB_INJURY,DISTRICT,1
DISCTB_INJURY,CODE,1
DISCTB_INJURY,DESCRIPTION,0
DISCTB_INJURY,STATE_CODE_EQUIV,0
DISCTB_INJURY,ACTIVE,0
DISCTB_INJURY,CHANGE_DATE_TIME,0
DISCTB_INJURY,CHANGE_UID,0
DISCTB_LOCATION,DISTRICT,1
DISCTB_LOCATION,CODE,1
DISCTB_LOCATION,DESCRIPTION,0
DISCTB_LOCATION,STATE_CODE_EQUIV,0
DISCTB_LOCATION,ACTIVE,0
DISCTB_LOCATION,CHANGE_DATE_TIME,0
DISCTB_LOCATION,CHANGE_UID,0
DISCTB_MAGISTRATE,DISTRICT,1
DISCTB_MAGISTRATE,CODE,1
DISCTB_MAGISTRATE,NAME,0
DISCTB_MAGISTRATE,STREET1,0
DISCTB_MAGISTRATE,STREET2,0
DISCTB_MAGISTRATE,CITY,0
DISCTB_MAGISTRATE,STATE,0
DISCTB_MAGISTRATE,ZIP,0
DISCTB_MAGISTRATE,PHONE,0
DISCTB_MAGISTRATE,FINE_BOTH,0
DISCTB_MAGISTRATE,ACTIVE,0
DISCTB_MAGISTRATE,CHANGE_DATE_TIME,0
DISCTB_MAGISTRATE,CHANGE_UID,0
DISCTB_NOTIFIED,DISTRICT,1
DISCTB_NOTIFIED,CODE,1
DISCTB_NOTIFIED,DESCRIPTION,0
DISCTB_NOTIFIED,ACTIVE,0
DISCTB_NOTIFIED,CHANGE_DATE_TIME,0
DISCTB_NOTIFIED,CHANGE_UID,0
DISCTB_OFF_ACTION,DISTRICT,1
DISCTB_OFF_ACTION,CODE,1
DISCTB_OFF_ACTION,DESCRIPTION,0
DISCTB_OFF_ACTION,LEVEL_NUMBER,0
DISCTB_OFF_ACTION,ATTENDANCE_CODE,0
DISCTB_OFF_ACTION,CARRYOVER,0
DISCTB_OFF_ACTION,STATE_CODE_EQUIV,0
DISCTB_OFF_ACTION,ACTIVE,0
DISCTB_OFF_ACTION,SEVERITY_LEVEL,0
DISCTB_OFF_ACTION,SIF_CODE,0
DISCTB_OFF_ACTION,CHANGE_DATE_TIME,0
DISCTB_OFF_ACTION,CHANGE_UID,0
DISCTB_OFF_SUBCODE,DISTRICT,1
DISCTB_OFF_SUBCODE,CODE,1
DISCTB_OFF_SUBCODE,DESCRIPTION,0
DISCTB_OFF_SUBCODE,ACTIVE,0
DISCTB_OFF_SUBCODE,CHANGE_DATE_TIME,0
DISCTB_OFF_SUBCODE,CHANGE_UID,0
DISCTB_POLICE_ACT,DISTRICT,1
DISCTB_POLICE_ACT,CODE,1
DISCTB_POLICE_ACT,DESCRIPTION,0
DISCTB_POLICE_ACT,ACTIVE,0
DISCTB_POLICE_ACT,STATE_CODE_EQUIV,0
DISCTB_POLICE_ACT,CHANGE_DATE_TIME,0
DISCTB_POLICE_ACT,CHANGE_UID,0
DISCTB_REASON,DISTRICT,1
DISCTB_REASON,CODE,1
DISCTB_REASON,DESCRIPTION,0
DISCTB_REASON,STATE_CODE_EQUIV,0
DISCTB_REASON,ACTIVE,0
DISCTB_REASON,CHANGE_DATE_TIME,0
DISCTB_REASON,CHANGE_UID,0
DISCTB_REFERRAL,DISTRICT,1
DISCTB_REFERRAL,CODE,1
DISCTB_REFERRAL,DESCRIPTION,0
DISCTB_REFERRAL,ACTIVE,0
DISCTB_REFERRAL,CHANGE_DATE_TIME,0
DISCTB_REFERRAL,CHANGE_UID,0
DISCTB_REFERRAL,STATE_CODE_EQUIV,0
DISCTB_TIMEFRAME,DISTRICT,1
DISCTB_TIMEFRAME,CODE,1
DISCTB_TIMEFRAME,DESCRIPTION,0
DISCTB_TIMEFRAME,STATE_CODE_EQUIV,0
DISCTB_TIMEFRAME,ACTIVE,0
DISCTB_TIMEFRAME,CHANGE_DATE_TIME,0
DISCTB_TIMEFRAME,CHANGE_UID,0
DISCTB_VIC_ACTION,DISTRICT,1
DISCTB_VIC_ACTION,CODE,1
DISCTB_VIC_ACTION,DESCRIPTION,0
DISCTB_VIC_ACTION,STATE_CODE_EQUIV,0
DISCTB_VIC_ACTION,ACTIVE,0
DISCTB_VIC_ACTION,CHANGE_DATE_TIME,0
DISCTB_VIC_ACTION,CHANGE_UID,0
DISCTB_VIC_CODE,DISTRICT,1
DISCTB_VIC_CODE,CODE,1
DISCTB_VIC_CODE,DESCRIPTION,0
DISCTB_VIC_CODE,STATE_CODE_EQUIV,0
DISCTB_VIC_CODE,ACTIVE,0
DISCTB_VIC_CODE,CHANGE_DATE_TIME,0
DISCTB_VIC_CODE,CHANGE_UID,0
DISCTB_VIC_DISP,DISTRICT,1
DISCTB_VIC_DISP,CODE,1
DISCTB_VIC_DISP,DESCRIPTION,0
DISCTB_VIC_DISP,STATE_CODE_EQUIV,0
DISCTB_VIC_DISP,ACTIVE,0
DISCTB_VIC_DISP,CHANGE_DATE_TIME,0
DISCTB_VIC_DISP,CHANGE_UID,0
DISCTB_VIC_REASON,DISTRICT,1
DISCTB_VIC_REASON,CODE,1
DISCTB_VIC_REASON,DESCRIPTION,0
DISCTB_VIC_REASON,STATE_CODE_EQUIV,0
DISCTB_VIC_REASON,ACTIVE,0
DISCTB_VIC_REASON,CHANGE_DATE_TIME,0
DISCTB_VIC_REASON,CHANGE_UID,0
DISCTB_VIC_SUBCODE,DISTRICT,1
DISCTB_VIC_SUBCODE,CODE,1
DISCTB_VIC_SUBCODE,DESCRIPTION,0
DISCTB_VIC_SUBCODE,ACTIVE,0
DISCTB_VIC_SUBCODE,CHANGE_DATE_TIME,0
DISCTB_VIC_SUBCODE,CHANGE_UID,0
DISCTB_WEAPON,DISTRICT,1
DISCTB_WEAPON,CODE,1
DISCTB_WEAPON,DESCRIPTION,0
DISCTB_WEAPON,STATE_CODE_EQUIV,0
DISCTB_WEAPON,ACTIVE,0
DISCTB_WEAPON,SEVERITY_ORDER,0
DISCTB_WEAPON,CHANGE_DATE_TIME,0
DISCTB_WEAPON,CHANGE_UID,0
DISCTB_WIT_CODE,DISTRICT,1
DISCTB_WIT_CODE,CODE,1
DISCTB_WIT_CODE,DESCRIPTION,0
DISCTB_WIT_CODE,ACTIVE,0
DISCTB_WIT_CODE,CHANGE_DATE_TIME,0
DISCTB_WIT_CODE,CHANGE_UID,0
DISCTB_WIT_SUBCODE,DISTRICT,1
DISCTB_WIT_SUBCODE,CODE,1
DISCTB_WIT_SUBCODE,DESCRIPTION,0
DISCTB_WIT_SUBCODE,ACTIVE,0
DISCTB_WIT_SUBCODE,CHANGE_DATE_TIME,0
DISCTB_WIT_SUBCODE,CHANGE_UID,0
dtproperties,id,0
dtproperties,objectid,0
dtproperties,property,0
dtproperties,value,0
dtproperties,uvalue,0
dtproperties,lvalue,0
dtproperties,version,0
ESP_MENU_FAVORITES,DISTRICT,1
ESP_MENU_FAVORITES,LOGIN_ID,1
ESP_MENU_FAVORITES,FAVORITE_ID,1
ESP_MENU_FAVORITES,FAVORITE_TYPE,0
ESP_MENU_FAVORITES,FOLDER_ID,0
ESP_MENU_FAVORITES,FAVORITE_ORDER,0
ESP_MENU_FAVORITES,DESCRIPTION,0
ESP_MENU_FAVORITES,AREA,0
ESP_MENU_FAVORITES,CONTROLLER,0
ESP_MENU_FAVORITES,ACTION,0
ESP_MENU_FAVORITES,PAGEURL,0
ESP_MENU_FAVORITES,QUERY_STRING,0
ESP_MENU_FAVORITES,CHANGE_DATE_TIME,0
ESP_MENU_FAVORITES,CHANGE_UID,0
ESP_MENU_ITEMS,DISTRICT,1
ESP_MENU_ITEMS,MENU_ID,1
ESP_MENU_ITEMS,MENU_TYPE,1
ESP_MENU_ITEMS,PARENT_ID,0
ESP_MENU_ITEMS,PARENT_TYPE,0
ESP_MENU_ITEMS,TITLE,0
ESP_MENU_ITEMS,DESCRIPTION,0
ESP_MENU_ITEMS,ICONURL,0
ESP_MENU_ITEMS,SEQUENCE,0
ESP_MENU_ITEMS,DISPLAY_COLUMN,0
ESP_MENU_ITEMS,AREA,0
ESP_MENU_ITEMS,CONTROLLER,0
ESP_MENU_ITEMS,ACTION,0
ESP_MENU_ITEMS,PAGEURL,0
ESP_MENU_ITEMS,TARGET,0
ESP_MENU_ITEMS,QUERY_STRING,0
ESP_MENU_ITEMS,TAC_ACCESS,0
ESP_MENU_ITEMS,RESERVED,0
ESP_MENU_ITEMS,CHANGE_DATE_TIME,0
ESP_MENU_ITEMS,CHANGE_UID,0
ESP_MENU_ITEMS,FEATURE_FLAG,0
ESP_PRSG_SCRIPT_HASH,SCRIPT_FOLDER,1
ESP_PRSG_SCRIPT_HASH,SCRIPT_NAME,1
ESP_PRSG_SCRIPT_HASH,SCRIPT_HASH,0
ESP_PRSG_SCRIPT_HASH,CHANGE_DATE_TIME,0
ESP_PRSG_SCRIPT_HASH,CHANGE_UID,0
FEE_CFG,DISTRICT,1
FEE_CFG,BUILDING,1
FEE_CFG,SCHD_PRO_RATE,0
FEE_CFG,PRORATE_LAST_CALC,0
FEE_CFG,BILL_STMT_HDR,0
FEE_CFG,BILL_STMT_FOOTER,0
FEE_CFG,PRORATE_RESOLVES,0
FEE_CFG,CHANGE_DATE_TIME,0
FEE_CFG,CHANGE_UID,0
FEE_CFG_PRO_RATE,DISTRICT,1
FEE_CFG_PRO_RATE,BUILDING,1
FEE_CFG_PRO_RATE,COURSE_WEEKS,1
FEE_CFG_PRO_RATE,ADD_DROP_INDICATOR,1
FEE_CFG_PRO_RATE,SEQUENCE_ORDER,1
FEE_CFG_PRO_RATE,NUMBER_OF_DAYS,0
FEE_CFG_PRO_RATE,PERCENT_DISCOUNT,0
FEE_CFG_PRO_RATE,CHANGE_DATE_TIME,0
FEE_CFG_PRO_RATE,CHANGE_UID,0
FEE_CFG_REDUCED,DISTRICT,1
FEE_CFG_REDUCED,BUILDING,1
FEE_CFG_REDUCED,FEE_TYPE,1
FEE_CFG_REDUCED,SEQUENCE_ORDER,1
FEE_CFG_REDUCED,RATE,0
FEE_CFG_REDUCED,TABLE_NAME,0
FEE_CFG_REDUCED,SCREEN_NUMBER,0
FEE_CFG_REDUCED,COLUMN_NAME,0
FEE_CFG_REDUCED,FIELD_NUMBER,0
FEE_CFG_REDUCED,REDUCED_VALUE,0
FEE_CFG_REDUCED,FEE_SUB_CATEGORY,0
FEE_CFG_REDUCED,CHANGE_DATE_TIME,0
FEE_CFG_REDUCED,CHANGE_UID,0
FEE_GROUP_CRIT,DISTRICT,1
FEE_GROUP_CRIT,SCHOOL_YEAR,1
FEE_GROUP_CRIT,SUMMER_SCHOOL,1
FEE_GROUP_CRIT,BUILDING,1
FEE_GROUP_CRIT,FEE_GROUP_CODE,1
FEE_GROUP_CRIT,SEQUENCE_NUM,1
FEE_GROUP_CRIT,AND_OR_FLAG,0
FEE_GROUP_CRIT,TABLE_NAME,0
FEE_GROUP_CRIT,SCREEN_TYPE,0
FEE_GROUP_CRIT,SCREEN_NUMBER,0
FEE_GROUP_CRIT,COLUMN_NAME,0
FEE_GROUP_CRIT,FIELD_NUMBER,0
FEE_GROUP_CRIT,OPERATOR,0
FEE_GROUP_CRIT,SEARCH_VALUE,0
FEE_GROUP_CRIT,CHANGE_DATE_TIME,0
FEE_GROUP_CRIT,CHANGE_UID,0
FEE_GROUP_CRIT,PROGRAM_ID,0
FEE_GROUP_DET,DISTRICT,1
FEE_GROUP_DET,SCHOOL_YEAR,1
FEE_GROUP_DET,SUMMER_SCHOOL,1
FEE_GROUP_DET,BUILDING,1
FEE_GROUP_DET,FEE_GROUP_CODE,1
FEE_GROUP_DET,SEQUENCE_ORDER,1
FEE_GROUP_DET,ITEM_CODE,0
FEE_GROUP_DET,TEXTBOOK_CODE,0
FEE_GROUP_DET,DESCRIPTION,0
FEE_GROUP_DET,QUANTITY,0
FEE_GROUP_DET,UNIT_COST,0
FEE_GROUP_DET,CAN_PRORATE,0
FEE_GROUP_DET,STAFF_ID_RESTR,0
FEE_GROUP_DET,CRS_SECTION_RESTR,0
FEE_GROUP_DET,COMMENT,0
FEE_GROUP_DET,CHANGE_DATE_TIME,0
FEE_GROUP_DET,CHANGE_UID,0
FEE_GROUP_HDR,DISTRICT,1
FEE_GROUP_HDR,SCHOOL_YEAR,1
FEE_GROUP_HDR,SUMMER_SCHOOL,1
FEE_GROUP_HDR,BUILDING,1
FEE_GROUP_HDR,FEE_GROUP_CODE,1
FEE_GROUP_HDR,DESCRIPTION,0
FEE_GROUP_HDR,FEE_TYPE,0
FEE_GROUP_HDR,REDUCED_RATE,0
FEE_GROUP_HDR,FREQUENCY,0
FEE_GROUP_HDR,COURSE_OR_ACTIVITY,0
FEE_GROUP_HDR,CHANGE_DATE_TIME,0
FEE_GROUP_HDR,CHANGE_UID,0
FEE_ITEM,DISTRICT,1
FEE_ITEM,SCHOOL_YEAR,1
FEE_ITEM,BUILDING,1
FEE_ITEM,ITEM_CODE,1
FEE_ITEM,FEE_TYPE,0
FEE_ITEM,DESCRIPTION,0
FEE_ITEM,UNIT_COST,0
FEE_ITEM,UNIT_DESCR_CODE,0
FEE_ITEM,PRIORITY,0
FEE_ITEM,CAN_PRORATE,0
FEE_ITEM,FEE_CATEGORY,0
FEE_ITEM,FEE_SUB_CATEGORY,0
FEE_ITEM,CHANGE_DATE_TIME,0
FEE_ITEM,CHANGE_UID,0
FEE_STU_AUDIT,DISTRICT,1
FEE_STU_AUDIT,AUDIT_NUMBER,1
FEE_STU_AUDIT,SCHOOL_YEAR,0
FEE_STU_AUDIT,SUMMER_SCHOOL,0
FEE_STU_AUDIT,BUILDING,0
FEE_STU_AUDIT,STUDENT_ID,0
FEE_STU_AUDIT,DATE_CREATED,0
FEE_STU_AUDIT,TRACKING_NUMBER,0
FEE_STU_AUDIT,ACTION_CODE,0
FEE_STU_AUDIT,PAYMENT_ID,0
FEE_STU_AUDIT,QUANTITY,0
FEE_STU_AUDIT,UNIT_COST,0
FEE_STU_AUDIT,COST_AMOUNT,0
FEE_STU_AUDIT,CREDIT_AMOUNT,0
FEE_STU_AUDIT,COMMENT,0
FEE_STU_AUDIT,CHANGE_DATE_TIME,0
FEE_STU_AUDIT,CHANGE_UID,0
FEE_STU_GROUP,DISTRICT,1
FEE_STU_GROUP,SCHOOL_YEAR,1
FEE_STU_GROUP,SUMMER_SCHOOL,1
FEE_STU_GROUP,BUILDING,1
FEE_STU_GROUP,FEE_GROUP_CODE,1
FEE_STU_GROUP,STUDENT_ID,1
FEE_STU_GROUP,CHANGE_DATE_TIME,0
FEE_STU_GROUP,CHANGE_UID,0
FEE_STU_ITEM,DISTRICT,1
FEE_STU_ITEM,TRACKING_NUMBER,1
FEE_STU_ITEM,SCHOOL_YEAR,0
FEE_STU_ITEM,SUMMER_SCHOOL,0
FEE_STU_ITEM,BUILDING,0
FEE_STU_ITEM,STUDENT_ID,0
FEE_STU_ITEM,DATE_CREATED,0
FEE_STU_ITEM,ITEM_CODE,0
FEE_STU_ITEM,TRACKING_NUMBER_DISPLAY,0
FEE_STU_ITEM,TEXTBOOK_CODE,0
FEE_STU_ITEM,DESCRIPTION,0
FEE_STU_ITEM,FEE_GROUP_CODE,0
FEE_STU_ITEM,SEQUENCE_ORDER,0
FEE_STU_ITEM,QUANTITY,0
FEE_STU_ITEM,UNIT_COST,0
FEE_STU_ITEM,UNIT_COST_OVR,0
FEE_STU_ITEM,TOTAL_PAID,0
FEE_STU_ITEM,TOTAL_CREDIT_APPLY,0
FEE_STU_ITEM,TOTAL_REFUND,0
FEE_STU_ITEM,BALANCE,0
FEE_STU_ITEM,REFUND_PRT_CHECK,0
FEE_STU_ITEM,PRORATED_ADD,0
FEE_STU_ITEM,PRORATED_DROP,0
FEE_STU_ITEM,PRORATED_RESOLVED,0
FEE_STU_ITEM,PRORATED_CLEAR,0
FEE_STU_ITEM,FEE_SUB_CATEGORY,0
FEE_STU_ITEM,CHANGE_DATE_TIME,0
FEE_STU_ITEM,CHANGE_UID,0
FEE_STU_PAYMENT,DISTRICT,1
FEE_STU_PAYMENT,PAYMENT_ID,1
FEE_STU_PAYMENT,SCHOOL_YEAR,0
FEE_STU_PAYMENT,SUMMER_SCHOOL,0
FEE_STU_PAYMENT,BUILDING,0
FEE_STU_PAYMENT,STUDENT_ID,0
FEE_STU_PAYMENT,PAYMENT_ID_DISPLAY,0
FEE_STU_PAYMENT,PAYMENT_DATE,0
FEE_STU_PAYMENT,REVERSE_FLAG,0
FEE_STU_PAYMENT,PAYMENT_TYPE_CODE,0
FEE_STU_PAYMENT,REFERENCE_NUMBER,0
FEE_STU_PAYMENT,COMMENT,0
FEE_STU_PAYMENT,TOTAL_PAID,0
FEE_STU_PAYMENT,CHANGE_DATE_TIME,0
FEE_STU_PAYMENT,CHANGE_UID,0
FEE_TEXTBOOK,DISTRICT,1
FEE_TEXTBOOK,SCHOOL_YEAR,1
FEE_TEXTBOOK,BUILDING,1
FEE_TEXTBOOK,TEXTBOOK_CODE,1
FEE_TEXTBOOK,DEPARTMENT,0
FEE_TEXTBOOK,DESCRIPTION,0
FEE_TEXTBOOK,UNIT_COST,0
FEE_TEXTBOOK,ISBN,0
FEE_TEXTBOOK,PUBLISHER,0
FEE_TEXTBOOK,COMMENT,0
FEE_TEXTBOOK,CHANGE_DATE_TIME,0
FEE_TEXTBOOK,CHANGE_UID,0
FEE_TEXTBOOK_CRS,DISTRICT,1
FEE_TEXTBOOK_CRS,SCHOOL_YEAR,1
FEE_TEXTBOOK_CRS,SUMMER_SCHOOL,1
FEE_TEXTBOOK_CRS,BUILDING,1
FEE_TEXTBOOK_CRS,TEXTBOOK_CODE,1
FEE_TEXTBOOK_CRS,COURSE,1
FEE_TEXTBOOK_CRS,CHANGE_DATE_TIME,0
FEE_TEXTBOOK_CRS,CHANGE_UID,0
FEE_TEXTBOOK_TEA,DISTRICT,1
FEE_TEXTBOOK_TEA,SCHOOL_YEAR,1
FEE_TEXTBOOK_TEA,SUMMER_SCHOOL,1
FEE_TEXTBOOK_TEA,BUILDING,1
FEE_TEXTBOOK_TEA,TEXTBOOK_CODE,1
FEE_TEXTBOOK_TEA,STAFF_ID,1
FEE_TEXTBOOK_TEA,CHANGE_DATE_TIME,0
FEE_TEXTBOOK_TEA,CHANGE_UID,0
FEE_YREND_RUN,DISTRICT,1
FEE_YREND_RUN,SCHOOL_YEAR,1
FEE_YREND_RUN,SUMMER_SCHOOL,1
FEE_YREND_RUN,RUN_KEY,1
FEE_YREND_RUN,RUN_DATE,0
FEE_YREND_RUN,RUN_STATUS,0
FEE_YREND_RUN,CLEAN_FEE_DATA,0
FEE_YREND_RUN,BUILDING_LIST,0
FEE_YREND_RUN,PURGE_FEE_YEAR,0
FEE_YREND_RUN,PURGE_STU_YEAR,0
FEE_YREND_RUN,RESTORE_KEY,0
FEE_YREND_RUN,CHANGE_DATE_TIME,0
FEE_YREND_RUN,CHANGE_UID,0
FEETB_CATEGORY,DISTRICT,1
FEETB_CATEGORY,SCHOOL_YEAR,1
FEETB_CATEGORY,CODE,1
FEETB_CATEGORY,DESCRIPTION,0
FEETB_CATEGORY,CHANGE_DATE_TIME,0
FEETB_CATEGORY,CHANGE_UID,0
FEETB_PAYMENT,DISTRICT,1
FEETB_PAYMENT,SCHOOL_YEAR,1
FEETB_PAYMENT,CODE,1
FEETB_PAYMENT,DESCRIPTION,0
FEETB_PAYMENT,CHANGE_DATE_TIME,0
FEETB_PAYMENT,CHANGE_UID,0
FEETB_STU_STATUS,DISTRICT,1
FEETB_STU_STATUS,SCHOOL_YEAR,1
FEETB_STU_STATUS,CODE,1
FEETB_STU_STATUS,DESCRIPTION,0
FEETB_STU_STATUS,THRESHOLD_AMOUNT,0
FEETB_STU_STATUS,CHANGE_DATE_TIME,0
FEETB_STU_STATUS,CHANGE_UID,0
FEETB_SUB_CATEGORY,DISTRICT,1
FEETB_SUB_CATEGORY,SCHOOL_YEAR,1
FEETB_SUB_CATEGORY,CODE,1
FEETB_SUB_CATEGORY,DESCRIPTION,0
FEETB_SUB_CATEGORY,CHANGE_DATE_TIME,0
FEETB_SUB_CATEGORY,CHANGE_UID,0
FEETB_UNIT_DESCR,DISTRICT,1
FEETB_UNIT_DESCR,SCHOOL_YEAR,1
FEETB_UNIT_DESCR,CODE,1
FEETB_UNIT_DESCR,DESCRIPTION,0
FEETB_UNIT_DESCR,CHANGE_DATE_TIME,0
FEETB_UNIT_DESCR,CHANGE_UID,0
GDBK_POST_CLS,DISTRICT,1
GDBK_POST_CLS,BUILDING,1
GDBK_POST_CLS,STUDENT_ID,1
GDBK_POST_CLS,COURSE,1
GDBK_POST_CLS,COURSE_SECTION,1
GDBK_POST_CLS,COURSE_SESSION,1
GDBK_POST_CLS,ABSENCE_DATE,1
GDBK_POST_CLS,ATTENDANCE_CODE,0
GDBK_POST_CLS,SOURCE,1
GDBK_POST_CLS,ARRIVE_TIME,0
GDBK_POST_CLS,DISMISS_TIME,0
GDBK_POST_CLS,ATT_COMMENT,0
GDBK_POST_DAT,DISTRICT,1
GDBK_POST_DAT,BUILDING,1
GDBK_POST_DAT,STUDENT_ID,1
GDBK_POST_DAT,ABSENCE_DATE,1
GDBK_POST_DAT,ATTENDANCE_CODE,0
GDBK_POST_DAT,AM_OR_PM,0
GDBK_POST_DAT,ARRIVE_TIME,0
GDBK_POST_DAT,DISMISS_TIME,0
GDBK_POST_DAT,ATT_COMMENT,0
GDBK_POST_IPR_COMM,DISTRICT,1
GDBK_POST_IPR_COMM,SECTION_KEY,1
GDBK_POST_IPR_COMM,COURSE_SESSION,1
GDBK_POST_IPR_COMM,STUDENT_ID,1
GDBK_POST_IPR_COMM,IPR_DATE,1
GDBK_POST_IPR_COMM,COMMENT_TYPE,1
GDBK_POST_IPR_COMM,COMMENT,0
GDBK_POST_IPR_MARK,DISTRICT,1
GDBK_POST_IPR_MARK,SECTION_KEY,1
GDBK_POST_IPR_MARK,COURSE_SESSION,1
GDBK_POST_IPR_MARK,STUDENT_ID,1
GDBK_POST_IPR_MARK,IPR_DATE,1
GDBK_POST_IPR_MARK,MARK_TYPE,1
GDBK_POST_IPR_MARK,MARK_VALUE,0
GDBK_POST_RC,DISTRICT,1
GDBK_POST_RC,BUILDING,1
GDBK_POST_RC,STUDENT_ID,1
GDBK_POST_RC,COURSE,1
GDBK_POST_RC,COURSE_SECTION,1
GDBK_POST_RC,COURSE_SESSION,1
GDBK_POST_RC,FINAL_GRADE,0
GDBK_POST_RC,MARKING_PERIOD,0
GDBK_POST_RC,GRADE1,0
GDBK_POST_RC,GRADE2,0
GDBK_POST_RC,GRADE3,0
GDBK_POST_RC,ABSENCES1,0
GDBK_POST_RC,ABSENCES2,0
GDBK_POST_RC,ABSENCES3,0
GDBK_POST_RC,COMMENT1,0
GDBK_POST_RC,COMMENT2,0
GDBK_POST_RC,COMMENT4,0
GDBK_POST_RC,COMMENT5,0
GDBK_POST_RC_ABS,DISTRICT,1
GDBK_POST_RC_ABS,SECTION_KEY,1
GDBK_POST_RC_ABS,COURSE_SESSION,1
GDBK_POST_RC_ABS,STUDENT_ID,1
GDBK_POST_RC_ABS,RC_DATE,1
GDBK_POST_RC_ABS,ABS_TYPE,1
GDBK_POST_RC_ABS,ABS_VALUE,0
GDBK_POST_RC_COMM,DISTRICT,1
GDBK_POST_RC_COMM,SECTION_KEY,1
GDBK_POST_RC_COMM,COURSE_SESSION,1
GDBK_POST_RC_COMM,STUDENT_ID,1
GDBK_POST_RC_COMM,RC_DATE,1
GDBK_POST_RC_COMM,COMMENT_TYPE,1
GDBK_POST_RC_COMM,COMMENT,0
GDBK_POST_RC_MARK,DISTRICT,1
GDBK_POST_RC_MARK,SECTION_KEY,1
GDBK_POST_RC_MARK,COURSE_SESSION,1
GDBK_POST_RC_MARK,STUDENT_ID,1
GDBK_POST_RC_MARK,RC_DATE,1
GDBK_POST_RC_MARK,MARK_TYPE,1
GDBK_POST_RC_MARK,MARK_VALUE,0
HAC_BUILDING_ALERT,DISTRICT,1
HAC_BUILDING_ALERT,BUILDING,1
HAC_BUILDING_ALERT,ALERT_TYPE,1
HAC_BUILDING_ALERT,SEND_TO_GUARDIANS,0
HAC_BUILDING_ALERT,SEND_TO_STUDENTS,0
HAC_BUILDING_ALERT,SEND_TO_TEACHERS,0
HAC_BUILDING_ALERT,SCHEDULE_TYPE,0
HAC_BUILDING_ALERT,TASK_OWNER,0
HAC_BUILDING_ALERT,ALERT_DATE,0
HAC_BUILDING_ALERT,INCLUDE_PRIOR_DAYS,0
HAC_BUILDING_ALERT,SCHD_TIME,0
HAC_BUILDING_ALERT,SCHD_DATE,0
HAC_BUILDING_ALERT,SCHD_INTERVAL,0
HAC_BUILDING_ALERT,SCHD_DOW,0
HAC_BUILDING_ALERT,PARAM_KEY,0
HAC_BUILDING_ALERT,LAST_RUN_DATE,0
HAC_BUILDING_ALERT,FROM_EMAIL,0
HAC_BUILDING_ALERT,SUBJECT_LINE,0
HAC_BUILDING_ALERT,HEADER_TEXT,0
HAC_BUILDING_ALERT,FOOTER_TEXT,0
HAC_BUILDING_ALERT,CHANGE_DATE_TIME,0
HAC_BUILDING_ALERT,CHANGE_UID,0
HAC_BUILDING_ALERT_MARK_TYPE,DISTRICT,1
HAC_BUILDING_ALERT_MARK_TYPE,BUILDING,1
HAC_BUILDING_ALERT_MARK_TYPE,ALERT_TYPE,1
HAC_BUILDING_ALERT_MARK_TYPE,AVG_MARK_TYPE,1
HAC_BUILDING_ALERT_MARK_TYPE,CHANGE_DATE_TIME,0
HAC_BUILDING_ALERT_MARK_TYPE,CHANGE_UID,0
HAC_Building_Cfg,DISTRICT,1
HAC_Building_Cfg,BUILDING,1
HAC_Building_Cfg,CONFIG_TYPE,1
HAC_Building_Cfg,ENABLE_HAC,0
HAC_Building_Cfg,BUILDING_LOGO,0
HAC_Building_Cfg,LOGO_HEADER_COLOR,0
HAC_Building_Cfg,LOGO_TEXT_COLOR,0
HAC_Building_Cfg,FIRST_PAGE,0
HAC_Building_Cfg,SHOW_PERSONAL,0
HAC_Building_Cfg,UPD_EMAIL,0
HAC_Building_Cfg,UPD_PHONE,0
HAC_Building_Cfg,SHOW_EMERGENCY,0
HAC_Building_Cfg,UPD_EMERGENCY,0
HAC_Building_Cfg,SHOW_CONTACT,0
HAC_Building_Cfg,SHOW_FERPA,0
HAC_Building_Cfg,UPD_FERPA,0
HAC_Building_Cfg,FERPA_EXPLANATION,0
HAC_Building_Cfg,SHOW_TRANSPORT,0
HAC_Building_Cfg,SHOW_SCHEDULE,0
HAC_Building_Cfg,SHOW_SCHD_GRID,0
HAC_Building_Cfg,SHOW_DROPPED_CRS,0
HAC_Building_Cfg,SHOW_REQUESTS,0
HAC_Building_Cfg,SHOW_ATTENDANCE,0
HAC_Building_Cfg,SHOW_DISCIPLINE,0
HAC_Building_Cfg,CURRENT_YEAR_DISC_ONLY,0
HAC_Building_Cfg,SHOW_ASSIGN,0
HAC_Building_Cfg,AVG_MARK_TYPE,0
HAC_Building_Cfg,INC_UNPUB_AVG,0
HAC_Building_Cfg,SHOW_CLASS_AVG,0
HAC_Building_Cfg,SHOW_ATTACHMENTS,0
HAC_Building_Cfg,DEF_CLASSWORK_VIEW,0
HAC_Building_Cfg,SHOW_IPR,0
HAC_Building_Cfg,SHOW_RC,0
HAC_Building_Cfg,SHOW_STU_COMP,0
HAC_Building_Cfg,SHOW_CRS_COMP,0
HAC_Building_Cfg,SHOW_LTDB,0
HAC_Building_Cfg,SHOW_EMAIL,0
HAC_Building_Cfg,SHOW_TRANSCRIPT,0
HAC_Building_Cfg,SHOW_CAREER_PLANNER,0
HAC_Building_Cfg,REQUEST_BY,0
HAC_Building_Cfg,REQUEST_YEAR,0
HAC_Building_Cfg,REQUEST_INTERVAL,0
HAC_Building_Cfg,PREREQ_CHK_REQ,0
HAC_Building_Cfg,SHOW_SUCCESS_PLAN,0
HAC_Building_Cfg,SHOW_SENS_PLAN,0
HAC_Building_Cfg,SHOW_SENS_INT,0
HAC_Building_Cfg,SHOW_SENS_INT_COMM,0
HAC_Building_Cfg,UPD_SSP_PARENT_GOAL,0
HAC_Building_Cfg,UPD_SSP_STUDENT_GOAL,0
HAC_Building_Cfg,SHOW_HONOR_ROLL_CREDIT,0
HAC_Building_Cfg,SHOW_HONOR_ROLL_GPA,0
HAC_Building_Cfg,SHOW_HONOR_MESSAGE,0
HAC_Building_Cfg,SHOW_REQUEST_ENTRY,0
HAC_Building_Cfg,MIN_CREDIT_REQ,0
HAC_Building_Cfg,MAX_CREDIT_REQ,0
HAC_Building_Cfg,SHOW_RC_ATTENDANCE,0
HAC_Building_Cfg,RC_HOLD_MESSAGE,0
HAC_Building_Cfg,SHOW_EO,0
HAC_Building_Cfg,SHOW_PERFORMANCEPLUS,0
HAC_Building_Cfg,SHOW_AVG_INHDR,0
HAC_Building_Cfg,HDR_AVG_MARKTYPE,0
HAC_Building_Cfg,SHOW_LAST_UPDDT,0
HAC_Building_Cfg,HDR_SHORT_DESC,0
HAC_Building_Cfg,AVG_TOOLTIP_DESC,0
HAC_Building_Cfg,HIDE_PERCENTAGE,0
HAC_Building_Cfg,HIDE_OVERALL_AVG,0
HAC_Building_Cfg,HIDE_COMP_SCORE,0
HAC_Building_Cfg,SHOW_SDE,0
HAC_Building_Cfg,SHOW_FEES,0
HAC_Building_Cfg,ENABLE_ONLINE_PAYMENT,0
HAC_Building_Cfg,SHOW_CALENDAR,0
HAC_Building_Cfg,AVG_ON_HOME_PAGE,0
HAC_Building_Cfg,HELP_URL,0
HAC_Building_Cfg,SHOW_IEP,0
HAC_Building_Cfg,SHOW_GIFTED,0
HAC_Building_Cfg,SHOW_504PLAN,0
HAC_Building_Cfg,SHOW_IEP_INVITATION,0
HAC_Building_Cfg,SHOW_EVAL_RPT,0
HAC_Building_Cfg,SHOW_IEP_PROGRESS,0
HAC_Building_Cfg,IEP_LIVING_WITH_ONLY,0
HAC_Building_Cfg,SHOW_WEEK_VIEW,0
HAC_Building_Cfg,SHOW_WEEK_VIEW_DISC,0
HAC_Building_Cfg,SHOW_WEEK_VIEW_FEES,0
HAC_Building_Cfg,SHOW_WEEK_VIEW_ATT,0
HAC_Building_Cfg,SHOW_WEEK_VIEW_CRS,0
HAC_Building_Cfg,SHOW_WEEK_VIEW_COMP,0
HAC_Building_Cfg,SHOW_REQUEST_ALTERNATE,0
HAC_Building_Cfg,AVERAGE_DISPLAY_TYPE,0
HAC_Building_Cfg,SHOW_RC_PRINT,0
HAC_Building_Cfg,SHOW_GENDER,0
HAC_Building_Cfg,SHOW_STUDENT_ID,0
HAC_Building_Cfg,SHOW_HOMEROOM,0
HAC_Building_Cfg,SHOW_HOMEROOM_TEACHER,0
HAC_Building_Cfg,SHOW_COUNSELOR,0
HAC_Building_Cfg,SHOW_HOUSE_TEAM,0
HAC_Building_Cfg,SHOW_LOCKER_NO,0
HAC_Building_Cfg,SHOW_LOCKER_COMBO,0
HAC_Building_Cfg,CHANGE_DATE_TIME,0
HAC_Building_Cfg,CHANGE_UID,0
HAC_Building_Cfg,SHOW_LEARNING_LOCATION,0
HAC_Building_Cfg,SHOW_MEETING_LINK,0
HAC_Building_Cfg,SHOW_MANUAL_CHECKIN,0
HAC_Building_Cfg,SHOW_FILE_UPLOAD,0
HAC_Building_Cfg,SHOW_STUDENT_SSID,0
HAC_Building_Cfg,VIEW_ADDITIONAL_EMAIL,0
HAC_Building_Cfg,UPD_ADDITIONAL_EMAIL,0
HAC_Building_Cfg,DISPLAY_TURNED_IN,0
HAC_BUILDING_CFG_ATTACHMENT,DISTRICT,1
HAC_BUILDING_CFG_ATTACHMENT,BUILDING,1
HAC_BUILDING_CFG_ATTACHMENT,CONFIG_TYPE,1
HAC_BUILDING_CFG_ATTACHMENT,UPLOAD_TYPE,1
HAC_BUILDING_CFG_ATTACHMENT,ALLOWABLE_FILE_TYPES,0
HAC_BUILDING_CFG_ATTACHMENT,USER_INSTRUCTION,0
HAC_BUILDING_CFG_ATTACHMENT,CATEGORY,0
HAC_BUILDING_CFG_ATTACHMENT,ACTIVE,0
HAC_BUILDING_CFG_ATTACHMENT,CHANGE_DATE_TIME,0
HAC_BUILDING_CFG_ATTACHMENT,CHANGE_UID,0
HAC_BUILDING_CFG_ATTACHMENT,SORT_ORDER,0
HAC_BUILDING_CFG_AUX,DISTRICT,1
HAC_BUILDING_CFG_AUX,BUILDING,1
HAC_BUILDING_CFG_AUX,CONFIG_TYPE,1
HAC_BUILDING_CFG_AUX,DISPLAY_REG_YEAR,0
HAC_BUILDING_CFG_AUX,DISPLAY_REG_YEAR_SPECIFY,0
HAC_BUILDING_CFG_AUX,DISPLAY_SUM_YEAR,0
HAC_BUILDING_CFG_AUX,DISPLAY_SUM_YEAR_SPECIFY,0
HAC_BUILDING_CFG_AUX,RESTRICT_CALENDAR,0
HAC_BUILDING_CFG_AUX,CLASSWORK_VIEW,0
HAC_BUILDING_CFG_AUX,CHANGE_DATE_TIME,0
HAC_BUILDING_CFG_AUX,CHANGE_UID,0
HAC_BUILDING_CFG_CONTACTS,DISTRICT,1
HAC_BUILDING_CFG_CONTACTS,BUILDING,1
HAC_BUILDING_CFG_CONTACTS,CONFIG_TYPE,1
HAC_BUILDING_CFG_CONTACTS,SHOW_GUARDIANS,0
HAC_BUILDING_CFG_CONTACTS,SHOW_EMERGENCY,0
HAC_BUILDING_CFG_CONTACTS,SHOW_OTHER,0
HAC_BUILDING_CFG_CONTACTS,CHANGE_DATE_TIME,0
HAC_BUILDING_CFG_CONTACTS,CHANGE_UID,0
HAC_BUILDING_CFG_DISC,DISTRICT,1
HAC_BUILDING_CFG_DISC,BUILDING,1
HAC_BUILDING_CFG_DISC,CONFIG_TYPE,1
HAC_BUILDING_CFG_DISC,INCIDENT_CODE,1
HAC_BUILDING_CFG_DISC,CHANGE_DATE_TIME,0
HAC_BUILDING_CFG_DISC,CHANGE_UID,0
HAC_BUILDING_CFG_HDR_RRK,DISTRICT,1
HAC_BUILDING_CFG_HDR_RRK,BUILDING,1
HAC_BUILDING_CFG_HDR_RRK,LABEL,0
HAC_BUILDING_CFG_HDR_RRK,CHANGE_DATE_TIME,0
HAC_BUILDING_CFG_HDR_RRK,CHANGE_UID,0
HAC_BUILDING_CFG_INTER,DISTRICT,1
HAC_BUILDING_CFG_INTER,BUILDING,1
HAC_BUILDING_CFG_INTER,CONFIG_TYPE,1
HAC_BUILDING_CFG_INTER,SHOW_INTERVENTION_MARK,0
HAC_BUILDING_CFG_INTER,SHOW_INTERVENTION_COMMENT,0
HAC_BUILDING_CFG_INTER,CHANGE_DATE_TIME,0
HAC_BUILDING_CFG_INTER,CHANGE_UID,0
HAC_BUILDING_CFG_RRK,DISTRICT,1
HAC_BUILDING_CFG_RRK,BUILDING,1
HAC_BUILDING_CFG_RRK,LOGIN_TYPE,1
HAC_BUILDING_CFG_RRK,SORT_ORDER,1
HAC_BUILDING_CFG_RRK,SCREEN_NUMBER,0
HAC_BUILDING_CFG_RRK,FIELD_NUMBER,0
HAC_BUILDING_CFG_RRK,FIELD_LABEL,0
HAC_BUILDING_CFG_RRK,FIELD_ACTIVE,0
HAC_BUILDING_CFG_RRK,CHANGE_DATE_TIME,0
HAC_BUILDING_CFG_RRK,CHANGE_UID,0
HAC_CHALLENGE_QUES,DISTRICT,1
HAC_CHALLENGE_QUES,CONTACT_ID,1
HAC_CHALLENGE_QUES,SEQ_NBR,1
HAC_CHALLENGE_QUES,QUESTION,0
HAC_CHALLENGE_QUES,ANSWER,0
HAC_CHALLENGE_QUES,CHANGE_DATE_TIME,0
HAC_CHALLENGE_QUES,CHANGE_UID,0
HAC_DIST_CFG_LDAP,DISTRICT,1
HAC_DIST_CFG_LDAP,LDAP_ID,1
HAC_DIST_CFG_LDAP,DISTINGUISHED_NAME,0
HAC_DIST_CFG_LDAP,DOMAIN_NAME,0
HAC_DIST_CFG_LDAP,SUB_SEARCH,0
HAC_DIST_CFG_LDAP,CHANGE_DATE_TIME,0
HAC_DIST_CFG_LDAP,CHANGE_UID,0
HAC_DIST_CFG_ONLINE_PAYMT,DISTRICT,1
HAC_DIST_CFG_ONLINE_PAYMT,USE_FRONTSTREAM,0
HAC_DIST_CFG_ONLINE_PAYMT,FRONTSTREAM_URL,0
HAC_DIST_CFG_ONLINE_PAYMT,PAYMENT_TYPE_CODE,0
HAC_DIST_CFG_ONLINE_PAYMT,FRONTSTREAM_STATUS_URL,0
HAC_DIST_CFG_ONLINE_PAYMT,FRONTSTREAM_MERCHANT_TOKEN,0
HAC_DIST_CFG_ONLINE_PAYMT,POLL_TASK_OWNER,0
HAC_DIST_CFG_ONLINE_PAYMT,POLL_DAYS,0
HAC_DIST_CFG_ONLINE_PAYMT,POLL_START_TIME,0
HAC_DIST_CFG_ONLINE_PAYMT,POLL_END_TIME,0
HAC_DIST_CFG_ONLINE_PAYMT,POLL_FREQ_MIN,0
HAC_DIST_CFG_ONLINE_PAYMT,KEEP_LOG_DAYS,0
HAC_DIST_CFG_ONLINE_PAYMT,CHANGE_DATE_TIME,0
HAC_DIST_CFG_ONLINE_PAYMT,CHANGE_UID,0
HAC_DIST_CFG_PWD,DISTRICT,1
HAC_DIST_CFG_PWD,USE_ENCRYPTION,0
HAC_DIST_CFG_PWD,HAC_ENCRYPTION_TYPE,0
HAC_DIST_CFG_PWD,PWD_MIN_LIMIT_ENABLED,0
HAC_DIST_CFG_PWD,PWD_MIN_LIMIT,0
HAC_DIST_CFG_PWD,PWD_MAX_LIMIT_ENABLED,0
HAC_DIST_CFG_PWD,PWD_MAX_LIMIT,0
HAC_DIST_CFG_PWD,PWD_COMP_RULE,0
HAC_DIST_CFG_PWD,PWD_CHNG_REQ,0
HAC_DIST_CFG_PWD,PWD_CHNG_REQ_ENABLED,0
HAC_DIST_CFG_PWD,PWD_LK_ACC,0
HAC_DIST_CFG_PWD,PWD_LK_ACC_MODE,0
HAC_DIST_CFG_PWD,PWD_LOCK_TOL_AUTO_TIMES,0
HAC_DIST_CFG_PWD,PWD_LOCK_TOL_AUTO_DUR,0
HAC_DIST_CFG_PWD,PWD_LOCK_TOL_AUTO_TIMES_HOLD,0
HAC_DIST_CFG_PWD,PWD_LOCK_TOL_AUTO_TIMES_LIMIT,0
HAC_DIST_CFG_PWD,PWD_LOCK_TOL_AUTO_TIMES_LIM_DUR,0
HAC_DIST_CFG_PWD,PWD_LOCK_TOL_MAN_ATTEMPT,0
HAC_DIST_CFG_PWD,PWD_LOCK_TOL_MAN_TIMES,0
HAC_DIST_CFG_PWD,PWD_LOCK_TOL_MAN_DUR,0
HAC_DIST_CFG_PWD,CHALLENGE_NO_QUESTIONS,0
HAC_DIST_CFG_PWD,CHALLENGE_ANSWER_QUESTIONS,0
HAC_DIST_CFG_PWD,PWD_UNSUCCESS_MSG,0
HAC_DIST_CFG_PWD,CONFIRMATION_MESSAGE,0
HAC_DIST_CFG_PWD,EMAIL_MESSAGE,0
HAC_DIST_CFG_PWD,CHANGE_DATE_TIME,0
HAC_DIST_CFG_PWD,CHANGE_UID,0
HAC_DIST_CFG_REG_EMAIL,DISTRICT,1
HAC_DIST_CFG_REG_EMAIL,FROM_EMAIL,0
HAC_DIST_CFG_REG_EMAIL,FROM_NAME,0
HAC_DIST_CFG_REG_EMAIL,ALLOW_REPLY_TO,0
HAC_DIST_CFG_REG_EMAIL,REPLY_TO_EMAIL,0
HAC_DIST_CFG_REG_EMAIL,CHANGE_DATE_TIME,0
HAC_DIST_CFG_REG_EMAIL,CHANGE_UID,0
HAC_District_Cfg,DISTRICT,1
HAC_District_Cfg,CONFIG_TYPE,1
HAC_District_Cfg,ENABLE_HAC,0
HAC_District_Cfg,ENABLE_HAC_TRANSLATION,0
HAC_District_Cfg,HAC_TRANS_LANGUAGE,0
HAC_District_Cfg,DISTRICT_LOGO,0
HAC_District_Cfg,ALLOW_REG,0
HAC_District_Cfg,REGISTER_STMT,0
HAC_District_Cfg,CHANGE_PASSWORDS,0
HAC_District_Cfg,PRIVACY_STMT,0
HAC_District_Cfg,TERMS_OF_USE_STMT,0
HAC_District_Cfg,LOGIN_VAL,0
HAC_District_Cfg,SHOW_USERVOICE,0
HAC_District_Cfg,LOGO_HEADER_COLOR,0
HAC_District_Cfg,LOGO_TEXT_COLOR,0
HAC_District_Cfg,HELP_URL,0
HAC_District_Cfg,CHANGE_DATE_TIME,0
HAC_District_Cfg,CHANGE_UID,0
HAC_FAILED_LOGIN_ATTEMPTS,DISTRICT,1
HAC_FAILED_LOGIN_ATTEMPTS,CONTACT_ID,1
HAC_FAILED_LOGIN_ATTEMPTS,FAILURE_DATE_TIME,1
HAC_FAILED_LOGIN_ATTEMPTS,CHANGE_DATE_TIME,0
HAC_FAILED_LOGIN_ATTEMPTS,CHANGE_UID,0
HAC_LINK,DISTRICT,1
HAC_LINK,BUILDING,1
HAC_LINK,LOGIN_TYPE,1
HAC_LINK,SORT_ORDER,1
HAC_LINK,LINK_URL,0
HAC_LINK,LINK_DESCRIPTION,0
HAC_LINK,NEW_UNTIL,0
HAC_LINK,SHOW_IN,0
HAC_LINK,CHANGE_DATE_TIME,0
HAC_LINK,CHANGE_UID,0
HAC_LINK_MACRO,DISTRICT,1
HAC_LINK_MACRO,BUILDING,1
HAC_LINK_MACRO,MACRO_NAME,1
HAC_LINK_MACRO,MACRO_VALUE,0
HAC_LINK_MACRO,CHANGE_DATE_TIME,0
HAC_LINK_MACRO,CHANGE_UID,0
HAC_MENU_LINKED_PAGES,DISTRICT,1
HAC_MENU_LINKED_PAGES,PARENT_CODE,1
HAC_MENU_LINKED_PAGES,CODE,1
HAC_MENU_LINKED_PAGES,DESCRIPTION,0
HAC_MENU_LINKED_PAGES,RESERVED,0
HAC_MENU_LINKED_PAGES,CHANGE_DATE_TIME,0
HAC_MENU_LINKED_PAGES,CHANGE_UID,0
HAC_MENULIST,DISTRICT,1
HAC_MENULIST,CODE,1
HAC_MENULIST,DESCRIPTION,0
HAC_MENULIST,RESERVED,0
HAC_MENULIST,CHANGE_DATE_TIME,0
HAC_MENULIST,CHANGE_UID,0
HAC_OLD_USER,DISTRICT,1
HAC_OLD_USER,STUDENT_ID,1
HAC_OLD_USER,OLD_PASSWORD,1
HAC_OLD_USER,CONTACT_ID,0
HAC_OLD_USER,CHANGE_DATE_TIME,0
HAC_OLD_USER,CHANGE_UID,0
HAC_ONLINE_PAYMENT,DISTRICT,1
HAC_ONLINE_PAYMENT,PAYMENT_ID,1
HAC_ONLINE_PAYMENT,LOGIN_ID,0
HAC_ONLINE_PAYMENT,STUDENT_ID,0
HAC_ONLINE_PAYMENT,BUILDING,0
HAC_ONLINE_PAYMENT,CHANGE_DATE_TIME,0
HAC_ONLINE_PAYMENT,CHANGE_UID,0
HAC_TRANSLATION,DISTRICT,1
HAC_TRANSLATION,LANG,1
HAC_TRANSLATION,PAGE,1
HAC_TRANSLATION,CONTROL_ID,1
HAC_TRANSLATION,ROW_NUM,0
HAC_TRANSLATION,TEXT_TRANSLATION,0
HAC_TRANSLATION,RESERVED,0
HAC_TRANSLATION,CHANGE_DATE_TIME,0
HAC_TRANSLATION,CHANGE_UID,0
IEP_STUDENT_FILES,DISTRICT,1
IEP_STUDENT_FILES,STUDENT_ID,1
IEP_STUDENT_FILES,FILE_TYPE,1
IEP_STUDENT_FILES,FILE_NAME,0
LSM_CFASSOCIATIONS,DISTRICT,1
LSM_CFASSOCIATIONS,IDENTIFIER,1
LSM_CFASSOCIATIONS,ORIGIN_IDENTIFIER,1
LSM_CFASSOCIATIONS,DESTINATION_IDENTIFIER,1
LSM_CFASSOCIATIONS,ASSOCIATION_TYPE,0
LSM_CFASSOCIATIONS,CHANGE_DATE_TIME,0
LSM_CFASSOCIATIONS,CHANGE_UID,0
LSM_CFASSOCIATIONS,DOCUMENT_IDENTIFIER,0
LSM_CFASSOCIATIONS,SEQUENCE_NUM,0
LSM_CFDOCUMENTS,DISTRICT,1
LSM_CFDOCUMENTS,IDENTIFIER,1
LSM_CFDOCUMENTS,TITLE,0
LSM_CFDOCUMENTS,SUBJECT,0
LSM_CFDOCUMENTS,HUMAN_CODING_SCHEME,0
LSM_CFDOCUMENTS,STATUS,0
LSM_CFDOCUMENTS,CHANGE_DATE_TIME,0
LSM_CFDOCUMENTS,CHANGE_UID,0
LSM_CFDOCUMENTS,CREATOR,0
LSM_CFDOCUMENTS,FROM_ESP,0
LSM_CFITEMS,DISTRICT,1
LSM_CFITEMS,IDENTIFIER,1
LSM_CFITEMS,PARENT_IDENTIFIER,0
LSM_CFITEMS,ITEM_TYPE,0
LSM_CFITEMS,HUMAN_CODING_SCHEME,0
LSM_CFITEMS,LIST_ENUMERATION,0
LSM_CFITEMS,GRADE_LEVEL,0
LSM_CFITEMS,FULL_STATEMENT,0
LSM_CFITEMS,ABBREV_STATEMENT,0
LSM_CFITEMS,STATUS,0
LSM_CFITEMS,CHANGE_DATE_TIME,0
LSM_CFITEMS,CHANGE_UID,0
LSM_CFITEMS,SUBJECT,0
LTDB_DASHBOARD,DISTRICT,1
LTDB_DASHBOARD,TEST_CODE,1
LTDB_DASHBOARD,TEST_LEVEL,1
LTDB_DASHBOARD,TEST_FORM,1
LTDB_DASHBOARD,TEST_KEY,0
LTDB_DASHBOARD,TEST_DATE,1
LTDB_DASHBOARD,SUBTEST,1
LTDB_DASHBOARD,SCORE_CODE,1
LTDB_DASHBOARD,SCORE_TOTAL,0
LTDB_DASHBOARD,NUMBER_SCORES,0
LTDB_DASHBOARD,RANGE1_COUNT,0
LTDB_DASHBOARD,RANGE2_COUNT,0
LTDB_DASHBOARD,RANGE3_COUNT,0
ltdb_group_det,DISTRICT,1
ltdb_group_det,SCHOOL_YEAR,1
ltdb_group_det,GROUP_CODE,1
ltdb_group_det,SECTION_KEY,1
ltdb_group_det,MARKING_PERIOD,0
ltdb_group_det,MARK_TYPE,0
ltdb_group_det,ACTIVE,0
ltdb_group_det,CHANGE_DATE_TIME,0
ltdb_group_det,CHANGE_UID,0
ltdb_group_hdr,DISTRICT,1
ltdb_group_hdr,SCHOOL_YEAR,1
ltdb_group_hdr,GROUP_CODE,1
ltdb_group_hdr,DESCRIPTION,0
ltdb_group_hdr,ACTIVE,0
ltdb_group_hdr,CHANGE_DATE_TIME,0
ltdb_group_hdr,CHANGE_UID,0
LTDB_IMPORT_DEF,district,1
LTDB_IMPORT_DEF,interface_id,1
LTDB_IMPORT_DEF,description,0
LTDB_IMPORT_DEF,change_date_time,0
LTDB_IMPORT_DEF,change_uid,0
LTDB_IMPORT_DET,DISTRICT,1
LTDB_IMPORT_DET,INTERFACE_ID,1
LTDB_IMPORT_DET,TEST_CODE,0
LTDB_IMPORT_DET,TEST_LEVEL,0
LTDB_IMPORT_DET,TEST_FORM,0
LTDB_IMPORT_DET,TEST_KEY,1
LTDB_IMPORT_DET,FIELD_ID,1
LTDB_IMPORT_DET,FIELD_ORDER,0
LTDB_IMPORT_DET,TABLE_NAME,0
LTDB_IMPORT_DET,COLUMN_NAME,0
LTDB_IMPORT_DET,SUBTEST,0
LTDB_IMPORT_DET,SCORE_CODE,0
LTDB_IMPORT_DET,FORMAT_STRING,0
LTDB_IMPORT_DET,START_POSITION,0
LTDB_IMPORT_DET,END_POSITION,0
LTDB_IMPORT_DET,MAP_FIELD,0
LTDB_IMPORT_DET,MAP_SCORE,0
LTDB_IMPORT_DET,FIELD_LENGTH,0
LTDB_IMPORT_DET,VALIDATION_TABLE,0
LTDB_IMPORT_DET,CODE_COLUMN,0
LTDB_IMPORT_DET,VALIDATION_LIST,0
LTDB_IMPORT_DET,ERROR_MESSAGE,0
LTDB_IMPORT_DET,EXTERNAL_TABLE,0
LTDB_IMPORT_DET,EXTERNAL_COL_IN,0
LTDB_IMPORT_DET,EXTERNAL_COL_OUT,0
LTDB_IMPORT_DET,LITERAL,0
LTDB_IMPORT_DET,SKIP_BLANK_VALUES,0
LTDB_IMPORT_DET,SKIP_SPECIFIC_VALUES,0
LTDB_IMPORT_DET,CHANGE_DATE_TIME,0
LTDB_IMPORT_DET,CHANGE_UID,0
LTDB_IMPORT_HDR,district,1
LTDB_IMPORT_HDR,interface_id,1
LTDB_IMPORT_HDR,description,0
LTDB_IMPORT_HDR,test_code,0
LTDB_IMPORT_HDR,test_level,0
LTDB_IMPORT_HDR,test_form,0
LTDB_IMPORT_HDR,test_key,1
LTDB_IMPORT_HDR,filename,0
LTDB_IMPORT_HDR,last_run_date,0
LTDB_IMPORT_HDR,delimit_char,0
LTDB_IMPORT_HDR,additional_sql,0
LTDB_IMPORT_HDR,change_date_time,0
LTDB_IMPORT_HDR,change_uid,0
LTDB_IMPORT_TRN,district,1
LTDB_IMPORT_TRN,interface_id,1
LTDB_IMPORT_TRN,description,0
LTDB_IMPORT_TRN,test_code,0
LTDB_IMPORT_TRN,test_level,0
LTDB_IMPORT_TRN,test_form,0
LTDB_IMPORT_TRN,test_key,1
LTDB_IMPORT_TRN,field_id,1
LTDB_IMPORT_TRN,translation_id,1
LTDB_IMPORT_TRN,old_value,0
LTDB_IMPORT_TRN,new_value,0
LTDB_IMPORT_TRN,change_date_time,0
LTDB_IMPORT_TRN,change_uid,0
LTDB_INTERFACE_DEF,DISTRICT,1
LTDB_INTERFACE_DEF,INTERFACE_ID,1
LTDB_INTERFACE_DEF,DESCRIPTION,0
LTDB_INTERFACE_DEF,UPLOAD_DOWNLOAD,0
LTDB_INTERFACE_DEF,CHANGE_DATE_TIME,0
LTDB_INTERFACE_DEF,CHANGE_UID,0
LTDB_INTERFACE_DET,DISTRICT,1
LTDB_INTERFACE_DET,INTERFACE_ID,1
LTDB_INTERFACE_DET,HEADER_ID,1
LTDB_INTERFACE_DET,FIELD_ID,1
LTDB_INTERFACE_DET,FIELD_ORDER,0
LTDB_INTERFACE_DET,TABLE_NAME,0
LTDB_INTERFACE_DET,TABLE_ALIAS,0
LTDB_INTERFACE_DET,COLUMN_NAME,0
LTDB_INTERFACE_DET,SCREEN_TYPE,0
LTDB_INTERFACE_DET,SCREEN_NUMBER,0
LTDB_INTERFACE_DET,FORMAT_STRING,0
LTDB_INTERFACE_DET,START_POSITION,0
LTDB_INTERFACE_DET,END_POSITION,0
LTDB_INTERFACE_DET,FIELD_LENGTH,0
LTDB_INTERFACE_DET,VALIDATION_TABLE,0
LTDB_INTERFACE_DET,CODE_COLUMN,0
LTDB_INTERFACE_DET,VALIDATION_LIST,0
LTDB_INTERFACE_DET,ERROR_MESSAGE,0
LTDB_INTERFACE_DET,EXTERNAL_TABLE,0
LTDB_INTERFACE_DET,EXTERNAL_COL_IN,0
LTDB_INTERFACE_DET,EXTERNAL_COL_OUT,0
LTDB_INTERFACE_DET,LITERAL,0
LTDB_INTERFACE_DET,COLUMN_OVERRIDE,0
LTDB_INTERFACE_DET,CHANGE_DATE_TIME,0
LTDB_INTERFACE_DET,CHANGE_UID,0
LTDB_INTERFACE_HDR,DISTRICT,1
LTDB_INTERFACE_HDR,INTERFACE_ID,1
LTDB_INTERFACE_HDR,HEADER_ID,1
LTDB_INTERFACE_HDR,HEADER_ORDER,0
LTDB_INTERFACE_HDR,DESCRIPTION,0
LTDB_INTERFACE_HDR,FILENAME,0
LTDB_INTERFACE_HDR,LAST_RUN_DATE,0
LTDB_INTERFACE_HDR,DELIMIT_CHAR,0
LTDB_INTERFACE_HDR,USE_CHANGE_FLAG,0
LTDB_INTERFACE_HDR,TABLE_AFFECTED,0
LTDB_INTERFACE_HDR,ADDITIONAL_SQL,0
LTDB_INTERFACE_HDR,COLUMN_HEADERS,0
LTDB_INTERFACE_HDR,CHANGE_DATE_TIME,0
LTDB_INTERFACE_HDR,CHANGE_UID,0
LTDB_INTERFACE_STU,DISTRICT,1
LTDB_INTERFACE_STU,INTERFACE_ID,1
LTDB_INTERFACE_STU,STUDENT_ID,1
LTDB_INTERFACE_STU,DATE_ADDED,0
LTDB_INTERFACE_STU,DATE_DELETED,0
LTDB_INTERFACE_STU,DATE_CHANGED,0
LTDB_INTERFACE_STU,CHANGE_DATE_TIME,0
LTDB_INTERFACE_STU,CHANGE_UID,0
LTDB_INTERFACE_TRN,DISTRICT,1
LTDB_INTERFACE_TRN,INTERFACE_ID,1
LTDB_INTERFACE_TRN,HEADER_ID,1
LTDB_INTERFACE_TRN,FIELD_ID,1
LTDB_INTERFACE_TRN,TRANSLATION_ID,1
LTDB_INTERFACE_TRN,OLD_VALUE,0
LTDB_INTERFACE_TRN,NEW_VALUE,0
LTDB_INTERFACE_TRN,CHANGE_DATE_TIME,0
LTDB_INTERFACE_TRN,CHANGE_UID,0
LTDB_SCORE_HAC,DISTRICT,1
LTDB_SCORE_HAC,TEST_CODE,1
LTDB_SCORE_HAC,TEST_LEVEL,1
LTDB_SCORE_HAC,TEST_FORM,1
LTDB_SCORE_HAC,TEST_KEY,0
LTDB_SCORE_HAC,SUBTEST,1
LTDB_SCORE_HAC,SCORE_CODE,1
LTDB_SCORE_HAC,DISPLAY_PARENT,0
LTDB_SCORE_HAC,DISPLAY_STUDENT,0
LTDB_SCORE_HAC,CHANGE_DATE_TIME,0
LTDB_SCORE_HAC,CHANGE_UID,0
LTDB_STU_AT_RISK,DISTRICT,1
LTDB_STU_AT_RISK,TEST_CODE,1
LTDB_STU_AT_RISK,TEST_LEVEL,1
LTDB_STU_AT_RISK,TEST_FORM,1
LTDB_STU_AT_RISK,TEST_KEY,0
LTDB_STU_AT_RISK,STUDENT_ID,1
LTDB_STU_AT_RISK,TEST_DATE,1
LTDB_STU_AT_RISK,SUBTEST,1
LTDB_STU_AT_RISK,SCORE_CODE,1
LTDB_STU_AT_RISK,SCORE,0
LTDB_STU_AT_RISK,QUALIFICATION,0
LTDB_STU_AT_RISK,QUAL_REASON,0
LTDB_STU_AT_RISK,TEST_CODE2,0
LTDB_STU_AT_RISK,TEST_LEVEL2,0
LTDB_STU_AT_RISK,TEST_FORM2,0
LTDB_STU_AT_RISK,TEST_KEY2,0
LTDB_STU_AT_RISK,TEST_DATE2,0
LTDB_STU_AT_RISK,SUBTEST2,0
LTDB_STU_AT_RISK,SCORE_CODE2,0
LTDB_STU_AT_RISK,SCORE2,0
LTDB_STU_AT_RISK,BUILDING,0
LTDB_STU_AT_RISK,GRADE,0
LTDB_STU_AT_RISK,AT_RISK,0
LTDB_STU_AT_RISK,START_DATE,0
LTDB_STU_AT_RISK,END_DATE,0
LTDB_STU_AT_RISK,PLAN_NUM,0
LTDB_STU_AT_RISK,PLAN_DATE,0
LTDB_STU_AT_RISK,CHANGE_DATE_TIME,0
LTDB_STU_AT_RISK,CHANGE_UID,0
LTDB_STU_SUBTEST,DISTRICT,1
LTDB_STU_SUBTEST,TEST_CODE,1
LTDB_STU_SUBTEST,TEST_LEVEL,1
LTDB_STU_SUBTEST,TEST_FORM,1
LTDB_STU_SUBTEST,TEST_KEY,0
LTDB_STU_SUBTEST,STUDENT_ID,1
LTDB_STU_SUBTEST,TEST_DATE,1
LTDB_STU_SUBTEST,SUBTEST,1
LTDB_STU_SUBTEST,SCORE_CODE,1
LTDB_STU_SUBTEST,SCORE,0
LTDB_STU_SUBTEST,CHANGE_DATE_TIME,0
LTDB_STU_SUBTEST,CHANGE_UID,0
LTDB_STU_TEST,DISTRICT,1
LTDB_STU_TEST,TEST_CODE,1
LTDB_STU_TEST,TEST_LEVEL,1
LTDB_STU_TEST,TEST_FORM,1
LTDB_STU_TEST,TEST_KEY,0
LTDB_STU_TEST,STUDENT_ID,1
LTDB_STU_TEST,TEST_DATE,1
LTDB_STU_TEST,TRANSCRIPT_PRINT,0
LTDB_STU_TEST,BUILDING,0
LTDB_STU_TEST,GRADE,0
LTDB_STU_TEST,AGE,0
LTDB_STU_TEST,CHANGE_DATE_TIME,0
LTDB_STU_TEST,CHANGE_UID,0
LTDB_STU_TRACKING,DISTRICT,1
LTDB_STU_TRACKING,TEST_CODE,1
LTDB_STU_TRACKING,TEST_LEVEL,1
LTDB_STU_TRACKING,TEST_FORM,1
LTDB_STU_TRACKING,TEST_KEY,0
LTDB_STU_TRACKING,FIELD_NUMBER,1
LTDB_STU_TRACKING,FIELD_ORDER,0
LTDB_STU_TRACKING,SOURCE,0
LTDB_STU_TRACKING,PROGRAM_FIELD,0
LTDB_STU_TRACKING,EXTERNAL_CODE,0
LTDB_STU_TRACKING,FIELD_LABEL,0
LTDB_STU_TRACKING,CHANGE_DATE_TIME,0
LTDB_STU_TRACKING,CHANGE_UID,0
LTDB_STU_TRK_DATA,DISTRICT,1
LTDB_STU_TRK_DATA,TEST_CODE,1
LTDB_STU_TRK_DATA,TEST_LEVEL,1
LTDB_STU_TRK_DATA,TEST_FORM,1
LTDB_STU_TRK_DATA,TEST_KEY,0
LTDB_STU_TRK_DATA,STUDENT_ID,1
LTDB_STU_TRK_DATA,TEST_DATE,1
LTDB_STU_TRK_DATA,FIELD_NUMBER,1
LTDB_STU_TRK_DATA,FIELD_VALUE,0
LTDB_STU_TRK_DATA,CHANGE_DATE_TIME,0
LTDB_STU_TRK_DATA,CHANGE_UID,0
LTDB_SUBTEST,DISTRICT,1
LTDB_SUBTEST,TEST_CODE,1
LTDB_SUBTEST,TEST_LEVEL,1
LTDB_SUBTEST,TEST_FORM,1
LTDB_SUBTEST,TEST_KEY,0
LTDB_SUBTEST,SUBTEST,1
LTDB_SUBTEST,DESCRIPTION,0
LTDB_SUBTEST,SUBTEST_ORDER,0
LTDB_SUBTEST,DISPLAY,0
LTDB_SUBTEST,STATE_CODE_EQUIV,0
LTDB_SUBTEST,PESC_CODE,0
LTDB_SUBTEST,CHANGE_DATE_TIME,0
LTDB_SUBTEST,CHANGE_UID,0
LTDB_SUBTEST_HAC,DISTRICT,1
LTDB_SUBTEST_HAC,TEST_CODE,1
LTDB_SUBTEST_HAC,TEST_LEVEL,1
LTDB_SUBTEST_HAC,TEST_FORM,1
LTDB_SUBTEST_HAC,TEST_KEY,0
LTDB_SUBTEST_HAC,SUBTEST,1
LTDB_SUBTEST_HAC,DISPLAY_PARENT,0
LTDB_SUBTEST_HAC,DISPLAY_STUDENT,0
LTDB_SUBTEST_HAC,CHANGE_DATE_TIME,0
LTDB_SUBTEST_HAC,CHANGE_UID,0
LTDB_SUBTEST_SCORE,DISTRICT,1
LTDB_SUBTEST_SCORE,TEST_CODE,1
LTDB_SUBTEST_SCORE,TEST_LEVEL,1
LTDB_SUBTEST_SCORE,TEST_FORM,1
LTDB_SUBTEST_SCORE,TEST_KEY,0
LTDB_SUBTEST_SCORE,SUBTEST,1
LTDB_SUBTEST_SCORE,SCORE_CODE,1
LTDB_SUBTEST_SCORE,SCORE_ORDER,0
LTDB_SUBTEST_SCORE,SCORE_LABEL,0
LTDB_SUBTEST_SCORE,REQUIRED,0
LTDB_SUBTEST_SCORE,FIELD_TYPE,0
LTDB_SUBTEST_SCORE,DATA_TYPE,0
LTDB_SUBTEST_SCORE,NUMBER_TYPE,0
LTDB_SUBTEST_SCORE,DATA_LENGTH,0
LTDB_SUBTEST_SCORE,FIELD_SCALE,0
LTDB_SUBTEST_SCORE,FIELD_PRECISION,0
LTDB_SUBTEST_SCORE,DEFAULT_VALUE,0
LTDB_SUBTEST_SCORE,VALIDATION_LIST,0
LTDB_SUBTEST_SCORE,VALIDATION_TABLE,0
LTDB_SUBTEST_SCORE,CODE_COLUMN,0
LTDB_SUBTEST_SCORE,DESCRIPTION_COLUMN,0
LTDB_SUBTEST_SCORE,DISPLAY,0
LTDB_SUBTEST_SCORE,INCLUDE_DASHBOARD,0
LTDB_SUBTEST_SCORE,MONTHS_TO_INCLUDE,0
LTDB_SUBTEST_SCORE,RANGE1_HIGH_LIMIT,0
LTDB_SUBTEST_SCORE,RANGE2_HIGH_LIMIT,0
LTDB_SUBTEST_SCORE,STATE_CODE_EQUIV,0
LTDB_SUBTEST_SCORE,SCORE_TYPE,0
LTDB_SUBTEST_SCORE,PERFPLUS_GROUP,0
LTDB_SUBTEST_SCORE,PESC_CODE,0
LTDB_SUBTEST_SCORE,CHANGE_DATE_TIME,0
LTDB_SUBTEST_SCORE,CHANGE_UID,0
LTDB_TEST,DISTRICT,1
LTDB_TEST,TEST_CODE,1
LTDB_TEST,TEST_LEVEL,1
LTDB_TEST,TEST_FORM,1
LTDB_TEST,TEST_KEY,0
LTDB_TEST,DESCRIPTION,0
LTDB_TEST,DISPLAY,0
LTDB_TEST,SEC_PACKAGE,0
LTDB_TEST,SEC_SUBPACKAGE,0
LTDB_TEST,SEC_FEATURE,0
LTDB_TEST,TEACHER_DISPLAY,0
LTDB_TEST,SUB_DISPLAY,0
LTDB_TEST,INCLUDE_PERFPLUS,0
LTDB_TEST,PESC_CODE,0
LTDB_TEST,CHANGE_DATE_TIME,0
LTDB_TEST,CHANGE_UID,0
LTDB_TEST_BUILDING,DISTRICT,1
LTDB_TEST_BUILDING,TEST_CODE,1
LTDB_TEST_BUILDING,TEST_LEVEL,1
LTDB_TEST_BUILDING,TEST_FORM,1
LTDB_TEST_BUILDING,TEST_KEY,0
LTDB_TEST_BUILDING,BUILDING,1
LTDB_TEST_BUILDING,CHANGE_DATE_TIME,0
LTDB_TEST_BUILDING,CHANGE_UID,0
LTDB_TEST_HAC,DISTRICT,1
LTDB_TEST_HAC,TEST_CODE,1
LTDB_TEST_HAC,TEST_LEVEL,1
LTDB_TEST_HAC,TEST_FORM,1
LTDB_TEST_HAC,TEST_KEY,0
LTDB_TEST_HAC,DISPLAY_PARENT,0
LTDB_TEST_HAC,DISPLAY_STUDENT,0
LTDB_TEST_HAC,CHANGE_DATE_TIME,0
LTDB_TEST_HAC,CHANGE_UID,0
LTDB_TEST_TRACKING,DISTRICT,1
LTDB_TEST_TRACKING,TEST_CODE,1
LTDB_TEST_TRACKING,TEST_LEVEL,1
LTDB_TEST_TRACKING,TEST_FORM,1
LTDB_TEST_TRACKING,TEST_KEY,0
LTDB_TEST_TRACKING,FIELD_NUMBER,1
LTDB_TEST_TRACKING,FIELD_ORDER,0
LTDB_TEST_TRACKING,FIELD_LABEL,0
LTDB_TEST_TRACKING,FIELD_DATA,0
LTDB_TEST_TRACKING,CHANGE_DATE_TIME,0
LTDB_TEST_TRACKING,CHANGE_UID,0
LTDB_USER_TEST,DISTRICT,1
LTDB_USER_TEST,TEST_CODE,1
LTDB_USER_TEST,TEST_LEVEL,1
LTDB_USER_TEST,TEST_FORM,1
LTDB_USER_TEST,TEST_KEY,0
LTDB_USER_TEST,SCREEN_NUMBER,1
LTDB_USER_TEST,FIELD_NUMBER,1
LTDB_USER_TEST,LIST_SEQUENCE,1
LTDB_USER_TEST,FIELD_VALUE,0
LTDB_USER_TEST,CHANGE_DATE_TIME,0
LTDB_USER_TEST,CHANGE_UID,0
LTDB_VIEW_DET,DISTRICT,1
LTDB_VIEW_DET,VIEW_CODE,1
LTDB_VIEW_DET,TEST_CODE,1
LTDB_VIEW_DET,TEST_LEVEL,1
LTDB_VIEW_DET,TEST_FORM,1
LTDB_VIEW_DET,TEST_KEY,1
LTDB_VIEW_DET,SUBTEST,1
LTDB_VIEW_DET,SCORE_CODE,1
LTDB_VIEW_DET,SCORE_ORDER,0
LTDB_VIEW_DET,SCORE_LABEL,0
LTDB_VIEW_DET,SCORE_SELECT,0
LTDB_VIEW_DET,RANGE1_HIGH_LIMIT,0
LTDB_VIEW_DET,RANGE2_HIGH_LIMIT,0
LTDB_VIEW_DET,CHANGE_DATE_TIME,0
LTDB_VIEW_DET,CHANGE_UID,0
LTDB_VIEW_HDR,DISTRICT,1
LTDB_VIEW_HDR,VIEW_CODE,1
LTDB_VIEW_HDR,DESCRIPTION,0
LTDB_VIEW_HDR,CHANGE_DATE_TIME,0
LTDB_VIEW_HDR,CHANGE_UID,0
LTDB_YEAREND_RUN,DISTRICT,1
LTDB_YEAREND_RUN,SCHOOL_YEAR,1
LTDB_YEAREND_RUN,RUN_KEY,1
LTDB_YEAREND_RUN,RUN_DATE,0
LTDB_YEAREND_RUN,RUN_STATUS,0
LTDB_YEAREND_RUN,CLEAN_LTDB_DATA,0
LTDB_YEAREND_RUN,PURGE_STU_YEAR,0
LTDB_YEAREND_RUN,RESTORE_KEY,0
LTDB_YEAREND_RUN,CHANGE_DATE_TIME,0
LTDB_YEAREND_RUN,CHANGE_UID,0
LTDBTB_SCORE_PESC_CODE,DISTRICT,1
LTDBTB_SCORE_PESC_CODE,CODE,1
LTDBTB_SCORE_PESC_CODE,DESCRIPTION,0
LTDBTB_SCORE_PESC_CODE,STATE_CODE_EQUIV,0
LTDBTB_SCORE_PESC_CODE,ACTIVE,0
LTDBTB_SCORE_PESC_CODE,CHANGE_DATE_TIME,0
LTDBTB_SCORE_PESC_CODE,CHANGE_UID,0
LTDBTB_SCORE_TYPE,DISTRICT,1
LTDBTB_SCORE_TYPE,CODE,1
LTDBTB_SCORE_TYPE,DESCRIPTION,0
LTDBTB_SCORE_TYPE,STATE_CODE_EQUIV,0
LTDBTB_SCORE_TYPE,ACTIVE,0
LTDBTB_SCORE_TYPE,CHANGE_DATE_TIME,0
LTDBTB_SCORE_TYPE,CHANGE_UID,0
LTDBTB_SUBTEST_PESC_CODE,DISTRICT,1
LTDBTB_SUBTEST_PESC_CODE,CODE,1
LTDBTB_SUBTEST_PESC_CODE,DESCRIPTION,0
LTDBTB_SUBTEST_PESC_CODE,STATE_CODE_EQUIV,0
LTDBTB_SUBTEST_PESC_CODE,ACTIVE,0
LTDBTB_SUBTEST_PESC_CODE,CHANGE_DATE_TIME,0
LTDBTB_SUBTEST_PESC_CODE,CHANGE_UID,0
LTDBTB_TEST_PESC_CODE,DISTRICT,1
LTDBTB_TEST_PESC_CODE,CODE,1
LTDBTB_TEST_PESC_CODE,DESCRIPTION,0
LTDBTB_TEST_PESC_CODE,STATE_CODE_EQUIV,0
LTDBTB_TEST_PESC_CODE,ACTIVE,0
LTDBTB_TEST_PESC_CODE,CHANGE_DATE_TIME,0
LTDBTB_TEST_PESC_CODE,CHANGE_UID,0
LTI_CLIENT,DISTRICT,1
LTI_CLIENT,CLIENT_CODE,1
LTI_CLIENT,CHANGE_DATE_TIME,0
LTI_CLIENT,CHANGE_UID,0
LTI_CLIENT,DESCRIPTION,0
LTI_CLIENT,ACTIVE,0
LTI_CLIENT_TOOL,DISTRICT,1
LTI_CLIENT_TOOL,CLIENT_CODE,1
LTI_CLIENT_TOOL,TOOL_ID,1
LTI_CLIENT_TOOL,CHANGE_DATE_TIME,0
LTI_CLIENT_TOOL,CHANGE_UID,0
LTI_CLIENT_TOOL,ACTIVE,0
LTI_NONCE_LOG,ID,1
LTI_NONCE_LOG,CONSUMER_KEY,0
LTI_NONCE_LOG,NONCE,0
LTI_NONCE_LOG,CHANGE_DATE_TIME,0
LTI_TOOL,DISTRICT,1
LTI_TOOL,TOOL_ID,1
LTI_TOOL,CHANGE_DATE_TIME,0
LTI_TOOL,CHANGE_UID,0
LTI_TOOL,DESCRIPTION,0
LTI_TOOL,API_SCOPE,0
LTI_TOOL,APP_URL,0
MED_CFG,DISTRICT,1
MED_CFG,BUILDING,1
MED_CFG,AUTO_CREATE,0
MED_CFG,CALL_MAINT,0
MED_CFG,RESET_COUNT,0
MED_CFG,PRT_LTR_MER_FILE,0
MED_CFG,OTHER_LANGUAGE,0
MED_CFG,USER_SCREEN,0
MED_CFG,MED_SCREEN,0
MED_CFG,USE_MONTH_YEAR,0
MED_CFG,USE_WARNING_STATUS,0
MED_CFG,PRIOR_DAYS_UPDATE,0
MED_CFG,ALLOW_NOTES_UPDATE,0
MED_CFG,EXAM_PRI_DAYS_UPD,0
MED_CFG,USE_LAST,0
MED_CFG,NOTIFY_DWNLD_PATH,0
MED_CFG,EMAIL_OPTION,0
MED_CFG,RETURN_EMAIL,0
MED_CFG,USE_HOME_ROOM,0
MED_CFG,USE_OUTCOME,0
MED_CFG,VALID_NURSE_INIT,0
MED_CFG,INIT_OTH_NURSE_LOG,0
MED_CFG,USE_VALIDATE_SAVE,0
MED_CFG,DEFAULT_TO_SAVE,0
MED_CFG,USE_IMMUN_ALERTS,0
MED_CFG,IMM_GRACE_PERIOD,0
MED_CFG,GRACE_ENTRY_DATE,0
MED_CFG,CLEAR_EXP_DATE,0
MED_CFG,IMM_PARENT_ALERTS,0
MED_CFG,IMM_INT_EMAILS,0
MED_CFG,SUBJECT_LINE,0
MED_CFG,FROM_EMAIL,0
MED_CFG,HEADER_TEXT,0
MED_CFG,FOOTER_TEXT,0
MED_CFG,DEFAULT_MARGIN_ERR,0
MED_CFG,CHANGE_DATE_TIME,0
MED_CFG,CHANGE_UID,0
MED_CFG_LANG,DISTRICT,1
MED_CFG_LANG,BUILDING,1
MED_CFG_LANG,LANGUAGE_CODE,1
MED_CFG_LANG,CHANGE_DATE_TIME,0
MED_CFG_LANG,CHANGE_UID,0
MED_CUSTOM_EXAM_COLUMN,COLUMN_ID,1
MED_CUSTOM_EXAM_COLUMN,EXAM_TYPE_ID,0
MED_CUSTOM_EXAM_COLUMN,COLUMN_NAME,0
MED_CUSTOM_EXAM_COLUMN,COLUMN_ORDER,0
MED_CUSTOM_EXAM_COLUMN,IS_BASE,0
MED_CUSTOM_EXAM_ELEMENT,FIELD_ID,1
MED_CUSTOM_EXAM_ELEMENT,DISTRICT,0
MED_CUSTOM_EXAM_ELEMENT,EXAM_ID,0
MED_CUSTOM_EXAM_ELEMENT,COLUMN_ID,0
MED_CUSTOM_EXAM_ELEMENT,COLUMN_VALUE,0
MED_CUSTOM_EXAM_KEY,EXAM_ID,1
MED_CUSTOM_EXAM_KEY,DISTRICT,0
MED_CUSTOM_EXAM_KEY,STUDENT_ID,0
MED_CUSTOM_EXAM_KEY,EXAM_TYPE_ID,0
MED_CUSTOM_EXAM_KEY,TEST_DATE,0
MED_CUSTOM_EXAM_KEY,CHANGE_DATE_TIME,0
MED_CUSTOM_EXAM_KEY,CHANGE_UID,0
MED_CUSTOM_EXAM_TYPE,EXAM_TYPE_ID,1
MED_CUSTOM_EXAM_TYPE,EXAM_SYMBOL,0
MED_CUSTOM_EXAM_TYPE,DESCRIPTION,0
MED_DENTAL,DISTRICT,1
MED_DENTAL,STUDENT_ID,1
MED_DENTAL,TEST_DATE,1
MED_DENTAL,GRADE,0
MED_DENTAL,LOCATION,0
MED_DENTAL,STATUS,0
MED_DENTAL,INITIALS,0
MED_DENTAL,ROW_IDENTITY,0
MED_DENTAL,CHANGE_DATE_TIME,0
MED_DENTAL,CHANGE_UID,0
MED_DENTAL_COLS,DISTRICT,1
MED_DENTAL_COLS,STUDENT_ID,1
MED_DENTAL_COLS,TEST_DATE,1
MED_DENTAL_COLS,DENTAL_SEALANTS,0
MED_DENTAL_COLS,CARIES_EXP,0
MED_DENTAL_COLS,UNTREATED_CARIES,0
MED_DENTAL_COLS,CHANGE_DATE_TIME,0
MED_DENTAL_COLS,CHANGE_UID,0
MED_DISTRICT_CFG,DISTRICT,1
MED_DISTRICT_CFG,USE_GRACE_PERIOD,0
MED_DISTRICT_CFG,YEAR_START_DATE,0
MED_DISTRICT_CFG,USE_REG_DATE,0
MED_DISTRICT_CFG,GRACE_PROC_TYPE,0
MED_DISTRICT_CFG,GRACE_CALENDAR,0
MED_DISTRICT_CFG,CHANGE_DATE_TIME,0
MED_DISTRICT_CFG,CHANGE_UID,0
MED_GENERAL,DISTRICT,1
MED_GENERAL,STUDENT_ID,1
MED_GENERAL,IMMUNE_STATUS,0
MED_GENERAL,IMMUNE_EXEMPT,0
MED_GENERAL,CALC_DATE,0
MED_GENERAL,OVERRIDE,0
MED_GENERAL,GROUP_CODE,0
MED_GENERAL,GRACE_PERIOD_DATE,0
MED_GENERAL,COMMENT,0
MED_GENERAL,IMM_ALERT,0
MED_GENERAL,ALERT_END_DATE,0
MED_GENERAL,ALERT_OVERRIDE,0
MED_GENERAL,CHANGE_DATE_TIME,0
MED_GENERAL,CHANGE_UID,0
MED_GRACE_SCHD,DISTRICT,1
MED_GRACE_SCHD,SERIES_SCHD,1
MED_GRACE_SCHD,YEAR_IN_DISTRICT,1
MED_GRACE_SCHD,UP_TO_DAY,1
MED_GRACE_SCHD,MIN_DOSES,0
MED_GRACE_SCHD,CHANGE_DATE_TIME,0
MED_GRACE_SCHD,CHANGE_UID,0
MED_GROWTH,DISTRICT,1
MED_GROWTH,STUDENT_ID,1
MED_GROWTH,TEST_DATE,1
MED_GROWTH,GRADE,0
MED_GROWTH,LOCATION,0
MED_GROWTH,HEIGHT,0
MED_GROWTH,PERCENT_HEIGHT,0
MED_GROWTH,WEIGHT,0
MED_GROWTH,PERCENT_WEIGHT,0
MED_GROWTH,BMI,0
MED_GROWTH,PERCENT_BMI,0
MED_GROWTH,AN_READING,0
MED_GROWTH,BLOOD_PRESSURE_DIA,0
MED_GROWTH,BLOOD_PRESSURE_SYS_AN,0
MED_GROWTH,BLOOD_PRESSURE_DIA_AN,0
MED_GROWTH,BLOOD_PRESSURE_SYS,0
MED_GROWTH,INITIALS,0
MED_GROWTH,ROW_IDENTITY,0
MED_GROWTH,CHANGE_DATE_TIME,0
MED_GROWTH,CHANGE_UID,0
MED_GROWTH_ARK,DISTRICT,1
MED_GROWTH_ARK,STUDENT_ID,1
MED_GROWTH_ARK,TEST_DATE,1
MED_GROWTH_ARK,REASON_NOT_ACCESSED,0
MED_GROWTH_ARK,CHANGE_DATE_TIME,0
MED_GROWTH_ARK,CHANGE_UID,0
MED_GROWTH_BMI_ARK,DISTRICT,1
MED_GROWTH_BMI_ARK,STUDENT_ID,1
MED_GROWTH_BMI_ARK,TEST_DATE,1
MED_GROWTH_BMI_ARK,BMI,0
MED_GROWTH_BMI_ARK,CHANGE_DATE_TIME,0
MED_GROWTH_BMI_ARK,CHANGE_UID,0
MED_HEARING,DISTRICT,1
MED_HEARING,STUDENT_ID,1
MED_HEARING,TEST_DATE,1
MED_HEARING,GRADE,0
MED_HEARING,LOCATION,0
MED_HEARING,RIGHT_EAR,0
MED_HEARING,LEFT_EAR,0
MED_HEARING,INITIALS,0
MED_HEARING,ROW_IDENTITY,0
MED_HEARING,CHANGE_DATE_TIME,0
MED_HEARING,CHANGE_UID,0
MED_HEARING_COLS,DISTRICT,1
MED_HEARING_COLS,STUDENT_ID,1
MED_HEARING_COLS,TEST_DATE,1
MED_HEARING_COLS,SCREENING_TYPE,0
MED_HEARING_COLS,KNOWN_CASE,0
MED_HEARING_COLS,CHANGE_DATE_TIME,0
MED_HEARING_COLS,CHANGE_UID,0
MED_HEARING_DET,DISTRICT,1
MED_HEARING_DET,STUDENT_ID,1
MED_HEARING_DET,TEST_DATE,1
MED_HEARING_DET,DECIBEL,1
MED_HEARING_DET,FREQUENCY,1
MED_HEARING_DET,RIGHT_EAR,0
MED_HEARING_DET,LEFT_EAR,0
MED_HEARING_DET,CHANGE_DATE_TIME,0
MED_HEARING_DET,CHANGE_UID,0
MED_IMM_CRIT,DISTRICT,1
MED_IMM_CRIT,CRITERIA_NUMBER,1
MED_IMM_CRIT,DESCRIPTION,0
MED_IMM_CRIT,MAX_LETTERS,0
MED_IMM_CRIT,CHANGE_DATE_TIME,0
MED_IMM_CRIT,CHANGE_UID,0
MED_IMM_CRIT_GRP,DISTRICT,1
MED_IMM_CRIT_GRP,CRITERIA_NUMBER,1
MED_IMM_CRIT_GRP,SEQUENCE_NUM,1
MED_IMM_CRIT_GRP,GROUP_TYPE,0
MED_IMM_CRIT_GRP,GROUP_MIN,0
MED_IMM_CRIT_GRP,GROUP_MAX,0
MED_IMM_CRIT_GRP,CHANGE_DATE_TIME,0
MED_IMM_CRIT_GRP,CHANGE_UID,0
MED_IMM_CRIT_SHOTS,DISTRICT,1
MED_IMM_CRIT_SHOTS,CRITERIA_NUMBER,1
MED_IMM_CRIT_SHOTS,SERIES_CODE,1
MED_IMM_CRIT_SHOTS,SERIES_CODE_ORDER,1
MED_IMM_CRIT_SHOTS,SERIES_SCHEDULE,0
MED_IMM_CRIT_SHOTS,CHANGE_DATE_TIME,0
MED_IMM_CRIT_SHOTS,CHANGE_UID,0
MED_ISSUED,DISTRICT,1
MED_ISSUED,STUDENT_ID,1
MED_ISSUED,ISSUED,1
MED_ISSUED,MED_CODE,1
MED_ISSUED,DOSE_NUMBER,1
MED_ISSUED,EVENT_TYPE,0
MED_ISSUED,COMMENT,0
MED_ISSUED,INITIALS,0
MED_ISSUED,CHANGE_DATE_TIME,0
MED_ISSUED,CHANGE_UID,0
MED_NOTES,DISTRICT,1
MED_NOTES,STUDENT_ID,1
MED_NOTES,EVENT_TYPE,1
MED_NOTES,EVENT_DATE,1
MED_NOTES,NOTE,0
MED_NOTES,CHANGE_DATE_TIME,0
MED_NOTES,CHANGE_UID,0
MED_OFFICE,DISTRICT,1
MED_OFFICE,STUDENT_ID,1
MED_OFFICE,OFFICE_DATE_IN,1
MED_OFFICE,OFFICE_DATE_OUT,0
MED_OFFICE,ROOM_ID,0
MED_OFFICE,COMMENT,0
MED_OFFICE,INITIALS,0
MED_OFFICE,ROW_IDENTITY,0
MED_OFFICE,CHANGE_DATE_TIME,0
MED_OFFICE,CHANGE_UID,0
MED_OFFICE_DET,DISTRICT,1
MED_OFFICE_DET,STUDENT_ID,1
MED_OFFICE_DET,OFFICE_DATE_IN,1
MED_OFFICE_DET,SEQUENCE_NUM,1
MED_OFFICE_DET,VISIT_REASON,0
MED_OFFICE_DET,TREATMENT_CODE,0
MED_OFFICE_DET,OUTCOME,0
MED_OFFICE_DET,CHANGE_DATE_TIME,0
MED_OFFICE_DET,CHANGE_UID,0
MED_OFFICE_SCHD,DISTRICT,1
MED_OFFICE_SCHD,STUDENT_ID,1
MED_OFFICE_SCHD,START_DATE,1
MED_OFFICE_SCHD,END_DATE,1
MED_OFFICE_SCHD,SCHEDULED_TIME,1
MED_OFFICE_SCHD,SEQUENCE_NUMBER,1
MED_OFFICE_SCHD,VISIT_REASON,0
MED_OFFICE_SCHD,TREATMENT_CODE,0
MED_OFFICE_SCHD,OUTCOME,0
MED_OFFICE_SCHD,CHANGE_DATE_TIME,0
MED_OFFICE_SCHD,CHANGE_UID,0
MED_PHYSICAL,DISTRICT,1
MED_PHYSICAL,STUDENT_ID,1
MED_PHYSICAL,TEST_DATE,1
MED_PHYSICAL,GRADE,0
MED_PHYSICAL,LOCATION,0
MED_PHYSICAL,PULSE,0
MED_PHYSICAL,BLOOD_PRESSURE_SYS,0
MED_PHYSICAL,BLOOD_PRESSURE_DIA,0
MED_PHYSICAL,ATHLETIC_STATUS,0
MED_PHYSICAL,CLEARED_STATUS,0
MED_PHYSICAL,INITIALS,0
MED_PHYSICAL,ROW_IDENTITY,0
MED_PHYSICAL,CHANGE_DATE_TIME,0
MED_PHYSICAL,CHANGE_UID,0
MED_PHYSICAL_EXAM,DISTRICT,1
MED_PHYSICAL_EXAM,STUDENT_ID,1
MED_PHYSICAL_EXAM,TEST_DATE,1
MED_PHYSICAL_EXAM,TEST_TYPE,1
MED_PHYSICAL_EXAM,TEST_RESULT,0
MED_PHYSICAL_EXAM,CHANGE_DATE_TIME,0
MED_PHYSICAL_EXAM,CHANGE_UID,0
MED_REFERRAL,DISTRICT,1
MED_REFERRAL,STUDENT_ID,1
MED_REFERRAL,TEST_TYPE,1
MED_REFERRAL,TEST_DATE,1
MED_REFERRAL,SEQUENCE_NUMBER,1
MED_REFERRAL,REFERRAL_CODE,0
MED_REFERRAL,REFERRAL_DATE,0
MED_REFERRAL,FOLLOW_UP_CODE,0
MED_REFERRAL,FOLLOW_UP_DATE,0
MED_REFERRAL,DOCTOR_NAME,0
MED_REFERRAL,COMMENT,0
MED_REFERRAL,ROW_IDENTITY,0
MED_REFERRAL,CHANGE_DATE_TIME,0
MED_REFERRAL,CHANGE_UID,0
MED_REQUIRED,DISTRICT,1
MED_REQUIRED,STUDENT_ID,1
MED_REQUIRED,MED_CODE,1
MED_REQUIRED,START_DATE,1
MED_REQUIRED,END_DATE,0
MED_REQUIRED,DOSE_NUMBER,1
MED_REQUIRED,DOSE_TIME,0
MED_REQUIRED,PHYSICIAN_NAME,0
MED_REQUIRED,DOSE_COMMENT,0
MED_REQUIRED,CHANGE_DATE_TIME,0
MED_REQUIRED,CHANGE_UID,0
MED_SCOLIOSIS,DISTRICT,1
MED_SCOLIOSIS,STUDENT_ID,1
MED_SCOLIOSIS,TEST_DATE,1
MED_SCOLIOSIS,GRADE,0
MED_SCOLIOSIS,LOCATION,0
MED_SCOLIOSIS,STATUS,0
MED_SCOLIOSIS,INITIALS,0
MED_SCOLIOSIS,ROW_IDENTITY,0
MED_SCOLIOSIS,CHANGE_DATE_TIME,0
MED_SCOLIOSIS,CHANGE_UID,0
MED_SCREENING,DISTRICT,1
MED_SCREENING,STUDENT_ID,1
MED_SCREENING,EXAM_CODE,1
MED_SCREENING,TEST_DATE,1
MED_SCREENING,GRADE,0
MED_SCREENING,LOCATION,0
MED_SCREENING,STATUS,0
MED_SCREENING,INITIALS,0
MED_SCREENING,ROW_IDENTITY,0
MED_SCREENING,CHANGE_DATE_TIME,0
MED_SCREENING,CHANGE_UID,0
MED_SERIES,DISTRICT,1
MED_SERIES,STUDENT_ID,1
MED_SERIES,SERIES_CODE,1
MED_SERIES,SERIES_EXEMPTION,0
MED_SERIES,TOTAL_DOSES,0
MED_SERIES,SERIES_STATUS,0
MED_SERIES,CALC_DATE,0
MED_SERIES,OVERRIDE,0
MED_SERIES,COMMENT,0
MED_SERIES,NUMBER_LETTERS,0
MED_SERIES,HAD_DISEASE,0
MED_SERIES,DISEASE_DATE,0
MED_SERIES,CHANGE_DATE_TIME,0
MED_SERIES,CHANGE_UID,0
MED_SERIES,NUMBER_NOTIFICATIONS,0
MED_SERIES_DET,DISTRICT,1
MED_SERIES_DET,STUDENT_ID,1
MED_SERIES_DET,SERIES_CODE,1
MED_SERIES_DET,SERIES_DATE,1
MED_SERIES_DET,CHANGE_DATE_TIME,0
MED_SERIES_DET,CHANGE_UID,0
MED_SERIES_SCHD_BOOSTER,DISTRICT,1
MED_SERIES_SCHD_BOOSTER,SERIES_SCHEDULE,1
MED_SERIES_SCHD_BOOSTER,BOOSTER_NUMBER,1
MED_SERIES_SCHD_BOOSTER,SHOT_TYPE,1
MED_SERIES_SCHD_BOOSTER,CHANGE_DATE_TIME,0
MED_SERIES_SCHD_BOOSTER,CHANGE_UID,0
MED_SERIES_SCHD_HDR,DISTRICT,1
MED_SERIES_SCHD_HDR,SERIES_SCHEDULE,1
MED_SERIES_SCHD_HDR,EXPIRES_AFTER,0
MED_SERIES_SCHD_HDR,EXPIRES_UNITS,0
MED_SERIES_SCHD_HDR,EXPIRES_CODE,0
MED_SERIES_SCHD_HDR,NUM_REQUIRED,0
MED_SERIES_SCHD_HDR,CHANGE_DATE_TIME,0
MED_SERIES_SCHD_HDR,CHANGE_UID,0
MED_SERIES_SCHD_TYPES,DISTRICT,1
MED_SERIES_SCHD_TYPES,SERIES_SCHEDULE,1
MED_SERIES_SCHD_TYPES,SHOT_TYPE,1
MED_SERIES_SCHD_TYPES,CHANGE_DATE_TIME,0
MED_SERIES_SCHD_TYPES,CHANGE_UID,0
MED_SERIES_SCHED,DISTRICT,1
MED_SERIES_SCHED,SERIES_SCHEDULE,1
MED_SERIES_SCHED,DOSE_NUMBER,1
MED_SERIES_SCHED,DESCRIPTION,0
MED_SERIES_SCHED,SERIES_CODE,0
MED_SERIES_SCHED,EVENT_DOSE,0
MED_SERIES_SCHED,TIME_EVENTS,0
MED_SERIES_SCHED,TIME_EVENTS_UNITS,0
MED_SERIES_SCHED,OVERDUE_MS,0
MED_SERIES_SCHED,OVERDUE_MS_UNITS,0
MED_SERIES_SCHED,TIME_BIRTH,0
MED_SERIES_SCHED,UNITS_TIME_BIRTH,0
MED_SERIES_SCHED,OVERDUE_RS,0
MED_SERIES_SCHED,OVERDUE_RS_UNITS,0
MED_SERIES_SCHED,NOT_BEFORE,0
MED_SERIES_SCHED,NOT_BEFORE_UNITS,0
MED_SERIES_SCHED,EXCEPTIONS,0
MED_SERIES_SCHED,EXCEPTIONS_DOSE,0
MED_SERIES_SCHED,GIVEN_AFTER,0
MED_SERIES_SCHED,GIVEN_AFTER_UNITS,0
MED_SERIES_SCHED,EXPIRES_AFTER,0
MED_SERIES_SCHED,EXPIRES_UNITS,0
MED_SERIES_SCHED,EXPIRES_CODE,0
MED_SERIES_SCHED,NOT_UNTIL_DOSE,0
MED_SERIES_SCHED,NOT_UNTIL_TIME,0
MED_SERIES_SCHED,NOT_UNTIL_UNITS,0
MED_SERIES_SCHED,CHANGE_DATE_TIME,0
MED_SERIES_SCHED,CHANGE_UID,0
MED_SHOT,DISTRICT,1
MED_SHOT,STUDENT_ID,1
MED_SHOT,SHOT_CODE,1
MED_SHOT,EXEMPT,0
MED_SHOT,COMMENT,0
MED_SHOT,OVERRIDE,0
MED_SHOT,HAD_DISEASE,0
MED_SHOT,DISEASE_DATE,0
MED_SHOT,CHANGE_DATE_TIME,0
MED_SHOT,CHANGE_UID,0
MED_SHOT_DET,DISTRICT,1
MED_SHOT_DET,STUDENT_ID,1
MED_SHOT_DET,SHOT_CODE,1
MED_SHOT_DET,SHOT_DATE,1
MED_SHOT_DET,SHOT_ORDER,0
MED_SHOT_DET,SOURCE_DOC,0
MED_SHOT_DET,SIGNED_DOC,0
MED_SHOT_DET,WARNING_STATUS,0
MED_SHOT_DET,OVERRIDE,0
MED_SHOT_DET,ROW_IDENTITY,0
MED_SHOT_DET,CHANGE_DATE_TIME,0
MED_SHOT_DET,CHANGE_UID,0
MED_STU_LETTER,DISTRICT,1
MED_STU_LETTER,STUDENT_ID,1
MED_STU_LETTER,CRIT_NUMBER,1
MED_STU_LETTER,CALC_DATE,1
MED_STU_LETTER,SERIES_CODE,1
MED_STU_LETTER,DATE_PRINTED,0
MED_STU_LETTER,NOTIFICATION_DATE,0
MED_STU_LETTER,SERIES_REASON,0
MED_STU_LETTER,CHANGE_DATE_TIME,0
MED_STU_LETTER,CHANGE_UID,0
MED_USER,DISTRICT,1
MED_USER,STUDENT_ID,1
MED_USER,SCREEN_NUMBER,1
MED_USER,FIELD_NUMBER,1
MED_USER,FIELD_VALUE,0
MED_USER,CHANGE_DATE_TIME,0
MED_USER,CHANGE_UID,0
MED_VISION,DISTRICT,1
MED_VISION,STUDENT_ID,1
MED_VISION,TEST_DATE,1
MED_VISION,GRADE,0
MED_VISION,LOCATION,0
MED_VISION,LENS,0
MED_VISION,RIGHT_EYE,0
MED_VISION,LEFT_EYE,0
MED_VISION,MUSCLE,0
MED_VISION,MUSCLE_LEFT,0
MED_VISION,COLOR_BLIND,0
MED_VISION,PLUS_LENS,0
MED_VISION,BINOC,0
MED_VISION,INITIALS,0
MED_VISION,TEST_TYPE,0
MED_VISION,STEREOPSIS,0
MED_VISION,NEAR_FAR_TYPE,0
MED_VISION,ROW_IDENTITY,0
MED_VISION,CHANGE_DATE_TIME,0
MED_VISION,CHANGE_UID,0
MED_VISION_COLS,DISTRICT,1
MED_VISION_COLS,STUDENT_ID,1
MED_VISION_COLS,TEST_DATE,1
MED_VISION_COLS,SCREENING_TYPE,0
MED_VISION_COLS,CHANGE_DATE_TIME,0
MED_VISION_COLS,CHANGE_UID,0
MED_VITALS,ROW_IDENTITY,1
MED_VITALS,MED_OFFICE_ROW_IDENTITY,0
MED_VITALS,CHANGE_DATE_TIME,0
MED_VITALS,CHANGE_UID,0
MED_VITALS,TIME_VITALS_TAKEN,0
MED_VITALS,BLOOD_PRESSURE_SYS,0
MED_VITALS,BLOOD_PRESSURE_DIA,0
MED_VITALS,PULSE,0
MED_VITALS,TEMPERATURE,0
MED_VITALS,TEMPERATURE_METHOD,0
MED_VITALS,RESPIRATION,0
MED_VITALS,PULSE_OXIMETER,0
MED_YEAREND_RUN,DISTRICT,1
MED_YEAREND_RUN,SCHOOL_YEAR,1
MED_YEAREND_RUN,RUN_KEY,1
MED_YEAREND_RUN,RUN_DATE,0
MED_YEAREND_RUN,RUN_STATUS,0
MED_YEAREND_RUN,CLEAN_MED_DATA,0
MED_YEAREND_RUN,PURGE_STU_YEAR,0
MED_YEAREND_RUN,PURGE_LETTERS_DATE,0
MED_YEAREND_RUN,RESTORE_KEY,0
MED_YEAREND_RUN,CHANGE_DATE_TIME,0
MED_YEAREND_RUN,CHANGE_UID,0
MEDTB_ALT_DOSE,DISTRICT,1
MEDTB_ALT_DOSE,SERIES_CODE,1
MEDTB_ALT_DOSE,ALT_NUMBER,1
MEDTB_ALT_DOSE,DESCRIPTION,0
MEDTB_ALT_DOSE,ACTIVE,0
MEDTB_ALT_DOSE,CHANGE_DATE_TIME,0
MEDTB_ALT_DOSE,CHANGE_UID,0
MEDTB_ALT_DOSE_DET,DISTRICT,1
MEDTB_ALT_DOSE_DET,SERIES_CODE,1
MEDTB_ALT_DOSE_DET,ALT_NUMBER,1
MEDTB_ALT_DOSE_DET,SEQ_NUMBER,1
MEDTB_ALT_DOSE_DET,ALT_DOSE,0
MEDTB_ALT_DOSE_DET,CHANGE_DATE_TIME,0
MEDTB_ALT_DOSE_DET,CHANGE_UID,0
MEDTB_BMI_STATUS,DISTRICT,1
MEDTB_BMI_STATUS,CODE,1
MEDTB_BMI_STATUS,DESCRIPTION,0
MEDTB_BMI_STATUS,MIN_BMI,0
MEDTB_BMI_STATUS,MAX_BMI,0
MEDTB_BMI_STATUS,ACTIVE,0
MEDTB_BMI_STATUS,CHANGE_DATE_TIME,0
MEDTB_BMI_STATUS,CHANGE_UID,0
MEDTB_CDC_LMS,DISTRICT,1
MEDTB_CDC_LMS,GENDER,1
MEDTB_CDC_LMS,AGE,1
MEDTB_CDC_LMS,CHART_TYPE,1
MEDTB_CDC_LMS,L,0
MEDTB_CDC_LMS,M,0
MEDTB_CDC_LMS,S,0
MEDTB_DECIBEL,DISTRICT,1
MEDTB_DECIBEL,DECIBEL_LEVEL,1
MEDTB_DECIBEL,SEQUENCE_NUMBER,0
MEDTB_DECIBEL,ACTIVE,0
MEDTB_DECIBEL,CHANGE_DATE_TIME,0
MEDTB_DECIBEL,CHANGE_UID,0
MEDTB_EVENT,DISTRICT,1
MEDTB_EVENT,CODE,1
MEDTB_EVENT,DESCRIPTION,0
MEDTB_EVENT,CHANGE_DATE_TIME,0
MEDTB_EVENT,CHANGE_UID,0
MEDTB_EXAM,DISTRICT,1
MEDTB_EXAM,CODE,1
MEDTB_EXAM,DESCRIPTION,0
MEDTB_EXAM,ACTIVE_NORMAL,0
MEDTB_EXAM,ACTIVE_ATHLETIC,0
MEDTB_EXAM,SEQ_NUMBER,0
MEDTB_EXAM,STATE_CODE_EQUIV,0
MEDTB_EXAM,ACTIVE,0
MEDTB_EXAM,CHANGE_DATE_TIME,0
MEDTB_EXAM,CHANGE_UID,0
MEDTB_EXEMPT,DISTRICT,1
MEDTB_EXEMPT,CODE,1
MEDTB_EXEMPT,DESCRIPTION,0
MEDTB_EXEMPT,STATE_CODE_EQUIV,0
MEDTB_EXEMPT,ACTIVE,0
MEDTB_EXEMPT,CHANGE_DATE_TIME,0
MEDTB_EXEMPT,CHANGE_UID,0
MEDTB_FOLLOWUP,DISTRICT,1
MEDTB_FOLLOWUP,CODE,1
MEDTB_FOLLOWUP,DESCRIPTION,0
MEDTB_FOLLOWUP,DENTAL,0
MEDTB_FOLLOWUP,GROWTH,0
MEDTB_FOLLOWUP,HEARING,0
MEDTB_FOLLOWUP,IMMUN,0
MEDTB_FOLLOWUP,OFFICE,0
MEDTB_FOLLOWUP,OTHER,0
MEDTB_FOLLOWUP,PHYSICAL,0
MEDTB_FOLLOWUP,SCOLIOSIS,0
MEDTB_FOLLOWUP,VISION,0
MEDTB_FOLLOWUP,STATE_CODE_EQUIV,0
MEDTB_FOLLOWUP,ACTIVE,0
MEDTB_FOLLOWUP,CHANGE_DATE_TIME,0
MEDTB_FOLLOWUP,CHANGE_UID,0
MEDTB_FREQUENCY,DISTRICT,1
MEDTB_FREQUENCY,FREQUENCY_LEVEL,1
MEDTB_FREQUENCY,SEQUENCE_NUMBER,0
MEDTB_FREQUENCY,ACTIVE,0
MEDTB_FREQUENCY,CHANGE_DATE_TIME,0
MEDTB_FREQUENCY,CHANGE_UID,0
MEDTB_LENS,DISTRICT,1
MEDTB_LENS,CODE,1
MEDTB_LENS,DESCRIPTION,0
MEDTB_LENS,STATE_CODE_EQUIV,0
MEDTB_LENS,ACTIVE,0
MEDTB_LENS,CHANGE_DATE_TIME,0
MEDTB_LENS,CHANGE_UID,0
MEDTB_LOCATION,DISTRICT,1
MEDTB_LOCATION,CODE,1
MEDTB_LOCATION,DESCRIPTION,0
MEDTB_LOCATION,STATE_CODE_EQUIV,0
MEDTB_LOCATION,ACTIVE,0
MEDTB_LOCATION,CHANGE_DATE_TIME,0
MEDTB_LOCATION,CHANGE_UID,0
MEDTB_MEDICINE,DISTRICT,1
MEDTB_MEDICINE,CODE,1
MEDTB_MEDICINE,DESCRIPTION,0
MEDTB_MEDICINE,PRN,0
MEDTB_MEDICINE,MEDICAID_CODE,0
MEDTB_MEDICINE,STATE_CODE_EQUIV,0
MEDTB_MEDICINE,ACTIVE,0
MEDTB_MEDICINE,CHANGE_DATE_TIME,0
MEDTB_MEDICINE,CHANGE_UID,0
MEDTB_OUTCOME,DISTRICT,1
MEDTB_OUTCOME,CODE,1
MEDTB_OUTCOME,DESCRIPTION,0
MEDTB_OUTCOME,STATE_CODE_EQUIV,0
MEDTB_OUTCOME,ACTIVE,0
MEDTB_OUTCOME,CHANGE_DATE_TIME,0
MEDTB_OUTCOME,CHANGE_UID,0
MEDTB_PERCENTS,DISTRICT,1
MEDTB_PERCENTS,AGE,1
MEDTB_PERCENTS,GENDER,1
MEDTB_PERCENTS,PERCENTILE,1
MEDTB_PERCENTS,HEIGHT,0
MEDTB_PERCENTS,WEIGHT,0
MEDTB_PERCENTS,BMI,0
MEDTB_PERCENTS,ACTIVE,0
MEDTB_PERCENTS,CHANGE_DATE_TIME,0
MEDTB_PERCENTS,CHANGE_UID,0
MEDTB_PERCENTS_ARK,DISTRICT,1
MEDTB_PERCENTS_ARK,AGE,1
MEDTB_PERCENTS_ARK,GENDER,1
MEDTB_PERCENTS_ARK,PERCENTILE,1
MEDTB_PERCENTS_ARK,HEIGHT,0
MEDTB_PERCENTS_ARK,WEIGHT,0
MEDTB_PERCENTS_ARK,BMI,0
MEDTB_PERCENTS_ARK,ACTIVE,0
MEDTB_PERCENTS_ARK,CHANGE_DATE_TIME,0
MEDTB_PERCENTS_ARK,CHANGE_UID,0
MEDTB_REFER,DISTRICT,1
MEDTB_REFER,CODE,1
MEDTB_REFER,DESCRIPTION,0
MEDTB_REFER,DENTAL,0
MEDTB_REFER,GROWTH,0
MEDTB_REFER,HEARING,0
MEDTB_REFER,IMMUN,0
MEDTB_REFER,OFFICE,0
MEDTB_REFER,OTHER,0
MEDTB_REFER,PHYSICAL,0
MEDTB_REFER,SCOLIOSIS,0
MEDTB_REFER,VISION,0
MEDTB_REFER,STATE_CODE_EQUIV,0
MEDTB_REFER,ACTIVE,0
MEDTB_REFER,CHANGE_DATE_TIME,0
MEDTB_REFER,CHANGE_UID,0
MEDTB_SCREENING,DISTRICT,1
MEDTB_SCREENING,CODE,1
MEDTB_SCREENING,DESCRIPTION,0
MEDTB_SCREENING,STATE_CODE_EQUIV,0
MEDTB_SCREENING,ACTIVE,0
MEDTB_SCREENING,CHANGE_DATE_TIME,0
MEDTB_SCREENING,CHANGE_UID,0
MEDTB_SHOT,DISTRICT,1
MEDTB_SHOT,CODE,1
MEDTB_SHOT,DESCRIPTION,0
MEDTB_SHOT,SHOT_ORDER,0
MEDTB_SHOT,AUTO_GENERATE,0
MEDTB_SHOT,LIVE_VIRUS,0
MEDTB_SHOT,SHOT_REQUIREMENT,0
MEDTB_SHOT,SERIES_FLAG,0
MEDTB_SHOT,LICENSING_DATE,0
MEDTB_SHOT,STATE_CODE_EQUIV,0
MEDTB_SHOT,PESC_CODE,0
MEDTB_SHOT,ACTIVE,0
MEDTB_SHOT,CHANGE_DATE_TIME,0
MEDTB_SHOT,CHANGE_UID,0
MEDTB_SOURCE_DOC,DISTRICT,1
MEDTB_SOURCE_DOC,CODE,1
MEDTB_SOURCE_DOC,DESCRIPTION,0
MEDTB_SOURCE_DOC,STATE_CODE_EQUIV,0
MEDTB_SOURCE_DOC,ACTIVE,0
MEDTB_SOURCE_DOC,CHANGE_DATE_TIME,0
MEDTB_SOURCE_DOC,CHANGE_UID,0
MEDTB_STATUS,DISTRICT,1
MEDTB_STATUS,CODE,1
MEDTB_STATUS,DESCRIPTION,0
MEDTB_STATUS,STATE_CODE_EQUIV,0
MEDTB_STATUS,ACTIVE,0
MEDTB_STATUS,CHANGE_DATE_TIME,0
MEDTB_STATUS,CHANGE_UID,0
MEDTB_TEMP_METHOD,CHANGE_DATE_TIME,0
MEDTB_TEMP_METHOD,CHANGE_UID,0
MEDTB_TEMP_METHOD,DISTRICT,1
MEDTB_TEMP_METHOD,CODE,1
MEDTB_TEMP_METHOD,DESCRIPTION,0
MEDTB_TEMP_METHOD,STATE_CODE_EQUIV,0
MEDTB_TEMP_METHOD,ACTIVE,0
MEDTB_TREATMENT,DISTRICT,1
MEDTB_TREATMENT,CODE,1
MEDTB_TREATMENT,DESCRIPTION,0
MEDTB_TREATMENT,MEDICAID_CODE,0
MEDTB_TREATMENT,STATE_CODE_EQUIV,0
MEDTB_TREATMENT,ACTIVE,0
MEDTB_TREATMENT,CHANGE_DATE_TIME,0
MEDTB_TREATMENT,CHANGE_UID,0
MEDTB_VACCINATION_PESC_CODE,DISTRICT,1
MEDTB_VACCINATION_PESC_CODE,CODE,1
MEDTB_VACCINATION_PESC_CODE,DESCRIPTION,0
MEDTB_VACCINATION_PESC_CODE,CHANGE_DATE_TIME,0
MEDTB_VACCINATION_PESC_CODE,CHANGE_UID,0
medtb_vis_exam_ark,DISTRICT,1
medtb_vis_exam_ark,FOLLOWUP_CODE,1
medtb_vis_exam_ark,DESCRIPTION,0
medtb_vis_exam_ark,CONFIRMED_NORMAL,0
medtb_vis_exam_ark,ACTIVE,0
medtb_vis_exam_ark,CHANGE_DATE_TIME,0
medtb_vis_exam_ark,CHANGE_UID,0
MEDTB_VISION_EXAM_TYPE,DISTRICT,1
MEDTB_VISION_EXAM_TYPE,CODE,1
MEDTB_VISION_EXAM_TYPE,DESCRIPTION,0
MEDTB_VISION_EXAM_TYPE,STATE_CODE_EQUIV,0
MEDTB_VISION_EXAM_TYPE,ACTIVE,0
MEDTB_VISION_EXAM_TYPE,CHANGE_DATE_TIME,0
MEDTB_VISION_EXAM_TYPE,CHANGE_UID,0
MEDTB_VISIT,DISTRICT,1
MEDTB_VISIT,CODE,1
MEDTB_VISIT,DESCRIPTION,0
MEDTB_VISIT,STATE_CODE_EQUIV,0
MEDTB_VISIT,ACTIVE,0
MEDTB_VISIT,CHANGE_DATE_TIME,0
MEDTB_VISIT,CHANGE_UID,0
MENU_ITEMS,DISTRICT,1
MENU_ITEMS,PARENT_MENU,1
MENU_ITEMS,SEQUENCE,1
MENU_ITEMS,MENU_ID,0
MENU_ITEMS,DESCRIPTION,0
MENU_ITEMS,TARGET,0
MENU_ITEMS,PAGE,0
MENU_ITEMS,SEC_PACKAGE,0
MENU_ITEMS,SEC_SUBPACKAGE,0
MENU_ITEMS,SEC_FEATURE,0
MENU_ITEMS,RESERVED,0
MENU_ITEMS,CHANGE_DATE_TIME,0
MENU_ITEMS,CHANGE_UID,0
MR_ABSENCE_TYPES,DISTRICT,1
MR_ABSENCE_TYPES,BUILDING,1
MR_ABSENCE_TYPES,ABSENCE_TYPE,1
MR_ABSENCE_TYPES,ABSENCE_ORDER,0
MR_ABSENCE_TYPES,ABSENCE_WHEN,0
MR_ABSENCE_TYPES,DESCRIPTION,0
MR_ABSENCE_TYPES,SUM_TO_YEARLY,0
MR_ABSENCE_TYPES,YEARLY_TYPE,0
MR_ABSENCE_TYPES,ACTIVE,0
MR_ABSENCE_TYPES,TWS_ACCESS,0
MR_ABSENCE_TYPES,MULTI_PERIOD_RULE,0
MR_ABSENCE_TYPES,CHANGE_DATE_TIME,0
MR_ABSENCE_TYPES,CHANGE_UID,0
MR_ABSENCE_VALID,DISTRICT,1
MR_ABSENCE_VALID,BUILDING,1
MR_ABSENCE_VALID,ABSENCE_TYPE,1
MR_ABSENCE_VALID,ATTENDANCE_CODE,1
MR_ABSENCE_VALID,CHANGE_DATE_TIME,0
MR_ABSENCE_VALID,CHANGE_UID,0
MR_ALT_LANG_CFG,DISTRICT,1
MR_ALT_LANG_CFG,LANGUAGE,1
MR_ALT_LANG_CFG,LABEL,1
MR_ALT_LANG_CFG,ALTERNATE_LABEL,0
MR_ALT_LANG_CFG,CHANGE_DATE_TIME,0
MR_ALT_LANG_CFG,CHANGE_UID,0
MR_AVERAGE_CALC,DISTRICT,1
MR_AVERAGE_CALC,SCHOOL_YEAR,1
MR_AVERAGE_CALC,BUILDING,1
MR_AVERAGE_CALC,AVERAGE_ID,1
MR_AVERAGE_CALC,AVERAGE_SEQUENCE,1
MR_AVERAGE_CALC,CALC_TYPE,1
MR_AVERAGE_CALC,MARK_TYPE,1
MR_AVERAGE_CALC,MARK_TYPE_MP,1
MR_AVERAGE_CALC,PERCENT_WEIGHT,0
MR_AVERAGE_CALC,EXEMPT_STATUS,0
MR_AVERAGE_CALC,CHANGE_DATE_TIME,0
MR_AVERAGE_CALC,CHANGE_UID,0
MR_AVERAGE_SETUP,DISTRICT,1
MR_AVERAGE_SETUP,SCHOOL_YEAR,1
MR_AVERAGE_SETUP,BUILDING,1
MR_AVERAGE_SETUP,AVERAGE_TYPE,0
MR_AVERAGE_SETUP,AVERAGE_ID,1
MR_AVERAGE_SETUP,AVERAGE_SEQUENCE,1
MR_AVERAGE_SETUP,MARK_TYPE,0
MR_AVERAGE_SETUP,DURATION,0
MR_AVERAGE_SETUP,MARK_TYPE_MP,0
MR_AVERAGE_SETUP,CALC_AT_MP,0
MR_AVERAGE_SETUP,USE_GRADEBOOK,0
MR_AVERAGE_SETUP,USE_STATUS_T,0
MR_AVERAGE_SETUP,USE_STATUS_O,0
MR_AVERAGE_SETUP,COURSE_ENDED,0
MR_AVERAGE_SETUP,BLANK_MARKS,0
MR_AVERAGE_SETUP,AVERAGE_PASS_FAIL,0
MR_AVERAGE_SETUP,AVERAGE_REGULAR,0
MR_AVERAGE_SETUP,STATE_CRS_EQUIV,0
MR_AVERAGE_SETUP,USE_RAW_AVERAGES,0
MR_AVERAGE_SETUP,CHANGE_DATE_TIME,0
MR_AVERAGE_SETUP,CHANGE_UID,0
MR_CFG,DISTRICT,1
MR_CFG,BUILDING,1
MR_CFG,CURRENT_RC_RUN,0
MR_CFG,INCLUDE_XFER_IN_RC,0
MR_CFG,DISPLAY_MBS_BLDG,0
MR_CFG,MAINTAIN_ATTEND,0
MR_CFG,PROCESS_IPR,0
MR_CFG,USE_LANG_TEMPLATE,0
MR_CFG,DATA_SOURCE_FILE,0
MR_CFG,PROGRAM_SCREEN,0
MR_CFG,REG_USER_SCREEN,0
MR_CFG,NOTIFY_DWNLD_PATH,0
MR_CFG,EMAIL_OPTION,0
MR_CFG,RETURN_EMAIL,0
MR_CFG,RET_EMAIL_MISSUB,0
MR_CFG,TEA_IPR_MNT,0
MR_CFG,SUB_IPR_MNT,0
MR_CFG,TEA_IPR_STU_SUMM,0
MR_CFG,SUB_IPR_STU_SUMM,0
MR_CFG,TEA_RC_MNT,0
MR_CFG,SUB_RC_MNT,0
MR_CFG,TEA_RC_STU_SUMM,0
MR_CFG,SUB_RC_STU_SUMM,0
MR_CFG,TEA_SC_MNT,0
MR_CFG,SUB_SC_MNT,0
MR_CFG,TEA_SC_STU_SUMM,0
MR_CFG,SUB_SC_STU_SUMM,0
MR_CFG,TEA_GB_DEFINE,0
MR_CFG,TEA_GB_SCORE,0
MR_CFG,SUB_GB_DEFINE,0
MR_CFG,SUB_GB_SCORE,0
MR_CFG,PROCESS_SC,0
MR_CFG,SC_COMMENT_LINES,0
MR_CFG,GB_ENTRY_B4_ENRLMT,0
MR_CFG,TAC_CHANGE_CREDIT,0
MR_CFG,GB_ALLOW_TEA_SCALE,0
MR_CFG,GB_LIMIT_CATEGORIES,0
MR_CFG,GB_LIMIT_DROP_SCORE,0
MR_CFG,GB_LIMIT_MISS_MARKS,0
MR_CFG,GB_ALLOW_OVR_WEIGHT,0
MR_CFG,GB_ALLOW_TRUNC_RND,0
MR_CFG,ASMT_DATE_VAL,0
MR_CFG,VALIDATE_TRANSFER,0
MR_CFG,MP_CRS_CREDIT_OVR,0
MR_CFG,TEA_GB_VIEW,0
MR_CFG,SUB_GB_VIEW,0
MR_CFG,TEA_PRINT_RC,0
MR_CFG,SUB_PRINT_RC,0
MR_CFG,TEA_TRANSCRIPT,0
MR_CFG,SUB_TRANSCRIPT,0
MR_CFG,TEA_GB_SUM_VIEW,0
MR_CFG,SUB_GB_SUM_VIEW,0
MR_CFG,USE_RC_HOLD,0
MR_CFG,STATUS_REASON,0
MR_CFG,OVERALL_BALANCE,0
MR_CFG,OVERALL_BAL_REASON,0
MR_CFG,COURSE_BALANCE,0
MR_CFG,COURSE_BAL_REASON,0
MR_CFG,STUDENT_BALANCE,0
MR_CFG,STUDENT_BAL_REASON,0
MR_CFG,ACTIVITY_BALANCE,0
MR_CFG,ACTIVITY_BAL_REASON,0
MR_CFG,ALLOW_COURSE_FREE_TEXT,0
MR_CFG,MAX_COURSE_FREE_TEXT_CHARACTERS,0
MR_CFG,SECONDARY_TEACHER_ACCESS,0
MR_CFG,CHANGE_DATE_TIME,0
MR_CFG,CHANGE_UID,0
mr_cfg_hold_fee,DISTRICT,1
mr_cfg_hold_fee,BUILDING,1
mr_cfg_hold_fee,ITEM_OR_CAT,1
mr_cfg_hold_fee,CODE,1
mr_cfg_hold_fee,BALANCE,0
mr_cfg_hold_fee,REASON,0
mr_cfg_hold_fee,CHANGE_DATE_TIME,0
mr_cfg_hold_fee,CHANGE_UID,0
mr_cfg_hold_status,DISTRICT,1
mr_cfg_hold_status,BUILDING,1
mr_cfg_hold_status,FEE_STATUS,1
mr_cfg_hold_status,CHANGE_DATE_TIME,0
mr_cfg_hold_status,CHANGE_UID,0
MR_CFG_LANG,DISTRICT,1
MR_CFG_LANG,BUILDING,1
MR_CFG_LANG,LANGUAGE_CODE,1
MR_CFG_LANG,CHANGE_DATE_TIME,0
MR_CFG_LANG,CHANGE_UID,0
MR_CFG_MISS_SUB,DISTRICT,1
MR_CFG_MISS_SUB,BUILDING,1
MR_CFG_MISS_SUB,LOGIN_ID,1
MR_CFG_MISS_SUB,CHANGE_DATE_TIME,0
MR_CFG_MISS_SUB,CHANGE_UID,0
MR_CLASS_SIZE,DISTRICT,1
MR_CLASS_SIZE,SCHOOL_YEAR,1
MR_CLASS_SIZE,GPA_TYPE,1
MR_CLASS_SIZE,RUN_TERM_YEAR,1
MR_CLASS_SIZE,BUILDING,1
MR_CLASS_SIZE,GRADE,1
MR_CLASS_SIZE,CLASS_SIZE,0
MR_CLASS_SIZE,CHANGE_DATE_TIME,0
MR_CLASS_SIZE,CHANGE_UID,0
MR_COMMENT_TYPES,DISTRICT,1
MR_COMMENT_TYPES,BUILDING,1
MR_COMMENT_TYPES,COMMENT_TYPE,1
MR_COMMENT_TYPES,COMMENT_ORDER,0
MR_COMMENT_TYPES,DESCRIPTION,0
MR_COMMENT_TYPES,ACTIVE,0
MR_COMMENT_TYPES,REQUIRED,0
MR_COMMENT_TYPES,USAGE,0
MR_COMMENT_TYPES,RC_USAGE,0
MR_COMMENT_TYPES,IPR_USAGE,0
MR_COMMENT_TYPES,SC_USAGE,0
MR_COMMENT_TYPES,TWS_ACCESS,0
MR_COMMENT_TYPES,CHANGE_DATE_TIME,0
MR_COMMENT_TYPES,CHANGE_UID,0
MR_COMMENT_VALID,DISTRICT,1
MR_COMMENT_VALID,BUILDING,1
MR_COMMENT_VALID,COMMENT_TYPE,1
MR_COMMENT_VALID,CODE,1
MR_COMMENT_VALID,CHANGE_DATE_TIME,0
MR_COMMENT_VALID,CHANGE_UID,0
MR_COMMENTS,DISTRICT,1
MR_COMMENTS,BUILDING,1
MR_COMMENTS,CODE,1
MR_COMMENTS,IPR_USAGE,0
MR_COMMENTS,SC_USAGE,0
MR_COMMENTS,RC_USAGE,0
MR_COMMENTS,FT_USAGE,0
MR_COMMENTS,DESCRIPTION,0
MR_COMMENTS,CHANGE_DATE_TIME,0
MR_COMMENTS,CHANGE_UID,0
MR_COMMENTS_ALT_LANG,DISTRICT,1
MR_COMMENTS_ALT_LANG,BUILDING,1
MR_COMMENTS_ALT_LANG,CODE,1
MR_COMMENTS_ALT_LANG,LANGUAGE,1
MR_COMMENTS_ALT_LANG,DESCRIPTION,0
MR_COMMENTS_ALT_LANG,CHANGE_DATE_TIME,0
MR_COMMENTS_ALT_LANG,CHANGE_UID,0
MR_CRDOVR_REASON,DISTRICT,1
MR_CRDOVR_REASON,CODE,1
MR_CRDOVR_REASON,DESCRIPTION,0
MR_CRDOVR_REASON,CHANGE_DATE_TIME,0
MR_CRDOVR_REASON,CHANGE_UID,0
MR_CREDIT_SETUP,DISTRICT,1
MR_CREDIT_SETUP,SCHOOL_YEAR,1
MR_CREDIT_SETUP,BUILDING,1
MR_CREDIT_SETUP,USE_STATUS_T,0
MR_CREDIT_SETUP,USE_STATUS_O,0
MR_CREDIT_SETUP,COURSE_ENDED,0
MR_CREDIT_SETUP,LIMIT_STU_GRADE,0
MR_CREDIT_SETUP,LIMIT_CRS_GRADE,0
MR_CREDIT_SETUP,ISSUE_PARTIAL,0
MR_CREDIT_SETUP,USE_CRS_AVG_RULE,0
MR_CREDIT_SETUP,AVG_MARK_TYPE,0
MR_CREDIT_SETUP,AVG_PASS_RULE,0
MR_CREDIT_SETUP,MIN_FAILING_MARK,0
MR_CREDIT_SETUP,CHECK_ABSENCES,0
MR_CREDIT_SETUP,ABS_TYPE,0
MR_CREDIT_SETUP,ABS_TOTAL,0
MR_CREDIT_SETUP,ABS_CRDOVR_REASON,0
MR_CREDIT_SETUP,CHANGE_DATE_TIME,0
MR_CREDIT_SETUP,CHANGE_UID,0
MR_CREDIT_SETUP_AB,DISTRICT,1
MR_CREDIT_SETUP_AB,SCHOOL_YEAR,1
MR_CREDIT_SETUP_AB,BUILDING,1
MR_CREDIT_SETUP_AB,ABS_TYPE,1
MR_CREDIT_SETUP_AB,ABS_TOTAL,1
MR_CREDIT_SETUP_AB,PER_MP_TERM_YR,0
MR_CREDIT_SETUP_AB,REVOKE_TERM_COURSE,0
MR_CREDIT_SETUP_AB,CHANGE_DATE_TIME,0
MR_CREDIT_SETUP_AB,CHANGE_UID,0
MR_CREDIT_SETUP_GD,DISTRICT,1
MR_CREDIT_SETUP_GD,SCHOOL_YEAR,1
MR_CREDIT_SETUP_GD,BUILDING,1
MR_CREDIT_SETUP_GD,GRADE,1
MR_CREDIT_SETUP_GD,CHANGE_DATE_TIME,0
MR_CREDIT_SETUP_GD,CHANGE_UID,0
MR_CREDIT_SETUP_MK,DISTRICT,1
MR_CREDIT_SETUP_MK,SCHOOL_YEAR,1
MR_CREDIT_SETUP_MK,BUILDING,1
MR_CREDIT_SETUP_MK,MARK_TYPE,1
MR_CREDIT_SETUP_MK,CHANGE_DATE_TIME,0
MR_CREDIT_SETUP_MK,CHANGE_UID,0
MR_CRSEQU_DET,DISTRICT,1
MR_CRSEQU_DET,SCHOOL_YEAR,1
MR_CRSEQU_DET,BUILDING,1
MR_CRSEQU_DET,STATE_ID,1
MR_CRSEQU_DET,COURSE,1
MR_CRSEQU_DET,COURSE_SECTION,1
MR_CRSEQU_DET,EQUIV_PARTS,0
MR_CRSEQU_DET,EQUIV_SEQUENCE,0
MR_CRSEQU_DET,CHANGE_DATE_TIME,0
MR_CRSEQU_DET,CHANGE_UID,0
MR_CRSEQU_HDR,DISTRICT,1
MR_CRSEQU_HDR,SCHOOL_YEAR,1
MR_CRSEQU_HDR,BUILDING,1
MR_CRSEQU_HDR,STATE_CODE,1
MR_CRSEQU_HDR,NEEDS_RECALC,0
MR_CRSEQU_HDR,ERROR_REASON,0
MR_CRSEQU_HDR,CHANGE_DATE_TIME,0
MR_CRSEQU_HDR,CHANGE_UID,0
MR_CRSEQU_SETUP,DISTRICT,1
MR_CRSEQU_SETUP,SCHOOL_YEAR,1
MR_CRSEQU_SETUP,BUILDING,1
MR_CRSEQU_SETUP,CRSEQU_FULL_YEAR,0
MR_CRSEQU_SETUP,CRSEQU_TWO_PART,0
MR_CRSEQU_SETUP,CRSEQU_THREE_PART,0
MR_CRSEQU_SETUP,CRSEQU_FOUR_PART,0
MR_CRSEQU_SETUP,RETAKE_RULE,0
MR_CRSEQU_SETUP,RETAKE_LEVEL,0
MR_CRSEQU_SETUP,CALC_GRAD_REQ,0
MR_CRSEQU_SETUP,CALC_CREDIT,0
MR_CRSEQU_SETUP,RC_WAREHOUSE,0
MR_CRSEQU_SETUP,TRN_WAREHOUSE,0
MR_CRSEQU_SETUP,CHANGE_DATE_TIME,0
MR_CRSEQU_SETUP,CHANGE_UID,0
MR_CRSEQU_SETUP_AB,DISTRICT,1
MR_CRSEQU_SETUP_AB,SCHOOL_YEAR,1
MR_CRSEQU_SETUP_AB,BUILDING,1
MR_CRSEQU_SETUP_AB,ABSENCE_TYPE,1
MR_CRSEQU_SETUP_AB,CHANGE_DATE_TIME,0
MR_CRSEQU_SETUP_AB,CHANGE_UID,0
MR_CRSEQU_SETUP_MK,DISTRICT,1
MR_CRSEQU_SETUP_MK,SCHOOL_YEAR,1
MR_CRSEQU_SETUP_MK,BUILDING,1
MR_CRSEQU_SETUP_MK,MARK_TYPE_STATE,1
MR_CRSEQU_SETUP_MK,MARK_TYPE_LOCAL,1
MR_CRSEQU_SETUP_MK,CHANGE_DATE_TIME,0
MR_CRSEQU_SETUP_MK,CHANGE_UID,0
MR_GB_ACCUMULATED_AVG,DISTRICT,1
MR_GB_ACCUMULATED_AVG,SECTION_KEY,1
MR_GB_ACCUMULATED_AVG,COURSE_SESSION,1
MR_GB_ACCUMULATED_AVG,COMPETENCY_GROUP,1
MR_GB_ACCUMULATED_AVG,COMPETENCY_NUMBER,1
MR_GB_ACCUMULATED_AVG,MARKING_PERIOD,1
MR_GB_ACCUMULATED_AVG,STUDENT_ID,1
MR_GB_ACCUMULATED_AVG,OVERRIDE_AVERAGE,0
MR_GB_ACCUMULATED_AVG,AVG_OR_RC_VALUE,0
MR_GB_ACCUMULATED_AVG,RC_VALUE,0
MR_GB_ACCUMULATED_AVG,CHANGE_DATE_TIME,0
MR_GB_ACCUMULATED_AVG,CHANGE_UID,0
MR_GB_ALPHA_MARKS,DISTRICT,1
MR_GB_ALPHA_MARKS,BUILDING,1
MR_GB_ALPHA_MARKS,CODE,1
MR_GB_ALPHA_MARKS,DESCRIPTION,0
MR_GB_ALPHA_MARKS,EXCLUDE,0
MR_GB_ALPHA_MARKS,PERCENT_VALUE,0
MR_GB_ALPHA_MARKS,CHANGE_DATE_TIME,0
MR_GB_ALPHA_MARKS,CHANGE_UID,0
MR_GB_ALPHA_MARKS,SGY_EQUIV,0
MR_GB_ALPHA_MARKS,IMS_EQUIV,0
MR_GB_ALPHA_MARKS,TURNED_IN,0
MR_GB_ASMT,DISTRICT,1
MR_GB_ASMT,SECTION_KEY,1
MR_GB_ASMT,COURSE_SESSION,1
MR_GB_ASMT,ASMT_NUMBER,1
MR_GB_ASMT,CRS_ASMT_NUMBER,0
MR_GB_ASMT,CATEGORY,0
MR_GB_ASMT,EXTRA_CREDIT,0
MR_GB_ASMT,ASSIGN_DATE,0
MR_GB_ASMT,DUE_DATE,0
MR_GB_ASMT,DESCRIPTION,0
MR_GB_ASMT,DESC_DETAIL,0
MR_GB_ASMT,POINTS,0
MR_GB_ASMT,WEIGHT,0
MR_GB_ASMT,PUBLISH_ASMT,0
MR_GB_ASMT,PUBLISH_SCORES,0
MR_GB_ASMT,RUBRIC_NUMBER,0
MR_GB_ASMT,USE_RUBRIC,0
MR_GB_ASMT,CANNOT_DROP,0
MR_GB_ASMT,HIGHLIGHT_POINTS,0
MR_GB_ASMT,POINTS_THRESHOLD,0
MR_GB_ASMT,HIGHLIGHT_PURPLE,0
MR_GB_ASMT,UC_STUDENT_WORK_TYPE,0
MR_GB_ASMT,CHANGE_DATE_TIME,0
MR_GB_ASMT,CHANGE_UID,0
MR_GB_ASMT_COMP,DISTRICT,1
MR_GB_ASMT_COMP,SECTION_KEY,1
MR_GB_ASMT_COMP,COURSE_SESSION,1
MR_GB_ASMT_COMP,ASMT_NUMBER,1
MR_GB_ASMT_COMP,COMPETENCY_GROUP,1
MR_GB_ASMT_COMP,COMPETENCY_NUMBER,1
MR_GB_ASMT_COMP,RUBRIC_NUMBER,0
MR_GB_ASMT_COMP,CRITERIA_NUMBER,1
MR_GB_ASMT_COMP,CHANGE_DATE_TIME,0
MR_GB_ASMT_COMP,CHANGE_UID,0
MR_GB_ASMT_STU_COMP,DISTRICT,1
MR_GB_ASMT_STU_COMP,BUILDING,1
MR_GB_ASMT_STU_COMP,COMPETENCY_GROUP,1
MR_GB_ASMT_STU_COMP,STAFF_ID,1
MR_GB_ASMT_STU_COMP,ASMT_NUMBER,1
MR_GB_ASMT_STU_COMP,CATEGORY,0
MR_GB_ASMT_STU_COMP,EXTRA_CREDIT,0
MR_GB_ASMT_STU_COMP,ASSIGN_DATE,0
MR_GB_ASMT_STU_COMP,DUE_DATE,0
MR_GB_ASMT_STU_COMP,DESCRIPTION,0
MR_GB_ASMT_STU_COMP,DESC_DETAIL,0
MR_GB_ASMT_STU_COMP,POINTS,0
MR_GB_ASMT_STU_COMP,WEIGHT,0
MR_GB_ASMT_STU_COMP,PUBLISH_ASMT,0
MR_GB_ASMT_STU_COMP,PUBLISH_SCORES,0
MR_GB_ASMT_STU_COMP,RUBRIC_NUMBER,0
MR_GB_ASMT_STU_COMP,USE_RUBRIC,0
MR_GB_ASMT_STU_COMP,CHANGE_DATE_TIME,0
MR_GB_ASMT_STU_COMP,CHANGE_UID,0
MR_GB_ASMT_STU_COMP_ATTACH,DISTRICT,1
MR_GB_ASMT_STU_COMP_ATTACH,SCHOOL_YEAR,1
MR_GB_ASMT_STU_COMP_ATTACH,COMPETENCY_GROUP,1
MR_GB_ASMT_STU_COMP_ATTACH,BUILDING,1
MR_GB_ASMT_STU_COMP_ATTACH,STAFF_ID,1
MR_GB_ASMT_STU_COMP_ATTACH,ASMT_NUMBER,1
MR_GB_ASMT_STU_COMP_ATTACH,ATTACHMENT_NAME,1
MR_GB_ASMT_STU_COMP_ATTACH,ATTACHMENT_DATA,0
MR_GB_ASMT_STU_COMP_ATTACH,CHANGE_DATE_TIME,0
MR_GB_ASMT_STU_COMP_ATTACH,CHANGE_UID,0
MR_GB_ASMT_STU_COMP_COMP,DISTRICT,1
MR_GB_ASMT_STU_COMP_COMP,BUILDING,1
MR_GB_ASMT_STU_COMP_COMP,STAFF_ID,1
MR_GB_ASMT_STU_COMP_COMP,ASMT_NUMBER,1
MR_GB_ASMT_STU_COMP_COMP,COMPETENCY_GROUP,1
MR_GB_ASMT_STU_COMP_COMP,COMPETENCY_NUMBER,1
MR_GB_ASMT_STU_COMP_COMP,RUBRIC_NUMBER,0
MR_GB_ASMT_STU_COMP_COMP,CRITERIA_NUMBER,1
MR_GB_ASMT_STU_COMP_COMP,CHANGE_DATE_TIME,0
MR_GB_ASMT_STU_COMP_COMP,CHANGE_UID,0
MR_GB_AVG_CALC,DISTRICT,1
MR_GB_AVG_CALC,SECTION_KEY,1
MR_GB_AVG_CALC,COURSE_SESSION,1
MR_GB_AVG_CALC,AVERAGE_ID,1
MR_GB_AVG_CALC,AVERAGE_SEQUENCE,1
MR_GB_AVG_CALC,CALC_TYPE,1
MR_GB_AVG_CALC,MARK_TYPE,1
MR_GB_AVG_CALC,MARK_TYPE_MP,1
MR_GB_AVG_CALC,PERCENT_WEIGHT,0
MR_GB_AVG_CALC,CHANGE_DATE_TIME,0
MR_GB_AVG_CALC,CHANGE_UID,0
MR_GB_CAT_AVG,DISTRICT,1
MR_GB_CAT_AVG,SECTION_KEY,1
MR_GB_CAT_AVG,COURSE_SESSION,1
MR_GB_CAT_AVG,CATEGORY,1
MR_GB_CAT_AVG,MARKING_PERIOD,1
MR_GB_CAT_AVG,STUDENT_ID,1
MR_GB_CAT_AVG,OVERRIDE_AVERAGE,0
MR_GB_CAT_AVG,CHANGE_DATE_TIME,0
MR_GB_CAT_AVG,CHANGE_UID,0
MR_GB_CAT_BLD,DISTRICT,1
MR_GB_CAT_BLD,BUILDING,1
MR_GB_CAT_BLD,CODE,1
MR_GB_CAT_BLD,CHANGE_DATE_TIME,0
MR_GB_CAT_BLD,CHANGE_UID,0
MR_GB_CAT_SESS_MARK,DISTRICT,1
MR_GB_CAT_SESS_MARK,SECTION_KEY,1
MR_GB_CAT_SESS_MARK,COURSE_SESSION,1
MR_GB_CAT_SESS_MARK,MARK_TYPE,1
MR_GB_CAT_SESS_MARK,MARKING_PERIOD,1
MR_GB_CAT_SESS_MARK,CATEGORY,1
MR_GB_CAT_SESS_MARK,CATEGORY_WEIGHT,0
MR_GB_CAT_SESS_MARK,DROP_LOWEST,0
MR_GB_CAT_SESS_MARK,EXCLUDE_MISSING,0
MR_GB_CAT_SESS_MARK,CHANGE_DATE_TIME,0
MR_GB_CAT_SESS_MARK,CHANGE_UID,0
MR_GB_CAT_SESSION,DISTRICT,1
MR_GB_CAT_SESSION,SECTION_KEY,1
MR_GB_CAT_SESSION,COURSE_SESSION,1
MR_GB_CAT_SESSION,CATEGORY,1
MR_GB_CAT_SESSION,MARKING_PERIOD,1
MR_GB_CAT_SESSION,CATEGORY_WEIGHT,0
MR_GB_CAT_SESSION,DROP_LOWEST,0
MR_GB_CAT_SESSION,EXCLUDE_MISSING,0
MR_GB_CAT_SESSION,CHANGE_DATE_TIME,0
MR_GB_CAT_SESSION,CHANGE_UID,0
MR_GB_CAT_STU_COMP,DISTRICT,1
MR_GB_CAT_STU_COMP,BUILDING,1
MR_GB_CAT_STU_COMP,COMPETENCY_GROUP,1
MR_GB_CAT_STU_COMP,STAFF_ID,1
MR_GB_CAT_STU_COMP,CATEGORY,1
MR_GB_CAT_STU_COMP,CHANGE_DATE_TIME,0
MR_GB_CAT_STU_COMP,CHANGE_UID,0
MR_GB_CATEGORY_TYPE_DET,DISTRICT,1
MR_GB_CATEGORY_TYPE_DET,BUILDING,1
MR_GB_CATEGORY_TYPE_DET,SCHOOL_YEAR,1
MR_GB_CATEGORY_TYPE_DET,DURATION_TYPE,1
MR_GB_CATEGORY_TYPE_DET,CATEGORY_TYPE,1
MR_GB_CATEGORY_TYPE_DET,CATEGORY,1
MR_GB_CATEGORY_TYPE_DET,MARK_TYPE,1
MR_GB_CATEGORY_TYPE_DET,MARKING_PERIODS,1
MR_GB_CATEGORY_TYPE_DET,CATEGORY_WEIGHT,0
MR_GB_CATEGORY_TYPE_DET,DROP_LOWEST,0
MR_GB_CATEGORY_TYPE_DET,EXCLUDE_MISSING,0
MR_GB_CATEGORY_TYPE_DET,CALCULATION,0
MR_GB_CATEGORY_TYPE_DET,CHANGE_DATE_TIME,0
MR_GB_CATEGORY_TYPE_DET,CHANGE_UID,0
MR_GB_CATEGORY_TYPE_HDR,DISTRICT,1
MR_GB_CATEGORY_TYPE_HDR,BUILDING,1
MR_GB_CATEGORY_TYPE_HDR,SCHOOL_YEAR,1
MR_GB_CATEGORY_TYPE_HDR,DURATION_TYPE,1
MR_GB_CATEGORY_TYPE_HDR,CATEGORY_TYPE,1
MR_GB_CATEGORY_TYPE_HDR,DESCRIPTION,0
MR_GB_CATEGORY_TYPE_HDR,USE_TOTAL_POINTS,0
MR_GB_CATEGORY_TYPE_HDR,ROUND_TRUNC,0
MR_GB_CATEGORY_TYPE_HDR,DEFAULT_SCALE,0
MR_GB_CATEGORY_TYPE_HDR,ACTIVE,0
MR_GB_CATEGORY_TYPE_HDR,CHANGE_DATE_TIME,0
MR_GB_CATEGORY_TYPE_HDR,CHANGE_UID,0
MR_GB_COMMENT,DISTRICT,1
MR_GB_COMMENT,BUILDING,1
MR_GB_COMMENT,CODE,1
MR_GB_COMMENT,DESCRIPTION,0
MR_GB_COMMENT,CHANGE_DATE_TIME,0
MR_GB_COMMENT,CHANGE_UID,0
MR_GB_IPR_AVG,DISTRICT,1
MR_GB_IPR_AVG,SECTION_KEY,1
MR_GB_IPR_AVG,COURSE_SESSION,1
MR_GB_IPR_AVG,MARK_TYPE,1
MR_GB_IPR_AVG,IPR_DATE,1
MR_GB_IPR_AVG,MARKING_PERIOD,1
MR_GB_IPR_AVG,STUDENT_ID,1
MR_GB_IPR_AVG,OVERRIDE_AVERAGE,0
MR_GB_IPR_AVG,CHANGE_DATE_TIME,0
MR_GB_IPR_AVG,CHANGE_UID,0
MR_GB_LOAD_AVG_ERR,RUN_KEY,1
MR_GB_LOAD_AVG_ERR,STUDENT_ID,1
MR_GB_LOAD_AVG_ERR,SECTION_KEY,1
MR_GB_LOAD_AVG_ERR,COURSE_SESSION,1
MR_GB_LOAD_AVG_ERR,MARK_TYPE,1
MR_GB_LOAD_AVG_ERR,ERROR_SEQ,1
MR_GB_LOAD_AVG_ERR,ERROR_MESSAGE,0
MR_GB_MARK_AVG,DISTRICT,1
MR_GB_MARK_AVG,SECTION_KEY,1
MR_GB_MARK_AVG,COURSE_SESSION,1
MR_GB_MARK_AVG,MARK_TYPE,1
MR_GB_MARK_AVG,MARKING_PERIOD,1
MR_GB_MARK_AVG,STUDENT_ID,1
MR_GB_MARK_AVG,OVERRIDE_AVERAGE,0
MR_GB_MARK_AVG,CHANGE_DATE_TIME,0
MR_GB_MARK_AVG,CHANGE_UID,0
MR_GB_MP_MARK,DISTRICT,1
MR_GB_MP_MARK,SECTION_KEY,1
MR_GB_MP_MARK,COURSE_SESSION,1
MR_GB_MP_MARK,MARK_TYPE,1
MR_GB_MP_MARK,MARKING_PERIOD,1
MR_GB_MP_MARK,OVERRIDE,0
MR_GB_MP_MARK,ROUND_TRUNC,0
MR_GB_MP_MARK,CHANGE_DATE_TIME,0
MR_GB_MP_MARK,CHANGE_UID,0
MR_GB_RUBRIC_CRIT,DISTRICT,1
MR_GB_RUBRIC_CRIT,RUBRIC_NUMBER,1
MR_GB_RUBRIC_CRIT,CRITERIA_NUMBER,1
MR_GB_RUBRIC_CRIT,DESCRIPTION,0
MR_GB_RUBRIC_CRIT,CRITERIA_ORDER,0
MR_GB_RUBRIC_CRIT,COMPETENCY_GROUP,0
MR_GB_RUBRIC_CRIT,COMPETENCY_NUMBER,0
MR_GB_RUBRIC_CRIT,CHANGE_DATE_TIME,0
MR_GB_RUBRIC_CRIT,CHANGE_UID,0
MR_GB_RUBRIC_DET,DISTRICT,1
MR_GB_RUBRIC_DET,RUBRIC_NUMBER,1
MR_GB_RUBRIC_DET,CRITERIA_NUMBER,1
MR_GB_RUBRIC_DET,PERF_LVL_NUMBER,1
MR_GB_RUBRIC_DET,DESCRIPTION,0
MR_GB_RUBRIC_DET,MAX_POINTS,0
MR_GB_RUBRIC_DET,CHANGE_DATE_TIME,0
MR_GB_RUBRIC_DET,CHANGE_UID,0
MR_GB_RUBRIC_HDR,DISTRICT,1
MR_GB_RUBRIC_HDR,RUBRIC_NUMBER,1
MR_GB_RUBRIC_HDR,DESCRIPTION,1
MR_GB_RUBRIC_HDR,NUMBER_OF_CRITERIA,0
MR_GB_RUBRIC_HDR,NUMBER_OF_PERF_LEVEL,0
MR_GB_RUBRIC_HDR,RUBRIC_TYPE,0
MR_GB_RUBRIC_HDR,RUBRIC_STYLE,0
MR_GB_RUBRIC_HDR,RUBRIC_MODE,0
MR_GB_RUBRIC_HDR,AUTHOR,0
MR_GB_RUBRIC_HDR,DESC_DETAIL,0
MR_GB_RUBRIC_HDR,TEMPLATE,0
MR_GB_RUBRIC_HDR,ACTIVE,0
MR_GB_RUBRIC_HDR,CHANGE_DATE_TIME,0
MR_GB_RUBRIC_HDR,CHANGE_UID,0
MR_GB_RUBRIC_PERF_LVL,DISTRICT,1
MR_GB_RUBRIC_PERF_LVL,RUBRIC_NUMBER,1
MR_GB_RUBRIC_PERF_LVL,PERF_LVL_NUMBER,1
MR_GB_RUBRIC_PERF_LVL,DESCRIPTION,0
MR_GB_RUBRIC_PERF_LVL,PERF_LVL_ORDER,0
MR_GB_RUBRIC_PERF_LVL,CHANGE_DATE_TIME,0
MR_GB_RUBRIC_PERF_LVL,CHANGE_UID,0
MR_GB_SCALE,DISTRICT,1
MR_GB_SCALE,SCHOOL_YEAR,1
MR_GB_SCALE,BUILDING,1
MR_GB_SCALE,SCALE,1
MR_GB_SCALE,DESCRIPTION,0
MR_GB_SCALE,LONG_DESCRIPTION,0
MR_GB_SCALE,DEFAULT_SCALE,0
MR_GB_SCALE,CHANGE_DATE_TIME,0
MR_GB_SCALE,CHANGE_UID,0
MR_GB_SCALE_DET,DISTRICT,1
MR_GB_SCALE_DET,SCHOOL_YEAR,1
MR_GB_SCALE_DET,BUILDING,1
MR_GB_SCALE_DET,SCALE,1
MR_GB_SCALE_DET,MARK,1
MR_GB_SCALE_DET,CUTOFF,0
MR_GB_SCALE_DET,CHANGE_DATE_TIME,0
MR_GB_SCALE_DET,CHANGE_UID,0
MR_GB_SESSION_PROP,DISTRICT,1
MR_GB_SESSION_PROP,SECTION_KEY,1
MR_GB_SESSION_PROP,COURSE_SESSION,1
MR_GB_SESSION_PROP,USE_TOTAL_POINTS,0
MR_GB_SESSION_PROP,USE_CAT_WEIGHT,0
MR_GB_SESSION_PROP,ROUND_TRUNC,0
MR_GB_SESSION_PROP,DEFAULT_SCALE,0
MR_GB_SESSION_PROP,CHANGE_DATE_TIME,0
MR_GB_SESSION_PROP,CHANGE_UID,0
MR_GB_STU_ALIAS,DISTRICT,1
MR_GB_STU_ALIAS,SECTION_KEY,1
MR_GB_STU_ALIAS,COURSE_SESSION,1
MR_GB_STU_ALIAS,STUDENT_ID,1
MR_GB_STU_ALIAS,ALIAS_NAME,0
MR_GB_STU_ALIAS,DISPLAY_ORDER,0
MR_GB_STU_ALIAS,CHANGE_DATE_TIME,0
MR_GB_STU_ALIAS,CHANGE_UID,0
MR_GB_STU_ASMT_CMT,DISTRICT,1
MR_GB_STU_ASMT_CMT,SECTION_KEY,1
MR_GB_STU_ASMT_CMT,COURSE_SESSION,1
MR_GB_STU_ASMT_CMT,ASMT_NUMBER,1
MR_GB_STU_ASMT_CMT,STUDENT_ID,1
MR_GB_STU_ASMT_CMT,COMMENT_CODE,0
MR_GB_STU_ASMT_CMT,COMMENT_TEXT,0
MR_GB_STU_ASMT_CMT,PUBLISH,0
MR_GB_STU_ASMT_CMT,CHANGE_DATE_TIME,0
MR_GB_STU_ASMT_CMT,CHANGE_UID,0
MR_GB_STU_COMP_ACCUMULATED_AVG,DISTRICT,1
MR_GB_STU_COMP_ACCUMULATED_AVG,BUILDING,1
MR_GB_STU_COMP_ACCUMULATED_AVG,COMPETENCY_GROUP,1
MR_GB_STU_COMP_ACCUMULATED_AVG,STAFF_ID,1
MR_GB_STU_COMP_ACCUMULATED_AVG,COMPETENCY_NUMBER,1
MR_GB_STU_COMP_ACCUMULATED_AVG,MARKING_PERIOD,1
MR_GB_STU_COMP_ACCUMULATED_AVG,STUDENT_ID,1
MR_GB_STU_COMP_ACCUMULATED_AVG,OVERRIDE_AVERAGE,0
MR_GB_STU_COMP_ACCUMULATED_AVG,AVG_OR_RC_VALUE,0
MR_GB_STU_COMP_ACCUMULATED_AVG,RC_VALUE,0
MR_GB_STU_COMP_ACCUMULATED_AVG,CHANGE_DATE_TIME,0
MR_GB_STU_COMP_ACCUMULATED_AVG,CHANGE_UID,0
MR_GB_STU_COMP_CAT_AVG,DISTRICT,1
MR_GB_STU_COMP_CAT_AVG,BUILDING,1
MR_GB_STU_COMP_CAT_AVG,COMPETENCY_GROUP,1
MR_GB_STU_COMP_CAT_AVG,STAFF_ID,1
MR_GB_STU_COMP_CAT_AVG,CATEGORY,1
MR_GB_STU_COMP_CAT_AVG,MARKING_PERIOD,1
MR_GB_STU_COMP_CAT_AVG,STUDENT_ID,1
MR_GB_STU_COMP_CAT_AVG,OVERRIDE_AVERAGE,0
MR_GB_STU_COMP_CAT_AVG,CHANGE_DATE_TIME,0
MR_GB_STU_COMP_CAT_AVG,CHANGE_UID,0
MR_GB_STU_COMP_STU_SCORE,DISTRICT,1
MR_GB_STU_COMP_STU_SCORE,BUILDING,1
MR_GB_STU_COMP_STU_SCORE,STAFF_ID,1
MR_GB_STU_COMP_STU_SCORE,COMPETENCY_GROUP,1
MR_GB_STU_COMP_STU_SCORE,ASMT_NUMBER,1
MR_GB_STU_COMP_STU_SCORE,STUDENT_ID,1
MR_GB_STU_COMP_STU_SCORE,ASMT_SCORE,0
MR_GB_STU_COMP_STU_SCORE,ASMT_EXCEPTION,0
MR_GB_STU_COMP_STU_SCORE,ASMT_ALPHA_MARK,0
MR_GB_STU_COMP_STU_SCORE,EXCLUDE_LOWEST,0
MR_GB_STU_COMP_STU_SCORE,CHANGE_DATE_TIME,0
MR_GB_STU_COMP_STU_SCORE,CHANGE_UID,0
MR_GB_STU_COMP_STU_SCORE_HIST,DISTRICT,1
MR_GB_STU_COMP_STU_SCORE_HIST,BUILDING,1
MR_GB_STU_COMP_STU_SCORE_HIST,STAFF_ID,1
MR_GB_STU_COMP_STU_SCORE_HIST,COMPETENCY_GROUP,1
MR_GB_STU_COMP_STU_SCORE_HIST,ASMT_NUMBER,1
MR_GB_STU_COMP_STU_SCORE_HIST,STUDENT_ID,1
MR_GB_STU_COMP_STU_SCORE_HIST,SCORE_CHANGED_DATE,1
MR_GB_STU_COMP_STU_SCORE_HIST,OLD_VALUE,0
MR_GB_STU_COMP_STU_SCORE_HIST,NEW_VALUE,0
MR_GB_STU_COMP_STU_SCORE_HIST,CHANGE_TYPE,0
MR_GB_STU_COMP_STU_SCORE_HIST,PRIVATE_NOTES,0
MR_GB_STU_COMP_STU_SCORE_HIST,CHANGE_DATE_TIME,0
MR_GB_STU_COMP_STU_SCORE_HIST,CHANGE_UID,0
MR_GB_STU_COMPS_ALIAS,DISTRICT,1
MR_GB_STU_COMPS_ALIAS,BUILDING,1
MR_GB_STU_COMPS_ALIAS,COMPETENCY_GROUP,1
MR_GB_STU_COMPS_ALIAS,STAFF_ID,1
MR_GB_STU_COMPS_ALIAS,STUDENT_ID,1
MR_GB_STU_COMPS_ALIAS,ALIAS_NAME,0
MR_GB_STU_COMPS_ALIAS,DISPLAY_ORDER,0
MR_GB_STU_COMPS_ALIAS,CHANGE_DATE_TIME,0
MR_GB_STU_COMPS_ALIAS,CHANGE_UID,0
MR_GB_STU_COMPS_STU_ASMT_CMT,DISTRICT,1
MR_GB_STU_COMPS_STU_ASMT_CMT,BUILDING,1
MR_GB_STU_COMPS_STU_ASMT_CMT,COMPETENCY_GROUP,1
MR_GB_STU_COMPS_STU_ASMT_CMT,STAFF_ID,1
MR_GB_STU_COMPS_STU_ASMT_CMT,ASMT_NUMBER,1
MR_GB_STU_COMPS_STU_ASMT_CMT,STUDENT_ID,1
MR_GB_STU_COMPS_STU_ASMT_CMT,COMMENT_CODE,0
MR_GB_STU_COMPS_STU_ASMT_CMT,COMMENT_TEXT,0
MR_GB_STU_COMPS_STU_ASMT_CMT,PUBLISH,0
MR_GB_STU_COMPS_STU_ASMT_CMT,CHANGE_DATE_TIME,0
MR_GB_STU_COMPS_STU_ASMT_CMT,CHANGE_UID,0
MR_GB_STU_COMPS_STU_NOTES,DISTRICT,1
MR_GB_STU_COMPS_STU_NOTES,BUILDING,1
MR_GB_STU_COMPS_STU_NOTES,COMPETENCY_GROUP,1
MR_GB_STU_COMPS_STU_NOTES,STAFF_ID,1
MR_GB_STU_COMPS_STU_NOTES,STUDENT_ID,1
MR_GB_STU_COMPS_STU_NOTES,NOTE_DATE,1
MR_GB_STU_COMPS_STU_NOTES,STU_NOTES,0
MR_GB_STU_COMPS_STU_NOTES,PUBLISH_NOTE,0
MR_GB_STU_COMPS_STU_NOTES,CHANGE_DATE_TIME,0
MR_GB_STU_COMPS_STU_NOTES,CHANGE_UID,0
MR_GB_STU_NOTES,DISTRICT,1
MR_GB_STU_NOTES,SECTION_KEY,1
MR_GB_STU_NOTES,COURSE_SESSION,1
MR_GB_STU_NOTES,STUDENT_ID,1
MR_GB_STU_NOTES,NOTE_DATE,1
MR_GB_STU_NOTES,STU_NOTES,0
MR_GB_STU_NOTES,PUBLISH_NOTE,0
MR_GB_STU_NOTES,CHANGE_DATE_TIME,0
MR_GB_STU_NOTES,CHANGE_UID,0
MR_GB_STU_SCALE,DISTRICT,1
MR_GB_STU_SCALE,SECTION_KEY,1
MR_GB_STU_SCALE,COURSE_SESSION,1
MR_GB_STU_SCALE,MARKING_PERIOD,1
MR_GB_STU_SCALE,STUDENT_ID,1
MR_GB_STU_SCALE,SCALE,0
MR_GB_STU_SCALE,CHANGE_DATE_TIME,0
MR_GB_STU_SCALE,CHANGE_UID,0
MR_GB_STU_SCORE,DISTRICT,1
MR_GB_STU_SCORE,SECTION_KEY,1
MR_GB_STU_SCORE,COURSE_SESSION,1
MR_GB_STU_SCORE,ASMT_NUMBER,1
MR_GB_STU_SCORE,STUDENT_ID,1
MR_GB_STU_SCORE,ASMT_SCORE,0
MR_GB_STU_SCORE,ASMT_EXCEPTION,0
MR_GB_STU_SCORE,ASMT_ALPHA_MARK,0
MR_GB_STU_SCORE,EXCLUDE_LOWEST,0
MR_GB_STU_SCORE,CHANGE_DATE_TIME,0
MR_GB_STU_SCORE,CHANGE_UID,0
MR_GB_STU_SCORE,IMS_ID,0
MR_GB_STU_SCORE_HIST,DISTRICT,1
MR_GB_STU_SCORE_HIST,SECTION_KEY,1
MR_GB_STU_SCORE_HIST,COURSE_SESSION,1
MR_GB_STU_SCORE_HIST,ASMT_NUMBER,1
MR_GB_STU_SCORE_HIST,STUDENT_ID,1
MR_GB_STU_SCORE_HIST,SCORE_CHANGED_DATE,1
MR_GB_STU_SCORE_HIST,OLD_VALUE,0
MR_GB_STU_SCORE_HIST,NEW_VALUE,0
MR_GB_STU_SCORE_HIST,CHANGE_TYPE,0
MR_GB_STU_SCORE_HIST,PRIVATE_NOTES,0
MR_GB_STU_SCORE_HIST,CHANGE_DATE_TIME,0
MR_GB_STU_SCORE_HIST,CHANGE_UID,0
MR_GPA_SETUP,DISTRICT,1
MR_GPA_SETUP,GPA_TYPE,1
MR_GPA_SETUP,DESCRIPTION,0
MR_GPA_SETUP,ISSUE_GPA,0
MR_GPA_SETUP,ATT_CREDIT_TO_USE,0
MR_GPA_SETUP,USE_PARTIAL,0
MR_GPA_SETUP,COURSE_NOT_ENDED,0
MR_GPA_SETUP,BLANK_MARKS,0
MR_GPA_SETUP,INCLUDE_AS_DEFAULT,0
MR_GPA_SETUP,ACTIVE,0
MR_GPA_SETUP,GPA_PRECISION,0
MR_GPA_SETUP,RANK_INACTIVES,0
MR_GPA_SETUP,STATE_CRS_EQUIV,0
MR_GPA_SETUP,ADD_ON_POINTS,0
MR_GPA_SETUP,DISTRICT_WIDE_RANK,0
MR_GPA_SETUP,INCLUDE_PERFPLUS,0
MR_GPA_SETUP,DISPLAY_RANK,0
MR_GPA_SETUP,DISPLAY_PERCENTILE,0
MR_GPA_SETUP,DISPLAY_DECILE,0
MR_GPA_SETUP,DISPLAY_QUARTILE,0
MR_GPA_SETUP,DISPLAY_QUINTILE,0
MR_GPA_SETUP,RANK_ON_GPA,0
MR_GPA_SETUP,PERCENTILE_MODE,0
MR_GPA_SETUP,PERCENTILE_RANK_TYPE,0
MR_GPA_SETUP,CHANGE_DATE_TIME,0
MR_GPA_SETUP,CHANGE_UID,0
MR_GPA_SETUP_BLDG,DISTRICT,1
MR_GPA_SETUP_BLDG,GPA_TYPE,1
MR_GPA_SETUP_BLDG,BLDG_TYPE,1
MR_GPA_SETUP_BLDG,CHANGE_DATE_TIME,0
MR_GPA_SETUP_BLDG,CHANGE_UID,0
MR_GPA_SETUP_EXCL,DISTRICT,1
MR_GPA_SETUP_EXCL,GPA_TYPE,1
MR_GPA_SETUP_EXCL,WITH_CODE,1
MR_GPA_SETUP_EXCL,CHANGE_DATE_TIME,0
MR_GPA_SETUP_EXCL,CHANGE_UID,0
MR_GPA_SETUP_GD,DISTRICT,1
MR_GPA_SETUP_GD,GPA_TYPE,1
MR_GPA_SETUP_GD,GRADE,1
MR_GPA_SETUP_GD,CHANGE_DATE_TIME,0
MR_GPA_SETUP_GD,CHANGE_UID,0
MR_GPA_SETUP_MK_GD,DISTRICT,1
MR_GPA_SETUP_MK_GD,GPA_TYPE,1
MR_GPA_SETUP_MK_GD,MARK_ORDER,1
MR_GPA_SETUP_MK_GD,GRADE,1
MR_GPA_SETUP_MK_GD,CHANGE_DATE_TIME,0
MR_GPA_SETUP_MK_GD,CHANGE_UID,0
MR_GPA_SETUP_MRK,DISTRICT,1
MR_GPA_SETUP_MRK,GPA_TYPE,1
MR_GPA_SETUP_MRK,MARK_TYPE,1
MR_GPA_SETUP_MRK,MARK_ORDER,1
MR_GPA_SETUP_MRK,GROUP_MARKS,0
MR_GPA_SETUP_MRK,GROUP_ORDER,0
MR_GPA_SETUP_MRK,WEIGHT,0
MR_GPA_SETUP_MRK,CHANGE_DATE_TIME,0
MR_GPA_SETUP_MRK,CHANGE_UID,0
MR_GRAD_REQ_DET,DISTRICT,1
MR_GRAD_REQ_DET,REQ_GROUP,1
MR_GRAD_REQ_DET,STU_GRAD_YEAR,1
MR_GRAD_REQ_DET,REQUIRE_CODE,1
MR_GRAD_REQ_DET,REQ_ORDER,0
MR_GRAD_REQ_DET,CREDIT,0
MR_GRAD_REQ_DET,MIN_MARK_VALUE,0
MR_GRAD_REQ_DET,REQ_VALUE,0
MR_GRAD_REQ_DET,REQ_UNITS,0
MR_GRAD_REQ_DET,CHANGE_DATE_TIME,0
MR_GRAD_REQ_DET,CHANGE_UID,0
MR_GRAD_REQ_FOCUS,DISTRICT,1
MR_GRAD_REQ_FOCUS,REQ_GROUP,1
MR_GRAD_REQ_FOCUS,STU_GRAD_YEAR,1
MR_GRAD_REQ_FOCUS,REQUIRE_CODE,1
MR_GRAD_REQ_FOCUS,MAJOR_CRITERIA,1
MR_GRAD_REQ_FOCUS,MINOR_CRITERIA,1
MR_GRAD_REQ_FOCUS,CREDIT,0
MR_GRAD_REQ_FOCUS,CHANGE_DATE_TIME,0
MR_GRAD_REQ_FOCUS,CHANGE_UID,0
MR_GRAD_REQ_HDR,DISTRICT,1
MR_GRAD_REQ_HDR,REQ_GROUP,1
MR_GRAD_REQ_HDR,STU_GRAD_YEAR,1
MR_GRAD_REQ_HDR,RETAKE_COURSE_RULE,0
MR_GRAD_REQ_HDR,WAIVED,0
MR_GRAD_REQ_HDR,CHANGE_DATE_TIME,0
MR_GRAD_REQ_HDR,CHANGE_UID,0
MR_GRAD_REQ_MRK_TYPE,DISTRICT,1
MR_GRAD_REQ_MRK_TYPE,REQ_GROUP,1
MR_GRAD_REQ_MRK_TYPE,STU_GRAD_YEAR,1
MR_GRAD_REQ_MRK_TYPE,MARK_TYPE,1
MR_GRAD_REQ_MRK_TYPE,CHANGE_DATE_TIME,0
MR_GRAD_REQ_MRK_TYPE,CHANGE_UID,0
MR_GRAD_REQ_TAG_RULES,DISTRICT,1
MR_GRAD_REQ_TAG_RULES,REQ_GROUP,1
MR_GRAD_REQ_TAG_RULES,STU_GRAD_YEAR,1
MR_GRAD_REQ_TAG_RULES,REQUIRE_CODE,1
MR_GRAD_REQ_TAG_RULES,OPTION_NUMBER,1
MR_GRAD_REQ_TAG_RULES,SEQUENCE_NUM,1
MR_GRAD_REQ_TAG_RULES,AND_OR_FLAG,0
MR_GRAD_REQ_TAG_RULES,TAG,0
MR_GRAD_REQ_TAG_RULES,CREDIT,0
MR_GRAD_REQ_TAG_RULES,CHANGE_DATE_TIME,0
MR_GRAD_REQ_TAG_RULES,CHANGE_UID,0
MR_HONOR_ELIG_CD,DISTRICT,1
MR_HONOR_ELIG_CD,SCHOOL_YEAR,1
MR_HONOR_ELIG_CD,SUMMER_SCHOOL,1
MR_HONOR_ELIG_CD,BUILDING,1
MR_HONOR_ELIG_CD,HONOR_TYPE,1
MR_HONOR_ELIG_CD,SEQUENCE_ORDER,1
MR_HONOR_ELIG_CD,CURRENT_ELIG_STAT,1
MR_HONOR_ELIG_CD,ELIGIBILITY_CODE,0
MR_HONOR_ELIG_CD,CHANGE_DATE_TIME,0
MR_HONOR_ELIG_CD,CHANGE_UID,0
MR_HONOR_SETUP,DISTRICT,1
MR_HONOR_SETUP,BUILDING,1
MR_HONOR_SETUP,HONOR_TYPE,1
MR_HONOR_SETUP,DESCRIPTION,0
MR_HONOR_SETUP,HONOR_GROUP,0
MR_HONOR_SETUP,PROCESSING_ORDER,0
MR_HONOR_SETUP,PROCESS_GPA,0
MR_HONOR_SETUP,CURRENT_OR_YTD_GPA,0
MR_HONOR_SETUP,MINIMUM_GPA,0
MR_HONOR_SETUP,MAXIMUM_GPA,0
MR_HONOR_SETUP,GPA_PRECISION,0
MR_HONOR_SETUP,MINIMUM_COURSES,0
MR_HONOR_SETUP,INCLUDE_NOT_ENDED,0
MR_HONOR_SETUP,INCLUDE_NON_HR_CRS,0
MR_HONOR_SETUP,MINIMUM_ERN_CREDIT,0
MR_HONOR_SETUP,MINIMUM_ATT_CREDIT,0
MR_HONOR_SETUP,ATT_CREDIT_TO_USE,0
MR_HONOR_SETUP,USE_PARTIAL_CREDIT,0
MR_HONOR_SETUP,INCLUDE_NON_HR_CRD,0
MR_HONOR_SETUP,INCLUDE_BLANK_MARK,0
MR_HONOR_SETUP,DISQUAL_BLANK_MARK,0
MR_HONOR_SETUP,MAX_BLANK_MARK,0
MR_HONOR_SETUP,INCLUDE_AS_DEFAULT,0
MR_HONOR_SETUP,HONOR_MESSAGE,0
MR_HONOR_SETUP,ACTIVE,0
MR_HONOR_SETUP,ELIG_INCLUDE_PRIOR,0
MR_HONOR_SETUP,ELIGIBILITY_CODE,0
MR_HONOR_SETUP,ELIG_DURATION,0
MR_HONOR_SETUP,ELIG_DURATION_DAYS,0
MR_HONOR_SETUP,AT_RISK_REASON,0
MR_HONOR_SETUP,AT_RISK_RESET_NUM,0
MR_HONOR_SETUP,AT_RISK_RESET_TYPE,0
MR_HONOR_SETUP,OPTION_TYPE,0
MR_HONOR_SETUP,CHANGE_DATE_TIME,0
MR_HONOR_SETUP,CHANGE_UID,0
MR_HONOR_SETUP_ABS,DISTRICT,1
MR_HONOR_SETUP_ABS,BUILDING,1
MR_HONOR_SETUP_ABS,HONOR_TYPE,1
MR_HONOR_SETUP_ABS,ABSENCE_TYPE,1
MR_HONOR_SETUP_ABS,MAXIMUM_ABSENCES,0
MR_HONOR_SETUP_ABS,CHANGE_DATE_TIME,0
MR_HONOR_SETUP_ABS,CHANGE_UID,0
MR_HONOR_SETUP_ALT_LANG,DISTRICT,1
MR_HONOR_SETUP_ALT_LANG,BUILDING,1
MR_HONOR_SETUP_ALT_LANG,HONOR_TYPE,1
MR_HONOR_SETUP_ALT_LANG,LANGUAGE,1
MR_HONOR_SETUP_ALT_LANG,HONOR_MESSAGE,0
MR_HONOR_SETUP_ALT_LANG,CHANGE_DATE_TIME,0
MR_HONOR_SETUP_ALT_LANG,CHANGE_UID,0
MR_HONOR_SETUP_COM,DISTRICT,1
MR_HONOR_SETUP_COM,BUILDING,1
MR_HONOR_SETUP_COM,HONOR_TYPE,1
MR_HONOR_SETUP_COM,HONOR_COMMENT,1
MR_HONOR_SETUP_COM,NUM_COMMENTS,0
MR_HONOR_SETUP_COM,CHANGE_DATE_TIME,0
MR_HONOR_SETUP_COM,CHANGE_UID,0
MR_HONOR_SETUP_GD,DISTRICT,1
MR_HONOR_SETUP_GD,BUILDING,1
MR_HONOR_SETUP_GD,HONOR_TYPE,1
MR_HONOR_SETUP_GD,GRADE,1
MR_HONOR_SETUP_GD,CHANGE_DATE_TIME,0
MR_HONOR_SETUP_GD,CHANGE_UID,0
MR_HONOR_SETUP_MKS,DISTRICT,1
MR_HONOR_SETUP_MKS,BUILDING,1
MR_HONOR_SETUP_MKS,HONOR_TYPE,1
MR_HONOR_SETUP_MKS,MARK_TYPE,1
MR_HONOR_SETUP_MKS,MARK_ORDER,1
MR_HONOR_SETUP_MKS,CHANGE_DATE_TIME,0
MR_HONOR_SETUP_MKS,CHANGE_UID,0
MR_HONOR_SETUP_Q_D,DISTRICT,1
MR_HONOR_SETUP_Q_D,BUILDING,1
MR_HONOR_SETUP_Q_D,HONOR_TYPE,1
MR_HONOR_SETUP_Q_D,QUALIFY_DISQUALIFY,1
MR_HONOR_SETUP_Q_D,SEQUENCE_NUM,1
MR_HONOR_SETUP_Q_D,NUMBER_OF_MARKS,0
MR_HONOR_SETUP_Q_D,MINIMUM_MARK,0
MR_HONOR_SETUP_Q_D,MAXIMUM_MARK,0
MR_HONOR_SETUP_Q_D,COURSE_LEVEL,0
MR_HONOR_SETUP_Q_D,CHANGE_DATE_TIME,0
MR_HONOR_SETUP_Q_D,CHANGE_UID,0
MR_IMPORT_STU_CRS_DET,DISTRICT,1
MR_IMPORT_STU_CRS_DET,STUDENT_ID,1
MR_IMPORT_STU_CRS_DET,SESSION_SEQ,1
MR_IMPORT_STU_CRS_DET,COURSE_SEQ,1
MR_IMPORT_STU_CRS_DET,DESCRIPTION,0
MR_IMPORT_STU_CRS_DET,STATE_CODE,0
MR_IMPORT_STU_CRS_DET,ABBREVIATION,0
MR_IMPORT_STU_CRS_DET,SEMESTER,0
MR_IMPORT_STU_CRS_DET,CLASS_PERIOD,0
MR_IMPORT_STU_CRS_DET,SEMESTER_SEQ,0
MR_IMPORT_STU_CRS_DET,DEPARTMENT,0
MR_IMPORT_STU_CRS_DET,WITHDRAW_GRADE,0
MR_IMPORT_STU_CRS_DET,GRADE_AVERAGE,0
MR_IMPORT_STU_CRS_DET,EARNED_CREDIT,0
MR_IMPORT_STU_CRS_DET,PASS_FAIL_CREDIT,0
MR_IMPORT_STU_CRS_DET,EXPLANATION,0
MR_IMPORT_STU_CRS_DET,COURSE_TEACHER,0
MR_IMPORT_STU_CRS_DET,CREDIT_CAMPUS,0
MR_IMPORT_STU_CRS_DET,CHANGE_DATE_TIME,0
MR_IMPORT_STU_CRS_DET,CHANGE_UID,0
MR_IMPORT_STU_CRS_GRADES,DISTRICT,1
MR_IMPORT_STU_CRS_GRADES,STUDENT_ID,1
MR_IMPORT_STU_CRS_GRADES,SESSION_SEQ,1
MR_IMPORT_STU_CRS_GRADES,COURSE_SEQ,1
MR_IMPORT_STU_CRS_GRADES,GRADE_SEQ,1
MR_IMPORT_STU_CRS_GRADES,COURSE_GRADE,0
MR_IMPORT_STU_CRS_GRADES,CHANGE_DATE_TIME,0
MR_IMPORT_STU_CRS_GRADES,CHANGE_UID,0
MR_IMPORT_STU_CRS_HDR,DISTRICT,1
MR_IMPORT_STU_CRS_HDR,STUDENT_ID,1
MR_IMPORT_STU_CRS_HDR,SESSION_SEQ,1
MR_IMPORT_STU_CRS_HDR,SCHOOL_YEAR,0
MR_IMPORT_STU_CRS_HDR,GRADE,0
MR_IMPORT_STU_CRS_HDR,SESSION_TYPE,0
MR_IMPORT_STU_CRS_HDR,GPA,0
MR_IMPORT_STU_CRS_HDR,CLASS_SIZE,0
MR_IMPORT_STU_CRS_HDR,CLASS_RANK,0
MR_IMPORT_STU_CRS_HDR,RANK_CALC_DATE,0
MR_IMPORT_STU_CRS_HDR,RANK_QUARTILE,0
MR_IMPORT_STU_CRS_HDR,COLLEGE_CAMPUS,0
MR_IMPORT_STU_CRS_HDR,CHANGE_DATE_TIME,0
MR_IMPORT_STU_CRS_HDR,CHANGE_UID,0
MR_IPR_ELIG_CD,DISTRICT,1
MR_IPR_ELIG_CD,SCHOOL_YEAR,1
MR_IPR_ELIG_CD,SUMMER_SCHOOL,1
MR_IPR_ELIG_CD,BUILDING,1
MR_IPR_ELIG_CD,ELIG_TYPE,1
MR_IPR_ELIG_CD,SEQUENCE_ORDER,1
MR_IPR_ELIG_CD,CURRENT_ELIG_STATUS,1
MR_IPR_ELIG_CD,ELIGIBILITY_CODE,0
MR_IPR_ELIG_CD,CHANGE_DATE_TIME,0
MR_IPR_ELIG_CD,CHANGE_UID,0
MR_IPR_ELIG_SETUP,DISTRICT,1
MR_IPR_ELIG_SETUP,BUILDING,1
MR_IPR_ELIG_SETUP,ELIG_TYPE,1
MR_IPR_ELIG_SETUP,DESCRIPTION,0
MR_IPR_ELIG_SETUP,PROCESSING_ORDER,0
MR_IPR_ELIG_SETUP,MINIMUM_COURSES,0
MR_IPR_ELIG_SETUP,INCLUDE_NOT_ENDED,0
MR_IPR_ELIG_SETUP,INCLUDE_BLANK_MARK,0
MR_IPR_ELIG_SETUP,DISQUAL_BLANK_MARK,0
MR_IPR_ELIG_SETUP,MAX_BLANK_MARK,0
MR_IPR_ELIG_SETUP,ACTIVE,0
MR_IPR_ELIG_SETUP,ELIG_INCLUDE_PRIOR,0
MR_IPR_ELIG_SETUP,ELIGIBILITY_CODE,0
MR_IPR_ELIG_SETUP,ELIG_DURATION,0
MR_IPR_ELIG_SETUP,ELIG_DURATION_DAYS,0
MR_IPR_ELIG_SETUP,USE_AT_RISK,0
MR_IPR_ELIG_SETUP,AT_RISK_REASON,0
MR_IPR_ELIG_SETUP,AT_RISK_DURATION,0
MR_IPR_ELIG_SETUP,AT_RISK_DAYS,0
MR_IPR_ELIG_SETUP,CHANGE_DATE_TIME,0
MR_IPR_ELIG_SETUP,CHANGE_UID,0
MR_IPR_ELIG_SETUP_ABS,DISTRICT,1
MR_IPR_ELIG_SETUP_ABS,BUILDING,1
MR_IPR_ELIG_SETUP_ABS,ELIG_TYPE,1
MR_IPR_ELIG_SETUP_ABS,ABSENCE_TYPE,1
MR_IPR_ELIG_SETUP_ABS,MAXIMUM_ABSENCES,0
MR_IPR_ELIG_SETUP_ABS,CHANGE_DATE_TIME,0
MR_IPR_ELIG_SETUP_ABS,CHANGE_UID,0
MR_IPR_ELIG_SETUP_COM,DISTRICT,1
MR_IPR_ELIG_SETUP_COM,BUILDING,1
MR_IPR_ELIG_SETUP_COM,ELIG_TYPE,1
MR_IPR_ELIG_SETUP_COM,ELIG_COMMENT,1
MR_IPR_ELIG_SETUP_COM,CHANGE_DATE_TIME,0
MR_IPR_ELIG_SETUP_COM,CHANGE_UID,0
MR_IPR_ELIG_SETUP_GD,DISTRICT,1
MR_IPR_ELIG_SETUP_GD,BUILDING,1
MR_IPR_ELIG_SETUP_GD,ELIG_TYPE,1
MR_IPR_ELIG_SETUP_GD,GRADE,1
MR_IPR_ELIG_SETUP_GD,CHANGE_DATE_TIME,0
MR_IPR_ELIG_SETUP_GD,CHANGE_UID,0
MR_IPR_ELIG_SETUP_MKS,DISTRICT,1
MR_IPR_ELIG_SETUP_MKS,BUILDING,1
MR_IPR_ELIG_SETUP_MKS,ELIG_TYPE,1
MR_IPR_ELIG_SETUP_MKS,MARK_TYPE,1
MR_IPR_ELIG_SETUP_MKS,MARK_ORDER,1
MR_IPR_ELIG_SETUP_MKS,CHANGE_DATE_TIME,0
MR_IPR_ELIG_SETUP_MKS,CHANGE_UID,0
MR_IPR_ELIG_SETUP_Q_D,DISTRICT,1
MR_IPR_ELIG_SETUP_Q_D,BUILDING,1
MR_IPR_ELIG_SETUP_Q_D,ELIG_TYPE,1
MR_IPR_ELIG_SETUP_Q_D,QUALIFY_DISQUALIFY,1
MR_IPR_ELIG_SETUP_Q_D,SEQUENCE_NUM,1
MR_IPR_ELIG_SETUP_Q_D,NUMBER_OF_MARKS,0
MR_IPR_ELIG_SETUP_Q_D,MINIMUM_MARK,0
MR_IPR_ELIG_SETUP_Q_D,MAXIMUM_MARK,0
MR_IPR_ELIG_SETUP_Q_D,COURSE_LEVEL,0
MR_IPR_ELIG_SETUP_Q_D,CHANGE_DATE_TIME,0
MR_IPR_ELIG_SETUP_Q_D,CHANGE_UID,0
MR_IPR_PRINT_HDR,DISTRICT,1
MR_IPR_PRINT_HDR,SCHOOL_YEAR,1
MR_IPR_PRINT_HDR,BUILDING,1
MR_IPR_PRINT_HDR,IPR_DATE,1
MR_IPR_PRINT_HDR,GRADE,1
MR_IPR_PRINT_HDR,RUN_DATE,0
MR_IPR_PRINT_HDR,HEADER_TEXT,0
MR_IPR_PRINT_HDR,FOOTER_TEXT,0
MR_IPR_PRINT_HDR,DATA_TITLE_01,0
MR_IPR_PRINT_HDR,DATA_TITLE_02,0
MR_IPR_PRINT_HDR,DATA_TITLE_03,0
MR_IPR_PRINT_HDR,DATA_TITLE_04,0
MR_IPR_PRINT_HDR,DATA_TITLE_05,0
MR_IPR_PRINT_HDR,DATA_TITLE_06,0
MR_IPR_PRINT_HDR,DATA_TITLE_07,0
MR_IPR_PRINT_HDR,DATA_TITLE_08,0
MR_IPR_PRINT_HDR,DATA_TITLE_09,0
MR_IPR_PRINT_HDR,DATA_TITLE_10,0
MR_IPR_PRINT_HDR,DATA_TITLE_11,0
MR_IPR_PRINT_HDR,DATA_TITLE_12,0
MR_IPR_PRINT_HDR,DATA_TITLE_13,0
MR_IPR_PRINT_HDR,DATA_TITLE_14,0
MR_IPR_PRINT_HDR,DATA_TITLE_15,0
MR_IPR_PRINT_HDR,DATA_TITLE_16,0
MR_IPR_PRINT_HDR,DATA_TITLE_17,0
MR_IPR_PRINT_HDR,DATA_TITLE_18,0
MR_IPR_PRINT_HDR,DATA_TITLE_19,0
MR_IPR_PRINT_HDR,DATA_TITLE_20,0
MR_IPR_PRINT_HDR,DATA_TITLE_21,0
MR_IPR_PRINT_HDR,DATA_TITLE_22,0
MR_IPR_PRINT_HDR,DATA_TITLE_23,0
MR_IPR_PRINT_HDR,DATA_TITLE_24,0
MR_IPR_PRINT_HDR,DATA_TITLE_25,0
MR_IPR_PRINT_HDR,DATA_TITLE_26,0
MR_IPR_PRINT_HDR,DATA_TITLE_27,0
MR_IPR_PRINT_HDR,DATA_TITLE_28,0
MR_IPR_PRINT_HDR,DATA_TITLE_29,0
MR_IPR_PRINT_HDR,DATA_TITLE_30,0
MR_IPR_PRINT_HDR,IPR_PRINT_KEY,0
MR_IPR_PRINT_HDR,CHANGE_DATE_TIME,0
MR_IPR_PRINT_HDR,CHANGE_UID,0
MR_IPR_PRT_STU_COM,IPR_PRINT_KEY,1
MR_IPR_PRT_STU_COM,STUDENT_ID,1
MR_IPR_PRT_STU_COM,SECTION_KEY,1
MR_IPR_PRT_STU_COM,COURSE_SESSION,1
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_01,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_02,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_03,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_04,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_05,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_06,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_07,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_08,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_09,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_10,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_11,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_12,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_13,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_14,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_15,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_16,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_17,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_18,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_19,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_20,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_21,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_22,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_23,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_24,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_25,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_26,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_27,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_28,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_29,0
MR_IPR_PRT_STU_COM,IPR_DATA_DESCR_30,0
MR_IPR_PRT_STU_COM,CHANGE_DATE_TIME,0
MR_IPR_PRT_STU_COM,CHANGE_UID,0
MR_IPR_PRT_STU_DET,IPR_PRINT_KEY,1
MR_IPR_PRT_STU_DET,STUDENT_ID,1
MR_IPR_PRT_STU_DET,SECTION_KEY,1
MR_IPR_PRT_STU_DET,COURSE_BUILDING,0
MR_IPR_PRT_STU_DET,COURSE,0
MR_IPR_PRT_STU_DET,COURSE_SECTION,0
MR_IPR_PRT_STU_DET,COURSE_SESSION,1
MR_IPR_PRT_STU_DET,DESCRIPTION,0
MR_IPR_PRT_STU_DET,CRS_PERIOD,0
MR_IPR_PRT_STU_DET,PRIMARY_STAFF_ID,0
MR_IPR_PRT_STU_DET,STAFF_NAME,0
MR_IPR_PRT_STU_DET,ROOM_ID,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_01,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_02,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_03,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_04,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_05,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_06,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_07,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_08,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_09,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_10,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_11,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_12,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_13,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_14,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_15,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_16,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_17,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_18,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_19,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_20,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_21,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_22,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_23,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_24,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_25,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_26,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_27,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_28,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_29,0
MR_IPR_PRT_STU_DET,IPR_DATA_VALUE_30,0
MR_IPR_PRT_STU_DET,CHANGE_DATE_TIME,0
MR_IPR_PRT_STU_DET,CHANGE_UID,0
MR_IPR_PRT_STU_HDR,IPR_PRINT_KEY,1
MR_IPR_PRT_STU_HDR,STUDENT_ID,1
MR_IPR_PRT_STU_HDR,STUDENT_NAME,0
MR_IPR_PRT_STU_HDR,BUILDING,0
MR_IPR_PRT_STU_HDR,GRADE,0
MR_IPR_PRT_STU_HDR,TRACK,0
MR_IPR_PRT_STU_HDR,COUNSELOR,0
MR_IPR_PRT_STU_HDR,HOUSE_TEAM,0
MR_IPR_PRT_STU_HDR,HOMEROOM_PRIMARY,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_DESCR_01,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_DESCR_02,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_DESCR_03,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_DESCR_04,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_DESCR_05,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_DESCR_06,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_DESCR_07,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_DESCR_08,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_DESCR_09,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_DESCR_10,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_CURR_01,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_CURR_02,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_CURR_03,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_CURR_04,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_CURR_05,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_CURR_06,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_CURR_07,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_CURR_08,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_CURR_09,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_CURR_10,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_YTD_01,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_YTD_02,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_YTD_03,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_YTD_04,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_YTD_05,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_YTD_06,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_YTD_07,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_YTD_08,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_YTD_09,0
MR_IPR_PRT_STU_HDR,DAILY_ATT_YTD_10,0
MR_IPR_PRT_STU_HDR,REPORT_TEMPLATE,0
MR_IPR_PRT_STU_HDR,CHANGE_DATE_TIME,0
MR_IPR_PRT_STU_HDR,CHANGE_UID,0
MR_IPR_PRT_STU_MSG,IPR_PRINT_KEY,1
MR_IPR_PRT_STU_MSG,STUDENT_ID,1
MR_IPR_PRT_STU_MSG,SECTION_KEY,1
MR_IPR_PRT_STU_MSG,COURSE_SESSION,1
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_01,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_02,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_03,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_04,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_05,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_06,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_07,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_08,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_09,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_10,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_11,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_12,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_13,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_14,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_15,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_16,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_17,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_18,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_19,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_20,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_21,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_22,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_23,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_24,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_25,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_26,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_27,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_28,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_29,0
MR_IPR_PRT_STU_MSG,IPR_MESSAGE_30,0
MR_IPR_PRT_STU_MSG,CHANGE_DATE_TIME,0
MR_IPR_PRT_STU_MSG,CHANGE_UID,0
MR_IPR_RUN,DISTRICT,1
MR_IPR_RUN,SCHOOL_YEAR,1
MR_IPR_RUN,BUILDING,1
MR_IPR_RUN,TRACK,1
MR_IPR_RUN,RUN_DATE,1
MR_IPR_RUN,ELIGIBILITY,0
MR_IPR_RUN,CHANGE_DATE_TIME,0
MR_IPR_RUN,CHANGE_UID,0
MR_IPR_STU_ABS,DISTRICT,1
MR_IPR_STU_ABS,STUDENT_ID,1
MR_IPR_STU_ABS,SECTION_KEY,1
MR_IPR_STU_ABS,COURSE_SESSION,1
MR_IPR_STU_ABS,IPR_DATE,1
MR_IPR_STU_ABS,ABSENCE_TYPE,1
MR_IPR_STU_ABS,ABSENCE_VALUE,0
MR_IPR_STU_ABS,OVERRIDE,0
MR_IPR_STU_ABS,CHANGE_DATE_TIME,0
MR_IPR_STU_ABS,CHANGE_UID,0
MR_IPR_STU_AT_RISK,DISTRICT,1
MR_IPR_STU_AT_RISK,SCHOOL_YEAR,1
MR_IPR_STU_AT_RISK,SUMMER_SCHOOL,1
MR_IPR_STU_AT_RISK,BUILDING,1
MR_IPR_STU_AT_RISK,STUDENT_ID,1
MR_IPR_STU_AT_RISK,IPR_DATE,1
MR_IPR_STU_AT_RISK,AT_RISK_TYPE,1
MR_IPR_STU_AT_RISK,DISQUAL_REASON,0
MR_IPR_STU_AT_RISK,AT_RISK_REASON,0
MR_IPR_STU_AT_RISK,EFFECTIVE_DATE,0
MR_IPR_STU_AT_RISK,EXPIRATION_DATE,0
MR_IPR_STU_AT_RISK,PLAN_NUM,0
MR_IPR_STU_AT_RISK,CHANGE_DATE_TIME,0
MR_IPR_STU_AT_RISK,CHANGE_UID,0
MR_IPR_STU_COM,DISTRICT,1
MR_IPR_STU_COM,STUDENT_ID,1
MR_IPR_STU_COM,SECTION_KEY,1
MR_IPR_STU_COM,COURSE_SESSION,1
MR_IPR_STU_COM,IPR_DATE,1
MR_IPR_STU_COM,COMMENT_TYPE,1
MR_IPR_STU_COM,COMMENT_VALUE,0
MR_IPR_STU_COM,CHANGE_DATE_TIME,0
MR_IPR_STU_COM,CHANGE_UID,0
MR_IPR_STU_ELIGIBLE,DISTRICT,1
MR_IPR_STU_ELIGIBLE,SCHOOL_YEAR,1
MR_IPR_STU_ELIGIBLE,SUMMER_SCHOOL,1
MR_IPR_STU_ELIGIBLE,BUILDING,1
MR_IPR_STU_ELIGIBLE,STUDENT_ID,1
MR_IPR_STU_ELIGIBLE,IPR_DATE,1
MR_IPR_STU_ELIGIBLE,DISQUAL_REASON,0
MR_IPR_STU_ELIGIBLE,ELIG_TYPE,1
MR_IPR_STU_ELIGIBLE,ELIGIBILITY_CODE,0
MR_IPR_STU_ELIGIBLE,EFFECTIVE_DATE,0
MR_IPR_STU_ELIGIBLE,EXPIRATION_DATE,0
MR_IPR_STU_ELIGIBLE,CHANGE_DATE_TIME,0
MR_IPR_STU_ELIGIBLE,CHANGE_UID,0
MR_IPR_STU_HDR,DISTRICT,1
MR_IPR_STU_HDR,STUDENT_ID,1
MR_IPR_STU_HDR,SECTION_KEY,1
MR_IPR_STU_HDR,COURSE_SESSION,1
MR_IPR_STU_HDR,IPR_DATE,1
MR_IPR_STU_HDR,INDIVIDUAL_IPR,0
MR_IPR_STU_HDR,CHANGE_DATE_TIME,0
MR_IPR_STU_HDR,CHANGE_UID,0
MR_IPR_STU_MARKS,DISTRICT,1
MR_IPR_STU_MARKS,STUDENT_ID,1
MR_IPR_STU_MARKS,SECTION_KEY,1
MR_IPR_STU_MARKS,COURSE_SESSION,1
MR_IPR_STU_MARKS,IPR_DATE,1
MR_IPR_STU_MARKS,MARK_TYPE,1
MR_IPR_STU_MARKS,MARK_VALUE,0
MR_IPR_STU_MARKS,CHANGE_DATE_TIME,0
MR_IPR_STU_MARKS,CHANGE_UID,0
MR_IPR_STU_MESSAGE,DISTRICT,1
MR_IPR_STU_MESSAGE,STUDENT_ID,1
MR_IPR_STU_MESSAGE,SECTION_KEY,1
MR_IPR_STU_MESSAGE,COURSE_SESSION,1
MR_IPR_STU_MESSAGE,IPR_DATE,1
MR_IPR_STU_MESSAGE,MESSAGE_ORDER,1
MR_IPR_STU_MESSAGE,MESSAGE_VALUE,0
MR_IPR_STU_MESSAGE,CHANGE_DATE_TIME,0
MR_IPR_STU_MESSAGE,CHANGE_UID,0
MR_IPR_TAKEN,DISTRICT,1
MR_IPR_TAKEN,SECTION_KEY,1
MR_IPR_TAKEN,COURSE_SESSION,1
MR_IPR_TAKEN,RUN_DATE,1
MR_IPR_TAKEN,CHANGE_DATE_TIME,0
MR_IPR_TAKEN,CHANGE_UID,0
MR_IPR_VIEW_ATT,DISTRICT,1
MR_IPR_VIEW_ATT,SCHOOL_YEAR,1
MR_IPR_VIEW_ATT,BUILDING,1
MR_IPR_VIEW_ATT,VIEW_TYPE,1
MR_IPR_VIEW_ATT,GRADE,1
MR_IPR_VIEW_ATT,ATT_VIEW_TYPE,0
MR_IPR_VIEW_ATT,VIEW_ORDER,1
MR_IPR_VIEW_ATT,ATT_TITLE,0
MR_IPR_VIEW_ATT,ATT_VIEW_INTERVAL,0
MR_IPR_VIEW_ATT,ATT_VIEW_SUM_BY,0
MR_IPR_VIEW_ATT,ATT_VIEW_CODE_GRP,0
MR_IPR_VIEW_ATT,CHANGE_DATE_TIME,0
MR_IPR_VIEW_ATT,CHANGE_UID,0
MR_IPR_VIEW_ATT_IT,DISTRICT,1
MR_IPR_VIEW_ATT_IT,SCHOOL_YEAR,1
MR_IPR_VIEW_ATT_IT,BUILDING,1
MR_IPR_VIEW_ATT_IT,VIEW_TYPE,1
MR_IPR_VIEW_ATT_IT,GRADE,1
MR_IPR_VIEW_ATT_IT,VIEW_ORDER,1
MR_IPR_VIEW_ATT_IT,ATT_VIEW_INTERVAL,1
MR_IPR_VIEW_ATT_IT,CHANGE_DATE_TIME,0
MR_IPR_VIEW_ATT_IT,CHANGE_UID,0
MR_IPR_VIEW_DET,DISTRICT,1
MR_IPR_VIEW_DET,SCHOOL_YEAR,1
MR_IPR_VIEW_DET,BUILDING,1
MR_IPR_VIEW_DET,VIEW_TYPE,1
MR_IPR_VIEW_DET,GRADE,1
MR_IPR_VIEW_DET,VIEW_SEQUENCE,1
MR_IPR_VIEW_DET,VIEW_ORDER,0
MR_IPR_VIEW_DET,SLOT_TYPE,0
MR_IPR_VIEW_DET,SLOT_CODE,0
MR_IPR_VIEW_DET,TITLE,0
MR_IPR_VIEW_DET,CHANGE_DATE_TIME,0
MR_IPR_VIEW_DET,CHANGE_UID,0
MR_IPR_VIEW_HDR,DISTRICT,1
MR_IPR_VIEW_HDR,SCHOOL_YEAR,1
MR_IPR_VIEW_HDR,BUILDING,1
MR_IPR_VIEW_HDR,VIEW_TYPE,1
MR_IPR_VIEW_HDR,GRADE,1
MR_IPR_VIEW_HDR,REPORT_TEMPLATE,0
MR_IPR_VIEW_HDR,PRINT_DROPPED_CRS,0
MR_IPR_VIEW_HDR,PRINT_LEGEND,0
MR_IPR_VIEW_HDR,PRINT_MBS,0
MR_IPR_VIEW_HDR,HEADER_TEXT,0
MR_IPR_VIEW_HDR,FOOTER_TEXT,0
MR_IPR_VIEW_HDR,CHANGE_DATE_TIME,0
MR_IPR_VIEW_HDR,CHANGE_UID,0
MR_LEVEL_DET,DISTRICT,1
MR_LEVEL_DET,BUILDING,1
MR_LEVEL_DET,LEVEL_NUMBER,1
MR_LEVEL_DET,MARK,1
MR_LEVEL_DET,NUMERIC_VALUE,0
MR_LEVEL_DET,POINT_VALUE,0
MR_LEVEL_DET,PASSING_MARK,0
MR_LEVEL_DET,RC_PRINT_VALUE,0
MR_LEVEL_DET,TRN_PRINT_VALUE,0
MR_LEVEL_DET,IPR_PRINT_VALUE,0
MR_LEVEL_DET,ADDON_POINTS,0
MR_LEVEL_DET,WEIGHT_BY_CRED,0
MR_LEVEL_DET,AVERAGE_USAGE,0
MR_LEVEL_DET,STATE_CODE_EQUIV,0
MR_LEVEL_DET,COLOR_LEVEL,0
MR_LEVEL_DET,ROW_IDENTITY,0
MR_LEVEL_DET,CHANGE_DATE_TIME,0
MR_LEVEL_DET,CHANGE_UID,0
MR_LEVEL_GPA,DISTRICT,1
MR_LEVEL_GPA,BUILDING,1
MR_LEVEL_GPA,LEVEL_NUMBER,1
MR_LEVEL_GPA,MARK,1
MR_LEVEL_GPA,GPA_TYPE,1
MR_LEVEL_GPA,CHANGE_DATE_TIME,0
MR_LEVEL_GPA,CHANGE_UID,0
MR_LEVEL_HDR,DISTRICT,1
MR_LEVEL_HDR,BUILDING,1
MR_LEVEL_HDR,LEVEL_NUMBER,1
MR_LEVEL_HDR,DESCRIPTION,0
MR_LEVEL_HDR,ACTIVE,0
MR_LEVEL_HDR,PESC_CODE,0
MR_LEVEL_HDR,ROW_IDENTITY,0
MR_LEVEL_HDR,CHANGE_DATE_TIME,0
MR_LEVEL_HDR,CHANGE_UID,0
MR_LEVEL_HONOR,DISTRICT,1
MR_LEVEL_HONOR,BUILDING,1
MR_LEVEL_HONOR,LEVEL_NUMBER,1
MR_LEVEL_HONOR,MARK,1
MR_LEVEL_HONOR,HONOR_TYPE,1
MR_LEVEL_HONOR,CHANGE_DATE_TIME,0
MR_LEVEL_HONOR,CHANGE_UID,0
MR_LEVEL_MARKS,DISTRICT,1
MR_LEVEL_MARKS,BUILDING,1
MR_LEVEL_MARKS,MARK,1
MR_LEVEL_MARKS,DISPLAY_ORDER,0
MR_LEVEL_MARKS,ACTIVE,0
MR_LEVEL_MARKS,STATE_CODE_EQUIV,0
MR_LEVEL_MARKS,COURSE_COMPLETED,0
MR_LEVEL_MARKS,CHANGE_DATE_TIME,0
MR_LEVEL_MARKS,CHANGE_UID,0
MR_LTDB_MARK_DTL,DISTRICT,1
MR_LTDB_MARK_DTL,CODE,1
MR_LTDB_MARK_DTL,LOW_VALUE,1
MR_LTDB_MARK_DTL,HIGH_VALUE,0
MR_LTDB_MARK_DTL,EQUIVALENT,0
MR_LTDB_MARK_DTL,CHANGE_DATE_TIME,0
MR_LTDB_MARK_DTL,CHANGE_UID,0
MR_LTDB_MARK_HDR,DISTRICT,1
MR_LTDB_MARK_HDR,CODE,1
MR_LTDB_MARK_HDR,DESCRIPTION,0
MR_LTDB_MARK_HDR,ACTIVE,0
MR_LTDB_MARK_HDR,CHANGE_DATE_TIME,0
MR_LTDB_MARK_HDR,CHANGE_UID,0
MR_MARK_ISSUED_AT,DISTRICT,1
MR_MARK_ISSUED_AT,BUILDING,1
MR_MARK_ISSUED_AT,MARK_TYPE,1
MR_MARK_ISSUED_AT,MARKING_PERIOD,1
MR_MARK_ISSUED_AT,CHANGE_DATE_TIME,0
MR_MARK_ISSUED_AT,CHANGE_UID,0
MR_MARK_SUBS,DISTRICT,1
MR_MARK_SUBS,SCHOOL_YEAR,1
MR_MARK_SUBS,BUILDING,1
MR_MARK_SUBS,LOW_RANGE,1
MR_MARK_SUBS,HIGH_RANGE,0
MR_MARK_SUBS,REPLACE_MARK,0
MR_MARK_SUBS,CHANGE_DATE_TIME,0
MR_MARK_SUBS,CHANGE_UID,0
MR_MARK_TYPES,DISTRICT,1
MR_MARK_TYPES,BUILDING,1
MR_MARK_TYPES,MARK_TYPE,1
MR_MARK_TYPES,MARK_ORDER,0
MR_MARK_TYPES,MARK_WHEN,0
MR_MARK_TYPES,DESCRIPTION,0
MR_MARK_TYPES,INCLUDE_AS_DEFAULT,0
MR_MARK_TYPES,REQUIRED,0
MR_MARK_TYPES,ACTIVE,0
MR_MARK_TYPES,TWS_ACCESS,0
MR_MARK_TYPES,RECEIVE_GB_RESULT,0
MR_MARK_TYPES,INCLUDE_PERFPLUS,0
MR_MARK_TYPES,ROW_IDENTITY,0
MR_MARK_TYPES,CHANGE_DATE_TIME,0
MR_MARK_TYPES,CHANGE_UID,0
MR_MARK_TYPES,STATE_CODE_EQUIV,0
MR_MARK_TYPES_LMS_MAP,DISTRICT,1
MR_MARK_TYPES_LMS_MAP,BUILDING,1
MR_MARK_TYPES_LMS_MAP,MARK_TYPE,1
MR_MARK_TYPES_LMS_MAP,MARK_TYPE_EQUIV,0
MR_MARK_TYPES_LMS_MAP,CHANGE_DATE_TIME,0
MR_MARK_TYPES_LMS_MAP,CHANGE_UID,0
MR_MARK_VALID,DISTRICT,1
MR_MARK_VALID,BUILDING,1
MR_MARK_VALID,MARK_TYPE,1
MR_MARK_VALID,MARK,1
MR_MARK_VALID,CHANGE_DATE_TIME,0
MR_MARK_VALID,CHANGE_UID,0
MR_PRINT_GD_SCALE,MR_PRINT_KEY,1
MR_PRINT_GD_SCALE,STUDENT_ID,1
MR_PRINT_GD_SCALE,PRINT_ORDER,0
MR_PRINT_GD_SCALE,GRADING_SCALE_TYPE,1
MR_PRINT_GD_SCALE,GRADING_SCALE_DESC,0
MR_PRINT_GD_SCALE,MARK_01,0
MR_PRINT_GD_SCALE,MARK_02,0
MR_PRINT_GD_SCALE,MARK_03,0
MR_PRINT_GD_SCALE,MARK_04,0
MR_PRINT_GD_SCALE,MARK_05,0
MR_PRINT_GD_SCALE,MARK_06,0
MR_PRINT_GD_SCALE,MARK_07,0
MR_PRINT_GD_SCALE,MARK_08,0
MR_PRINT_GD_SCALE,MARK_09,0
MR_PRINT_GD_SCALE,MARK_10,0
MR_PRINT_GD_SCALE,MARK_11,0
MR_PRINT_GD_SCALE,MARK_12,0
MR_PRINT_GD_SCALE,MARK_13,0
MR_PRINT_GD_SCALE,MARK_14,0
MR_PRINT_GD_SCALE,MARK_15,0
MR_PRINT_GD_SCALE,MARK_16,0
MR_PRINT_GD_SCALE,MARK_17,0
MR_PRINT_GD_SCALE,MARK_18,0
MR_PRINT_GD_SCALE,MARK_19,0
MR_PRINT_GD_SCALE,MARK_20,0
MR_PRINT_GD_SCALE,MARK_21,0
MR_PRINT_GD_SCALE,MARK_22,0
MR_PRINT_GD_SCALE,MARK_23,0
MR_PRINT_GD_SCALE,MARK_24,0
MR_PRINT_GD_SCALE,MARK_25,0
MR_PRINT_GD_SCALE,MARK_26,0
MR_PRINT_GD_SCALE,MARK_27,0
MR_PRINT_GD_SCALE,MARK_28,0
MR_PRINT_GD_SCALE,MARK_29,0
MR_PRINT_GD_SCALE,MARK_30,0
MR_PRINT_GD_SCALE,MARK_DESCR_01,0
MR_PRINT_GD_SCALE,MARK_DESCR_02,0
MR_PRINT_GD_SCALE,MARK_DESCR_03,0
MR_PRINT_GD_SCALE,MARK_DESCR_04,0
MR_PRINT_GD_SCALE,MARK_DESCR_05,0
MR_PRINT_GD_SCALE,MARK_DESCR_06,0
MR_PRINT_GD_SCALE,MARK_DESCR_07,0
MR_PRINT_GD_SCALE,MARK_DESCR_08,0
MR_PRINT_GD_SCALE,MARK_DESCR_09,0
MR_PRINT_GD_SCALE,MARK_DESCR_10,0
MR_PRINT_GD_SCALE,MARK_DESCR_11,0
MR_PRINT_GD_SCALE,MARK_DESCR_12,0
MR_PRINT_GD_SCALE,MARK_DESCR_13,0
MR_PRINT_GD_SCALE,MARK_DESCR_14,0
MR_PRINT_GD_SCALE,MARK_DESCR_15,0
MR_PRINT_GD_SCALE,MARK_DESCR_16,0
MR_PRINT_GD_SCALE,MARK_DESCR_17,0
MR_PRINT_GD_SCALE,MARK_DESCR_18,0
MR_PRINT_GD_SCALE,MARK_DESCR_19,0
MR_PRINT_GD_SCALE,MARK_DESCR_20,0
MR_PRINT_GD_SCALE,MARK_DESCR_21,0
MR_PRINT_GD_SCALE,MARK_DESCR_22,0
MR_PRINT_GD_SCALE,MARK_DESCR_23,0
MR_PRINT_GD_SCALE,MARK_DESCR_24,0
MR_PRINT_GD_SCALE,MARK_DESCR_25,0
MR_PRINT_GD_SCALE,MARK_DESCR_26,0
MR_PRINT_GD_SCALE,MARK_DESCR_27,0
MR_PRINT_GD_SCALE,MARK_DESCR_28,0
MR_PRINT_GD_SCALE,MARK_DESCR_29,0
MR_PRINT_GD_SCALE,MARK_DESCR_30,0
MR_PRINT_GD_SCALE,CHANGE_DATE_TIME,0
MR_PRINT_GD_SCALE,CHANGE_UID,0
MR_PRINT_HDR,DISTRICT,1
MR_PRINT_HDR,SCHOOL_YEAR,1
MR_PRINT_HDR,BUILDING,1
MR_PRINT_HDR,RC_RUN,1
MR_PRINT_HDR,GRADE,1
MR_PRINT_HDR,AS_OF_DATE,0
MR_PRINT_HDR,RUN_DATE,0
MR_PRINT_HDR,HEADER_TEXT,0
MR_PRINT_HDR,FOOTER_TEXT,0
MR_PRINT_HDR,MR_DATA_TITLE_01,0
MR_PRINT_HDR,MR_DATA_TITLE_02,0
MR_PRINT_HDR,MR_DATA_TITLE_03,0
MR_PRINT_HDR,MR_DATA_TITLE_04,0
MR_PRINT_HDR,MR_DATA_TITLE_05,0
MR_PRINT_HDR,MR_DATA_TITLE_06,0
MR_PRINT_HDR,MR_DATA_TITLE_07,0
MR_PRINT_HDR,MR_DATA_TITLE_08,0
MR_PRINT_HDR,MR_DATA_TITLE_09,0
MR_PRINT_HDR,MR_DATA_TITLE_10,0
MR_PRINT_HDR,MR_DATA_TITLE_11,0
MR_PRINT_HDR,MR_DATA_TITLE_12,0
MR_PRINT_HDR,MR_DATA_TITLE_13,0
MR_PRINT_HDR,MR_DATA_TITLE_14,0
MR_PRINT_HDR,MR_DATA_TITLE_15,0
MR_PRINT_HDR,MR_DATA_TITLE_16,0
MR_PRINT_HDR,MR_DATA_TITLE_17,0
MR_PRINT_HDR,MR_DATA_TITLE_18,0
MR_PRINT_HDR,MR_DATA_TITLE_19,0
MR_PRINT_HDR,MR_DATA_TITLE_20,0
MR_PRINT_HDR,MR_DATA_TITLE_21,0
MR_PRINT_HDR,MR_DATA_TITLE_22,0
MR_PRINT_HDR,MR_DATA_TITLE_23,0
MR_PRINT_HDR,MR_DATA_TITLE_24,0
MR_PRINT_HDR,MR_DATA_TITLE_25,0
MR_PRINT_HDR,MR_DATA_TITLE_26,0
MR_PRINT_HDR,MR_DATA_TITLE_27,0
MR_PRINT_HDR,MR_DATA_TITLE_28,0
MR_PRINT_HDR,MR_DATA_TITLE_29,0
MR_PRINT_HDR,MR_DATA_TITLE_30,0
MR_PRINT_HDR,MR_SC_TITLE_01,0
MR_PRINT_HDR,MR_SC_TITLE_02,0
MR_PRINT_HDR,MR_SC_TITLE_03,0
MR_PRINT_HDR,MR_SC_TITLE_04,0
MR_PRINT_HDR,MR_SC_TITLE_05,0
MR_PRINT_HDR,MR_SC_TITLE_06,0
MR_PRINT_HDR,MR_SC_TITLE_07,0
MR_PRINT_HDR,MR_SC_TITLE_08,0
MR_PRINT_HDR,MR_SC_TITLE_09,0
MR_PRINT_HDR,MR_SC_TITLE_10,0
MR_PRINT_HDR,MR_SC_TITLE_11,0
MR_PRINT_HDR,MR_SC_TITLE_12,0
MR_PRINT_HDR,MR_SC_TITLE_13,0
MR_PRINT_HDR,MR_SC_TITLE_14,0
MR_PRINT_HDR,MR_SC_TITLE_15,0
MR_PRINT_HDR,MR_SC_TITLE_16,0
MR_PRINT_HDR,MR_SC_TITLE_17,0
MR_PRINT_HDR,MR_SC_TITLE_18,0
MR_PRINT_HDR,MR_SC_TITLE_19,0
MR_PRINT_HDR,MR_SC_TITLE_20,0
MR_PRINT_HDR,MR_SC_TITLE_21,0
MR_PRINT_HDR,MR_SC_TITLE_22,0
MR_PRINT_HDR,MR_SC_TITLE_23,0
MR_PRINT_HDR,MR_SC_TITLE_24,0
MR_PRINT_HDR,MR_SC_TITLE_25,0
MR_PRINT_HDR,MR_SC_TITLE_26,0
MR_PRINT_HDR,MR_SC_TITLE_27,0
MR_PRINT_HDR,MR_SC_TITLE_28,0
MR_PRINT_HDR,MR_SC_TITLE_29,0
MR_PRINT_HDR,MR_SC_TITLE_30,0
MR_PRINT_HDR,PROGRAM_TITLE_01,0
MR_PRINT_HDR,PROGRAM_TITLE_02,0
MR_PRINT_HDR,PROGRAM_TITLE_03,0
MR_PRINT_HDR,PROGRAM_TITLE_04,0
MR_PRINT_HDR,PROGRAM_TITLE_05,0
MR_PRINT_HDR,PROGRAM_TITLE_06,0
MR_PRINT_HDR,PROGRAM_TITLE_07,0
MR_PRINT_HDR,PROGRAM_TITLE_08,0
MR_PRINT_HDR,PROGRAM_TITLE_09,0
MR_PRINT_HDR,PROGRAM_TITLE_10,0
MR_PRINT_HDR,PROGRAM_TITLE_11,0
MR_PRINT_HDR,PROGRAM_TITLE_12,0
MR_PRINT_HDR,MR_PRINT_KEY,0
MR_PRINT_HDR,CHANGE_DATE_TIME,0
MR_PRINT_HDR,CHANGE_UID,0
MR_PRINT_KEY,DISTRICT,1
MR_PRINT_KEY,KEY_TYPE,1
MR_PRINT_KEY,PRINT_KEY,0
MR_PRINT_KEY,CHANGE_DATE_TIME,0
MR_PRINT_KEY,CHANGE_UID,0
MR_PRINT_STU_COMM,MR_PRINT_KEY,1
MR_PRINT_STU_COMM,STUDENT_ID,1
MR_PRINT_STU_COMM,SECTION_KEY,1
MR_PRINT_STU_COMM,COURSE_SESSION,1
MR_PRINT_STU_COMM,MR_DATA_DESCR_01,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_02,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_03,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_04,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_05,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_06,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_07,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_08,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_09,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_10,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_11,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_12,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_13,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_14,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_15,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_16,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_17,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_18,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_19,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_20,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_21,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_22,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_23,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_24,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_25,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_26,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_27,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_28,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_29,0
MR_PRINT_STU_COMM,MR_DATA_DESCR_30,0
MR_PRINT_STU_COMM,CHANGE_DATE_TIME,0
MR_PRINT_STU_COMM,CHANGE_UID,0
MR_PRINT_STU_CRSCP,MR_PRINT_KEY,1
MR_PRINT_STU_CRSCP,STUDENT_ID,1
MR_PRINT_STU_CRSCP,COURSE_BUILDING,1
MR_PRINT_STU_CRSCP,COURSE,1
MR_PRINT_STU_CRSCP,COMPETENCY_GROUP,1
MR_PRINT_STU_CRSCP,COMPETENCY_NUMBER,1
MR_PRINT_STU_CRSCP,SEQUENCE_NUMBER,0
MR_PRINT_STU_CRSCP,DESCRIPTION,0
MR_PRINT_STU_CRSCP,FORMAT_LEVEL,0
MR_PRINT_STU_CRSCP,HEADING_ONLY,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_01,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_02,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_03,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_04,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_05,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_06,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_07,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_08,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_09,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_10,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_11,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_12,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_13,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_14,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_15,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_16,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_17,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_18,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_19,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_20,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_21,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_22,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_23,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_24,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_25,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_26,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_27,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_28,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_29,0
MR_PRINT_STU_CRSCP,SC_DATA_VALUE_30,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_01,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_02,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_03,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_04,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_05,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_06,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_07,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_08,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_09,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_10,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_11,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_12,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_13,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_14,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_15,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_16,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_17,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_18,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_19,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_20,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_21,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_22,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_23,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_24,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_25,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_26,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_27,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_28,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_29,0
MR_PRINT_STU_CRSCP,SC_COMM_DESCR_30,0
MR_PRINT_STU_CRSCP,CHANGE_DATE_TIME,0
MR_PRINT_STU_CRSCP,CHANGE_UID,0
MR_PRINT_STU_CRSTXT,MR_PRINT_KEY,1
MR_PRINT_STU_CRSTXT,STUDENT_ID,1
MR_PRINT_STU_CRSTXT,MARKING_PERIOD,1
MR_PRINT_STU_CRSTXT,SECTION_KEY_01,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_02,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_03,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_04,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_05,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_06,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_07,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_08,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_09,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_10,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_11,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_12,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_13,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_14,0
MR_PRINT_STU_CRSTXT,SECTION_KEY_15,0
MR_PRINT_STU_CRSTXT,STAFF_ID_01,0
MR_PRINT_STU_CRSTXT,STAFF_ID_02,0
MR_PRINT_STU_CRSTXT,STAFF_ID_03,0
MR_PRINT_STU_CRSTXT,STAFF_ID_04,0
MR_PRINT_STU_CRSTXT,STAFF_ID_05,0
MR_PRINT_STU_CRSTXT,STAFF_ID_06,0
MR_PRINT_STU_CRSTXT,STAFF_ID_07,0
MR_PRINT_STU_CRSTXT,STAFF_ID_08,0
MR_PRINT_STU_CRSTXT,STAFF_ID_09,0
MR_PRINT_STU_CRSTXT,STAFF_ID_10,0
MR_PRINT_STU_CRSTXT,STAFF_ID_11,0
MR_PRINT_STU_CRSTXT,STAFF_ID_12,0
MR_PRINT_STU_CRSTXT,STAFF_ID_13,0
MR_PRINT_STU_CRSTXT,STAFF_ID_14,0
MR_PRINT_STU_CRSTXT,STAFF_ID_15,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_01,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_02,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_03,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_04,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_05,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_06,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_07,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_08,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_09,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_10,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_11,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_12,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_13,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_14,0
MR_PRINT_STU_CRSTXT,STAFF_NAME_15,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_01,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_02,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_03,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_04,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_05,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_06,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_07,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_08,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_09,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_10,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_11,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_12,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_13,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_14,0
MR_PRINT_STU_CRSTXT,COURSE_COMMENT_15,0
MR_PRINT_STU_CRSTXT,CHANGE_DATE_TIME,0
MR_PRINT_STU_CRSTXT,CHANGE_UID,0
MR_PRINT_STU_DET,MR_PRINT_KEY,1
MR_PRINT_STU_DET,STUDENT_ID,1
MR_PRINT_STU_DET,SECTION_KEY,1
MR_PRINT_STU_DET,COURSE_BUILDING,0
MR_PRINT_STU_DET,COURSE,0
MR_PRINT_STU_DET,COURSE_SECTION,0
MR_PRINT_STU_DET,COURSE_SESSION,1
MR_PRINT_STU_DET,DESCRIPTION,0
MR_PRINT_STU_DET,CRS_PERIOD,0
MR_PRINT_STU_DET,PRIMARY_STAFF_ID,0
MR_PRINT_STU_DET,STAFF_NAME,0
MR_PRINT_STU_DET,ROOM_ID,0
MR_PRINT_STU_DET,ATTEMPTED_CREDIT,0
MR_PRINT_STU_DET,ATT_OVERRIDE,0
MR_PRINT_STU_DET,ATT_OVR_REASON,0
MR_PRINT_STU_DET,EARNED_CREDIT,0
MR_PRINT_STU_DET,EARN_OVERRIDE,0
MR_PRINT_STU_DET,EARN_OVR_REASON,0
MR_PRINT_STU_DET,MR_DATA_VALUE_01,0
MR_PRINT_STU_DET,MR_DATA_VALUE_02,0
MR_PRINT_STU_DET,MR_DATA_VALUE_03,0
MR_PRINT_STU_DET,MR_DATA_VALUE_04,0
MR_PRINT_STU_DET,MR_DATA_VALUE_05,0
MR_PRINT_STU_DET,MR_DATA_VALUE_06,0
MR_PRINT_STU_DET,MR_DATA_VALUE_07,0
MR_PRINT_STU_DET,MR_DATA_VALUE_08,0
MR_PRINT_STU_DET,MR_DATA_VALUE_09,0
MR_PRINT_STU_DET,MR_DATA_VALUE_10,0
MR_PRINT_STU_DET,MR_DATA_VALUE_11,0
MR_PRINT_STU_DET,MR_DATA_VALUE_12,0
MR_PRINT_STU_DET,MR_DATA_VALUE_13,0
MR_PRINT_STU_DET,MR_DATA_VALUE_14,0
MR_PRINT_STU_DET,MR_DATA_VALUE_15,0
MR_PRINT_STU_DET,MR_DATA_VALUE_16,0
MR_PRINT_STU_DET,MR_DATA_VALUE_17,0
MR_PRINT_STU_DET,MR_DATA_VALUE_18,0
MR_PRINT_STU_DET,MR_DATA_VALUE_19,0
MR_PRINT_STU_DET,MR_DATA_VALUE_20,0
MR_PRINT_STU_DET,MR_DATA_VALUE_21,0
MR_PRINT_STU_DET,MR_DATA_VALUE_22,0
MR_PRINT_STU_DET,MR_DATA_VALUE_23,0
MR_PRINT_STU_DET,MR_DATA_VALUE_24,0
MR_PRINT_STU_DET,MR_DATA_VALUE_25,0
MR_PRINT_STU_DET,MR_DATA_VALUE_26,0
MR_PRINT_STU_DET,MR_DATA_VALUE_27,0
MR_PRINT_STU_DET,MR_DATA_VALUE_28,0
MR_PRINT_STU_DET,MR_DATA_VALUE_29,0
MR_PRINT_STU_DET,MR_DATA_VALUE_30,0
MR_PRINT_STU_DET,CHANGE_DATE_TIME,0
MR_PRINT_STU_DET,CHANGE_UID,0
MR_PRINT_STU_GPA,MR_PRINT_KEY,1
MR_PRINT_STU_GPA,STUDENT_ID,1
MR_PRINT_STU_GPA,GPA_ORDER,1
MR_PRINT_STU_GPA,GPA_TYPE,0
MR_PRINT_STU_GPA,GPA_TITLE,0
MR_PRINT_STU_GPA,GPA_TERM01,0
MR_PRINT_STU_GPA,GPA_TERM02,0
MR_PRINT_STU_GPA,GPA_TERM03,0
MR_PRINT_STU_GPA,GPA_TERM04,0
MR_PRINT_STU_GPA,GPA_TERM05,0
MR_PRINT_STU_GPA,GPA_TERM06,0
MR_PRINT_STU_GPA,GPA_TERM07,0
MR_PRINT_STU_GPA,GPA_TERM08,0
MR_PRINT_STU_GPA,GPA_TERM09,0
MR_PRINT_STU_GPA,GPA_TERM10,0
MR_PRINT_STU_GPA,GPA_CURR01,0
MR_PRINT_STU_GPA,GPA_CURR02,0
MR_PRINT_STU_GPA,GPA_CURR03,0
MR_PRINT_STU_GPA,GPA_CURR04,0
MR_PRINT_STU_GPA,GPA_CURR05,0
MR_PRINT_STU_GPA,GPA_CURR06,0
MR_PRINT_STU_GPA,GPA_CURR07,0
MR_PRINT_STU_GPA,GPA_CURR08,0
MR_PRINT_STU_GPA,GPA_CURR09,0
MR_PRINT_STU_GPA,GPA_CURR10,0
MR_PRINT_STU_GPA,GPA_CUM01,0
MR_PRINT_STU_GPA,GPA_CUM02,0
MR_PRINT_STU_GPA,GPA_CUM03,0
MR_PRINT_STU_GPA,GPA_CUM04,0
MR_PRINT_STU_GPA,GPA_CUM05,0
MR_PRINT_STU_GPA,GPA_CUM06,0
MR_PRINT_STU_GPA,GPA_CUM07,0
MR_PRINT_STU_GPA,GPA_CUM08,0
MR_PRINT_STU_GPA,GPA_CUM09,0
MR_PRINT_STU_GPA,GPA_CUM10,0
MR_PRINT_STU_GPA,RANK_NUM_CURR01,0
MR_PRINT_STU_GPA,RANK_NUM_CURR02,0
MR_PRINT_STU_GPA,RANK_NUM_CURR03,0
MR_PRINT_STU_GPA,RANK_NUM_CURR04,0
MR_PRINT_STU_GPA,RANK_NUM_CURR05,0
MR_PRINT_STU_GPA,RANK_NUM_CURR06,0
MR_PRINT_STU_GPA,RANK_NUM_CURR07,0
MR_PRINT_STU_GPA,RANK_NUM_CURR08,0
MR_PRINT_STU_GPA,RANK_NUM_CURR09,0
MR_PRINT_STU_GPA,RANK_NUM_CURR10,0
MR_PRINT_STU_GPA,RANK_NUM_CUM01,0
MR_PRINT_STU_GPA,RANK_NUM_CUM02,0
MR_PRINT_STU_GPA,RANK_NUM_CUM03,0
MR_PRINT_STU_GPA,RANK_NUM_CUM04,0
MR_PRINT_STU_GPA,RANK_NUM_CUM05,0
MR_PRINT_STU_GPA,RANK_NUM_CUM06,0
MR_PRINT_STU_GPA,RANK_NUM_CUM07,0
MR_PRINT_STU_GPA,RANK_NUM_CUM08,0
MR_PRINT_STU_GPA,RANK_NUM_CUM09,0
MR_PRINT_STU_GPA,RANK_NUM_CUM10,0
MR_PRINT_STU_GPA,RANK_OUT_OF01,0
MR_PRINT_STU_GPA,RANK_OUT_OF02,0
MR_PRINT_STU_GPA,RANK_OUT_OF03,0
MR_PRINT_STU_GPA,RANK_OUT_OF04,0
MR_PRINT_STU_GPA,RANK_OUT_OF05,0
MR_PRINT_STU_GPA,RANK_OUT_OF06,0
MR_PRINT_STU_GPA,RANK_OUT_OF07,0
MR_PRINT_STU_GPA,RANK_OUT_OF08,0
MR_PRINT_STU_GPA,RANK_OUT_OF09,0
MR_PRINT_STU_GPA,RANK_OUT_OF10,0
MR_PRINT_STU_GPA,CHANGE_DATE_TIME,0
MR_PRINT_STU_GPA,CHANGE_UID,0
MR_PRINT_STU_HDR,MR_PRINT_KEY,1
MR_PRINT_STU_HDR,STUDENT_ID,1
MR_PRINT_STU_HDR,STUDENT_NAME,0
MR_PRINT_STU_HDR,BUILDING,0
MR_PRINT_STU_HDR,GRADE,0
MR_PRINT_STU_HDR,TRACK,0
MR_PRINT_STU_HDR,COUNSELOR,0
MR_PRINT_STU_HDR,HOUSE_TEAM,0
MR_PRINT_STU_HDR,HOMEROOM_PRIMARY,0
MR_PRINT_STU_HDR,RANK_NUM_CURR,0
MR_PRINT_STU_HDR,RANK_NUM_CUM,0
MR_PRINT_STU_HDR,RANK_OUT_OF,0
MR_PRINT_STU_HDR,DAILY_ATT_DESCR_01,0
MR_PRINT_STU_HDR,DAILY_ATT_DESCR_02,0
MR_PRINT_STU_HDR,DAILY_ATT_DESCR_03,0
MR_PRINT_STU_HDR,DAILY_ATT_DESCR_04,0
MR_PRINT_STU_HDR,DAILY_ATT_DESCR_05,0
MR_PRINT_STU_HDR,DAILY_ATT_DESCR_06,0
MR_PRINT_STU_HDR,DAILY_ATT_DESCR_07,0
MR_PRINT_STU_HDR,DAILY_ATT_DESCR_08,0
MR_PRINT_STU_HDR,DAILY_ATT_DESCR_09,0
MR_PRINT_STU_HDR,DAILY_ATT_DESCR_10,0
MR_PRINT_STU_HDR,DAILY_ATT_CURR_01,0
MR_PRINT_STU_HDR,DAILY_ATT_CURR_02,0
MR_PRINT_STU_HDR,DAILY_ATT_CURR_03,0
MR_PRINT_STU_HDR,DAILY_ATT_CURR_04,0
MR_PRINT_STU_HDR,DAILY_ATT_CURR_05,0
MR_PRINT_STU_HDR,DAILY_ATT_CURR_06,0
MR_PRINT_STU_HDR,DAILY_ATT_CURR_07,0
MR_PRINT_STU_HDR,DAILY_ATT_CURR_08,0
MR_PRINT_STU_HDR,DAILY_ATT_CURR_09,0
MR_PRINT_STU_HDR,DAILY_ATT_CURR_10,0
MR_PRINT_STU_HDR,DAILY_ATT_YTD_01,0
MR_PRINT_STU_HDR,DAILY_ATT_YTD_02,0
MR_PRINT_STU_HDR,DAILY_ATT_YTD_03,0
MR_PRINT_STU_HDR,DAILY_ATT_YTD_04,0
MR_PRINT_STU_HDR,DAILY_ATT_YTD_05,0
MR_PRINT_STU_HDR,DAILY_ATT_YTD_06,0
MR_PRINT_STU_HDR,DAILY_ATT_YTD_07,0
MR_PRINT_STU_HDR,DAILY_ATT_YTD_08,0
MR_PRINT_STU_HDR,DAILY_ATT_YTD_09,0
MR_PRINT_STU_HDR,DAILY_ATT_YTD_10,0
MR_PRINT_STU_HDR,CREDIT_HONOR,0
MR_PRINT_STU_HDR,CREDIT_SEM,0
MR_PRINT_STU_HDR,CREDIT_CUM,0
MR_PRINT_STU_HDR,CREDIT_ATT_CUR,0
MR_PRINT_STU_HDR,CREDIT_ATT_SEM,0
MR_PRINT_STU_HDR,CREDIT_ATT_CUM,0
MR_PRINT_STU_HDR,GPA_HONOR,0
MR_PRINT_STU_HDR,GPA_SEM,0
MR_PRINT_STU_HDR,GPA_CUM,0
MR_PRINT_STU_HDR,HONOR_TYPE_01,0
MR_PRINT_STU_HDR,HONOR_TYPE_02,0
MR_PRINT_STU_HDR,HONOR_TYPE_03,0
MR_PRINT_STU_HDR,HONOR_TYPE_04,0
MR_PRINT_STU_HDR,HONOR_TYPE_05,0
MR_PRINT_STU_HDR,HONOR_TYPE_06,0
MR_PRINT_STU_HDR,HONOR_TYPE_07,0
MR_PRINT_STU_HDR,HONOR_TYPE_08,0
MR_PRINT_STU_HDR,HONOR_TYPE_09,0
MR_PRINT_STU_HDR,HONOR_TYPE_10,0
MR_PRINT_STU_HDR,HONOR_MSG_01,0
MR_PRINT_STU_HDR,HONOR_MSG_02,0
MR_PRINT_STU_HDR,HONOR_MSG_03,0
MR_PRINT_STU_HDR,HONOR_MSG_04,0
MR_PRINT_STU_HDR,HONOR_MSG_05,0
MR_PRINT_STU_HDR,HONOR_MSG_06,0
MR_PRINT_STU_HDR,HONOR_MSG_07,0
MR_PRINT_STU_HDR,HONOR_MSG_08,0
MR_PRINT_STU_HDR,HONOR_MSG_09,0
MR_PRINT_STU_HDR,HONOR_MSG_10,0
MR_PRINT_STU_HDR,HONOR_GPA_01,0
MR_PRINT_STU_HDR,HONOR_GPA_02,0
MR_PRINT_STU_HDR,HONOR_GPA_03,0
MR_PRINT_STU_HDR,HONOR_GPA_04,0
MR_PRINT_STU_HDR,HONOR_GPA_05,0
MR_PRINT_STU_HDR,HONOR_GPA_06,0
MR_PRINT_STU_HDR,HONOR_GPA_07,0
MR_PRINT_STU_HDR,HONOR_GPA_08,0
MR_PRINT_STU_HDR,HONOR_GPA_09,0
MR_PRINT_STU_HDR,HONOR_GPA_10,0
MR_PRINT_STU_HDR,HONOR_CREDIT_01,0
MR_PRINT_STU_HDR,HONOR_CREDIT_02,0
MR_PRINT_STU_HDR,HONOR_CREDIT_03,0
MR_PRINT_STU_HDR,HONOR_CREDIT_04,0
MR_PRINT_STU_HDR,HONOR_CREDIT_05,0
MR_PRINT_STU_HDR,HONOR_CREDIT_06,0
MR_PRINT_STU_HDR,HONOR_CREDIT_07,0
MR_PRINT_STU_HDR,HONOR_CREDIT_08,0
MR_PRINT_STU_HDR,HONOR_CREDIT_09,0
MR_PRINT_STU_HDR,HONOR_CREDIT_10,0
MR_PRINT_STU_HDR,HONOR_QUALIFIED_01,0
MR_PRINT_STU_HDR,HONOR_QUALIFIED_02,0
MR_PRINT_STU_HDR,HONOR_QUALIFIED_03,0
MR_PRINT_STU_HDR,HONOR_QUALIFIED_04,0
MR_PRINT_STU_HDR,HONOR_QUALIFIED_05,0
MR_PRINT_STU_HDR,HONOR_QUALIFIED_06,0
MR_PRINT_STU_HDR,HONOR_QUALIFIED_07,0
MR_PRINT_STU_HDR,HONOR_QUALIFIED_08,0
MR_PRINT_STU_HDR,HONOR_QUALIFIED_09,0
MR_PRINT_STU_HDR,HONOR_QUALIFIED_10,0
MR_PRINT_STU_HDR,REPORT_TEMPLATE,0
MR_PRINT_STU_HDR,CHANGE_DATE_TIME,0
MR_PRINT_STU_HDR,CHANGE_UID,0
MR_PRINT_STU_HNR,MR_PRINT_KEY,1
MR_PRINT_STU_HNR,STUDENT_ID,1
MR_PRINT_STU_HNR,HONOR_ORDER,1
MR_PRINT_STU_HNR,HONOR_TYPE,0
MR_PRINT_STU_HNR,HONOR_TITLE,0
MR_PRINT_STU_HNR,HONOR_RUN01,0
MR_PRINT_STU_HNR,HONOR_RUN02,0
MR_PRINT_STU_HNR,HONOR_RUN03,0
MR_PRINT_STU_HNR,HONOR_RUN04,0
MR_PRINT_STU_HNR,HONOR_RUN05,0
MR_PRINT_STU_HNR,HONOR_RUN06,0
MR_PRINT_STU_HNR,HONOR_RUN07,0
MR_PRINT_STU_HNR,HONOR_RUN08,0
MR_PRINT_STU_HNR,HONOR_RUN09,0
MR_PRINT_STU_HNR,HONOR_RUN10,0
MR_PRINT_STU_HNR,HONOR_GPA01,0
MR_PRINT_STU_HNR,HONOR_GPA02,0
MR_PRINT_STU_HNR,HONOR_GPA03,0
MR_PRINT_STU_HNR,HONOR_GPA04,0
MR_PRINT_STU_HNR,HONOR_GPA05,0
MR_PRINT_STU_HNR,HONOR_GPA06,0
MR_PRINT_STU_HNR,HONOR_GPA07,0
MR_PRINT_STU_HNR,HONOR_GPA08,0
MR_PRINT_STU_HNR,HONOR_GPA09,0
MR_PRINT_STU_HNR,HONOR_GPA10,0
MR_PRINT_STU_HNR,HONOR_QUAL01,0
MR_PRINT_STU_HNR,HONOR_QUAL02,0
MR_PRINT_STU_HNR,HONOR_QUAL03,0
MR_PRINT_STU_HNR,HONOR_QUAL04,0
MR_PRINT_STU_HNR,HONOR_QUAL05,0
MR_PRINT_STU_HNR,HONOR_QUAL06,0
MR_PRINT_STU_HNR,HONOR_QUAL07,0
MR_PRINT_STU_HNR,HONOR_QUAL08,0
MR_PRINT_STU_HNR,HONOR_QUAL09,0
MR_PRINT_STU_HNR,HONOR_QUAL10,0
MR_PRINT_STU_HNR,CHANGE_DATE_TIME,0
MR_PRINT_STU_HNR,CHANGE_UID,0
mr_print_stu_hold,MR_PRINT_KEY,1
mr_print_stu_hold,STUDENT_ID,1
mr_print_stu_hold,REPORT_CARD_HOLD,0
mr_print_stu_hold,STATUS_HOLD,0
mr_print_stu_hold,FEE_STATUS,0
mr_print_stu_hold,STATUS_DESCRIPTION,0
mr_print_stu_hold,OVERALL_HOLD,0
mr_print_stu_hold,OVERALL_THRESHOLD,0
mr_print_stu_hold,OVERALL_BALANCE,0
mr_print_stu_hold,COURSE_HOLD,0
mr_print_stu_hold,COURSE_THRESHOLD,0
mr_print_stu_hold,COURSE_BALANCE,0
mr_print_stu_hold,STUDENT_HOLD,0
mr_print_stu_hold,STUDENT_THRESHOLD,0
mr_print_stu_hold,STUDENT_BALANCE,0
mr_print_stu_hold,ACTIVITY_HOLD,0
mr_print_stu_hold,ACTIVITY_THRESHOLD,0
mr_print_stu_hold,ACTIVITY_BALANCE,0
mr_print_stu_hold,REASON1,0
mr_print_stu_hold,REASON2,0
mr_print_stu_hold,REASON3,0
mr_print_stu_hold,REASON4,0
mr_print_stu_hold,REASON5,0
mr_print_stu_hold,REASON6,0
mr_print_stu_hold,REASON7,0
mr_print_stu_hold,REASON8,0
mr_print_stu_hold,REASON9,0
mr_print_stu_hold,REASON10,0
mr_print_stu_hold,REASON_DESC1,0
mr_print_stu_hold,REASON_DESC2,0
mr_print_stu_hold,REASON_DESC3,0
mr_print_stu_hold,REASON_DESC4,0
mr_print_stu_hold,REASON_DESC5,0
mr_print_stu_hold,REASON_DESC6,0
mr_print_stu_hold,REASON_DESC7,0
mr_print_stu_hold,REASON_DESC8,0
mr_print_stu_hold,REASON_DESC9,0
mr_print_stu_hold,REASON_DESC10,0
mr_print_stu_hold,HOLD_HEADER_TEXT,0
mr_print_stu_hold,HOLD_FOOTER_TEXT,0
mr_print_stu_hold,CHANGE_DATE_TIME,0
mr_print_stu_hold,CHANGE_UID,0
mr_print_stu_item,MR_PRINT_KEY,1
mr_print_stu_item,STUDENT_ID,1
mr_print_stu_item,TRACKING_NUMBER,1
mr_print_stu_item,ITEM_DATE,0
mr_print_stu_item,ITEM,0
mr_print_stu_item,DESCRIPTION,0
mr_print_stu_item,BALANCE,0
mr_print_stu_item,HOLD_ITEM,0
mr_print_stu_item,CHANGE_DATE_TIME,0
mr_print_stu_item,CHANGE_UID,0
MR_PRINT_STU_LTDB,MR_PRINT_KEY,1
MR_PRINT_STU_LTDB,STUDENT_ID,1
MR_PRINT_STU_LTDB,LTDB_TITLE_01,0
MR_PRINT_STU_LTDB,LTDB_TITLE_02,0
MR_PRINT_STU_LTDB,LTDB_TITLE_03,0
MR_PRINT_STU_LTDB,LTDB_TITLE_04,0
MR_PRINT_STU_LTDB,LTDB_TITLE_05,0
MR_PRINT_STU_LTDB,LTDB_TITLE_06,0
MR_PRINT_STU_LTDB,LTDB_TITLE_07,0
MR_PRINT_STU_LTDB,LTDB_TITLE_08,0
MR_PRINT_STU_LTDB,LTDB_TITLE_09,0
MR_PRINT_STU_LTDB,LTDB_TITLE_10,0
MR_PRINT_STU_LTDB,LTDB_TITLE_11,0
MR_PRINT_STU_LTDB,LTDB_TITLE_12,0
MR_PRINT_STU_LTDB,LTDB_TITLE_13,0
MR_PRINT_STU_LTDB,LTDB_TITLE_14,0
MR_PRINT_STU_LTDB,LTDB_TITLE_15,0
MR_PRINT_STU_LTDB,LTDB_TITLE_16,0
MR_PRINT_STU_LTDB,LTDB_TITLE_17,0
MR_PRINT_STU_LTDB,LTDB_TITLE_18,0
MR_PRINT_STU_LTDB,LTDB_TITLE_19,0
MR_PRINT_STU_LTDB,LTDB_TITLE_20,0
MR_PRINT_STU_LTDB,LTDB_TITLE_21,0
MR_PRINT_STU_LTDB,LTDB_TITLE_22,0
MR_PRINT_STU_LTDB,LTDB_TITLE_23,0
MR_PRINT_STU_LTDB,LTDB_TITLE_24,0
MR_PRINT_STU_LTDB,LTDB_TITLE_25,0
MR_PRINT_STU_LTDB,LTDB_TITLE_26,0
MR_PRINT_STU_LTDB,LTDB_TITLE_27,0
MR_PRINT_STU_LTDB,LTDB_TITLE_28,0
MR_PRINT_STU_LTDB,LTDB_TITLE_29,0
MR_PRINT_STU_LTDB,LTDB_TITLE_30,0
MR_PRINT_STU_LTDB,SCORE_01,0
MR_PRINT_STU_LTDB,SCORE_02,0
MR_PRINT_STU_LTDB,SCORE_03,0
MR_PRINT_STU_LTDB,SCORE_04,0
MR_PRINT_STU_LTDB,SCORE_05,0
MR_PRINT_STU_LTDB,SCORE_06,0
MR_PRINT_STU_LTDB,SCORE_07,0
MR_PRINT_STU_LTDB,SCORE_08,0
MR_PRINT_STU_LTDB,SCORE_09,0
MR_PRINT_STU_LTDB,SCORE_10,0
MR_PRINT_STU_LTDB,SCORE_11,0
MR_PRINT_STU_LTDB,SCORE_12,0
MR_PRINT_STU_LTDB,SCORE_13,0
MR_PRINT_STU_LTDB,SCORE_14,0
MR_PRINT_STU_LTDB,SCORE_15,0
MR_PRINT_STU_LTDB,SCORE_16,0
MR_PRINT_STU_LTDB,SCORE_17,0
MR_PRINT_STU_LTDB,SCORE_18,0
MR_PRINT_STU_LTDB,SCORE_19,0
MR_PRINT_STU_LTDB,SCORE_20,0
MR_PRINT_STU_LTDB,SCORE_21,0
MR_PRINT_STU_LTDB,SCORE_22,0
MR_PRINT_STU_LTDB,SCORE_23,0
MR_PRINT_STU_LTDB,SCORE_24,0
MR_PRINT_STU_LTDB,SCORE_25,0
MR_PRINT_STU_LTDB,SCORE_26,0
MR_PRINT_STU_LTDB,SCORE_27,0
MR_PRINT_STU_LTDB,SCORE_28,0
MR_PRINT_STU_LTDB,SCORE_29,0
MR_PRINT_STU_LTDB,SCORE_30,0
MR_PRINT_STU_LTDB,TEST_DATE_01,0
MR_PRINT_STU_LTDB,TEST_DATE_02,0
MR_PRINT_STU_LTDB,TEST_DATE_03,0
MR_PRINT_STU_LTDB,TEST_DATE_04,0
MR_PRINT_STU_LTDB,TEST_DATE_05,0
MR_PRINT_STU_LTDB,TEST_DATE_06,0
MR_PRINT_STU_LTDB,TEST_DATE_07,0
MR_PRINT_STU_LTDB,TEST_DATE_08,0
MR_PRINT_STU_LTDB,TEST_DATE_09,0
MR_PRINT_STU_LTDB,TEST_DATE_10,0
MR_PRINT_STU_LTDB,TEST_DATE_11,0
MR_PRINT_STU_LTDB,TEST_DATE_12,0
MR_PRINT_STU_LTDB,TEST_DATE_13,0
MR_PRINT_STU_LTDB,TEST_DATE_14,0
MR_PRINT_STU_LTDB,TEST_DATE_15,0
MR_PRINT_STU_LTDB,TEST_DATE_16,0
MR_PRINT_STU_LTDB,TEST_DATE_17,0
MR_PRINT_STU_LTDB,TEST_DATE_18,0
MR_PRINT_STU_LTDB,TEST_DATE_19,0
MR_PRINT_STU_LTDB,TEST_DATE_20,0
MR_PRINT_STU_LTDB,TEST_DATE_21,0
MR_PRINT_STU_LTDB,TEST_DATE_22,0
MR_PRINT_STU_LTDB,TEST_DATE_23,0
MR_PRINT_STU_LTDB,TEST_DATE_24,0
MR_PRINT_STU_LTDB,TEST_DATE_25,0
MR_PRINT_STU_LTDB,TEST_DATE_26,0
MR_PRINT_STU_LTDB,TEST_DATE_27,0
MR_PRINT_STU_LTDB,TEST_DATE_28,0
MR_PRINT_STU_LTDB,TEST_DATE_29,0
MR_PRINT_STU_LTDB,TEST_DATE_30,0
MR_PRINT_STU_LTDB,CHANGE_DATE_TIME,0
MR_PRINT_STU_LTDB,CHANGE_UID,0
MR_PRINT_STU_PROG,MR_PRINT_KEY,1
MR_PRINT_STU_PROG,STUDENT_ID,1
MR_PRINT_STU_PROG,PROGRAM_ID,1
MR_PRINT_STU_PROG,FIELD_NUMBER,1
MR_PRINT_STU_PROG,VIEW_ORDER,0
MR_PRINT_STU_PROG,PROGRAM_LABEL,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_01,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_02,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_03,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_04,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_05,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_06,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_07,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_08,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_09,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_10,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_11,0
MR_PRINT_STU_PROG,PROGRAM_VALUE_12,0
MR_PRINT_STU_PROG,CHANGE_DATE_TIME,0
MR_PRINT_STU_PROG,CHANGE_UID,0
MR_PRINT_STU_SCTXT,MR_PRINT_KEY,1
MR_PRINT_STU_SCTXT,STUDENT_ID,1
MR_PRINT_STU_SCTXT,MARKING_PERIOD,1
MR_PRINT_STU_SCTXT,STAFF_01,0
MR_PRINT_STU_SCTXT,STAFF_02,0
MR_PRINT_STU_SCTXT,STAFF_03,0
MR_PRINT_STU_SCTXT,STAFF_04,0
MR_PRINT_STU_SCTXT,STAFF_05,0
MR_PRINT_STU_SCTXT,STAFF_06,0
MR_PRINT_STU_SCTXT,STAFF_07,0
MR_PRINT_STU_SCTXT,STAFF_08,0
MR_PRINT_STU_SCTXT,STAFF_09,0
MR_PRINT_STU_SCTXT,STAFF_10,0
MR_PRINT_STU_SCTXT,STAFF_NAME_01,0
MR_PRINT_STU_SCTXT,STAFF_NAME_02,0
MR_PRINT_STU_SCTXT,STAFF_NAME_03,0
MR_PRINT_STU_SCTXT,STAFF_NAME_04,0
MR_PRINT_STU_SCTXT,STAFF_NAME_05,0
MR_PRINT_STU_SCTXT,STAFF_NAME_06,0
MR_PRINT_STU_SCTXT,STAFF_NAME_07,0
MR_PRINT_STU_SCTXT,STAFF_NAME_08,0
MR_PRINT_STU_SCTXT,STAFF_NAME_09,0
MR_PRINT_STU_SCTXT,STAFF_NAME_10,0
MR_PRINT_STU_SCTXT,STAFF_COMMENT_01,0
MR_PRINT_STU_SCTXT,STAFF_COMMENT_02,0
MR_PRINT_STU_SCTXT,STAFF_COMMENT_03,0
MR_PRINT_STU_SCTXT,STAFF_COMMENT_04,0
MR_PRINT_STU_SCTXT,STAFF_COMMENT_05,0
MR_PRINT_STU_SCTXT,STAFF_COMMENT_06,0
MR_PRINT_STU_SCTXT,STAFF_COMMENT_07,0
MR_PRINT_STU_SCTXT,STAFF_COMMENT_08,0
MR_PRINT_STU_SCTXT,STAFF_COMMENT_09,0
MR_PRINT_STU_SCTXT,STAFF_COMMENT_10,0
MR_PRINT_STU_SCTXT,CHANGE_DATE_TIME,0
MR_PRINT_STU_SCTXT,CHANGE_UID,0
MR_PRINT_STU_SEC_TEACHER,MR_PRINT_KEY,1
MR_PRINT_STU_SEC_TEACHER,STUDENT_ID,1
MR_PRINT_STU_SEC_TEACHER,SECTION_KEY,1
MR_PRINT_STU_SEC_TEACHER,COURSE_SESSION,1
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_ID_01,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_NAME_01,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_ID_02,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_NAME_02,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_ID_03,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_NAME_03,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_ID_04,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_NAME_04,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_ID_05,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_NAME_05,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_ID_06,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_NAME_06,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_ID_07,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_NAME_07,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_ID_08,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_NAME_08,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_ID_09,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_NAME_09,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_ID_10,0
MR_PRINT_STU_SEC_TEACHER,SEC_STAFF_NAME_10,0
MR_PRINT_STU_SEC_TEACHER,CHANGE_DATE_TIME,0
MR_PRINT_STU_SEC_TEACHER,CHANGE_UID,0
MR_PRINT_STU_STUCP,MR_PRINT_KEY,1
MR_PRINT_STU_STUCP,STUDENT_ID,1
MR_PRINT_STU_STUCP,COMP_BUILDING,1
MR_PRINT_STU_STUCP,COMPETENCY_GROUP,1
MR_PRINT_STU_STUCP,GROUP_DESCRIPTION,0
MR_PRINT_STU_STUCP,GROUP_SEQUENCE,0
MR_PRINT_STU_STUCP,COMPETENCY_NUMBER,1
MR_PRINT_STU_STUCP,COMP_SEQUENCE,0
MR_PRINT_STU_STUCP,DESCRIPTION,0
MR_PRINT_STU_STUCP,STAFF_ID,0
MR_PRINT_STU_STUCP,STAFF_NAME,0
MR_PRINT_STU_STUCP,FORMAT_LEVEL,0
MR_PRINT_STU_STUCP,HEADING_ONLY,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_01,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_02,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_03,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_04,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_05,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_06,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_07,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_08,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_09,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_10,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_11,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_12,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_13,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_14,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_15,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_16,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_17,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_18,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_19,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_20,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_21,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_22,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_23,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_24,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_25,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_26,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_27,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_28,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_29,0
MR_PRINT_STU_STUCP,SC_DATA_VALUE_30,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_01,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_02,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_03,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_04,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_05,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_06,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_07,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_08,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_09,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_10,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_11,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_12,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_13,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_14,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_15,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_16,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_17,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_18,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_19,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_20,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_21,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_22,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_23,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_24,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_25,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_26,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_27,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_28,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_29,0
MR_PRINT_STU_STUCP,SC_COMM_DESCR_30,0
MR_PRINT_STU_STUCP,CHANGE_DATE_TIME,0
MR_PRINT_STU_STUCP,CHANGE_UID,0
MR_RC_STU_AT_RISK,DISTRICT,1
MR_RC_STU_AT_RISK,SCHOOL_YEAR,1
MR_RC_STU_AT_RISK,SUMMER_SCHOOL,1
MR_RC_STU_AT_RISK,BUILDING,1
MR_RC_STU_AT_RISK,STUDENT_ID,1
MR_RC_STU_AT_RISK,HONOR_TYPE,1
MR_RC_STU_AT_RISK,RC_RUN,1
MR_RC_STU_AT_RISK,AT_RISK_REASON,0
MR_RC_STU_AT_RISK,EXPIRE_YEAR,0
MR_RC_STU_AT_RISK,EXPIRE_RUN_TERM,0
MR_RC_STU_AT_RISK,CHANGE_DATE_TIME,0
MR_RC_STU_AT_RISK,CHANGE_UID,0
MR_RC_STU_AT_RISK,PLAN_NUM,0
MR_RC_STU_ATT_VIEW,DISTRICT,1
MR_RC_STU_ATT_VIEW,SCHOOL_YEAR,1
MR_RC_STU_ATT_VIEW,BUILDING,1
MR_RC_STU_ATT_VIEW,STUDENT_ID,1
MR_RC_STU_ATT_VIEW,VIEW_TYPE,1
MR_RC_STU_ATT_VIEW,RC_RUN,1
MR_RC_STU_ATT_VIEW,ABSENCE_VALUE_TOT,0
MR_RC_STU_ATT_VIEW,CHANGE_DATE_TIME,0
MR_RC_STU_ATT_VIEW,CHANGE_UID,0
MR_RC_STU_ELIGIBLE,DISTRICT,1
MR_RC_STU_ELIGIBLE,SCHOOL_YEAR,1
MR_RC_STU_ELIGIBLE,SUMMER_SCHOOL,1
MR_RC_STU_ELIGIBLE,BUILDING,1
MR_RC_STU_ELIGIBLE,STUDENT_ID,1
MR_RC_STU_ELIGIBLE,HONOR_TYPE,1
MR_RC_STU_ELIGIBLE,RC_RUN,1
MR_RC_STU_ELIGIBLE,ELIGIBILITY_CODE,0
MR_RC_STU_ELIGIBLE,EFFECTIVE_DATE,0
MR_RC_STU_ELIGIBLE,EXPIRATION_DATE,0
MR_RC_STU_ELIGIBLE,DISQUAL_REASON,0
MR_RC_STU_ELIGIBLE,CHANGE_DATE_TIME,0
MR_RC_STU_ELIGIBLE,CHANGE_UID,0
MR_RC_TAKEN,DISTRICT,1
MR_RC_TAKEN,SECTION_KEY,1
MR_RC_TAKEN,COURSE_SESSION,1
MR_RC_TAKEN,MARKING_PERIOD,1
MR_RC_TAKEN,CHANGE_DATE_TIME,0
MR_RC_TAKEN,CHANGE_UID,0
MR_RC_VIEW_ALT_LANG,DISTRICT,1
MR_RC_VIEW_ALT_LANG,SCHOOL_YEAR,1
MR_RC_VIEW_ALT_LANG,BUILDING,1
MR_RC_VIEW_ALT_LANG,VIEW_TYPE,1
MR_RC_VIEW_ALT_LANG,RC_RUN,1
MR_RC_VIEW_ALT_LANG,GRADE,1
MR_RC_VIEW_ALT_LANG,LANGUAGE,1
MR_RC_VIEW_ALT_LANG,LABEL_TYPE,1
MR_RC_VIEW_ALT_LANG,VIEW_ORDER,1
MR_RC_VIEW_ALT_LANG,DESCRIPTION,0
MR_RC_VIEW_ALT_LANG,CHANGE_DATE_TIME,0
MR_RC_VIEW_ALT_LANG,CHANGE_UID,0
MR_RC_VIEW_ATT,DISTRICT,1
MR_RC_VIEW_ATT,SCHOOL_YEAR,1
MR_RC_VIEW_ATT,BUILDING,1
MR_RC_VIEW_ATT,VIEW_TYPE,1
MR_RC_VIEW_ATT,RC_RUN,1
MR_RC_VIEW_ATT,GRADE,1
MR_RC_VIEW_ATT,ATT_VIEW_TYPE,0
MR_RC_VIEW_ATT,VIEW_ORDER,1
MR_RC_VIEW_ATT,ATT_TITLE,0
MR_RC_VIEW_ATT,ATT_VIEW_INTERVAL,0
MR_RC_VIEW_ATT,ATT_VIEW_SUM_BY,0
MR_RC_VIEW_ATT,ATT_VIEW_CODE_GRP,0
MR_RC_VIEW_ATT,CHANGE_DATE_TIME,0
MR_RC_VIEW_ATT,CHANGE_UID,0
MR_RC_VIEW_ATT_INT,DISTRICT,1
MR_RC_VIEW_ATT_INT,SCHOOL_YEAR,1
MR_RC_VIEW_ATT_INT,BUILDING,1
MR_RC_VIEW_ATT_INT,VIEW_TYPE,1
MR_RC_VIEW_ATT_INT,RC_RUN,1
MR_RC_VIEW_ATT_INT,GRADE,1
MR_RC_VIEW_ATT_INT,VIEW_ORDER,1
MR_RC_VIEW_ATT_INT,ATT_VIEW_INTERVAL,1
MR_RC_VIEW_ATT_INT,CHANGE_DATE_TIME,0
MR_RC_VIEW_ATT_INT,CHANGE_UID,0
MR_RC_VIEW_DET,DISTRICT,1
MR_RC_VIEW_DET,SCHOOL_YEAR,1
MR_RC_VIEW_DET,BUILDING,1
MR_RC_VIEW_DET,VIEW_TYPE,1
MR_RC_VIEW_DET,RC_RUN,1
MR_RC_VIEW_DET,GRADE,1
MR_RC_VIEW_DET,VIEW_SEQUENCE,1
MR_RC_VIEW_DET,VIEW_ORDER,0
MR_RC_VIEW_DET,TITLE,0
MR_RC_VIEW_DET,SLOT_TYPE,0
MR_RC_VIEW_DET,SLOT_CODE,0
MR_RC_VIEW_DET,CHANGE_DATE_TIME,0
MR_RC_VIEW_DET,CHANGE_UID,0
MR_RC_VIEW_GPA,DISTRICT,1
MR_RC_VIEW_GPA,SCHOOL_YEAR,1
MR_RC_VIEW_GPA,BUILDING,1
MR_RC_VIEW_GPA,VIEW_TYPE,1
MR_RC_VIEW_GPA,RC_RUN,1
MR_RC_VIEW_GPA,GRADE,1
MR_RC_VIEW_GPA,VIEW_SEQUENCE,1
MR_RC_VIEW_GPA,GPA_TYPE,0
MR_RC_VIEW_GPA,GPA_TITLE,0
MR_RC_VIEW_GPA,PRINT_CLASS_RANK,0
MR_RC_VIEW_GPA,CHANGE_DATE_TIME,0
MR_RC_VIEW_GPA,CHANGE_UID,0
MR_RC_VIEW_GRD_SC,DISTRICT,1
MR_RC_VIEW_GRD_SC,SCHOOL_YEAR,1
MR_RC_VIEW_GRD_SC,BUILDING,1
MR_RC_VIEW_GRD_SC,VIEW_TYPE,1
MR_RC_VIEW_GRD_SC,RC_RUN,1
MR_RC_VIEW_GRD_SC,GRADE,1
MR_RC_VIEW_GRD_SC,VIEW_ORDER,1
MR_RC_VIEW_GRD_SC,LABEL,0
MR_RC_VIEW_GRD_SC,GRADING_SCALE_TYPE,0
MR_RC_VIEW_GRD_SC,CHANGE_DATE_TIME,0
MR_RC_VIEW_GRD_SC,CHANGE_UID,0
MR_RC_VIEW_HDR,DISTRICT,1
MR_RC_VIEW_HDR,SCHOOL_YEAR,1
MR_RC_VIEW_HDR,BUILDING,1
MR_RC_VIEW_HDR,VIEW_TYPE,1
MR_RC_VIEW_HDR,RC_RUN,1
MR_RC_VIEW_HDR,GRADE,1
MR_RC_VIEW_HDR,REPORT_TEMPLATE,0
MR_RC_VIEW_HDR,RANK_GPA_TYPE,0
MR_RC_VIEW_HDR,PRINT_CLASS_RANK,0
MR_RC_VIEW_HDR,PRINT_HONOR_MSG,0
MR_RC_VIEW_HDR,PRINT_DROPPED_CRS,0
MR_RC_VIEW_HDR,PRINT_LEGEND,0
MR_RC_VIEW_HDR,PRINT_MBS,0
MR_RC_VIEW_HDR,HEADER_TEXT,0
MR_RC_VIEW_HDR,FOOTER_TEXT,0
MR_RC_VIEW_HDR,CREDIT_TO_PRINT,0
MR_RC_VIEW_HDR,USE_RC_HOLD,0
MR_RC_VIEW_HDR,HOLD_HEADER_TEXT,0
MR_RC_VIEW_HDR,HOLD_FOOTER_TEXT,0
MR_RC_VIEW_HDR,CURRENT_GPA,0
MR_RC_VIEW_HDR,SEMESTER_GPA,0
MR_RC_VIEW_HDR,CUMULATIVE_GPA,0
MR_RC_VIEW_HDR,CURRENT_CREDIT,0
MR_RC_VIEW_HDR,SEMESTER_CREDIT,0
MR_RC_VIEW_HDR,CUMULATIVE_CREDIT,0
MR_RC_VIEW_HDR,ALT_CURRENT_LBL,0
MR_RC_VIEW_HDR,ALT_SEMESTER_LBL,0
MR_RC_VIEW_HDR,ALT_CUMULATIVE_LBL,0
MR_RC_VIEW_HDR,CHANGE_DATE_TIME,0
MR_RC_VIEW_HDR,CHANGE_UID,0
MR_RC_VIEW_HONOR,DISTRICT,1
MR_RC_VIEW_HONOR,SCHOOL_YEAR,1
MR_RC_VIEW_HONOR,BUILDING,1
MR_RC_VIEW_HONOR,VIEW_TYPE,1
MR_RC_VIEW_HONOR,RC_RUN,1
MR_RC_VIEW_HONOR,GRADE,1
MR_RC_VIEW_HONOR,HONOR_SEQUENCE,1
MR_RC_VIEW_HONOR,HONOR_GPA_TYPE,0
MR_RC_VIEW_HONOR,CHANGE_DATE_TIME,0
MR_RC_VIEW_HONOR,CHANGE_UID,0
MR_RC_VIEW_LTDB,DISTRICT,1
MR_RC_VIEW_LTDB,SCHOOL_YEAR,1
MR_RC_VIEW_LTDB,BUILDING,1
MR_RC_VIEW_LTDB,VIEW_TYPE,1
MR_RC_VIEW_LTDB,RC_RUN,1
MR_RC_VIEW_LTDB,GRADE,1
MR_RC_VIEW_LTDB,VIEW_ORDER,1
MR_RC_VIEW_LTDB,LABEL,0
MR_RC_VIEW_LTDB,TEST_CODE,0
MR_RC_VIEW_LTDB,TEST_LEVEL,0
MR_RC_VIEW_LTDB,TEST_FORM,0
MR_RC_VIEW_LTDB,SUBTEST,0
MR_RC_VIEW_LTDB,SCORE_CODE,0
MR_RC_VIEW_LTDB,PRINT_TYPE,0
MR_RC_VIEW_LTDB,PRINT_NUMBER,0
MR_RC_VIEW_LTDB,CHANGE_DATE_TIME,0
MR_RC_VIEW_LTDB,CHANGE_UID,0
MR_RC_VIEW_MPS,DISTRICT,1
MR_RC_VIEW_MPS,SCHOOL_YEAR,1
MR_RC_VIEW_MPS,BUILDING,1
MR_RC_VIEW_MPS,VIEW_TYPE,1
MR_RC_VIEW_MPS,RC_RUN,1
MR_RC_VIEW_MPS,GRADE,1
MR_RC_VIEW_MPS,VIEW_SEQUENCE,1
MR_RC_VIEW_MPS,MARKING_PERIOD,1
MR_RC_VIEW_MPS,CHANGE_DATE_TIME,0
MR_RC_VIEW_MPS,CHANGE_UID,0
MR_RC_VIEW_SC_MP,DISTRICT,1
MR_RC_VIEW_SC_MP,SCHOOL_YEAR,1
MR_RC_VIEW_SC_MP,BUILDING,1
MR_RC_VIEW_SC_MP,VIEW_TYPE,1
MR_RC_VIEW_SC_MP,RC_RUN,1
MR_RC_VIEW_SC_MP,GRADE,1
MR_RC_VIEW_SC_MP,VIEW_SEQUENCE,1
MR_RC_VIEW_SC_MP,MARKING_PERIOD,1
MR_RC_VIEW_SC_MP,CHANGE_DATE_TIME,0
MR_RC_VIEW_SC_MP,CHANGE_UID,0
MR_RC_VIEW_SP,DISTRICT,1
MR_RC_VIEW_SP,SCHOOL_YEAR,1
MR_RC_VIEW_SP,BUILDING,1
MR_RC_VIEW_SP,VIEW_TYPE,1
MR_RC_VIEW_SP,RC_RUN,1
MR_RC_VIEW_SP,GRADE,1
MR_RC_VIEW_SP,VIEW_ORDER,1
MR_RC_VIEW_SP,LABEL,0
MR_RC_VIEW_SP,PROGRAM_ID,0
MR_RC_VIEW_SP,FIELD_NUMBER,0
MR_RC_VIEW_SP,PRINT_TYPE,0
MR_RC_VIEW_SP,CHANGE_DATE_TIME,0
MR_RC_VIEW_SP,CHANGE_UID,0
MR_RC_VIEW_SP_COLS,DISTRICT,1
MR_RC_VIEW_SP_COLS,SCHOOL_YEAR,1
MR_RC_VIEW_SP_COLS,BUILDING,1
MR_RC_VIEW_SP_COLS,VIEW_TYPE,1
MR_RC_VIEW_SP_COLS,RC_RUN,1
MR_RC_VIEW_SP_COLS,GRADE,1
MR_RC_VIEW_SP_COLS,COLUMN_NUMBER,1
MR_RC_VIEW_SP_COLS,TITLE,0
MR_RC_VIEW_SP_COLS,CHANGE_DATE_TIME,0
MR_RC_VIEW_SP_COLS,CHANGE_UID,0
MR_RC_VIEW_SP_MP,DISTRICT,1
MR_RC_VIEW_SP_MP,SCHOOL_YEAR,1
MR_RC_VIEW_SP_MP,BUILDING,1
MR_RC_VIEW_SP_MP,VIEW_TYPE,1
MR_RC_VIEW_SP_MP,RC_RUN,1
MR_RC_VIEW_SP_MP,GRADE,1
MR_RC_VIEW_SP_MP,PROGRAM_ID,1
MR_RC_VIEW_SP_MP,FIELD_NUMBER,1
MR_RC_VIEW_SP_MP,COLUMN_NUMBER,1
MR_RC_VIEW_SP_MP,SEARCH_MP,1
MR_RC_VIEW_SP_MP,CHANGE_DATE_TIME,0
MR_RC_VIEW_SP_MP,CHANGE_UID,0
MR_RC_VIEW_STUCMP,DISTRICT,1
MR_RC_VIEW_STUCMP,SCHOOL_YEAR,1
MR_RC_VIEW_STUCMP,BUILDING,1
MR_RC_VIEW_STUCMP,VIEW_TYPE,1
MR_RC_VIEW_STUCMP,RC_RUN,1
MR_RC_VIEW_STUCMP,GRADE,1
MR_RC_VIEW_STUCMP,VIEW_SEQUENCE,1
MR_RC_VIEW_STUCMP,VIEW_ORDER,0
MR_RC_VIEW_STUCMP,TITLE,0
MR_RC_VIEW_STUCMP,SLOT_TYPE,0
MR_RC_VIEW_STUCMP,SLOT_CODE,0
MR_RC_VIEW_STUCMP,CHANGE_DATE_TIME,0
MR_RC_VIEW_STUCMP,CHANGE_UID,0
MR_REQ_AREAS,DISTRICT,1
MR_REQ_AREAS,CODE,1
MR_REQ_AREAS,DESCRIPTION,0
MR_REQ_AREAS,AREA_TYPE,0
MR_REQ_AREAS,STATE_CODE_EQUIV,0
MR_REQ_AREAS,ACTIVE,0
MR_REQ_AREAS,CHANGE_DATE_TIME,0
MR_REQ_AREAS,CHANGE_UID,0
MR_SC_COMP_COMS,DISTRICT,1
MR_SC_COMP_COMS,BUILDING,1
MR_SC_COMP_COMS,SCHOOL_YEAR,1
MR_SC_COMP_COMS,COMPETENCY_GROUP,1
MR_SC_COMP_COMS,COMPETENCY_NUMBER,1
MR_SC_COMP_COMS,COMMENT_TYPE,1
MR_SC_COMP_COMS,CHANGE_DATE_TIME,0
MR_SC_COMP_COMS,CHANGE_UID,0
MR_SC_COMP_CRS,DISTRICT,1
MR_SC_COMP_CRS,BUILDING,1
MR_SC_COMP_CRS,SCHOOL_YEAR,1
MR_SC_COMP_CRS,COMPETENCY_GROUP,1
MR_SC_COMP_CRS,COURSE_BUILDING,1
MR_SC_COMP_CRS,COURSE,1
MR_SC_COMP_CRS,CHANGE_DATE_TIME,0
MR_SC_COMP_CRS,CHANGE_UID,0
MR_SC_COMP_DET,DISTRICT,1
MR_SC_COMP_DET,BUILDING,1
MR_SC_COMP_DET,SCHOOL_YEAR,1
MR_SC_COMP_DET,COMPETENCY_GROUP,1
MR_SC_COMP_DET,COMPETENCY_NUMBER,1
MR_SC_COMP_DET,DESCRIPTION,0
MR_SC_COMP_DET,SEQUENCE_NUMBER,0
MR_SC_COMP_DET,FORMAT_LEVEL,0
MR_SC_COMP_DET,HEADING_ONLY,0
MR_SC_COMP_DET,GRADING_SCALE,0
MR_SC_COMP_DET,USE_DEFAULT_MARK,0
MR_SC_COMP_DET,STATE_STANDARD_NUM,0
MR_SC_COMP_DET,ACCUMULATOR_TYPE,0
MR_SC_COMP_DET,CHANGE_DATE_TIME,0
MR_SC_COMP_DET,CHANGE_UID,0
MR_SC_COMP_DET,LSM_IDENTIFIER,0
MR_SC_COMP_DET_ALT_LANG,DISTRICT,1
MR_SC_COMP_DET_ALT_LANG,BUILDING,1
MR_SC_COMP_DET_ALT_LANG,SCHOOL_YEAR,1
MR_SC_COMP_DET_ALT_LANG,COMPETENCY_GROUP,1
MR_SC_COMP_DET_ALT_LANG,COMPETENCY_NUMBER,1
MR_SC_COMP_DET_ALT_LANG,LANGUAGE,1
MR_SC_COMP_DET_ALT_LANG,DESCRIPTION,0
MR_SC_COMP_DET_ALT_LANG,CHANGE_DATE_TIME,0
MR_SC_COMP_DET_ALT_LANG,CHANGE_UID,0
MR_SC_COMP_HDR,DISTRICT,1
MR_SC_COMP_HDR,SCHOOL_YEAR,1
MR_SC_COMP_HDR,DISTR_OR_BLDG,1
MR_SC_COMP_HDR,COMPETENCY_GROUP,1
MR_SC_COMP_HDR,BUILDING,1
MR_SC_COMP_HDR,BUILDING_TYPE,1
MR_SC_COMP_HDR,DESCRIPTION,0
MR_SC_COMP_HDR,SEQUENCE_ORDER,0
MR_SC_COMP_HDR,COMPETENCY_TYPE,0
MR_SC_COMP_HDR,CHANGE_DATE_TIME,0
MR_SC_COMP_HDR,CHANGE_UID,0
MR_SC_COMP_HDR,LSM_IDENTIFIER,0
MR_SC_COMP_MRKS,DISTRICT,1
MR_SC_COMP_MRKS,BUILDING,1
MR_SC_COMP_MRKS,SCHOOL_YEAR,1
MR_SC_COMP_MRKS,COMPETENCY_GROUP,1
MR_SC_COMP_MRKS,COMPETENCY_NUMBER,1
MR_SC_COMP_MRKS,MARK_TYPE,1
MR_SC_COMP_MRKS,CHANGE_DATE_TIME,0
MR_SC_COMP_MRKS,CHANGE_UID,0
MR_SC_COMP_STU,DISTRICT,1
MR_SC_COMP_STU,BUILDING,1
MR_SC_COMP_STU,SCHOOL_YEAR,1
MR_SC_COMP_STU,COMPETENCY_GROUP,1
MR_SC_COMP_STU,SEQUENCE_NUMBER,1
MR_SC_COMP_STU,AND_OR_FLAG,0
MR_SC_COMP_STU,TABLE_NAME,0
MR_SC_COMP_STU,SCREEN_TYPE,0
MR_SC_COMP_STU,SCREEN_NUMBER,0
MR_SC_COMP_STU,COLUMN_NAME,0
MR_SC_COMP_STU,FIELD_NUMBER,0
MR_SC_COMP_STU,OPERATOR,0
MR_SC_COMP_STU,SEARCH_VALUE,0
MR_SC_COMP_STU,CHANGE_DATE_TIME,0
MR_SC_COMP_STU,CHANGE_UID,0
MR_SC_CRS_TAKEN,DISTRICT,1
MR_SC_CRS_TAKEN,SECTION_KEY,1
MR_SC_CRS_TAKEN,COURSE_SESSION,1
MR_SC_CRS_TAKEN,COMPETENCY_GROUP,1
MR_SC_CRS_TAKEN,MARKING_PERIOD,1
MR_SC_CRS_TAKEN,CHANGE_DATE_TIME,0
MR_SC_CRS_TAKEN,CHANGE_UID,0
MR_SC_CRSSTU_TAKEN,DISTRICT,1
MR_SC_CRSSTU_TAKEN,SECTION_KEY,1
MR_SC_CRSSTU_TAKEN,COURSE_SESSION,1
MR_SC_CRSSTU_TAKEN,COMPETENCY_GROUP,1
MR_SC_CRSSTU_TAKEN,MARKING_PERIOD,1
MR_SC_CRSSTU_TAKEN,STUDENT_ID,1
MR_SC_CRSSTU_TAKEN,CHANGE_DATE_TIME,0
MR_SC_CRSSTU_TAKEN,CHANGE_UID,0
MR_SC_DISTR_FORMAT,DISTRICT,1
MR_SC_DISTR_FORMAT,SC_LEVEL,1
MR_SC_DISTR_FORMAT,FONT_TYPE,0
MR_SC_DISTR_FORMAT,FONT_SIZE,0
MR_SC_DISTR_FORMAT,COLOR,0
MR_SC_DISTR_FORMAT,FORMAT_BOLD,0
MR_SC_DISTR_FORMAT,FORMAT_UNDERLINE,0
MR_SC_DISTR_FORMAT,FORMAT_ITALICS,0
MR_SC_DISTR_FORMAT,CHANGE_DATE_TIME,0
MR_SC_DISTR_FORMAT,CHANGE_UID,0
MR_SC_GD_SCALE_ALT_LANG,DISTRICT,1
MR_SC_GD_SCALE_ALT_LANG,BUILDING,1
MR_SC_GD_SCALE_ALT_LANG,GRADING_SCALE_TYPE,1
MR_SC_GD_SCALE_ALT_LANG,DISPLAY_ORDER,1
MR_SC_GD_SCALE_ALT_LANG,LANGUAGE,1
MR_SC_GD_SCALE_ALT_LANG,DESCRIPTION,0
MR_SC_GD_SCALE_ALT_LANG,CHANGE_DATE_TIME,0
MR_SC_GD_SCALE_ALT_LANG,CHANGE_UID,0
MR_SC_GD_SCALE_DET,DISTRICT,1
MR_SC_GD_SCALE_DET,BUILDING,1
MR_SC_GD_SCALE_DET,GRADING_SCALE_TYPE,1
MR_SC_GD_SCALE_DET,DISPLAY_ORDER,1
MR_SC_GD_SCALE_DET,MARK,0
MR_SC_GD_SCALE_DET,DESCRIPTION,0
MR_SC_GD_SCALE_DET,POINT_VALUE,0
MR_SC_GD_SCALE_DET,PASSING_MARK,0
MR_SC_GD_SCALE_DET,ACTIVE,0
MR_SC_GD_SCALE_DET,AVERAGE,0
MR_SC_GD_SCALE_DET,COLOR_LEVEL,0
MR_SC_GD_SCALE_DET,CHANGE_DATE_TIME,0
MR_SC_GD_SCALE_DET,CHANGE_UID,0
MR_SC_GD_SCALE_HDR,DISTRICT,1
MR_SC_GD_SCALE_HDR,BUILDING,1
MR_SC_GD_SCALE_HDR,GRADING_SCALE_TYPE,1
MR_SC_GD_SCALE_HDR,DESCRIPTION,0
MR_SC_GD_SCALE_HDR,DEFAULT_MARK,0
MR_SC_GD_SCALE_HDR,CHANGE_DATE_TIME,0
MR_SC_GD_SCALE_HDR,CHANGE_UID,0
MR_SC_ST_STANDARD,DISTRICT,1
MR_SC_ST_STANDARD,STATE,1
MR_SC_ST_STANDARD,DOCUMENT_NAME,1
MR_SC_ST_STANDARD,SUBJECT,1
MR_SC_ST_STANDARD,SCHOOL_YEAR,1
MR_SC_ST_STANDARD,GRADE,1
MR_SC_ST_STANDARD,GUID,1
MR_SC_ST_STANDARD,STATE_STANDARD_NUM,0
MR_SC_ST_STANDARD,LEVEL_NUMBER,0
MR_SC_ST_STANDARD,NUM_OF_CHILDREN,0
MR_SC_ST_STANDARD,LABEL,0
MR_SC_ST_STANDARD,TITLE,0
MR_SC_ST_STANDARD,DESCRIPTION,0
MR_SC_ST_STANDARD,PARENT_GUID,0
MR_SC_ST_STANDARD,LOW_GRADE,0
MR_SC_ST_STANDARD,HIGH_GRADE,0
MR_SC_ST_STANDARD,AB_GUID,0
MR_SC_ST_STANDARD,PP_GUID,0
MR_SC_ST_STANDARD,PP_PARENT_GUID,0
MR_SC_ST_STANDARD,PP_ID,0
MR_SC_ST_STANDARD,PP_PARENT_ID,0
MR_SC_ST_STANDARD,RESERVED,0
MR_SC_ST_STANDARD,CHANGE_DATE_TIME,0
MR_SC_ST_STANDARD,CHANGE_UID,0
MR_SC_STU_COMMENT,DISTRICT,1
MR_SC_STU_COMMENT,SCHOOL_YEAR,1
MR_SC_STU_COMMENT,STUDENT_ID,1
MR_SC_STU_COMMENT,COMPETENCY_GROUP,1
MR_SC_STU_COMMENT,COMPETENCY_NUMBER,1
MR_SC_STU_COMMENT,MARKING_PERIOD,1
MR_SC_STU_COMMENT,BUILDING,0
MR_SC_STU_COMMENT,COMMENT_TYPE,1
MR_SC_STU_COMMENT,CODE,0
MR_SC_STU_COMMENT,CHANGE_DATE_TIME,0
MR_SC_STU_COMMENT,CHANGE_UID,0
MR_SC_STU_COMP,DISTRICT,1
MR_SC_STU_COMP,SCHOOL_YEAR,1
MR_SC_STU_COMP,STUDENT_ID,1
MR_SC_STU_COMP,COMPETENCY_GROUP,1
MR_SC_STU_COMP,COMPETENCY_NUMBER,1
MR_SC_STU_COMP,MARKING_PERIOD,1
MR_SC_STU_COMP,BUILDING,0
MR_SC_STU_COMP,MARK_TYPE,1
MR_SC_STU_COMP,MARK_VALUE,0
MR_SC_STU_COMP,MARK_OVERRIDE,0
MR_SC_STU_COMP,CHANGE_DATE_TIME,0
MR_SC_STU_COMP,CHANGE_UID,0
MR_SC_STU_CRS_COMM,DISTRICT,1
MR_SC_STU_CRS_COMM,SCHOOL_YEAR,1
MR_SC_STU_CRS_COMM,STUDENT_ID,1
MR_SC_STU_CRS_COMM,BUILDING,1
MR_SC_STU_CRS_COMM,COURSE,1
MR_SC_STU_CRS_COMM,COMPETENCY_GROUP,1
MR_SC_STU_CRS_COMM,COMPETENCY_NUMBER,1
MR_SC_STU_CRS_COMM,MARKING_PERIOD,1
MR_SC_STU_CRS_COMM,COMMENT_TYPE,1
MR_SC_STU_CRS_COMM,CODE,0
MR_SC_STU_CRS_COMM,CHANGE_DATE_TIME,0
MR_SC_STU_CRS_COMM,CHANGE_UID,0
MR_SC_STU_CRS_COMP,DISTRICT,1
MR_SC_STU_CRS_COMP,SCHOOL_YEAR,1
MR_SC_STU_CRS_COMP,STUDENT_ID,1
MR_SC_STU_CRS_COMP,BUILDING,1
MR_SC_STU_CRS_COMP,COURSE,1
MR_SC_STU_CRS_COMP,COMPETENCY_GROUP,1
MR_SC_STU_CRS_COMP,COMPETENCY_NUMBER,1
MR_SC_STU_CRS_COMP,MARKING_PERIOD,1
MR_SC_STU_CRS_COMP,MARK_TYPE,1
MR_SC_STU_CRS_COMP,MARK_VALUE,0
MR_SC_STU_CRS_COMP,MARK_OVERRIDE,0
MR_SC_STU_CRS_COMP,CHANGE_DATE_TIME,0
MR_SC_STU_CRS_COMP,CHANGE_UID,0
MR_SC_STU_TAKEN,DISTRICT,1
MR_SC_STU_TAKEN,BUILDING,1
MR_SC_STU_TAKEN,SCHOOL_YEAR,1
MR_SC_STU_TAKEN,COMPETENCY_GROUP,1
MR_SC_STU_TAKEN,STAFF_ID,1
MR_SC_STU_TAKEN,MARKING_PERIOD,1
MR_SC_STU_TAKEN,CHANGE_DATE_TIME,0
MR_SC_STU_TAKEN,CHANGE_UID,0
MR_SC_STU_TEA,DISTRICT,1
MR_SC_STU_TEA,BUILDING,1
MR_SC_STU_TEA,SCHOOL_YEAR,1
MR_SC_STU_TEA,STUDENT_ID,1
MR_SC_STU_TEA,COMPETENCY_GROUP,1
MR_SC_STU_TEA,STAFF_ID,0
MR_SC_STU_TEA,OVERRIDE,0
MR_SC_STU_TEA,CHANGE_DATE_TIME,0
MR_SC_STU_TEA,CHANGE_UID,0
MR_SC_STU_TEA_XREF,DISTRICT,0
MR_SC_STU_TEA_XREF,SCHOOL_YEAR,0
MR_SC_STU_TEA_XREF,STUDENT_ID,0
MR_SC_STU_TEA_XREF,COMPETENCY_GROUP,0
MR_SC_STU_TEA_XREF,STAFF_ID,0
MR_SC_STU_TEA_XREF,CHANGE_DATE_TIME,0
MR_SC_STU_TEA_XREF,CHANGE_UID,0
MR_SC_STU_TEXT,DISTRICT,1
MR_SC_STU_TEXT,BUILDING,1
MR_SC_STU_TEXT,SCHOOL_YEAR,1
MR_SC_STU_TEXT,STUDENT_ID,1
MR_SC_STU_TEXT,STAFF_ID,1
MR_SC_STU_TEXT,MARKING_PERIOD,1
MR_SC_STU_TEXT,STUDENT_TEXT,0
MR_SC_STU_TEXT,CHANGE_DATE_TIME,0
MR_SC_STU_TEXT,CHANGE_UID,0
MR_SC_STUSTU_TAKEN,DISTRICT,1
MR_SC_STUSTU_TAKEN,BUILDING,1
MR_SC_STUSTU_TAKEN,SCHOOL_YEAR,1
MR_SC_STUSTU_TAKEN,COMPETENCY_GROUP,1
MR_SC_STUSTU_TAKEN,STAFF_ID,1
MR_SC_STUSTU_TAKEN,MARKING_PERIOD,1
MR_SC_STUSTU_TAKEN,STUDENT_ID,1
MR_SC_STUSTU_TAKEN,CHANGE_DATE_TIME,0
MR_SC_STUSTU_TAKEN,CHANGE_UID,0
MR_SC_TEA_COMP,DISTRICT,1
MR_SC_TEA_COMP,BUILDING,1
MR_SC_TEA_COMP,SCHOOL_YEAR,1
MR_SC_TEA_COMP,COMPETENCY_GROUP,1
MR_SC_TEA_COMP,DEFAULT_ASSIGNMENT,1
MR_SC_TEA_COMP,STAFF_ID,1
MR_SC_TEA_COMP,CHANGE_DATE_TIME,0
MR_SC_TEA_COMP,CHANGE_UID,0
MR_STATE_COURSES,DISTRICT,1
MR_STATE_COURSES,SCHOOL_YEAR,1
MR_STATE_COURSES,STATE_CODE,1
MR_STATE_COURSES,DESCRIPTION,0
MR_STATE_COURSES,ABBREV_COURSE_NAME,0
MR_STATE_COURSES,FLAG_01,0
MR_STATE_COURSES,FLAG_02,0
MR_STATE_COURSES,FLAG_03,0
MR_STATE_COURSES,FLAG_04,0
MR_STATE_COURSES,FLAG_05,0
MR_STATE_COURSES,FLAG_06,0
MR_STATE_COURSES,FLAG_07,0
MR_STATE_COURSES,FLAG_08,0
MR_STATE_COURSES,FLAG_09,0
MR_STATE_COURSES,FLAG_10,0
MR_STATE_COURSES,ACTIVE,0
MR_STATE_COURSES,CHANGE_DATE_TIME,0
MR_STATE_COURSES,CHANGE_UID,0
MR_STU_ABSENCES,DISTRICT,1
MR_STU_ABSENCES,STUDENT_ID,1
MR_STU_ABSENCES,SECTION_KEY,1
MR_STU_ABSENCES,COURSE_SESSION,1
MR_STU_ABSENCES,MARKING_PERIOD,1
MR_STU_ABSENCES,ABSENCE_TYPE,1
MR_STU_ABSENCES,ABSENCE_VALUE,0
MR_STU_ABSENCES,OVERRIDE,0
MR_STU_ABSENCES,CHANGE_DATE_TIME,0
MR_STU_ABSENCES,CHANGE_UID,0
MR_STU_BLDG_TYPE,DISTRICT,1
MR_STU_BLDG_TYPE,STUDENT_ID,1
MR_STU_BLDG_TYPE,SECTION_KEY,1
MR_STU_BLDG_TYPE,COURSE_SESSION,1
MR_STU_BLDG_TYPE,BLDG_TYPE,1
MR_STU_BLDG_TYPE,CHANGE_DATE_TIME,0
MR_STU_BLDG_TYPE,CHANGE_UID,0
MR_STU_COMMENTS,DISTRICT,1
MR_STU_COMMENTS,SCHOOL_YEAR,1
MR_STU_COMMENTS,BUILDING,1
MR_STU_COMMENTS,STUDENT_ID,1
MR_STU_COMMENTS,SEQUENCE_NUM,1
MR_STU_COMMENTS,TRN_COMMENT,0
MR_STU_COMMENTS,EXCLUDE,0
MR_STU_COMMENTS,CHANGE_DATE_TIME,0
MR_STU_COMMENTS,CHANGE_UID,0
MR_STU_CRS_DATES,DISTRICT,1
MR_STU_CRS_DATES,STUDENT_ID,1
MR_STU_CRS_DATES,SECTION_KEY,1
MR_STU_CRS_DATES,COURSE_SESSION,1
MR_STU_CRS_DATES,START_DATE,1
MR_STU_CRS_DATES,END_DATE,0
MR_STU_CRS_DATES,CHANGE_DATE_TIME,0
MR_STU_CRS_DATES,CHANGE_UID,0
MR_STU_CRSEQU_ABS,DISTRICT,1
MR_STU_CRSEQU_ABS,SCHOOL_YEAR,1
MR_STU_CRSEQU_ABS,BUILDING,1
MR_STU_CRSEQU_ABS,STUDENT_ID,1
MR_STU_CRSEQU_ABS,STATE_ID,1
MR_STU_CRSEQU_ABS,SECTION_KEY,1
MR_STU_CRSEQU_ABS,COURSE_SESSION,1
MR_STU_CRSEQU_ABS,ABSENCE_TYPE,1
MR_STU_CRSEQU_ABS,MARKING_PERIOD,1
MR_STU_CRSEQU_ABS,ABSENCE_VALUE,0
MR_STU_CRSEQU_ABS,CHANGE_DATE_TIME,0
MR_STU_CRSEQU_ABS,CHANGE_UID,0
MR_STU_CRSEQU_CRD,DISTRICT,1
MR_STU_CRSEQU_CRD,SCHOOL_YEAR,1
MR_STU_CRSEQU_CRD,BUILDING,1
MR_STU_CRSEQU_CRD,STUDENT_ID,1
MR_STU_CRSEQU_CRD,STATE_ID,1
MR_STU_CRSEQU_CRD,SECTION_KEY,1
MR_STU_CRSEQU_CRD,COURSE_SESSION,1
MR_STU_CRSEQU_CRD,EQUIV_SEQUENCE,0
MR_STU_CRSEQU_CRD,ATT_CREDIT,0
MR_STU_CRSEQU_CRD,EARN_OVERRIDE,0
MR_STU_CRSEQU_CRD,EARN_CREDIT,0
MR_STU_CRSEQU_CRD,CHANGE_DATE_TIME,0
MR_STU_CRSEQU_CRD,CHANGE_UID,0
MR_STU_CRSEQU_MARK,DISTRICT,1
MR_STU_CRSEQU_MARK,SCHOOL_YEAR,1
MR_STU_CRSEQU_MARK,BUILDING,1
MR_STU_CRSEQU_MARK,STUDENT_ID,1
MR_STU_CRSEQU_MARK,STATE_ID,1
MR_STU_CRSEQU_MARK,SECTION_KEY,1
MR_STU_CRSEQU_MARK,COURSE_SESSION,1
MR_STU_CRSEQU_MARK,DEST_MARK_TYPE,1
MR_STU_CRSEQU_MARK,DESTINATION_MP,1
MR_STU_CRSEQU_MARK,SOURCE_MARK_TYPE,0
MR_STU_CRSEQU_MARK,SOURCE_MP,0
MR_STU_CRSEQU_MARK,MARK_VALUE,0
MR_STU_CRSEQU_MARK,CHANGE_DATE_TIME,0
MR_STU_CRSEQU_MARK,CHANGE_UID,0
MR_STU_EXCLUDE_BUILDING_TYPE,DISTRICT,1
MR_STU_EXCLUDE_BUILDING_TYPE,STUDENT_ID,1
MR_STU_EXCLUDE_BUILDING_TYPE,SECTION_KEY,1
MR_STU_EXCLUDE_BUILDING_TYPE,COURSE_SESSION,1
MR_STU_EXCLUDE_BUILDING_TYPE,BLDG_TYPE,1
MR_STU_EXCLUDE_BUILDING_TYPE,CHANGE_DATE_TIME,0
MR_STU_EXCLUDE_BUILDING_TYPE,CHANGE_UID,0
MR_STU_GPA,DISTRICT,1
MR_STU_GPA,STUDENT_ID,1
MR_STU_GPA,GPA_TYPE,1
MR_STU_GPA,SCHOOL_YEAR,1
MR_STU_GPA,RUN_TERM_YEAR,1
MR_STU_GPA,BUILDING,0
MR_STU_GPA,GRADE,0
MR_STU_GPA,NEEDS_RECALC,0
MR_STU_GPA,OVERRIDE,0
MR_STU_GPA,CUR_GPA_CALC_DATE,0
MR_STU_GPA,CUR_GPA,0
MR_STU_GPA,CUR_QUALITY_POINTS,0
MR_STU_GPA,CUR_ADD_ON_POINTS,0
MR_STU_GPA,CUR_ATT_CREDIT,0
MR_STU_GPA,CUR_EARN_CREDIT,0
MR_STU_GPA,CUR_RNK_CALC_DATE,0
MR_STU_GPA,CUR_RANK,0
MR_STU_GPA,CUR_PERCENTILE,0
MR_STU_GPA,CUR_DECILE,0
MR_STU_GPA,CUR_QUINTILE,0
MR_STU_GPA,CUR_QUARTILE,0
MR_STU_GPA,CUR_RANK_GPA,0
MR_STU_GPA,CUM_GPA_CALC_DATE,0
MR_STU_GPA,CUM_GPA,0
MR_STU_GPA,CUM_QUALITY_POINTS,0
MR_STU_GPA,CUM_ADD_ON_POINTS,0
MR_STU_GPA,CUM_ATT_CREDIT,0
MR_STU_GPA,CUM_EARN_CREDIT,0
MR_STU_GPA,CUM_RNK_CALC_DATE,0
MR_STU_GPA,CUM_RANK,0
MR_STU_GPA,CUM_PERCENTILE,0
MR_STU_GPA,CUM_DECILE,0
MR_STU_GPA,CUM_QUINTILE,0
MR_STU_GPA,CUM_QUARTILE,0
MR_STU_GPA,CUM_RANK_GPA,0
MR_STU_GPA,CUR_RANK_QUAL_PTS,0
MR_STU_GPA,CUM_RANK_QUAL_PTS,0
MR_STU_GPA,BLDG_OVERRIDE,0
MR_STU_GPA,CHANGE_DATE_TIME,0
MR_STU_GPA,CHANGE_UID,0
MR_STU_GRAD,DISTRICT,1
MR_STU_GRAD,STUDENT_ID,1
MR_STU_GRAD,REQUIRE_CODE,1
MR_STU_GRAD,SUBJ_AREA_CREDIT,0
MR_STU_GRAD,CUR_ATT_CREDITS,0
MR_STU_GRAD,CUR_EARN_CREDITS,0
MR_STU_GRAD,SUBJ_AREA_CRD_WAV,0
MR_STU_GRAD,CUR_ATT_CRD_WAV,0
MR_STU_GRAD,CUR_EARN_CRD_WAV,0
MR_STU_GRAD,CHANGE_DATE_TIME,0
MR_STU_GRAD,CHANGE_UID,0
MR_STU_GRAD_AREA,DISTRICT,1
MR_STU_GRAD_AREA,STUDENT_ID,1
MR_STU_GRAD_AREA,SECTION_KEY,1
MR_STU_GRAD_AREA,COURSE_SESSION,1
MR_STU_GRAD_AREA,REQUIRE_CODE,1
MR_STU_GRAD_AREA,CODE_OVERRIDE,0
MR_STU_GRAD_AREA,SUBJ_AREA_CREDIT,0
MR_STU_GRAD_AREA,CREDIT_OVERRIDE,0
MR_STU_GRAD_AREA,WAIVED,0
MR_STU_GRAD_AREA,CHANGE_DATE_TIME,0
MR_STU_GRAD_AREA,CHANGE_UID,0
MR_STU_GRAD_VALUE,DISTRICT,1
MR_STU_GRAD_VALUE,STUDENT_ID,1
MR_STU_GRAD_VALUE,REQUIRE_CODE,1
MR_STU_GRAD_VALUE,VALUE,0
MR_STU_GRAD_VALUE,CHANGE_DATE_TIME,0
MR_STU_GRAD_VALUE,CHANGE_UID,0
MR_STU_HDR,DISTRICT,1
MR_STU_HDR,STUDENT_ID,1
MR_STU_HDR,SECTION_KEY,1
MR_STU_HDR,COURSE_SESSION,1
MR_STU_HDR,RC_STATUS,0
MR_STU_HDR,ATT_CREDIT,0
MR_STU_HDR,ATT_OVERRIDE,0
MR_STU_HDR,ATT_OVR_REASON,0
MR_STU_HDR,EARN_CREDIT,0
MR_STU_HDR,EARN_OVERRIDE,0
MR_STU_HDR,ERN_OVR_REASON,0
MR_STU_HDR,STATE_CRS_EQUIV,0
MR_STU_HDR,ROW_IDENTITY,0
MR_STU_HDR,CHANGE_DATE_TIME,0
MR_STU_HDR,CHANGE_UID,0
MR_STU_HDR_SUBJ,DISTRICT,1
MR_STU_HDR_SUBJ,STUDENT_ID,1
MR_STU_HDR_SUBJ,SECTION_KEY,1
MR_STU_HDR_SUBJ,COURSE_SESSION,1
MR_STU_HDR_SUBJ,SUBJECT_AREA,1
MR_STU_HDR_SUBJ,VALUE,0
MR_STU_HDR_SUBJ,OVERRIDE,0
MR_STU_HDR_SUBJ,CHANGE_DATE_TIME,0
MR_STU_HDR_SUBJ,CHANGE_UID,0
MR_STU_HONOR,DISTRICT,1
MR_STU_HONOR,SCHOOL_YEAR,1
MR_STU_HONOR,BUILDING,1
MR_STU_HONOR,STUDENT_ID,1
MR_STU_HONOR,HONOR_TYPE,1
MR_STU_HONOR,RC_RUN,1
MR_STU_HONOR,QUALIFIED,0
MR_STU_HONOR,DISQUAL_REASON,0
MR_STU_HONOR,HONOR_GPA,0
MR_STU_HONOR,HONOR_CREDIT,0
MR_STU_HONOR,HONOR_POINTS,0
MR_STU_HONOR,CHANGE_DATE_TIME,0
MR_STU_HONOR,CHANGE_UID,0
MR_STU_MARKS,DISTRICT,1
MR_STU_MARKS,STUDENT_ID,1
MR_STU_MARKS,SECTION_KEY,1
MR_STU_MARKS,COURSE_SESSION,1
MR_STU_MARKS,MARKING_PERIOD,1
MR_STU_MARKS,MARK_TYPE,1
MR_STU_MARKS,MARK_VALUE,0
MR_STU_MARKS,OVERRIDE,0
MR_STU_MARKS,RAW_MARK_VALUE,0
MR_STU_MARKS,OVERRIDE_REASON,0
MR_STU_MARKS,OVERRIDE_NOTES,0
MR_STU_MARKS,ROW_IDENTITY,0
MR_STU_MARKS,CHANGE_DATE_TIME,0
MR_STU_MARKS,CHANGE_UID,0
MR_STU_MP,DISTRICT,1
MR_STU_MP,STUDENT_ID,1
MR_STU_MP,SECTION_KEY,1
MR_STU_MP,COURSE_SESSION,1
MR_STU_MP,MARKING_PERIOD,1
MR_STU_MP,ATT_CREDIT,0
MR_STU_MP,ATT_OVERRIDE,0
MR_STU_MP,ATT_OVR_REASON,0
MR_STU_MP,EARN_CREDIT,0
MR_STU_MP,EARN_OVERRIDE,0
MR_STU_MP,ERN_OVR_REASON,0
MR_STU_MP,TRAIL_FLAG,0
MR_STU_MP,CHANGE_DATE_TIME,0
MR_STU_MP,CHANGE_UID,0
MR_STU_MP_COMMENTS,DISTRICT,1
MR_STU_MP_COMMENTS,STUDENT_ID,1
MR_STU_MP_COMMENTS,SECTION_KEY,1
MR_STU_MP_COMMENTS,COURSE_SESSION,1
MR_STU_MP_COMMENTS,MARKING_PERIOD,1
MR_STU_MP_COMMENTS,COMMENT_TYPE,1
MR_STU_MP_COMMENTS,CODE,0
MR_STU_MP_COMMENTS,CHANGE_DATE_TIME,0
MR_STU_MP_COMMENTS,CHANGE_UID,0
MR_STU_OUT_COURSE,DISTRICT,1
MR_STU_OUT_COURSE,SCHOOL_YEAR,1
MR_STU_OUT_COURSE,STUDENT_ID,1
MR_STU_OUT_COURSE,BUILDING,0
MR_STU_OUT_COURSE,TRANSFER_SEQUENCE,1
MR_STU_OUT_COURSE,STATE_BUILDING,0
MR_STU_OUT_COURSE,BUILDING_NAME,0
MR_STU_OUT_COURSE,OUTSIDE_COURSE,0
MR_STU_OUT_COURSE,CHANGE_DATE_TIME,0
MR_STU_OUT_COURSE,CHANGE_UID,0
MR_STU_RUBRIC_COMP_SCORE,DISTRICT,1
MR_STU_RUBRIC_COMP_SCORE,RUBRIC_NUMBER,1
MR_STU_RUBRIC_COMP_SCORE,BUILDING,1
MR_STU_RUBRIC_COMP_SCORE,COMPETENCY_GROUP,1
MR_STU_RUBRIC_COMP_SCORE,STAFF_ID,1
MR_STU_RUBRIC_COMP_SCORE,ASMT_NUMBER,1
MR_STU_RUBRIC_COMP_SCORE,CRITERIA_NUMBER,1
MR_STU_RUBRIC_COMP_SCORE,STUDENT_ID,1
MR_STU_RUBRIC_COMP_SCORE,RUBRIC_SCORE,0
MR_STU_RUBRIC_COMP_SCORE,CHANGE_DATE_TIME,0
MR_STU_RUBRIC_COMP_SCORE,CHANGE_UID,0
MR_STU_RUBRIC_COMP_SCORE_HIST,DISTRICT,1
MR_STU_RUBRIC_COMP_SCORE_HIST,RUBRIC_NUMBER,1
MR_STU_RUBRIC_COMP_SCORE_HIST,BUILDING,1
MR_STU_RUBRIC_COMP_SCORE_HIST,COMPETENCY_GROUP,1
MR_STU_RUBRIC_COMP_SCORE_HIST,STAFF_ID,1
MR_STU_RUBRIC_COMP_SCORE_HIST,ASMT_NUMBER,1
MR_STU_RUBRIC_COMP_SCORE_HIST,CRITERIA_NUMBER,1
MR_STU_RUBRIC_COMP_SCORE_HIST,STUDENT_ID,1
MR_STU_RUBRIC_COMP_SCORE_HIST,SCORE_CHANGED_DATE,1
MR_STU_RUBRIC_COMP_SCORE_HIST,OLD_VALUE,0
MR_STU_RUBRIC_COMP_SCORE_HIST,NEW_VALUE,0
MR_STU_RUBRIC_COMP_SCORE_HIST,CHANGE_TYPE,0
MR_STU_RUBRIC_COMP_SCORE_HIST,PRIVATE_NOTES,0
MR_STU_RUBRIC_COMP_SCORE_HIST,CHANGE_DATE_TIME,0
MR_STU_RUBRIC_COMP_SCORE_HIST,CHANGE_UID,0
MR_STU_RUBRIC_SCORE,DISTRICT,1
MR_STU_RUBRIC_SCORE,RUBRIC_NUMBER,1
MR_STU_RUBRIC_SCORE,SECTION_KEY,1
MR_STU_RUBRIC_SCORE,COURSE_SESSION,1
MR_STU_RUBRIC_SCORE,ASMT_NUMBER,1
MR_STU_RUBRIC_SCORE,CRITERIA_NUMBER,1
MR_STU_RUBRIC_SCORE,STUDENT_ID,1
MR_STU_RUBRIC_SCORE,RUBRIC_SCORE,0
MR_STU_RUBRIC_SCORE,CHANGE_DATE_TIME,0
MR_STU_RUBRIC_SCORE,CHANGE_UID,0
MR_STU_RUBRIC_SCORE_HIST,DISTRICT,1
MR_STU_RUBRIC_SCORE_HIST,RUBRIC_NUMBER,1
MR_STU_RUBRIC_SCORE_HIST,SECTION_KEY,1
MR_STU_RUBRIC_SCORE_HIST,COURSE_SESSION,1
MR_STU_RUBRIC_SCORE_HIST,ASMT_NUMBER,1
MR_STU_RUBRIC_SCORE_HIST,CRITERIA_NUMBER,1
MR_STU_RUBRIC_SCORE_HIST,STUDENT_ID,1
MR_STU_RUBRIC_SCORE_HIST,SCORE_CHANGED_DATE,1
MR_STU_RUBRIC_SCORE_HIST,OLD_VALUE,0
MR_STU_RUBRIC_SCORE_HIST,NEW_VALUE,0
MR_STU_RUBRIC_SCORE_HIST,CHANGE_TYPE,0
MR_STU_RUBRIC_SCORE_HIST,PRIVATE_NOTES,0
MR_STU_RUBRIC_SCORE_HIST,CHANGE_DATE_TIME,0
MR_STU_RUBRIC_SCORE_HIST,CHANGE_UID,0
MR_STU_TAG_ALERT,DISTRICT,1
MR_STU_TAG_ALERT,STUDENT_ID,1
MR_STU_TAG_ALERT,REQ_GROUP,1
MR_STU_TAG_ALERT,REQUIRE_CODE,1
MR_STU_TAG_ALERT,CHANGE_DATE_TIME,0
MR_STU_TAG_ALERT,CHANGE_UID,0
MR_STU_TEXT,DISTRICT,1
MR_STU_TEXT,BUILDING,0
MR_STU_TEXT,STUDENT_ID,1
MR_STU_TEXT,SCHOOL_YEAR,0
MR_STU_TEXT,SECTION_KEY,1
MR_STU_TEXT,COURSE_SESSION,1
MR_STU_TEXT,STAFF_ID,0
MR_STU_TEXT,MARKING_PERIOD,1
MR_STU_TEXT,COMMENT_TEXT,0
MR_STU_TEXT,CHANGE_DATE_TIME,0
MR_STU_TEXT,CHANGE_UID,0
MR_STU_USER,DISTRICT,1
MR_STU_USER,SECTION_KEY,1
MR_STU_USER,COURSE_SESSION,1
MR_STU_USER,STUDENT_ID,1
MR_STU_USER,SCREEN_NUMBER,1
MR_STU_USER,FIELD_NUMBER,1
MR_STU_USER,FIELD_VALUE,0
MR_STU_USER,CHANGE_DATE_TIME,0
MR_STU_USER,CHANGE_UID,0
MR_STU_XFER_BLDGS,DISTRICT,1
MR_STU_XFER_BLDGS,SCHOOL_YEAR,1
MR_STU_XFER_BLDGS,STUDENT_ID,1
MR_STU_XFER_BLDGS,BUILDING,0
MR_STU_XFER_BLDGS,TRANSFER_SEQUENCE,1
MR_STU_XFER_BLDGS,STATE_BUILDING,0
MR_STU_XFER_BLDGS,BUILDING_NAME,0
MR_STU_XFER_BLDGS,GRADE,0
MR_STU_XFER_BLDGS,ABBREVIATION,0
MR_STU_XFER_BLDGS,STREET1,0
MR_STU_XFER_BLDGS,STREET2,0
MR_STU_XFER_BLDGS,CITY,0
MR_STU_XFER_BLDGS,STATE,0
MR_STU_XFER_BLDGS,ZIP_CODE,0
MR_STU_XFER_BLDGS,COUNTRY,0
MR_STU_XFER_BLDGS,PHONE,0
MR_STU_XFER_BLDGS,FAX,0
MR_STU_XFER_BLDGS,PRINCIPAL,0
MR_STU_XFER_BLDGS,BUILDING_TYPE,0
MR_STU_XFER_BLDGS,TRANSFER_COMMENT,0
MR_STU_XFER_BLDGS,STATE_CODE_EQUIV,0
MR_STU_XFER_BLDGS,ENTRY_DATE,0
MR_STU_XFER_BLDGS,WITHDRAWAL_DATE,0
MR_STU_XFER_BLDGS,ROW_IDENTITY,0
MR_STU_XFER_BLDGS,CHANGE_DATE_TIME,0
MR_STU_XFER_BLDGS,CHANGE_UID,0
MR_STU_XFER_RUNS,DISTRICT,1
MR_STU_XFER_RUNS,SCHOOL_YEAR,1
MR_STU_XFER_RUNS,STUDENT_ID,1
MR_STU_XFER_RUNS,TRANSFER_SEQUENCE,1
MR_STU_XFER_RUNS,RC_RUN,1
MR_STU_XFER_RUNS,CHANGE_DATE_TIME,0
MR_STU_XFER_RUNS,CHANGE_UID,0
MR_TRN_PRINT_HDR,DISTRICT,1
MR_TRN_PRINT_HDR,SCHOOL_YEAR,1
MR_TRN_PRINT_HDR,BUILDING,1
MR_TRN_PRINT_HDR,GROUP_BY,1
MR_TRN_PRINT_HDR,GRADE,1
MR_TRN_PRINT_HDR,RUN_TERM_YEAR,1
MR_TRN_PRINT_HDR,RUN_DATE,0
MR_TRN_PRINT_HDR,TRN_PRINT_KEY,0
MR_TRN_PRINT_HDR,BLDG_NAME,0
MR_TRN_PRINT_HDR,STREET1,0
MR_TRN_PRINT_HDR,STREET2,0
MR_TRN_PRINT_HDR,CITY,0
MR_TRN_PRINT_HDR,STATE,0
MR_TRN_PRINT_HDR,ZIP,0
MR_TRN_PRINT_HDR,PRINCIPAL,0
MR_TRN_PRINT_HDR,PHONE,0
MR_TRN_PRINT_HDR,CEEB_NUMBER,0
MR_TRN_PRINT_HDR,HEADER_TEXT,0
MR_TRN_PRINT_HDR,FOOTER_TEXT,0
MR_TRN_PRINT_HDR,DATA_TITLE_01,0
MR_TRN_PRINT_HDR,DATA_TITLE_02,0
MR_TRN_PRINT_HDR,DATA_TITLE_03,0
MR_TRN_PRINT_HDR,DATA_TITLE_04,0
MR_TRN_PRINT_HDR,DATA_TITLE_05,0
MR_TRN_PRINT_HDR,DATA_TITLE_06,0
MR_TRN_PRINT_HDR,DATA_TITLE_07,0
MR_TRN_PRINT_HDR,DATA_TITLE_08,0
MR_TRN_PRINT_HDR,DATA_TITLE_09,0
MR_TRN_PRINT_HDR,DATA_TITLE_10,0
MR_TRN_PRINT_HDR,DATA_TITLE_11,0
MR_TRN_PRINT_HDR,DATA_TITLE_12,0
MR_TRN_PRINT_HDR,DATA_TITLE_13,0
MR_TRN_PRINT_HDR,DATA_TITLE_14,0
MR_TRN_PRINT_HDR,DATA_TITLE_15,0
MR_TRN_PRINT_HDR,DATA_TITLE_16,0
MR_TRN_PRINT_HDR,DATA_TITLE_17,0
MR_TRN_PRINT_HDR,DATA_TITLE_18,0
MR_TRN_PRINT_HDR,DATA_TITLE_19,0
MR_TRN_PRINT_HDR,DATA_TITLE_20,0
MR_TRN_PRINT_HDR,DATA_TITLE_21,0
MR_TRN_PRINT_HDR,DATA_TITLE_22,0
MR_TRN_PRINT_HDR,DATA_TITLE_23,0
MR_TRN_PRINT_HDR,DATA_TITLE_24,0
MR_TRN_PRINT_HDR,DATA_TITLE_25,0
MR_TRN_PRINT_HDR,DATA_TITLE_26,0
MR_TRN_PRINT_HDR,DATA_TITLE_27,0
MR_TRN_PRINT_HDR,DATA_TITLE_28,0
MR_TRN_PRINT_HDR,DATA_TITLE_29,0
MR_TRN_PRINT_HDR,DATA_TITLE_30,0
MR_TRN_PRINT_HDR,CHANGE_DATE_TIME,0
MR_TRN_PRINT_HDR,CHANGE_UID,0
MR_TRN_PRT_CRS_UD,DISTRICT,1
MR_TRN_PRT_CRS_UD,MR_TRN_PRINT_KEY,1
MR_TRN_PRT_CRS_UD,SECTION_KEY,1
MR_TRN_PRT_CRS_UD,FIELD_LABEL01,0
MR_TRN_PRT_CRS_UD,FIELD_LABEL02,0
MR_TRN_PRT_CRS_UD,FIELD_LABEL03,0
MR_TRN_PRT_CRS_UD,FIELD_LABEL04,0
MR_TRN_PRT_CRS_UD,FIELD_LABEL05,0
MR_TRN_PRT_CRS_UD,FIELD_LABEL06,0
MR_TRN_PRT_CRS_UD,FIELD_LABEL07,0
MR_TRN_PRT_CRS_UD,FIELD_LABEL08,0
MR_TRN_PRT_CRS_UD,FIELD_LABEL09,0
MR_TRN_PRT_CRS_UD,FIELD_LABEL10,0
MR_TRN_PRT_CRS_UD,FIELD_VALUE01,0
MR_TRN_PRT_CRS_UD,FIELD_VALUE02,0
MR_TRN_PRT_CRS_UD,FIELD_VALUE03,0
MR_TRN_PRT_CRS_UD,FIELD_VALUE04,0
MR_TRN_PRT_CRS_UD,FIELD_VALUE05,0
MR_TRN_PRT_CRS_UD,FIELD_VALUE06,0
MR_TRN_PRT_CRS_UD,FIELD_VALUE07,0
MR_TRN_PRT_CRS_UD,FIELD_VALUE08,0
MR_TRN_PRT_CRS_UD,FIELD_VALUE09,0
MR_TRN_PRT_CRS_UD,FIELD_VALUE10,0
MR_TRN_PRT_CRS_UD,CHANGE_DATE_TIME,0
MR_TRN_PRT_CRS_UD,CHANGE_UID,0
MR_TRN_PRT_STU_ACT,DISTRICT,1
MR_TRN_PRT_STU_ACT,MR_TRN_PRINT_KEY,1
MR_TRN_PRT_STU_ACT,STUDENT_ID,1
MR_TRN_PRT_STU_ACT,ACTIVITY01,0
MR_TRN_PRT_STU_ACT,ACTIVITY02,0
MR_TRN_PRT_STU_ACT,ACTIVITY03,0
MR_TRN_PRT_STU_ACT,ACTIVITY04,0
MR_TRN_PRT_STU_ACT,ACTIVITY05,0
MR_TRN_PRT_STU_ACT,ACTIVITY06,0
MR_TRN_PRT_STU_ACT,ACTIVITY07,0
MR_TRN_PRT_STU_ACT,ACTIVITY08,0
MR_TRN_PRT_STU_ACT,ACTIVITY09,0
MR_TRN_PRT_STU_ACT,ACTIVITY10,0
MR_TRN_PRT_STU_ACT,ACTIVITY11,0
MR_TRN_PRT_STU_ACT,ACTIVITY12,0
MR_TRN_PRT_STU_ACT,ACTIVITY13,0
MR_TRN_PRT_STU_ACT,ACTIVITY14,0
MR_TRN_PRT_STU_ACT,ACTIVITY15,0
MR_TRN_PRT_STU_ACT,ACTIVITY16,0
MR_TRN_PRT_STU_ACT,ACTIVITY17,0
MR_TRN_PRT_STU_ACT,ACTIVITY18,0
MR_TRN_PRT_STU_ACT,ACTIVITY19,0
MR_TRN_PRT_STU_ACT,ACTIVITY20,0
MR_TRN_PRT_STU_ACT,ACTIVITY21,0
MR_TRN_PRT_STU_ACT,ACTIVITY22,0
MR_TRN_PRT_STU_ACT,ACTIVITY23,0
MR_TRN_PRT_STU_ACT,ACTIVITY24,0
MR_TRN_PRT_STU_ACT,ACTIVITY25,0
MR_TRN_PRT_STU_ACT,ACTIVITY26,0
MR_TRN_PRT_STU_ACT,ACTIVITY27,0
MR_TRN_PRT_STU_ACT,ACTIVITY28,0
MR_TRN_PRT_STU_ACT,ACTIVITY29,0
MR_TRN_PRT_STU_ACT,ACTIVITY30,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS01,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS02,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS03,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS04,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS05,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS06,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS07,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS08,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS09,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS10,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS11,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS12,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS13,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS14,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS15,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS16,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS17,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS18,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS19,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS20,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS21,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS22,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS23,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS24,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS25,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS26,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS27,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS28,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS29,0
MR_TRN_PRT_STU_ACT,ACTIVITY_YEARS30,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS01,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS02,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS03,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS04,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS05,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS06,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS07,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS08,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS09,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS10,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS11,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS12,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS13,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS14,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS15,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS16,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS17,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS18,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS19,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS20,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS21,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS22,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS23,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS24,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS25,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS26,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS27,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS28,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS29,0
MR_TRN_PRT_STU_ACT,ACTIVITY_COMMENTS30,0
MR_TRN_PRT_STU_ACT,CHANGE_DATE_TIME,0
MR_TRN_PRT_STU_ACT,CHANGE_UID,0
MR_TRN_PRT_STU_BRK,DISTRICT,1
MR_TRN_PRT_STU_BRK,MR_TRN_PRINT_KEY,1
MR_TRN_PRT_STU_BRK,STUDENT_ID,1
MR_TRN_PRT_STU_BRK,SCHOOL_YEAR,1
MR_TRN_PRT_STU_BRK,RUN_TERM_YEAR,1
MR_TRN_PRT_STU_BRK,DISPLAY_YEAR,0
MR_TRN_PRT_STU_BRK,STUDENT_GRADE,0
MR_TRN_PRT_STU_BRK,CUR_GPA,0
MR_TRN_PRT_STU_BRK,CUM_GPA,0
MR_TRN_PRT_STU_BRK,BUILDING,0
MR_TRN_PRT_STU_BRK,BLDG_NAME,0
MR_TRN_PRT_STU_BRK,CHANGE_DATE_TIME,0
MR_TRN_PRT_STU_BRK,CHANGE_UID,0
MR_TRN_PRT_STU_COM,DISTRICT,1
MR_TRN_PRT_STU_COM,MR_TRN_PRINT_KEY,1
MR_TRN_PRT_STU_COM,STUDENT_ID,1
MR_TRN_PRT_STU_COM,COMMENT01,0
MR_TRN_PRT_STU_COM,COMMENT02,0
MR_TRN_PRT_STU_COM,COMMENT03,0
MR_TRN_PRT_STU_COM,COMMENT04,0
MR_TRN_PRT_STU_COM,COMMENT05,0
MR_TRN_PRT_STU_COM,COMMENT06,0
MR_TRN_PRT_STU_COM,COMMENT07,0
MR_TRN_PRT_STU_COM,COMMENT08,0
MR_TRN_PRT_STU_COM,COMMENT09,0
MR_TRN_PRT_STU_COM,COMMENT10,0
MR_TRN_PRT_STU_COM,COMMENT11,0
MR_TRN_PRT_STU_COM,COMMENT12,0
MR_TRN_PRT_STU_COM,COMMENT13,0
MR_TRN_PRT_STU_COM,COMMENT14,0
MR_TRN_PRT_STU_COM,COMMENT15,0
MR_TRN_PRT_STU_COM,COMMENT16,0
MR_TRN_PRT_STU_COM,COMMENT17,0
MR_TRN_PRT_STU_COM,COMMENT18,0
MR_TRN_PRT_STU_COM,COMMENT19,0
MR_TRN_PRT_STU_COM,COMMENT20,0
MR_TRN_PRT_STU_COM,COMMENT21,0
MR_TRN_PRT_STU_COM,COMMENT22,0
MR_TRN_PRT_STU_COM,COMMENT23,0
MR_TRN_PRT_STU_COM,COMMENT24,0
MR_TRN_PRT_STU_COM,COMMENT25,0
MR_TRN_PRT_STU_COM,COMMENT26,0
MR_TRN_PRT_STU_COM,COMMENT27,0
MR_TRN_PRT_STU_COM,COMMENT28,0
MR_TRN_PRT_STU_COM,COMMENT29,0
MR_TRN_PRT_STU_COM,COMMENT30,0
MR_TRN_PRT_STU_COM,CHANGE_DATE_TIME,0
MR_TRN_PRT_STU_COM,CHANGE_UID,0
MR_TRN_PRT_STU_DET,DISTRICT,1
MR_TRN_PRT_STU_DET,MR_TRN_PRINT_KEY,1
MR_TRN_PRT_STU_DET,STUDENT_ID,1
MR_TRN_PRT_STU_DET,SECTION_KEY,1
MR_TRN_PRT_STU_DET,COURSE_BUILDING,0
MR_TRN_PRT_STU_DET,COURSE,0
MR_TRN_PRT_STU_DET,COURSE_SECTION,0
MR_TRN_PRT_STU_DET,COURSE_SESSION,1
MR_TRN_PRT_STU_DET,RUN_TERM_YEAR,1
MR_TRN_PRT_STU_DET,SCHOOL_YEAR,0
MR_TRN_PRT_STU_DET,STUDENT_GRADE,0
MR_TRN_PRT_STU_DET,DESCRIPTION,0
MR_TRN_PRT_STU_DET,CRS_PERIOD,0
MR_TRN_PRT_STU_DET,COURSE_LEVEL,0
MR_TRN_PRT_STU_DET,PRIMARY_STAFF_ID,0
MR_TRN_PRT_STU_DET,STAFF_NAME,0
MR_TRN_PRT_STU_DET,ROOM_ID,0
MR_TRN_PRT_STU_DET,ATTEMPTED_CREDIT,0
MR_TRN_PRT_STU_DET,EARNED_CREDIT,0
MR_TRN_PRT_STU_DET,DEPARTMENT,0
MR_TRN_PRT_STU_DET,DEPT_DESCR,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_01,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_02,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_03,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_04,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_05,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_06,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_07,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_08,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_09,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_10,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_11,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_12,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_13,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_14,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_15,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_16,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_17,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_18,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_19,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_20,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_21,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_22,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_23,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_24,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_25,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_26,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_27,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_28,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_29,0
MR_TRN_PRT_STU_DET,TRN_DATA_VALUE_30,0
MR_TRN_PRT_STU_DET,CHANGE_DATE_TIME,0
MR_TRN_PRT_STU_DET,CHANGE_UID,0
MR_TRN_PRT_STU_HDR,DISTRICT,1
MR_TRN_PRT_STU_HDR,TRN_PRINT_KEY,1
MR_TRN_PRT_STU_HDR,STUDENT_ID,1
MR_TRN_PRT_STU_HDR,STUDENT_NAME,0
MR_TRN_PRT_STU_HDR,BUILDING,0
MR_TRN_PRT_STU_HDR,GRADE,0
MR_TRN_PRT_STU_HDR,TRACK,0
MR_TRN_PRT_STU_HDR,COUNSELOR,0
MR_TRN_PRT_STU_HDR,HOUSE_TEAM,0
MR_TRN_PRT_STU_HDR,HOMEROOM_PRIMARY,0
MR_TRN_PRT_STU_HDR,BIRTHDATE,0
MR_TRN_PRT_STU_HDR,GRADUATION_YEAR,0
MR_TRN_PRT_STU_HDR,GRADUATION_DATE,0
MR_TRN_PRT_STU_HDR,GENDER,0
MR_TRN_PRT_STU_HDR,GUARDIAN_NAME,0
MR_TRN_PRT_STU_HDR,PHONE,0
MR_TRN_PRT_STU_HDR,APARTMENT,0
MR_TRN_PRT_STU_HDR,COMPLEX,0
MR_TRN_PRT_STU_HDR,STREET_NUMBER,0
MR_TRN_PRT_STU_HDR,STREET_PREFIX,0
MR_TRN_PRT_STU_HDR,STREET_NAME,0
MR_TRN_PRT_STU_HDR,STREET_SUFFIX,0
MR_TRN_PRT_STU_HDR,STREET_TYPE,0
MR_TRN_PRT_STU_HDR,CITY,0
MR_TRN_PRT_STU_HDR,STATE,0
MR_TRN_PRT_STU_HDR,ZIP,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_DESCR_01,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_DESCR_02,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_DESCR_03,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_DESCR_04,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_DESCR_05,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_DESCR_06,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_DESCR_07,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_DESCR_08,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_DESCR_09,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_DESCR_10,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_TOT_01,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_TOT_02,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_TOT_03,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_TOT_04,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_TOT_05,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_TOT_06,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_TOT_07,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_TOT_08,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_TOT_09,0
MR_TRN_PRT_STU_HDR,DAILY_ATT_TOT_10,0
MR_TRN_PRT_STU_HDR,GPA_TYPE_01,0
MR_TRN_PRT_STU_HDR,GPA_TYPE_02,0
MR_TRN_PRT_STU_HDR,GPA_TYPE_03,0
MR_TRN_PRT_STU_HDR,GPA_TYPE_04,0
MR_TRN_PRT_STU_HDR,GPA_TYPE_05,0
MR_TRN_PRT_STU_HDR,GPA_TYPE_06,0
MR_TRN_PRT_STU_HDR,GPA_TYPE_07,0
MR_TRN_PRT_STU_HDR,GPA_TYPE_08,0
MR_TRN_PRT_STU_HDR,GPA_TYPE_09,0
MR_TRN_PRT_STU_HDR,GPA_TYPE_10,0
MR_TRN_PRT_STU_HDR,GPA_DESCR_01,0
MR_TRN_PRT_STU_HDR,GPA_DESCR_02,0
MR_TRN_PRT_STU_HDR,GPA_DESCR_03,0
MR_TRN_PRT_STU_HDR,GPA_DESCR_04,0
MR_TRN_PRT_STU_HDR,GPA_DESCR_05,0
MR_TRN_PRT_STU_HDR,GPA_DESCR_06,0
MR_TRN_PRT_STU_HDR,GPA_DESCR_07,0
MR_TRN_PRT_STU_HDR,GPA_DESCR_08,0
MR_TRN_PRT_STU_HDR,GPA_DESCR_09,0
MR_TRN_PRT_STU_HDR,GPA_DESCR_10,0
MR_TRN_PRT_STU_HDR,GPA_CUM_01,0
MR_TRN_PRT_STU_HDR,GPA_CUM_02,0
MR_TRN_PRT_STU_HDR,GPA_CUM_03,0
MR_TRN_PRT_STU_HDR,GPA_CUM_04,0
MR_TRN_PRT_STU_HDR,GPA_CUM_05,0
MR_TRN_PRT_STU_HDR,GPA_CUM_06,0
MR_TRN_PRT_STU_HDR,GPA_CUM_07,0
MR_TRN_PRT_STU_HDR,GPA_CUM_08,0
MR_TRN_PRT_STU_HDR,GPA_CUM_09,0
MR_TRN_PRT_STU_HDR,GPA_CUM_10,0
MR_TRN_PRT_STU_HDR,GPA_RANK_01,0
MR_TRN_PRT_STU_HDR,GPA_RANK_02,0
MR_TRN_PRT_STU_HDR,GPA_RANK_03,0
MR_TRN_PRT_STU_HDR,GPA_RANK_04,0
MR_TRN_PRT_STU_HDR,GPA_RANK_05,0
MR_TRN_PRT_STU_HDR,GPA_RANK_06,0
MR_TRN_PRT_STU_HDR,GPA_RANK_07,0
MR_TRN_PRT_STU_HDR,GPA_RANK_08,0
MR_TRN_PRT_STU_HDR,GPA_RANK_09,0
MR_TRN_PRT_STU_HDR,GPA_RANK_10,0
MR_TRN_PRT_STU_HDR,GPA_PERCENTILE_01,0
MR_TRN_PRT_STU_HDR,GPA_PERCENTILE_02,0
MR_TRN_PRT_STU_HDR,GPA_PERCENTILE_03,0
MR_TRN_PRT_STU_HDR,GPA_PERCENTILE_04,0
MR_TRN_PRT_STU_HDR,GPA_PERCENTILE_05,0
MR_TRN_PRT_STU_HDR,GPA_PERCENTILE_06,0
MR_TRN_PRT_STU_HDR,GPA_PERCENTILE_07,0
MR_TRN_PRT_STU_HDR,GPA_PERCENTILE_08,0
MR_TRN_PRT_STU_HDR,GPA_PERCENTILE_09,0
MR_TRN_PRT_STU_HDR,GPA_PERCENTILE_10,0
MR_TRN_PRT_STU_HDR,GPA_DECILE_01,0
MR_TRN_PRT_STU_HDR,GPA_DECILE_02,0
MR_TRN_PRT_STU_HDR,GPA_DECILE_03,0
MR_TRN_PRT_STU_HDR,GPA_DECILE_04,0
MR_TRN_PRT_STU_HDR,GPA_DECILE_05,0
MR_TRN_PRT_STU_HDR,GPA_DECILE_06,0
MR_TRN_PRT_STU_HDR,GPA_DECILE_07,0
MR_TRN_PRT_STU_HDR,GPA_DECILE_08,0
MR_TRN_PRT_STU_HDR,GPA_DECILE_09,0
MR_TRN_PRT_STU_HDR,GPA_DECILE_10,0
MR_TRN_PRT_STU_HDR,GPA_QUARTILE_01,0
MR_TRN_PRT_STU_HDR,GPA_QUARTILE_02,0
MR_TRN_PRT_STU_HDR,GPA_QUARTILE_03,0
MR_TRN_PRT_STU_HDR,GPA_QUARTILE_04,0
MR_TRN_PRT_STU_HDR,GPA_QUARTILE_05,0
MR_TRN_PRT_STU_HDR,GPA_QUARTILE_06,0
MR_TRN_PRT_STU_HDR,GPA_QUARTILE_07,0
MR_TRN_PRT_STU_HDR,GPA_QUARTILE_08,0
MR_TRN_PRT_STU_HDR,GPA_QUARTILE_09,0
MR_TRN_PRT_STU_HDR,GPA_QUARTILE_10,0
MR_TRN_PRT_STU_HDR,GPA_QUINTILE_01,0
MR_TRN_PRT_STU_HDR,GPA_QUINTILE_02,0
MR_TRN_PRT_STU_HDR,GPA_QUINTILE_03,0
MR_TRN_PRT_STU_HDR,GPA_QUINTILE_04,0
MR_TRN_PRT_STU_HDR,GPA_QUINTILE_05,0
MR_TRN_PRT_STU_HDR,GPA_QUINTILE_06,0
MR_TRN_PRT_STU_HDR,GPA_QUINTILE_07,0
MR_TRN_PRT_STU_HDR,GPA_QUINTILE_08,0
MR_TRN_PRT_STU_HDR,GPA_QUINTILE_09,0
MR_TRN_PRT_STU_HDR,GPA_QUINTILE_10,0
MR_TRN_PRT_STU_HDR,GPA_CLASS_SIZE_01,0
MR_TRN_PRT_STU_HDR,GPA_CLASS_SIZE_02,0
MR_TRN_PRT_STU_HDR,GPA_CLASS_SIZE_03,0
MR_TRN_PRT_STU_HDR,GPA_CLASS_SIZE_04,0
MR_TRN_PRT_STU_HDR,GPA_CLASS_SIZE_05,0
MR_TRN_PRT_STU_HDR,GPA_CLASS_SIZE_06,0
MR_TRN_PRT_STU_HDR,GPA_CLASS_SIZE_07,0
MR_TRN_PRT_STU_HDR,GPA_CLASS_SIZE_08,0
MR_TRN_PRT_STU_HDR,GPA_CLASS_SIZE_09,0
MR_TRN_PRT_STU_HDR,GPA_CLASS_SIZE_10,0
MR_TRN_PRT_STU_HDR,REPORT_TEMPLATE,0
MR_TRN_PRT_STU_HDR,GENDER_IDENTITY,0
MR_TRN_PRT_STU_HDR,CHANGE_DATE_TIME,0
MR_TRN_PRT_STU_HDR,CHANGE_UID,0
MR_TRN_PRT_STU_LTD,DISTRICT,1
MR_TRN_PRT_STU_LTD,MR_TRN_PRINT_KEY,1
MR_TRN_PRT_STU_LTD,STUDENT_ID,1
MR_TRN_PRT_STU_LTD,TEST_CODE,1
MR_TRN_PRT_STU_LTD,TEST_DATE,1
MR_TRN_PRT_STU_LTD,LTDB_TITLE_01,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_02,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_03,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_04,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_05,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_06,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_07,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_08,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_09,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_10,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_11,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_12,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_13,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_14,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_15,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_16,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_17,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_18,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_19,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_20,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_21,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_22,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_23,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_24,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_25,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_26,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_27,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_28,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_29,0
MR_TRN_PRT_STU_LTD,LTDB_TITLE_30,0
MR_TRN_PRT_STU_LTD,SCORE01,0
MR_TRN_PRT_STU_LTD,SCORE02,0
MR_TRN_PRT_STU_LTD,SCORE03,0
MR_TRN_PRT_STU_LTD,SCORE04,0
MR_TRN_PRT_STU_LTD,SCORE05,0
MR_TRN_PRT_STU_LTD,SCORE06,0
MR_TRN_PRT_STU_LTD,SCORE07,0
MR_TRN_PRT_STU_LTD,SCORE08,0
MR_TRN_PRT_STU_LTD,SCORE09,0
MR_TRN_PRT_STU_LTD,SCORE10,0
MR_TRN_PRT_STU_LTD,SCORE11,0
MR_TRN_PRT_STU_LTD,SCORE12,0
MR_TRN_PRT_STU_LTD,SCORE13,0
MR_TRN_PRT_STU_LTD,SCORE14,0
MR_TRN_PRT_STU_LTD,SCORE15,0
MR_TRN_PRT_STU_LTD,SCORE16,0
MR_TRN_PRT_STU_LTD,SCORE17,0
MR_TRN_PRT_STU_LTD,SCORE18,0
MR_TRN_PRT_STU_LTD,SCORE19,0
MR_TRN_PRT_STU_LTD,SCORE20,0
MR_TRN_PRT_STU_LTD,SCORE21,0
MR_TRN_PRT_STU_LTD,SCORE22,0
MR_TRN_PRT_STU_LTD,SCORE23,0
MR_TRN_PRT_STU_LTD,SCORE24,0
MR_TRN_PRT_STU_LTD,SCORE25,0
MR_TRN_PRT_STU_LTD,SCORE26,0
MR_TRN_PRT_STU_LTD,SCORE27,0
MR_TRN_PRT_STU_LTD,SCORE28,0
MR_TRN_PRT_STU_LTD,SCORE29,0
MR_TRN_PRT_STU_LTD,SCORE30,0
MR_TRN_PRT_STU_LTD,TEST_DATE01,0
MR_TRN_PRT_STU_LTD,TEST_DATE02,0
MR_TRN_PRT_STU_LTD,TEST_DATE03,0
MR_TRN_PRT_STU_LTD,TEST_DATE04,0
MR_TRN_PRT_STU_LTD,TEST_DATE05,0
MR_TRN_PRT_STU_LTD,TEST_DATE06,0
MR_TRN_PRT_STU_LTD,TEST_DATE07,0
MR_TRN_PRT_STU_LTD,TEST_DATE08,0
MR_TRN_PRT_STU_LTD,TEST_DATE09,0
MR_TRN_PRT_STU_LTD,TEST_DATE10,0
MR_TRN_PRT_STU_LTD,TEST_DATE11,0
MR_TRN_PRT_STU_LTD,TEST_DATE12,0
MR_TRN_PRT_STU_LTD,TEST_DATE13,0
MR_TRN_PRT_STU_LTD,TEST_DATE14,0
MR_TRN_PRT_STU_LTD,TEST_DATE15,0
MR_TRN_PRT_STU_LTD,TEST_DATE16,0
MR_TRN_PRT_STU_LTD,TEST_DATE17,0
MR_TRN_PRT_STU_LTD,TEST_DATE18,0
MR_TRN_PRT_STU_LTD,TEST_DATE19,0
MR_TRN_PRT_STU_LTD,TEST_DATE20,0
MR_TRN_PRT_STU_LTD,TEST_DATE21,0
MR_TRN_PRT_STU_LTD,TEST_DATE22,0
MR_TRN_PRT_STU_LTD,TEST_DATE23,0
MR_TRN_PRT_STU_LTD,TEST_DATE24,0
MR_TRN_PRT_STU_LTD,TEST_DATE25,0
MR_TRN_PRT_STU_LTD,TEST_DATE26,0
MR_TRN_PRT_STU_LTD,TEST_DATE27,0
MR_TRN_PRT_STU_LTD,TEST_DATE28,0
MR_TRN_PRT_STU_LTD,TEST_DATE29,0
MR_TRN_PRT_STU_LTD,TEST_DATE30,0
MR_TRN_PRT_STU_LTD,CHANGE_DATE_TIME,0
MR_TRN_PRT_STU_LTD,CHANGE_UID,0
MR_TRN_PRT_STU_MED,DISTRICT,1
MR_TRN_PRT_STU_MED,MR_TRN_PRINT_KEY,1
MR_TRN_PRT_STU_MED,STUDENT_ID,1
MR_TRN_PRT_STU_MED,SHOT_ORDER,1
MR_TRN_PRT_STU_MED,SHOT_CODE,1
MR_TRN_PRT_STU_MED,SHOT_TITLE,0
MR_TRN_PRT_STU_MED,EXEMPT,0
MR_TRN_PRT_STU_MED,HAD_DISEASE,0
MR_TRN_PRT_STU_MED,SHOT_DATE_01,0
MR_TRN_PRT_STU_MED,SHOT_DATE_02,0
MR_TRN_PRT_STU_MED,SHOT_DATE_03,0
MR_TRN_PRT_STU_MED,SHOT_DATE_04,0
MR_TRN_PRT_STU_MED,SHOT_DATE_05,0
MR_TRN_PRT_STU_MED,SHOT_DATE_06,0
MR_TRN_PRT_STU_MED,SHOT_DATE_07,0
MR_TRN_PRT_STU_MED,SHOT_DATE_08,0
MR_TRN_PRT_STU_MED,SHOT_DATE_09,0
MR_TRN_PRT_STU_MED,SHOT_DATE_10,0
MR_TRN_PRT_STU_MED,CHANGE_DATE_TIME,0
MR_TRN_PRT_STU_MED,CHANGE_UID,0
MR_TRN_PRT_STU_REQ,DISTRICT,1
MR_TRN_PRT_STU_REQ,MR_TRN_PRINT_KEY,1
MR_TRN_PRT_STU_REQ,STUDENT_ID,1
MR_TRN_PRT_STU_REQ,REQ_GROUP,0
MR_TRN_PRT_STU_REQ,GRADUATION_YEAR,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE01,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE02,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE03,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE04,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE05,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE06,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE07,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE08,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE09,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE10,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE11,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE12,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE13,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE14,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE15,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE16,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE17,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE18,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE19,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE20,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE21,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE22,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE23,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE24,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE25,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE26,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE27,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE28,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE29,0
MR_TRN_PRT_STU_REQ,REQUIRE_CODE30,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC01,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC02,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC03,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC04,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC05,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC06,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC07,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC08,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC09,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC10,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC11,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC12,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC13,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC14,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC15,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC16,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC17,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC18,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC19,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC20,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC21,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC22,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC23,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC24,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC25,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC26,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC27,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC28,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC29,0
MR_TRN_PRT_STU_REQ,REQUIRE_DESC30,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT01,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT02,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT03,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT04,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT05,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT06,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT07,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT08,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT09,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT10,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT11,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT12,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT13,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT14,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT15,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT16,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT17,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT18,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT19,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT20,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT21,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT22,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT23,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT24,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT25,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT26,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT27,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT28,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT29,0
MR_TRN_PRT_STU_REQ,SUBJ_AREA_CREDIT30,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS01,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS02,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS03,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS04,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS05,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS06,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS07,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS08,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS09,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS10,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS11,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS12,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS13,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS14,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS15,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS16,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS17,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS18,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS19,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS20,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS21,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS22,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS23,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS24,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS25,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS26,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS27,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS28,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS29,0
MR_TRN_PRT_STU_REQ,CUR_ATT_CREDITS30,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS01,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS02,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS03,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS04,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS05,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS06,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS07,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS08,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS09,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS10,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS11,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS12,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS13,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS14,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS15,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS16,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS17,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS18,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS19,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS20,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS21,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS22,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS23,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS24,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS25,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS26,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS27,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS28,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS29,0
MR_TRN_PRT_STU_REQ,CUR_EARN_CREDITS30,0
MR_TRN_PRT_STU_REQ,CHANGE_DATE_TIME,0
MR_TRN_PRT_STU_REQ,CHANGE_UID,0
MR_TRN_VIEW_ATT,DISTRICT,1
MR_TRN_VIEW_ATT,BUILDING,1
MR_TRN_VIEW_ATT,TYPE,1
MR_TRN_VIEW_ATT,GRADE,1
MR_TRN_VIEW_ATT,GROUP_BY,1
MR_TRN_VIEW_ATT,ATT_VIEW_TYPE,0
MR_TRN_VIEW_ATT,VIEW_ORDER,1
MR_TRN_VIEW_ATT,ATT_TITLE,0
MR_TRN_VIEW_ATT,ATT_VIEW_INTERVAL,0
MR_TRN_VIEW_ATT,ATT_VIEW_SUM_BY,0
MR_TRN_VIEW_ATT,ATT_VIEW_CODE_GRP,0
MR_TRN_VIEW_ATT,CHANGE_DATE_TIME,0
MR_TRN_VIEW_ATT,CHANGE_UID,0
MR_TRN_VIEW_BLDTYP,DISTRICT,1
MR_TRN_VIEW_BLDTYP,BUILDING,1
MR_TRN_VIEW_BLDTYP,TYPE,1
MR_TRN_VIEW_BLDTYP,GRADE,1
MR_TRN_VIEW_BLDTYP,GROUP_BY,1
MR_TRN_VIEW_BLDTYP,BLDG_TYPE,1
MR_TRN_VIEW_BLDTYP,CHANGE_DATE_TIME,0
MR_TRN_VIEW_BLDTYP,CHANGE_UID,0
MR_TRN_VIEW_DET,DISTRICT,1
MR_TRN_VIEW_DET,BUILDING,1
MR_TRN_VIEW_DET,TYPE,1
MR_TRN_VIEW_DET,GRADE,1
MR_TRN_VIEW_DET,GROUP_BY,1
MR_TRN_VIEW_DET,RUN_TERM_YEAR,1
MR_TRN_VIEW_DET,VIEW_SEQUENCE,1
MR_TRN_VIEW_DET,TITLE,0
MR_TRN_VIEW_DET,VIEW_ORDER,0
MR_TRN_VIEW_DET,SLOT_TYPE,0
MR_TRN_VIEW_DET,SLOT_CODE,0
MR_TRN_VIEW_DET,CHANGE_DATE_TIME,0
MR_TRN_VIEW_DET,CHANGE_UID,0
MR_TRN_VIEW_GPA,DISTRICT,1
MR_TRN_VIEW_GPA,BUILDING,1
MR_TRN_VIEW_GPA,TYPE,1
MR_TRN_VIEW_GPA,GRADE,1
MR_TRN_VIEW_GPA,GROUP_BY,1
MR_TRN_VIEW_GPA,GPA_TYPE,1
MR_TRN_VIEW_GPA,VIEW_ORDER,0
MR_TRN_VIEW_GPA,GPA_TITLE,0
MR_TRN_VIEW_GPA,INCLUDE_RANK,0
MR_TRN_VIEW_GPA,INCLUDE_PERCENTILE,0
MR_TRN_VIEW_GPA,INCLUDE_DECILE,0
MR_TRN_VIEW_GPA,INCLUDE_QUARTILE,0
MR_TRN_VIEW_GPA,INCLUDE_QUINTILE,0
MR_TRN_VIEW_GPA,GPA_LEVEL,0
MR_TRN_VIEW_GPA,CHANGE_DATE_TIME,0
MR_TRN_VIEW_GPA,CHANGE_UID,0
MR_TRN_VIEW_HDR,DISTRICT,1
MR_TRN_VIEW_HDR,BUILDING,1
MR_TRN_VIEW_HDR,TYPE,1
MR_TRN_VIEW_HDR,GRADE,1
MR_TRN_VIEW_HDR,GROUP_BY,1
MR_TRN_VIEW_HDR,DISPLAY_ATTCREDIT,0
MR_TRN_VIEW_HDR,DISPLAY_ERNCREDIT,0
MR_TRN_VIEW_HDR,DISPLAY_CRSLEVEL,0
MR_TRN_VIEW_HDR,DISPLAY_CRSTYPE,0
MR_TRN_VIEW_HDR,STU_ADDRESS_TYPE,0
MR_TRN_VIEW_HDR,PRINT_BLDG_INFO,0
MR_TRN_VIEW_HDR,PRINT_STU_DATA,0
MR_TRN_VIEW_HDR,PRINT_CREDIT_SUM,0
MR_TRN_VIEW_HDR,CRS_AREA_GPA,0
MR_TRN_VIEW_HDR,PRINT_CLASS_RANK,0
MR_TRN_VIEW_HDR,PRINT_COMMENTS,0
MR_TRN_VIEW_HDR,PRINT_ACTIVITIES,0
MR_TRN_VIEW_HDR,PRINT_GRAD_REQ,0
MR_TRN_VIEW_HDR,CEEB_NUMBER,0
MR_TRN_VIEW_HDR,HEADER_TEXT,0
MR_TRN_VIEW_HDR,FOOTER_TEXT,0
MR_TRN_VIEW_HDR,REPORT_TEMPLATE,0
MR_TRN_VIEW_HDR,CHANGE_DATE_TIME,0
MR_TRN_VIEW_HDR,CHANGE_UID,0
MR_TRN_VIEW_LTDB,DISTRICT,1
MR_TRN_VIEW_LTDB,BUILDING,1
MR_TRN_VIEW_LTDB,TYPE,1
MR_TRN_VIEW_LTDB,GRADE,1
MR_TRN_VIEW_LTDB,GROUP_BY,1
MR_TRN_VIEW_LTDB,VIEW_ORDER,1
MR_TRN_VIEW_LTDB,LABEL,0
MR_TRN_VIEW_LTDB,TEST_CODE,0
MR_TRN_VIEW_LTDB,TEST_LEVEL,0
MR_TRN_VIEW_LTDB,TEST_FORM,0
MR_TRN_VIEW_LTDB,SUBTEST,0
MR_TRN_VIEW_LTDB,SCORE_CODE,0
MR_TRN_VIEW_LTDB,PRINT_TYPE,0
MR_TRN_VIEW_LTDB,PRINT_NUMBER,0
MR_TRN_VIEW_LTDB,PRINT_BLANK,0
MR_TRN_VIEW_LTDB,GROUP_SCORES,0
MR_TRN_VIEW_LTDB,CHANGE_DATE_TIME,0
MR_TRN_VIEW_LTDB,CHANGE_UID,0
MR_TRN_VIEW_MED,DISTRICT,1
MR_TRN_VIEW_MED,BUILDING,1
MR_TRN_VIEW_MED,TYPE,1
MR_TRN_VIEW_MED,GRADE,1
MR_TRN_VIEW_MED,GROUP_BY,1
MR_TRN_VIEW_MED,SERIES_SHOT,1
MR_TRN_VIEW_MED,VIEW_ORDER,0
MR_TRN_VIEW_MED,SHOT_TITLE,0
MR_TRN_VIEW_MED,CHANGE_DATE_TIME,0
MR_TRN_VIEW_MED,CHANGE_UID,0
MR_TRN_VIEW_MPS,DISTRICT,1
MR_TRN_VIEW_MPS,BUILDING,1
MR_TRN_VIEW_MPS,TYPE,1
MR_TRN_VIEW_MPS,GRADE,1
MR_TRN_VIEW_MPS,GROUP_BY,1
MR_TRN_VIEW_MPS,RUN_TERM_YEAR,1
MR_TRN_VIEW_MPS,VIEW_SEQUENCE,1
MR_TRN_VIEW_MPS,MARKING_PERIOD,1
MR_TRN_VIEW_MPS,CHANGE_DATE_TIME,0
MR_TRN_VIEW_MPS,CHANGE_UID,0
MR_TRN_VIEW_MS,DISTRICT,1
MR_TRN_VIEW_MS,BUILDING,1
MR_TRN_VIEW_MS,GRADE,1
MR_TRN_VIEW_MS,VIEW_ID,1
MR_TRN_VIEW_MS,VIEW_ORDER,0
MR_TRN_VIEW_MS,TABLE_NAME,0
MR_TRN_VIEW_MS,COLUMN_NAME,0
MR_TRN_VIEW_MS,SCREEN_NUMBER,0
MR_TRN_VIEW_MS,FIELD_NUMBER,0
MR_TRN_VIEW_MS,DEFAULT_VALUE,0
MR_TRN_VIEW_MS,CHANGE_DATE_TIME,0
MR_TRN_VIEW_MS,CHANGE_UID,0
MR_TRN_VIEW_UD,DISTRICT,1
MR_TRN_VIEW_UD,BUILDING,1
MR_TRN_VIEW_UD,TYPE,1
MR_TRN_VIEW_UD,GRADE,1
MR_TRN_VIEW_UD,GROUP_BY,1
MR_TRN_VIEW_UD,RUN_TERM_YEAR,1
MR_TRN_VIEW_UD,SCREEN_TYPE,1
MR_TRN_VIEW_UD,SCREEN_NUMBER,1
MR_TRN_VIEW_UD,FIELD_NUMBER,1
MR_TRN_VIEW_UD,CHANGE_DATE_TIME,0
MR_TRN_VIEW_UD,CHANGE_UID,0
MR_TX_CREDIT_SETUP,DISTRICT,1
MR_TX_CREDIT_SETUP,BUILDING,1
MR_TX_CREDIT_SETUP,SCHOOL_YEAR,1
MR_TX_CREDIT_SETUP,PROCESS_EOC,0
MR_TX_CREDIT_SETUP,EOC_MARK,0
MR_TX_CREDIT_SETUP,INCOMPLETE_EOC,0
MR_TX_CREDIT_SETUP,EOC_MARKTYPE_PROC,0
MR_TX_CREDIT_SETUP,EOC_ALT_MARK,0
MR_TX_CREDIT_SETUP,MIN_COHORT_YEAR,0
MR_TX_CREDIT_SETUP,CHANGE_DATE_TIME,0
MR_TX_CREDIT_SETUP,CHANGE_UID,0
MR_YEAREND_RUN,DISTRICT,1
MR_YEAREND_RUN,SCHOOL_YEAR,1
MR_YEAREND_RUN,SUMMER_SCHOOL,1
MR_YEAREND_RUN,RUN_KEY,1
MR_YEAREND_RUN,RUN_DATE,0
MR_YEAREND_RUN,RUN_STATUS,0
MR_YEAREND_RUN,CLEAN_MR_DATA,0
MR_YEAREND_RUN,BUILDING_LIST,0
MR_YEAREND_RUN,PURGE_BLD_YEAR,0
MR_YEAREND_RUN,PURGE_STU_YEAR,0
MR_YEAREND_RUN,PURGE_IPR_YEAR,0
MR_YEAREND_RUN,PURGE_GB_ASMT_YEAR,0
MR_YEAREND_RUN,PURGE_GB_SCORE_YEAR,0
MR_YEAREND_RUN,RESTORE_KEY,0
MR_YEAREND_RUN,CHANGE_DATE_TIME,0
MR_YEAREND_RUN,CHANGE_UID,0
MRTB_DISQUALIFY_REASON,DISTRICT,1
MRTB_DISQUALIFY_REASON,CODE,1
MRTB_DISQUALIFY_REASON,DESCRIPTION,0
MRTB_DISQUALIFY_REASON,CHANGE_DATE_TIME,0
MRTB_DISQUALIFY_REASON,CHANGE_UID,0
MRTB_GB_CATEGORY,DISTRICT,1
MRTB_GB_CATEGORY,CODE,1
MRTB_GB_CATEGORY,DESCRIPTION,0
MRTB_GB_CATEGORY,CATEGORY_ID,0
MRTB_GB_CATEGORY,CHANGE_DATE_TIME,0
MRTB_GB_CATEGORY,CHANGE_UID,0
MRTB_GB_EXCEPTION,DISTRICT,1
MRTB_GB_EXCEPTION,CODE,1
MRTB_GB_EXCEPTION,DESCRIPTION,0
MRTB_GB_EXCEPTION,EXCLUDE_AVERAGE,0
MRTB_GB_EXCEPTION,CHANGE_DATE_TIME,0
MRTB_GB_EXCEPTION,CHANGE_UID,0
MRTB_LEVEL_HDR_PESC_CODE,DISTRICT,1
MRTB_LEVEL_HDR_PESC_CODE,CODE,1
MRTB_LEVEL_HDR_PESC_CODE,DESCRIPTION,0
MRTB_LEVEL_HDR_PESC_CODE,CHANGE_DATE_TIME,0
MRTB_LEVEL_HDR_PESC_CODE,CHANGE_UID,0
MRTB_MARKOVR_REASON,DISTRICT,1
MRTB_MARKOVR_REASON,CODE,1
MRTB_MARKOVR_REASON,DESCRIPTION,0
MRTB_MARKOVR_REASON,CHANGE_DATE_TIME,0
MRTB_MARKOVR_REASON,CHANGE_UID,0
MRTB_ST_CRS_FLAGS,DISTRICT,1
MRTB_ST_CRS_FLAGS,FLAG,1
MRTB_ST_CRS_FLAGS,LABEL,0
MRTB_ST_CRS_FLAGS,CHANGE_DATE_TIME,0
MRTB_ST_CRS_FLAGS,CHANGE_UID,0
MRTB_SUBJ_AREA_SUB,DISTRICT,1
MRTB_SUBJ_AREA_SUB,CODE,1
MRTB_SUBJ_AREA_SUB,DESCRIPTION,0
MRTB_SUBJ_AREA_SUB,CHANGE_DATE_TIME,0
MRTB_SUBJ_AREA_SUB,CHANGE_UID,0
MSG_BUILDING_SETUP,DISTRICT,1
MSG_BUILDING_SETUP,BUILDING,1
MSG_BUILDING_SETUP,EVENT_CODE,1
MSG_BUILDING_SETUP,EVENT_AVAILABILITY,0
MSG_BUILDING_SETUP,ALLOW_ESP,0
MSG_BUILDING_SETUP,ALLOW_TAC,0
MSG_BUILDING_SETUP,ALLOW_HAC,0
MSG_BUILDING_SETUP,CHANGE_DATE_TIME,0
MSG_BUILDING_SETUP,CHANGE_UID,0
MSG_BUILDING_SETUP_ENABLE,DISTRICT,1
MSG_BUILDING_SETUP_ENABLE,BUILDING,1
MSG_BUILDING_SETUP_ENABLE,EVENT_PACKAGE,1
MSG_BUILDING_SETUP_ENABLE,IS_ENABLED,0
MSG_BUILDING_SETUP_ENABLE,CHANGE_DATE_TIME,0
MSG_BUILDING_SETUP_ENABLE,CHANGE_UID,0
MSG_BUILDING_SETUP_VALUES,DISTRICT,1
MSG_BUILDING_SETUP_VALUES,BUILDING,1
MSG_BUILDING_SETUP_VALUES,EVENT_CODE,1
MSG_BUILDING_SETUP_VALUES,WORKFLOW_VALUE,1
MSG_BUILDING_SETUP_VALUES,CHANGE_DATE_TIME,0
MSG_BUILDING_SETUP_VALUES,CHANGE_UID,0
MSG_DISTRICT_SETUP,DISTRICT,1
MSG_DISTRICT_SETUP,EVENT_CODE,1
MSG_DISTRICT_SETUP,EVENT_AVAILABILITY,0
MSG_DISTRICT_SETUP,ALLOW_ESP,0
MSG_DISTRICT_SETUP,ALLOW_TAC,0
MSG_DISTRICT_SETUP,ALLOW_HAC,0
MSG_DISTRICT_SETUP,CHANGE_DATE_TIME,0
MSG_DISTRICT_SETUP,CHANGE_UID,0
MSG_DISTRICT_SETUP_ENABLE,DISTRICT,1
MSG_DISTRICT_SETUP_ENABLE,EVENT_PACKAGE,1
MSG_DISTRICT_SETUP_ENABLE,IS_ENABLED,0
MSG_DISTRICT_SETUP_ENABLE,CHANGE_DATE_TIME,0
MSG_DISTRICT_SETUP_ENABLE,CHANGE_UID,0
MSG_DISTRICT_SETUP_VALUES,DISTRICT,1
MSG_DISTRICT_SETUP_VALUES,EVENT_CODE,1
MSG_DISTRICT_SETUP_VALUES,WORKFLOW_VALUE,1
MSG_DISTRICT_SETUP_VALUES,CHANGE_DATE_TIME,0
MSG_DISTRICT_SETUP_VALUES,CHANGE_UID,0
MSG_EVENT,DISTRICT,1
MSG_EVENT,EVENT_CODE,1
MSG_EVENT,EVENT_DESCRIPTION,0
MSG_EVENT,EVENT_PACKAGE,0
MSG_EVENT,EVENT_ORDER,0
MSG_EVENT,ESP_SEC_PACKAGE,0
MSG_EVENT,ESP_SEC_SUBPACKAGE,0
MSG_EVENT,ESP_SEC_FEATURE,0
MSG_EVENT,USE_ESP,0
MSG_EVENT,USE_TAC,0
MSG_EVENT,USE_HAC,0
MSG_EVENT,USE_WATCHLIST,0
MSG_EVENT,SCHEDULE_POPUP,0
MSG_EVENT,RESERVED,0
MSG_EVENT,CHANGE_DATE_TIME,0
MSG_EVENT,CHANGE_UID,0
MSG_IEP_AUDIENCE,DISTRICT,1
MSG_IEP_AUDIENCE,EVENT_CODE,1
MSG_IEP_AUDIENCE,AUDIENCE,1
MSG_IEP_AUDIENCE,CHANGE_DATE_TIME,0
MSG_IEP_AUDIENCE,CHANGE_UID,0
MSG_SCHEDULE,DISTRICT,1
MSG_SCHEDULE,BUILDING,1
MSG_SCHEDULE,EVENT_CODE,1
MSG_SCHEDULE,TASK_OWNER,0
MSG_SCHEDULE,SCHEDULE_TYPE,0
MSG_SCHEDULE,SCHD_TIME,0
MSG_SCHEDULE,SCHD_DATE,0
MSG_SCHEDULE,SCHD_INTERVAL,0
MSG_SCHEDULE,SCHD_DOW,0
MSG_SCHEDULE,PARAM_KEY,0
MSG_SCHEDULE,LAST_RUN_DATE,0
MSG_SCHEDULE,CHANGE_DATE_TIME,0
MSG_SCHEDULE,CHANGE_UID,0
MSG_SUB_EVENT,DISTRICT,1
MSG_SUB_EVENT,EVENT_CODE,1
MSG_SUB_EVENT,EVENT_SUB_CODE,1
MSG_SUB_EVENT,PNRS_SHORTMESSAGE,0
MSG_SUB_EVENT,PNRS_LONGMESSAGE,0
MSG_SUB_EVENT,PNRS_LONGMESSAGEREMOTE,0
MSG_SUB_EVENT,RESERVED,0
MSG_SUB_EVENT,CHANGE_DATE_TIME,0
MSG_SUB_EVENT,CHANGE_UID,0
MSG_USER_PREFERENCE_DET,DISTRICT,1
MSG_USER_PREFERENCE_DET,APPLICATION_TYPE,1
MSG_USER_PREFERENCE_DET,LOGIN_ID,1
MSG_USER_PREFERENCE_DET,EVENT_CODE,1
MSG_USER_PREFERENCE_DET,SEND_EMAIL,0
MSG_USER_PREFERENCE_DET,WATCH_NAME,0
MSG_USER_PREFERENCE_DET,HOME_BUILDING_ONLY,0
MSG_USER_PREFERENCE_DET,SEND_HIGH_PRIORITY,0
MSG_USER_PREFERENCE_DET,CHANGE_DATE_TIME,0
MSG_USER_PREFERENCE_DET,CHANGE_UID,0
MSG_USER_PREFERENCE_HDR,DISTRICT,1
MSG_USER_PREFERENCE_HDR,APPLICATION_TYPE,1
MSG_USER_PREFERENCE_HDR,LOGIN_ID,1
MSG_USER_PREFERENCE_HDR,DAILY_DIGEST,0
MSG_USER_PREFERENCE_HDR,NO_IEP_LOGIN,0
MSG_USER_PREFERENCE_HDR,CHANGE_DATE_TIME,0
MSG_USER_PREFERENCE_HDR,CHANGE_UID,0
MSG_VALUE_SPECIFICATION,DISTRICT,1
MSG_VALUE_SPECIFICATION,EVENT_CODE,1
MSG_VALUE_SPECIFICATION,VALUE_LABEL,0
MSG_VALUE_SPECIFICATION,DATA_TYPE,0
MSG_VALUE_SPECIFICATION,VALIDATION_TABLE,0
MSG_VALUE_SPECIFICATION,VALIDATION_CODE_COLUMN,0
MSG_VALUE_SPECIFICATION,VALIDATION_DESCRIPTION_COLUMN,0
MSG_VALUE_SPECIFICATION,USE_SUBSCRIPTION,0
MSG_VALUE_SPECIFICATION,CHANGE_DATE_TIME,0
MSG_VALUE_SPECIFICATION,CHANGE_UID,0
NSE_ADDRESS,ADDRESS_ID,1
NSE_ADDRESS,NSE_ID,0
NSE_ADDRESS,APARTMENT,0
NSE_ADDRESS,COMPLEX,0
NSE_ADDRESS,HOUSE_NUMBER,0
NSE_ADDRESS,STREET_NAME,0
NSE_ADDRESS,STREET_TYPE,0
NSE_ADDRESS,DEVELOPMENT,0
NSE_ADDRESS,CITY,0
NSE_ADDRESS,ADDR_STATE,0
NSE_ADDRESS,ZIP,0
NSE_ADDRESS,ISMAILING,0
NSE_ADDRESS,ISSTUDENT,0
NSE_ADDRESS,CONTACT_TYPE,0
NSE_ADDRESS,HOUSENO,0
NSE_ADDRESS,LASTMODIFIEDBY,0
NSE_ADDRESS,LASTMODIFIEDDATE,0
NSE_ADDRESS,STREET_PREFIX,0
NSE_ADDRESS,STREET_SUFFIX,0
NSE_ADDRESS,EFFECTIVEDATE,0
NSE_ADDRESS,VERIFY_DATE,0
NSE_ADMIN_DOCUMENTS,ADMIN_DOCUMENT_ID,1
NSE_ADMIN_DOCUMENTS,FILE_NAME,0
NSE_ADMIN_DOCUMENTS,TITLE,0
NSE_ADMIN_DOCUMENTS,APPLICATIONID,0
NSE_ADMIN_DOCUMENTS,FILEID,0
NSE_ADMIN_DOCUMENTS,CHANGE_DATE_TIME,0
NSE_ADMIN_DOCUMENTS,CHANGE_UID,0
NSE_ADMIN_DOCUMENTS_FOR_GRADE,ADMIN_DOCUMENT_ID,1
NSE_ADMIN_DOCUMENTS_FOR_GRADE,GRADE,1
NSE_ADMIN_DOCUMENTS_FOR_GRADE,CHANGE_DATE_TIME,0
NSE_ADMIN_DOCUMENTS_FOR_GRADE,CHANGE_UID,0
NSE_ADMIN_SETTINGS,SETTING_ID,1
NSE_ADMIN_SETTINGS,THEME_ID,0
NSE_ADMIN_SETTINGS,FILEID,0
NSE_ADMIN_SETTINGS,FILE_NAME,0
NSE_ADMIN_SETTINGS,HELP_URL,0
NSE_ADMIN_SETTINGS,ALLOW_ALERT,0
NSE_ADMIN_SETTINGS,ALERT_TYPE,0
NSE_ADMIN_SETTINGS,ALERT_TIME,0
NSE_ADMIN_SETTINGS,ALERT_DAY,0
NSE_ADMIN_SETTINGS,TIMEINTERVAL,0
NSE_ADMIN_SETTINGS,PARENT_FROMEMAIL,0
NSE_ADMIN_SETTINGS,PARENT_DISPLAYNAME,0
NSE_ADMIN_SETTINGS,PARENT_CCEMAIL,0
NSE_ADMIN_SETTINGS,PARENT_SMTPSERVERNAME,0
NSE_ADMIN_SETTINGS,REG_FROMEMAIL,0
NSE_ADMIN_SETTINGS,REG_DISPLAYNAME,0
NSE_ADMIN_SETTINGS,REG_CCEMAIL,0
NSE_ADMIN_SETTINGS,REG_SMTPSERVERNAME,0
NSE_ADMIN_SETTINGS,LASTMODIFIEDBY,0
NSE_ADMIN_SETTINGS,LASTMODIFIEDDATE,0
NSE_ADMIN_SETTINGS,DEBUG_EMAIL,0
NSE_ADMIN_SETTINGS,PRE_REG_BUILDING,0
NSE_ADMIN_SETTINGS,ENGLISH_LANGUAGE_CODE,0
NSE_ADMIN_SETTINGS,HELP_URL_UPDATE_FORM,0
NSE_ADMIN_SETTINGS,REG_UPDATE_MAX_ENTRIES,0
NSE_ADMIN_SETTINGS,REG_NEW_MAX_ENTRIES,0
NSE_ADMIN_SETTINGS,WARN_BLANK_UPDT,0
NSE_ADMIN_SETTINGS,ALERT_STU_MATCH,0
NSE_ADMIN_SETTINGS,DISPLAY_MATCH_CONTACT,0
NSE_APPLICATION,APPLICATION_ID,1
NSE_APPLICATION,APPLICATION_NAME,0
NSE_APPLICATION,SHOW_MEDICAL,0
NSE_APPLICATION,SHOW_HISPANIC_UNANSWERED,0
NSE_APPLICATION,PREFERRED_BUILDING_COUNT,0
NSE_APPLICATION,ALLOW_MULTIPLE_RACE,0
NSE_APPLICATION,APPLICATION_STATUS,0
NSE_APPLICATION,LASTMODIFIEDBY,0
NSE_APPLICATION,LASTMODIFIEDDATE,0
NSE_APPLICATION,DESCRIPTION,0
NSE_APPLICATION,IS_DEFAULT,0
NSE_APPLICATION,SHOW_EXISTING_DATA_VACCINATION,0
NSE_APPLICATION,AUTO_ACCEPT,0
NSE_APPLICATION,SHOW_STUDENT,0
NSE_APPLICATION,SHOW_ADDRESS,0
NSE_APPLICATION,SHOW_CONTACT,0
NSE_APPLICATION,SHOW_BUILDING,0
NSE_APPLICATION,SHOW_UPLOAD,0
NSE_APPLICATION,FORMTYPE,0
NSE_APPLICATION,BUILDING_TO_BE_EXCLUDED,0
NSE_APPLICATION,LIMIT_CONTACT_TYPES,0
NSE_APPLICATION,CONTACT_TYPES_ALLOWED,0
NSE_APPLICATION,DEFAULT_SCHOOL_YEAR,0
NSE_APPLICATION,DEFAULT_ENTRY_DATE,0
NSE_APPLICATION,USE_NEXT_PREV,0
NSE_APPLICATION,USE_SECT_COMPL,0
NSE_APPLICATION,HIGHLIGHT_FAILD_VALID,0
NSE_APPLICATION,DISPLAY_TOOL_ICON,0
NSE_APPLICATION_DETAILS,APPLICATION_ID,0
NSE_APPLICATION_DETAILS,FIELD_ID,0
NSE_APPLICATION_DETAILS,IS_VISIBLE,0
NSE_APPLICATION_DETAILS,IS_REQUIRED,0
NSE_APPLICATION_DETAILS,LASTMODIFIEDBY,0
NSE_APPLICATION_DETAILS,LASTMODIFIEDDATE,0
NSE_APPLICATION_DETAILS,SHOWEXISTINGDATA,0
NSE_APPLICATION_DETAILS,CONFIGFIELD,0
NSE_APPLICATION_DETAILS,DONOTALLOWCHANGE,0
NSE_APPLICATION_DETAILS,IS_CAPITALIZE,0
NSE_APPLICATION_RELATIONSHIP,APPLICATION_ID,1
NSE_APPLICATION_RELATIONSHIP,SIGNATURE_ID,0
NSE_APPLICATION_RELATIONSHIP,DISCLAIMER_ID,0
NSE_APPLICATION_RELATIONSHIP,LASTMODIFIEDBY,0
NSE_APPLICATION_RELATIONSHIP,LASTMODIFIEDDATE,0
NSE_APPLICATION_STUDENT,APPLICATION_ID,1
NSE_APPLICATION_STUDENT,NSE_ID,1
NSE_APPLICATION_STUDENT,CHANGE_DATE_TIME,0
NSE_APPLICATION_STUDENT,CHANGE_UID,0
NSE_APPLICATION_TRANSLATION,RECID,0
NSE_APPLICATION_TRANSLATION,APPLICATION_ID,1
NSE_APPLICATION_TRANSLATION,NAMETRANSLATION,0
NSE_APPLICATION_TRANSLATION,DESCRIPTIONTRANSLATION,0
NSE_APPLICATION_TRANSLATION,LANGCODE,1
NSE_APPLICATION_TRANSLATION,CHANGE_DATE_TIME,0
NSE_APPLICATION_TRANSLATION,CHANGE_UID,0
NSE_BUILDING,BUILDING_ID,1
NSE_BUILDING,NSE_ID,0
NSE_BUILDING,SUGGESTEDBUILDING,0
NSE_BUILDING,PREFERREDBUILDING1,0
NSE_BUILDING,PREFERREDBUILDING2,0
NSE_BUILDING,PREFERREDBUILDING3,0
NSE_BUILDING,PREFERREDBUILDING4,0
NSE_BUILDING,PREFERREDBUILDING5,0
NSE_BUILDING,SELECTEDBUILDING,0
NSE_BUILDING,OVERRIDE_BUILDING,0
NSE_BUILDING,OVERRIDE_REASON,0
NSE_BUILDING,TRACK,0
NSE_BUILDING,CALENDAR,0
NSE_BUILDING,ENTRYTYPE,0
NSE_BUILDING,ENTRYCODE,0
NSE_BUILDING,ENTRYDATE,0
NSE_BUILDING,PLANAREANUMBER,0
NSE_BUILDING,LASTMODIFIEDBY,0
NSE_BUILDING,LASTMODIFIEDDATE,0
NSE_BUILDING,NEXTYEARSUGGESTEDBUILDING,0
NSE_CONFIGURABLE_FIELDS,FIELD_ID,1
NSE_CONFIGURABLE_FIELDS,TAB_ID,0
NSE_CONFIGURABLE_FIELDS,CHANGE_DATE_TIME,0
NSE_CONFIGURABLE_FIELDS,CHANGE_UID,0
NSE_CONTACT,CONTACT_ID,1
NSE_CONTACT,NSE_ID,0
NSE_CONTACT,ADDRESS_ID,0
NSE_CONTACT,TITLE,0
NSE_CONTACT,FIRSTNAME,0
NSE_CONTACT,MIDDLENAME,0
NSE_CONTACT,LASTNAME,0
NSE_CONTACT,GENERATION,0
NSE_CONTACT,RELATIONSHIP,0
NSE_CONTACT,WORKPHONE,0
NSE_CONTACT,WORKPHONEEXT,0
NSE_CONTACT,HOME_LANGUAGE,0
NSE_CONTACT,LANGUAGE_OF_CORRESPONDENCE,0
NSE_CONTACT,USE_LANGUAGE_FOR_MAILING,0
NSE_CONTACT,EMAIL_ID,0
NSE_CONTACT,USE_EMAIL_FOR_MAILING,0
NSE_CONTACT,EDUCATION_LEVEL,0
NSE_CONTACT,COPYADDRESSFLAG,0
NSE_CONTACT,REGISTRATIONLABELSFLAG,0
NSE_CONTACT,ATTENDANCENOTIFICATIONSFLAG,0
NSE_CONTACT,DISCIPLINELETTERSFLAG,0
NSE_CONTACT,SCHEDULESFLAG,0
NSE_CONTACT,SUCCESSPLANFLAG,0
NSE_CONTACT,IPRLETTERSFLAG,0
NSE_CONTACT,REPORTCARDSFLAG,0
NSE_CONTACT,MEDICALLETTERSFLAG,0
NSE_CONTACT,STUDENTFEESFLAG,0
NSE_CONTACT,ESCHOOL_CONTACT_ID,0
NSE_CONTACT,ISEXISTING_ESCHOOL_CONTACT_ID,0
NSE_CONTACT,CONTACT_TYPE,0
NSE_CONTACT,LIVINGWITH,0
NSE_CONTACT,LASTMODIFIEDBY,0
NSE_CONTACT,LASTMODIFIEDDATE,0
NSE_CONTACT,IS_COPIED_FROM_NSE,0
NSE_CONTACT,COPIED_FROM_ID,0
NSE_CONTACT,CONTACT_STATUS,0
NSE_CONTACT_PHONE,NSE_ID,1
NSE_CONTACT_PHONE,DISTRICT,0
NSE_CONTACT_PHONE,CONTACT_ID,1
NSE_CONTACT_PHONE,PHONE_TYPE,1
NSE_CONTACT_PHONE,PHONE_LISTING,0
NSE_CONTACT_PHONE,PHONE,0
NSE_CONTACT_PHONE,PHONE_EXTENSION,0
NSE_CONTACT_PHONE,SIF_REFID,0
NSE_CONTACT_PHONE,CHANGE_DATE_TIME,0
NSE_CONTACT_PHONE,CHANGE_UID,0
NSE_CONTACT_VERIFY,NSE_ID,1
NSE_CONTACT_VERIFY,DISTRICT,0
NSE_CONTACT_VERIFY,CONTACT_ID,1
NSE_CONTACT_VERIFY,VERIFY_DATE,0
NSE_CONTACT_VERIFY,CHANGE_DATE_TIME,0
NSE_CONTACT_VERIFY,CHANGE_UID,0
NSE_CONTACTMATCH_LOG,CONTACT_ID,1
NSE_CONTACTMATCH_LOG,NSE_ID,0
NSE_CONTACTMATCH_LOG,ADDRESS_ID,0
NSE_CONTACTMATCH_LOG,TITLE,0
NSE_CONTACTMATCH_LOG,FIRSTNAME,0
NSE_CONTACTMATCH_LOG,MIDDLENAME,0
NSE_CONTACTMATCH_LOG,LASTNAME,0
NSE_CONTACTMATCH_LOG,GENERATION,0
NSE_CONTACTMATCH_LOG,RELATIONSHIP,0
NSE_CONTACTMATCH_LOG,WORKPHONE,0
NSE_CONTACTMATCH_LOG,WORKPHONEEXT,0
NSE_CONTACTMATCH_LOG,HOME_LANGUAGE,0
NSE_CONTACTMATCH_LOG,LANGUAGE_OF_CORRESPONDENCE,0
NSE_CONTACTMATCH_LOG,USE_LANGUAGE_FOR_MAILING,0
NSE_CONTACTMATCH_LOG,EMAIL_ID,0
NSE_CONTACTMATCH_LOG,USE_EMAIL_FOR_MAILING,0
NSE_CONTACTMATCH_LOG,EDUCATION_LEVEL,0
NSE_CONTACTMATCH_LOG,COPYADDRESSFLAG,0
NSE_CONTACTMATCH_LOG,REGISTRATIONLABELSFLAG,0
NSE_CONTACTMATCH_LOG,ATTENDANCENOTIFICATIONSFLAG,0
NSE_CONTACTMATCH_LOG,DISCIPLINELETTERSFLAG,0
NSE_CONTACTMATCH_LOG,SCHEDULESFLAG,0
NSE_CONTACTMATCH_LOG,SUCCESSPLANFLAG,0
NSE_CONTACTMATCH_LOG,IPRLETTERSFLAG,0
NSE_CONTACTMATCH_LOG,REPORTCARDSFLAG,0
NSE_CONTACTMATCH_LOG,MEDICALLETTERSFLAG,0
NSE_CONTACTMATCH_LOG,STUDENTFEESFLAG,0
NSE_CONTACTMATCH_LOG,ESCHOOL_CONTACT_ID,0
NSE_CONTACTMATCH_LOG,ISEXISTING_ESCHOOL_CONTACT_ID,0
NSE_CONTACTMATCH_LOG,CONTACT_TYPE,0
NSE_CONTACTMATCH_LOG,LIVINGWITH,0
NSE_CONTACTMATCH_LOG,LASTMODIFIEDBY,0
NSE_CONTACTMATCH_LOG,LASTMODIFIEDDATE,0
NSE_CONTROLSLIST,CONTROL_ID,1
NSE_CONTROLSLIST,CONTROL_TYPE,0
NSE_CONTROLSLIST,CONTROL_NAME,0
NSE_CONTROLSLIST,DEFAULT_TRANSLATION,0
NSE_CONTROLSLIST,CHANGE_DATE_TIME,0
NSE_CONTROLSLIST,CHANGE_UID,0
NSE_CONTROLTRANSLATION,TRANSLATION_ID,1
NSE_CONTROLTRANSLATION,CONTROL_ID,0
NSE_CONTROLTRANSLATION,LANGUAGE_ID,0
NSE_CONTROLTRANSLATION,TRANSLATION,0
NSE_CONTROLTRANSLATION,LASTMODIFIEDBY,0
NSE_CONTROLTRANSLATION,LASTMODIFIEDDATE,0
NSE_DISCLAIMER,DISCLAIMER_ID,1
NSE_DISCLAIMER,TITLE,0
NSE_DISCLAIMER,RESOURCE_ID,0
NSE_DISCLAIMER,LASTMODIFIEDBY,0
NSE_DISCLAIMER,LASTMODIFIEDDATE,0
NSE_DYNAMIC_FIELDS_APPLICATION,DYNAMIC_FIELD_ID,1
NSE_DYNAMIC_FIELDS_APPLICATION,RESOURCE_ID,0
NSE_DYNAMIC_FIELDS_APPLICATION,TAB_ID,0
NSE_DYNAMIC_FIELDS_APPLICATION,APPLICATION_ID,0
NSE_DYNAMIC_FIELDS_APPLICATION,FIELD_ORDER,0
NSE_DYNAMIC_FIELDS_APPLICATION,FIELD_REQUIRED,0
NSE_DYNAMIC_FIELDS_APPLICATION,FIELD_REQUIRED_REGISTRAR,0
NSE_DYNAMIC_FIELDS_APPLICATION,DEFAULT_VALUE,0
NSE_DYNAMIC_FIELDS_APPLICATION,FIELD_TYPE,0
NSE_DYNAMIC_FIELDS_APPLICATION,FIELD_TABLE,0
NSE_DYNAMIC_FIELDS_APPLICATION,FIELD_COLUMN,0
NSE_DYNAMIC_FIELDS_APPLICATION,FIELD_SHOW_ON_APPLICATION,0
NSE_DYNAMIC_FIELDS_APPLICATION,CONTROL_TYPE,0
NSE_DYNAMIC_FIELDS_APPLICATION,DATA_TYPE,0
NSE_DYNAMIC_FIELDS_APPLICATION,FIELD_LENGTH,0
NSE_DYNAMIC_FIELDS_APPLICATION,LASTMODIFIEDBY,0
NSE_DYNAMIC_FIELDS_APPLICATION,LASTMODIFIEDDATE,0
NSE_DYNAMIC_FIELDS_GRADE,DYNAMIC_FIELD_ID,1
NSE_DYNAMIC_FIELDS_GRADE,GRADE,1
NSE_DYNAMIC_FIELDS_GRADE,LASTMODIFIEDBY,0
NSE_DYNAMIC_FIELDS_GRADE,LASTMODIFIEDDATE,0
NSE_DYNAMIC_FIELDS_GROUP,APPLICATION_ID,1
NSE_DYNAMIC_FIELDS_GROUP,TAB_ID,1
NSE_DYNAMIC_FIELDS_GROUP,DYNAMIC_FIELD_ID,1
NSE_DYNAMIC_FIELDS_GROUP,GROUP_TITLE,0
NSE_DYNAMIC_FIELDS_GROUP,GROUP_HEADER_TEXT,0
NSE_DYNAMIC_FIELDS_GROUP,LASTMODIFIEDBY,0
NSE_DYNAMIC_FIELDS_GROUP,LASTMODIFIEDDATE,0
NSE_DYNAMIC_FIELDS_TOOLTIP,TOOLTIP_ID,1
NSE_DYNAMIC_FIELDS_TOOLTIP,RESOURCE_ID,0
NSE_DYNAMIC_FIELDS_TOOLTIP,DYNAMIC_FIELD_ID,0
NSE_DYNAMIC_FIELDS_TOOLTIP,CHANGE_DATE_TIME,0
NSE_DYNAMIC_FIELDS_TOOLTIP,CHANGE_UID,0
NSE_EOCONTACT,NSE_ID,1
NSE_EOCONTACT,ESP_CONTACT_ID,0
NSE_EOCONTACT,CONTACT_STATUS,0
NSE_EOCONTACT,DISTRICT,0
NSE_EOCONTACT,CONTACT_ID,1
NSE_EOCONTACT,TITLE,0
NSE_EOCONTACT,SALUTATION,0
NSE_EOCONTACT,FIRST_NAME,0
NSE_EOCONTACT,MIDDLE_NAME,0
NSE_EOCONTACT,LAST_NAME,0
NSE_EOCONTACT,GENERATION,0
NSE_EOCONTACT,LANGUAGE,0
NSE_EOCONTACT,HOME_LANGUAGE,0
NSE_EOCONTACT,USE_FOR_MAILING,0
NSE_EOCONTACT,EMPLOYER,0
NSE_EOCONTACT,DEVELOPMENT,0
NSE_EOCONTACT,APARTMENT,0
NSE_EOCONTACT,COMPLEX,0
NSE_EOCONTACT,STREET_NUMBER,0
NSE_EOCONTACT,STREET_PREFIX,0
NSE_EOCONTACT,STREET_NAME,0
NSE_EOCONTACT,STREET_SUFFIX,0
NSE_EOCONTACT,STREET_TYPE,0
NSE_EOCONTACT,CITY,0
NSE_EOCONTACT,STATE,0
NSE_EOCONTACT,ZIP,0
NSE_EOCONTACT,PLAN_AREA_NUMBER,0
NSE_EOCONTACT,HOME_BUILDING_TYPE,0
NSE_EOCONTACT,EMAIL,0
NSE_EOCONTACT,EMAIL_PREFERENCE,0
NSE_EOCONTACT,DELIVERY_POINT,0
NSE_EOCONTACT,LOGIN_ID,0
NSE_EOCONTACT,WEB_PASSWORD,0
NSE_EOCONTACT,PWD_CHG_DATE_TIME,0
NSE_EOCONTACT,LAST_LOGIN_DATE,0
NSE_EOCONTACT,EDUCATION_LEVEL,0
NSE_EOCONTACT,SIF_REFID,0
NSE_EOCONTACT,CHANGE_DATE_TIME,0
NSE_EOCONTACT,CHANGE_UID,0
NSE_EOCONTACT,HAC_LDAP_FLAG,0
NSE_EOCONTACT,MATCHED_CONTACT,0
NSE_FIELDS,FIELD_ID,1
NSE_FIELDS,RESOURCE_ID,0
NSE_FIELDS,FIELD_TYPE,0
NSE_FIELDS,DB_FIELD_NAME,0
NSE_FIELDS,TAB_ID,0
NSE_FIELDS,LASTMODIFIEDBY,0
NSE_FIELDS,LASTMODIFIEDDATE,0
NSE_HAC_ACCESS,NSE_GUID,1
NSE_HAC_ACCESS,LOGIN_ID,1
NSE_HAC_ACCESS,WEB_PASSWORD,0
NSE_HAC_ACCESS,STUDENT_ID,0
NSE_HAC_ACCESS,PREFERRED_LANG,0
NSE_HAC_ACCESS,ACCESSED_TIME,0
NSE_HAC_ACCESS,NSE_ID,0
NSE_LANGUAGE,LANGUAGEID,1
NSE_LANGUAGE,LANGUAGENAME,0
NSE_LANGUAGE,ISSUPPORTED,0
NSE_LANGUAGE,LASTMODIFIEDBY,0
NSE_LANGUAGE,LASTMODIFIEDDATE,0
NSE_LANGUAGE,LANGUAGECODE,0
NSE_MEDICAL,MEDICAL_ID,1
NSE_MEDICAL,NSE_ID,0
NSE_MEDICAL,VACCINATION,0
NSE_MEDICAL,EXEMPTION,0
NSE_MEDICAL,DATE1,0
NSE_MEDICAL,DATE2,0
NSE_MEDICAL,DATE3,0
NSE_MEDICAL,DATE4,0
NSE_MEDICAL,DATE5,0
NSE_MEDICAL,DATE6,0
NSE_MEDICAL,LASTMODIFIEDBY,0
NSE_MEDICAL,LASTMODIFIEDDATE,0
NSE_PHONENUMBERS,ID,1
NSE_PHONENUMBERS,NSE_ID,0
NSE_PHONENUMBERS,CONTACT_ID,0
NSE_PHONENUMBERS,PHONE_TYPE,0
NSE_PHONENUMBERS,PHONE_NUMBER,0
NSE_PHONENUMBERS,EXT,0
NSE_PHONENUMBERS,LISTING_STATUS,0
NSE_PHONENUMBERS,LASTMODIFIEDBY,0
NSE_PHONENUMBERS,LASTMODIFIEDDATE,0
NSE_REG_USER,NSE_ID,1
NSE_REG_USER,DYNAMIC_FIELD_ID,1
NSE_REG_USER,FIELD_VALUE,0
NSE_REG_USER,LASTMODIFIEDBY,0
NSE_REG_USER,LASTMODIFIEDDATE,0
NSE_RESOURCE,RESOURCE_ID,1
NSE_RESOURCE,RESOURCE_VALUE,0
NSE_RESOURCE,RESOURCE_TYPE_ID,0
NSE_RESOURCE,CHANGE_DATE_TIME,0
NSE_RESOURCE,CHANGE_UID,0
NSE_RESOURCE_TYPE,RESOURCE_TYPE_ID,1
NSE_RESOURCE_TYPE,RESOURCE_TYPE,0
NSE_RESOURCE_TYPE,CHANGE_DATE_TIME,0
NSE_RESOURCE_TYPE,CHANGE_UID,0
NSE_SECTION_COMPLETE,NSE_ID,1
NSE_SECTION_COMPLETE,TAB_ID,1
NSE_SECTION_COMPLETE,SECTION_COMPLETE,0
NSE_SECTION_COMPLETE,LASTMODIFIEDBY,0
NSE_SECTION_COMPLETE,LASTMODIFIEDDATE,0
NSE_SIGNATURE,SIGNATURE_ID,1
NSE_SIGNATURE,TITLE,0
NSE_SIGNATURE,RESOURCE_ID,0
NSE_SIGNATURE,LASTMODIFIEDBY,0
NSE_SIGNATURE,LASTMODIFIEDDATE,0
NSE_STU_CONTACT,NSE_ID,1
NSE_STU_CONTACT,DISTRICT,0
NSE_STU_CONTACT,CONTACT_ID,1
NSE_STU_CONTACT,ESP_CONTACT_TYPE,0
NSE_STU_CONTACT,CONTACT_TYPE,1
NSE_STU_CONTACT,CONTACT_PRIORITY,0
NSE_STU_CONTACT,RELATION_CODE,0
NSE_STU_CONTACT,LIVING_WITH,0
NSE_STU_CONTACT,WEB_ACCESS,0
NSE_STU_CONTACT,COMMENTS,0
NSE_STU_CONTACT,TRANSPORT_TO,0
NSE_STU_CONTACT,TRANSPORT_FROM,0
NSE_STU_CONTACT,MAIL_ATT,0
NSE_STU_CONTACT,MAIL_DISC,0
NSE_STU_CONTACT,MAIL_FEES,0
NSE_STU_CONTACT,MAIL_IPR,0
NSE_STU_CONTACT,MAIL_MED,0
NSE_STU_CONTACT,MAIL_RC,0
NSE_STU_CONTACT,MAIL_REG,0
NSE_STU_CONTACT,MAIL_SCHD,0
NSE_STU_CONTACT,MAIL_SSP,0
NSE_STU_CONTACT,CHANGE_DATE_TIME,0
NSE_STU_CONTACT,CHANGE_UID,0
NSE_STUDENT,NSE_ID,1
NSE_STUDENT,STUDENT_ID,0
NSE_STUDENT,ADDRESS_ID,0
NSE_STUDENT,GRADE,0
NSE_STUDENT,FIRSTNAME,0
NSE_STUDENT,MIDDLENAME,0
NSE_STUDENT,LASTNAME,0
NSE_STUDENT,GENERATION,0
NSE_STUDENT,NICKNAME,0
NSE_STUDENT,GENDER,0
NSE_STUDENT,BIRTHDATE,0
NSE_STUDENT,SSN,0
NSE_STUDENT,HISPANIC_LATINO_ETHNICITY,0
NSE_STUDENT,RACE,0
NSE_STUDENT,NATIVE_LANGUAGE,0
NSE_STUDENT,HOME_LANGUAGE,0
NSE_STUDENT,LANGUAGE_OF_CORRESPONDENCE,0
NSE_STUDENT,USE_LANGUAGE_FOR_MAILING,0
NSE_STUDENT,EMAIL_ID,0
NSE_STUDENT,USE_EMAIL_FOR_MAILING,0
NSE_STUDENT,WEB_ACCESS,0
NSE_STUDENT,LOGIN_ID,0
NSE_STUDENT,STUDENT_PASSWORD,0
NSE_STUDENT,PARENT_ID,0
NSE_STUDENT,STUDENT_STATUS,0
NSE_STUDENT,LASTMODIFIEDBY,0
NSE_STUDENT,LASTMODIFIEDDATE,0
NSE_STUDENT,ENTRYTYPE,0
NSE_STUDENT,ENTRYDATE,0
NSE_STUDENT,FEDERALCODE,0
NSE_STUDENT,FAMILYCENSUSNUMBER,0
NSE_STUDENT,NOTES,0
NSE_STUDENT,ISEXISTING_ESCHOOL_ID,0
NSE_STUDENT,REASON,0
NSE_STUDENT,COPIEDFROM,0
NSE_STUDENT,BIRTH_VERIFY,0
NSE_STUDENT,HISPANIC_CODE,0
NSE_STUDENT,BIRTHCOUNTRY,0
NSE_STUDENT,ENTRYYEAR,0
NSE_STUDENT,USER_KEY,0
NSE_STUDENT_RACE,NSE_ID,1
NSE_STUDENT_RACE,RACE,1
NSE_STUDENT_RACE,RACE_ORDER,0
NSE_STUDENT_RACE,CHANGE_DATE_TIME,0
NSE_STUDENT_RACE,CHANGE_UID,0
NSE_TABS,TAB_ID,1
NSE_TABS,RESOURCE_ID,0
NSE_TABS,TAB_ORDER,0
NSE_TABS,APPLICATION_ID,0
NSE_TABS,CHANGE_DATE_TIME,0
NSE_TABS,CHANGE_UID,0
NSE_TOOLTIP,TOOLTIP_ID,1
NSE_TOOLTIP,RESOURCE_ID,0
NSE_TOOLTIP,FIELD_ID,0
NSE_TOOLTIP,CHANGE_DATE_TIME,0
NSE_TOOLTIP,CHANGE_UID,0
NSE_TRANSLATION,TRANS_ID,1
NSE_TRANSLATION,LANGUAGE_ID,1
NSE_TRANSLATION,RESOURCE_ID,1
NSE_TRANSLATION,TRANSLATION,0
NSE_TRANSLATION,CHANGE_DATE_TIME,0
NSE_TRANSLATION,CHANGE_UID,0
NSE_UPLOAD_DOCUMENTS,UPLOAD_DOCUMENT_ID,1
NSE_UPLOAD_DOCUMENTS,NSE_ID,0
NSE_UPLOAD_DOCUMENTS,FILE_NAME,0
NSE_UPLOAD_DOCUMENTS,FILEID,0
NSE_UPLOAD_DOCUMENTS,CHANGE_DATE_TIME,0
NSE_UPLOAD_DOCUMENTS,CHANGE_UID,0
NSE_UPLOADFILES,FILE_ID,1
NSE_UPLOADFILES,FILE_CONTENT,0
NSE_UPLOADFILES,LASTMODIFIEDBY,0
NSE_UPLOADFILES,LASTMODIFIEDDATE,0
NSE_USER,USERID,1
NSE_USER,LOGINID,0
NSE_USER,USER_PASSWORD,0
NSE_USER,ROLEID,0
NSE_USER,LASTMODIFIEDDATE,0
NSE_USER,CHANGE_UID,0
NSE_USER,USER_KEY,0
NSE_USERDETAIL,USERID,1
NSE_USERDETAIL,FIRSTNAME,0
NSE_USERDETAIL,LASTNAME,0
NSE_USERDETAIL,PHONE,0
NSE_USERDETAIL,STREET,0
NSE_USERDETAIL,CITY,0
NSE_USERDETAIL,USER_STATE,0
NSE_USERDETAIL,STREET_TYPE,0
NSE_USERDETAIL,ZIPCODE,0
NSE_USERDETAIL,PREFERREDLANGUAGE,0
NSE_USERDETAIL,LASTMODIFIEDBY,0
NSE_USERDETAIL,LASTMODIFIEDDATE,0
NSE_USERDETAIL,EMAIL,0
NSE_USERDETAIL,APARTMENT,0
NSE_USERDETAIL,HOUSE_NUMBER,0
NSE_USERDETAIL,STREET_PREFIX,0
NSE_USERDETAIL,STREET_SUFFIX,0
NSE_VACCINATION_CONFIGURATION,APPLICATION_ID,1
NSE_VACCINATION_CONFIGURATION,VACCINATION_CODE,1
NSE_VACCINATION_CONFIGURATION,LASTMODIFIEDBY,0
NSE_VACCINATION_CONFIGURATION,LASTMODIFIEDDATE,0
Outdated_statistics,Table name,0
Outdated_statistics,Index name,0
Outdated_statistics,Last updated,0
Outdated_statistics,Rows modified,0
P360_NotificationLink,PNL_ID,1
P360_NotificationLink,PNL_TStamp,0
P360_NotificationLink,PNL_LastUser,0
P360_NotificationLink,PNL_District,0
P360_NotificationLink,PNL_PNR_ID,0
P360_NotificationLink,PNL_SessionVariableNumber,0
P360_NotificationLink,PNL_SessionVariableName,0
P360_NotificationResultSet,PNRS_ID,1
P360_NotificationResultSet,PNRS_TStamp,0
P360_NotificationResultSet,PNRS_LastUser,0
P360_NotificationResultSet,PNRS_District,0
P360_NotificationResultSet,PNRS_PNR_ID,0
P360_NotificationResultSet,PNRS_PNRU_ID,0
P360_NotificationResultSet,PNRS_PNR_Subquery_ID,0
P360_NotificationResultSet,PNRS_SentToPOD,0
P360_NotificationResultSet,PNRS_Category,0
P360_NotificationResultSet,PNRS_ShortMessage,0
P360_NotificationResultSet,PNRS_LongMessage,0
P360_NotificationResultSet,PNRS_LongMessageRemote,0
P360_NotificationResultSet,PNRS_Value01,0
P360_NotificationResultSet,PNRS_Value02,0
P360_NotificationResultSet,PNRS_Value03,0
P360_NotificationResultSet,PNRS_Value04,0
P360_NotificationResultSet,PNRS_Value05,0
P360_NotificationResultSet,PNRS_Value06,0
P360_NotificationResultSet,PNRS_Value07,0
P360_NotificationResultSet,PNRS_Value08,0
P360_NotificationResultSet,PNRS_Value09,0
P360_NotificationResultSet,PNRS_Value10,0
P360_NotificationResultSet,PNRS_Value11,0
P360_NotificationResultSet,PNRS_Value12,0
P360_NotificationResultSet,PNRS_Value13,0
P360_NotificationResultSet,PNRS_Value14,0
P360_NotificationResultSet,PNRS_Value15,0
P360_NotificationResultSet,PNRS_Value16,0
P360_NotificationResultSetUser,PNRSU_ID,1
P360_NotificationResultSetUser,PNRSU_TStamp,0
P360_NotificationResultSetUser,PNRSU_LastUser,0
P360_NotificationResultSetUser,PNRSU_District,0
P360_NotificationResultSetUser,PNRSU_PNRS_ID,0
P360_NotificationResultSetUser,PNRSU_UserId,0
P360_NotificationResultSetUser,PNRSU_UserApplication,0
P360_NotificationResultSetUser,PNRSU_EmailAddress,0
P360_NotificationResultSetUser,PNRSU_DeliveryMethod,0
P360_NotificationResultSetUser,PNRSU_InstantAlert,0
P360_NotificationRule,PNR_ID,1
P360_NotificationRule,PNR_TStamp,0
P360_NotificationRule,PNR_LastUser,0
P360_NotificationRule,PNR_District,0
P360_NotificationRule,PNR_Name,0
P360_NotificationRule,PNR_Description,0
P360_NotificationRule,PNR_SourceApplication,0
P360_NotificationRule,PNR_RemoteSecurityApplication,0
P360_NotificationRule,PNR_RemoteSecurityType,0
P360_NotificationRule,PNR_RequiredSecurity,0
P360_NotificationRule,PNR_RuleType,0
P360_NotificationRule,PNR_Rule,0
P360_NotificationRule,PNR_Category,0
P360_NotificationRule,PNR_FilterSQL,0
P360_NotificationRule,PNR_HighestRequiredLevel,0
P360_NotificationRule,PNR_ShortMessage,0
P360_NotificationRule,PNR_LongMessage,0
P360_NotificationRule,PNR_LongMessageRemote,0
P360_NotificationRule,PNR_LinkToPageTitle,0
P360_NotificationRule,PNR_LinkToPageURL,0
P360_NotificationRule,PNR_LinkToPageMethod,0
P360_NotificationRule,PNR_AlertEveryTime,0
P360_NotificationRule,PNR_Subquery,0
P360_NotificationRule,PNR_Subquery_ID,0
P360_NotificationRule,PNR_Active,0
P360_NotificationRuleKey,PNRK_ID,1
P360_NotificationRuleKey,PNRK_TStamp,0
P360_NotificationRuleKey,PNRK_LastUser,0
P360_NotificationRuleKey,PNRK_District,0
P360_NotificationRuleKey,PNRK_PNR_ID,0
P360_NotificationRuleKey,PNRK_KeyName,0
P360_NotificationRuleKey,PNRK_ResultValueID,0
P360_NotificationRuleUser,PNRU_ID,1
P360_NotificationRuleUser,PNRU_TStamp,0
P360_NotificationRuleUser,PNRU_LastUser,0
P360_NotificationRuleUser,PNRU_District,0
P360_NotificationRuleUser,PNRU_PNR_ID,0
P360_NotificationRuleUser,PNRU_Level,0
P360_NotificationRuleUser,PNRU_Actor,0
P360_NotificationRuleUser,PNRU_SubscribeStatus,0
P360_NotificationRuleUser,PNRU_DeliveryMethod,0
P360_NotificationRuleUser,PNRU_InstantAlert,0
P360_NotificationRuleUser,PNRU_Active,0
P360_NotificationSchedule,PNS_ID,1
P360_NotificationSchedule,PNS_TStamp,0
P360_NotificationSchedule,PNS_LastUser,0
P360_NotificationSchedule,PNS_District,0
P360_NotificationSchedule,PNS_PNRU_ID,0
P360_NotificationSchedule,PNS_PNRS_ID,0
P360_NotificationSchedule,PNS_Minute,0
P360_NotificationSchedule,PNS_Hour,0
P360_NotificationSchedule,PNS_DayOfMonth,0
P360_NotificationSchedule,PNS_Month,0
P360_NotificationSchedule,PNS_DayOfWeek,0
P360_NotificationSchedule,PNS_TaskType,0
P360_NotificationSchedule,PNS_AssignedToTask,0
P360_NotificationTasks,PNT_ID,1
P360_NotificationTasks,PNT_PNS_ID,0
P360_NotificationTasks,PNT_AgentPriority,0
P360_NotificationTasks,PNT_StartDateTime,0
P360_NotificationTasks,PNT_Status,0
P360_NotificationTasks,PNT_TaskType,0
P360_NotificationUserCriteria,PNUC_ID,1
P360_NotificationUserCriteria,PNUC_TStamp,0
P360_NotificationUserCriteria,PNUC_LastUser,0
P360_NotificationUserCriteria,PNUC_District,0
P360_NotificationUserCriteria,PNUC_PNR_ID,0
P360_NotificationUserCriteria,PNUC_PNRU_ID,0
P360_NotificationUserCriteria,PNUC_CriteriaType,0
P360_NotificationUserCriteria,PNUC_CriteriaVariable,0
P360_NotificationUserCriteria,PNUC_CriteriaValue,0
PESC_SUBTEST_CODE,DISTRICT,1
PESC_SUBTEST_CODE,SUBTEST_CODE,1
PESC_SUBTEST_CODE,SUBTEST_NAME,0
PESC_SUBTEST_CODE,CHANGE_DATE_TIME,0
PESC_SUBTEST_CODE,CHANGE_UID,0
PESC_TEST_CODE,DISTRICT,1
PESC_TEST_CODE,TEST_CODE,1
PESC_TEST_CODE,TEST_NAME,0
PESC_TEST_CODE,CHANGE_DATE_TIME,0
PESC_TEST_CODE,CHANGE_UID,0
PESCTB_DIPLO_XWALK,DISTRICT,1
PESCTB_DIPLO_XWALK,CODE,1
PESCTB_DIPLO_XWALK,ACADEMICAWARDLEVEL,0
PESCTB_DIPLO_XWALK,DIPLOMATYPE,0
PESCTB_DIPLO_XWALK,CHANGE_DATE_TIME,0
PESCTB_DIPLO_XWALK,CHANGE_UID,0
PESCTB_GEND_XWALK,DISTRICT,1
PESCTB_GEND_XWALK,CODE,1
PESCTB_GEND_XWALK,PESCCODE,0
PESCTB_GEND_XWALK,CHANGE_DATE_TIME,0
PESCTB_GEND_XWALK,CHANGE_UID,0
PESCTB_GPA_XWALK,DISTRICT,1
PESCTB_GPA_XWALK,CODE,1
PESCTB_GPA_XWALK,PESCCODE,0
PESCTB_GPA_XWALK,CHANGE_DATE_TIME,0
PESCTB_GPA_XWALK,CHANGE_UID,0
PESCTB_GRADE_XWALK,DISTRICT,1
PESCTB_GRADE_XWALK,CODE,1
PESCTB_GRADE_XWALK,PESCCODE,0
PESCTB_GRADE_XWALK,CHANGE_DATE_TIME,0
PESCTB_GRADE_XWALK,CHANGE_UID,0
PESCTB_SCORE_XWALK,DISTRICT,1
PESCTB_SCORE_XWALK,CODE,1
PESCTB_SCORE_XWALK,PESCCODE,0
PESCTB_SCORE_XWALK,CHANGE_DATE_TIME,0
PESCTB_SCORE_XWALK,CHANGE_UID,0
PESCTB_SHOT_XWALK,DISTRICT,1
PESCTB_SHOT_XWALK,CODE,1
PESCTB_SHOT_XWALK,PESCCODE,0
PESCTB_SHOT_XWALK,PESC_DESC_HELP,0
PESCTB_SHOT_XWALK,CHANGE_DATE_TIME,0
PESCTB_SHOT_XWALK,CHANGE_UID,0
PESCTB_STU_STATUS,DISTRICT,1
PESCTB_STU_STATUS,STUDENT_ID,1
PESCTB_STU_STATUS,REPORT_ID,1
PESCTB_STU_STATUS,DATASET_ID,1
PESCTB_STU_STATUS,CHANGE_DATE_TIME,0
PESCTB_STU_STATUS,CHANGE_UID,0
PESCTB_SUFFIX_XWALK,DISTRICT,1
PESCTB_SUFFIX_XWALK,CODE,1
PESCTB_SUFFIX_XWALK,PESCCODE,0
PESCTB_SUFFIX_XWALK,CHANGE_DATE_TIME,0
PESCTB_SUFFIX_XWALK,CHANGE_UID,0
PESCTB_TERM_XWALK,DISTRICT,1
PESCTB_TERM_XWALK,BUILDING,1
PESCTB_TERM_XWALK,RUNTERMYEAR,1
PESCTB_TERM_XWALK,PESCCODE,0
PESCTB_TERM_XWALK,CHANGE_DATE_TIME,0
PESCTB_TERM_XWALK,CHANGE_UID,0
PP_CFG,DISTRICT,1
PP_CFG,TM1_HOST,0
PP_CFG,TM1_SERVER,0
PP_CFG,TM1_ADMIN,0
PP_CFG,TM1_PWD,0
PP_CFG,TM1_WEB_URL,0
PP_CFG,TM1_INSTALL_SERVER,0
PP_CFG,TM1_INSTALL_PATH,0
PP_CFG,TM1_DSN,0
PP_CFG,REFRESH_MONTHS,0
PP_CFG,CHANGE_DATE_TIME,0
PP_CFG,CHANGE_UID,0
PP_DISTDEF_MAP,DISTRICT,1
PP_DISTDEF_MAP,SCREEN_NUMBER,1
PP_DISTDEF_MAP,FIELD_NUMBER,1
PP_DISTDEF_MAP,FIELD_LABEL,0
PP_DISTDEF_MAP,DEFAULT_VALUE,0
PP_DISTDEF_MAP,DEFAULT_FORMATTED,0
PP_DISTDEF_MAP,PROGRAM_ID,0
PP_DISTDEF_MAP,DATA_TYPE,0
PP_DISTDEF_MAP,NUMBER_TYPE,0
PP_DISTDEF_MAP,DATA_LENGTH,0
PP_DISTDEF_MAP,CUBE_ORDER,0
PP_DISTDEF_MAP,CHANGE_DATE_TIME,0
PP_DISTDEF_MAP,CHANGE_UID,0
PP_MONTH_DAYS,DISTRICT,1
PP_MONTH_DAYS,SCHOOL_YEAR,1
PP_MONTH_DAYS,SUMMER_SCHOOL,1
PP_MONTH_DAYS,CALENDAR_YEAR,1
PP_MONTH_DAYS,CALENDAR_MONTH,1
PP_MONTH_DAYS,BUILDING,1
PP_MONTH_DAYS,TRACK,1
PP_MONTH_DAYS,CALENDAR,0
PP_MONTH_DAYS,DAYS_IN_MONTH,0
PP_MONTH_DAYS,FIRST_DAY_OF_MONTH,0
PP_MONTH_DAYS,LAST_DAY_OF_MONTH,0
PP_MONTH_DAYS,CHANGE_DATE_TIME,0
PP_MONTH_DAYS,CHANGE_UID,0
PP_REBUILD_HISTORY,DISTRICT,1
PP_REBUILD_HISTORY,CUBE_NAME,1
PP_REBUILD_HISTORY,NEEDS_REBUILD,0
PP_REBUILD_HISTORY,CURRENT_RUN_TIME,0
PP_REBUILD_HISTORY,LAST_RUN_TIME,0
PP_REBUILD_HISTORY,LAST_UPDATE_TYPE,0
PP_REBUILD_HISTORY,LAST_STATUS,0
PP_REBUILD_HISTORY,LAST_CALC_ID,0
PP_REBUILD_HISTORY,CHANGE_DATE_TIME,0
PP_REBUILD_HISTORY,CHANGE_UID,0
PP_SECURITY,DISTRICT,1
PP_SECURITY,CUBE_NAME,1
PP_SECURITY,ITEM_TYPE,1
PP_SECURITY,ITEM_NAME,1
PP_SECURITY,PACKAGE,0
PP_SECURITY,SUBPACKAGE,0
PP_SECURITY,FEATURE,0
PP_SECURITY,CHANGE_DATE_TIME,0
PP_SECURITY,CHANGE_UID,0
PP_STUDENT_CACHE,DISTRICT,1
PP_STUDENT_CACHE,START_DATE,1
PP_STUDENT_CACHE,END_DATE,1
PP_STUDENT_CACHE,SCHOOL_YEAR,0
PP_STUDENT_CACHE,BUILDING,0
PP_STUDENT_CACHE,SUMMER_SCHOOL,0
PP_STUDENT_CACHE,STUDENT_GUID,0
PP_STUDENT_CACHE,STUDENT_ID,1
PP_STUDENT_CACHE,STUDENT_NAME,0
PP_STUDENT_CACHE,ETHNIC_CODE,0
PP_STUDENT_CACHE,GENDER,0
PP_STUDENT_CACHE,GRADE,0
PP_STUDENT_CACHE,HOUSE_TEAM,0
PP_STUDENT_CACHE,MEAL_STATUS,0
PP_STUDENT_CACHE,CURRICULUM,0
PP_STUDENT_CACHE,GRADUATION_YEAR,0
PP_STUDENT_CACHE,TRACK,0
PP_STUDENT_CACHE,CALENDAR,0
PP_STUDENT_CACHE,RESIDENCY_CODE,0
PP_STUDENT_CACHE,CITIZEN_STATUS,0
PP_STUDENT_CACHE,AT_RISK,0
PP_STUDENT_CACHE,MIGRANT,0
PP_STUDENT_CACHE,HAS_IEP,0
PP_STUDENT_CACHE,SECTION_504_PLAN,0
PP_STUDENT_CACHE,HOMELESS_STATUS,0
PP_STUDENT_CACHE,ESL,0
PP_STUDENT_CACHE,DIPLOMA_TYPE,0
PP_STUDENT_CACHE,DISTDEF_01,0
PP_STUDENT_CACHE,DISTDEF_02,0
PP_STUDENT_CACHE,DISTDEF_03,0
PP_STUDENT_CACHE,DISTDEF_04,0
PP_STUDENT_CACHE,DISTDEF_05,0
PP_STUDENT_CACHE,DISTDEF_06,0
PP_STUDENT_CACHE,DISTDEF_07,0
PP_STUDENT_CACHE,DISTDEF_08,0
PP_STUDENT_CACHE,DISTDEF_09,0
PP_STUDENT_CACHE,DISTDEF_10,0
PP_STUDENT_CACHE,DISTDEF_11,0
PP_STUDENT_CACHE,DISTDEF_12,0
PP_STUDENT_CACHE,DISTDEF_13,0
PP_STUDENT_CACHE,DISTDEF_14,0
PP_STUDENT_CACHE,DISTDEF_15,0
PP_STUDENT_CACHE,DISTDEF_16,0
PP_STUDENT_CACHE,DISTDEF_17,0
PP_STUDENT_CACHE,DISTDEF_18,0
PP_STUDENT_CACHE,DISTDEF_19,0
PP_STUDENT_CACHE,DISTDEF_20,0
PP_STUDENT_CACHE,DISTDEF_21,0
PP_STUDENT_CACHE,DISTDEF_22,0
PP_STUDENT_CACHE,DISTDEF_23,0
PP_STUDENT_CACHE,DISTDEF_24,0
PP_STUDENT_CACHE,DISTDEF_25,0
PP_STUDENT_CACHE,IS_DIRTY,0
PP_STUDENT_CACHE,CHANGE_DATE_TIME,0
PP_STUDENT_CACHE,CHANGE_UID,0
PP_STUDENT_MONTH,DISTRICT,1
PP_STUDENT_MONTH,STUDENT_ID,1
PP_STUDENT_MONTH,START_DATE,1
PP_STUDENT_MONTH,DAYS_IN_MONTH,0
PP_STUDENT_MONTH,CHANGE_DATE_TIME,0
PP_STUDENT_MONTH,CHANGE_UID,0
PP_STUDENT_MONTH_ABS,DISTRICT,1
PP_STUDENT_MONTH_ABS,STUDENT_ID,1
PP_STUDENT_MONTH_ABS,START_DATE,1
PP_STUDENT_MONTH_ABS,VIEW_TYPE,1
PP_STUDENT_MONTH_ABS,ATT_BUILDING,1
PP_STUDENT_MONTH_ABS,PRESENT_TIME,0
PP_STUDENT_MONTH_ABS,TOTAL_DAY_TIME,0
PP_STUDENT_MONTH_ABS,MEMBERSHIP_VALUE,0
PP_STUDENT_MONTH_ABS,CHANGE_DATE_TIME,0
PP_STUDENT_MONTH_ABS,CHANGE_UID,0
PP_STUDENT_TEMP,DISTRICT,1
PP_STUDENT_TEMP,SCHOOL_DAY,1
PP_STUDENT_TEMP,SCHOOL_YEAR,1
PP_STUDENT_TEMP,BUILDING,1
PP_STUDENT_TEMP,STUDENT_ID,1
PP_STUDENT_TEMP,SUMMER_SCHOOL,0
PP_STUDENT_TEMP,ETHNIC_CODE,0
PP_STUDENT_TEMP,GRADE,0
PP_STUDENT_TEMP,HOUSE_TEAM,0
PP_STUDENT_TEMP,MEAL_STATUS,0
PP_STUDENT_TEMP,CURRICULUM,0
PP_STUDENT_TEMP,GRADUATION_YEAR,0
PP_STUDENT_TEMP,TRACK,0
PP_STUDENT_TEMP,CALENDAR,0
PP_STUDENT_TEMP,RESIDENCY_CODE,0
PP_STUDENT_TEMP,CITIZEN_STATUS,0
PP_STUDENT_TEMP,AT_RISK,0
PP_STUDENT_TEMP,MIGRANT,0
PP_STUDENT_TEMP,HAS_IEP,0
PP_STUDENT_TEMP,SECTION_504_PLAN,0
PP_STUDENT_TEMP,HOMELESS_STATUS,0
PP_STUDENT_TEMP,ESL,0
PP_STUDENT_TEMP,DIPLOMA_TYPE,0
PP_STUDENT_TEMP,DISTDEF_01,0
PP_STUDENT_TEMP,DISTDEF_02,0
PP_STUDENT_TEMP,DISTDEF_03,0
PP_STUDENT_TEMP,DISTDEF_04,0
PP_STUDENT_TEMP,DISTDEF_05,0
PP_STUDENT_TEMP,DISTDEF_06,0
PP_STUDENT_TEMP,DISTDEF_07,0
PP_STUDENT_TEMP,DISTDEF_08,0
PP_STUDENT_TEMP,DISTDEF_09,0
PP_STUDENT_TEMP,DISTDEF_10,0
PP_STUDENT_TEMP,DISTDEF_11,0
PP_STUDENT_TEMP,DISTDEF_12,0
PP_STUDENT_TEMP,DISTDEF_13,0
PP_STUDENT_TEMP,DISTDEF_14,0
PP_STUDENT_TEMP,DISTDEF_15,0
PP_STUDENT_TEMP,DISTDEF_16,0
PP_STUDENT_TEMP,DISTDEF_17,0
PP_STUDENT_TEMP,DISTDEF_18,0
PP_STUDENT_TEMP,DISTDEF_19,0
PP_STUDENT_TEMP,DISTDEF_20,0
PP_STUDENT_TEMP,DISTDEF_21,0
PP_STUDENT_TEMP,DISTDEF_22,0
PP_STUDENT_TEMP,DISTDEF_23,0
PP_STUDENT_TEMP,DISTDEF_24,0
PP_STUDENT_TEMP,DISTDEF_25,0
PRCH_STU_STATUS,DISTRICT,1
PRCH_STU_STATUS,STUDENT_ID,1
PRCH_STU_STATUS,PESC_FILE_LOC,0
PRCH_STU_STATUS,PENDING_UPLOAD,0
PRCH_STU_STATUS,LAST_UPLOAD_ATT,0
PRCH_STU_STATUS,LAST_UPLOAD_SUC,0
PRCH_STU_STATUS,UPLOAD_RESPONSE,0
PRCH_STU_STATUS,UPLOAD_MESSAGE,0
PRCH_STU_STATUS,CHANGE_DATE_TIME,0
PRCH_STU_STATUS,CHANGE_UID,0
PS_SPECIAL_ED_PHONE_TYPE_MAP,DISTRICT,0
PS_SPECIAL_ED_PHONE_TYPE_MAP,SPECIAL_ED_PHONE_TYPE,1
PS_SPECIAL_ED_PHONE_TYPE_MAP,ESCHOOLPLUS_PHONE_TYPE,0
PS_SPECIAL_ED_PHONE_TYPE_MAP,CHANGE_DATE_TIME,0
PS_SPECIAL_ED_PHONE_TYPE_MAP,CHANGE_UID,0
REG,DISTRICT,1
REG,STUDENT_ID,1
REG,FIRST_NAME,0
REG,MIDDLE_NAME,0
REG,LAST_NAME,0
REG,GENERATION,0
REG,BUILDING,0
REG,HOME_BUILDING,0
REG,BUILDING_OVERRIDE,0
REG,BUILDING_REASON,0
REG,GRADE,0
REG,GENDER,0
REG,LANGUAGE,0
REG,NATIVE_LANGUAGE,0
REG,CALENDAR,0
REG,TRACK,0
REG,CURRENT_STATUS,0
REG,SUMMER_STATUS,0
REG,COUNSELOR,0
REG,HOUSE_TEAM,0
REG,HOMEROOM_PRIMARY,0
REG,HOMEROOM_SECONDARY,0
REG,BIRTHDATE,0
REG,FAMILY_CENSUS,0
REG,ALT_BUILDING,0
REG,ALT_DISTRICT,0
REG,NICKNAME,0
REG,HOME_DISTRICT,0
REG,ATTENDING_DISTRICT,0
REG,ALT_BLDG_ACCT,0
REG,DIST_ENROLL_DATE,0
REG,STATE_ENROLL_DATE,0
REG,US_ENROLL_DATE,0
REG,STUDENT_GUID,0
REG,RES_COUNTY_CODE,0
REG,STATE_RES_BUILDING,0
REG,GRADE_9_DATE,0
REG,GENDER_IDENTITY,0
REG,CHANGE_DATE_TIME,0
REG,CHANGE_UID,0
REG,HOME_DISTRICT_OVERRIDE,0
REG,UNIQUE_REG_ID,0
REG_ACADEMIC,DISTRICT,1
REG_ACADEMIC,STUDENT_ID,1
REG_ACADEMIC,GRADUATION_YEAR,0
REG_ACADEMIC,GRADUATION_DATE,0
REG_ACADEMIC,PROMOTION,0
REG_ACADEMIC,CURRICULUM,0
REG_ACADEMIC,SCHD_PRIORITY,0
REG_ACADEMIC,GRADUATE_REQ_GROUP,0
REG_ACADEMIC,MODELED_GRAD_PLAN,0
REG_ACADEMIC,PENDING_GRAD_PLAN,0
REG_ACADEMIC,EXP_GRAD_PLAN,0
REG_ACADEMIC,ACT_GRAD_PLAN,0
REG_ACADEMIC,DIPLOMA_TYPE,0
REG_ACADEMIC,ELIG_STATUS,0
REG_ACADEMIC,ELIG_REASON,0
REG_ACADEMIC,ELIG_EFFECTIVE_DTE,0
REG_ACADEMIC,ELIG_EXPIRES_DATE,0
REG_ACADEMIC,HOLD_REPORT_CARD,0
REG_ACADEMIC,RC_HOLD_OVERRIDE,0
REG_ACADEMIC,VOTEC,0
REG_ACADEMIC,ADVISOR,0
REG_ACADEMIC,DISCIPLINARIAN,0
REG_ACADEMIC,FEDERAL_GRAD_YEAR,0
REG_ACADEMIC,ROW_IDENTITY,0
REG_ACADEMIC,CHANGE_DATE_TIME,0
REG_ACADEMIC,CHANGE_UID,0
REG_ACADEMIC_SUPP,DISTRICT,1
REG_ACADEMIC_SUPP,STUDENT_ID,1
REG_ACADEMIC_SUPP,SUPP_TYPE,1
REG_ACADEMIC_SUPP,SUPP_REQ_GROUP,1
REG_ACADEMIC_SUPP,CHANGE_DATE_TIME,0
REG_ACADEMIC_SUPP,CHANGE_UID,0
REG_ACT_PREREQ,DISTRICT,1
REG_ACT_PREREQ,SCHOOL_YEAR,1
REG_ACT_PREREQ,BUILDING,1
REG_ACT_PREREQ,ACTIVITY_CODE,1
REG_ACT_PREREQ,SEQUENCE_NUM,1
REG_ACT_PREREQ,AND_OR_FLAG,0
REG_ACT_PREREQ,TABLE_NAME,0
REG_ACT_PREREQ,COLUMN_NAME,0
REG_ACT_PREREQ,OPERATOR,0
REG_ACT_PREREQ,LOW_VALUE,0
REG_ACT_PREREQ,HIGH_VALUE,0
REG_ACT_PREREQ,CHANGE_DATE_TIME,0
REG_ACT_PREREQ,CHANGE_UID,0
REG_ACTIVITY_ADV,DISTRICT,1
REG_ACTIVITY_ADV,SCHOOL_YEAR,1
REG_ACTIVITY_ADV,BUILDING,1
REG_ACTIVITY_ADV,ACTIVITY_CODE,1
REG_ACTIVITY_ADV,STAFF_ID,1
REG_ACTIVITY_ADV,ROW_IDENTITY,0
REG_ACTIVITY_ADV,CHANGE_DATE_TIME,0
REG_ACTIVITY_ADV,CHANGE_UID,0
REG_ACTIVITY_DET,DISTRICT,1
REG_ACTIVITY_DET,SCHOOL_YEAR,1
REG_ACTIVITY_DET,BUILDING,1
REG_ACTIVITY_DET,ACTIVITY_CODE,1
REG_ACTIVITY_DET,STUDENT_ID,1
REG_ACTIVITY_DET,ACTIVITY_STATUS,0
REG_ACTIVITY_DET,INELIGIBLE,0
REG_ACTIVITY_DET,OVERRIDE,0
REG_ACTIVITY_DET,START_DATE,0
REG_ACTIVITY_DET,END_DATE,0
REG_ACTIVITY_DET,DURATION,0
REG_ACTIVITY_DET,ACTIVITY_COMMENT,0
REG_ACTIVITY_DET,ROW_IDENTITY,0
REG_ACTIVITY_DET,CHANGE_DATE_TIME,0
REG_ACTIVITY_DET,CHANGE_UID,0
REG_ACTIVITY_ELIG,DISTRICT,1
REG_ACTIVITY_ELIG,SCHOOL_YEAR,1
REG_ACTIVITY_ELIG,BUILDING,1
REG_ACTIVITY_ELIG,STUDENT_ID,1
REG_ACTIVITY_ELIG,ELIG_EFFECTIVE_DTE,1
REG_ACTIVITY_ELIG,ELIG_STATUS,0
REG_ACTIVITY_ELIG,ELIG_REASON,0
REG_ACTIVITY_ELIG,ELIG_EXPIRES_DATE,0
REG_ACTIVITY_ELIG,CHANGE_DATE_TIME,0
REG_ACTIVITY_ELIG,CHANGE_UID,0
REG_ACTIVITY_HDR,DISTRICT,1
REG_ACTIVITY_HDR,SCHOOL_YEAR,1
REG_ACTIVITY_HDR,BUILDING,1
REG_ACTIVITY_HDR,ACTIVITY_CODE,1
REG_ACTIVITY_HDR,DESCRIPTION,0
REG_ACTIVITY_HDR,MODERATOR,0
REG_ACTIVITY_HDR,MAX_ENROLLMENT,0
REG_ACTIVITY_HDR,CURRENT_ENROLLMENT,0
REG_ACTIVITY_HDR,EXCEED_MAXIMUM,0
REG_ACTIVITY_HDR,STATE_CODE_EQUIV,0
REG_ACTIVITY_HDR,ROW_IDENTITY,0
REG_ACTIVITY_HDR,CHANGE_DATE_TIME,0
REG_ACTIVITY_HDR,CHANGE_UID,0
REG_ACTIVITY_INEL,DISTRICT,1
REG_ACTIVITY_INEL,SCHOOL_YEAR,1
REG_ACTIVITY_INEL,BUILDING,1
REG_ACTIVITY_INEL,STUDENT_ID,1
REG_ACTIVITY_INEL,ACTIVITY_CODE,1
REG_ACTIVITY_INEL,NOTIFICATION_DATE,1
REG_ACTIVITY_INEL,TRIGGER_EVENT,1
REG_ACTIVITY_INEL,ATTENDANCE_DATE,1
REG_ACTIVITY_INEL,ATTENDANCE_PERIOD,1
REG_ACTIVITY_INEL,INELIGIBILITY_CODE,0
REG_ACTIVITY_INEL,SOURCE,0
REG_ACTIVITY_INEL,INVALID_EVENT,0
REG_ACTIVITY_INEL,CHANGE_DATE_TIME,0
REG_ACTIVITY_INEL,CHANGE_UID,0
REG_ACTIVITY_MP,DISTRICT,1
REG_ACTIVITY_MP,SCHOOL_YEAR,1
REG_ACTIVITY_MP,BUILDING,1
REG_ACTIVITY_MP,ACTIVITY_CODE,1
REG_ACTIVITY_MP,MARKING_PERIOD,1
REG_ACTIVITY_MP,CHANGE_DATE_TIME,0
REG_ACTIVITY_MP,CHANGE_UID,0
REG_APPOINTMENT,DISTRICT,1
REG_APPOINTMENT,APPOINTMENT_ID,1
REG_APPOINTMENT,BUILDING,0
REG_APPOINTMENT,STUDENT_ID,0
REG_APPOINTMENT,DATE_ENTERED,0
REG_APPOINTMENT,ENTRY_UID,0
REG_APPOINTMENT,APPT_START_TIME,0
REG_APPOINTMENT,APPT_END_TIME,0
REG_APPOINTMENT,APPT_TYPE,0
REG_APPOINTMENT,APPT_REASON,0
REG_APPOINTMENT,STAFF_ID,0
REG_APPOINTMENT,PERIOD,0
REG_APPOINTMENT,KEPT_APPT,0
REG_APPOINTMENT,INCLUDE_STUDENT_NOTE,0
REG_APPOINTMENT,CHANGE_DATE_TIME,0
REG_APPOINTMENT,CHANGE_UID,0
REG_APPT_SHARE,DISTRICT,1
REG_APPT_SHARE,STAFF_ID,1
REG_APPT_SHARE,LOGIN_ID,1
REG_APPT_SHARE,CHANGE_DATE_TIME,0
REG_APPT_SHARE,CHANGE_UID,0
REG_AT_RISK_FACTOR,DISTRICT,1
REG_AT_RISK_FACTOR,FACTOR_CODE,1
REG_AT_RISK_FACTOR,DESCRIPTION,0
REG_AT_RISK_FACTOR,ACTIVE,0
REG_AT_RISK_FACTOR,DISPLAY_ORDER,0
REG_AT_RISK_FACTOR,FACTOR_TYPE,0
REG_AT_RISK_FACTOR,TABLE_NAME,0
REG_AT_RISK_FACTOR,COLUMN_NAME,0
REG_AT_RISK_FACTOR,SCREEN_NUMBER,0
REG_AT_RISK_FACTOR,FIELD_NUMBER,0
REG_AT_RISK_FACTOR,UPDATE_OVERALL,0
REG_AT_RISK_FACTOR,ALLOW_FORMER_STATUS,0
REG_AT_RISK_FACTOR,CALC_REQ_REASONS,0
REG_AT_RISK_FACTOR,CHANGE_DATE_TIME,0
REG_AT_RISK_FACTOR,CHANGE_UID,0
REG_AT_RISK_FACTOR_REASON,DISTRICT,1
REG_AT_RISK_FACTOR_REASON,FACTOR_CODE,1
REG_AT_RISK_FACTOR_REASON,FACTOR_REASON,1
REG_AT_RISK_FACTOR_REASON,CHANGE_DATE_TIME,0
REG_AT_RISK_FACTOR_REASON,CHANGE_UID,0
REG_BUILDING,DISTRICT,1
REG_BUILDING,BUILDING,1
REG_BUILDING,NAME,0
REG_BUILDING,TRANSFER_BUILDING,0
REG_BUILDING,ABBREVIATION,0
REG_BUILDING,STREET1,0
REG_BUILDING,STREET2,0
REG_BUILDING,CITY,0
REG_BUILDING,STATE,0
REG_BUILDING,ZIP,0
REG_BUILDING,PHONE,0
REG_BUILDING,FAX,0
REG_BUILDING,PRINCIPAL,0
REG_BUILDING,CALENDAR,0
REG_BUILDING,BUILDING_TYPE,0
REG_BUILDING,DEFAULT_ZIP,0
REG_BUILDING,STATE_CODE_EQUIV,0
REG_BUILDING,COUNTY_CODE,0
REG_BUILDING,OUT_OF_DISTRICT,0
REG_BUILDING,PESC_CODE,0
REG_BUILDING,CHANGE_DATE_TIME,0
REG_BUILDING,CHANGE_UID,0
REG_BUILDING_GRADE,DISTRICT,1
REG_BUILDING_GRADE,BUILDING,1
REG_BUILDING_GRADE,GRADE,1
REG_BUILDING_GRADE,CHANGE_DATE_TIME,0
REG_BUILDING_GRADE,CHANGE_UID,0
REG_CAL_DAYS,DISTRICT,1
REG_CAL_DAYS,BUILDING,1
REG_CAL_DAYS,SCHOOL_YEAR,1
REG_CAL_DAYS,SUMMER_SCHOOL,1
REG_CAL_DAYS,TRACK,1
REG_CAL_DAYS,CALENDAR,1
REG_CAL_DAYS,CAL_DATE,1
REG_CAL_DAYS,CYCLE_FLAG,0
REG_CAL_DAYS,CYCLE_CODE,0
REG_CAL_DAYS,MEMBERSHIP_DAY,0
REG_CAL_DAYS,MEMBERSHIP_VALUE,0
REG_CAL_DAYS,TAKE_ATTENDANCE,0
REG_CAL_DAYS,INCLUDE_TOTALS,0
REG_CAL_DAYS,DAY_TYPE,0
REG_CAL_DAYS,DAY_NUMBER,0
REG_CAL_DAYS,DAY_IN_MEMBERSHIP,0
REG_CAL_DAYS,ALTERNATE_CYCLE,0
REG_CAL_DAYS,WEEK_NUMBER,0
REG_CAL_DAYS,INSTRUCT_TIME,0
REG_CAL_DAYS,ROW_IDENTITY,0
REG_CAL_DAYS,CHANGE_DATE_TIME,0
REG_CAL_DAYS,CHANGE_UID,0
REG_CAL_DAYS_LEARNING_LOC,DISTRICT,1
REG_CAL_DAYS_LEARNING_LOC,BUILDING,1
REG_CAL_DAYS_LEARNING_LOC,SCHOOL_YEAR,1
REG_CAL_DAYS_LEARNING_LOC,SUMMER_SCHOOL,1
REG_CAL_DAYS_LEARNING_LOC,TRACK,1
REG_CAL_DAYS_LEARNING_LOC,CALENDAR,1
REG_CAL_DAYS_LEARNING_LOC,CAL_DATE,1
REG_CAL_DAYS_LEARNING_LOC,LEARNING_LOCATION,1
REG_CAL_DAYS_LEARNING_LOC,CHANGE_DATE_TIME,0
REG_CAL_DAYS_LEARNING_LOC,CHANGE_UID,0
REG_CAL_DAYS_LEARNING_LOC,ROW_IDENTITY,0
REG_CAL_DAYS_LEARNING_LOC,LOCATION_TYPE,0
REG_CAL_DAYS_LL_PDS,DISTRICT,1
REG_CAL_DAYS_LL_PDS,BUILDING,1
REG_CAL_DAYS_LL_PDS,SCHOOL_YEAR,1
REG_CAL_DAYS_LL_PDS,SUMMER_SCHOOL,1
REG_CAL_DAYS_LL_PDS,TRACK,1
REG_CAL_DAYS_LL_PDS,CALENDAR,1
REG_CAL_DAYS_LL_PDS,CAL_DATE,1
REG_CAL_DAYS_LL_PDS,LEARNING_LOCATION,1
REG_CAL_DAYS_LL_PDS,LOCATION_TYPE,1
REG_CAL_DAYS_LL_PDS,ATT_PERIOD,1
REG_CAL_DAYS_LL_PDS,CHANGE_DATE_TIME,0
REG_CAL_DAYS_LL_PDS,CHANGE_UID,0
REG_CAL_DAYS_LL_PDS,ROW_IDENTITY,0
REG_CALENDAR,DISTRICT,1
REG_CALENDAR,BUILDING,1
REG_CALENDAR,SCHOOL_YEAR,1
REG_CALENDAR,SUMMER_SCHOOL,1
REG_CALENDAR,TRACK,1
REG_CALENDAR,CALENDAR,1
REG_CALENDAR,DESCRIPTION,0
REG_CALENDAR,DEF_MEM_VALUE,0
REG_CALENDAR,FIRST_DAY,0
REG_CALENDAR,LAST_DAY,0
REG_CALENDAR,SUNDAY,0
REG_CALENDAR,MONDAY,0
REG_CALENDAR,TUESDAY,0
REG_CALENDAR,WEDNESDAY,0
REG_CALENDAR,THURSDAY,0
REG_CALENDAR,FRIDAY,0
REG_CALENDAR,SATURDAY,0
REG_CALENDAR,DAYS_IN_CYCLE,0
REG_CALENDAR,FIRST_DAY_CYCLE,0
REG_CALENDAR,DAYS_IN_CALENDAR,0
REG_CALENDAR,DAYS_IN_MEMBERSHIP,0
REG_CALENDAR,STATE_CODE_EQUIV,0
REG_CALENDAR,ROW_IDENTITY,0
REG_CALENDAR,CHANGE_DATE_TIME,0
REG_CALENDAR,CHANGE_UID,0
REG_CFG,DISTRICT,1
REG_CFG,BUILDING,1
REG_CFG,SCHOOL_YEAR,1
REG_CFG,AUTO_ASSIGN,0
REG_CFG,OVERIDE_AUTO_ASSGN,0
REG_CFG,STARTING_ID,0
REG_CFG,MAX_ID_ALLOWED,0
REG_CFG,HIGHEST_ID_USED,0
REG_CFG,DEFAULT_ENTRY_CODE,0
REG_CFG,DEFAULT_ENTRY_DATE,0
REG_CFG,YEAREND_WD_CODE,0
REG_CFG,YEAREND_ENTRY_CODE,0
REG_CFG,DROP_OUT_CODE,0
REG_CFG,EMAIL,0
REG_CFG,YEAR_ROUND,0
REG_CFG,PHOTO_PATH,0
REG_CFG,PHOTO_EXTENSION,0
REG_CFG,ST_ID_PREFIX,0
REG_CFG,ST_STARTING_ID,0
REG_CFG,ST_MAX_ID_ALLOWED,0
REG_CFG,ST_HIGHEST_ID_USED,0
REG_CFG,ST_AUTO_ASSIGN_OV,0
REG_CFG,TEA_PERS_STU_SUMM,0
REG_CFG,SUB_PERS_STU_SUMM,0
REG_CFG,TEA_EMERG_STU_SUMM,0
REG_CFG,SUB_EMERG_STU_SUMM,0
REG_CFG,TEA_STUDENT_SEARCH,0
REG_CFG,SUB_STUDENT_SEARCH,0
REG_CFG,TEA_VIEW_IEP,0
REG_CFG,SUB_VIEW_IEP,0
REG_CFG,TEA_VIEW_GIFTED,0
REG_CFG,SUB_VIEW_GIFTED,0
REG_CFG,TEA_VIEW_504,0
REG_CFG,SUB_VIEW_504,0
REG_CFG,LOCKER_ASSIGN,0
REG_CFG,AUTO_LOCKER_ASSIGN,0
REG_CFG,REGISTRAR_EMAIL,0
REG_CFG,MAX_WITH_BACKDATE,0
REG_CFG,MSG_NEW_STUD,0
REG_CFG,MSG_NEW_PR_STUD,0
REG_CFG,MSG_PRIM_HOMEROOM,0
REG_CFG,MSG_SEC_HOMEROOM,0
REG_CFG,MSG_STU_COUNS,0
REG_CFG,MSG_SUMMER_COUNS,0
REG_CFG,MSG_EW_REENTRY,0
REG_CFG,MSG_EW_CHG_BLDG,0
REG_CFG,CHANGE_DATE_TIME,0
REG_CFG,CHANGE_UID,0
REG_CFG,PHOTO_DIRECTORY,0
REG_CFG_ALERT,DISTRICT,1
REG_CFG_ALERT,BUILDING,1
REG_CFG_ALERT,SCHOOL_YEAR,1
REG_CFG_ALERT,ALERT_TYPE,1
REG_CFG_ALERT,VISIBLE_TO_TEACHER,0
REG_CFG_ALERT,VISIBLE_TO_SUB,0
REG_CFG_ALERT,CHANGE_DATE_TIME,0
REG_CFG_ALERT,CHANGE_UID,0
REG_CFG_ALERT_CODE,DISTRICT,1
REG_CFG_ALERT_CODE,BUILDING,1
REG_CFG_ALERT_CODE,SCHOOL_YEAR,1
REG_CFG_ALERT_CODE,ALERT_TYPE,1
REG_CFG_ALERT_CODE,CODE,1
REG_CFG_ALERT_CODE,CHANGE_DATE_TIME,0
REG_CFG_ALERT_CODE,CHANGE_UID,0
REG_CFG_ALERT_DEF_CRIT,DISTRICT,1
REG_CFG_ALERT_DEF_CRIT,BUILDING,1
REG_CFG_ALERT_DEF_CRIT,SCHOOL_YEAR,1
REG_CFG_ALERT_DEF_CRIT,CRIT_ORDER,1
REG_CFG_ALERT_DEF_CRIT,SEQUENCE_NUM,1
REG_CFG_ALERT_DEF_CRIT,AND_OR_FLAG,0
REG_CFG_ALERT_DEF_CRIT,TABLE_NAME,0
REG_CFG_ALERT_DEF_CRIT,COLUMN_NAME,0
REG_CFG_ALERT_DEF_CRIT,OPERATOR,0
REG_CFG_ALERT_DEF_CRIT,CRITERIA_VALUE1,0
REG_CFG_ALERT_DEF_CRIT,CHANGE_DATE_TIME,0
REG_CFG_ALERT_DEF_CRIT,CHANGE_UID,0
REG_CFG_ALERT_DEFINED,DISTRICT,1
REG_CFG_ALERT_DEFINED,BUILDING,1
REG_CFG_ALERT_DEFINED,SCHOOL_YEAR,1
REG_CFG_ALERT_DEFINED,CRIT_ORDER,1
REG_CFG_ALERT_DEFINED,TITLE,0
REG_CFG_ALERT_DEFINED,VISIBLE_TO_TEACHER,0
REG_CFG_ALERT_DEFINED,VISIBLE_TO_SUB,0
REG_CFG_ALERT_DEFINED,ACTIVE,0
REG_CFG_ALERT_DEFINED,CRIT_STRING1,0
REG_CFG_ALERT_DEFINED,CRIT_STRING2,0
REG_CFG_ALERT_DEFINED,CHANGE_DATE_TIME,0
REG_CFG_ALERT_DEFINED,CHANGE_UID,0
REG_CFG_ALERT_UDS_CRIT_KTY,DISTRICT,1
REG_CFG_ALERT_UDS_CRIT_KTY,BUILDING,1
REG_CFG_ALERT_UDS_CRIT_KTY,SCHOOL_YEAR,1
REG_CFG_ALERT_UDS_CRIT_KTY,CRIT_ORDER,1
REG_CFG_ALERT_UDS_CRIT_KTY,SEQUENCE_NUM,1
REG_CFG_ALERT_UDS_CRIT_KTY,AND_OR_FLAG,0
REG_CFG_ALERT_UDS_CRIT_KTY,SCREEN_NUMBER,0
REG_CFG_ALERT_UDS_CRIT_KTY,FIELD_NUMBER,0
REG_CFG_ALERT_UDS_CRIT_KTY,OPERATOR,0
REG_CFG_ALERT_UDS_CRIT_KTY,CRITERIA_VALUE1,0
REG_CFG_ALERT_UDS_CRIT_KTY,CHANGE_DATE_TIME,0
REG_CFG_ALERT_UDS_CRIT_KTY,CHANGE_UID,0
REG_CFG_ALERT_UDS_KTY,DISTRICT,1
REG_CFG_ALERT_UDS_KTY,BUILDING,1
REG_CFG_ALERT_UDS_KTY,SCHOOL_YEAR,1
REG_CFG_ALERT_UDS_KTY,CRIT_ORDER,1
REG_CFG_ALERT_UDS_KTY,TITLE,0
REG_CFG_ALERT_UDS_KTY,VISIBLE_TO_TEACHER,0
REG_CFG_ALERT_UDS_KTY,VISIBLE_TO_SUB,0
REG_CFG_ALERT_UDS_KTY,ACTIVE,0
REG_CFG_ALERT_UDS_KTY,ALERT_LETTER,0
REG_CFG_ALERT_UDS_KTY,CRITERIA_STRING,0
REG_CFG_ALERT_UDS_KTY,CHANGE_DATE_TIME,0
REG_CFG_ALERT_UDS_KTY,CHANGE_UID,0
REG_CFG_ALERT_USER,DISTRICT,1
REG_CFG_ALERT_USER,BUILDING,1
REG_CFG_ALERT_USER,SCHOOL_YEAR,1
REG_CFG_ALERT_USER,SCREEN_NUMBER,1
REG_CFG_ALERT_USER,FIELD_NUMBER,1
REG_CFG_ALERT_USER,ALERT_TEXT,0
REG_CFG_ALERT_USER,DISPLAY_VALUE,0
REG_CFG_ALERT_USER,DISPLAY_DESC,0
REG_CFG_ALERT_USER,LIST_DISPLAY,0
REG_CFG_ALERT_USER,VISIBLE_TO_TEACHER,0
REG_CFG_ALERT_USER,VISIBLE_TO_SUB,0
REG_CFG_ALERT_USER,CHANGE_DATE_TIME,0
REG_CFG_ALERT_USER,CHANGE_UID,0
REG_CFG_EW_APPLY,DISTRICT,1
REG_CFG_EW_APPLY,BUILDING,1
REG_CFG_EW_APPLY,SCHOOL_YEAR,1
REG_CFG_EW_APPLY,CRITERIA_NUMBER,1
REG_CFG_EW_APPLY,APPLIES_TO_CODE,1
REG_CFG_EW_APPLY,CHANGE_DATE_TIME,0
REG_CFG_EW_APPLY,CHANGE_UID,0
REG_CFG_EW_COMBO,DISTRICT,1
REG_CFG_EW_COMBO,BUILDING,1
REG_CFG_EW_COMBO,SCHOOL_YEAR,1
REG_CFG_EW_COMBO,CRITERIA_NUMBER,1
REG_CFG_EW_COMBO,TYPE,0
REG_CFG_EW_COMBO,CONDITION,0
REG_CFG_EW_COMBO,DEFAULT_ENTRY_CODE,0
REG_CFG_EW_COMBO,DATE_GAP,0
REG_CFG_EW_COMBO,CHANGE_DATE_TIME,0
REG_CFG_EW_COMBO,CHANGE_UID,0
REG_CFG_EW_COND,DISTRICT,1
REG_CFG_EW_COND,BUILDING,1
REG_CFG_EW_COND,SCHOOL_YEAR,1
REG_CFG_EW_COND,CRITERIA_NUMBER,1
REG_CFG_EW_COND,PRECEDING_CODE,1
REG_CFG_EW_COND,CHANGE_DATE_TIME,0
REG_CFG_EW_COND,CHANGE_UID,0
REG_CFG_EW_REQ_ENT,DISTRICT,1
REG_CFG_EW_REQ_ENT,BUILDING,1
REG_CFG_EW_REQ_ENT,SCHOOL_YEAR,1
REG_CFG_EW_REQ_ENT,CRITERIA_NUMBER,1
REG_CFG_EW_REQ_ENT,ENTRY_CODE,1
REG_CFG_EW_REQ_ENT,CHANGE_DATE_TIME,0
REG_CFG_EW_REQ_ENT,CHANGE_UID,0
REG_CFG_EW_REQ_FLD,DISTRICT,1
REG_CFG_EW_REQ_FLD,BUILDING,1
REG_CFG_EW_REQ_FLD,SCHOOL_YEAR,1
REG_CFG_EW_REQ_FLD,CRITERIA_NUMBER,1
REG_CFG_EW_REQ_FLD,PROGRAM_ID,1
REG_CFG_EW_REQ_FLD,FIELD_NUMBER,1
REG_CFG_EW_REQ_FLD,CHANGE_DATE_TIME,0
REG_CFG_EW_REQ_FLD,CHANGE_UID,0
REG_CFG_EW_REQ_WD,DISTRICT,1
REG_CFG_EW_REQ_WD,BUILDING,1
REG_CFG_EW_REQ_WD,SCHOOL_YEAR,1
REG_CFG_EW_REQ_WD,CRITERIA_NUMBER,1
REG_CFG_EW_REQ_WD,WITHDRAWAL_CODE,1
REG_CFG_EW_REQ_WD,CHANGE_DATE_TIME,0
REG_CFG_EW_REQ_WD,CHANGE_UID,0
REG_CFG_EW_REQUIRE,DISTRICT,1
REG_CFG_EW_REQUIRE,BUILDING,1
REG_CFG_EW_REQUIRE,SCHOOL_YEAR,1
REG_CFG_EW_REQUIRE,CRITERIA_NUMBER,1
REG_CFG_EW_REQUIRE,COMMENT_REQUIRED,0
REG_CFG_EW_REQUIRE,CHANGE_DATE_TIME,0
REG_CFG_EW_REQUIRE,CHANGE_UID,0
REG_CLASSIFICATION,DISTRICT,1
REG_CLASSIFICATION,STUDENT_ID,1
REG_CLASSIFICATION,CLASSIFICATION_CODE,1
REG_CLASSIFICATION,CLASSIFICATION_ORDER,0
REG_CLASSIFICATION,CHANGE_DATE_TIME,0
REG_CLASSIFICATION,CHANGE_UID,0
REG_CLASSIFICATION_EVA,DISTRICT,1
REG_CLASSIFICATION_EVA,STUDENT_ID,1
REG_CLASSIFICATION_EVA,CLASSIFICATION_CODE,1
REG_CLASSIFICATION_EVA,CLASSIFICATION_ORDER,0
REG_CLASSIFICATION_EVA,CHANGE_DATE_TIME,0
REG_CLASSIFICATION_EVA,CHANGE_UID,0
REG_CONTACT,DISTRICT,1
REG_CONTACT,CONTACT_ID,1
REG_CONTACT,TITLE,0
REG_CONTACT,SALUTATION,0
REG_CONTACT,FIRST_NAME,0
REG_CONTACT,MIDDLE_NAME,0
REG_CONTACT,LAST_NAME,0
REG_CONTACT,GENERATION,0
REG_CONTACT,LANGUAGE,0
REG_CONTACT,HOME_LANGUAGE,0
REG_CONTACT,USE_FOR_MAILING,0
REG_CONTACT,EMPLOYER,0
REG_CONTACT,DEVELOPMENT,0
REG_CONTACT,APARTMENT,0
REG_CONTACT,COMPLEX,0
REG_CONTACT,STREET_NUMBER,0
REG_CONTACT,STREET_PREFIX,0
REG_CONTACT,STREET_NAME,0
REG_CONTACT,STREET_SUFFIX,0
REG_CONTACT,STREET_TYPE,0
REG_CONTACT,CITY,0
REG_CONTACT,STATE,0
REG_CONTACT,ZIP,0
REG_CONTACT,PLAN_AREA_NUMBER,0
REG_CONTACT,HOME_BUILDING_TYPE,0
REG_CONTACT,EMAIL,0
REG_CONTACT,EMAIL_PREFERENCE,0
REG_CONTACT,DELIVERY_POINT,0
REG_CONTACT,LOGIN_ID,0
REG_CONTACT,WEB_PASSWORD,0
REG_CONTACT,PWD_CHG_DATE_TIME,0
REG_CONTACT,LAST_LOGIN_DATE,0
REG_CONTACT,EDUCATION_LEVEL,0
REG_CONTACT,SIF_REFID,0
REG_CONTACT,HAC_LDAP_FLAG,0
REG_CONTACT,ACCT_LOCKED,0
REG_CONTACT,ACCT_LOCKED_DATE_TIME,0
REG_CONTACT,CHG_PW_NEXT_LOGIN,0
REG_CONTACT,ONBOARD_TOKEN,0
REG_CONTACT,ONBOARD_TOKEN_USED,0
REG_CONTACT,ROW_IDENTITY,0
REG_CONTACT,KEY_USED,0
REG_CONTACT,CONTACT_KEY,0
REG_CONTACT,CHANGE_DATE_TIME,0
REG_CONTACT,CHANGE_UID,0
REG_CONTACT,UNIQUE_REG_CONTACT_ID,0
REG_CONTACT_ADDITIONAL_EMAIL,DISTRICT,1
REG_CONTACT_ADDITIONAL_EMAIL,CONTACT_ID,1
REG_CONTACT_ADDITIONAL_EMAIL,EMAIL,1
REG_CONTACT_ADDITIONAL_EMAIL,CHANGE_DATE_TIME,0
REG_CONTACT_ADDITIONAL_EMAIL,CHANGE_UID,0
REG_CONTACT_HIST,DISTRICT,1
REG_CONTACT_HIST,STUDENT_ID,1
REG_CONTACT_HIST,ADDRESS_TYPE,1
REG_CONTACT_HIST,CONTACT_ID,1
REG_CONTACT_HIST,DEVELOPMENT,0
REG_CONTACT_HIST,APARTMENT,0
REG_CONTACT_HIST,COMPLEX,0
REG_CONTACT_HIST,STREET_NUMBER,0
REG_CONTACT_HIST,STREET_PREFIX,0
REG_CONTACT_HIST,STREET_NAME,0
REG_CONTACT_HIST,STREET_SUFFIX,0
REG_CONTACT_HIST,STREET_TYPE,0
REG_CONTACT_HIST,CITY,0
REG_CONTACT_HIST,STATE,0
REG_CONTACT_HIST,ZIP,0
REG_CONTACT_HIST,DELIVERY_POINT,0
REG_CONTACT_HIST,CHANGE_DATE_TIME,1
REG_CONTACT_HIST,CHANGE_UID,0
REG_CONTACT_HIST_TMP,DISTRICT,1
REG_CONTACT_HIST_TMP,STUDENT_ID,1
REG_CONTACT_HIST_TMP,ADDRESS_TYPE,1
REG_CONTACT_HIST_TMP,CONTACT_ID,1
REG_CONTACT_HIST_TMP,DEVELOPMENT,0
REG_CONTACT_HIST_TMP,APARTMENT,0
REG_CONTACT_HIST_TMP,COMPLEX,0
REG_CONTACT_HIST_TMP,STREET_NUMBER,0
REG_CONTACT_HIST_TMP,STREET_PREFIX,0
REG_CONTACT_HIST_TMP,STREET_NAME,0
REG_CONTACT_HIST_TMP,STREET_SUFFIX,0
REG_CONTACT_HIST_TMP,STREET_TYPE,0
REG_CONTACT_HIST_TMP,CITY,0
REG_CONTACT_HIST_TMP,STATE,0
REG_CONTACT_HIST_TMP,ZIP,0
REG_CONTACT_HIST_TMP,DELIVERY_POINT,0
REG_CONTACT_HIST_TMP,CHANGE_DATE_TIME,1
REG_CONTACT_HIST_TMP,CHANGE_UID,0
REG_CONTACT_LANGUAGE_INTERPRETER,DISTRICT,1
REG_CONTACT_LANGUAGE_INTERPRETER,CONTACT_ID,1
REG_CONTACT_LANGUAGE_INTERPRETER,LANGUAGE_INTERPRETER,1
REG_CONTACT_LANGUAGE_INTERPRETER,INTERPRETER,0
REG_CONTACT_LANGUAGE_INTERPRETER,CHANGE_DATE_TIME,0
REG_CONTACT_LANGUAGE_INTERPRETER,CHANGE_UID,0
REG_CONTACT_PHONE,DISTRICT,1
REG_CONTACT_PHONE,CONTACT_ID,1
REG_CONTACT_PHONE,PHONE_TYPE,1
REG_CONTACT_PHONE,PHONE_LISTING,0
REG_CONTACT_PHONE,PHONE,0
REG_CONTACT_PHONE,PHONE_EXTENSION,0
REG_CONTACT_PHONE,SIF_REFID,0
REG_CONTACT_PHONE,PHONE_PRIORITY,0
REG_CONTACT_PHONE,CHANGE_DATE_TIME,0
REG_CONTACT_PHONE,CHANGE_UID,0
REG_CYCLE,DISTRICT,1
REG_CYCLE,SCHOOL_YEAR,1
REG_CYCLE,SUMMER_SCHOOL,1
REG_CYCLE,BUILDING,1
REG_CYCLE,CYCLE_ORDER,0
REG_CYCLE,CODE,1
REG_CYCLE,DESCRIPTION,0
REG_CYCLE,ALTERNATE_CYCLE,0
REG_CYCLE,CHANGE_DATE_TIME,0
REG_CYCLE,CHANGE_UID,0
REG_DISABILITY,DISTRICT,1
REG_DISABILITY,STUDENT_ID,1
REG_DISABILITY,DISABILITY,1
REG_DISABILITY,SEQUENCE_NUM,1
REG_DISABILITY,DISABILITY_ORDER,0
REG_DISABILITY,START_DATE,0
REG_DISABILITY,END_DATE,0
REG_DISABILITY,CHANGE_DATE_TIME,0
REG_DISABILITY,CHANGE_UID,0
REG_DISTRICT,DISTRICT,1
REG_DISTRICT,NAME,0
REG_DISTRICT,VALIDATION_ONLY,0
REG_DISTRICT,SCHOOL_YEAR,0
REG_DISTRICT,SUMMER_SCHOOL_YEAR,0
REG_DISTRICT,ADDRESS_FORMAT,0
REG_DISTRICT,STREET1,0
REG_DISTRICT,STREET2,0
REG_DISTRICT,CITY,0
REG_DISTRICT,STATE,0
REG_DISTRICT,ZIP,0
REG_DISTRICT,PHONE,0
REG_DISTRICT,SUPERINTENDENT,0
REG_DISTRICT,EMAIL,0
REG_DISTRICT,ALPHANUMERIC_IDS,0
REG_DISTRICT,STUDENT_ID_LENGTH,0
REG_DISTRICT,ZERO_FILL_IDS,0
REG_DISTRICT,AUTO_ASSIGN,0
REG_DISTRICT,OVERIDE_AUTO_ASSGN,0
REG_DISTRICT,STARTING_ID,0
REG_DISTRICT,HIGHEST_ID_USED,0
REG_DISTRICT,SHOW_SSN,0
REG_DISTRICT,TRANSPORT_STUDENT,0
REG_DISTRICT,ST_ID_REQUIRED,0
REG_DISTRICT,ST_ID_LABEL,0
REG_DISTRICT,ST_ID_LENGTH,0
REG_DISTRICT,ST_ID_ENFORCE_LEN,0
REG_DISTRICT,CHANGE_ID_IN_PRIOR,0
REG_DISTRICT,ID_ON_STATE_REPORT,0
REG_DISTRICT,ST_AUTO_ASSIGN,0
REG_DISTRICT,ST_ID_PREFIX,0
REG_DISTRICT,ST_STARTING_ID,0
REG_DISTRICT,ST_MAX_ID_ALLOWED,0
REG_DISTRICT,ST_HIGHEST_ID_USED,0
REG_DISTRICT,ST_ID_INCLUDE,0
REG_DISTRICT,ST_AUTO_ASSIGN_OV,0
REG_DISTRICT,FMS_DEPARTMENT,0
REG_DISTRICT,FMS_HOME_ORGN,0
REG_DISTRICT,FMS_PROGRAM,0
REG_DISTRICT,AGGREGATE,0
REG_DISTRICT,LIST_MAX,0
REG_DISTRICT,ETHNICITY_REQUIRED,0
REG_DISTRICT,USE_ETHNIC_PERCENT,0
REG_DISTRICT,USE_DIS_DATES,0
REG_DISTRICT,USE_ALERT_DATES,0
REG_DISTRICT,STATE_CODE_EQUIV,0
REG_DISTRICT,AUDIT_UPDATES,0
REG_DISTRICT,AUDIT_DELETE_ONLY,0
REG_DISTRICT,AUDIT_CLEAR_INT,0
REG_DISTRICT,LANGUAGE_REQUIRED,0
REG_DISTRICT,SPECIAL_ED_TABLE,0
REG_DISTRICT,SPECIAL_ED_SCR_NUM,0
REG_DISTRICT,SPECIAL_ED_COLUMN,0
REG_DISTRICT,IEPPLUS_INTEGRATION,0
REG_DISTRICT,PARAM_KEY,0
REG_DISTRICT,CRN_FROM_TAC,0
REG_DISTRICT,SHOW_RES_BLDG,0
REG_DISTRICT,ALT_ATTENDANCE_AGE,0
REG_DISTRICT,ALT_ATT_GRADES,0
REG_DISTRICT,CUTOFF_DATE,0
REG_DISTRICT,EW_MEMBERSHIP,0
REG_DISTRICT,ROLL_ENTRY_RULE,0
REG_DISTRICT,ROLL_WD_RULE,0
REG_DISTRICT,USE_RANK_CLASS_SIZE_EXCLUDE,0
REG_DISTRICT,INCLUDE_IEP,0
REG_DISTRICT,INCLUDE_GIFTED,0
REG_DISTRICT,INCLUDE_504,0
REG_DISTRICT,MIN_AGE_CITATION,0
REG_DISTRICT,LOCKOUT_USERS,0
REG_DISTRICT,DISABLE_SCHEDULED_TASKS,0
REG_DISTRICT,FIRSTWAVE_ID,0
REG_DISTRICT,SHOW_USERVOICE,0
REG_DISTRICT,EMAIL_DELIMITER,0
REG_DISTRICT,ALLOW_USERS_TO_SET_THEMES,0
REG_DISTRICT,AUTO_GENERATE_FAMILY_NUMBER,0
REG_DISTRICT,LOG_HAC_LOGINS,0
REG_DISTRICT,LOG_TAC_LOGINS,0
REG_DISTRICT,LOG_TAC_PUBLISH_EVENTS,0
REG_DISTRICT,MULTIPLE_CLASSIFICATIONS,0
REG_DISTRICT,CURRENT_KEY,0
REG_DISTRICT,PREVIOUS_KEY,0
REG_DISTRICT,COMPROMISED,0
REG_DISTRICT,CHANGE_DATE_TIME,0
REG_DISTRICT,CHANGE_UID,0
REG_DISTRICT,HIDE_GENDER_IDENTITY,0
REG_DISTRICT,HOME_PHONE_TYPE,0
REG_DISTRICT,MOBILE_PHONE_TYPE,0
REG_DISTRICT,GAINSIGHTS_ENABLED,0
REG_DISTRICT,ALLOW_MULTIPLE_STUDENT_EMAIL,0
REG_DISTRICT,ALLOW_MULTIPLE_CONTACT_EMAIL,0
REG_DISTRICT,ADDITIONAL_GENDERS,0
REG_DISTRICT_ATTACHMENT,DISTRICT,1
REG_DISTRICT_ATTACHMENT,ALLOW_ATTACHMENTS,0
REG_DISTRICT_ATTACHMENT,MAX_FILES,0
REG_DISTRICT_ATTACHMENT,MAX_KB_SIZE,0
REG_DISTRICT_ATTACHMENT,ATTACHMENT_FILE_TYPES,0
REG_DISTRICT_ATTACHMENT,CHANGE_DATE_TIME,0
REG_DISTRICT_ATTACHMENT,CHANGE_UID,0
REG_DISTRICT_SMTP,DISTRICT,1
REG_DISTRICT_SMTP,USE_LOCALHOST,0
REG_DISTRICT_SMTP,SERVER_ADDRESS,0
REG_DISTRICT_SMTP,SERVER_PORT,0
REG_DISTRICT_SMTP,USE_SSL,0
REG_DISTRICT_SMTP,LOGIN_ID,0
REG_DISTRICT_SMTP,LOGIN_DOMAIN,0
REG_DISTRICT_SMTP,PASSWORD,0
REG_DISTRICT_SMTP,USE_GENERIC_FROM,0
REG_DISTRICT_SMTP,GENERIC_FROM_ADDRESS,0
REG_DISTRICT_SMTP,GENERIC_FROM_NAME,0
REG_DISTRICT_SMTP,GENERIC_REPLY_ALLOWED,0
REG_DISTRICT_SMTP,CHANGE_DATE_TIME,0
REG_DISTRICT_SMTP,CHANGE_UID,0
REG_DURATION,DISTRICT,1
REG_DURATION,SCHOOL_YEAR,1
REG_DURATION,BUILDING,1
REG_DURATION,CODE,1
REG_DURATION,DESCRIPTION,0
REG_DURATION,SUMMER_SCHOOL,0
REG_DURATION,NUMBER_WEEKS,0
REG_DURATION,NUMBER_IN_YEAR,0
REG_DURATION,CHANGE_DATE_TIME,0
REG_DURATION,CHANGE_UID,0
REG_EMERGENCY,DISTRICT,1
REG_EMERGENCY,STUDENT_ID,1
REG_EMERGENCY,DOCTOR_NAME,0
REG_EMERGENCY,DOCTOR_PHONE,0
REG_EMERGENCY,DOCTOR_EXTENSION,0
REG_EMERGENCY,HOSPITAL_CODE,0
REG_EMERGENCY,INSURANCE_COMPANY,0
REG_EMERGENCY,INSURANCE_ID,0
REG_EMERGENCY,INSURANCE_GROUP,0
REG_EMERGENCY,INSURANCE_GRP_NAME,0
REG_EMERGENCY,INSURANCE_SUBSCR,0
REG_EMERGENCY,CHANGE_DATE_TIME,0
REG_EMERGENCY,CHANGE_UID,0
REG_EMERGENCY,DENTIST,0
REG_EMERGENCY,DENTIST_PHONE,0
REG_EMERGENCY,DENTIST_EXT,0
REG_EMERGENCY,MEDICAL_SPECIALIST,0
REG_EMERGENCY,MEDICAL_SPECIALIST_PHONE,0
REG_EMERGENCY,MEDICAL_SPECIALIST_EXT,0
REG_ENTRY_WITH,DISTRICT,1
REG_ENTRY_WITH,STUDENT_ID,1
REG_ENTRY_WITH,ENTRY_WD_TYPE,1
REG_ENTRY_WITH,SCHOOL_YEAR,1
REG_ENTRY_WITH,ENTRY_DATE,1
REG_ENTRY_WITH,ENTRY_CODE,0
REG_ENTRY_WITH,BUILDING,0
REG_ENTRY_WITH,GRADE,0
REG_ENTRY_WITH,TRACK,0
REG_ENTRY_WITH,CALENDAR,0
REG_ENTRY_WITH,WITHDRAWAL_DATE,0
REG_ENTRY_WITH,WITHDRAWAL_CODE,0
REG_ENTRY_WITH,COMMENTS,0
REG_ENTRY_WITH,ROW_IDENTITY,0
REG_ENTRY_WITH,CHANGE_DATE_TIME,0
REG_ENTRY_WITH,CHANGE_UID,0
REG_ETHNICITY,DISTRICT,1
REG_ETHNICITY,STUDENT_ID,1
REG_ETHNICITY,ETHNIC_CODE,1
REG_ETHNICITY,ETHNICITY_ORDER,0
REG_ETHNICITY,PERCENTAGE,0
REG_ETHNICITY,CHANGE_DATE_TIME,0
REG_ETHNICITY,CHANGE_UID,0
REG_EVENT,DISTRICT,1
REG_EVENT,EVENT_ID,1
REG_EVENT,PUBLISH_EVENT,0
REG_EVENT,SUBJECT,0
REG_EVENT,MESSAGE_BODY,0
REG_EVENT,START_DATE_TIME,0
REG_EVENT,END_DATE_TIME,0
REG_EVENT,ALL_DAY_EVENT,0
REG_EVENT,LOCATION,0
REG_EVENT,CHANGE_DATE_TIME,0
REG_EVENT,CHANGE_UID,0
REG_EVENT_ACTIVITY,DISTRICT,1
REG_EVENT_ACTIVITY,SCHOOL_YEAR,1
REG_EVENT_ACTIVITY,BUILDING,1
REG_EVENT_ACTIVITY,ACTIVITY_CODE,1
REG_EVENT_ACTIVITY,EVENT_ID,1
REG_EVENT_ACTIVITY,CHANGE_DATE_TIME,0
REG_EVENT_ACTIVITY,CHANGE_UID,0
REG_EVENT_COMP,DISTRICT,1
REG_EVENT_COMP,BUILDING,1
REG_EVENT_COMP,COMPETENCY_GROUP,1
REG_EVENT_COMP,STAFF_ID,1
REG_EVENT_COMP,EVENT_ID,1
REG_EVENT_COMP,CHANGE_DATE_TIME,0
REG_EVENT_COMP,CHANGE_UID,0
REG_EVENT_HRM,DISTRICT,1
REG_EVENT_HRM,BUILDING,1
REG_EVENT_HRM,ROOM_ID,1
REG_EVENT_HRM,EVENT_ID,1
REG_EVENT_HRM,CHANGE_DATE_TIME,0
REG_EVENT_HRM,CHANGE_UID,0
REG_EVENT_MS,DISTRICT,1
REG_EVENT_MS,SECTION_KEY,1
REG_EVENT_MS,COURSE_SESSION,1
REG_EVENT_MS,EVENT_ID,1
REG_EVENT_MS,CHANGE_DATE_TIME,0
REG_EVENT_MS,CHANGE_UID,0
REG_EXCLUDE_HONOR,DISTRICT,1
REG_EXCLUDE_HONOR,STUDENT_ID,1
REG_EXCLUDE_HONOR,HONOR_TYPE,1
REG_EXCLUDE_HONOR,CHANGE_DATE_TIME,0
REG_EXCLUDE_HONOR,CHANGE_UID,0
REG_EXCLUDE_IPR,DISTRICT,1
REG_EXCLUDE_IPR,STUDENT_ID,1
REG_EXCLUDE_IPR,ELIG_TYPE,1
REG_EXCLUDE_IPR,CHANGE_DATE_TIME,0
REG_EXCLUDE_IPR,CHANGE_UID,0
REG_EXCLUDE_RANK,DISTRICT,1
REG_EXCLUDE_RANK,STUDENT_ID,1
REG_EXCLUDE_RANK,RANK_TYPE,1
REG_EXCLUDE_RANK,INCLUDE_CLASS_SIZE,0
REG_EXCLUDE_RANK,CHANGE_DATE_TIME,0
REG_EXCLUDE_RANK,CHANGE_UID,0
REG_GEO_CFG,DISTRICT,1
REG_GEO_CFG,USE_GEO_CODE,0
REG_GEO_CFG,USE_ZONES,0
REG_GEO_CFG,SHARE_PLANS,0
REG_GEO_CFG,ADDRESS_REQUIRED,0
REG_GEO_CFG,ALLOW_OVERLAP,0
REG_GEO_CFG,USE_PREFIX_SUFFIX,0
REG_GEO_CFG,NEXT_ASSIGN_YEAR,0
REG_GEO_CFG,CHANGE_DATE_TIME,0
REG_GEO_CFG,CHANGE_UID,0
REG_GEO_CFG_DATES,DISTRICT,1
REG_GEO_CFG_DATES,USE_DATE_RANGE,0
REG_GEO_CFG_DATES,REQUIRE_OVR_REASON,0
REG_GEO_CFG_DATES,DISPLAY_DATE_MESSAGE,0
REG_GEO_CFG_DATES,CHANGE_DATE_TIME,0
REG_GEO_CFG_DATES,CHANGE_UID,0
REG_GEO_PLAN_AREA,DISTRICT,1
REG_GEO_PLAN_AREA,SCHOOL_YEAR,1
REG_GEO_PLAN_AREA,PLAN_AREA_NUMBER,1
REG_GEO_PLAN_AREA,ZONE_NUMBER,0
REG_GEO_PLAN_AREA,DEVELOPMENT,0
REG_GEO_PLAN_AREA,STREET_PREFIX,0
REG_GEO_PLAN_AREA,STREET_NAME,0
REG_GEO_PLAN_AREA,STREET_TYPE,0
REG_GEO_PLAN_AREA,STREET_SUFFIX,0
REG_GEO_PLAN_AREA,COMPLEX,0
REG_GEO_PLAN_AREA,APARTMENT_REQ,0
REG_GEO_PLAN_AREA,ODD_START_ST_NUM,0
REG_GEO_PLAN_AREA,ODD_END_ST_NUM,0
REG_GEO_PLAN_AREA,EVEN_START_ST_NUM,0
REG_GEO_PLAN_AREA,EVEN_END_ST_NUM,0
REG_GEO_PLAN_AREA,CITY,0
REG_GEO_PLAN_AREA,STATE,0
REG_GEO_PLAN_AREA,ODD_ZIP,0
REG_GEO_PLAN_AREA,ODD_ZIP_PLUS4,0
REG_GEO_PLAN_AREA,EVEN_ZIP,0
REG_GEO_PLAN_AREA,EVEN_ZIP_PLUS4,0
REG_GEO_PLAN_AREA,START_LATITUDE,0
REG_GEO_PLAN_AREA,START_LONGITUDE,0
REG_GEO_PLAN_AREA,END_LATITUDE,0
REG_GEO_PLAN_AREA,END_LONGITUDE,0
REG_GEO_PLAN_AREA,HOME_DISTRICT,0
REG_GEO_PLAN_AREA,EXTERNAL_ID_CODE,0
REG_GEO_PLAN_AREA,CHANGE_DATE_TIME,0
REG_GEO_PLAN_AREA,CHANGE_UID,0
REG_GEO_STU_PLAN,DISTRICT,1
REG_GEO_STU_PLAN,STUDENT_ID,1
REG_GEO_STU_PLAN,PLAN_AREA_NUMBER,0
REG_GEO_STU_PLAN,BUILDING,0
REG_GEO_STU_PLAN,NEXT_BUILDING,0
REG_GEO_STU_PLAN,CHANGE_DATE_TIME,0
REG_GEO_STU_PLAN,CHANGE_UID,0
REG_GEO_ZONE_DATES,DISTRICT,1
REG_GEO_ZONE_DATES,SCHOOL_YEAR,1
REG_GEO_ZONE_DATES,ZONE_NUMBER,1
REG_GEO_ZONE_DATES,BUILDING,1
REG_GEO_ZONE_DATES,HOME_BUILDING_TYPE,1
REG_GEO_ZONE_DATES,GRADE,1
REG_GEO_ZONE_DATES,START_DATE,1
REG_GEO_ZONE_DATES,END_DATE,0
REG_GEO_ZONE_DATES,CHANGE_DATE_TIME,0
REG_GEO_ZONE_DATES,CHANGE_UID,0
REG_GEO_ZONE_DET,DISTRICT,1
REG_GEO_ZONE_DET,SCHOOL_YEAR,1
REG_GEO_ZONE_DET,ZONE_NUMBER,1
REG_GEO_ZONE_DET,BUILDING,1
REG_GEO_ZONE_DET,HOME_BUILDING_TYPE,1
REG_GEO_ZONE_DET,GRADE,1
REG_GEO_ZONE_DET,HOME_BUILDING,0
REG_GEO_ZONE_DET,CHANGE_DATE_TIME,0
REG_GEO_ZONE_DET,CHANGE_UID,0
REG_GEO_ZONE_HDR,DISTRICT,1
REG_GEO_ZONE_HDR,SCHOOL_YEAR,1
REG_GEO_ZONE_HDR,ZONE_NUMBER,1
REG_GEO_ZONE_HDR,DESCRIPTION,0
REG_GEO_ZONE_HDR,CHANGE_DATE_TIME,0
REG_GEO_ZONE_HDR,CHANGE_UID,0
REG_GRADE,DISTRICT,1
REG_GRADE,CODE,1
REG_GRADE,DESCRIPTION,0
REG_GRADE,NEXT_GRADE,0
REG_GRADE,YEARS_TILL_GRAD,0
REG_GRADE,STATE_CODE_EQUIV,0
REG_GRADE,FEDERAL_CODE_EQUIV,0
REG_GRADE,ACTIVE,0
REG_GRADE,SIF_CODE,0
REG_GRADE,SIF2_CODE,0
REG_GRADE,PESC_CODE,0
REG_GRADE,GRADE_ORDER,0
REG_GRADE,GRAD_PLAN_LABEL,0
REG_GRADE,CHANGE_DATE_TIME,0
REG_GRADE,CHANGE_UID,0
REG_GRADE,CEDS_CODE,0
REG_GROUP_HDR,DISTRICT,1
REG_GROUP_HDR,GROUP_CODE,1
REG_GROUP_HDR,DESCRIPTION,0
REG_GROUP_HDR,CHANGE_DATE_TIME,0
REG_GROUP_HDR,CHANGE_UID,0
REG_GROUP_USED_FOR,DISTRICT,1
REG_GROUP_USED_FOR,GROUP_CODE,1
REG_GROUP_USED_FOR,USED_FOR_CODE,1
REG_GROUP_USED_FOR,CHANGE_DATE_TIME,0
REG_GROUP_USED_FOR,CHANGE_UID,0
REG_HISPANIC,DISTRICT,1
REG_HISPANIC,STUDENT_ID,1
REG_HISPANIC,HISPANIC_CODE,1
REG_HISPANIC,CHANGE_DATE_TIME,0
REG_HISPANIC,CHANGE_UID,0
REG_HISTORY_CFG,DISTRICT,1
REG_HISTORY_CFG,USE_ADDRESS_HISTORY,0
REG_HISTORY_CFG,HIST_CONTACT_TYPE,0
REG_HISTORY_CFG,HIST_RELATIONSHIP,0
REG_HISTORY_CFG,HIST_LIVING_WITH,0
REG_HISTORY_CFG,HIST_TRANSPORT_TO,0
REG_HISTORY_CFG,HIST_TRANSPORT_FROM,0
REG_HISTORY_CFG,HIST_DEVELOPMENT,0
REG_HISTORY_CFG,HIST_APARTMENT,0
REG_HISTORY_CFG,HIST_COMPLEX,0
REG_HISTORY_CFG,HIST_STREET_NUMBER,0
REG_HISTORY_CFG,HIST_STREET_PREFIX,0
REG_HISTORY_CFG,HIST_STREET_NAME,0
REG_HISTORY_CFG,HIST_STREET_SUFFIX,0
REG_HISTORY_CFG,HIST_STREET_TYPE,0
REG_HISTORY_CFG,HIST_CITY,0
REG_HISTORY_CFG,HIST_STATE,0
REG_HISTORY_CFG,HIST_ZIP,0
REG_HISTORY_CFG,HIST_DELIVERY_POINT,0
REG_HISTORY_CFG,CHANGE_DATE_TIME,0
REG_HISTORY_CFG,CHANGE_UID,0
REG_HOLD,DISTRICT,1
REG_HOLD,STUDENT_ID,1
REG_HOLD,FIRST_NAME,0
REG_HOLD,MIDDLE_NAME,0
REG_HOLD,LAST_NAME,0
REG_HOLD,GENERATION,0
REG_HOLD,BUILDING,0
REG_HOLD,GRADE,0
REG_HOLD,GENDER,0
REG_HOLD,LANGUAGE,0
REG_HOLD,COUNSELOR,0
REG_HOLD,HOUSE_TEAM,0
REG_HOLD,HOMEROOM_PRIMARY,0
REG_HOLD,HOMEROOM_SECONDARY,0
REG_HOLD,BIRTHDATE,0
REG_HOLD,NICKNAME,0
REG_HOLD,ENTRY_WD_TYPE,1
REG_HOLD,SIF_REFID,0
REG_HOLD,CHANGE_DATE_TIME,0
REG_HOLD,CHANGE_UID,0
reg_hold_calc_detail,DISTRICT,1
reg_hold_calc_detail,STUDENT_ID,1
reg_hold_calc_detail,HOLD_TYPE,1
reg_hold_calc_detail,ITEM_OR_CAT,1
reg_hold_calc_detail,CODE,1
reg_hold_calc_detail,CODE_OR_BALANCE,0
reg_hold_calc_detail,THRESHOLD,0
reg_hold_calc_detail,CHANGE_DATE_TIME,0
reg_hold_calc_detail,CHANGE_UID,0
REG_HOLD_RC_STATUS,DISTRICT,1
REG_HOLD_RC_STATUS,STUDENT_ID,1
REG_HOLD_RC_STATUS,CODE,1
REG_HOLD_RC_STATUS,FREE_TEXT,0
REG_HOLD_RC_STATUS,CALCULATED,0
REG_HOLD_RC_STATUS,CHANGE_DATE_TIME,0
REG_HOLD_RC_STATUS,CHANGE_UID,0
REG_IEP_SETUP,DISTRICT,1
REG_IEP_SETUP,SECURITY_TOKEN,0
REG_IEP_SETUP,CHANGE_DATE_TIME,0
REG_IEP_SETUP,CHANGE_UID,0
REG_IEP_STATUS,ID,1
REG_IEP_STATUS,DISTRICT,0
REG_IEP_STATUS,STUDENT_ID,0
REG_IEP_STATUS,IEPPLUS_ID,0
REG_IEP_STATUS,STATUS_DESCRIPTION,0
REG_IEP_STATUS,START_DATE,0
REG_IEP_STATUS,EXIT_DATE,0
REG_IEP_STATUS,EXIT_REASON,0
REG_IMMUNIZATION,DISTRICT,1
REG_IMMUNIZATION,STUDENT_ID,1
REG_IMMUNIZATION,CODE,1
REG_IMMUNIZATION,STATUS_CODE,0
REG_IMMUNIZATION,CHANGE_DATE_TIME,0
REG_IMMUNIZATION,CHANGE_UID,0
REG_IMPORT,DISTRICT,1
REG_IMPORT,STUDENT_ID,1
REG_IMPORT,FIRST_NAME,0
REG_IMPORT,MIDDLE_NAME,0
REG_IMPORT,LAST_NAME,0
REG_IMPORT,GENERATION,0
REG_IMPORT,STATE_REPORT_ID,0
REG_IMPORT,PRIOR_STATE_ID,0
REG_IMPORT,GENDER,0
REG_IMPORT,ETHNIC_CODE,0
REG_IMPORT,BIRTHDATE,0
REG_IMPORT,LANGUAGE,0
REG_IMPORT,MIGRANT,0
REG_IMPORT,HOMELESS_STATUS,0
REG_IMPORT,CHANGE_DATE_TIME,0
REG_IMPORT,CHANGE_UID,0
REG_IMPORT_CONTACT,DISTRICT,1
REG_IMPORT_CONTACT,STUDENT_ID,1
REG_IMPORT_CONTACT,CONTACT_SEQ,1
REG_IMPORT_CONTACT,FIRST_NAME,0
REG_IMPORT_CONTACT,MIDDLE_NAME,0
REG_IMPORT_CONTACT,LAST_NAME,0
REG_IMPORT_CONTACT,GENERATION,0
REG_IMPORT_CONTACT,CHANGE_DATE_TIME,0
REG_IMPORT_CONTACT,CHANGE_UID,0
REG_IMPORT_PROGRAM,DISTRICT,1
REG_IMPORT_PROGRAM,STUDENT_ID,1
REG_IMPORT_PROGRAM,PROGRAM_NAME,1
REG_IMPORT_PROGRAM,PROGRAM_VALUE,0
REG_IMPORT_PROGRAM,CHANGE_DATE_TIME,0
REG_IMPORT_PROGRAM,CHANGE_UID,0
REG_KEY_CONTACT_ID,DISTRICT,1
REG_KEY_CONTACT_ID,CONTACT_ID,1
REG_KEY_CONTACT_ID,WRAPPED,0
REG_KEY_CONTACT_ID,MAX_VALUE,0
REG_KEY_CONTACT_ID,EXTERNAL_VALUE,0
REG_KEY_CONTACT_ID,LAST_CMD,0
REG_KEY_CONTACT_ID,CMD_VALUE,0
REG_KEY_CONTACT_ID,CMD_DATE_TIME,0
REG_KEY_CONTACT_ID,CMD_UID,0
REG_KEY_CONTACT_ID,CHANGE_DATE_TIME,0
REG_KEY_CONTACT_ID,CHANGE_UID,0
REG_LEGAL_INFO,DISTRICT,1
REG_LEGAL_INFO,STUDENT_ID,1
REG_LEGAL_INFO,LEGAL_FIRST_NAME,0
REG_LEGAL_INFO,LEGAL_MIDDLE_NAME,0
REG_LEGAL_INFO,LEGAL_LAST_NAME,0
REG_LEGAL_INFO,LEGAL_GENERATION,0
REG_LEGAL_INFO,LEGAL_GENDER,0
REG_LEGAL_INFO,CHANGE_REASON,0
REG_LEGAL_INFO,CHANGE_DATE_TIME,0
REG_LEGAL_INFO,CHANGE_UID,0
REG_LOCKER,DISTRICT,1
REG_LOCKER,BUILDING,1
REG_LOCKER,LOCKER_ID,1
REG_LOCKER,LOCKER_DESC,0
REG_LOCKER,SERIAL_NUM,0
REG_LOCKER,LOCATION,0
REG_LOCKER,IS_LOCKED,0
REG_LOCKER,MAX_ASSIGNED,0
REG_LOCKER,HOMEROOM,0
REG_LOCKER,GRADE,0
REG_LOCKER,GENDER,0
REG_LOCKER,HOUSE_TEAM,0
REG_LOCKER,IN_SERVICE,0
REG_LOCKER,CURRENT_COMBO,0
REG_LOCKER,CHANGE_DATE_TIME,0
REG_LOCKER,CHANGE_UID,0
REG_LOCKER_COMBO,DISTRICT,1
REG_LOCKER_COMBO,BUILDING,1
REG_LOCKER_COMBO,LOCKER_ID,1
REG_LOCKER_COMBO,COMBO_SEQUENCE,1
REG_LOCKER_COMBO,COMBINATION,0
REG_LOCKER_COMBO,CHANGE_DATE_TIME,0
REG_LOCKER_COMBO,CHANGE_UID,0
REG_MAP_STU_GEOCODE,DISTRICT,1
REG_MAP_STU_GEOCODE,STUDENT_ID,1
REG_MAP_STU_GEOCODE,LATITUDE,0
REG_MAP_STU_GEOCODE,LONGITUDE,0
REG_MAP_STU_GEOCODE,CHANGE_DATE_TIME,0
REG_MAP_STU_GEOCODE,CHANGE_UID,0
REG_MED_ALERTS,DISTRICT,1
REG_MED_ALERTS,STUDENT_ID,1
REG_MED_ALERTS,MED_ALERT_CODE,1
REG_MED_ALERTS,SEQUENCE_NUM,1
REG_MED_ALERTS,MED_ALERT_COMMENT,0
REG_MED_ALERTS,START_DATE,0
REG_MED_ALERTS,END_DATE,0
REG_MED_ALERTS,ROW_IDENTITY,0
REG_MED_ALERTS,CHANGE_DATE_TIME,0
REG_MED_ALERTS,CHANGE_UID,0
REG_MED_PROCEDURE,DISTRICT,1
REG_MED_PROCEDURE,STUDENT_ID,1
REG_MED_PROCEDURE,CODE,1
REG_MED_PROCEDURE,PROCEDURE_DATE,1
REG_MED_PROCEDURE,STATUS_CODE,0
REG_MED_PROCEDURE,CHANGE_DATE_TIME,0
REG_MED_PROCEDURE,CHANGE_UID,0
REG_MP_DATES,DISTRICT,1
REG_MP_DATES,BUILDING,1
REG_MP_DATES,SCHOOL_YEAR,1
REG_MP_DATES,TRACK,1
REG_MP_DATES,MARKING_PERIOD,1
REG_MP_DATES,START_DATE,0
REG_MP_DATES,END_DATE,0
REG_MP_DATES,ROW_IDENTITY,0
REG_MP_DATES,CHANGE_DATE_TIME,0
REG_MP_DATES,CHANGE_UID,0
REG_MP_WEEKS,DISTRICT,1
REG_MP_WEEKS,BUILDING,1
REG_MP_WEEKS,SCHOOL_YEAR,1
REG_MP_WEEKS,MARKING_PERIOD,1
REG_MP_WEEKS,MP_ORDER,0
REG_MP_WEEKS,DURATION_TYPE,0
REG_MP_WEEKS,DESCRIPTION,0
REG_MP_WEEKS,START_WEEK_NUMBER,0
REG_MP_WEEKS,END_WEEK_NUMBER,0
REG_MP_WEEKS,SCHD_INTERVAL,0
REG_MP_WEEKS,TERM,0
REG_MP_WEEKS,RC_RUN,0
REG_MP_WEEKS,STATE_CODE_EQUIV,0
REG_MP_WEEKS,CHANGE_DATE_TIME,0
REG_MP_WEEKS,CHANGE_UID,0
REG_NEXT_YEAR,DISTRICT,1
REG_NEXT_YEAR,STUDENT_ID,1
REG_NEXT_YEAR,BUILDING,0
REG_NEXT_YEAR,HOME_BUILDING,0
REG_NEXT_YEAR,BUILDING_OVERRIDE,0
REG_NEXT_YEAR,BUILDING_REASON,0
REG_NEXT_YEAR,GRADE,0
REG_NEXT_YEAR,COUNSELOR,0
REG_NEXT_YEAR,HOMEROOM_PRIMARY,0
REG_NEXT_YEAR,HOMEROOM_SECONDARY,0
REG_NEXT_YEAR,HOUSE_TEAM,0
REG_NEXT_YEAR,TRACK,0
REG_NEXT_YEAR,CHANGE_DATE_TIME,0
REG_NEXT_YEAR,CHANGE_UID,0
REG_NOTES,DISTRICT,1
REG_NOTES,STUDENT_ID,1
REG_NOTES,NOTE_TYPE,1
REG_NOTES,ENTRY_DATE_TIME,1
REG_NOTES,ENTRY_UID,0
REG_NOTES,NOTE_TEXT,0
REG_NOTES,SENSITIVE,0
REG_NOTES,PRIVATE_FLAG,0
REG_NOTES,PUBLISH_TO_WEB,0
REG_NOTES,APPOINTMENT_ID,0
REG_NOTES,CHANGE_DATE_TIME,0
REG_NOTES,CHANGE_UID,0
REG_NOTES,STUDENT_ALERT_TYPE,0
REG_PERSONAL,DISTRICT,1
REG_PERSONAL,STUDENT_ID,1
REG_PERSONAL,SSN,0
REG_PERSONAL,BIRTH_CITY,0
REG_PERSONAL,BIRTH_STATE,0
REG_PERSONAL,BIRTH_COUNTRY,0
REG_PERSONAL,MEAL_STATUS,0
REG_PERSONAL,CLASSIFICATION,0
REG_PERSONAL,LOCKER_NUMBER,0
REG_PERSONAL,LOCKER_COMBINATION,0
REG_PERSONAL,COMMENTS,0
REG_PERSONAL,ETHNIC_CODE,0
REG_PERSONAL,HISPANIC,0
REG_PERSONAL,FED_RACE_ETHNIC,0
REG_PERSONAL,RESIDENCY_CODE,0
REG_PERSONAL,STATE_REPORT_ID,0
REG_PERSONAL,PREVIOUS_ID,0
REG_PERSONAL,PREVIOUS_ID_ASOF,0
REG_PERSONAL,SHOW_ALERTS,0
REG_PERSONAL,MIGRANT,0
REG_PERSONAL,AT_RISK,0
REG_PERSONAL,ESL,0
REG_PERSONAL,HAS_IEP,0
REG_PERSONAL,IEP_STATUS,0
REG_PERSONAL,SECTION_504_PLAN,0
REG_PERSONAL,HOMELESS_STATUS,0
REG_PERSONAL,MIGRANT_ID,0
REG_PERSONAL,CITIZEN_STATUS,0
REG_PERSONAL,MOTHER_MAIDEN_NAME,0
REG_PERSONAL,FEE_STATUS,0
REG_PERSONAL,FEE_STATUS_OVR,0
REG_PERSONAL,FEE_BALANCE,0
REG_PERSONAL,FERPA_NAME,0
REG_PERSONAL,FERPA_ADDRESS,0
REG_PERSONAL,FERPA_PHONE,0
REG_PERSONAL,FERPA_PHOTO,0
REG_PERSONAL,TRANSFER_BLDG_FROM,0
REG_PERSONAL,ACADEMIC_DIS,0
REG_PERSONAL,HAS_SSP,0
REG_PERSONAL,IEP_INTEGRATION,0
REG_PERSONAL,FOSTER_CARE,0
REG_PERSONAL,ORIGIN_COUNTRY,0
REG_PERSONAL,ELL_YEARS,0
REG_PERSONAL,IMMIGRANT,0
REG_PERSONAL,AT_RISK_CALC_OVR,0
REG_PERSONAL,AT_RISK_LAST_CALC,0
REG_PERSONAL,PRIVATE_MILITARY,0
REG_PERSONAL,PRIVATE_COLLEGE,0
REG_PERSONAL,PRIVATE_COMPANY,0
REG_PERSONAL,PRIVATE_ORGANIZATIONS,0
REG_PERSONAL,PRIVATE_INDIVIDUAL,0
REG_PERSONAL,CHANGE_DATE_TIME,0
REG_PERSONAL,CHANGE_UID,0
REG_PHONE_HIST,DISTRICT,1
REG_PHONE_HIST,CONTACT_ID,1
REG_PHONE_HIST,PHONE_TYPE,1
REG_PHONE_HIST,STUDENT_ID,1
REG_PHONE_HIST,ADDRESS_TYPE,1
REG_PHONE_HIST,PHONE_LISTING,0
REG_PHONE_HIST,PHONE,0
REG_PHONE_HIST,PHONE_EXTENSION,0
REG_PHONE_HIST,CHANGE_DATE_TIME,1
REG_PHONE_HIST,CHANGE_UID,0
REG_PHONE_HISTORY_CFG,DISTRICT,1
REG_PHONE_HISTORY_CFG,USE_PHONE_HISTORY,0
REG_PHONE_HISTORY_CFG,HIST_STU_NUMBER,0
REG_PHONE_HISTORY_CFG,HIST_STU_EXT,0
REG_PHONE_HISTORY_CFG,HIST_STU_LISTING,0
REG_PHONE_HISTORY_CFG,HIST_CONTACT_NUM,0
REG_PHONE_HISTORY_CFG,HIST_CONTACT_EXT,0
REG_PHONE_HISTORY_CFG,HIST_CONTACT_LISTING,0
REG_PHONE_HISTORY_CFG,CHANGE_DATE_TIME,0
REG_PHONE_HISTORY_CFG,CHANGE_UID,0
REG_PROG_SETUP_BLD,DISTRICT,1
REG_PROG_SETUP_BLD,PROGRAM_ID,1
REG_PROG_SETUP_BLD,BUILDING,1
REG_PROG_SETUP_BLD,CHANGE_DATE_TIME,0
REG_PROG_SETUP_BLD,CHANGE_UID,0
REG_PROGRAM_COLUMN,DISTRICT,1
REG_PROGRAM_COLUMN,PROGRAM_ID,1
REG_PROGRAM_COLUMN,FIELD_NUMBER,1
REG_PROGRAM_COLUMN,FIELD_ORDER,0
REG_PROGRAM_COLUMN,FIELD_LEVEL,0
REG_PROGRAM_COLUMN,TABLE_NAME,0
REG_PROGRAM_COLUMN,SCREEN_NUMBER,0
REG_PROGRAM_COLUMN,COLUMN_NAME,0
REG_PROGRAM_COLUMN,LINK_DATES_TO,0
REG_PROGRAM_COLUMN,LINK_TYPE,0
REG_PROGRAM_COLUMN,LABEL,0
REG_PROGRAM_COLUMN,SCREEN_TYPE,0
REG_PROGRAM_COLUMN,DATA_TYPE,0
REG_PROGRAM_COLUMN,DATA_SIZE,0
REG_PROGRAM_COLUMN,ADD_DEFAULT,0
REG_PROGRAM_COLUMN,VALIDATION_LIST,0
REG_PROGRAM_COLUMN,VALIDATION_TABLE,0
REG_PROGRAM_COLUMN,CODE_COLUMN,0
REG_PROGRAM_COLUMN,DESCRIPTION_COLUMN,0
REG_PROGRAM_COLUMN,STATE_CODE_EQUIV,0
REG_PROGRAM_COLUMN,USE_REASONS,0
REG_PROGRAM_COLUMN,USE_OVERRIDE,0
REG_PROGRAM_COLUMN,YREND_INACTIVES,0
REG_PROGRAM_COLUMN,INACTIVE_SRC_RESET,0
REG_PROGRAM_COLUMN,INACTIVE_WD_CODE,0
REG_PROGRAM_COLUMN,YREND_ACTIVES,0
REG_PROGRAM_COLUMN,ACTIVE_SRC_RESET,0
REG_PROGRAM_COLUMN,ACTIVE_WD_CODE,0
REG_PROGRAM_COLUMN,YREND_ENTRY_DATE,0
REG_PROGRAM_COLUMN,YREND_ACTPRES,0
REG_PROGRAM_COLUMN,SEC_PACKAGE,0
REG_PROGRAM_COLUMN,SEC_SUBPACKAGE,0
REG_PROGRAM_COLUMN,SEC_FEATURE,0
REG_PROGRAM_COLUMN,YREND_LOCKED,0
REG_PROGRAM_COLUMN,CHANGE_DATE_TIME,0
REG_PROGRAM_COLUMN,CHANGE_UID,0
REG_PROGRAM_COLUMN,ROW_IDENTITY,0
REG_PROGRAM_SETUP,DISTRICT,1
REG_PROGRAM_SETUP,PROGRAM_ID,1
REG_PROGRAM_SETUP,DESCRIPTION,0
REG_PROGRAM_SETUP,SEC_PACKAGE,0
REG_PROGRAM_SETUP,SEC_SUBPACKAGE,0
REG_PROGRAM_SETUP,SEC_FEATURE,0
REG_PROGRAM_SETUP,START_DATE,0
REG_PROGRAM_SETUP,END_DATE,0
REG_PROGRAM_SETUP,INSTRUCT_HOURS,0
REG_PROGRAM_SETUP,INSTRUCT_HOUR_UNIT,0
REG_PROGRAM_SETUP,RESERVED,0
REG_PROGRAM_SETUP,RULES_LOCKED,0
REG_PROGRAM_SETUP,CHANGE_DATE_TIME,0
REG_PROGRAM_SETUP,CHANGE_UID,0
REG_PROGRAM_SETUP,ROW_IDENTITY,0
REG_PROGRAM_USER,DISTRICT,1
REG_PROGRAM_USER,PROGRAM_ID,1
REG_PROGRAM_USER,SCREEN_NUMBER,1
REG_PROGRAM_USER,FIELD_NUMBER,1
REG_PROGRAM_USER,LIST_SEQUENCE,1
REG_PROGRAM_USER,FIELD_VALUE,0
REG_PROGRAM_USER,CHANGE_DATE_TIME,0
REG_PROGRAM_USER,CHANGE_UID,0
REG_PROGRAM_USER,ROW_IDENTITY,0
REG_PROGRAMS,DISTRICT,1
REG_PROGRAMS,PROGRAM_ID,1
REG_PROGRAMS,FIELD_NUMBER,1
REG_PROGRAMS,STUDENT_ID,1
REG_PROGRAMS,START_DATE,1
REG_PROGRAMS,SUMMER_SCHOOL,1
REG_PROGRAMS,ENTRY_REASON,0
REG_PROGRAMS,PROGRAM_VALUE,0
REG_PROGRAMS,END_DATE,0
REG_PROGRAMS,WITHDRAWAL_REASON,0
REG_PROGRAMS,PROGRAM_OVERRIDE,0
REG_PROGRAMS,CHANGE_DATE_TIME,0
REG_PROGRAMS,CHANGE_UID,0
REG_PROGRAMS,ROW_IDENTITY,0
REG_PRT_FLG_DFLT,DISTRICT,1
REG_PRT_FLG_DFLT,CONTACT_TYPE,1
REG_PRT_FLG_DFLT,MAIL_ATT,0
REG_PRT_FLG_DFLT,MAIL_DISC,0
REG_PRT_FLG_DFLT,MAIL_FEES,0
REG_PRT_FLG_DFLT,MAIL_IPR,0
REG_PRT_FLG_DFLT,MAIL_MED,0
REG_PRT_FLG_DFLT,MAIL_RC,0
REG_PRT_FLG_DFLT,MAIL_REG,0
REG_PRT_FLG_DFLT,MAIL_SCHD,0
REG_PRT_FLG_DFLT,MAIL_SSP,0
REG_PRT_FLG_DFLT,CHANGE_DATE_TIME,0
REG_PRT_FLG_DFLT,CHANGE_UID,0
REG_ROOM,DISTRICT,1
REG_ROOM,BUILDING,1
REG_ROOM,ROOM_ID,1
REG_ROOM,DESCRIPTION,0
REG_ROOM,ROOM_TYPE,0
REG_ROOM,MAX_STUDENTS,0
REG_ROOM,ROOM_AVAILABLE,0
REG_ROOM,HANDICAPPED_ACCESS,0
REG_ROOM,COMPUTERS_COUNT,0
REG_ROOM,PHONE,0
REG_ROOM,PHONE_EXTENSION,0
REG_ROOM,COMMENTS,0
REG_ROOM,GROUP_CODE,0
REG_ROOM,REGULAR_YEAR,0
REG_ROOM,SUMMER_SCHOOL,0
REG_ROOM,STATE_CODE_EQUIV,0
REG_ROOM,ROW_IDENTITY,0
REG_ROOM,CHANGE_DATE_TIME,0
REG_ROOM,CHANGE_UID,0
REG_ROOM_AIN,DISTRICT,1
REG_ROOM_AIN,BUILDING,1
REG_ROOM_AIN,ROOM_ID,1
REG_ROOM_AIN,IS_HRM_SCHD_PRIMARY_HOMEROOM,0
REG_ROOM_AIN,CHANGE_DATE_TIME,0
REG_ROOM_AIN,CHANGE_UID,0
REG_STAFF,DISTRICT,1
REG_STAFF,STAFF_ID,1
REG_STAFF,FIRST_NAME,0
REG_STAFF,MIDDLE_NAME,0
REG_STAFF,LAST_NAME,0
REG_STAFF,MAIDEN_NAME,0
REG_STAFF,TITLE_CODE,0
REG_STAFF,EMAIL,0
REG_STAFF,SSN,0
REG_STAFF,FMS_DEPARTMENT,0
REG_STAFF,FMS_EMPL_NUMBER,0
REG_STAFF,FMS_LOCATION,0
REG_STAFF,TEACHER_LOAD,0
REG_STAFF,LOGIN_ID,0
REG_STAFF,SUB_LOGIN_ID,0
REG_STAFF,SUB_EXPIRATION,0
REG_STAFF,GENDER,0
REG_STAFF,PRIM_ETHNIC_CODE,0
REG_STAFF,HISPANIC,0
REG_STAFF,FED_RACE_ETHNIC,0
REG_STAFF,BIRTHDATE,0
REG_STAFF,STAFF_STATE_ID,0
REG_STAFF,ESP_LOGIN_ID,0
REG_STAFF,ROW_IDENTITY,0
REG_STAFF,CHANGE_DATE_TIME,0
REG_STAFF,CHANGE_UID,0
REG_STAFF,GENDER_IDENTITY,0
REG_STAFF,CLASSLINK_ID,0
REG_STAFF,UNIQUE_REG_STAFF_ID,0
REG_STAFF_ADDRESS,DISTRICT,1
REG_STAFF_ADDRESS,STAFF_ID,1
REG_STAFF_ADDRESS,APARTMENT,0
REG_STAFF_ADDRESS,COMPLEX,0
REG_STAFF_ADDRESS,STREET_NUMBER,0
REG_STAFF_ADDRESS,STREET_PREFIX,0
REG_STAFF_ADDRESS,STREET_NAME,0
REG_STAFF_ADDRESS,STREET_SUFFIX,0
REG_STAFF_ADDRESS,STREET_TYPE,0
REG_STAFF_ADDRESS,CITY,0
REG_STAFF_ADDRESS,STATE,0
REG_STAFF_ADDRESS,ZIP,0
REG_STAFF_ADDRESS,DELIVERY_POINT,0
REG_STAFF_ADDRESS,CHANGE_DATE_TIME,0
REG_STAFF_ADDRESS,CHANGE_UID,0
REG_STAFF_BLDGS,DISTRICT,1
REG_STAFF_BLDGS,BUILDING,1
REG_STAFF_BLDGS,STAFF_ID,1
REG_STAFF_BLDGS,STAFF_NAME,0
REG_STAFF_BLDGS,INITIALS,0
REG_STAFF_BLDGS,IS_COUNSELOR,0
REG_STAFF_BLDGS,IS_TEACHER,0
REG_STAFF_BLDGS,IS_ADVISOR,0
REG_STAFF_BLDGS,HOMEROOM_PRIMARY,0
REG_STAFF_BLDGS,HOMEROOM_SECONDARY,0
REG_STAFF_BLDGS,ROOM,0
REG_STAFF_BLDGS,HOUSE_TEAM,0
REG_STAFF_BLDGS,DEPARTMENT,0
REG_STAFF_BLDGS,PHONE,0
REG_STAFF_BLDGS,PHONE_EXTENSION,0
REG_STAFF_BLDGS,ACTIVE,0
REG_STAFF_BLDGS,IS_PRIMARY_BLDG,0
REG_STAFF_BLDGS,GROUP_CODE,0
REG_STAFF_BLDGS,MAXIMUM_CONTIGUOUS,0
REG_STAFF_BLDGS,MAXIMUM_PER_DAY,0
REG_STAFF_BLDGS,ALLOW_OVERRIDE,0
REG_STAFF_BLDGS,REGULAR_YEAR,0
REG_STAFF_BLDGS,SUMMER_SCHOOL,0
REG_STAFF_BLDGS,TAKE_LUNCH_COUNTS,0
REG_STAFF_BLDGS,ROW_IDENTITY,0
REG_STAFF_BLDGS,CHANGE_DATE_TIME,0
REG_STAFF_BLDGS,CHANGE_UID,0
REG_STAFF_BLDGS_ELEM_AIN,DISTRICT,1
REG_STAFF_BLDGS_ELEM_AIN,BUILDING,1
REG_STAFF_BLDGS_ELEM_AIN,STAFF_ID,1
REG_STAFF_BLDGS_ELEM_AIN,ELEM_NEXT_HOMEROOM_PRIMARY,0
REG_STAFF_BLDGS_ELEM_AIN,CHANGE_DATE_TIME,0
REG_STAFF_BLDGS_ELEM_AIN,CHANGE_UID,0
REG_STAFF_BLDGS_HRM_AIN,DISTRICT,1
REG_STAFF_BLDGS_HRM_AIN,BUILDING,1
REG_STAFF_BLDGS_HRM_AIN,STAFF_ID,1
REG_STAFF_BLDGS_HRM_AIN,NEXT_YEAR_PRIMARY_HRM,0
REG_STAFF_BLDGS_HRM_AIN,CHANGE_DATE_TIME,0
REG_STAFF_BLDGS_HRM_AIN,CHANGE_UID,0
REG_STAFF_ETHNIC,DISTRICT,1
REG_STAFF_ETHNIC,STAFF_ID,1
REG_STAFF_ETHNIC,ETHNIC_CODE,1
REG_STAFF_ETHNIC,ETHNICITY_ORDER,0
REG_STAFF_ETHNIC,PERCENTAGE,0
REG_STAFF_ETHNIC,CHANGE_DATE_TIME,0
REG_STAFF_ETHNIC,CHANGE_UID,0
REG_STAFF_HISPANIC,DISTRICT,1
REG_STAFF_HISPANIC,STAFF_ID,1
REG_STAFF_HISPANIC,HISPANIC_CODE,1
REG_STAFF_HISPANIC,CHANGE_DATE_TIME,0
REG_STAFF_HISPANIC,CHANGE_UID,0
REG_STAFF_PHOTO_CFG,DISTRICT,1
REG_STAFF_PHOTO_CFG,PHOTO_PATH,0
REG_STAFF_PHOTO_CFG,PHOTO_DIRECTORY,0
REG_STAFF_PHOTO_CFG,PHOTO_NAME,0
REG_STAFF_PHOTO_CFG,PHOTO_EXTENSION,0
REG_STAFF_PHOTO_CFG,CHANGE_DATE_TIME,0
REG_STAFF_PHOTO_CFG,CHANGE_UID,0
REG_STAFF_QUALIFY,DISTRICT,1
REG_STAFF_QUALIFY,STAFF_ID,1
REG_STAFF_QUALIFY,QUALIFICATION,1
REG_STAFF_QUALIFY,EXPIRATION_DATE,0
REG_STAFF_QUALIFY,CHANGE_DATE_TIME,0
REG_STAFF_QUALIFY,CHANGE_UID,0
REG_STAFF_SIGNATURE,DISTRICT,1
REG_STAFF_SIGNATURE,STAFF_ID,1
REG_STAFF_SIGNATURE,TRANSCRIPT_SIGNATUR,0
REG_STAFF_SIGNATURE,TRANSCRIPT_TITLE,0
REG_STAFF_SIGNATURE,CHANGE_DATE_TIME,0
REG_STAFF_SIGNATURE,CHANGE_UID,0
REG_STAFF_SIGNATURE_CFG,DISTRICT,1
REG_STAFF_SIGNATURE_CFG,SIGNATURE_PATH,0
REG_STAFF_SIGNATURE_CFG,SIGNATURE_DIRECTOR,0
REG_STAFF_SIGNATURE_CFG,SIGNATURE_NAME,0
REG_STAFF_SIGNATURE_CFG,SIGNATURE_EXTENSIO,0
REG_STAFF_SIGNATURE_CFG,CHANGE_DATE_TIME,0
REG_STAFF_SIGNATURE_CFG,CHANGE_UID,0
REG_STATE,DISTRICT,1
REG_STATE,CODE,1
REG_STATE,DESCRIPTION,0
REG_STATE,STU_WITHDRAW_RULE,0
REG_STATE,STATE_CODE_EQUIV,0
REG_STATE,ACTIVE,0
REG_STATE,CHANGE_DATE_TIME,0
REG_STATE,CHANGE_UID,0
REG_STU_AT_RISK,DISTRICT,1
REG_STU_AT_RISK,STUDENT_ID,1
REG_STU_AT_RISK,FACTOR_CODE,1
REG_STU_AT_RISK,FACTOR_STATUS,0
REG_STU_AT_RISK,STATUS_OVR,0
REG_STU_AT_RISK,CHANGE_DATE_TIME,0
REG_STU_AT_RISK,CHANGE_UID,0
REG_STU_AT_RISK_CALC,DISTRICT,1
REG_STU_AT_RISK_CALC,STUDENT_ID,1
REG_STU_AT_RISK_CALC,LTDB_CALC_DATE,0
REG_STU_AT_RISK_CALC,ATT_CALC_DATE,0
REG_STU_AT_RISK_CALC,REG_CALC_DATE,0
REG_STU_AT_RISK_CALC,MR_CALC_DATE,0
REG_STU_AT_RISK_CALC,DISC_CALC_DATE,0
REG_STU_AT_RISK_CALC,IPR_CALC_DATE,0
REG_STU_AT_RISK_CALC,CHANGE_DATE_TIME,0
REG_STU_AT_RISK_CALC,CHANGE_UID,0
REG_STU_CONT_HIST,DISTRICT,1
REG_STU_CONT_HIST,STUDENT_ID,1
REG_STU_CONT_HIST,CONTACT_ID,1
REG_STU_CONT_HIST,CONTACT_TYPE,1
REG_STU_CONT_HIST,RELATION_CODE,0
REG_STU_CONT_HIST,LIVING_WITH,1
REG_STU_CONT_HIST,TRANSPORT_TO,1
REG_STU_CONT_HIST,TRANSPORT_FROM,1
REG_STU_CONT_HIST,CHANGE_DATE_TIME,1
REG_STU_CONT_HIST,CHANGE_UID,1
REG_STU_CONTACT,DISTRICT,1
REG_STU_CONTACT,STUDENT_ID,1
REG_STU_CONTACT,CONTACT_ID,1
REG_STU_CONTACT,CONTACT_TYPE,1
REG_STU_CONTACT,CONTACT_PRIORITY,0
REG_STU_CONTACT,RELATION_CODE,0
REG_STU_CONTACT,LIVING_WITH,0
REG_STU_CONTACT,WEB_ACCESS,0
REG_STU_CONTACT,COMMENTS,0
REG_STU_CONTACT,TRANSPORT_TO,0
REG_STU_CONTACT,TRANSPORT_FROM,0
REG_STU_CONTACT,MAIL_ATT,0
REG_STU_CONTACT,MAIL_DISC,0
REG_STU_CONTACT,MAIL_FEES,0
REG_STU_CONTACT,MAIL_IPR,0
REG_STU_CONTACT,MAIL_MED,0
REG_STU_CONTACT,MAIL_RC,0
REG_STU_CONTACT,MAIL_REG,0
REG_STU_CONTACT,MAIL_SCHD,0
REG_STU_CONTACT,MAIL_SSP,0
REG_STU_CONTACT,LEGAL_GUARD,0
REG_STU_CONTACT,CUST_GUARD,0
REG_STU_CONTACT,UPD_STU_EO_INFO,0
REG_STU_CONTACT,ROW_IDENTITY,0
REG_STU_CONTACT,CHANGE_DATE_TIME,0
REG_STU_CONTACT,CHANGE_UID,0
REG_STU_CONTACT_ALERT,DISTRICT,1
REG_STU_CONTACT_ALERT,STUDENT_ID,1
REG_STU_CONTACT_ALERT,CONTACT_ID,1
REG_STU_CONTACT_ALERT,ALERT_TYPE,1
REG_STU_CONTACT_ALERT,SIGNUP_DATE,0
REG_STU_CONTACT_ALERT,LAST_ALERT_DATE,0
REG_STU_CONTACT_ALERT,NEXT_ALERT_DATE,0
REG_STU_CONTACT_ALERT,SCHEDULE_TYPE,0
REG_STU_CONTACT_ALERT,SCHD_INTERVAL,0
REG_STU_CONTACT_ALERT,SCHD_DOW,0
REG_STU_CONTACT_ALERT,NOTIFICATION_TYPE,0
REG_STU_CONTACT_ALERT,CHANGE_DATE_TIME,0
REG_STU_CONTACT_ALERT,CHANGE_UID,0
REG_STU_CONTACT_ALERT_ATT,DISTRICT,1
REG_STU_CONTACT_ALERT_ATT,STUDENT_ID,1
REG_STU_CONTACT_ALERT_ATT,CONTACT_ID,1
REG_STU_CONTACT_ALERT_ATT,ATTENDANCE_CODE,1
REG_STU_CONTACT_ALERT_ATT,CHANGE_DATE_TIME,0
REG_STU_CONTACT_ALERT_ATT,CHANGE_UID,0
REG_STU_CONTACT_ALERT_AVG,DISTRICT,1
REG_STU_CONTACT_ALERT_AVG,STUDENT_ID,1
REG_STU_CONTACT_ALERT_AVG,CONTACT_ID,1
REG_STU_CONTACT_ALERT_AVG,MIN_AVG,0
REG_STU_CONTACT_ALERT_AVG,MAX_AVG,0
REG_STU_CONTACT_ALERT_AVG,CHANGE_DATE_TIME,0
REG_STU_CONTACT_ALERT_AVG,CHANGE_UID,0
REG_STU_CONTACT_ALERT_DISC,DISTRICT,1
REG_STU_CONTACT_ALERT_DISC,STUDENT_ID,1
REG_STU_CONTACT_ALERT_DISC,CONTACT_ID,1
REG_STU_CONTACT_ALERT_DISC,CODE,1
REG_STU_CONTACT_ALERT_DISC,CHANGE_DATE_TIME,0
REG_STU_CONTACT_ALERT_DISC,CHANGE_UID,0
REG_STU_CONTACT_ALERT_GB,DISTRICT,1
REG_STU_CONTACT_ALERT_GB,STUDENT_ID,1
REG_STU_CONTACT_ALERT_GB,CONTACT_ID,1
REG_STU_CONTACT_ALERT_GB,MIN_AVG,0
REG_STU_CONTACT_ALERT_GB,MAX_AVG,0
REG_STU_CONTACT_ALERT_GB,CHANGE_DATE_TIME,0
REG_STU_CONTACT_ALERT_GB,CHANGE_UID,0
REG_SUMMER_SCHOOL,DISTRICT,1
REG_SUMMER_SCHOOL,STUDENT_ID,1
REG_SUMMER_SCHOOL,BUILDING,0
REG_SUMMER_SCHOOL,GRADE,0
REG_SUMMER_SCHOOL,TRACK,0
REG_SUMMER_SCHOOL,CALENDAR,0
REG_SUMMER_SCHOOL,COUNSELOR,0
REG_SUMMER_SCHOOL,HOUSE_TEAM,0
REG_SUMMER_SCHOOL,HOMEROOM_PRIMARY,0
REG_SUMMER_SCHOOL,HOMEROOM_SECONDARY,0
REG_SUMMER_SCHOOL,CHANGE_DATE_TIME,0
REG_SUMMER_SCHOOL,CHANGE_UID,0
REG_SUMMER_SCHOOL,ROW_IDENTITY,0
REG_TRACK,DISTRICT,1
REG_TRACK,SCHOOL_YEAR,1
REG_TRACK,BUILDING,1
REG_TRACK,CODE,1
REG_TRACK,DESCRIPTION,0
REG_TRACK,START_DATE,0
REG_TRACK,END_DATE,0
REG_TRACK,CHANGE_DATE_TIME,0
REG_TRACK,CHANGE_UID,0
REG_TRAVEL,DISTRICT,1
REG_TRAVEL,STUDENT_ID,1
REG_TRAVEL,TRAVEL_DIRECTION,1
REG_TRAVEL,TRAVEL_TRIP,1
REG_TRAVEL,START_DATE,0
REG_TRAVEL,END_DATE,0
REG_TRAVEL,TRAVEL_SEGMENT,1
REG_TRAVEL,SUNDAY,0
REG_TRAVEL,MONDAY,0
REG_TRAVEL,TUESDAY,0
REG_TRAVEL,WEDNESDAY,0
REG_TRAVEL,THURSDAY,0
REG_TRAVEL,FRIDAY,0
REG_TRAVEL,SATURDAY,0
REG_TRAVEL,TRAVEL_TYPE,0
REG_TRAVEL,TRANSPORT_DISTANCE,0
REG_TRAVEL,BUS_NUMBER,0
REG_TRAVEL,BUS_ROUTE,0
REG_TRAVEL,STOP_NUMBER,0
REG_TRAVEL,STOP_TIME,0
REG_TRAVEL,STOP_DESCRIPTION,0
REG_TRAVEL,SHUTTLE_STOP,0
REG_TRAVEL,ROW_IDENTITY,0
REG_TRAVEL,CHANGE_DATE_TIME,0
REG_TRAVEL,CHANGE_UID,0
REG_USER,DISTRICT,1
REG_USER,STUDENT_ID,1
REG_USER,SCREEN_NUMBER,1
REG_USER,FIELD_NUMBER,1
REG_USER,LIST_SEQUENCE,1
REG_USER,FIELD_VALUE,0
REG_USER,ROW_IDENTITY,0
REG_USER,CHANGE_DATE_TIME,0
REG_USER,CHANGE_UID,0
REG_USER_BUILDING,DISTRICT,1
REG_USER_BUILDING,BUILDING,1
REG_USER_BUILDING,SCREEN_NUMBER,1
REG_USER_BUILDING,FIELD_NUMBER,1
REG_USER_BUILDING,LIST_SEQUENCE,1
REG_USER_BUILDING,FIELD_VALUE,0
REG_USER_BUILDING,CHANGE_DATE_TIME,0
REG_USER_BUILDING,CHANGE_UID,0
REG_USER_DISTRICT,DISTRICT,1
REG_USER_DISTRICT,SCREEN_NUMBER,1
REG_USER_DISTRICT,FIELD_NUMBER,1
REG_USER_DISTRICT,LIST_SEQUENCE,1
REG_USER_DISTRICT,FIELD_VALUE,0
REG_USER_DISTRICT,CHANGE_DATE_TIME,0
REG_USER_DISTRICT,CHANGE_UID,0
REG_USER_PLAN_AREA,DISTRICT,1
REG_USER_PLAN_AREA,SCHOOL_YEAR,1
REG_USER_PLAN_AREA,PLAN_AREA_NUMBER,1
REG_USER_PLAN_AREA,SCREEN_NUMBER,1
REG_USER_PLAN_AREA,FIELD_NUMBER,1
REG_USER_PLAN_AREA,FIELD_VALUE,0
REG_USER_PLAN_AREA,CHANGE_DATE_TIME,0
REG_USER_PLAN_AREA,CHANGE_UID,0
REG_USER_STAFF,DISTRICT,1
REG_USER_STAFF,STAFF_ID,1
REG_USER_STAFF,SCREEN_NUMBER,1
REG_USER_STAFF,LIST_SEQUENCE,1
REG_USER_STAFF,FIELD_NUMBER,1
REG_USER_STAFF,FIELD_VALUE,0
REG_USER_STAFF,ROW_IDENTITY,0
REG_USER_STAFF,CHANGE_DATE_TIME,0
REG_USER_STAFF,CHANGE_UID,0
REG_USER_STAFF_BLD,DISTRICT,1
REG_USER_STAFF_BLD,BUILDING,1
REG_USER_STAFF_BLD,STAFF_ID,1
REG_USER_STAFF_BLD,SCREEN_NUMBER,1
REG_USER_STAFF_BLD,LIST_SEQUENCE,1
REG_USER_STAFF_BLD,FIELD_NUMBER,1
REG_USER_STAFF_BLD,FIELD_VALUE,0
REG_USER_STAFF_BLD,CHANGE_DATE_TIME,0
REG_USER_STAFF_BLD,CHANGE_UID,0
REG_YREND_CRITERIA,DISTRICT,1
REG_YREND_CRITERIA,RUN_PROCESS,1
REG_YREND_CRITERIA,CRITERION,1
REG_YREND_CRITERIA,SEQUENCE,0
REG_YREND_CRITERIA,DESCRIPTION,0
REG_YREND_CRITERIA,STUDENT_STATUS,0
REG_YREND_CRITERIA,ROLLOVER_ENTRY,0
REG_YREND_CRITERIA,ROLLOVER_WITH,0
REG_YREND_CRITERIA,CHANGE_DATE_TIME,0
REG_YREND_CRITERIA,CHANGE_UID,0
REG_YREND_RUN,DISTRICT,1
REG_YREND_RUN,RUN_KEY,1
REG_YREND_RUN,SCHOOL_YEAR,0
REG_YREND_RUN,SUMMER_SCHOOL,0
REG_YREND_RUN,RUN_STATUS,0
REG_YREND_RUN,CALENDAR_SELECT,0
REG_YREND_RUN,CRITERIA_SELECT,0
REG_YREND_RUN,PURGE_APPT_DATE,0
REG_YREND_RUN,PURGE_TAC_MSG_DATE,0
REG_YREND_RUN,CHANGE_DATE_TIME,0
REG_YREND_RUN,CHANGE_UID,0
REG_YREND_RUN_CAL,DISTRICT,1
REG_YREND_RUN_CAL,RUN_KEY,1
REG_YREND_RUN_CAL,BUILDING,1
REG_YREND_RUN_CAL,CALENDAR,1
REG_YREND_RUN_CAL,SCHOOL_YEAR,0
REG_YREND_RUN_CAL,CHANGE_DATE_TIME,0
REG_YREND_RUN_CAL,CHANGE_UID,0
REG_YREND_RUN_CRIT,DISTRICT,1
REG_YREND_RUN_CRIT,RUN_KEY,1
REG_YREND_RUN_CRIT,CRITERION,1
REG_YREND_RUN_CRIT,SCHOOL_YEAR,0
REG_YREND_RUN_CRIT,CHANGE_DATE_TIME,0
REG_YREND_RUN_CRIT,CHANGE_UID,0
REG_YREND_SELECT,DISTRICT,1
REG_YREND_SELECT,RUN_PROCESS,1
REG_YREND_SELECT,CRITERION,1
REG_YREND_SELECT,LINE_NUMBER,1
REG_YREND_SELECT,AND_OR_FLAG,0
REG_YREND_SELECT,TABLE_NAME,0
REG_YREND_SELECT,COLUMN_NAME,0
REG_YREND_SELECT,OPERATOR,0
REG_YREND_SELECT,SEARCH_VALUE1,0
REG_YREND_SELECT,SEARCH_VALUE2,0
REG_YREND_SELECT,CHANGE_DATE_TIME,0
REG_YREND_SELECT,CHANGE_UID,0
REG_YREND_STUDENTS,DISTRICT,1
REG_YREND_STUDENTS,STUDENT_ID,1
REG_YREND_STUDENTS,RUN_PROCESS,1
REG_YREND_STUDENTS,SCHOOL_YEAR,0
REG_YREND_STUDENTS,REG_ROLLOVER,0
REG_YREND_STUDENTS,REG_CRITERION,0
REG_YREND_STUDENTS,WAS_PREREG,0
REG_YREND_STUDENTS,CHANGE_DATE_TIME,0
REG_YREND_STUDENTS,CHANGE_UID,0
REG_YREND_UPDATE,DISTRICT,1
REG_YREND_UPDATE,RUN_PROCESS,1
REG_YREND_UPDATE,CRITERION,1
REG_YREND_UPDATE,LINE_NUMBER,1
REG_YREND_UPDATE,TABLE_NAME,0
REG_YREND_UPDATE,COLUMN_NAME,0
REG_YREND_UPDATE,NEW_VALUE,0
REG_YREND_UPDATE,CHANGE_DATE_TIME,0
REG_YREND_UPDATE,CHANGE_UID,0
REGPROG_YREND_RUN,DISTRICT,1
REGPROG_YREND_RUN,SCHOOL_YEAR,1
REGPROG_YREND_RUN,SUMMER_SCHOOL,1
REGPROG_YREND_RUN,RUN_KEY,1
REGPROG_YREND_RUN,RUN_DATE,0
REGPROG_YREND_RUN,RUN_STATUS,0
REGPROG_YREND_RUN,RESTORE_KEY,0
REGPROG_YREND_RUN,CHANGE_DATE_TIME,0
REGPROG_YREND_RUN,CHANGE_UID,0
REGPROG_YREND_TABS,DISTRICT,1
REGPROG_YREND_TABS,SCHOOL_YEAR,1
REGPROG_YREND_TABS,SUMMER_SCHOOL,1
REGPROG_YREND_TABS,RUN_KEY,1
REGPROG_YREND_TABS,TABLE_NAME,1
REGPROG_YREND_TABS,RESTORE_ORDER,0
REGPROG_YREND_TABS,CHANGE_DATE_TIME,0
REGPROG_YREND_TABS,CHANGE_UID,0
REGTB_ACADEMIC_DIS,DISTRICT,1
REGTB_ACADEMIC_DIS,CODE,1
REGTB_ACADEMIC_DIS,DESCRIPTION,0
REGTB_ACADEMIC_DIS,STATE_CODE_EQUIV,0
REGTB_ACADEMIC_DIS,ACTIVE,0
REGTB_ACADEMIC_DIS,CHANGE_DATE_TIME,0
REGTB_ACADEMIC_DIS,CHANGE_UID,0
REGTB_ACCDIST,DISTRICT,1
REGTB_ACCDIST,CODE,1
REGTB_ACCDIST,DESCRIPTION,0
REGTB_ACCDIST,CHANGE_DATE_TIME,0
REGTB_ACCDIST,CHANGE_UID,0
REGTB_ALT_PORTFOLIO,DISTRICT,1
REGTB_ALT_PORTFOLIO,CODE,1
REGTB_ALT_PORTFOLIO,DESCRIPTION,0
REGTB_ALT_PORTFOLIO,STATE_CODE_EQUIV,0
REGTB_ALT_PORTFOLIO,ACTIVE,0
REGTB_ALT_PORTFOLIO,SIF_CODE,0
REGTB_ALT_PORTFOLIO,SIF2_CODE,0
REGTB_ALT_PORTFOLIO,CHANGE_DATE_TIME,0
REGTB_ALT_PORTFOLIO,CHANGE_UID,0
REGTB_APPT_TYPE,DISTRICT,1
REGTB_APPT_TYPE,CODE,1
REGTB_APPT_TYPE,DESCRIPTION,0
REGTB_APPT_TYPE,LINK_PATH,0
REGTB_APPT_TYPE,ACTIVE,0
REGTB_APPT_TYPE,CHANGE_DATE_TIME,0
REGTB_APPT_TYPE,CHANGE_UID,0
REGTB_AR_ACT641,DISTRICT,1
REGTB_AR_ACT641,CODE,1
REGTB_AR_ACT641,DESCRIPTION,0
REGTB_AR_ACT641,STATE_CODE_EQUIV,0
REGTB_AR_ACT641,ACTIVE,0
REGTB_AR_ACT641,CHANGE_DATE_TIME,0
REGTB_AR_ACT641,CHANGE_UID,0
REGTB_AR_ANTICSVCE,DISTRICT,1
REGTB_AR_ANTICSVCE,code,1
REGTB_AR_ANTICSVCE,description,0
REGTB_AR_ANTICSVCE,ACTIVE,0
REGTB_AR_ANTICSVCE,change_date_time,0
REGTB_AR_ANTICSVCE,change_uid,0
REGTB_AR_BARRIER,DISTRICT,1
REGTB_AR_BARRIER,CODE,1
REGTB_AR_BARRIER,DESCRIPTION,0
REGTB_AR_BARRIER,STATE_CODE_EQUIV,0
REGTB_AR_BARRIER,ACTIVE,0
REGTB_AR_BARRIER,CHANGE_DATE_TIME,0
REGTB_AR_BARRIER,CHANGE_UID,0
REGTB_AR_BIRTHVER,DISTRICT,1
REGTB_AR_BIRTHVER,code,1
REGTB_AR_BIRTHVER,description,0
REGTB_AR_BIRTHVER,ACTIVE,0
REGTB_AR_BIRTHVER,change_date_time,0
REGTB_AR_BIRTHVER,change_uid,0
REGTB_AR_CNTYRESID,DISTRICT,1
REGTB_AR_CNTYRESID,code,1
REGTB_AR_CNTYRESID,description,0
REGTB_AR_CNTYRESID,ACTIVE,0
REGTB_AR_CNTYRESID,change_date_time,0
REGTB_AR_CNTYRESID,change_uid,0
REGTB_AR_COOPS,DISTRICT,1
REGTB_AR_COOPS,code,1
REGTB_AR_COOPS,description,0
REGTB_AR_COOPS,ACTIVE,0
REGTB_AR_COOPS,change_date_time,0
REGTB_AR_COOPS,change_uid,0
REGTB_AR_CORECONT,DISTRICT,1
REGTB_AR_CORECONT,CODE,1
REGTB_AR_CORECONT,DESCRIPTION,0
REGTB_AR_CORECONT,STATE_CODE_EQUIV,0
REGTB_AR_CORECONT,ACTIVE,0
REGTB_AR_CORECONT,CHANGE_DATE_TIME,0
REGTB_AR_CORECONT,CHANGE_UID,0
REGTB_AR_DEVICE_ACC,DISTRICT,1
REGTB_AR_DEVICE_ACC,CODE,1
REGTB_AR_DEVICE_ACC,DESCRIPTION,0
REGTB_AR_DEVICE_ACC,STATE_CODE_EQUIV,0
REGTB_AR_DEVICE_ACC,ACTIVE,0
REGTB_AR_DEVICE_ACC,CHANGE_DATE_TIME,0
REGTB_AR_DEVICE_ACC,CHANGE_UID,0
REGTB_AR_ELDPROG,DISTRICT,1
REGTB_AR_ELDPROG,CODE,1
REGTB_AR_ELDPROG,DESCRIPTION,0
REGTB_AR_ELDPROG,STATE_CODE_EQUIV,0
REGTB_AR_ELDPROG,ACTIVE,0
REGTB_AR_ELDPROG,CHANGE_DATE_TIME,0
REGTB_AR_ELDPROG,CHANGE_UID,0
REGTB_AR_ELL_MONI,DISTRICT,1
REGTB_AR_ELL_MONI,code,1
REGTB_AR_ELL_MONI,description,0
REGTB_AR_ELL_MONI,ACTIVE,0
REGTB_AR_ELL_MONI,change_date_time,0
REGTB_AR_ELL_MONI,change_uid,0
REGTB_AR_FACTYPE,DISTRICT,1
REGTB_AR_FACTYPE,code,1
REGTB_AR_FACTYPE,description,0
REGTB_AR_FACTYPE,ACTIVE,0
REGTB_AR_FACTYPE,change_date_time,0
REGTB_AR_FACTYPE,change_uid,0
REGTB_AR_HOMELESS,DISTRICT,1
REGTB_AR_HOMELESS,code,1
REGTB_AR_HOMELESS,description,0
REGTB_AR_HOMELESS,ACTIVE,0
REGTB_AR_HOMELESS,change_date_time,0
REGTB_AR_HOMELESS,change_uid,0
REGTB_AR_IMMSTATUS,district,1
REGTB_AR_IMMSTATUS,code,1
REGTB_AR_IMMSTATUS,description,0
REGTB_AR_IMMSTATUS,ACTIVE,0
REGTB_AR_IMMSTATUS,change_date_time,0
REGTB_AR_IMMSTATUS,change_uid,0
REGTB_AR_INS_CARRI,DISTRICT,1
REGTB_AR_INS_CARRI,code,1
REGTB_AR_INS_CARRI,description,0
REGTB_AR_INS_CARRI,ACTIVE,0
REGTB_AR_INS_CARRI,change_date_time,0
REGTB_AR_INS_CARRI,change_uid,0
REGTB_AR_LEARNDVC,DISTRICT,1
REGTB_AR_LEARNDVC,CODE,1
REGTB_AR_LEARNDVC,DESCRIPTION,0
REGTB_AR_LEARNDVC,STATE_CODE_EQUIV,0
REGTB_AR_LEARNDVC,ACTIVE,0
REGTB_AR_LEARNDVC,CHANGE_DATE_TIME,0
REGTB_AR_LEARNDVC,CHANGE_UID,0
REGTB_AR_MILITARYDEPEND,DISTRICT,1
REGTB_AR_MILITARYDEPEND,CODE,1
REGTB_AR_MILITARYDEPEND,DESCRIPTION,0
REGTB_AR_MILITARYDEPEND,STATE_CODE_EQUIV,0
REGTB_AR_MILITARYDEPEND,ACTIVE,0
REGTB_AR_MILITARYDEPEND,CHANGE_DATE_TIME,0
REGTB_AR_MILITARYDEPEND,CHANGE_UID,0
REGTB_AR_NETPRFRM,DISTRICT,1
REGTB_AR_NETPRFRM,CODE,1
REGTB_AR_NETPRFRM,DESCRIPTION,0
REGTB_AR_NETPRFRM,STATE_CODE_EQUIV,0
REGTB_AR_NETPRFRM,ACTIVE,0
REGTB_AR_NETPRFRM,CHANGE_DATE_TIME,0
REGTB_AR_NETPRFRM,CHANGE_UID,0
REGTB_AR_NETTYPE,DISTRICT,1
REGTB_AR_NETTYPE,CODE,1
REGTB_AR_NETTYPE,DESCRIPTION,0
REGTB_AR_NETTYPE,STATE_CODE_EQUIV,0
REGTB_AR_NETTYPE,ACTIVE,0
REGTB_AR_NETTYPE,CHANGE_DATE_TIME,0
REGTB_AR_NETTYPE,CHANGE_UID,0
REGTB_AR_PRESCHOOL,DISTRICT,1
REGTB_AR_PRESCHOOL,code,1
REGTB_AR_PRESCHOOL,description,0
REGTB_AR_PRESCHOOL,ACTIVE,0
REGTB_AR_PRESCHOOL,change_date_time,0
REGTB_AR_PRESCHOOL,change_uid,0
REGTB_AR_RAEL,DISTRICT,1
REGTB_AR_RAEL,CODE,1
REGTB_AR_RAEL,DESCRIPTION,0
REGTB_AR_RAEL,STATE_EQUIV,0
REGTB_AR_RAEL,ACTIVE,0
REGTB_AR_RAEL,CHANGE_DATE_TIME,0
REGTB_AR_RAEL,CHANGE_UID,0
REGTB_AR_SCH_LEA,DISTRICT,1
REGTB_AR_SCH_LEA,code,1
REGTB_AR_SCH_LEA,description,0
REGTB_AR_SCH_LEA,ACTIVE,0
REGTB_AR_SCH_LEA,change_date_time,0
REGTB_AR_SCH_LEA,change_uid,0
REGTB_AR_SEND_LEA,DISTRICT,1
REGTB_AR_SEND_LEA,code,1
REGTB_AR_SEND_LEA,description,0
REGTB_AR_SEND_LEA,ACTIVE,0
REGTB_AR_SEND_LEA,change_date_time,0
REGTB_AR_SEND_LEA,change_uid,0
REGTB_AR_SHAREDDVC,DISTRICT,1
REGTB_AR_SHAREDDVC,CODE,1
REGTB_AR_SHAREDDVC,DESCRIPTION,0
REGTB_AR_SHAREDDVC,STATE_CODE_EQUIV,0
REGTB_AR_SHAREDDVC,ACTIVE,0
REGTB_AR_SHAREDDVC,CHANGE_DATE_TIME,0
REGTB_AR_SHAREDDVC,CHANGE_UID,0
REGTB_AR_STU_INSTRUCT,DISTRICT,1
REGTB_AR_STU_INSTRUCT,CODE,1
REGTB_AR_STU_INSTRUCT,DESCRIPTION,0
REGTB_AR_STU_INSTRUCT,STATE_CODE_EQUIV,0
REGTB_AR_STU_INSTRUCT,ACTIVE,0
REGTB_AR_STU_INSTRUCT,CHANGE_DATE_TIME,0
REGTB_AR_STU_INSTRUCT,CHANGE_UID,0
REGTB_AR_SUP_SVC,DISTRICT,1
REGTB_AR_SUP_SVC,code,1
REGTB_AR_SUP_SVC,description,0
REGTB_AR_SUP_SVC,ACTIVE,0
REGTB_AR_SUP_SVC,change_date_time,0
REGTB_AR_SUP_SVC,change_uid,0
REGTB_AT_RISK_REASON,DISTRICT,1
REGTB_AT_RISK_REASON,CODE,1
REGTB_AT_RISK_REASON,DESCRIPTION,0
REGTB_AT_RISK_REASON,USE_SSP,0
REGTB_AT_RISK_REASON,USE_AT_RISK,0
REGTB_AT_RISK_REASON,ACTIVE,0
REGTB_AT_RISK_REASON,CHANGE_DATE_TIME,0
REGTB_AT_RISK_REASON,CHANGE_UID,0
REGTB_ATTACHMENT_CATEGORY,DISTRICT,1
REGTB_ATTACHMENT_CATEGORY,ATTACHMENT_CATEGORY,1
REGTB_ATTACHMENT_CATEGORY,DESCRIPTION,0
REGTB_ATTACHMENT_CATEGORY,SEC_PACKAGE,0
REGTB_ATTACHMENT_CATEGORY,SEC_SUBPACKAGE,0
REGTB_ATTACHMENT_CATEGORY,SEC_FEATURE,0
REGTB_ATTACHMENT_CATEGORY,ACTIVE,0
REGTB_ATTACHMENT_CATEGORY,CHANGE_DATE_TIME,0
REGTB_ATTACHMENT_CATEGORY,CHANGE_UID,0
REGTB_BLDG_REASON,DISTRICT,1
REGTB_BLDG_REASON,CODE,1
REGTB_BLDG_REASON,DESCRIPTION,0
REGTB_BLDG_REASON,ACTIVE,0
REGTB_BLDG_REASON,SIF_CODE,0
REGTB_BLDG_REASON,SIF2_CODE,0
REGTB_BLDG_REASON,CHANGE_DATE_TIME,0
REGTB_BLDG_REASON,CHANGE_UID,0
REGTB_BLDG_TYPES,DISTRICT,1
REGTB_BLDG_TYPES,CODE,1
REGTB_BLDG_TYPES,DESCRIPTION,0
REGTB_BLDG_TYPES,STATE_CODE_EQUIV,0
REGTB_BLDG_TYPES,ACTIVE,0
REGTB_BLDG_TYPES,CHANGE_DATE_TIME,0
REGTB_BLDG_TYPES,CHANGE_UID,0
REGTB_CC_BLDG_TYPE,DISTRICT,1
REGTB_CC_BLDG_TYPE,CODE,1
REGTB_CC_BLDG_TYPE,SCHOOL_TYPE,0
REGTB_CC_BLDG_TYPE,CHANGE_DATE_TIME,0
REGTB_CC_BLDG_TYPE,CHANGE_UID,0
REGTB_CC_MARK_TYPE,DISTRICT,1
REGTB_CC_MARK_TYPE,MARK_NO,1
REGTB_CC_MARK_TYPE,MARK_TYPE,0
REGTB_CC_MARK_TYPE,CHANGE_DATE_TIME,0
REGTB_CC_MARK_TYPE,CHANGE_UID,0
REGTB_CITIZENSHIP,DISTRICT,1
REGTB_CITIZENSHIP,CODE,1
REGTB_CITIZENSHIP,DESCRIPTION,0
REGTB_CITIZENSHIP,STATE_CODE_EQUIV,0
REGTB_CITIZENSHIP,ACTIVE,0
REGTB_CITIZENSHIP,CHANGE_DATE_TIME,0
REGTB_CITIZENSHIP,CHANGE_UID,0
REGTB_CLASSIFY,DISTRICT,1
REGTB_CLASSIFY,CODE,1
REGTB_CLASSIFY,DESCRIPTION,0
REGTB_CLASSIFY,SCHEDULING_WEIGHT,0
REGTB_CLASSIFY,STATE_CODE_EQUIV,0
REGTB_CLASSIFY,ACTIVE,0
REGTB_CLASSIFY,CHANGE_DATE_TIME,0
REGTB_CLASSIFY,CHANGE_UID,0
REGTB_COMPLEX,DISTRICT,1
REGTB_COMPLEX,CODE,1
REGTB_COMPLEX,DESCRIPTION,0
REGTB_COMPLEX,TYPE,0
REGTB_COMPLEX,ACTIVE,0
REGTB_COMPLEX,CHANGE_DATE_TIME,0
REGTB_COMPLEX,CHANGE_UID,0
REGTB_COMPLEX_TYPE,DISTRICT,1
REGTB_COMPLEX_TYPE,CODE,1
REGTB_COMPLEX_TYPE,DESCRIPTION,0
REGTB_COMPLEX_TYPE,ACTIVE,0
REGTB_COMPLEX_TYPE,CHANGE_DATE_TIME,0
REGTB_COMPLEX_TYPE,CHANGE_UID,0
REGTB_COUNTRY,DISTRICT,1
REGTB_COUNTRY,CODE,1
REGTB_COUNTRY,DESCRIPTION,0
REGTB_COUNTRY,STATE_CODE_EQUIV,0
REGTB_COUNTRY,ACTIVE,0
REGTB_COUNTRY,CHANGE_DATE_TIME,0
REGTB_COUNTRY,CHANGE_UID,0
REGTB_COUNTY,DISTRICT,1
REGTB_COUNTY,CODE,1
REGTB_COUNTY,DESCRIPTION,0
REGTB_COUNTY,STATE_CODE_EQUIV,0
REGTB_COUNTY,ACTIVE,0
REGTB_COUNTY,CHANGE_DATE_TIME,0
REGTB_COUNTY,CHANGE_UID,0
REGTB_CURR_CODE,DISTRICT,1
REGTB_CURR_CODE,CODE,1
REGTB_CURR_CODE,DESCRIPTION,0
REGTB_CURR_CODE,STATE_CODE_EQUIV,0
REGTB_CURR_CODE,ACTIVE,0
REGTB_CURR_CODE,CHANGE_DATE_TIME,0
REGTB_CURR_CODE,CHANGE_UID,0
REGTB_DAY_TYPE,DISTRICT,1
REGTB_DAY_TYPE,CODE,1
REGTB_DAY_TYPE,DESCRIPTION,0
REGTB_DAY_TYPE,STATE_CODE_EQUIV,0
REGTB_DAY_TYPE,ACTIVE,0
REGTB_DAY_TYPE,CHANGE_DATE_TIME,0
REGTB_DAY_TYPE,CHANGE_UID,0
REGTB_DEPARTMENT,DISTRICT,1
REGTB_DEPARTMENT,CODE,1
REGTB_DEPARTMENT,DESCRIPTION,0
REGTB_DEPARTMENT,DEPT_ORDER,0
REGTB_DEPARTMENT,STATE_CODE_EQUIV,0
REGTB_DEPARTMENT,PERF_PLUS_CODE,0
REGTB_DEPARTMENT,ACTIVE,0
REGTB_DEPARTMENT,SIF_CODE,0
REGTB_DEPARTMENT,SIF2_CODE,0
REGTB_DEPARTMENT,ROW_IDENTITY,0
REGTB_DEPARTMENT,CHANGE_DATE_TIME,0
REGTB_DEPARTMENT,CHANGE_UID,0
REGTB_DIPLOMAS,DISTRICT,1
REGTB_DIPLOMAS,CODE,1
REGTB_DIPLOMAS,DESCRIPTION,0
REGTB_DIPLOMAS,TRANSCRIPT_DESCRIPTION,0
REGTB_DIPLOMAS,STATE_CODE_EQUIV,0
REGTB_DIPLOMAS,ACTIVE,0
REGTB_DIPLOMAS,CHANGE_DATE_TIME,0
REGTB_DIPLOMAS,CHANGE_UID,0
REGTB_DISABILITY,DISTRICT,1
REGTB_DISABILITY,CODE,1
REGTB_DISABILITY,DESCRIPTION,0
REGTB_DISABILITY,STATE_CODE_EQUIV,0
REGTB_DISABILITY,SENSITIVE,0
REGTB_DISABILITY,ACTIVE,0
REGTB_DISABILITY,CHANGE_DATE_TIME,0
REGTB_DISABILITY,CHANGE_UID,0
REGTB_EDU_LEVEL,DISTRICT,1
REGTB_EDU_LEVEL,CODE,1
REGTB_EDU_LEVEL,DESCRIPTION,0
REGTB_EDU_LEVEL,STATE_CODE_EQUIV,0
REGTB_EDU_LEVEL,ACTIVE,0
REGTB_EDU_LEVEL,CHANGE_DATE_TIME,0
REGTB_EDU_LEVEL,CHANGE_UID,0
REGTB_ELIG_REASON,DISTRICT,1
REGTB_ELIG_REASON,CODE,1
REGTB_ELIG_REASON,DESCRIPTION,0
REGTB_ELIG_REASON,PRIORITY,0
REGTB_ELIG_REASON,ELIGIBLE_FLAG,0
REGTB_ELIG_REASON,ACTIVE,0
REGTB_ELIG_REASON,CHANGE_DATE_TIME,0
REGTB_ELIG_REASON,CHANGE_UID,0
REGTB_ELIG_STATUS,DISTRICT,1
REGTB_ELIG_STATUS,CODE,1
REGTB_ELIG_STATUS,DESCRIPTION,0
REGTB_ELIG_STATUS,PRIORITY,0
REGTB_ELIG_STATUS,ELIGIBLE_FLAG,0
REGTB_ELIG_STATUS,ACTIVE,0
REGTB_ELIG_STATUS,CHANGE_DATE_TIME,0
REGTB_ELIG_STATUS,CHANGE_UID,0
REGTB_ENTRY,DISTRICT,1
REGTB_ENTRY,CODE,1
REGTB_ENTRY,DESCRIPTION,0
REGTB_ENTRY,STATE_CODE_EQUIV,0
REGTB_ENTRY,ACTIVE,0
REGTB_ENTRY,SIF_CODE,0
REGTB_ENTRY,SIF2_CODE,0
REGTB_ENTRY,CHANGE_DATE_TIME,0
REGTB_ENTRY,CHANGE_UID,0
REGTB_ETHNICITY,DISTRICT,1
REGTB_ETHNICITY,CODE,1
REGTB_ETHNICITY,DESCRIPTION,0
REGTB_ETHNICITY,STATE_CODE_EQUIV,0
REGTB_ETHNICITY,FEDERAL_CODE_EQUIV,0
REGTB_ETHNICITY,ACTIVE,0
REGTB_ETHNICITY,SIF_CODE,0
REGTB_ETHNICITY,SIF2_CODE,0
REGTB_ETHNICITY,CHANGE_DATE_TIME,0
REGTB_ETHNICITY,CHANGE_UID,0
REGTB_ETHNICITY,PREVIOUSLY_REPORTED_AS,0
REGTB_GENDER,DISTRICT,1
REGTB_GENDER,CODE,1
REGTB_GENDER,DESCRIPTION,0
REGTB_GENDER,STATE_CODE_EQUIV,0
REGTB_GENDER,FEDERAL_CODE_EQUIV,0
REGTB_GENDER,SIF_CODE,0
REGTB_GENDER,SIF2_CODE,0
REGTB_GENDER,ACTIVE,0
REGTB_GENDER,CHANGE_DATE_TIME,0
REGTB_GENDER,CHANGE_UID,0
REGTB_GENDER_IDENTITY,DISTRICT,1
REGTB_GENDER_IDENTITY,CODE,1
REGTB_GENDER_IDENTITY,DESCRIPTION,0
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_01,0
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_02,0
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_03,0
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_04,0
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_05,0
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_06,0
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_07,0
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_08,0
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_09,0
REGTB_GENDER_IDENTITY,STATE_CODE_EQUIV_10,0
REGTB_GENDER_IDENTITY,FED_CODE_EQUIV,0
REGTB_GENDER_IDENTITY,ACTIVE,0
REGTB_GENDER_IDENTITY,CHANGE_DATE_TIME,0
REGTB_GENDER_IDENTITY,CHANGE_UID,0
REGTB_GENERATION,DISTRICT,1
REGTB_GENERATION,CODE,1
REGTB_GENERATION,STATE_CODE_EQUIV,0
REGTB_GENERATION,ACTIVE,0
REGTB_GENERATION,CHANGE_DATE_TIME,0
REGTB_GENERATION,CHANGE_UID,0
REGTB_GRAD_PLANS,DISTRICT,1
REGTB_GRAD_PLANS,CODE,1
REGTB_GRAD_PLANS,DESCRIPTION,0
REGTB_GRAD_PLANS,STATE_CODE_EQUIV,0
REGTB_GRAD_PLANS,EXPECTED,0
REGTB_GRAD_PLANS,ACTUAL,0
REGTB_GRAD_PLANS,ACTIVE,0
REGTB_GRAD_PLANS,CHANGE_DATE_TIME,0
REGTB_GRAD_PLANS,CHANGE_UID,0
REGTB_GRADE_CEDS_CODE,DISTRICT,1
REGTB_GRADE_CEDS_CODE,CODE,1
REGTB_GRADE_CEDS_CODE,DESCRIPTION,0
REGTB_GRADE_CEDS_CODE,CHANGE_DATE_TIME,0
REGTB_GRADE_CEDS_CODE,CHANGE_UID,0
REGTB_GRADE_PESC_CODE,DISTRICT,1
REGTB_GRADE_PESC_CODE,CODE,1
REGTB_GRADE_PESC_CODE,DESCRIPTION,0
REGTB_GRADE_PESC_CODE,CHANGE_DATE_TIME,0
REGTB_GRADE_PESC_CODE,CHANGE_UID,0
REGTB_GROUP_USED_FOR,DISTRICT,1
REGTB_GROUP_USED_FOR,CODE,1
REGTB_GROUP_USED_FOR,DESCRIPTION,0
REGTB_GROUP_USED_FOR,ACTIVE,0
REGTB_GROUP_USED_FOR,CHANGE_DATE_TIME,0
REGTB_GROUP_USED_FOR,CHANGE_UID,0
REGTB_HISPANIC,DISTRICT,1
REGTB_HISPANIC,CODE,1
REGTB_HISPANIC,DESCRIPTION,0
REGTB_HISPANIC,STATE_CODE_EQUIV,0
REGTB_HISPANIC,ACTIVE,0
REGTB_HISPANIC,CHANGE_DATE_TIME,0
REGTB_HISPANIC,CHANGE_UID,0
REGTB_HISPANIC,PREVIOUSLY_REPORTED_AS,0
REGTB_HOLD_RC_CODE,DISTRICT,1
REGTB_HOLD_RC_CODE,CODE,1
REGTB_HOLD_RC_CODE,DESCRIPTION,0
REGTB_HOLD_RC_CODE,ACTIVE,0
REGTB_HOLD_RC_CODE,CHANGE_DATE_TIME,0
REGTB_HOLD_RC_CODE,CHANGE_UID,0
REGTB_HOME_BLDG_TYPE,DISTRICT,1
REGTB_HOME_BLDG_TYPE,CODE,1
REGTB_HOME_BLDG_TYPE,DESCRIPTION,0
REGTB_HOME_BLDG_TYPE,ACTIVE,0
REGTB_HOME_BLDG_TYPE,CHANGE_DATE_TIME,0
REGTB_HOME_BLDG_TYPE,CHANGE_UID,0
REGTB_HOMELESS,DISTRICT,1
REGTB_HOMELESS,CODE,1
REGTB_HOMELESS,DESCRIPTION,0
REGTB_HOMELESS,STATE_CODE_EQUIV,0
REGTB_HOMELESS,SIF2_CODE,0
REGTB_HOMELESS,ACTIVE,0
REGTB_HOMELESS,CHANGE_DATE_TIME,0
REGTB_HOMELESS,CHANGE_UID,0
REGTB_HOSPITAL,DISTRICT,1
REGTB_HOSPITAL,CODE,1
REGTB_HOSPITAL,DESCRIPTION,0
REGTB_HOSPITAL,ACTIVE,0
REGTB_HOSPITAL,CHANGE_DATE_TIME,0
REGTB_HOSPITAL,CHANGE_UID,0
REGTB_HOUSE_TEAM,DISTRICT,1
REGTB_HOUSE_TEAM,CODE,1
REGTB_HOUSE_TEAM,DESCRIPTION,0
REGTB_HOUSE_TEAM,STATE_CODE_EQUIV,0
REGTB_HOUSE_TEAM,ACTIVE,0
REGTB_HOUSE_TEAM,CHANGE_DATE_TIME,0
REGTB_HOUSE_TEAM,CHANGE_UID,0
REGTB_IEP_STATUS,DISTRICT,1
REGTB_IEP_STATUS,CODE,1
REGTB_IEP_STATUS,DESCRIPTION,0
REGTB_IEP_STATUS,STATE_CODE_EQUIV,0
REGTB_IEP_STATUS,ACTIVE,0
REGTB_IEP_STATUS,CHANGE_DATE_TIME,0
REGTB_IEP_STATUS,CHANGE_UID,0
REGTB_IMMUN_STATUS,DISTRICT,1
REGTB_IMMUN_STATUS,CODE,1
REGTB_IMMUN_STATUS,DESCRIPTION,0
REGTB_IMMUN_STATUS,STATE_CODE_EQUIV,0
REGTB_IMMUN_STATUS,ACTIVE,0
REGTB_IMMUN_STATUS,CHANGE_DATE_TIME,0
REGTB_IMMUN_STATUS,CHANGE_UID,0
REGTB_IMMUNS,DISTRICT,1
REGTB_IMMUNS,CODE,1
REGTB_IMMUNS,DESCRIPTION,0
REGTB_IMMUNS,STATE_CODE_EQUIV,0
REGTB_IMMUNS,ACTIVE,0
REGTB_IMMUNS,CHANGE_DATE_TIME,0
REGTB_IMMUNS,CHANGE_UID,0
REGTB_LANGUAGE,DISTRICT,1
REGTB_LANGUAGE,CODE,1
REGTB_LANGUAGE,DESCRIPTION,0
REGTB_LANGUAGE,STATE_CODE_EQUIV,0
REGTB_LANGUAGE,ACTIVE,0
REGTB_LANGUAGE,ALTERNATE_LANGUAGE,0
REGTB_LANGUAGE,HAC_LANGUAGE,0
REGTB_LANGUAGE,SIF_CODE,0
REGTB_LANGUAGE,SIF2_CODE,0
REGTB_LANGUAGE,CHANGE_DATE_TIME,0
REGTB_LANGUAGE,CHANGE_UID,0
REGTB_LANGUAGE,USE_IN_HOME,0
REGTB_LANGUAGE,USE_IN_NATIVE,0
REGTB_LEARNING_LOCATION,DISTRICT,1
REGTB_LEARNING_LOCATION,CODE,1
REGTB_LEARNING_LOCATION,DESCRIPTION,0
REGTB_LEARNING_LOCATION,STATE_CODE_EQUIV,0
REGTB_LEARNING_LOCATION,ACTIVE,0
REGTB_LEARNING_LOCATION,CHANGE_DATE_TIME,0
REGTB_LEARNING_LOCATION,CHANGE_UID,0
REGTB_LEARNING_LOCATION,ROW_IDENTITY,0
REGTB_MEAL_STATUS,DISTRICT,1
REGTB_MEAL_STATUS,CODE,1
REGTB_MEAL_STATUS,DESCRIPTION,0
REGTB_MEAL_STATUS,STATE_CODE_EQUIV,0
REGTB_MEAL_STATUS,ACTIVE,0
REGTB_MEAL_STATUS,SIF_CODE,0
REGTB_MEAL_STATUS,SIF2_CODE,0
REGTB_MEAL_STATUS,CHANGE_DATE_TIME,0
REGTB_MEAL_STATUS,CHANGE_UID,0
REGTB_MED_PROC,DISTRICT,1
REGTB_MED_PROC,CODE,1
REGTB_MED_PROC,DESCRIPTION,0
REGTB_MED_PROC,STATE_CODE_EQUIV,0
REGTB_MED_PROC,ACTIVE,0
REGTB_MED_PROC,CHANGE_DATE_TIME,0
REGTB_MED_PROC,CHANGE_UID,0
REGTB_MEDIC_ALERT,DISTRICT,1
REGTB_MEDIC_ALERT,CODE,1
REGTB_MEDIC_ALERT,DESCRIPTION,0
REGTB_MEDIC_ALERT,STATE_CODE_EQUIV,0
REGTB_MEDIC_ALERT,SENSITIVE,0
REGTB_MEDIC_ALERT,ACTIVE,0
REGTB_MEDIC_ALERT,ROW_IDENTITY,0
REGTB_MEDIC_ALERT,CHANGE_DATE_TIME,0
REGTB_MEDIC_ALERT,CHANGE_UID,0
REGTB_NAME_CHGRSN ,DISTRICT,1
REGTB_NAME_CHGRSN ,CODE,1
REGTB_NAME_CHGRSN ,DESCRIPTION,0
REGTB_NAME_CHGRSN ,STATE_CODE_EQUIV,0
REGTB_NAME_CHGRSN ,ACTIVE,0
REGTB_NAME_CHGRSN ,CHANGE_DATE_TIME,0
REGTB_NAME_CHGRSN ,CHANGE_UID,0
REGTB_NOTE_TYPE,DISTRICT,1
REGTB_NOTE_TYPE,CODE,1
REGTB_NOTE_TYPE,DESCRIPTION,0
REGTB_NOTE_TYPE,SENSITIVE,0
REGTB_NOTE_TYPE,ACTIVE,0
REGTB_NOTE_TYPE,CHANGE_DATE_TIME,0
REGTB_NOTE_TYPE,CHANGE_UID,0
REGTB_NOTE_TYPE,STATE_CODE_EQUIV,0
REGTB_PESC_CODE,DISTRICT,1
REGTB_PESC_CODE,CODE,1
REGTB_PESC_CODE,DESCRIPTION,0
REGTB_PESC_CODE,STATE,0
REGTB_PESC_CODE,STATE_CODE_EQUIV,0
REGTB_PESC_CODE,ACTIVE,0
REGTB_PESC_CODE,CHANGE_DATE_TIME,0
REGTB_PESC_CODE,CHANGE_UID,0
REGTB_PHONE,DISTRICT,1
REGTB_PHONE,CODE,1
REGTB_PHONE,DESCRIPTION,0
REGTB_PHONE,ACTIVE,0
REGTB_PHONE,STATE_CODE_EQUIV,0
REGTB_PHONE,SIF_CODE,0
REGTB_PHONE,SIF2_CODE,0
REGTB_PHONE,CHANGE_DATE_TIME,0
REGTB_PHONE,CHANGE_UID,0
REGTB_PROC_STATUS,DISTRICT,1
REGTB_PROC_STATUS,CODE,1
REGTB_PROC_STATUS,DESCRIPTION,0
REGTB_PROC_STATUS,ACTIVE,0
REGTB_PROC_STATUS,CHANGE_DATE_TIME,0
REGTB_PROC_STATUS,CHANGE_UID,0
REGTB_PROG_ENTRY,DISTRICT,1
REGTB_PROG_ENTRY,CODE,1
REGTB_PROG_ENTRY,DESCRIPTION,0
REGTB_PROG_ENTRY,STATE_CODE_EQUIV,0
REGTB_PROG_ENTRY,ACTIVE,0
REGTB_PROG_ENTRY,CHANGE_DATE_TIME,0
REGTB_PROG_ENTRY,CHANGE_UID,0
REGTB_PROG_WITH,DISTRICT,1
REGTB_PROG_WITH,CODE,1
REGTB_PROG_WITH,DESCRIPTION,0
REGTB_PROG_WITH,STATE_CODE_EQUIV,0
REGTB_PROG_WITH,ACTIVE,0
REGTB_PROG_WITH,CHANGE_DATE_TIME,0
REGTB_PROG_WITH,CHANGE_UID,0
REGTB_QUALIFY,DISTRICT,1
REGTB_QUALIFY,CODE,1
REGTB_QUALIFY,DESCRIPTION,0
REGTB_QUALIFY,ACTIVE,0
REGTB_QUALIFY,CHANGE_DATE_TIME,0
REGTB_QUALIFY,CHANGE_UID,0
REGTB_RELATION,DISTRICT,1
REGTB_RELATION,CODE,1
REGTB_RELATION,DESCRIPTION,0
REGTB_RELATION,STATE_CODE_EQUIV,0
REGTB_RELATION,ACTIVE,0
REGTB_RELATION,SIF_CODE,0
REGTB_RELATION,SIF2_CODE,0
REGTB_RELATION,PESC_CODE,0
REGTB_RELATION,CHANGE_DATE_TIME,0
REGTB_RELATION,CHANGE_UID,0
REGTB_RELATION,IMS_EQUIV,0
REGTB_RELATION_PESC_CODE,DISTRICT,1
REGTB_RELATION_PESC_CODE,CODE,1
REGTB_RELATION_PESC_CODE,DESCRIPTION,0
REGTB_RELATION_PESC_CODE,CHANGE_DATE_TIME,0
REGTB_RELATION_PESC_CODE,CHANGE_UID,0
REGTB_REQ_GROUP,DISTRICT,1
REGTB_REQ_GROUP,CODE,1
REGTB_REQ_GROUP,DESCRIPTION,0
REGTB_REQ_GROUP,IMAGE_FILE_NAME,0
REGTB_REQ_GROUP,GRAD_OR_SUPP,0
REGTB_REQ_GROUP,STATE_CODE_EQUIV,0
REGTB_REQ_GROUP,ROW_IDENTITY,0
REGTB_REQ_GROUP,CHANGE_DATE_TIME,0
REGTB_REQ_GROUP,CHANGE_UID,0
REGTB_RESIDENCY,DISTRICT,1
REGTB_RESIDENCY,CODE,1
REGTB_RESIDENCY,DESCRIPTION,0
REGTB_RESIDENCY,STATE_CODE_EQUIV,0
REGTB_RESIDENCY,ACTIVE,0
REGTB_RESIDENCY,SIF_CODE,0
REGTB_RESIDENCY,SIF2_CODE,0
REGTB_RESIDENCY,CHANGE_DATE_TIME,0
REGTB_RESIDENCY,CHANGE_UID,0
REGTB_ROOM_TYPE,DISTRICT,1
REGTB_ROOM_TYPE,CODE,1
REGTB_ROOM_TYPE,DESCRIPTION,0
REGTB_ROOM_TYPE,STATE_CODE_EQUIV,0
REGTB_ROOM_TYPE,ACTIVE,0
REGTB_ROOM_TYPE,CHANGE_DATE_TIME,0
REGTB_ROOM_TYPE,CHANGE_UID,0
REGTB_SCHOOL,DISTRICT,1
REGTB_SCHOOL,CODE,1
REGTB_SCHOOL,DESCRIPTION,0
REGTB_SCHOOL,CHANGE_DATE_TIME,0
REGTB_SCHOOL,CHANGE_UID,0
REGTB_SCHOOL_YEAR,DISTRICT,1
REGTB_SCHOOL_YEAR,SCHOOL_YEAR,1
REGTB_SCHOOL_YEAR,DISPLAY_YEAR,0
REGTB_SCHOOL_YEAR,ACTIVE,0
REGTB_SCHOOL_YEAR,CHANGE_DATE_TIME,0
REGTB_SCHOOL_YEAR,CHANGE_UID,0
REGTB_SIF_AUTH_MAP,DISTRICT,1
REGTB_SIF_AUTH_MAP,SIF_REFID_TYPE,1
REGTB_SIF_AUTH_MAP,SYSTEM_TYPE,1
REGTB_SIF_AUTH_MAP,SYSTEM_VALUE,1
REGTB_SIF_AUTH_MAP,ELEMENT_NAME,1
REGTB_SIF_AUTH_MAP,TO_TABLE,0
REGTB_SIF_AUTH_MAP,TO_COLUMN,0
REGTB_SIF_AUTH_MAP,TO_USER_SCREEN,0
REGTB_SIF_AUTH_MAP,TO_USER_FIELD,0
REGTB_SIF_AUTH_MAP,ACTIVE,0
REGTB_SIF_AUTH_MAP,CHANGE_DATE_TIME,0
REGTB_SIF_AUTH_MAP,CHANGE_UID,0
REGTB_SIF_JOBCLASS,DISTRICT,1
REGTB_SIF_JOBCLASS,CODE,1
REGTB_SIF_JOBCLASS,IS_COUNSELOR,0
REGTB_SIF_JOBCLASS,IS_TEACHER,0
REGTB_SIF_JOBCLASS,ACTIVE,0
REGTB_SIF_JOBCLASS,CHANGE_DATE_TIME,0
REGTB_SIF_JOBCLASS,CHANGE_UID,0
REGTB_ST_PREFIX,DISTRICT,1
REGTB_ST_PREFIX,CODE,1
REGTB_ST_PREFIX,DESCRIPTION,0
REGTB_ST_PREFIX,ACTIVE,0
REGTB_ST_PREFIX,CHANGE_DATE_TIME,0
REGTB_ST_PREFIX,CHANGE_UID,0
REGTB_ST_SUFFIX,DISTRICT,1
REGTB_ST_SUFFIX,CODE,1
REGTB_ST_SUFFIX,DESCRIPTION,0
REGTB_ST_SUFFIX,ACTIVE,0
REGTB_ST_SUFFIX,CHANGE_DATE_TIME,0
REGTB_ST_SUFFIX,CHANGE_UID,0
REGTB_ST_TYPE,DISTRICT,1
REGTB_ST_TYPE,CODE,1
REGTB_ST_TYPE,DESCRIPTION,0
REGTB_ST_TYPE,ACTIVE,0
REGTB_ST_TYPE,CHANGE_DATE_TIME,0
REGTB_ST_TYPE,CHANGE_UID,0
REGTB_STATE_BLDG,DISTRICT,1
REGTB_STATE_BLDG,CODE,1
REGTB_STATE_BLDG,DESCRIPTION,0
REGTB_STATE_BLDG,STATE_CODE_EQUIV,0
REGTB_STATE_BLDG,ACTIVE,0
REGTB_STATE_BLDG,CHANGE_DATE_TIME,0
REGTB_STATE_BLDG,CHANGE_UID,0
REGTB_STATE_BLDG,LOCAL_BUILDING,0
REGTB_TITLE,DISTRICT,1
REGTB_TITLE,CODE,1
REGTB_TITLE,DESCRIPTION,0
REGTB_TITLE,ACTIVE,0
REGTB_TITLE,CHANGE_DATE_TIME,0
REGTB_TITLE,CHANGE_UID,0
REGTB_TRANSPORT_CODE,DISTRICT,1
REGTB_TRANSPORT_CODE,CODE,1
REGTB_TRANSPORT_CODE,DESCRIPTION,0
REGTB_TRANSPORT_CODE,STATE_CODE_EQUIV,1
REGTB_TRANSPORT_CODE,ACTIVE,0
REGTB_TRANSPORT_CODE,CHANGE_DATE_TIME,0
REGTB_TRANSPORT_CODE,CHANGE_UID,0
REGTB_TRAVEL,DISTRICT,1
REGTB_TRAVEL,CODE,1
REGTB_TRAVEL,DESCRIPTION,0
REGTB_TRAVEL,ACTIVE,0
REGTB_TRAVEL,SIF_CODE,0
REGTB_TRAVEL,SIF2_CODE,0
REGTB_TRAVEL,CHANGE_DATE_TIME,0
REGTB_TRAVEL,CHANGE_UID,0
REGTB_WITHDRAWAL,DISTRICT,1
REGTB_WITHDRAWAL,CODE,1
REGTB_WITHDRAWAL,DESCRIPTION,0
REGTB_WITHDRAWAL,STATE_CODE_EQUIV,0
REGTB_WITHDRAWAL,ACTIVE,0
REGTB_WITHDRAWAL,SIF_CODE,0
REGTB_WITHDRAWAL,SIF2_CODE,0
REGTB_WITHDRAWAL,DROPOUT_CODE,0
REGTB_WITHDRAWAL,STUDENT_EXIT,0
REGTB_WITHDRAWAL,CHANGE_DATE_TIME,0
REGTB_WITHDRAWAL,CHANGE_UID,0
SCHD_ALLOCATION,DISTRICT,1
SCHD_ALLOCATION,BUILDING,1
SCHD_ALLOCATION,GROUP_TYPE,1
SCHD_ALLOCATION,GROUP_CODE,1
SCHD_ALLOCATION,PERIOD,1
SCHD_ALLOCATION,MARKING_PERIOD,1
SCHD_ALLOCATION,CYCLE,1
SCHD_ALLOCATION,ALLOCATIONS,0
SCHD_ALLOCATION,CHANGE_DATE_TIME,0
SCHD_ALLOCATION,CHANGE_UID,0
SCHD_CFG,DISTRICT,1
SCHD_CFG,SCHOOL_YEAR,1
SCHD_CFG,SUMMER_SCHOOL,1
SCHD_CFG,BUILDING,1
SCHD_CFG,MAXIMUM_TIMESLOTS,0
SCHD_CFG,DEF_ADD_DATE_CODE,0
SCHD_CFG,DEFAULT_ADD_DATE,0
SCHD_CFG,CURRENT_INTERVAL,0
SCHD_CFG,DATE_CHECK,0
SCHD_CFG,IN_PROGRESS,0
SCHD_CFG,DISPLAY_MSE_BLDG,0
SCHD_CFG,OUTPUT_FILE_PATH,0
SCHD_CFG,MAX_SCAN_GUID,0
SCHD_CFG,TRAIL_MARKS,0
SCHD_CFG,MULTIPLE_BELL_SCHD,0
SCHD_CFG,DEFAULT_DURATION,0
SCHD_CFG,DEFAULT_MAX_SEATS,0
SCHD_CFG,DEFAULT_MARKS_ARE,0
SCHD_CFG,TEA_SCHD_STU_SUMM,0
SCHD_CFG,SUB_SCHD_STU_SUMM,0
SCHD_CFG,TEA_SCHD_STU_REC,0
SCHD_CFG,SUB_SCHD_STU_REC,0
SCHD_CFG,TAC_LIMIT_REC_NUM,0
SCHD_CFG,TAC_LIMIT_REC_DEPT,0
SCHD_CFG,PREREQ_CRS_BLDG,0
SCHD_CFG,PREREQ_CHK_REQ,0
SCHD_CFG,PREREQ_CHK_SCHD,0
SCHD_CFG,PREREQ_CRS_TOOK,0
SCHD_CFG,DEFAULT_NOMARKS_FIRST_DAYS,0
SCHD_CFG,DEFAULT_UNGRADED_LAST_DAYS,0
SCHD_CFG,DEFAULT_FIRST_NEXT,0
SCHD_CFG,DEFAULT_LAST_PREVIOUS,0
SCHD_CFG,LAST_ISSUED_BY,0
SCHD_CFG,USE_UNGRADED,0
SCHD_CFG,USE_FOCUS,0
SCHD_CFG,MAX_FOCUS_PERCENT,0
SCHD_CFG,REQ_CRS_STAFF_DATE_ENTRY,0
SCHD_CFG,CHANGE_DATE_TIME,0
SCHD_CFG,CHANGE_UID,0
SCHD_CFG_DISC_OFF,DISTRICT,1
SCHD_CFG_DISC_OFF,SCHOOL_YEAR,1
SCHD_CFG_DISC_OFF,SUMMER_SCHOOL,1
SCHD_CFG_DISC_OFF,BUILDING,1
SCHD_CFG_DISC_OFF,OFFENSE_CODE,1
SCHD_CFG_DISC_OFF,CHANGE_DATE_TIME,0
SCHD_CFG_DISC_OFF,CHANGE_UID,0
SCHD_CFG_ELEM_AIN,DISTRICT,1
SCHD_CFG_ELEM_AIN,SCHOOL_YEAR,1
SCHD_CFG_ELEM_AIN,SUMMER_SCHOOL,1
SCHD_CFG_ELEM_AIN,BUILDING,1
SCHD_CFG_ELEM_AIN,USE_ELEM_SCHD,1
SCHD_CFG_ELEM_AIN,CHANGE_DATE_TIME,1
SCHD_CFG_ELEM_AIN,CHANGE_UID,1
SCHD_CFG_FOCUS_CRT,DISTRICT,1
SCHD_CFG_FOCUS_CRT,SCHOOL_YEAR,1
SCHD_CFG_FOCUS_CRT,SUMMER_SCHOOL,1
SCHD_CFG_FOCUS_CRT,BUILDING,1
SCHD_CFG_FOCUS_CRT,SEQUENCE_NUM,1
SCHD_CFG_FOCUS_CRT,AND_OR_FLAG,0
SCHD_CFG_FOCUS_CRT,SCREEN_TYPE,0
SCHD_CFG_FOCUS_CRT,TABLE_NAME,0
SCHD_CFG_FOCUS_CRT,FIELD_NUMBER,0
SCHD_CFG_FOCUS_CRT,SCREEN_NUMBER,0
SCHD_CFG_FOCUS_CRT,COLUMN_NAME,0
SCHD_CFG_FOCUS_CRT,PROGRAM_ID,0
SCHD_CFG_FOCUS_CRT,OPERATOR,0
SCHD_CFG_FOCUS_CRT,SEARCH_VALUE,0
SCHD_CFG_FOCUS_CRT,CHANGE_DATE_TIME,0
SCHD_CFG_FOCUS_CRT,CHANGE_UID,0
SCHD_CFG_HOUSETEAM,DISTRICT,1
SCHD_CFG_HOUSETEAM,SCHOOL_YEAR,1
SCHD_CFG_HOUSETEAM,SUMMER_SCHOOL,1
SCHD_CFG_HOUSETEAM,BUILDING,1
SCHD_CFG_HOUSETEAM,HOUSE_TEAM,1
SCHD_CFG_HOUSETEAM,CHANGE_DATE_TIME,0
SCHD_CFG_HOUSETEAM,CHANGE_UID,0
SCHD_CFG_HRM_AIN,DISTRICT,1
SCHD_CFG_HRM_AIN,SCHOOL_YEAR,1
SCHD_CFG_HRM_AIN,SUMMER_SCHOOL,1
SCHD_CFG_HRM_AIN,BUILDING,1
SCHD_CFG_HRM_AIN,SCHD_BY_PRIMARY_HRM,0
SCHD_CFG_HRM_AIN,CHANGE_DATE_TIME,0
SCHD_CFG_HRM_AIN,CHANGE_UID,0
SCHD_CFG_INTERVAL,DISTRICT,1
SCHD_CFG_INTERVAL,SCHOOL_YEAR,1
SCHD_CFG_INTERVAL,BUILDING,1
SCHD_CFG_INTERVAL,SCHD_INTERVAL,1
SCHD_CFG_INTERVAL,DESCRIPTION,0
SCHD_CFG_INTERVAL,CHANGE_DATE_TIME,0
SCHD_CFG_INTERVAL,CHANGE_UID,0
SCHD_CNFLCT_MATRIX,DISTRICT,1
SCHD_CNFLCT_MATRIX,BUILDING,1
SCHD_CNFLCT_MATRIX,MATRIX_TYPE,1
SCHD_CNFLCT_MATRIX,SCHD_INTERVAL,1
SCHD_CNFLCT_MATRIX,COURSE1,1
SCHD_CNFLCT_MATRIX,COURSE2,1
SCHD_CNFLCT_MATRIX,NUMBER_CONFLICTS,0
SCHD_CNFLCT_MATRIX,CHANGE_DATE_TIME,0
SCHD_CNFLCT_MATRIX,CHANGE_UID,0
SCHD_COURSE,DISTRICT,1
SCHD_COURSE,BUILDING,1
SCHD_COURSE,COURSE,1
SCHD_COURSE,BUILDING_TYPE,0
SCHD_COURSE,DIST_LEVEL,0
SCHD_COURSE,DESCRIPTION,0
SCHD_COURSE,LONG_DESCRIPTION,0
SCHD_COURSE,DEPARTMENT,0
SCHD_COURSE,HOUSE_TEAM,0
SCHD_COURSE,STUDY_HALL,0
SCHD_COURSE,REGULAR_SCHOOL,0
SCHD_COURSE,SUMMER_SCHOOL,0
SCHD_COURSE,VOTEC,0
SCHD_COURSE,ACTIVE_STATUS,0
SCHD_COURSE,SIMPLE_TALLY,0
SCHD_COURSE,CONFLICT_MATRIX,0
SCHD_COURSE,GENDER_RESTRICTION,0
SCHD_COURSE,ALTERNATE_COURSE,0
SCHD_COURSE,CREDIT,0
SCHD_COURSE,FEE,0
SCHD_COURSE,PRIORITY,0
SCHD_COURSE,SEMESTER_WEIGHT,0
SCHD_COURSE,BLOCK_TYPE,0
SCHD_COURSE,SCAN_COURSE,0
SCHD_COURSE,TAKE_ATTENDANCE,0
SCHD_COURSE,RECEIVE_MARK,0
SCHD_COURSE,COURSE_LEVEL,0
SCHD_COURSE,SUBJ_AREA_CREDIT,0
SCHD_COURSE,REC_NEXT_COURSE,0
SCHD_COURSE,REQUEST_FROM_HAC,0
SCHD_COURSE,SAME_TEACHER,0
SCHD_COURSE,INCLD_PASSING_TIME,0
SCHD_COURSE,COURSE_CREDIT_BASIS,0
SCHD_COURSE,NCES_CODE,0
SCHD_COURSE,INCLD_CURRICULUM_CONNECTOR,0
SCHD_COURSE,MIN_GRADE,0
SCHD_COURSE,MAX_GRADE,0
SCHD_COURSE,CLASSIFY_STUS_MAX,0
SCHD_COURSE,CLASSIFY_NUM_OR_PER,0
SCHD_COURSE,SIF_CREDIT_TYPE,0
SCHD_COURSE,SIF_INSTRUCTIONAL_LEVEL,0
SCHD_COURSE,ROW_IDENTITY,0
SCHD_COURSE,CHANGE_DATE_TIME,0
SCHD_COURSE,CHANGE_UID,0
SCHD_COURSE_BLOCK,DISTRICT,1
SCHD_COURSE_BLOCK,BUILDING,1
SCHD_COURSE_BLOCK,BLOCK_COURSE,1
SCHD_COURSE_BLOCK,BLOCKETTE_COURSE,1
SCHD_COURSE_BLOCK,SAME_SECTION,0
SCHD_COURSE_BLOCK,MANDATORY,0
SCHD_COURSE_BLOCK,CHANGE_DATE_TIME,0
SCHD_COURSE_BLOCK,CHANGE_UID,0
SCHD_COURSE_GPA,DISTRICT,1
SCHD_COURSE_GPA,BUILDING,1
SCHD_COURSE_GPA,COURSE,1
SCHD_COURSE_GPA,GPA_TYPE,1
SCHD_COURSE_GPA,GPA_LEVEL,0
SCHD_COURSE_GPA,CHANGE_DATE_TIME,0
SCHD_COURSE_GPA,CHANGE_UID,0
SCHD_COURSE_GRADE,DISTRICT,1
SCHD_COURSE_GRADE,BUILDING,1
SCHD_COURSE_GRADE,COURSE,1
SCHD_COURSE_GRADE,RESTRICT_GRADE,1
SCHD_COURSE_GRADE,CHANGE_DATE_TIME,0
SCHD_COURSE_GRADE,CHANGE_UID,0
SCHD_COURSE_HONORS,DISTRICT,1
SCHD_COURSE_HONORS,BUILDING,1
SCHD_COURSE_HONORS,COURSE,1
SCHD_COURSE_HONORS,HONOR_TYPE,1
SCHD_COURSE_HONORS,HONOR_LEVEL,0
SCHD_COURSE_HONORS,CHANGE_DATE_TIME,0
SCHD_COURSE_HONORS,CHANGE_UID,0
SCHD_COURSE_QUALIFY,DISTRICT,1
SCHD_COURSE_QUALIFY,BUILDING,1
SCHD_COURSE_QUALIFY,COURSE,1
SCHD_COURSE_QUALIFY,QUALIFICATION,1
SCHD_COURSE_QUALIFY,CHANGE_DATE_TIME,0
SCHD_COURSE_QUALIFY,CHANGE_UID,0
SCHD_COURSE_SEQ,DISTRICT,1
SCHD_COURSE_SEQ,BUILDING,1
SCHD_COURSE_SEQ,SEQUENCE_NUM,0
SCHD_COURSE_SEQ,COURSE_OR_GROUP_A,1
SCHD_COURSE_SEQ,SEQUENCE_A,1
SCHD_COURSE_SEQ,SEQUENCE_TYPE,0
SCHD_COURSE_SEQ,COURSE_OR_GROUP_B,1
SCHD_COURSE_SEQ,SEQUENCE_B,1
SCHD_COURSE_SEQ,IS_VALID,0
SCHD_COURSE_SEQ,ERROR_MESSAGE,0
SCHD_COURSE_SEQ,PREREQ_MIN_MARK,0
SCHD_COURSE_SEQ,PREREQ_MARK_TYPE,0
SCHD_COURSE_SEQ,CHANGE_DATE_TIME,0
SCHD_COURSE_SEQ,CHANGE_UID,0
SCHD_COURSE_SUBJ,DISTRICT,1
SCHD_COURSE_SUBJ,BUILDING,1
SCHD_COURSE_SUBJ,COURSE,1
SCHD_COURSE_SUBJ,SUBJECT_AREA,1
SCHD_COURSE_SUBJ,SUBJ_ORDER,0
SCHD_COURSE_SUBJ,SUB_AREA,0
SCHD_COURSE_SUBJ,CHANGE_DATE_TIME,0
SCHD_COURSE_SUBJ,CHANGE_UID,0
SCHD_COURSE_SUBJ_TAG,DISTRICT,1
SCHD_COURSE_SUBJ_TAG,BUILDING,1
SCHD_COURSE_SUBJ_TAG,COURSE,1
SCHD_COURSE_SUBJ_TAG,SUBJECT_AREA,1
SCHD_COURSE_SUBJ_TAG,TAG,1
SCHD_COURSE_SUBJ_TAG,CHANGE_DATE_TIME,0
SCHD_COURSE_SUBJ_TAG,CHANGE_UID,0
SCHD_COURSE_USER,DISTRICT,1
SCHD_COURSE_USER,BUILDING,1
SCHD_COURSE_USER,COURSE,1
SCHD_COURSE_USER,SCREEN_NUMBER,1
SCHD_COURSE_USER,FIELD_NUMBER,1
SCHD_COURSE_USER,LIST_SEQUENCE,1
SCHD_COURSE_USER,FIELD_VALUE,0
SCHD_COURSE_USER,CHANGE_DATE_TIME,0
SCHD_COURSE_USER,CHANGE_UID,0
SCHD_CRS_BLDG_TYPE,DISTRICT,1
SCHD_CRS_BLDG_TYPE,BUILDING,1
SCHD_CRS_BLDG_TYPE,COURSE,1
SCHD_CRS_BLDG_TYPE,BLDG_TYPE,1
SCHD_CRS_BLDG_TYPE,CHANGE_DATE_TIME,0
SCHD_CRS_BLDG_TYPE,CHANGE_UID,0
SCHD_CRS_GROUP_DET,DISTRICT,1
SCHD_CRS_GROUP_DET,BUILDING,1
SCHD_CRS_GROUP_DET,COURSE_GROUP,1
SCHD_CRS_GROUP_DET,COURSE_BUILDING,1
SCHD_CRS_GROUP_DET,COURSE,1
SCHD_CRS_GROUP_DET,CHANGE_DATE_TIME,0
SCHD_CRS_GROUP_DET,CHANGE_UID,0
SCHD_CRS_GROUP_HDR,DISTRICT,1
SCHD_CRS_GROUP_HDR,BUILDING,1
SCHD_CRS_GROUP_HDR,COURSE_GROUP,1
SCHD_CRS_GROUP_HDR,DESCRIPTION,0
SCHD_CRS_GROUP_HDR,CHANGE_DATE_TIME,0
SCHD_CRS_GROUP_HDR,CHANGE_UID,0
SCHD_CRS_MARK_TYPE,DISTRICT,1
SCHD_CRS_MARK_TYPE,BUILDING,1
SCHD_CRS_MARK_TYPE,COURSE,1
SCHD_CRS_MARK_TYPE,MARK_TYPE,1
SCHD_CRS_MARK_TYPE,CHANGE_DATE_TIME,0
SCHD_CRS_MARK_TYPE,CHANGE_UID,0
SCHD_CRS_MSB_COMBO,DISTRICT,1
SCHD_CRS_MSB_COMBO,BUILDING,1
SCHD_CRS_MSB_COMBO,COMBINATION_NUMBER,1
SCHD_CRS_MSB_COMBO,COMBINATION_COURSE,1
SCHD_CRS_MSB_COMBO,CHANGE_DATE_TIME,0
SCHD_CRS_MSB_COMBO,CHANGE_UID,0
SCHD_CRS_MSB_DET,DISTRICT,1
SCHD_CRS_MSB_DET,BUILDING,1
SCHD_CRS_MSB_DET,COURSE,1
SCHD_CRS_MSB_DET,COURSE_SECTION,1
SCHD_CRS_MSB_DET,MEETING_CODE,0
SCHD_CRS_MSB_DET,STAFF_TYPE,0
SCHD_CRS_MSB_DET,STAFF_RESOURCE,0
SCHD_CRS_MSB_DET,ROOM_TYPE,0
SCHD_CRS_MSB_DET,ROOM_RESOURCE,0
SCHD_CRS_MSB_DET,MAXIMUM_SEATS,0
SCHD_CRS_MSB_DET,CHANGE_DATE_TIME,0
SCHD_CRS_MSB_DET,CHANGE_UID,0
SCHD_CRS_MSB_HDR,DISTRICT,1
SCHD_CRS_MSB_HDR,BUILDING,1
SCHD_CRS_MSB_HDR,COURSE,1
SCHD_CRS_MSB_HDR,NUMBER_REQUESTS,0
SCHD_CRS_MSB_HDR,AVERAGE_CLASS_SIZE,0
SCHD_CRS_MSB_HDR,NUMBER_SECTIONS,0
SCHD_CRS_MSB_HDR,SECTIONS_SAME,0
SCHD_CRS_MSB_HDR,COURSE_LENGTH,0
SCHD_CRS_MSB_HDR,DURATION_TYPE,0
SCHD_CRS_MSB_HDR,SPAN,0
SCHD_CRS_MSB_HDR,SAME_TEACHER,0
SCHD_CRS_MSB_HDR,SAME_PERIOD,0
SCHD_CRS_MSB_HDR,CHANGE_DATE_TIME,0
SCHD_CRS_MSB_HDR,CHANGE_UID,0
SCHD_CRS_MSB_PATRN,DISTRICT,1
SCHD_CRS_MSB_PATRN,BUILDING,1
SCHD_CRS_MSB_PATRN,COURSE,1
SCHD_CRS_MSB_PATRN,COURSE_SECTION,1
SCHD_CRS_MSB_PATRN,SEM_OR_MP,1
SCHD_CRS_MSB_PATRN,PATTERN,0
SCHD_CRS_MSB_PATRN,CHANGE_DATE_TIME,0
SCHD_CRS_MSB_PATRN,CHANGE_UID,0
SCHD_CRSSEQ_MARKTYPE,DISTRICT,1
SCHD_CRSSEQ_MARKTYPE,BUILDING,1
SCHD_CRSSEQ_MARKTYPE,COURSE_OR_GROUP_A,1
SCHD_CRSSEQ_MARKTYPE,SEQUENCE_A,1
SCHD_CRSSEQ_MARKTYPE,COURSE_OR_GROUP_B,1
SCHD_CRSSEQ_MARKTYPE,SEQUENCE_B,1
SCHD_CRSSEQ_MARKTYPE,PREREQ_MARK_TYPE,1
SCHD_CRSSEQ_MARKTYPE,CHANGE_DATE_TIME,0
SCHD_CRSSEQ_MARKTYPE,CHANGE_UID,0
SCHD_DISTCRS_BLDG_TYPES,DISTRICT,1
SCHD_DISTCRS_BLDG_TYPES,BUILDING,1
SCHD_DISTCRS_BLDG_TYPES,COURSE,1
SCHD_DISTCRS_BLDG_TYPES,BUILDING_TYPE,1
SCHD_DISTCRS_BLDG_TYPES,ACTIVE,0
SCHD_DISTCRS_BLDG_TYPES,CHANGE_DATE_TIME,0
SCHD_DISTCRS_BLDG_TYPES,CHANGE_UID,0
SCHD_DISTCRS_SECTIONS_OVERRIDE,DISTRICT,1
SCHD_DISTCRS_SECTIONS_OVERRIDE,BUILDING,1
SCHD_DISTCRS_SECTIONS_OVERRIDE,COURSE,1
SCHD_DISTCRS_SECTIONS_OVERRIDE,PAGE_SECTION,1
SCHD_DISTCRS_SECTIONS_OVERRIDE,BLDG_OVERRIDDEN,0
SCHD_DISTCRS_SECTIONS_OVERRIDE,CHANGE_DATE_TIME,0
SCHD_DISTCRS_SECTIONS_OVERRIDE,CHANGE_UID,0
SCHD_DISTRICT_CFG,DISTRICT,1
SCHD_DISTRICT_CFG,USE_DIST_CRS_CAT,0
SCHD_DISTRICT_CFG,BLDGS_UPD_CRS_CAT,0
SCHD_DISTRICT_CFG,BLDGS_ADD_CRS_CAT,0
SCHD_DISTRICT_CFG,CLASSIFY_STUS_MAX,0
SCHD_DISTRICT_CFG,CLASSIFY_NUM_OR_PER,0
SCHD_DISTRICT_CFG,CHANGE_DATE_TIME,0
SCHD_DISTRICT_CFG,CHANGE_UID,0
SCHD_DISTRICT_CFG_UPD,DISTRICT,1
SCHD_DISTRICT_CFG_UPD,PAGE_SECTION,1
SCHD_DISTRICT_CFG_UPD,CAN_UPDATE,0
SCHD_DISTRICT_CFG_UPD,CHANGE_DATE_TIME,0
SCHD_DISTRICT_CFG_UPD,CHANGE_UID,0
SCHD_LUNCH_CODE,DISTRICT,1
SCHD_LUNCH_CODE,BUILDING,1
SCHD_LUNCH_CODE,LUNCH_CODE,1
SCHD_LUNCH_CODE,START_TIME,0
SCHD_LUNCH_CODE,END_TIME,0
SCHD_LUNCH_CODE,CHANGE_DATE_TIME,0
SCHD_LUNCH_CODE,CHANGE_UID,0
SCHD_MS,DISTRICT,1
SCHD_MS,SCHOOL_YEAR,1
SCHD_MS,SUMMER_SCHOOL,1
SCHD_MS,BUILDING,1
SCHD_MS,COURSE,1
SCHD_MS,COURSE_SECTION,1
SCHD_MS,SECTION_KEY,0
SCHD_MS,DESCRIPTION,0
SCHD_MS,STUDY_HALL,0
SCHD_MS,MAXIMUM_SEATS,0
SCHD_MS,DEPARTMENT,0
SCHD_MS,VOTEC,0
SCHD_MS,FEE,0
SCHD_MS,GENDER_RESTRICTION,0
SCHD_MS,BLOCK_TYPE,0
SCHD_MS,TRACK,0
SCHD_MS,DURATION_TYPE,0
SCHD_MS,SUBJ_AREA_CREDIT,0
SCHD_MS,AVERAGE_TYPE,0
SCHD_MS,STATE_CRS_EQUIV,0
SCHD_MS,SAME_TEACHER,0
SCHD_MS,LOCK,0
SCHD_MS,COURSE_CREDIT_BASIS,0
SCHD_MS,NCES_CODE,0
SCHD_MS,CATEGORY_TYPE,0
SCHD_MS,CLASSIFY_STUS_MAX,0
SCHD_MS,CLASSIFY_NUM_OR_PER,0
SCHD_MS,ROW_IDENTITY,0
SCHD_MS,CHANGE_DATE_TIME,0
SCHD_MS,CHANGE_UID,0
SCHD_MS,UNIQUE_MS_COURSE_ID,0
SCHD_MS,UNIQUE_MS_BUILDING_ID,0
SCHD_MS_ALT_LANG,DISTRICT,1
SCHD_MS_ALT_LANG,SECTION_KEY,1
SCHD_MS_ALT_LANG,COURSE_SESSION,1
SCHD_MS_ALT_LANG,LANGUAGE,1
SCHD_MS_ALT_LANG,DESCRIPTION,0
SCHD_MS_ALT_LANG,CHANGE_DATE_TIME,0
SCHD_MS_ALT_LANG,CHANGE_UID,0
SCHD_MS_BLDG_TYPE,DISTRICT,1
SCHD_MS_BLDG_TYPE,SECTION_KEY,1
SCHD_MS_BLDG_TYPE,COURSE_SESSION,1
SCHD_MS_BLDG_TYPE,BLDG_TYPE,1
SCHD_MS_BLDG_TYPE,CHANGE_DATE_TIME,0
SCHD_MS_BLDG_TYPE,CHANGE_UID,0
SCHD_MS_BLOCK,DISTRICT,1
SCHD_MS_BLOCK,BLOCK_SECTION,1
SCHD_MS_BLOCK,COURSE,1
SCHD_MS_BLOCK,BLOCKETTE_SECTION,0
SCHD_MS_BLOCK,MANDATORY,0
SCHD_MS_BLOCK,CHANGE_DATE_TIME,0
SCHD_MS_BLOCK,CHANGE_UID,0
SCHD_MS_CYCLE,DISTRICT,1
SCHD_MS_CYCLE,SECTION_KEY,1
SCHD_MS_CYCLE,COURSE_SESSION,1
SCHD_MS_CYCLE,CYCLE_CODE,1
SCHD_MS_CYCLE,CHANGE_DATE_TIME,0
SCHD_MS_CYCLE,CHANGE_UID,0
SCHD_MS_GPA,DISTRICT,1
SCHD_MS_GPA,SECTION_KEY,1
SCHD_MS_GPA,COURSE_SESSION,1
SCHD_MS_GPA,GPA_TYPE,1
SCHD_MS_GPA,GPA_LEVEL,0
SCHD_MS_GPA,CHANGE_DATE_TIME,0
SCHD_MS_GPA,CHANGE_UID,0
SCHD_MS_GRADE,DISTRICT,1
SCHD_MS_GRADE,SECTION_KEY,1
SCHD_MS_GRADE,RESTRICT_GRADE,1
SCHD_MS_GRADE,ROW_IDENTITY,0
SCHD_MS_GRADE,CHANGE_DATE_TIME,0
SCHD_MS_GRADE,CHANGE_UID,0
SCHD_MS_HONORS,DISTRICT,1
SCHD_MS_HONORS,SECTION_KEY,1
SCHD_MS_HONORS,COURSE_SESSION,1
SCHD_MS_HONORS,HONOR_TYPE,1
SCHD_MS_HONORS,HONOR_LEVEL,0
SCHD_MS_HONORS,CHANGE_DATE_TIME,0
SCHD_MS_HONORS,CHANGE_UID,0
SCHD_MS_HOUSE_TEAM,DISTRICT,1
SCHD_MS_HOUSE_TEAM,SECTION_KEY,1
SCHD_MS_HOUSE_TEAM,HOUSE_TEAM,1
SCHD_MS_HOUSE_TEAM,CHANGE_DATE_TIME,0
SCHD_MS_HOUSE_TEAM,CHANGE_UID,0
SCHD_MS_HRM_AIN,DISTRICT,1
SCHD_MS_HRM_AIN,SECTION_KEY,1
SCHD_MS_HRM_AIN,HRM_SCHD_PRIMARY_HOMEROOM,0
SCHD_MS_HRM_AIN,CHANGE_DATE_TIME,0
SCHD_MS_HRM_AIN,CHANGE_UID,0
SCHD_MS_KEY,DISTRICT,1
SCHD_MS_KEY,SECTION_KEY,1
SCHD_MS_KEY,CHANGE_DATE_TIME,0
SCHD_MS_KEY,CHANGE_UID,0
SCHD_MS_LUNCH,DISTRICT,1
SCHD_MS_LUNCH,SECTION_KEY,1
SCHD_MS_LUNCH,COURSE_SESSION,1
SCHD_MS_LUNCH,CYCLE_DAY,1
SCHD_MS_LUNCH,LUNCH_CODE,0
SCHD_MS_LUNCH,START_DATE,1
SCHD_MS_LUNCH,END_DATE,0
SCHD_MS_LUNCH,CHANGE_DATE_TIME,0
SCHD_MS_LUNCH,CHANGE_UID,0
SCHD_MS_MARK_TYPES,DISTRICT,1
SCHD_MS_MARK_TYPES,SECTION_KEY,1
SCHD_MS_MARK_TYPES,COURSE_SESSION,1
SCHD_MS_MARK_TYPES,MARK_TYPE,1
SCHD_MS_MARK_TYPES,CHANGE_DATE_TIME,0
SCHD_MS_MARK_TYPES,CHANGE_UID,0
SCHD_MS_MP,DISTRICT,1
SCHD_MS_MP,SECTION_KEY,1
SCHD_MS_MP,COURSE_SESSION,1
SCHD_MS_MP,MARKING_PERIOD,1
SCHD_MS_MP,USED_SEATS,0
SCHD_MS_MP,CLASSIFICATION_WEIGHT,0
SCHD_MS_MP,ROW_IDENTITY,0
SCHD_MS_MP,CHANGE_DATE_TIME,0
SCHD_MS_MP,CHANGE_UID,0
SCHD_MS_QUALIFY,DISTRICT,1
SCHD_MS_QUALIFY,SECTION_KEY,1
SCHD_MS_QUALIFY,QUALIFICATION,1
SCHD_MS_QUALIFY,CHANGE_DATE_TIME,0
SCHD_MS_QUALIFY,CHANGE_UID,0
SCHD_MS_SCHEDULE,DISTRICT,1
SCHD_MS_SCHEDULE,SCHOOL_YEAR,1
SCHD_MS_SCHEDULE,SUMMER_SCHOOL,1
SCHD_MS_SCHEDULE,BUILDING,1
SCHD_MS_SCHEDULE,COURSE,1
SCHD_MS_SCHEDULE,COURSE_SECTION,1
SCHD_MS_SCHEDULE,SECTION_KEY,0
SCHD_MS_SCHEDULE,DESCRIPTION,0
SCHD_MS_SCHEDULE,STUDY_HALL,0
SCHD_MS_SCHEDULE,TRACK,0
SCHD_MS_SCHEDULE,COURSE_SESSION,1
SCHD_MS_SCHEDULE,SESSION_DESCRIPTION,0
SCHD_MS_SCHEDULE,START_PERIOD,0
SCHD_MS_SCHEDULE,END_PERIOD,0
SCHD_MS_SCHEDULE,TAKE_ATTENDANCE,0
SCHD_MS_SCHEDULE,RECEIVE_MARK,0
SCHD_MS_SCHEDULE,PRIMARY_STAFF_ID,0
SCHD_MS_SCHEDULE,ROOM_ID,0
SCHD_MS_SCHEDULE,CHANGE_DATE_TIME,0
SCHD_MS_SCHEDULE,CHANGE_UID,0
SCHD_MS_SESSION,DISTRICT,1
SCHD_MS_SESSION,SECTION_KEY,1
SCHD_MS_SESSION,COURSE_SESSION,1
SCHD_MS_SESSION,DESCRIPTION,0
SCHD_MS_SESSION,START_PERIOD,0
SCHD_MS_SESSION,END_PERIOD,0
SCHD_MS_SESSION,TAKE_ATTENDANCE,0
SCHD_MS_SESSION,RECEIVE_MARK,0
SCHD_MS_SESSION,CREDIT,0
SCHD_MS_SESSION,PRIMARY_STAFF_ID,0
SCHD_MS_SESSION,ROOM_ID,0
SCHD_MS_SESSION,COURSE_LEVEL,0
SCHD_MS_SESSION,INCLD_PASSING_TIME,0
SCHD_MS_SESSION,USE_FOCUS,0
SCHD_MS_SESSION,ROW_IDENTITY,0
SCHD_MS_SESSION,CHANGE_DATE_TIME,0
SCHD_MS_SESSION,CHANGE_UID,0
SCHD_MS_SESSION,UNIQUE_MS_SESSION_ID,0
SCHD_MS_STAFF,DISTRICT,1
SCHD_MS_STAFF,SECTION_KEY,1
SCHD_MS_STAFF,COURSE_SESSION,1
SCHD_MS_STAFF,STAFF_ID,1
SCHD_MS_STAFF,ROW_IDENTITY,0
SCHD_MS_STAFF,CHANGE_DATE_TIME,0
SCHD_MS_STAFF,CHANGE_UID,0
SCHD_MS_STAFF_DATE,DISTRICT,1
SCHD_MS_STAFF_DATE,SECTION_KEY,1
SCHD_MS_STAFF_DATE,COURSE_SESSION,1
SCHD_MS_STAFF_DATE,STAFF_ID,1
SCHD_MS_STAFF_DATE,START_DATE,1
SCHD_MS_STAFF_DATE,SEQUENCE,1
SCHD_MS_STAFF_DATE,END_DATE,0
SCHD_MS_STAFF_DATE,PRIMARY_SECONDARY,0
SCHD_MS_STAFF_DATE,COTEACHER,0
SCHD_MS_STAFF_DATE,CHANGE_DATE_TIME,0
SCHD_MS_STAFF_DATE,CHANGE_UID,0
SCHD_MS_STAFF_STUDENT,DISTRICT,1
SCHD_MS_STAFF_STUDENT,SECTION_KEY,1
SCHD_MS_STAFF_STUDENT,COURSE_SESSION,1
SCHD_MS_STAFF_STUDENT,STAFF_ID,1
SCHD_MS_STAFF_STUDENT,STUDENT_ID,1
SCHD_MS_STAFF_STUDENT,START_DATE,1
SCHD_MS_STAFF_STUDENT,SEQUENCE,1
SCHD_MS_STAFF_STUDENT,STAFF_STUDENT_KEY,1
SCHD_MS_STAFF_STUDENT,MINUTES,0
SCHD_MS_STAFF_STUDENT,STUSTARTDATE,0
SCHD_MS_STAFF_STUDENT,STUENDDATE,0
SCHD_MS_STAFF_STUDENT,CHANGE_DATE_TIME,0
SCHD_MS_STAFF_STUDENT,CHANGE_UID,0
SCHD_MS_STAFF_STUDENT_pa,DISTRICT,0
SCHD_MS_STAFF_STUDENT_pa,SECTION_KEY,0
SCHD_MS_STAFF_STUDENT_pa,COURSE_SESSION,0
SCHD_MS_STAFF_STUDENT_pa,STAFF_ID,0
SCHD_MS_STAFF_STUDENT_pa,START_DATE,0
SCHD_MS_STAFF_STUDENT_pa,STUDENT_ID,0
SCHD_MS_STAFF_STUDENT_pa,MINUTES,0
SCHD_MS_STAFF_STUDENT_pa,STUSTARTDATE,0
SCHD_MS_STAFF_STUDENT_pa,STUENDDATE,0
SCHD_MS_STAFF_STUDENT_pa,CHANGE_DATE_TIME,0
SCHD_MS_STAFF_STUDENT_pa,CHANGE_UID,0
SCHD_MS_STAFF_USER,DISTRICT,1
SCHD_MS_STAFF_USER,SECTION_KEY,1
SCHD_MS_STAFF_USER,COURSE_SESSION,1
SCHD_MS_STAFF_USER,STAFF_ID,1
SCHD_MS_STAFF_USER,FIELD_NUMBER,1
SCHD_MS_STAFF_USER,START_DATE,1
SCHD_MS_STAFF_USER,SEQUENCE,1
SCHD_MS_STAFF_USER,END_DATE,0
SCHD_MS_STAFF_USER,FIELD_VALUE,0
SCHD_MS_STAFF_USER,CHANGE_DATE_TIME,0
SCHD_MS_STAFF_USER,CHANGE_UID,0
SCHD_MS_STU_FILTER,DISTRICT,1
SCHD_MS_STU_FILTER,PARAM_KEY,1
SCHD_MS_STU_FILTER,FILTER_NUMBER,1
SCHD_MS_STU_FILTER,STUDENT_ID,1
SCHD_MS_STU_FILTER,CHANGE_DATE_TIME,0
SCHD_MS_STU_FILTER,CHANGE_UID,0
SCHD_MS_STUDY_SEAT,DISTRICT,1
SCHD_MS_STUDY_SEAT,SECTION_KEY,1
SCHD_MS_STUDY_SEAT,COURSE_SESSION,1
SCHD_MS_STUDY_SEAT,MARKING_PERIOD,1
SCHD_MS_STUDY_SEAT,CYCLE_CODE,1
SCHD_MS_STUDY_SEAT,USED_SEATS,0
SCHD_MS_STUDY_SEAT,CHANGE_DATE_TIME,0
SCHD_MS_STUDY_SEAT,CHANGE_UID,0
SCHD_MS_SUBJ,DISTRICT,1
SCHD_MS_SUBJ,SECTION_KEY,1
SCHD_MS_SUBJ,COURSE_SESSION,1
SCHD_MS_SUBJ,SUBJECT_AREA,1
SCHD_MS_SUBJ,SUBJ_ORDER,0
SCHD_MS_SUBJ,SUB_AREA,0
SCHD_MS_SUBJ,ROW_IDENTITY,0
SCHD_MS_SUBJ,CHANGE_DATE_TIME,0
SCHD_MS_SUBJ,CHANGE_UID,0
SCHD_MS_SUBJ_TAG,DISTRICT,1
SCHD_MS_SUBJ_TAG,SECTION_KEY,1
SCHD_MS_SUBJ_TAG,COURSE_SESSION,1
SCHD_MS_SUBJ_TAG,SUBJECT_AREA,1
SCHD_MS_SUBJ_TAG,TAG,1
SCHD_MS_SUBJ_TAG,CHANGE_DATE_TIME,0
SCHD_MS_SUBJ_TAG,CHANGE_UID,0
SCHD_MS_USER,DISTRICT,1
SCHD_MS_USER,SECTION_KEY,1
SCHD_MS_USER,SCREEN_NUMBER,1
SCHD_MS_USER,FIELD_NUMBER,1
SCHD_MS_USER,LIST_SEQUENCE,1
SCHD_MS_USER,FIELD_VALUE,0
SCHD_MS_USER,CHANGE_DATE_TIME,0
SCHD_MS_USER,CHANGE_UID,0
SCHD_MSB_MEET_CYC,DISTRICT,1
SCHD_MSB_MEET_CYC,MEETING_KEY,1
SCHD_MSB_MEET_CYC,SEQUENCE_NUM,1
SCHD_MSB_MEET_CYC,CYCLE_CODE,1
SCHD_MSB_MEET_CYC,CHANGE_DATE_TIME,0
SCHD_MSB_MEET_CYC,CHANGE_UID,0
SCHD_MSB_MEET_DET,DISTRICT,1
SCHD_MSB_MEET_DET,MEETING_KEY,1
SCHD_MSB_MEET_DET,SEQUENCE_NUM,1
SCHD_MSB_MEET_DET,JOIN_CONDITION,0
SCHD_MSB_MEET_DET,CYCLES_SELECTED,0
SCHD_MSB_MEET_DET,PERIODS_SELECTED,0
SCHD_MSB_MEET_DET,CHANGE_DATE_TIME,0
SCHD_MSB_MEET_DET,CHANGE_UID,0
SCHD_MSB_MEET_HDR,DISTRICT,1
SCHD_MSB_MEET_HDR,SCHOOL_YEAR,1
SCHD_MSB_MEET_HDR,BUILDING,1
SCHD_MSB_MEET_HDR,MEETING_CODE,1
SCHD_MSB_MEET_HDR,MEETING_KEY,0
SCHD_MSB_MEET_HDR,DESCRIPTION,0
SCHD_MSB_MEET_HDR,CHANGE_DATE_TIME,0
SCHD_MSB_MEET_HDR,CHANGE_UID,0
SCHD_MSB_MEET_PER,DISTRICT,1
SCHD_MSB_MEET_PER,MEETING_KEY,1
SCHD_MSB_MEET_PER,SEQUENCE_NUM,1
SCHD_MSB_MEET_PER,PERIOD,1
SCHD_MSB_MEET_PER,CHANGE_DATE_TIME,0
SCHD_MSB_MEET_PER,CHANGE_UID,0
SCHD_PARAMS,DISTRICT,1
SCHD_PARAMS,SCHOOL_YEAR,1
SCHD_PARAMS,SUMMER_SCHOOL,1
SCHD_PARAMS,BUILDING,1
SCHD_PARAMS,OVERRIDE_SEATS,0
SCHD_PARAMS,OVERRIDE_HOUSETEAM,0
SCHD_PARAMS,IGNORED_PRIORITIES,0
SCHD_PARAMS,STUDENT_ALT,0
SCHD_PARAMS,COURSE_ALT,0
SCHD_PARAMS,STUDENT_COURSE_ALT,0
SCHD_PARAMS,SCHD_INTERVAL,0
SCHD_PARAMS,PRESERVE_SCHEDULE,0
SCHD_PARAMS,BALANCE_CRITERIA,0
SCHD_PARAMS,MAXIMUM_TRIES,0
SCHD_PARAMS,USE_BALANCING,0
SCHD_PARAMS,MAXIMUM_IMBALANCE,0
SCHD_PARAMS,MAXIMUM_RESHUFFLE,0
SCHD_PARAMS,MAXIMUM_RESCHEDULE,0
SCHD_PARAMS,SECONDS_TIMEOUT,0
SCHD_PARAMS,MATCH_PERIODS_ONLY,0
SCHD_PARAMS,CHANGE_DATE_TIME,0
SCHD_PARAMS,CHANGE_UID,0
SCHD_PARAMS_SORT,DISTRICT,1
SCHD_PARAMS_SORT,SCHOOL_YEAR,1
SCHD_PARAMS_SORT,SUMMER_SCHOOL,1
SCHD_PARAMS_SORT,BUILDING,1
SCHD_PARAMS_SORT,SORT_ORDER,1
SCHD_PARAMS_SORT,ORDER_CODE,0
SCHD_PARAMS_SORT,CHANGE_DATE_TIME,0
SCHD_PARAMS_SORT,CHANGE_UID,0
SCHD_PERIOD,DISTRICT,1
SCHD_PERIOD,SCHOOL_YEAR,1
SCHD_PERIOD,SUMMER_SCHOOL,1
SCHD_PERIOD,BUILDING,1
SCHD_PERIOD,CODE,1
SCHD_PERIOD,DESCRIPTION,0
SCHD_PERIOD,PERIOD_ORDER,0
SCHD_PERIOD,STANDARD_PERIOD,0
SCHD_PERIOD,STATE_CODE_EQUIV,0
SCHD_PERIOD,ROW_IDENTITY,0
SCHD_PERIOD,CHANGE_DATE_TIME,0
SCHD_PERIOD,CHANGE_UID,0
SCHD_PREREQ_COURSE_ERR,DISTRICT,1
SCHD_PREREQ_COURSE_ERR,STUDENT_ID,1
SCHD_PREREQ_COURSE_ERR,BUILDING,1
SCHD_PREREQ_COURSE_ERR,COURSE,1
SCHD_PREREQ_COURSE_ERR,ERROR_CODE,1
SCHD_PREREQ_COURSE_ERR,PREREQ_BUILDING,0
SCHD_PREREQ_COURSE_ERR,PREREQ_COURSE,0
SCHD_PREREQ_COURSE_ERR,PREREQ_COURSE_OR_GROUP,0
SCHD_PREREQ_COURSE_ERR,PREREQ_MARK_TYPE,0
SCHD_PREREQ_COURSE_ERR,PREREQ_MIN_MARK,0
SCHD_PREREQ_COURSE_ERR,PREREQ_ACTUAL_MARK,0
SCHD_PREREQ_COURSE_ERR,CHANGE_DATE_TIME,0
SCHD_PREREQ_COURSE_ERR,CHANGE_UID,0
SCHD_REC_TAKEN,DISTRICT,1
SCHD_REC_TAKEN,SECTION_KEY,1
SCHD_REC_TAKEN,LOGIN_ID,1
SCHD_REC_TAKEN,CHANGE_DATE_TIME,0
SCHD_REC_TAKEN,CHANGE_UID,0
SCHD_RESOURCE,DISTRICT,1
SCHD_RESOURCE,BUILDING,1
SCHD_RESOURCE,GROUP_TYPE,1
SCHD_RESOURCE,GROUP_CODE,1
SCHD_RESOURCE,GROUP_DESCRIPTION,0
SCHD_RESOURCE,CHANGE_DATE_TIME,0
SCHD_RESOURCE,CHANGE_UID,0
SCHD_RESTRICTION,DISTRICT,1
SCHD_RESTRICTION,BUILDING,1
SCHD_RESTRICTION,GROUP_TYPE,1
SCHD_RESTRICTION,RESOURCE_ID,1
SCHD_RESTRICTION,PERIOD,1
SCHD_RESTRICTION,MARKING_PERIOD,1
SCHD_RESTRICTION,CYCLE,1
SCHD_RESTRICTION,CHANGE_DATE_TIME,0
SCHD_RESTRICTION,CHANGE_UID,0
SCHD_RUN,DISTRICT,1
SCHD_RUN,BUILDING,1
SCHD_RUN,SCHOOL_YEAR,1
SCHD_RUN,RUN_KEY,1
SCHD_RUN,RUN_LABEL,0
SCHD_RUN,RUN_STATUS,0
SCHD_RUN,RUN_DATE_TIME,0
SCHD_RUN,CHANGE_DATE_TIME,0
SCHD_RUN,CHANGE_UID,0
SCHD_RUN_TABLE,DISTRICT,1
SCHD_RUN_TABLE,TABLE_NAME,1
SCHD_RUN_TABLE,DELETE_VIA_TRIGGER,0
SCHD_RUN_TABLE,HAS_BUILDING,0
SCHD_RUN_TABLE,HAS_SCHOOL_YEAR,0
SCHD_RUN_TABLE,CROSS_TABLE,0
SCHD_RUN_TABLE,KEY_COLUMN,0
SCHD_SCAN_REQUEST,DISTRICT,1
SCHD_SCAN_REQUEST,SCHOOL_YEAR,1
SCHD_SCAN_REQUEST,SUMMER_SCHOOL,1
SCHD_SCAN_REQUEST,BUILDING,1
SCHD_SCAN_REQUEST,SCAN_GUID,0
SCHD_SCAN_REQUEST,COURSE,1
SCHD_SCAN_REQUEST,GRADE,1
SCHD_SCAN_REQUEST,SEQUENCE_NUMBER,0
SCHD_SCAN_REQUEST,PAGE_NUMBER,0
SCHD_SCAN_REQUEST,LINE_NUMBER,0
SCHD_SCAN_REQUEST,CHANGE_DATE_TIME,0
SCHD_SCAN_REQUEST,CHANGE_UID,0
SCHD_STU_CONF_CYC,DISTRICT,1
SCHD_STU_CONF_CYC,STUDENT_ID,1
SCHD_STU_CONF_CYC,SECTION_KEY,1
SCHD_STU_CONF_CYC,MODELED,1
SCHD_STU_CONF_CYC,DATE_RANGE_KEY,1
SCHD_STU_CONF_CYC,COURSE_SESSION,1
SCHD_STU_CONF_CYC,CYCLE_CODE,1
SCHD_STU_CONF_CYC,CHANGE_DATE_TIME,0
SCHD_STU_CONF_CYC,CHANGE_UID,0
SCHD_STU_CONF_MP,DISTRICT,1
SCHD_STU_CONF_MP,STUDENT_ID,1
SCHD_STU_CONF_MP,SECTION_KEY,1
SCHD_STU_CONF_MP,MODELED,1
SCHD_STU_CONF_MP,DATE_RANGE_KEY,1
SCHD_STU_CONF_MP,COURSE_SESSION,1
SCHD_STU_CONF_MP,MARKING_PERIOD,1
SCHD_STU_CONF_MP,CHANGE_DATE_TIME,0
SCHD_STU_CONF_MP,CHANGE_UID,0
SCHD_STU_COURSE,DISTRICT,1
SCHD_STU_COURSE,STUDENT_ID,1
SCHD_STU_COURSE,SECTION_KEY,1
SCHD_STU_COURSE,MODELED,1
SCHD_STU_COURSE,COURSE_STATUS,0
SCHD_STU_COURSE,MODEL_VAL_TYPE,0
SCHD_STU_COURSE,RETAKE,0
SCHD_STU_COURSE,CHANGE_DATE_TIME,0
SCHD_STU_COURSE,CHANGE_UID,0
SCHD_STU_CRS_DATES,DISTRICT,1
SCHD_STU_CRS_DATES,STUDENT_ID,1
SCHD_STU_CRS_DATES,SECTION_KEY,1
SCHD_STU_CRS_DATES,MODELED,1
SCHD_STU_CRS_DATES,DATE_RANGE_KEY,1
SCHD_STU_CRS_DATES,DATE_ADDED,0
SCHD_STU_CRS_DATES,DATE_DROPPED,0
SCHD_STU_CRS_DATES,RESOLVED_CONFLICT,0
SCHD_STU_CRS_DATES,MR_UNGRADED,0
SCHD_STU_CRS_DATES,MR_FIRST_MP,0
SCHD_STU_CRS_DATES,MR_LAST_MP,0
SCHD_STU_CRS_DATES,MR_LAST_MARK_BY,0
SCHD_STU_CRS_DATES,FROM_SECTION_KEY,0
SCHD_STU_CRS_DATES,FROM_RANGE_KEY,0
SCHD_STU_CRS_DATES,TO_SECTION_KEY,0
SCHD_STU_CRS_DATES,TO_RANGE_KEY,0
SCHD_STU_CRS_DATES,ROW_IDENTITY,0
SCHD_STU_CRS_DATES,CHANGE_DATE_TIME,0
SCHD_STU_CRS_DATES,CHANGE_UID,0
SCHD_STU_PREREQOVER,DISTRICT,1
SCHD_STU_PREREQOVER,SCHOOL_YEAR,1
SCHD_STU_PREREQOVER,BUILDING,1
SCHD_STU_PREREQOVER,STUDENT_ID,1
SCHD_STU_PREREQOVER,COURSE,1
SCHD_STU_PREREQOVER,CHANGE_DATE_TIME,0
SCHD_STU_PREREQOVER,CHANGE_UID,0
SCHD_STU_RECOMMEND,DISTRICT,1
SCHD_STU_RECOMMEND,SCHOOL_YEAR,1
SCHD_STU_RECOMMEND,BUILDING,1
SCHD_STU_RECOMMEND,STUDENT_ID,1
SCHD_STU_RECOMMEND,COURSE,1
SCHD_STU_RECOMMEND,STAFF_ID,1
SCHD_STU_RECOMMEND,SECTION_KEY,1
SCHD_STU_RECOMMEND,PRIORITY,0
SCHD_STU_RECOMMEND,ENROLL_COURSE,0
SCHD_STU_RECOMMEND,CHANGE_DATE_TIME,0
SCHD_STU_RECOMMEND,CHANGE_UID,0
SCHD_STU_REQ,DISTRICT,1
SCHD_STU_REQ,SCHOOL_YEAR,1
SCHD_STU_REQ,BUILDING,1
SCHD_STU_REQ,STUDENT_ID,1
SCHD_STU_REQ,SCHD_INTERVAL,1
SCHD_STU_REQ,COURSE,1
SCHD_STU_REQ,COURSE_SECTION,0
SCHD_STU_REQ,TEACHER_OVERLOAD,0
SCHD_STU_REQ,REQUEST_TYPE,0
SCHD_STU_REQ,IS_LOCKED,0
SCHD_STU_REQ,ALT_TO_REQUEST,0
SCHD_STU_REQ,ALTERNATE_SEQUENCE,0
SCHD_STU_REQ,RETAKE,0
SCHD_STU_REQ,CHANGE_DATE_TIME,0
SCHD_STU_REQ,CHANGE_UID,0
SCHD_STU_REQ_MP,DISTRICT,1
SCHD_STU_REQ_MP,SCHOOL_YEAR,1
SCHD_STU_REQ_MP,BUILDING,1
SCHD_STU_REQ_MP,STUDENT_ID,1
SCHD_STU_REQ_MP,SCHD_INTERVAL,1
SCHD_STU_REQ_MP,COURSE,1
SCHD_STU_REQ_MP,MARKING_PERIOD,1
SCHD_STU_REQ_MP,CHANGE_DATE_TIME,0
SCHD_STU_REQ_MP,CHANGE_UID,0
SCHD_STU_STAFF_USER,DISTRICT,1
SCHD_STU_STAFF_USER,SECTION_KEY,1
SCHD_STU_STAFF_USER,COURSE_SESSION,1
SCHD_STU_STAFF_USER,STAFF_ID,1
SCHD_STU_STAFF_USER,STUDENT_ID,1
SCHD_STU_STAFF_USER,START_DATE,1
SCHD_STU_STAFF_USER,SEQUENCE,0
SCHD_STU_STAFF_USER,STAFF_STUDENT_KEY,1
SCHD_STU_STAFF_USER,FIELD_NUMBER,1
SCHD_STU_STAFF_USER,LIST_SEQUENCE,0
SCHD_STU_STAFF_USER,FIELD_VALUE,0
SCHD_STU_STAFF_USER,CHANGE_DATE_TIME,0
SCHD_STU_STAFF_USER,CHANGE_UID,0
SCHD_STU_STATUS,DISTRICT,1
SCHD_STU_STATUS,SCHOOL_YEAR,1
SCHD_STU_STATUS,BUILDING,1
SCHD_STU_STATUS,STUDENT_ID,1
SCHD_STU_STATUS,SCHD_INTERVAL,1
SCHD_STU_STATUS,SCHEDULE_STATUS,0
SCHD_STU_STATUS,REQUEST_STATUS,0
SCHD_STU_STATUS,NUMBER_SINGLETONS,0
SCHD_STU_STATUS,NUMBER_DOUBLETONS,0
SCHD_STU_STATUS,NUMBER_MULTISESS,0
SCHD_STU_STATUS,NUMBER_BLOCKS,0
SCHD_STU_STATUS,CHANGE_DATE_TIME,0
SCHD_STU_STATUS,CHANGE_UID,0
SCHD_STU_USER,DISTRICT,1
SCHD_STU_USER,SECTION_KEY,1
SCHD_STU_USER,DATE_RANGE_KEY,1
SCHD_STU_USER,STUDENT_ID,1
SCHD_STU_USER,SCREEN_NUMBER,1
SCHD_STU_USER,FIELD_NUMBER,1
SCHD_STU_USER,FIELD_VALUE,0
SCHD_STU_USER,CHANGE_DATE_TIME,0
SCHD_STU_USER,CHANGE_UID,0
SCHD_TIMETABLE,DISTRICT,1
SCHD_TIMETABLE,SCHOOL_YEAR,1
SCHD_TIMETABLE,SUMMER_SCHOOL,1
SCHD_TIMETABLE,BUILDING,1
SCHD_TIMETABLE,BELL_SCHD,1
SCHD_TIMETABLE,TIMESLOT,1
SCHD_TIMETABLE,CYCLE,1
SCHD_TIMETABLE,START_TIME,0
SCHD_TIMETABLE,END_TIME,0
SCHD_TIMETABLE,PERIOD,0
SCHD_TIMETABLE,PARENT_CYCLE_DAY,0
SCHD_TIMETABLE,LUNCH_TIME,0
SCHD_TIMETABLE,CHANGE_DATE_TIME,0
SCHD_TIMETABLE,CHANGE_UID,0
SCHD_TIMETABLE_HDR,DISTRICT,1
SCHD_TIMETABLE_HDR,SCHOOL_YEAR,1
SCHD_TIMETABLE_HDR,SUMMER_SCHOOL,1
SCHD_TIMETABLE_HDR,BUILDING,1
SCHD_TIMETABLE_HDR,BELL_SCHD,1
SCHD_TIMETABLE_HDR,HOUSE_TEAM,1
SCHD_TIMETABLE_HDR,CHANGE_DATE_TIME,0
SCHD_TIMETABLE_HDR,CHANGE_UID,0
SCHD_TMP_STU_REQ_LIST,DISTRICT,1
SCHD_TMP_STU_REQ_LIST,LOGIN_ID,1
SCHD_TMP_STU_REQ_LIST,COURSE,1
SCHD_TMP_STU_REQ_LIST,ISOTHERCOURSE,0
SCHD_TMP_STU_REQ_LIST,PAGE_NO,0
SCHD_TMP_STU_REQ_LIST,ROW_NO,0
SCHD_TMP_STU_REQ_LIST,REQUEST_TYPE,0
SCHD_TMP_STU_REQ_LIST,SCHD_INTERVAL,0
SCHD_TMP_STU_REQ_LIST,IS_LOCKED,0
SCHD_TMP_STU_REQ_LIST,COURSE_DESC,0
SCHD_TMP_STU_REQ_LIST,ALT_TO_REQUEST,0
SCHD_TMP_STU_REQ_LIST,ALTERNATE_SEQUENCE,0
SCHD_TMP_STU_REQ_LIST,PREREQUISITE_OVERRIDE,0
SCHD_TMP_STU_REQ_LIST,RETAKE,0
SCHD_TMP_STU_REQ_LIST,CHANGE_DATE_TIME,0
SCHD_TMP_STU_REQ_LIST,CHANGE_UID,0
SCHD_UNSCANNED,DISTRICT,1
SCHD_UNSCANNED,SCHOOL_YEAR,1
SCHD_UNSCANNED,SUMMER_SCHOOL,1
SCHD_UNSCANNED,BUILDING,1
SCHD_UNSCANNED,SCAN_GUID,1
SCHD_UNSCANNED,STUDENT_ID,1
SCHD_UNSCANNED,GRADE,0
SCHD_UNSCANNED,POSTED,0
SCHD_UNSCANNED,PAGE_NUMBER,1
SCHD_UNSCANNED,CHANGE_DATE_TIME,0
SCHD_UNSCANNED,CHANGE_UID,0
SCHD_YREND_RUN,DISTRICT,1
SCHD_YREND_RUN,SCHOOL_YEAR,1
SCHD_YREND_RUN,SUMMER_SCHOOL,1
SCHD_YREND_RUN,RUN_KEY,1
SCHD_YREND_RUN,RUN_DATE,0
SCHD_YREND_RUN,RUN_STATUS,0
SCHD_YREND_RUN,CLEANSCHDDATA,0
SCHD_YREND_RUN,BUILDING_LIST,0
SCHD_YREND_RUN,PURGE_CC,0
SCHD_YREND_RUN,PURGE_BI_YEAR,0
SCHD_YREND_RUN,PURGE_MS_YEAR,0
SCHD_YREND_RUN,PURGE_SS_YEAR,0
SCHD_YREND_RUN,PURGE_SR_YEAR,0
SCHD_YREND_RUN,RESTORE_KEY,0
SCHD_YREND_RUN,CHANGE_DATE_TIME,0
SCHD_YREND_RUN,CHANGE_UID,0
SCHDTB_AR_ALETYPE,DISTRICT,1
SCHDTB_AR_ALETYPE,CODE,1
SCHDTB_AR_ALETYPE,DESCRIPTION,0
SCHDTB_AR_ALETYPE,STATE_CODE_EQUIV,0
SCHDTB_AR_ALETYPE,ACTIVE,0
SCHDTB_AR_ALETYPE,CHANGE_DATE_TIME,0
SCHDTB_AR_ALETYPE,CHANGE_UID,0
SCHDTB_AR_DIG_LRN,DISTRICT,1
SCHDTB_AR_DIG_LRN,CODE,1
SCHDTB_AR_DIG_LRN,DESCRIPTION,0
SCHDTB_AR_DIG_LRN,STATE_EQUIV,0
SCHDTB_AR_DIG_LRN,ACTIVE,0
SCHDTB_AR_DIG_LRN,CHANGE_DATE_TIME,0
SCHDTB_AR_DIG_LRN,CHANGE_UID,0
SCHDTB_AR_DIST_PRO,DISTRICT,1
SCHDTB_AR_DIST_PRO,CODE,1
SCHDTB_AR_DIST_PRO,DESCRIPTION,0
SCHDTB_AR_DIST_PRO,ACTIVE,0
SCHDTB_AR_DIST_PRO,CHANGE_DATE_TIME,0
SCHDTB_AR_DIST_PRO,CHANGE_UID,0
SCHDTB_AR_HQT,DISTRICT,1
SCHDTB_AR_HQT,CODE,1
SCHDTB_AR_HQT,DESCRIPTION,0
SCHDTB_AR_HQT,ACTIVE,0
SCHDTB_AR_HQT,CHANGE_DATE_TIME,0
SCHDTB_AR_HQT,CHANGE_UID,0
SCHDTB_AR_INST,DISTRICT,1
SCHDTB_AR_INST,CODE,1
SCHDTB_AR_INST,DESCRIPTION,0
SCHDTB_AR_INST,ACTIVE,0
SCHDTB_AR_INST,CHANGE_DATE_TIME,0
SCHDTB_AR_INST,CHANGE_UID,0
SCHDTB_AR_JOBCODE,DISTRICT,1
SCHDTB_AR_JOBCODE,CODE,1
SCHDTB_AR_JOBCODE,DESCRIPTION,0
SCHDTB_AR_JOBCODE,ACTIVE,0
SCHDTB_AR_JOBCODE,CHANGE_DATE_TIME,0
SCHDTB_AR_JOBCODE,CHANGE_UID,0
SCHDTB_AR_LEARN,DISTRICT,1
SCHDTB_AR_LEARN,CODE,1
SCHDTB_AR_LEARN,DESCRIPTION,0
SCHDTB_AR_LEARN,ACTIVE,0
SCHDTB_AR_LEARN,CHANGE_DATE_TIME,0
SCHDTB_AR_LEARN,CHANGE_UID,0
SCHDTB_AR_LIC_EX,DISTRICT,1
SCHDTB_AR_LIC_EX,CODE,1
SCHDTB_AR_LIC_EX,DESCRIPTION,0
SCHDTB_AR_LIC_EX,STATE_EQUIV,0
SCHDTB_AR_LIC_EX,ACTIVE,0
SCHDTB_AR_LIC_EX,CHANGE_DATE_TIME,0
SCHDTB_AR_LIC_EX,CHANGE_UID,0
SCHDTB_AR_TRANSVEN,DISTRICT,1
SCHDTB_AR_TRANSVEN,CODE,1
SCHDTB_AR_TRANSVEN,DESCRIPTION,0
SCHDTB_AR_TRANSVEN,STATE_EQUIV,0
SCHDTB_AR_TRANSVEN,ACTIVE,0
SCHDTB_AR_TRANSVEN,CHANGE_DATE_TIME,0
SCHDTB_AR_TRANSVEN,CHANGE_UID,0
SCHDTB_AR_VOCLEA,DISTRICT,1
SCHDTB_AR_VOCLEA,CODE,1
SCHDTB_AR_VOCLEA,DESCRIPTION,0
SCHDTB_AR_VOCLEA,ACTIVE,0
SCHDTB_AR_VOCLEA,CHANGE_DATE_TIME,0
SCHDTB_AR_VOCLEA,CHANGE_UID,0
SCHDTB_COURSE_NCES_CODE,DISTRICT,1
SCHDTB_COURSE_NCES_CODE,CODE,1
SCHDTB_COURSE_NCES_CODE,DESCRIPTION,0
SCHDTB_COURSE_NCES_CODE,STATE_CODE_EQUIV,0
SCHDTB_COURSE_NCES_CODE,ACTIVE,0
SCHDTB_COURSE_NCES_CODE,CHANGE_DATE_TIME,0
SCHDTB_COURSE_NCES_CODE,CHANGE_UID,0
SCHDTB_CREDIT_BASIS,DISTRICT,1
SCHDTB_CREDIT_BASIS,CODE,1
SCHDTB_CREDIT_BASIS,DESCRIPTION,0
SCHDTB_CREDIT_BASIS,ACTIVE,0
SCHDTB_CREDIT_BASIS,PESC_CODE,0
SCHDTB_CREDIT_BASIS,CHANGE_DATE_TIME,0
SCHDTB_CREDIT_BASIS,CHANGE_UID,0
SCHDTB_CREDIT_BASIS_PESC_CODE,DISTRICT,1
SCHDTB_CREDIT_BASIS_PESC_CODE,CODE,1
SCHDTB_CREDIT_BASIS_PESC_CODE,DESCRIPTION,0
SCHDTB_CREDIT_BASIS_PESC_CODE,CHANGE_DATE_TIME,0
SCHDTB_CREDIT_BASIS_PESC_CODE,CHANGE_UID,0
SCHDTB_SIF_CREDIT_TYPE,DISTRICT,1
SCHDTB_SIF_CREDIT_TYPE,CODE,1
SCHDTB_SIF_CREDIT_TYPE,DESCRIPTION,0
SCHDTB_SIF_CREDIT_TYPE,ACTIVE,0
SCHDTB_SIF_CREDIT_TYPE,CHANGE_DATE_TIME,0
SCHDTB_SIF_CREDIT_TYPE,CHANGE_UID,0
SCHDTB_SIF_INSTRUCTIONAL_LEVEL,DISTRICT,1
SCHDTB_SIF_INSTRUCTIONAL_LEVEL,CODE,1
SCHDTB_SIF_INSTRUCTIONAL_LEVEL,DESCRIPTION,0
SCHDTB_SIF_INSTRUCTIONAL_LEVEL,ACTIVE,0
SCHDTB_SIF_INSTRUCTIONAL_LEVEL,STATE_CODE_EQUIV,0
SCHDTB_SIF_INSTRUCTIONAL_LEVEL,CHANGE_DATE_TIME,0
SCHDTB_SIF_INSTRUCTIONAL_LEVEL,CHANGE_UID,0
SCHDTB_STU_COURSE_TRIGGER,DISTRICT,1
SCHDTB_STU_COURSE_TRIGGER,STATE_ABR,0
SCHDTB_STU_COURSE_TRIGGER,MS_SCREEN_NUMBER,1
SCHDTB_STU_COURSE_TRIGGER,MS_FIELD_NUMBER,1
SCHDTB_STU_COURSE_TRIGGER,SC_SCREEN_NUMBER,1
SCHDTB_STU_COURSE_TRIGGER,SC_FIELD_NUMBER,1
SCHDTB_STU_COURSE_TRIGGER,FIELD_LABEL,0
SCHDTB_STU_COURSE_TRIGGER,CHANGE_DATE_TIME,0
SCHDTB_STU_COURSE_TRIGGER,CHANGE_UID,0
SCHOOLOGY_ASMT_XREF,DISTRICT,1
SCHOOLOGY_ASMT_XREF,SECTION_KEY,1
SCHOOLOGY_ASMT_XREF,COURSE_SESSION,1
SCHOOLOGY_ASMT_XREF,ESP_ASMT_NUMBER,1
SCHOOLOGY_ASMT_XREF,SCHOOLOGY_ASMT_ID,0
SCHOOLOGY_ASMT_XREF,CHANGE_DATE_TIME,0
SCHOOLOGY_ASMT_XREF,CHANGE_UID,0
SCHOOLOGY_INTF_DET,DISTRICT,1
SCHOOLOGY_INTF_DET,JOB_GUID,1
SCHOOLOGY_INTF_DET,PAGE_NUM,1
SCHOOLOGY_INTF_DET,RETURN_STRING,0
SCHOOLOGY_INTF_HDR,DISTRICT,1
SCHOOLOGY_INTF_HDR,JOB_GUID,1
SCHOOLOGY_INTF_HDR,CALL_TYPE,0
SCHOOLOGY_INTF_HDR,CALL_DATE_TIME,0
SCHOOLOGY_INTF_HDR,PER_PAGE,0
SCHOOLOGY_INTF_HDR,PAGE_TOTAL,0
SDE_CAMPUS,INSTITUTE_ID,1
SDE_CAMPUS,CAMPUS_ID,1
SDE_CAMPUS,NAME,0
SDE_CAMPUS,CITY,0
SDE_CAMPUS,CAMPUS_STATE,0
SDE_CAMPUS,COUNTRY,0
SDE_CAMPUS,CHANGE_DATE_TIME,0
SDE_CAMPUS,CHANGE_UID,0
SDE_CERT,DISTRICT,1
SDE_CERT,SERIAL_NUMBER,0
SDE_DIST_CFG,DISTRICT,1
SDE_DIST_CFG,INSTITUTION_ID,1
SDE_DIST_CFG,CHANGE_DATE_TIME,0
SDE_DIST_CFG,CHANGE_UID,0
SDE_INSTITUTION,INSTITUTION_ID,1
SDE_INSTITUTION,NAME,0
SDE_INSTITUTION,CITY,0
SDE_INSTITUTION,INSTITUTE_STATE,0
SDE_INSTITUTION,COUNTRY,0
SDE_INSTITUTION,CHANGE_DATE_TIME,0
SDE_INSTITUTION,CHANGE_UID,0
SDE_IPP_TRANSACTIONS_DATA,PROCESS_ID,1
SDE_IPP_TRANSACTIONS_DATA,CURRENT_STATUS,0
SDE_IPP_TRANSACTIONS_DATA,INITIATED_DATE,0
SDE_IPP_TRANSACTIONS_DATA,INITIATED_BY,0
SDE_IPP_TRANSACTIONS_DATA,IDENTITY_VERIFIED_DATE,0
SDE_IPP_TRANSACTIONS_DATA,DATA_AVAILABLE_DATE,0
SDE_IPP_TRANSACTIONS_DATA,COMPLETED_DATE,0
SDE_IPP_TRANSACTIONS_DATA,RECEIVING_INSTITUTION_ID,0
SDE_IPP_TRANSACTIONS_DATA,RECEIVING_CAMPUS_ID,0
SDE_IPP_TRANSACTIONS_DATA,SENDING_INSTITUTION_ID,0
SDE_IPP_TRANSACTIONS_DATA,SENDING_CAMPUS_ID,0
SDE_IPP_TRANSACTIONS_DATA,STUDENT_FIRST_NAME,0
SDE_IPP_TRANSACTIONS_DATA,STUDENT_MIDDLE_NAME,0
SDE_IPP_TRANSACTIONS_DATA,STUDENT_LAST_NAME,0
SDE_IPP_TRANSACTIONS_DATA,STUDENT_BIRTHDATE,0
SDE_IPP_TRANSACTIONS_DATA,STUDENT_GENDER,0
SDE_IPP_TRANSACTIONS_DATA,OLD_LOCAL_STUDENT_ID,0
SDE_IPP_TRANSACTIONS_DATA,OLD_STATE_STUDENT_ID,0
SDE_IPP_TRANSACTIONS_DATA,NEW_LOCAL_STUDENT_ID,0
SDE_IPP_TRANSACTIONS_DATA,NEW_STATE_STUDENT_ID,0
SDE_IPP_TRANSACTIONS_DATA,RECEIVER_NOTES,0
SDE_IPP_TRANSACTIONS_DATA,SENDER_NOTES,0
SDE_IPP_TRANSACTIONS_DATA,CHANGE_UID,0
SDE_IPP_TRANSACTIONS_DATA,CHANGE_DATE_TIME,0
SDE_PESC_IMPORT,DISTRICT,1
SDE_PESC_IMPORT,PROCESS_ID,1
SDE_PESC_IMPORT,INSTITUTE_ID,0
SDE_PESC_IMPORT,STUDENT_ID,0
SDE_PESC_IMPORT,ORIGINAL_PESC_XML,0
SDE_PESC_IMPORT,INTERMEDIATE_ACADEMIC_CHANGES,0
SDE_PESC_IMPORT,INTERMEDIATE_HEALTH_CHANGES,0
SDE_PESC_IMPORT,INTERMEDIATE_TEST_CHANGES,0
SDE_PESC_IMPORT,IMPORTED,0
SDE_PESC_IMPORT,CHANGE_DATE_TIME,0
SDE_PESC_IMPORT,CHANGE_UID,0
SDE_PESC_TRANSCRIPT,PROCESS_ID,1
SDE_PESC_TRANSCRIPT,USER_ID,0
SDE_PESC_TRANSCRIPT,FILENAME,0
SDE_PESC_TRANSCRIPT,COMPLETED,0
SDE_PESC_TRANSCRIPT,PESC_STATUS,0
SDE_PESC_TRANSCRIPT,CHANGE_DATE_TIME,0
SDE_PESC_TRANSCRIPT,CHANGE_UID,0
SDE_SECURITY,DISTRICT,1
SDE_SECURITY,USER_ID,1
SDE_SECURITY,FIRST_NAME,0
SDE_SECURITY,LAST_NAME,0
SDE_SECURITY,EMAIL,0
SDE_SECURITY,CALL_MODE,0
SDE_SECURITY,CAMPUSES,1
SDE_SECURITY,CHANGE_DATE_TIME,0
SDE_SECURITY,CHANGE_UID,0
SDE_TRANSACTION_TIME,INSTITUTION_ID,1
SDE_TRANSACTION_TIME,LAST_FETCH_TIME_TRANSACTION_LOG,0
SDE_TRANSACTION_TIME,LAST_FETCH_TIME_NOTIFICATION,0
SDE_TRANSCRIPT,PROCESS_ID,1
SDE_TRANSCRIPT,PARAM_KEY,0
SDE_TRANSCRIPT,USER_ID,0
SDE_TRANSCRIPT,FILENAME,0
SDE_TRANSCRIPT,COMPLETED,0
SDE_TRANSCRIPT,STATUS,0
SDE_TRANSCRIPT,CHANGE_DATE_TIME,0
SDE_TRANSCRIPT,CHANGE_UID,0
SDE_TRANSCRIPT_CONFIGURATION,DISTRICT,1
SDE_TRANSCRIPT_CONFIGURATION,BUILDING,1
SDE_TRANSCRIPT_CONFIGURATION,PARAM_IDX,1
SDE_TRANSCRIPT_CONFIGURATION,PARAM_NAME,0
SDE_TRANSCRIPT_CONFIGURATION,PARAM_VALUE,0
SDE_TRANSCRIPT_CONFIGURATION,APPLICABLE_TO,1
SDE_TRANSCRIPT_CONFIGURATION,CHANGE_DATE_TIME,0
SDE_TRANSCRIPT_CONFIGURATION,CHANGE_UID,0
SEC_GLOBAL_ID,DISTRICT,1
SEC_GLOBAL_ID,LOGIN_ID,1
SEC_GLOBAL_ID,LOGIN_TYPE,1
SEC_GLOBAL_ID,CHANGE_DATE_TIME,0
SEC_GLOBAL_ID,CHANGE_UID,0
SEC_GLOBAL_ID,GLOBAL_ID,0
SEC_LOOKUP_INFO,DISTRICT,1
SEC_LOOKUP_INFO,MENU_ITEM,1
SEC_LOOKUP_INFO,LOOKUP_ID,1
SEC_LOOKUP_INFO,SEC_TYPE,1
SEC_LOOKUP_INFO,PACKAGE,1
SEC_LOOKUP_INFO,SUBPACKAGE,1
SEC_LOOKUP_INFO,FEATURE,1
SEC_LOOKUP_INFO,READ_WRITE_REQD,0
SEC_LOOKUP_INFO,FUNCTIONALITY_DESC,0
SEC_LOOKUP_INFO,SUBPACKAGE_YEAR_SPEC,0
SEC_LOOKUP_INFO,RESERVED,0
SEC_LOOKUP_INFO,CHANGE_DATE_TIME,0
SEC_LOOKUP_INFO,CHANGE_UID,0
SEC_LOOKUP_MENU_ITEMS,DISTRICT,1
SEC_LOOKUP_MENU_ITEMS,PARENT_MENU,1
SEC_LOOKUP_MENU_ITEMS,SEQUENCE,1
SEC_LOOKUP_MENU_ITEMS,LOOKUP_ID,0
SEC_LOOKUP_MENU_ITEMS,SEARCH_TYPE,0
SEC_LOOKUP_MENU_ITEMS,SORT_TYPE,0
SEC_LOOKUP_MENU_ITEMS,RESERVED,0
SEC_LOOKUP_MENU_ITEMS,CHANGE_DATE_TIME,0
SEC_LOOKUP_MENU_ITEMS,CHANGE_UID,0
SEC_LOOKUP_MENU_REL,DISTRICT,1
SEC_LOOKUP_MENU_REL,SOURCE_MENU_ITEM,1
SEC_LOOKUP_MENU_REL,SOURCE_LOOKUP_ID,1
SEC_LOOKUP_MENU_REL,DEST_MENU_ITEM,1
SEC_LOOKUP_MENU_REL,DEST_LOOKUP_ID,1
SEC_LOOKUP_MENU_REL,RESERVED,0
SEC_LOOKUP_MENU_REL,CHANGE_DATE_TIME,0
SEC_LOOKUP_MENU_REL,CHANGE_UID,0
SEC_LOOKUP_NON_MENU,DISTRICT,1
SEC_LOOKUP_NON_MENU,LOOKUP_ID,1
SEC_LOOKUP_NON_MENU,PAGE_TITLE,0
SEC_LOOKUP_NON_MENU,PAGE_NAME,0
SEC_LOOKUP_NON_MENU,SEARCH_TYPE,0
SEC_LOOKUP_NON_MENU,SORT_TYPE,0
SEC_LOOKUP_NON_MENU,RESERVED,0
SEC_LOOKUP_NON_MENU,CHANGE_DATE_TIME,0
SEC_LOOKUP_NON_MENU,CHANGE_UID,0
SEC_USER,DISTRICT,1
SEC_USER,LOGIN_ID,1
SEC_USER,USER_OR_ROLE,0
SEC_USER,LOGIN_NAME,0
SEC_USER,BUILDING,0
SEC_USER,DEPARTMENT,0
SEC_USER,EMAIL,0
SEC_USER,SCHOOL_YEAR,0
SEC_USER,SUMMER_SCHOOL,0
SEC_USER,USE_MENU_CACHE,0
SEC_USER,MAY_IMPERSONATE,0
SEC_USER,HAS_READ_NEWS,0
SEC_USER,INITIALS,0
SEC_USER,LOCAL_LOGIN_ID,0
SEC_USER,TEACHER_ACCOUNT,0
SEC_USER,CHANGE_DATE_TIME,0
SEC_USER,CHANGE_UID,0
SEC_USER,CLASSLINK_ID,0
SEC_USER,USER_UNIQUE_ID,0
SEC_USER,ROW_IDENTITY,0
SEC_USER_AD,DISTRICT,1
SEC_USER_AD,LOGIN_ID,1
SEC_USER_AD,USER_OR_ROLE,0
SEC_USER_AD,DEACTIVATE,0
SEC_USER_AD,AD_GROUP,0
SEC_USER_AD,REV_REQ_FOR_ADD,0
SEC_USER_AD,REV_REQ_FOR_DEL,0
SEC_USER_AD,REV_EMAIL_ADDRESS,0
SEC_USER_AD,NOT_REQ_FOR_ADD,0
SEC_USER_AD,NOT_REQ_FOR_DEL,0
SEC_USER_AD,NOT_EMAIL_ADDRESS,0
SEC_USER_AD,CHANGE_DATE_TIME,0
SEC_USER_AD,CHANGE_UID,0
SEC_USER_BUILDING,DISTRICT,1
SEC_USER_BUILDING,LOGIN_ID,1
SEC_USER_BUILDING,BUILDING,1
SEC_USER_BUILDING,CHANGE_DATE_TIME,0
SEC_USER_BUILDING,CHANGE_UID,0
SEC_USER_BUILDING,ROW_IDENTITY,0
SEC_USER_MENU_CACHE,DISTRICT,1
SEC_USER_MENU_CACHE,LOGIN_ID,1
SEC_USER_MENU_CACHE,MENU,0
SEC_USER_MENU_CACHE,CHANGE_DATE_TIME,0
SEC_USER_MENU_CACHE,CHANGE_UID,0
SEC_USER_RESOURCE,DISTRICT,1
SEC_USER_RESOURCE,LOGIN_ID,1
SEC_USER_RESOURCE,ROLE_ID,1
SEC_USER_RESOURCE,PACKAGE,1
SEC_USER_RESOURCE,SUBPACKAGE,1
SEC_USER_RESOURCE,FEATURE,1
SEC_USER_RESOURCE,BUILDING,1
SEC_USER_RESOURCE,ACCESS_TYPE,0
SEC_USER_RESOURCE,CHANGE_DATE_TIME,0
SEC_USER_RESOURCE,CHANGE_UID,0
SEC_USER_ROLE,DISTRICT,1
SEC_USER_ROLE,LOGIN_ID,1
SEC_USER_ROLE,ROLE_ID,1
SEC_USER_ROLE,DEF_BUILDING_OVR,0
SEC_USER_ROLE,CHANGE_DATE_TIME,0
SEC_USER_ROLE,CHANGE_UID,0
SEC_USER_ROLE,ROW_IDENTITY,0
SEC_USER_ROLE_BLDG_OVR,DISTRICT,1
SEC_USER_ROLE_BLDG_OVR,LOGIN_ID,1
SEC_USER_ROLE_BLDG_OVR,ROLE_ID,1
SEC_USER_ROLE_BLDG_OVR,BUILDING,1
SEC_USER_ROLE_BLDG_OVR,CHANGE_DATE_TIME,0
SEC_USER_ROLE_BLDG_OVR,CHANGE_UID,0
SEC_USER_ROLE_BLDG_OVR,ROW_IDENTITY,0
SEC_USER_STAFF,DISTRICT,1
SEC_USER_STAFF,LOGIN_ID,1
SEC_USER_STAFF,STAFF_ID,1
SEC_USER_STAFF,CHANGE_DATE_TIME,0
SEC_USER_STAFF,CHANGE_UID,0
SECTB_ACTION_FEATURE,DISTRICT,1
SECTB_ACTION_FEATURE,AREA,1
SECTB_ACTION_FEATURE,CONTROLLER,1
SECTB_ACTION_FEATURE,ACTION,1
SECTB_ACTION_FEATURE,FEATURE_ID,1
SECTB_ACTION_FEATURE,PACKAGE,0
SECTB_ACTION_FEATURE,SUBPACKAGE,0
SECTB_ACTION_FEATURE,FEATURE,0
SECTB_ACTION_FEATURE,DESCRIPTION,0
SECTB_ACTION_FEATURE,BUILDING_ACCESS_LEVEL,0
SECTB_ACTION_FEATURE,RESERVED,0
SECTB_ACTION_FEATURE,CHANGE_DATE_TIME,0
SECTB_ACTION_FEATURE,CHANGE_UID,0
SECTB_ACTION_FEATURE,TAC_ACCESS,0
SECTB_ACTION_RESOURCE,DISTRICT,1
SECTB_ACTION_RESOURCE,AREA,1
SECTB_ACTION_RESOURCE,CONTROLLER,1
SECTB_ACTION_RESOURCE,ACTION,1
SECTB_ACTION_RESOURCE,PACKAGE,0
SECTB_ACTION_RESOURCE,SUBPACKAGE,0
SECTB_ACTION_RESOURCE,FEATURE,0
SECTB_ACTION_RESOURCE,ENV_SUBPACKAGE,0
SECTB_ACTION_RESOURCE,DESCRIPTION,0
SECTB_ACTION_RESOURCE,BUILDING_ACCESS_LEVEL,0
SECTB_ACTION_RESOURCE,RESERVED,0
SECTB_ACTION_RESOURCE,CHANGE_DATE_TIME,0
SECTB_ACTION_RESOURCE,CHANGE_UID,0
SECTB_PACKAGE,DISTRICT,1
SECTB_PACKAGE,PACKAGE,1
SECTB_PACKAGE,DESCRIPTION,0
SECTB_PACKAGE,IS_ADVANCED_FEATURE,0
SECTB_PACKAGE,RESERVED,0
SECTB_PACKAGE,LICENSE_KEY,0
SECTB_PACKAGE,IS_VALID,0
SECTB_PACKAGE,CHANGE_DATE_TIME,0
SECTB_PACKAGE,CHANGE_UID,0
SECTB_PAGE_RESOURCE,DISTRICT,1
SECTB_PAGE_RESOURCE,MENU_ID,1
SECTB_PAGE_RESOURCE,MENU_TYPE,1
SECTB_PAGE_RESOURCE,PACKAGE,0
SECTB_PAGE_RESOURCE,SUBPACKAGE,0
SECTB_PAGE_RESOURCE,FEATURE,0
SECTB_PAGE_RESOURCE,ENV_SUBPACKAGE,0
SECTB_PAGE_RESOURCE,DESCRIPTION,0
SECTB_PAGE_RESOURCE,BUILDING_ACCESS_LEVEL,0
SECTB_PAGE_RESOURCE,RESERVED,0
SECTB_PAGE_RESOURCE,CHANGE_DATE_TIME,0
SECTB_PAGE_RESOURCE,CHANGE_UID,0
SECTB_RESOURCE,DISTRICT,1
SECTB_RESOURCE,PACKAGE,1
SECTB_RESOURCE,SUBPACKAGE,1
SECTB_RESOURCE,FEATURE,1
SECTB_RESOURCE,DESCRIPTION,0
SECTB_RESOURCE,RESERVED,0
SECTB_RESOURCE,BLDG_LIST_REQUIRED,0
SECTB_RESOURCE,ADVANCED_FEATURE,0
SECTB_RESOURCE,CHANGE_DATE_TIME,0
SECTB_RESOURCE,CHANGE_UID,0
SECTB_SUBPACKAGE,DISTRICT,1
SECTB_SUBPACKAGE,SUBPACKAGE,1
SECTB_SUBPACKAGE,DESCRIPTION,0
SECTB_SUBPACKAGE,RESERVED,0
SECTB_SUBPACKAGE,CHANGE_DATE_TIME,0
SECTB_SUBPACKAGE,CHANGE_UID,0
SIF_AGENT_CFG,DISTRICT,1
SIF_AGENT_CFG,AGENT_ID,1
SIF_AGENT_CFG,AGENT_NAME,0
SIF_AGENT_CFG,SUMMER_SCHOOL,0
SIF_AGENT_CFG,IS_REGISTERED,0
SIF_AGENT_CFG,IS_RUNNING,0
SIF_AGENT_CFG,MAX_BUFFER,0
SIF_AGENT_CFG,SIF_VERSION,0
SIF_AGENT_CFG,SIF_MODE,0
SIF_AGENT_CFG,POLL_INTERVAL,0
SIF_AGENT_CFG,SIF_PROTOCOL,0
SIF_AGENT_CFG,AGENT_URL,0
SIF_AGENT_CFG,ZIS_URL,0
SIF_AGENT_CFG,ZIS_RETRIES,0
SIF_AGENT_CFG,ZIS_ID,0
SIF_AGENT_CFG,AGENT_WAKE_TIME,0
SIF_AGENT_CFG,AGENT_SLEEP_TIME,0
SIF_AGENT_CFG,PROXY_SERVER,0
SIF_AGENT_CFG,MAX_LOG_DAYS,0
SIF_AGENT_CFG,LOG_LEVEL,0
SIF_AGENT_CFG,LAST_LOG_PURGE,0
SIF_AGENT_CFG,CFG_DB_NAME,0
SIF_AGENT_CFG,PUSH_TO_URL,0
SIF_AGENT_CFG,CHANGE_DATE_TIME,0
SIF_AGENT_CFG,CHANGE_UID,0
SIF_EVENT_DET,TRANSACTION_ID,1
SIF_EVENT_DET,COLUMN_NAME,1
SIF_EVENT_DET,NEW_VALUE,0
SIF_EVENT_DET,CHANGE_DATE_TIME,0
SIF_EVENT_DET,CHANGE_UID,0
SIF_EVENT_HDR,DISTRICT,1
SIF_EVENT_HDR,TRANSACTION_ID,1
SIF_EVENT_HDR,SIF_EVENT,1
SIF_EVENT_HDR,ACTION_TYPE,0
SIF_EVENT_HDR,SUMMER_SCHOOL,0
SIF_EVENT_HDR,SIF_MESSAGE,0
SIF_EVENT_HDR,CHANGE_DATE_TIME,0
SIF_EVENT_HDR,CHANGE_UID,0
SIF_EXTENDED_MAP,DISTRICT,1
SIF_EXTENDED_MAP,AGENT_ID,1
SIF_EXTENDED_MAP,SIF_EVENT,1
SIF_EXTENDED_MAP,ELEMENT_NAME,1
SIF_EXTENDED_MAP,TABLE_NAME,0
SIF_EXTENDED_MAP,COLUMN_NAME,0
SIF_EXTENDED_MAP,FORMAT_TYPE,0
SIF_EXTENDED_MAP,DATA_TYPE,0
SIF_EXTENDED_MAP,DATA_LENGTH,0
SIF_EXTENDED_MAP,DEFAULT_VALUE,0
SIF_EXTENDED_MAP,VALIDATION_LIST,0
SIF_EXTENDED_MAP,VALIDATION_TABLE,0
SIF_EXTENDED_MAP,CODE_COLUMN,0
SIF_EXTENDED_MAP,SIF_CODE_COLUMN,0
SIF_EXTENDED_MAP,PUBLISH,0
SIF_EXTENDED_MAP,PROVIDE,0
SIF_EXTENDED_MAP,SUBSCRIBE,0
SIF_EXTENDED_MAP,CHANGE_DATE_TIME,0
SIF_EXTENDED_MAP,CHANGE_UID,0
SIF_GUID_ATT_CLASS,DISTRICT,1
SIF_GUID_ATT_CLASS,SCHOOL_YEAR,1
SIF_GUID_ATT_CLASS,SUMMER_SCHOOL,1
SIF_GUID_ATT_CLASS,BUILDING,1
SIF_GUID_ATT_CLASS,STUDENT_ID,1
SIF_GUID_ATT_CLASS,ATTENDANCE_DATE,1
SIF_GUID_ATT_CLASS,ATTENDANCE_PERIOD,1
SIF_GUID_ATT_CLASS,SEQUENCE_NUM,1
SIF_GUID_ATT_CLASS,SIF_REFID,0
SIF_GUID_ATT_CLASS,CHANGE_DATE_TIME,0
SIF_GUID_ATT_CLASS,CHANGE_UID,0
SIF_GUID_ATT_CODE,DISTRICT,1
SIF_GUID_ATT_CODE,BUILDING,1
SIF_GUID_ATT_CODE,SCHOOL_YEAR,1
SIF_GUID_ATT_CODE,SUMMER_SCHOOL,1
SIF_GUID_ATT_CODE,ATTENDANCE_CODE,1
SIF_GUID_ATT_CODE,SIF_REFID,0
SIF_GUID_ATT_CODE,CHANGE_DATE_TIME,0
SIF_GUID_ATT_CODE,CHANGE_UID,0
SIF_GUID_ATT_DAILY,DISTRICT,1
SIF_GUID_ATT_DAILY,SCHOOL_YEAR,1
SIF_GUID_ATT_DAILY,SUMMER_SCHOOL,1
SIF_GUID_ATT_DAILY,BUILDING,1
SIF_GUID_ATT_DAILY,STUDENT_ID,1
SIF_GUID_ATT_DAILY,ATTENDANCE_DATE,1
SIF_GUID_ATT_DAILY,ATTENDANCE_PERIOD,1
SIF_GUID_ATT_DAILY,SEQUENCE_NUM,1
SIF_GUID_ATT_DAILY,SIF_REFID,0
SIF_GUID_ATT_DAILY,CHANGE_DATE_TIME,0
SIF_GUID_ATT_DAILY,CHANGE_UID,0
SIF_GUID_AUTH,DISTRICT,1
SIF_GUID_AUTH,PERSON_ID,1
SIF_GUID_AUTH,SIF_REFID_TYPE,1
SIF_GUID_AUTH,SYSTEM_TYPE,1
SIF_GUID_AUTH,SYSTEM_VALUE,1
SIF_GUID_AUTH,SIF_REFID,0
SIF_GUID_AUTH,CHANGE_DATE_TIME,0
SIF_GUID_AUTH,CHANGE_UID,0
SIF_GUID_BUILDING,DISTRICT,1
SIF_GUID_BUILDING,BUILDING,1
SIF_GUID_BUILDING,SIF_REFID,0
SIF_GUID_BUILDING,CHANGE_DATE_TIME,0
SIF_GUID_BUILDING,CHANGE_UID,0
SIF_GUID_BUS_DETAIL,DISTRICT,0
SIF_GUID_BUS_DETAIL,BUSROUTEINFOREFID,0
SIF_GUID_BUS_DETAIL,BUSSTOPINFOREFID,0
SIF_GUID_BUS_DETAIL,STOP_TIME,0
SIF_GUID_BUS_DETAIL,SIF_REFID,1
SIF_GUID_BUS_DETAIL,CHANGE_DATE_TIME,0
SIF_GUID_BUS_DETAIL,CHANGE_UID,0
SIF_GUID_BUS_INFO,DISTRICT,0
SIF_GUID_BUS_INFO,BUS_NUMBER,0
SIF_GUID_BUS_INFO,SIF_REFID,1
SIF_GUID_BUS_INFO,CHANGE_DATE_TIME,0
SIF_GUID_BUS_INFO,CHANGE_UID,0
SIF_GUID_BUS_ROUTE,DISTRICT,0
SIF_GUID_BUS_ROUTE,BUSINFOREFID,0
SIF_GUID_BUS_ROUTE,BUS_ROUTE,0
SIF_GUID_BUS_ROUTE,TRAVEL_DIRECTION,0
SIF_GUID_BUS_ROUTE,SIF_REFID,1
SIF_GUID_BUS_ROUTE,CHANGE_DATE_TIME,0
SIF_GUID_BUS_ROUTE,CHANGE_UID,0
SIF_GUID_BUS_STOP,DISTRICT,0
SIF_GUID_BUS_STOP,STOP_DESCRIPTION,0
SIF_GUID_BUS_STOP,SIF_REFID,1
SIF_GUID_BUS_STOP,CHANGE_DATE_TIME,0
SIF_GUID_BUS_STOP,CHANGE_UID,0
SIF_GUID_BUS_STU,DISTRICT,1
SIF_GUID_BUS_STU,STUDENT_ID,1
SIF_GUID_BUS_STU,TRAVEL_DIRECTION,1
SIF_GUID_BUS_STU,TRAVEL_TRIP,1
SIF_GUID_BUS_STU,TRAVEL_SEGMENT,1
SIF_GUID_BUS_STU,SIF_REFID,0
SIF_GUID_BUS_STU,CHANGE_DATE_TIME,0
SIF_GUID_BUS_STU,CHANGE_UID,0
SIF_GUID_CALENDAR_SUMMARY,DISTRICT,1
SIF_GUID_CALENDAR_SUMMARY,BUILDING,1
SIF_GUID_CALENDAR_SUMMARY,SCHOOL_YEAR,1
SIF_GUID_CALENDAR_SUMMARY,SUMMER_SCHOOL,1
SIF_GUID_CALENDAR_SUMMARY,TRACK,1
SIF_GUID_CALENDAR_SUMMARY,CALENDAR,1
SIF_GUID_CALENDAR_SUMMARY,SIF_REFID,0
SIF_GUID_CALENDAR_SUMMARY,CHANGE_DATE_TIME,0
SIF_GUID_CALENDAR_SUMMARY,CHANGE_UID,0
SIF_GUID_CONTACT,DISTRICT,1
SIF_GUID_CONTACT,CONTACT_ID,1
SIF_GUID_CONTACT,STUDENT_ID,1
SIF_GUID_CONTACT,CONTACT_TYPE,1
SIF_GUID_CONTACT,SIF_REFID,0
SIF_GUID_CONTACT,SIF_CONTACT_ID,0
SIF_GUID_CONTACT,CHANGE_DATE_TIME,0
SIF_GUID_CONTACT,CHANGE_UID,0
SIF_GUID_COURSE,DISTRICT,1
SIF_GUID_COURSE,BUILDING,1
SIF_GUID_COURSE,COURSE,1
SIF_GUID_COURSE,SIF_REFID,0
SIF_GUID_COURSE,CHANGE_DATE_TIME,0
SIF_GUID_COURSE,CHANGE_UID,0
SIF_GUID_CRS_SESS,DISTRICT,1
SIF_GUID_CRS_SESS,SECTION_KEY,1
SIF_GUID_CRS_SESS,COURSE_SESSION,1
SIF_GUID_CRS_SESS,SIF_REFID,0
SIF_GUID_CRS_SESS,CHANGE_DATE_TIME,0
SIF_GUID_CRS_SESS,CHANGE_UID,0
SIF_GUID_DISTRICT,DISTRICT,1
SIF_GUID_DISTRICT,SIF_REFID,0
SIF_GUID_DISTRICT,CHANGE_DATE_TIME,0
SIF_GUID_DISTRICT,CHANGE_UID,0
SIF_GUID_GB_ASMT,DISTRICT,1
SIF_GUID_GB_ASMT,SECTION_KEY,1
SIF_GUID_GB_ASMT,COURSE_SESSION,1
SIF_GUID_GB_ASMT,ASMT_NUMBER,1
SIF_GUID_GB_ASMT,SIF_REFID,0
SIF_GUID_GB_ASMT,CHANGE_DATE_TIME,0
SIF_GUID_GB_ASMT,CHANGE_UID,0
SIF_GUID_HOSPITAL,DISTRICT,1
SIF_GUID_HOSPITAL,CODE,1
SIF_GUID_HOSPITAL,SIF_REFID,0
SIF_GUID_HOSPITAL,CHANGE_DATE_TIME,0
SIF_GUID_HOSPITAL,CHANGE_UID,0
SIF_GUID_IEP,DISTRICT,1
SIF_GUID_IEP,STUDENT_ID,1
SIF_GUID_IEP,SIF_REFID,0
SIF_GUID_IEP,CHANGE_DATE_TIME,0
SIF_GUID_IEP,CHANGE_UID,0
SIF_GUID_MED_ALERT,DISTRICT,1
SIF_GUID_MED_ALERT,CODE,1
SIF_GUID_MED_ALERT,SIF_REFID,0
SIF_GUID_MED_ALERT,CHANGE_DATE_TIME,0
SIF_GUID_MED_ALERT,CHANGE_UID,0
SIF_GUID_PROGRAM,DISTRICT,1
SIF_GUID_PROGRAM,STUDENT_ID,1
SIF_GUID_PROGRAM,PROGRAM_ID,1
SIF_GUID_PROGRAM,FIELD_NUMBER,1
SIF_GUID_PROGRAM,START_DATE,1
SIF_GUID_PROGRAM,SIF_REFID,0
SIF_GUID_PROGRAM,CHANGE_DATE_TIME,0
SIF_GUID_PROGRAM,CHANGE_UID,0
SIF_GUID_REG_EW,DISTRICT,1
SIF_GUID_REG_EW,STUDENT_ID,1
SIF_GUID_REG_EW,ENTRY_WD_TYPE,1
SIF_GUID_REG_EW,SCHOOL_YEAR,1
SIF_GUID_REG_EW,ENTRY_DATE,1
SIF_GUID_REG_EW,SIF_REFID,0
SIF_GUID_REG_EW,CHANGE_DATE_TIME,0
SIF_GUID_REG_EW,CHANGE_UID,0
SIF_GUID_ROOM,DISTRICT,1
SIF_GUID_ROOM,BUILDING,1
SIF_GUID_ROOM,ROOM_ID,1
SIF_GUID_ROOM,SIF_REFID,0
SIF_GUID_ROOM,CHANGE_DATE_TIME,0
SIF_GUID_ROOM,CHANGE_UID,0
SIF_GUID_STAFF,DISTRICT,1
SIF_GUID_STAFF,STAFF_ID,1
SIF_GUID_STAFF,SIF_REFID,0
SIF_GUID_STAFF,CHANGE_DATE_TIME,0
SIF_GUID_STAFF,CHANGE_UID,0
SIF_GUID_STAFF_BLD,DISTRICT,1
SIF_GUID_STAFF_BLD,BUILDING,1
SIF_GUID_STAFF_BLD,STAFF_ID,1
SIF_GUID_STAFF_BLD,SIF_REFID,0
SIF_GUID_STAFF_BLD,CHANGE_DATE_TIME,0
SIF_GUID_STAFF_BLD,CHANGE_UID,0
SIF_GUID_STU_SESS,DISTRICT,1
SIF_GUID_STU_SESS,STUDENT_ID,1
SIF_GUID_STU_SESS,SECTION_KEY,1
SIF_GUID_STU_SESS,COURSE_SESSION,1
SIF_GUID_STU_SESS,DATE_RANGE_KEY,1
SIF_GUID_STU_SESS,SIF_REFID,0
SIF_GUID_STU_SESS,CHANGE_DATE_TIME,0
SIF_GUID_STU_SESS,CHANGE_UID,0
SIF_GUID_STUDENT,DISTRICT,1
SIF_GUID_STUDENT,STUDENT_ID,1
SIF_GUID_STUDENT,SIF_REFID,0
SIF_GUID_STUDENT,CHANGE_DATE_TIME,0
SIF_GUID_STUDENT,CHANGE_UID,0
SIF_GUID_TERM,DISTRICT,1
SIF_GUID_TERM,BUILDING,1
SIF_GUID_TERM,SCHOOL_YEAR,1
SIF_GUID_TERM,TRACK,1
SIF_GUID_TERM,MARKING_PERIOD,1
SIF_GUID_TERM,SIF_REFID,0
SIF_GUID_TERM,CHANGE_DATE_TIME,0
SIF_GUID_TERM,CHANGE_UID,0
SIF_LOGFILE,LOG_ID,1
SIF_LOGFILE,DISTRICT,0
SIF_LOGFILE,AGENT_ID,0
SIF_LOGFILE,MESSAGE_REFID,0
SIF_LOGFILE,SOURCE_ID,0
SIF_LOGFILE,OBJECT_NAME,0
SIF_LOGFILE,MESSAGE_TYPE,0
SIF_LOGFILE,MESSAGE_XML,0
SIF_LOGFILE,WEBSERVICE_XML,0
SIF_LOGFILE,ERROR_MESSAGE,0
SIF_LOGFILE,LOG_DATETIME,0
SIF_PROGRAM_COLUMN,DISTRICT,1
SIF_PROGRAM_COLUMN,AGENT_ID,1
SIF_PROGRAM_COLUMN,PROGRAM_ID,1
SIF_PROGRAM_COLUMN,FIELD_NUMBER,1
SIF_PROGRAM_COLUMN,PROVIDE,0
SIF_PROGRAM_COLUMN,PUBLISH,0
SIF_PROGRAM_COLUMN,SUBSCRIBE,0
SIF_PROGRAM_COLUMN,SERVICE_CODE_TYPE,0
SIF_PROGRAM_COLUMN,ELEMENT_NAME,0
SIF_PROGRAM_COLUMN,CHANGE_DATE_TIME,0
SIF_PROGRAM_COLUMN,CHANGE_UID,0
SIF_PROVIDE,DISTRICT,1
SIF_PROVIDE,AGENT_ID,1
SIF_PROVIDE,SIF_EVENT,1
SIF_PROVIDE,MESSAGE_ID,0
SIF_PROVIDE,CHANGE_DATE_TIME,0
SIF_PROVIDE,CHANGE_UID,0
SIF_PUBLISH,DISTRICT,1
SIF_PUBLISH,AGENT_ID,1
SIF_PUBLISH,SIF_EVENT,1
SIF_PUBLISH,MESSAGE_ID,0
SIF_PUBLISH,CHANGE_DATE_TIME,0
SIF_PUBLISH,CHANGE_UID,0
SIF_REQUEST_QUEUE,MESSAGE_ID,1
SIF_REQUEST_QUEUE,DISTRICT,0
SIF_REQUEST_QUEUE,AGENT_ID,0
SIF_REQUEST_QUEUE,SIF_EVENT,0
SIF_REQUEST_QUEUE,CHANGE_DATE_TIME,0
SIF_REQUEST_QUEUE,CHANGE_UID,0
SIF_RESPOND,DISTRICT,1
SIF_RESPOND,AGENT_ID,1
SIF_RESPOND,SIF_EVENT,1
SIF_RESPOND,MESSAGE_ID,0
SIF_RESPOND,CHANGE_DATE_TIME,0
SIF_RESPOND,CHANGE_UID,0
SIF_SUBSCRIBE,DISTRICT,1
SIF_SUBSCRIBE,AGENT_ID,1
SIF_SUBSCRIBE,SIF_EVENT,1
SIF_SUBSCRIBE,MESSAGE_ID,0
SIF_SUBSCRIBE,CHANGE_DATE_TIME,0
SIF_SUBSCRIBE,CHANGE_UID,0
SIF_USER_FIELD,DISTRICT,1
SIF_USER_FIELD,AGENT_ID,1
SIF_USER_FIELD,SIF_EVENT,1
SIF_USER_FIELD,ELEMENT_NAME,1
SIF_USER_FIELD,SCREEN_TYPE,0
SIF_USER_FIELD,SCREEN_NUMBER,0
SIF_USER_FIELD,FIELD_NUMBER,0
SIF_USER_FIELD,FORMAT_TYPE,0
SIF_USER_FIELD,VALIDATION_TABLE,0
SIF_USER_FIELD,CODE_COLUMN,0
SIF_USER_FIELD,SIF_CODE_COLUMN,0
SIF_USER_FIELD,YES_VALUES_LIST,0
SIF_USER_FIELD,PUBLISH,0
SIF_USER_FIELD,PROVIDE,0
SIF_USER_FIELD,SUBSCRIBE,0
SIF_USER_FIELD,CHANGE_DATE_TIME,0
SIF_USER_FIELD,CHANGE_UID,0
SMS_CFG,REPORT_CLEANUP,1
SMS_CFG,CHANGE_DATE_TIME,0
SMS_CFG,CHANGE_UID,0
SMS_PROGRAM_RULES,DISTRICT,1
SMS_PROGRAM_RULES,PROGRAM_ID,1
SMS_PROGRAM_RULES,FIELD_NUMBER,1
SMS_PROGRAM_RULES,FIELD_ATTRIBUTE,0
SMS_PROGRAM_RULES,GROUP_NUMBER,1
SMS_PROGRAM_RULES,RULE_NUMBER,1
SMS_PROGRAM_RULES,RULE_OPERATOR,0
SMS_PROGRAM_RULES,RULE_VALUE,0
SMS_PROGRAM_RULES,RULE_TABLE,0
SMS_PROGRAM_RULES,RULE_COLUMN,0
SMS_PROGRAM_RULES,RULE_IDENTIFIER,0
SMS_PROGRAM_RULES,RULE_FIELD_NUMBER,0
SMS_PROGRAM_RULES,RULE_FIELD_ATTRIBUTE,0
SMS_PROGRAM_RULES,WHERE_TABLE,0
SMS_PROGRAM_RULES,WHERE_COLUMN,0
SMS_PROGRAM_RULES,WHERE_IDENTIFIER,0
SMS_PROGRAM_RULES,WHERE_FIELD_NUMBER,0
SMS_PROGRAM_RULES,WHERE_FIELD_ATTRIBUTE,0
SMS_PROGRAM_RULES,WHERE_OPERATOR,0
SMS_PROGRAM_RULES,WHERE_VALUE,0
SMS_PROGRAM_RULES,AND_OR_FLAG,0
SMS_PROGRAM_RULES,CHANGE_DATE_TIME,0
SMS_PROGRAM_RULES,CHANGE_UID,0
SMS_PROGRAM_RULES_MESSAGES,DISTRICT,1
SMS_PROGRAM_RULES_MESSAGES,PROGRAM_ID,1
SMS_PROGRAM_RULES_MESSAGES,FIELD_NUMBER,1
SMS_PROGRAM_RULES_MESSAGES,GROUP_NUMBER,1
SMS_PROGRAM_RULES_MESSAGES,ERROR_MESSAGE,0
SMS_PROGRAM_RULES_MESSAGES,SHOW_CUSTOM_MESSAGE,0
SMS_PROGRAM_RULES_MESSAGES,SHOW_BOTH,0
SMS_PROGRAM_RULES_MESSAGES,CHANGE_DATE_TIME,0
SMS_PROGRAM_RULES_MESSAGES,CHANGE_UID,0
SMS_USER_FIELDS,DISTRICT,1
SMS_USER_FIELDS,SCREEN_TYPE,1
SMS_USER_FIELDS,SCREEN_NUMBER,1
SMS_USER_FIELDS,FIELD_NUMBER,1
SMS_USER_FIELDS,FIELD_LABEL,0
SMS_USER_FIELDS,STATE_CODE_EQUIV,0
SMS_USER_FIELDS,FIELD_ORDER,0
SMS_USER_FIELDS,REQUIRED_FIELD,0
SMS_USER_FIELDS,FIELD_TYPE,0
SMS_USER_FIELDS,DATA_TYPE,0
SMS_USER_FIELDS,NUMBER_TYPE,0
SMS_USER_FIELDS,DATA_LENGTH,0
SMS_USER_FIELDS,FIELD_SCALE,0
SMS_USER_FIELDS,FIELD_PRECISION,0
SMS_USER_FIELDS,DEFAULT_VALUE,0
SMS_USER_FIELDS,DEFAULT_TABLE,0
SMS_USER_FIELDS,DEFAULT_COLUMN,0
SMS_USER_FIELDS,VALIDATION_LIST,0
SMS_USER_FIELDS,VALIDATION_TABLE,0
SMS_USER_FIELDS,CODE_COLUMN,0
SMS_USER_FIELDS,DESCRIPTION_COLUMN,0
SMS_USER_FIELDS,SPI_TABLE,0
SMS_USER_FIELDS,SPI_COLUMN,0
SMS_USER_FIELDS,SPI_SCREEN_NUMBER,0
SMS_USER_FIELDS,SPI_FIELD_NUMBER,0
SMS_USER_FIELDS,SPI_FIELD_TYPE,0
SMS_USER_FIELDS,INCLUDE_PERFPLUS,0
SMS_USER_FIELDS,SEC_PACKAGE,0
SMS_USER_FIELDS,SEC_SUBPACKAGE,0
SMS_USER_FIELDS,SEC_FEATURE,0
SMS_USER_FIELDS,CHANGE_DATE_TIME,0
SMS_USER_FIELDS,CHANGE_UID,0
SMS_USER_RULES,DISTRICT,1
SMS_USER_RULES,SCREEN_TYPE,1
SMS_USER_RULES,SCREEN_NUMBER,1
SMS_USER_RULES,FIELD_NUMBER,1
SMS_USER_RULES,GROUP_NUMBER,1
SMS_USER_RULES,RULE_NUMBER,1
SMS_USER_RULES,RULE_OPERATOR,0
SMS_USER_RULES,RULE_VALUE,0
SMS_USER_RULES,RULE_TABLE,0
SMS_USER_RULES,RULE_COLUMN,0
SMS_USER_RULES,RULE_SCREEN_NUMBER,0
SMS_USER_RULES,RULE_FIELD_NUMBER,0
SMS_USER_RULES,WHERE_TABLE,0
SMS_USER_RULES,WHERE_COLUMN,0
SMS_USER_RULES,WHERE_SCREEN_NUM,0
SMS_USER_RULES,WHERE_FIELD_NUMBER,0
SMS_USER_RULES,WHERE_OPERATOR,0
SMS_USER_RULES,WHERE_VALUE,0
SMS_USER_RULES,AND_OR_FLAG,0
SMS_USER_RULES,CHANGE_DATE_TIME,0
SMS_USER_RULES,CHANGE_UID,0
SMS_USER_RULES_MESSAGES,DISTRICT,1
SMS_USER_RULES_MESSAGES,SCREEN_TYPE,1
SMS_USER_RULES_MESSAGES,SCREEN_NUMBER,1
SMS_USER_RULES_MESSAGES,FIELD_NUMBER,1
SMS_USER_RULES_MESSAGES,GROUP_NUMBER,1
SMS_USER_RULES_MESSAGES,ERROR_MESSAGE,0
SMS_USER_RULES_MESSAGES,SHOW_CUSTOM_MESSAGE,0
SMS_USER_RULES_MESSAGES,SHOW_BOTH,0
SMS_USER_RULES_MESSAGES,CHANGE_DATE_TIME,0
SMS_USER_RULES_MESSAGES,CHANGE_UID,0
SMS_USER_SCREEN,DISTRICT,1
SMS_USER_SCREEN,SCREEN_TYPE,1
SMS_USER_SCREEN,SCREEN_NUMBER,1
SMS_USER_SCREEN,LIST_TYPE,0
SMS_USER_SCREEN,COLUMNS,0
SMS_USER_SCREEN,DESCRIPTION,0
SMS_USER_SCREEN,REQUIRED_SCREEN,0
SMS_USER_SCREEN,SEC_PACKAGE,0
SMS_USER_SCREEN,SEC_SUBPACKAGE,0
SMS_USER_SCREEN,SEC_FEATURE,0
SMS_USER_SCREEN,RESERVED,0
SMS_USER_SCREEN,STATE_FLAG,0
SMS_USER_SCREEN,CHANGE_DATE_TIME,0
SMS_USER_SCREEN,CHANGE_UID,0
SMS_USER_SCREEN_COMB_DET,DISTRICT,1
SMS_USER_SCREEN_COMB_DET,COMBINED_SCREEN_TYPE,1
SMS_USER_SCREEN_COMB_DET,COMBINED_SCREEN_NUMBER,1
SMS_USER_SCREEN_COMB_DET,SCREEN_TYPE,1
SMS_USER_SCREEN_COMB_DET,SCREEN_NUMBER,1
SMS_USER_SCREEN_COMB_DET,SCREEN_ORDER,0
SMS_USER_SCREEN_COMB_DET,HIDE_ON_MENU,0
SMS_USER_SCREEN_COMB_DET,CHANGE_DATE_TIME,0
SMS_USER_SCREEN_COMB_DET,CHANGE_UID,0
SMS_USER_SCREEN_COMB_HDR,DISTRICT,1
SMS_USER_SCREEN_COMB_HDR,COMBINED_SCREEN_TYPE,1
SMS_USER_SCREEN_COMB_HDR,COMBINED_SCREEN_NUMBER,1
SMS_USER_SCREEN_COMB_HDR,DESCRIPTION,0
SMS_USER_SCREEN_COMB_HDR,SEC_PACKAGE,0
SMS_USER_SCREEN_COMB_HDR,SEC_SUBPACKAGE,0
SMS_USER_SCREEN_COMB_HDR,SEC_FEATURE,0
SMS_USER_SCREEN_COMB_HDR,RESERVED,0
SMS_USER_SCREEN_COMB_HDR,CHANGE_DATE_TIME,0
SMS_USER_SCREEN_COMB_HDR,CHANGE_UID,0
SMS_USER_TABLE,DISTRICT,1
SMS_USER_TABLE,TABLE_NAME,1
SMS_USER_TABLE,PACKAGE,1
SMS_USER_TABLE,TABLE_DESCR,0
SMS_USER_TABLE,CHANGE_DATE_TIME,0
SMS_USER_TABLE,CHANGE_UID,0
SPI_API_VAL_COLUMN,DISTRICT,1
SPI_API_VAL_COLUMN,TABLE_NAME,1
SPI_API_VAL_COLUMN,COLUMN_NAME,1
SPI_API_VAL_COLUMN,COLUMN_ORDER,0
SPI_API_VAL_COLUMN,JSON_PROPERTY_NAME,0
SPI_API_VAL_COLUMN,CHANGE_DATE_TIME,0
SPI_API_VAL_COLUMN,CHANGE_UID,0
SPI_API_VAL_SCOPE,DISTRICT,1
SPI_API_VAL_SCOPE,TABLE_NAME,1
SPI_API_VAL_SCOPE,SCOPE,1
SPI_API_VAL_SCOPE,SQL_WHERE,0
SPI_API_VAL_SCOPE,CHANGE_DATE_TIME,0
SPI_API_VAL_SCOPE,CHANGE_UID,0
SPI_API_VAL_TABLE,DISTRICT,1
SPI_API_VAL_TABLE,TABLE_NAME,1
SPI_API_VAL_TABLE,JSON_PROPERTY_NAME,0
SPI_API_VAL_TABLE,SQL_WHERE,0
SPI_API_VAL_TABLE,CHANGE_DATE_TIME,0
SPI_API_VAL_TABLE,CHANGE_UID,0
SPI_APPUSERDEF,PARENT_MENU,0
SPI_APPUSERDEF,PAGE,0
SPI_APPUSERDEF,SCREEN_TYPE,0
SPI_AUDIT_DET1,KEY_GUID,1
SPI_AUDIT_DET1,REC_INDEX,1
SPI_AUDIT_DET1,DISTRICT,0
SPI_AUDIT_DET1,TABLE_NAME,0
SPI_AUDIT_DET1,USER_ID,0
SPI_AUDIT_DET1,TWS_USER_ID,0
SPI_AUDIT_DET1,MOD_DATE,0
SPI_AUDIT_DET1,UPDATE_MODE,0
SPI_AUDIT_DET1,DATA_FIELD_01,0
SPI_AUDIT_DET1,DATA_VALUE_01,0
SPI_AUDIT_DET1,DATA_FIELD_02,0
SPI_AUDIT_DET1,DATA_VALUE_02,0
SPI_AUDIT_DET1,DATA_FIELD_03,0
SPI_AUDIT_DET1,DATA_VALUE_03,0
SPI_AUDIT_DET1,DATA_FIELD_04,0
SPI_AUDIT_DET1,DATA_VALUE_04,0
SPI_AUDIT_DET1,DATA_FIELD_05,0
SPI_AUDIT_DET1,DATA_VALUE_05,0
SPI_AUDIT_DET1,DATA_FIELD_06,0
SPI_AUDIT_DET1,DATA_VALUE_06,0
SPI_AUDIT_DET1,DATA_FIELD_07,0
SPI_AUDIT_DET1,DATA_VALUE_07,0
SPI_AUDIT_DET1,DATA_FIELD_08,0
SPI_AUDIT_DET1,DATA_VALUE_08,0
SPI_AUDIT_DET1,DATA_FIELD_09,0
SPI_AUDIT_DET1,DATA_VALUE_09,0
SPI_AUDIT_DET1,DATA_FIELD_10,0
SPI_AUDIT_DET1,DATA_VALUE_10,0
SPI_AUDIT_DET1,DATA_FIELD_11,0
SPI_AUDIT_DET1,DATA_VALUE_11,0
SPI_AUDIT_DET1,DATA_FIELD_12,0
SPI_AUDIT_DET1,DATA_VALUE_12,0
SPI_AUDIT_DET1,DATA_FIELD_13,0
SPI_AUDIT_DET1,DATA_VALUE_13,0
SPI_AUDIT_DET1,DATA_FIELD_14,0
SPI_AUDIT_DET1,DATA_VALUE_14,0
SPI_AUDIT_DET1,DATA_FIELD_15,0
SPI_AUDIT_DET1,DATA_VALUE_15,0
SPI_AUDIT_DET1,DATA_FIELD_16,0
SPI_AUDIT_DET1,DATA_VALUE_16,0
SPI_AUDIT_DET1,DATA_FIELD_17,0
SPI_AUDIT_DET1,DATA_VALUE_17,0
SPI_AUDIT_DET1,DATA_FIELD_18,0
SPI_AUDIT_DET1,DATA_VALUE_18,0
SPI_AUDIT_DET1,DATA_FIELD_19,0
SPI_AUDIT_DET1,DATA_VALUE_19,0
SPI_AUDIT_DET1,DATA_FIELD_20,0
SPI_AUDIT_DET1,DATA_VALUE_20,0
SPI_AUDIT_DET1,DATA_FIELD_21,0
SPI_AUDIT_DET1,DATA_VALUE_21,0
SPI_AUDIT_DET1,DATA_FIELD_22,0
SPI_AUDIT_DET1,DATA_VALUE_22,0
SPI_AUDIT_DET1,DATA_FIELD_23,0
SPI_AUDIT_DET1,DATA_VALUE_23,0
SPI_AUDIT_DET1,DATA_FIELD_24,0
SPI_AUDIT_DET1,DATA_VALUE_24,0
SPI_AUDIT_DET1,DATA_FIELD_25,0
SPI_AUDIT_DET1,DATA_VALUE_25,0
SPI_AUDIT_DET2,KEY_GUID,1
SPI_AUDIT_DET2,REC_INDEX,1
SPI_AUDIT_DET2,DATA_FIELD_26,0
SPI_AUDIT_DET2,DATA_VALUE_26,0
SPI_AUDIT_DET2,DATA_FIELD_27,0
SPI_AUDIT_DET2,DATA_VALUE_27,0
SPI_AUDIT_DET2,DATA_FIELD_28,0
SPI_AUDIT_DET2,DATA_VALUE_28,0
SPI_AUDIT_DET2,DATA_FIELD_29,0
SPI_AUDIT_DET2,DATA_VALUE_29,0
SPI_AUDIT_DET2,DATA_FIELD_30,0
SPI_AUDIT_DET2,DATA_VALUE_30,0
SPI_AUDIT_DET2,DATA_FIELD_31,0
SPI_AUDIT_DET2,DATA_VALUE_31,0
SPI_AUDIT_DET2,DATA_FIELD_32,0
SPI_AUDIT_DET2,DATA_VALUE_32,0
SPI_AUDIT_DET2,DATA_FIELD_33,0
SPI_AUDIT_DET2,DATA_VALUE_33,0
SPI_AUDIT_DET2,DATA_FIELD_34,0
SPI_AUDIT_DET2,DATA_VALUE_34,0
SPI_AUDIT_DET2,DATA_FIELD_35,0
SPI_AUDIT_DET2,DATA_VALUE_35,0
SPI_AUDIT_DET2,DATA_FIELD_36,0
SPI_AUDIT_DET2,DATA_VALUE_36,0
SPI_AUDIT_DET2,DATA_FIELD_37,0
SPI_AUDIT_DET2,DATA_VALUE_37,0
SPI_AUDIT_DET2,DATA_FIELD_38,0
SPI_AUDIT_DET2,DATA_VALUE_38,0
SPI_AUDIT_DET2,DATA_FIELD_39,0
SPI_AUDIT_DET2,DATA_VALUE_39,0
SPI_AUDIT_DET2,DATA_FIELD_40,0
SPI_AUDIT_DET2,DATA_VALUE_40,0
SPI_AUDIT_DET2,DATA_FIELD_41,0
SPI_AUDIT_DET2,DATA_VALUE_41,0
SPI_AUDIT_DET2,DATA_FIELD_42,0
SPI_AUDIT_DET2,DATA_VALUE_42,0
SPI_AUDIT_DET2,DATA_FIELD_43,0
SPI_AUDIT_DET2,DATA_VALUE_43,0
SPI_AUDIT_DET2,DATA_FIELD_44,0
SPI_AUDIT_DET2,DATA_VALUE_44,0
SPI_AUDIT_DET2,DATA_FIELD_45,0
SPI_AUDIT_DET2,DATA_VALUE_45,0
SPI_AUDIT_DET2,DATA_FIELD_46,0
SPI_AUDIT_DET2,DATA_VALUE_46,0
SPI_AUDIT_DET2,DATA_FIELD_47,0
SPI_AUDIT_DET2,DATA_VALUE_47,0
SPI_AUDIT_DET2,DATA_FIELD_48,0
SPI_AUDIT_DET2,DATA_VALUE_48,0
SPI_AUDIT_DET2,DATA_FIELD_49,0
SPI_AUDIT_DET2,DATA_VALUE_49,0
SPI_AUDIT_DET2,DATA_FIELD_50,0
SPI_AUDIT_DET2,DATA_VALUE_50,0
SPI_AUDIT_HISTORY,CHANGE_ID,1
SPI_AUDIT_HISTORY,SERVER_NAME,0
SPI_AUDIT_HISTORY,TABLE_NAME,0
SPI_AUDIT_HISTORY,CHANGE_TYPE,0
SPI_AUDIT_HISTORY,CHANGE_DATE_TIME,0
SPI_AUDIT_HISTORY,CHANGE_UID,0
SPI_AUDIT_HISTORY_FIELDS,CHANGE_ID,1
SPI_AUDIT_HISTORY_FIELDS,COLUMN_NAME,1
SPI_AUDIT_HISTORY_FIELDS,INITIAL_VALUE,0
SPI_AUDIT_HISTORY_FIELDS,NEW_VALUE,0
SPI_AUDIT_HISTORY_KEYS,CHANGE_ID,1
SPI_AUDIT_HISTORY_KEYS,KEY_FIELD,1
SPI_AUDIT_HISTORY_KEYS,KEY_VALUE,0
SPI_AUDIT_SESS,KEY_GUID,1
SPI_AUDIT_SESS,LOGON_USER,0
SPI_AUDIT_SESS,SERVER_NAME,0
SPI_AUDIT_SESS,REMOTE_ADDR,0
SPI_AUDIT_SESS,USER_AGENT,0
SPI_AUDIT_SESS,PATH_INFO,0
SPI_AUDIT_SESS,HTTP_REFERER,0
SPI_AUDIT_SESS,QUERY_STRING,0
SPI_AUDIT_TASK,PARAM_KEY,1
SPI_AUDIT_TASK,RUN_TIME,1
SPI_AUDIT_TASK,DISTRICT,0
SPI_AUDIT_TASK,TASK_OWNER,0
SPI_AUDIT_TASK,TASK_DESCRIPTION,0
SPI_AUDIT_TASK_PAR,PARAM_KEY,1
SPI_AUDIT_TASK_PAR,PARAM_IDX,1
SPI_AUDIT_TASK_PAR,RUN_TIME,1
SPI_AUDIT_TASK_PAR,IS_ENV_PARAM,0
SPI_AUDIT_TASK_PAR,PARAM_NAME,0
SPI_AUDIT_TASK_PAR,PARAM_VALUE,0
SPI_BACKUP_TABLES,PACKAGE,1
SPI_BACKUP_TABLES,TABLE_NAME,1
SPI_BACKUP_TABLES,RESTORE_ORDER,0
SPI_BACKUP_TABLES,JOIN_CONDITION,0
SPI_BLDG_PACKAGE,DISTRICT,1
SPI_BLDG_PACKAGE,BUILDING,1
SPI_BLDG_PACKAGE,PACKAGE,1
SPI_BLDG_PACKAGE,CHANGE_DATE_TIME,0
SPI_BLDG_PACKAGE,CHANGE_UID,0
SPI_BUILDING_LIST,DISTRICT,1
SPI_BUILDING_LIST,OPTION_TYPE,1
SPI_BUILDING_LIST,LIST_PAGE_TITLE,0
SPI_BUILDING_LIST,TABLE_NAME,0
SPI_BUILDING_LIST,NAVIGATE_TO,0
SPI_BUILDING_LIST,USE_SCHOOL_YEAR,0
SPI_BUILDING_LIST,USE_SUMMER_SCHOOL,0
Spi_checklist_menu_items,DISTRICT,0
Spi_checklist_menu_items,PAGE_ID,0
Spi_checklist_menu_items,DESCRIPTION,0
Spi_checklist_menu_items,URL,0
Spi_checklist_menu_items,RESERVED,0
Spi_checklist_menu_items,CHANGE_DATE_TIME,0
Spi_checklist_menu_items,CHANGE_UID,0
SPI_CHECKLIST_RESULTS,DISTRICT,1
SPI_CHECKLIST_RESULTS,BUILDING,1
SPI_CHECKLIST_RESULTS,CHECKLIST_CODE,1
SPI_CHECKLIST_RESULTS,CHECKLIST_RUN_WHEN,1
SPI_CHECKLIST_RESULTS,RC_RUN,1
SPI_CHECKLIST_RESULTS,CHECKLIST_ORDER,1
SPI_CHECKLIST_RESULTS,IS_DONE,0
SPI_CHECKLIST_RESULTS,CHANGE_DATE_TIME,0
SPI_CHECKLIST_RESULTS,CHANGE_UID,0
SPI_CHECKLIST_SETUP_DET,DISTRICT,1
SPI_CHECKLIST_SETUP_DET,BUILDING,1
SPI_CHECKLIST_SETUP_DET,CHECKLIST_CODE,1
SPI_CHECKLIST_SETUP_DET,CHECKLIST_RUN_WHEN,1
SPI_CHECKLIST_SETUP_DET,RC_RUN,1
SPI_CHECKLIST_SETUP_DET,CHECKLIST_ORDER,1
SPI_CHECKLIST_SETUP_DET,PAGE_ID,0
SPI_CHECKLIST_SETUP_DET,CHECKLIST_ITEM_NOTE,0
SPI_CHECKLIST_SETUP_DET,CHANGE_DATE_TIME,0
SPI_CHECKLIST_SETUP_DET,CHANGE_UID,0
SPI_CHECKLIST_SETUP_HDR,DISTRICT,1
SPI_CHECKLIST_SETUP_HDR,BUILDING,1
SPI_CHECKLIST_SETUP_HDR,CHECKLIST_CODE,1
SPI_CHECKLIST_SETUP_HDR,CHECKLIST_RUN_WHEN,1
SPI_CHECKLIST_SETUP_HDR,RC_RUN,1
SPI_CHECKLIST_SETUP_HDR,CHECKLIST_DESCRIPTION,0
SPI_CHECKLIST_SETUP_HDR,PACKAGE,0
SPI_CHECKLIST_SETUP_HDR,NOTE_TEXT,0
SPI_CHECKLIST_SETUP_HDR,CHANGE_DATE_TIME,0
SPI_CHECKLIST_SETUP_HDR,CHANGE_UID,0
SPI_CODE_IN_USE,DISTRICT,1
SPI_CODE_IN_USE,TABLE_NAME,1
SPI_CODE_IN_USE,COLUMN_NAME,1
SPI_CODE_IN_USE,FOREIGN_KEY_TABLE_NAME,1
SPI_CODE_IN_USE,FOREIGN_KEY_COLUMN_NAME,1
SPI_CODE_IN_USE,USE_ENV_DISTRICT,0
SPI_CODE_IN_USE,USE_ENV_SCHOOL_YEAR,0
SPI_CODE_IN_USE,USE_ENV_SUMMER_SCHOOL,0
SPI_CODE_IN_USE,CRITERIA,0
SPI_CODE_IN_USE,CHANGE_DATE_TIME,0
SPI_CODE_IN_USE,CHANGE_UID,0
SPI_CODE_IN_USE_FILTER,DISTRICT,1
SPI_CODE_IN_USE_FILTER,TABLE_NAME,1
SPI_CODE_IN_USE_FILTER,COLUMN_NAME,1
SPI_CODE_IN_USE_FILTER,FOREIGN_KEY_TABLE_NAME,1
SPI_CODE_IN_USE_FILTER,FOREIGN_KEY_COLUMN_NAME,1
SPI_CODE_IN_USE_FILTER,FILTER_COLUMN_NAME,1
SPI_CODE_IN_USE_FILTER,CHANGE_DATE_TIME,0
SPI_CODE_IN_USE_FILTER,CHANGE_UID,0
SPI_COLUMN_CONTROL,COLUMNCONTROLID,1
SPI_COLUMN_CONTROL,TABLENAME,0
SPI_COLUMN_CONTROL,COLUMNNAME,0
SPI_COLUMN_CONTROL,CONTROLTYPEID,0
SPI_COLUMN_CONTROL,RESERVED,0
SPI_COLUMN_CONTROL,CHANGE_DATE_TIME,0
SPI_COLUMN_CONTROL,CHANGE_UID,0
SPI_COLUMN_INFO,DISTRICT,1
SPI_COLUMN_INFO,TABLE_NAME,1
SPI_COLUMN_INFO,COLUMN_NAME,1
SPI_COLUMN_INFO,UI_CONTROL_TYPE,0
SPI_COLUMN_INFO,VAL_LIST,0
SPI_COLUMN_INFO,VAL_LIST_DISP,0
SPI_COLUMN_INFO,VAL_TBL_NAME,0
SPI_COLUMN_INFO,VAL_COL_CODE,0
SPI_COLUMN_INFO,VAL_COL_DESC,0
SPI_COLUMN_INFO,VAL_SQL_WHERE,0
SPI_COLUMN_INFO,VAL_ORDER_BY_CODE,0
SPI_COLUMN_INFO,VAL_DISP_FORMAT,0
SPI_COLUMN_INFO,SEC_PACKAGE,0
SPI_COLUMN_INFO,SEC_SUBPACKAGE,0
SPI_COLUMN_INFO,SEC_FEATURE,0
SPI_COLUMN_INFO,COLUMN_WIDTH,0
SPI_COLUMN_INFO,CHANGE_DATE_TIME,0
SPI_COLUMN_INFO,CHANGE_UID,0
SPI_COLUMN_INFO,SOUNDS_LIKE,0
SPI_COLUMN_NAMES,DISTRICT,1
SPI_COLUMN_NAMES,TABLE_NAME,1
SPI_COLUMN_NAMES,COLUMN_NAME,1
SPI_COLUMN_NAMES,CULTURE_CODE,1
SPI_COLUMN_NAMES,COLUMN_DESCRIPTION,0
SPI_COLUMN_NAMES,CHANGE_DATE_TIME,0
SPI_COLUMN_NAMES,CHANGE_UID,0
SPI_COLUMN_VALIDATION,DISTRICT,1
SPI_COLUMN_VALIDATION,TABLE_NAME,1
SPI_COLUMN_VALIDATION,COLUMN_NAME,1
SPI_COLUMN_VALIDATION,VAL_LIST,0
SPI_COLUMN_VALIDATION,VAL_LIST_DISP,0
SPI_COLUMN_VALIDATION,VAL_TBL_NAME,0
SPI_COLUMN_VALIDATION,VAL_COL_CODE,0
SPI_COLUMN_VALIDATION,VAL_COL_DESC,0
SPI_COLUMN_VALIDATION,VAL_SQL_WHERE,0
SPI_COLUMN_VALIDATION,RESERVED,0
SPI_COLUMN_VALIDATION,CHANGE_DATE_TIME,0
SPI_COLUMN_VALIDATION,CHANGE_UID,0
SPI_CONFIG_EXTENSION,CONFIG_ID,1
SPI_CONFIG_EXTENSION,TABLE_NAME,0
SPI_CONFIG_EXTENSION,SCHOOL_YEAR_REQUIRED,0
SPI_CONFIG_EXTENSION,SUMMER_SCHOOL_REQUIRED,0
SPI_CONFIG_EXTENSION,BUILDING_REQUIRED,0
SPI_CONFIG_EXTENSION,CONFIG_TYPE_REQUIRED,0
SPI_CONFIG_EXTENSION_DETAIL,DETAIL_ID,1
SPI_CONFIG_EXTENSION_DETAIL,ENV_ID,0
SPI_CONFIG_EXTENSION_DETAIL,CONFIG_ID,0
SPI_CONFIG_EXTENSION_DETAIL,PRODUCT,0
SPI_CONFIG_EXTENSION_DETAIL,DATA,0
SPI_CONFIG_EXTENSION_DETAIL,DATA_TYPE,0
SPI_CONFIG_EXTENSION_DETAIL,CHANGE_DATE_TIME,0
SPI_CONFIG_EXTENSION_DETAIL,CHANGE_UID,0
SPI_CONFIG_EXTENSION_ENVIRONMENT,ENV_ID,1
SPI_CONFIG_EXTENSION_ENVIRONMENT,DISTRICT,0
SPI_CONFIG_EXTENSION_ENVIRONMENT,SCHOOL_YEAR,0
SPI_CONFIG_EXTENSION_ENVIRONMENT,SUMMER_SCHOOL,0
SPI_CONFIG_EXTENSION_ENVIRONMENT,BUILDING,0
SPI_CONFIG_EXTENSION_ENVIRONMENT,CONFIG_TYPE,0
SPI_CONVERT,DISTRICT,0
SPI_CONVERT,DESCRIPTION,0
SPI_CONVERT,CATEGORY,0
SPI_CONVERT,INDEX1,0
SPI_CONVERT,INDEX2,0
SPI_CONVERT,INDEX3,0
SPI_CONVERT,INDEX4,0
SPI_CONVERT,INDEX5,0
SPI_CONVERT,INDEX6,0
SPI_CONVERT,FIELD_VALUE,0
SPI_CONVERT,LOADED,0
SPI_CONVERT,ID_NUM,1
SPI_CONVERT,CHANGE_DATE_TIME,0
SPI_CONVERT,CHANGE_UID,0
SPI_CONVERT_CONTACT,DISTRICT,1
SPI_CONVERT_CONTACT,STUDENT_ID,1
SPI_CONVERT_CONTACT,CONTACT_ID,1
SPI_CONVERT_CONTACT,FIRST_NAME,0
SPI_CONVERT_CONTACT,MIDDLE_NAME,0
SPI_CONVERT_CONTACT,LAST_NAME,0
SPI_CONVERT_CONTACT,APARTMENT,0
SPI_CONVERT_CONTACT,LOT,0
SPI_CONVERT_CONTACT,STREET,0
SPI_CONVERT_CONTACT,CITY,0
SPI_CONVERT_CONTACT,STATE,0
SPI_CONVERT_CONTACT,ZIPCODE,0
SPI_CONVERT_CONTACT,PHONE,0
SPI_CONVERT_ERROR_LOG,DISTRICT,1
SPI_CONVERT_ERROR_LOG,RUN_ID,1
SPI_CONVERT_ERROR_LOG,RUN_TIME,1
SPI_CONVERT_ERROR_LOG,RUN_ORDER,1
SPI_CONVERT_ERROR_LOG,PACKAGE_ID,0
SPI_CONVERT_ERROR_LOG,PROC_NAME,0
SPI_CONVERT_ERROR_LOG,TABLE_NAME,0
SPI_CONVERT_ERROR_LOG,ERROR_ID,0
SPI_CONVERT_ERROR_LOG,LINE_NUMBER,0
SPI_CONVERT_ERROR_LOG,SQL_STATEMENT,0
SPI_CONVERT_ERROR_LOG,ERROR_DESCRIPTION,0
SPI_CONVERT_ERROR_LOG,SEVERITY,0
SPI_CONVERT_ERROR_LOG,KEY1_COLNAME,0
SPI_CONVERT_ERROR_LOG,KEY1_VALUE,0
SPI_CONVERT_ERROR_LOG,KEY2_COLNAME,0
SPI_CONVERT_ERROR_LOG,KEY2_VALUE,0
SPI_CONVERT_ERROR_LOG,KEY3_COLNAME,0
SPI_CONVERT_ERROR_LOG,KEY3_VALUE,0
SPI_CONVERT_ERROR_LOG,KEY4_COLNAME,0
SPI_CONVERT_ERROR_LOG,KEY4_VALUE,0
SPI_CONVERT_ERROR_LOG,KEY5_COLNAME,0
SPI_CONVERT_ERROR_LOG,KEY5_VALUE,0
SPI_CONVERT_ERROR_LOG,KEY6_COLNAME,0
SPI_CONVERT_ERROR_LOG,KEY6_VALUE,0
SPI_CONVERT_ERROR_LOG,KEY7_COLNAME,0
SPI_CONVERT_ERROR_LOG,KEY7_VALUE,0
SPI_CONVERT_ERROR_LOG,KEY8_COLNAME,0
SPI_CONVERT_ERROR_LOG,KEY8_VALUE,0
SPI_CONVERT_ERROR_LOG,KEY9_COLNAME,0
SPI_CONVERT_ERROR_LOG,KEY9_VALUE,0
SPI_CONVERT_MAP,DISTRICT,1
SPI_CONVERT_MAP,TABLE_NAME,1
SPI_CONVERT_MAP,FIELD_NAME,1
SPI_CONVERT_MAP,INDEX1_DESC,0
SPI_CONVERT_MAP,INDEX2_DESC,0
SPI_CONVERT_MAP,INDEX3_DESC,0
SPI_CONVERT_MAP,INDEX4_DESC,0
SPI_CONVERT_MAP,INDEX5_DESC,0
SPI_CONVERT_MAP,INDEX6_DESC,0
SPI_CONVERT_MAP,VAL_TABLE,0
SPI_CONVERT_MAP,VAL_FIELD,0
SPI_CONVERT_MAP,CATEGORY,0
SPI_CONVERT_MAP,CHANGE_DATE_TIME,0
SPI_CONVERT_MAP,CHANGE_UID,0
SPI_CONVERT_STAFF,DISTRICT,0
SPI_CONVERT_STAFF,BUILDING,0
SPI_CONVERT_STAFF,OS_TEA_NUMBER,0
SPI_CONVERT_STAFF,STAFF_ID,0
SPI_CONVERT_STAFF,FIRST_NAME,0
SPI_CONVERT_STAFF,LAST_NAME,0
SPI_CONVERT_STAFF,SSN,0
SPI_CONVERT_TYPE,DISTRICT,1
SPI_CONVERT_TYPE,CATEGORY,1
SPI_CONVERT_TYPE,INDEX1_DESC,0
SPI_CONVERT_TYPE,INDEX2_DESC,0
SPI_CONVERT_TYPE,INDEX3_DESC,0
SPI_CONVERT_TYPE,INDEX4_DESC,0
SPI_CONVERT_TYPE,INDEX5_DESC,0
SPI_CONVERT_TYPE,INDEX6_DESC,0
SPI_CONVERT_TYPE,CHANGE_DATE_TIME,0
SPI_CONVERT_TYPE,CHANGE_UID,0
SPI_COPY_CALC,DISTRICT,1
SPI_COPY_CALC,TABLE_NAME,1
SPI_COPY_CALC,COLUMN_NAME,1
SPI_COPY_CALC,PROCESS_ACTION,0
SPI_COPY_CALC,RESERVED,0
SPI_COPY_CALC,CHANGE_DATE_TIME,0
SPI_COPY_CALC,CHANGE_UID,0
SPI_COPY_DET,DISTRICT,1
SPI_COPY_DET,COPY_ID,1
SPI_COPY_DET,TABLE_NAME,1
SPI_COPY_DET,ORDER_WITHIN_ID,0
SPI_COPY_DET,WHERE_BUILDING,0
SPI_COPY_DET,WHERE_SCHOOL_YEAR,0
SPI_COPY_DET,WHERE_SUMMER,0
SPI_COPY_DET,WHERE_ALL_BUILDINGS,0
SPI_COPY_DET,SKIP_IF_YEAR_DIFFERS,0
SPI_COPY_DET,RESERVED,0
SPI_COPY_DET,CHANGE_DATE_TIME,0
SPI_COPY_DET,CHANGE_UID,0
SPI_COPY_HDR,DISTRICT,1
SPI_COPY_HDR,COPY_ID,1
SPI_COPY_HDR,COPY_ID_ORDER,0
SPI_COPY_HDR,SEC_PACKAGE,0
SPI_COPY_HDR,TITLE,0
SPI_COPY_HDR,PACKAGE_ORDER,0
SPI_COPY_HDR,ROW_POSITION,0
SPI_COPY_HDR,COLUMN_POSITION,0
SPI_COPY_HDR,SCHOOL_YEAR_DIFFER,0
SPI_COPY_HDR,SUMMER_DIFFER,0
SPI_COPY_HDR,RESERVED,0
SPI_COPY_HDR,CHANGE_DATE_TIME,0
SPI_COPY_HDR,CHANGE_UID,0
SPI_COPY_JOIN,DISTRICT,1
SPI_COPY_JOIN,TABLE_NAME,1
SPI_COPY_JOIN,COLUMN_NAME,1
SPI_COPY_JOIN,HDR_TABLE_NAME,1
SPI_COPY_JOIN,HDR_COLUMN_NAME,1
SPI_COPY_JOIN,RESERVED,0
SPI_COPY_JOIN,CHANGE_DATE_TIME,0
SPI_COPY_JOIN,CHANGE_UID,0
SPI_COPY_LINK,DISTRICT,1
SPI_COPY_LINK,COPY_ID,1
SPI_COPY_LINK,LINK_COPY_ID,1
SPI_COPY_LINK,RESERVED,0
SPI_COPY_LINK,CHANGE_DATE_TIME,0
SPI_COPY_LINK,CHANGE_UID,0
SPI_COPY_MS_DET,DISTRICT,1
SPI_COPY_MS_DET,TABLE_NAME,1
SPI_COPY_MS_DET,RESERVED,0
SPI_COPY_MS_DET,CHANGE_DATE_TIME,0
SPI_COPY_MS_DET,CHANGE_UID,0
SPI_CUST_TEMPLATES,DISTRICT,1
SPI_CUST_TEMPLATES,CUSTOM_CODE,1
SPI_CUST_TEMPLATES,TEMPLATE_FILE_NAME,1
SPI_CUST_TEMPLATES,FRIENDLY_NAME,0
SPI_CUST_TEMPLATES,DEFAULT_TEMPLATE,0
SPI_CUST_TEMPLATES,CHANGE_DATE_TIME,0
SPI_CUST_TEMPLATES,CHANGE_UID,0
SPI_CUSTOM_CODE,DISTRICT,1
SPI_CUSTOM_CODE,CUSTOM_CODE,1
SPI_CUSTOM_CODE,PACKAGE,1
SPI_CUSTOM_DATA,DISTRICT,1
SPI_CUSTOM_DATA,CUSTOM_CODE,1
SPI_CUSTOM_DATA,DATA_CODE,1
SPI_CUSTOM_DATA,DATA_VALUE,0
SPI_CUSTOM_LAUNCH,LAUNCHER_ID,1
SPI_CUSTOM_LAUNCH,BIN_NAME,0
SPI_CUSTOM_LAUNCH,LAUNCHER_TYPE,0
SPI_CUSTOM_MODS,DISTRICT,1
SPI_CUSTOM_MODS,CUSTOM_CODE,1
SPI_CUSTOM_MODS,BASE_MODULE,1
SPI_CUSTOM_MODS,CUSTOM_MODULE,0
SPI_CUSTOM_MODS,DESCRIPTION,0
SPI_CUSTOM_SCRIPT,MODULE_NAME,1
SPI_CUSTOM_SCRIPT,PROGRAM,0
SPI_CUSTOM_SCRIPT_backup,MODULE_NAME,0
SPI_CUSTOM_SCRIPT_backup,PROGRAM,0
SPI_DATA_CACHE,DISTRICT,1
SPI_DATA_CACHE,CACHE_TYPE,1
SPI_DATA_CACHE,CACHE_KEY,1
SPI_DATA_CACHE,OWNER_ID,1
SPI_DATA_CACHE,CACHE_DATA,0
SPI_DATA_CACHE,CHANGE_DATE_TIME,0
SPI_DATA_CACHE,CHANGE_UID,0
SPI_DIST_BUILDING_CHECKLIST,DISTRICT,1
SPI_DIST_BUILDING_CHECKLIST,SETUP_TYPE,1
SPI_DIST_BUILDING_CHECKLIST,PANEL_HEADING_CODE,1
SPI_DIST_BUILDING_CHECKLIST,PACKAGE,0
SPI_DIST_BUILDING_CHECKLIST,MENU_ID,1
SPI_DIST_BUILDING_CHECKLIST,MENU_TYPE,1
SPI_DIST_BUILDING_CHECKLIST,MENU_TITLE_OVERRIDE,0
SPI_DIST_BUILDING_CHECKLIST,OPTION_ORDER,1
SPI_DIST_BUILDING_CHECKLIST,VAL_TABLE_NAME,0
SPI_DIST_BUILDING_CHECKLIST,EVALUATE_SCHOOL_YEAR,0
SPI_DIST_BUILDING_CHECKLIST,EVALUATE_SUMMER_SCHOOL,0
SPI_DIST_BUILDING_CHECKLIST,QUERYSTRING,0
SPI_DIST_BUILDING_CHECKLIST,RESERVED,0
SPI_DIST_BUILDING_CHECKLIST,CHANGE_DATE_TIME,0
SPI_DIST_BUILDING_CHECKLIST,CHANGE_UID,0
SPI_DIST_PACKAGE,DISTRICT,1
SPI_DIST_PACKAGE,CONFIG_DIST,1
SPI_DIST_PACKAGE,PACKAGE,1
SPI_DIST_PACKAGE,CHANGE_DATE_TIME,0
SPI_DIST_PACKAGE,CHANGE_UID,0
SPI_DISTRICT_INIT,VAL_TAB,1
SPI_DISTRICT_INIT,APP_CODE,1
SPI_DISTRICT_INIT,DELETE_BEFORE_COPY,0
SPI_DYNAMIC_CONTAINERTYPE,CONTAINERTYPEID,1
SPI_DYNAMIC_CONTAINERTYPE,CONTAINERTYPE,0
SPI_DYNAMIC_CONTAINERTYPE,RESERVED,0
SPI_DYNAMIC_CONTAINERTYPE,CHANGE_DATE_TIME,0
SPI_DYNAMIC_CONTAINERTYPE,CHANGE_UID,0
SPI_DYNAMIC_LAYOUT,LAYOUTID,1
SPI_DYNAMIC_LAYOUT,PAGEID,0
SPI_DYNAMIC_LAYOUT,USERID,0
SPI_DYNAMIC_LAYOUT,PARENTLAYOUTID,0
SPI_DYNAMIC_LAYOUT,CONTAINERTYPEID,0
SPI_DYNAMIC_LAYOUT,ORDERNUMBER,0
SPI_DYNAMIC_LAYOUT,TITLE,0
SPI_DYNAMIC_LAYOUT,WIDTH,0
SPI_DYNAMIC_LAYOUT,WIDGETID,0
SPI_DYNAMIC_LAYOUT,INSTANCEID,0
SPI_DYNAMIC_LAYOUT,RESERVED,0
SPI_DYNAMIC_LAYOUT,CHANGE_DATE_TIME,0
SPI_DYNAMIC_LAYOUT,CHANGE_UID,0
SPI_DYNAMIC_PAGE,PAGEID,1
SPI_DYNAMIC_PAGE,PAGENAME,0
SPI_DYNAMIC_PAGE,RESERVED,0
SPI_DYNAMIC_PAGE,CHANGE_DATE_TIME,0
SPI_DYNAMIC_PAGE,CHANGE_UID,0
SPI_DYNAMIC_PAGE_WIDGET,PAGEWIDGETID,1
SPI_DYNAMIC_PAGE_WIDGET,PAGEID,0
SPI_DYNAMIC_PAGE_WIDGET,WIDGETID,0
SPI_DYNAMIC_PAGE_WIDGET,ISEDITABLE,0
SPI_DYNAMIC_PAGE_WIDGET,ISREQUIRED,0
SPI_DYNAMIC_PAGE_WIDGET,RESERVED,0
SPI_DYNAMIC_PAGE_WIDGET,CHANGE_DATE_TIME,0
SPI_DYNAMIC_PAGE_WIDGET,CHANGE_UID,0
SPI_DYNAMIC_SETTING,SETTINGID,1
SPI_DYNAMIC_SETTING,SETTINGNAME,0
SPI_DYNAMIC_SETTING,SETTINGTYPEID,0
SPI_DYNAMIC_SETTING,DATATYPEID,0
SPI_DYNAMIC_SETTING,RESERVED,0
SPI_DYNAMIC_SETTING,CHANGE_DATE_TIME,0
SPI_DYNAMIC_SETTING,CHANGE_UID,0
SPI_DYNAMIC_WIDGET,WIDGETID,1
SPI_DYNAMIC_WIDGET,WIDGETTYPEID,0
SPI_DYNAMIC_WIDGET,TITLE,0
SPI_DYNAMIC_WIDGET,DESCRIPTION,0
SPI_DYNAMIC_WIDGET,ISRESIZABLE,0
SPI_DYNAMIC_WIDGET,AREA,0
SPI_DYNAMIC_WIDGET,CONTROLLER,0
SPI_DYNAMIC_WIDGET,ACTION,0
SPI_DYNAMIC_WIDGET,PARTIALVIEW,0
SPI_DYNAMIC_WIDGET,COLUMNCONTROLID,0
SPI_DYNAMIC_WIDGET,PACKAGE,0
SPI_DYNAMIC_WIDGET,SUBPACKAGE,0
SPI_DYNAMIC_WIDGET,FEATURE,0
SPI_DYNAMIC_WIDGET,RESERVED,0
SPI_DYNAMIC_WIDGET,CHANGE_DATE_TIME,0
SPI_DYNAMIC_WIDGET,CHANGE_UID,0
SPI_DYNAMIC_WIDGET_SETTING,WIDGETSETTINGID,1
SPI_DYNAMIC_WIDGET_SETTING,INSTANCEID,1
SPI_DYNAMIC_WIDGET_SETTING,WIDGETID,0
SPI_DYNAMIC_WIDGET_SETTING,SETTINGID,0
SPI_DYNAMIC_WIDGET_SETTING,PAGEID,0
SPI_DYNAMIC_WIDGET_SETTING,USERID,0
SPI_DYNAMIC_WIDGET_SETTING,DATAKEY,0
SPI_DYNAMIC_WIDGET_SETTING,VALUEINT,0
SPI_DYNAMIC_WIDGET_SETTING,VALUEBOOL,0
SPI_DYNAMIC_WIDGET_SETTING,VALUESTRING,0
SPI_DYNAMIC_WIDGET_SETTING,VALUEDATETIME,0
SPI_DYNAMIC_WIDGET_SETTING,RESERVED,0
SPI_DYNAMIC_WIDGET_SETTING,CHANGE_DATE_TIME,0
SPI_DYNAMIC_WIDGET_SETTING,CHANGE_UID,0
SPI_DYNAMIC_WIDGET_TYPE,WIDGETTYPEID,1
SPI_DYNAMIC_WIDGET_TYPE,WIDGETTYPE,0
SPI_DYNAMIC_WIDGET_TYPE,RESERVED,0
SPI_DYNAMIC_WIDGET_TYPE,CHANGE_DATE_TIME,0
SPI_DYNAMIC_WIDGET_TYPE,CHANGE_UID,0
SPI_EVENT,DISTRICT,0
SPI_EVENT,LOGIN_ID,0
SPI_EVENT,EVENT_DATE_TIME,0
SPI_EVENT,EVENT_TYPE,0
SPI_EVENT,SECTION_KEY,0
SPI_EVENT,COURSE_SESSION,0
SPI_EVENT,ASMT_NUMBER,0
SPI_EVENT,CHANGE_DATE_TIME,0
SPI_EVENT,CHANGE_UID,0
SPI_EVENT,EVENT_ID,1
SPI_FEATURE_FLAG,DISTRICT,1
SPI_FEATURE_FLAG,CODE,1
SPI_FEATURE_FLAG,DESCRIPTION,0
SPI_FEATURE_FLAG,ENABLED,0
SPI_FEATURE_FLAG,CHANGE_DATE_TIME,0
SPI_FEATURE_FLAG,CHANGE_UID,0
SPI_FEEDBACK_ANS,DISTRICT,1
SPI_FEEDBACK_ANS,CATEGORY,1
SPI_FEEDBACK_ANS,LINE_NUMBER,1
SPI_FEEDBACK_ANS,ANSWER,0
SPI_FEEDBACK_ANS,COMMENT,0
SPI_FEEDBACK_Q_HDR,DISTRICT,1
SPI_FEEDBACK_Q_HDR,CATEGORY,1
SPI_FEEDBACK_Q_HDR,DESCRIPTION,1
SPI_FEEDBACK_QUEST,DISTRICT,1
SPI_FEEDBACK_QUEST,CATEGORY,1
SPI_FEEDBACK_QUEST,LINE_NUMBER,1
SPI_FEEDBACK_QUEST,QUESTION,0
SPI_FEEDBACK_QUEST,ANSWER_TYPE,0
SPI_FEEDBACK_RECIP,DISTRICT,1
SPI_FEEDBACK_RECIP,RECIPIENT,1
SPI_FEEDBACK_RECIP,RECIPIENT_TYPE,0
SPI_FIELD_HELP,DISTRICT,1
SPI_FIELD_HELP,AREA,1
SPI_FIELD_HELP,CONTROLLER,1
SPI_FIELD_HELP,ACTION,1
SPI_FIELD_HELP,FIELD,1
SPI_FIELD_HELP,IS_GRID_HEADER,0
SPI_FIELD_HELP,IS_IN_DIALOG,0
SPI_FIELD_HELP,GRID_ID,0
SPI_FIELD_HELP,DIALOG_ID,0
SPI_FIELD_HELP,DESCRIPTION,0
SPI_FIELD_HELP,DISPLAY_NAME,0
SPI_FIELD_HELP,STATE,1
SPI_FIELD_HELP,RESERVED,0
SPI_FIELD_HELP,ACTIVE,0
SPI_FIELD_HELP,CHANGE_DATE_TIME,0
SPI_FIELD_HELP,CHANGE_UID,0
SPI_FIRSTWAVE,FIRSTWAVE_ID,1
SPI_FIRSTWAVE,SITE_CODE,0
SPI_FIRSTWAVE,DISTRICT_NAME,0
SPI_HAC_NEWS,DISTRICT,1
SPI_HAC_NEWS,NEWS_ID,1
SPI_HAC_NEWS,ADMIN_OR_TEACHER,0
SPI_HAC_NEWS,HEADLINE,0
SPI_HAC_NEWS,NEWS_TEXT,0
SPI_HAC_NEWS,EFFECTIVE_DATE,0
SPI_HAC_NEWS,EXPIRATION_DATE,0
SPI_HAC_NEWS,FOR_PARENTS,0
SPI_HAC_NEWS,FOR_STUDENTS,0
SPI_HAC_NEWS,STAFF_ID,0
SPI_HAC_NEWS,SECTION_KEY,0
SPI_HAC_NEWS,PRINT_COURSE_INFO,0
SPI_HAC_NEWS,CHANGE_DATE_TIME,0
SPI_HAC_NEWS,CHANGE_UID,0
SPI_HAC_NEWS_BLDG,DISTRICT,1
SPI_HAC_NEWS_BLDG,NEWS_ID,1
SPI_HAC_NEWS_BLDG,BUILDING,1
SPI_HAC_NEWS_BLDG,CHANGE_DATE_TIME,0
SPI_HAC_NEWS_BLDG,CHANGE_UID,0
SPI_HOME_SECTIONS,DISTRICT,1
SPI_HOME_SECTIONS,CODE,1
SPI_HOME_SECTIONS,DESCRIPTION,0
SPI_HOME_SECTIONS,REQUIRED_SECTION,0
SPI_HOME_SECTIONS,HAS_SETTINGS,0
SPI_HOME_SECTIONS,REFRESH_TYPE,0
SPI_HOME_SECTIONS,CAN_DELETE,0
SPI_HOME_SECTIONS,DESIRED_COL_WIDTH,0
SPI_HOME_SECTIONS,XSL_DISPLAY_FILE,0
SPI_HOME_SECTIONS,XSL_SETTINGS_FILE,0
SPI_HOME_SECTIONS,SEC_PACKAGE,0
SPI_HOME_SECTIONS,SEC_SUBPACKAGE,0
SPI_HOME_SECTIONS,SEC_FEATURE,0
SPI_HOME_SECTIONS,CAN_ADDNEW,0
SPI_HOME_SECTIONS,CHANGE_DATE_TIME,0
SPI_HOME_SECTIONS,CHANGE_UID,0
SPI_HOME_USER_CFG,DISTRICT,1
SPI_HOME_USER_CFG,LOGIN_ID,1
SPI_HOME_USER_CFG,SECTION_CODE,1
SPI_HOME_USER_CFG,SETTING_CODE,1
SPI_HOME_USER_CFG,SETTING_VALUE,0
SPI_HOME_USER_CFG,CHANGE_DATE_TIME,0
SPI_HOME_USER_CFG,CHANGE_UID,0
SPI_HOME_USER_SEC,DISTRICT,1
SPI_HOME_USER_SEC,LOGIN_ID,1
SPI_HOME_USER_SEC,SECTION_CODE,1
SPI_HOME_USER_SEC,COLUMN_NO,0
SPI_HOME_USER_SEC,ROW_NO,0
SPI_HOME_USER_SEC,CHANGE_DATE_TIME,0
SPI_HOME_USER_SEC,CHANGE_UID,0
SPI_IEPWEBSVC_CFG,DISTRICT,1
SPI_IEPWEBSVC_CFG,CUSTOMER_CODE,0
SPI_IEPWEBSVC_CFG,PASSWORD,0
SPI_IEPWEBSVC_CFG,CHANGE_DATE_TIME,0
SPI_IEPWEBSVC_CFG,CHANGE_UID,0
SPI_IMM_TSK_RESULT,DISTRICT,1
SPI_IMM_TSK_RESULT,PARAM_KEY,1
SPI_IMM_TSK_RESULT,RESULT,0
SPI_IMM_TSK_RESULT,CHANGE_DATE_TIME,0
SPI_IMM_TSK_RESULT,CHANGE_UID,0
SPI_INPROG,PROC_KEY,1
SPI_INPROG,PARAM_KEY,1
SPI_INPROG,START_TIME,0
SPI_INPROG,CHANGE_DATE_TIME,0
SPI_INPROG,CHANGE_UID,0
SPI_INTEGRATION_DET,DISTRICT,1
SPI_INTEGRATION_DET,PRODUCT,1
SPI_INTEGRATION_DET,OPTION_NAME,1
SPI_INTEGRATION_DET,OPTION_VALUE,0
SPI_INTEGRATION_HDR,DISTRICT,1
SPI_INTEGRATION_HDR,PRODUCT,1
SPI_INTEGRATION_HDR,DESCRIPTION,0
SPI_INTEGRATION_HDR,PACKAGE,0
SPI_INTEGRATION_HDR,SUBPACKAGE,0
SPI_INTEGRATION_HDR,FEATURE,0
SPI_INTEGRATION_LOGIN,DISTRICT,1
SPI_INTEGRATION_LOGIN,PRODUCT,1
SPI_INTEGRATION_LOGIN,LOGIN_ID,1
SPI_INTEGRATION_LOGIN,OTHER_LOGIN_ID,0
SPI_INTEGRATION_LOGIN,CHANGE_DATE_TIME,0
SPI_INTEGRATION_LOGIN,CHANGE_UID,0
SPI_INTEGRATION_SESSION_DET,SESSION_GUID,1
SPI_INTEGRATION_SESSION_DET,VARIABLE_NAME,1
SPI_INTEGRATION_SESSION_DET,VARIABLE_VALUE,0
SPI_INTEGRATION_SESSION_HDR,SESSION_GUID,1
SPI_INTEGRATION_SESSION_HDR,TSTAMP,0
SPI_INTEGRATION_STUDATA_DET,DISTRICT,1
SPI_INTEGRATION_STUDATA_DET,GROUP_CODE,1
SPI_INTEGRATION_STUDATA_DET,STUDENT_ID,1
SPI_INTEGRATION_STUDATA_HDR,DISTRICT,1
SPI_INTEGRATION_STUDATA_HDR,GROUP_CODE,1
SPI_JOIN_COND,REFTABLE,1
SPI_JOIN_COND,REFCOL,1
SPI_JOIN_COND,LINKTABLE,1
SPI_JOIN_COND,SEQUENCE,1
SPI_JOIN_COND,JOINTABLE,0
SPI_JOIN_COND,JOINCOLUMN,0
SPI_JOIN_COND,JOINTYPE,0
SPI_JOIN_COND,VALUE_TYPE,0
SPI_JOIN_COND,JOINVALUE,0
SPI_JOIN_COND,BASETABLE,0
SPI_JOIN_COND,BASECOLUMN,0
SPI_JOIN_SELECT,REFTABLE,1
SPI_JOIN_SELECT,REFCOL,1
SPI_JOIN_SELECT,LINKTABLE,1
SPI_JOIN_SELECT,SELECTCLAUSE,0
SPI_JOIN_SELECT,AS_COLUMN,0
SPI_MAP_CFG,DISTRICT,1
SPI_MAP_CFG,GOOGLE_MAP_KEY,0
SPI_MAP_CFG,HEAT_MAP_KEY,0
SPI_MAP_CFG,MAX_ROWS,0
SPI_MAP_CFG,TASK_USER_ID,0
SPI_MAP_CFG,TASK_PASSWORD,0
SPI_MAP_CFG,TASK_DOMAIN,0
SPI_MAP_CFG,TASK_PROXY,0
SPI_MAP_CFG,CHANGE_DATE_TIME,0
SPI_MAP_CFG,CHANGE_UID,0
SPI_NEWS,DISTRICT,1
SPI_NEWS,NEWS_ID,1
SPI_NEWS,NEWS_DATE,0
SPI_NEWS,NEWS_HEADLINE,0
SPI_NEWS,NEWS_TEXT,0
SPI_NEWS,EXPIRATION_DATE,0
SPI_NEWS,REQUIRED_READING,0
SPI_NEWS,FOR_OFFICE_EMPLOYEES,0
SPI_NEWS,FOR_TEACHERS,0
SPI_NEWS,FOR_PARENTS,0
SPI_NEWS,CHANGE_DATE_TIME,0
SPI_NEWS,CHANGE_UID,0
SPI_NEWS_BLDG,DISTRICT,1
SPI_NEWS_BLDG,NEWS_ID,1
SPI_NEWS_BLDG,BUILDING,1
SPI_NEWS_BLDG,CHANGE_DATE_TIME,0
SPI_NEWS_BLDG,CHANGE_UID,0
SPI_OBJECT_PERM,DISTRICT,1
SPI_OBJECT_PERM,PERMISSION,1
SPI_OBJECT_PERM,OBJECT,1
SPI_OBJECT_PERM,SQL_USER,1
SPI_OPTION_COLUMN_NULLABLE,DISTRICT,1
SPI_OPTION_COLUMN_NULLABLE,SEARCH_TYPE,1
SPI_OPTION_COLUMN_NULLABLE,TABLE_NAME,1
SPI_OPTION_COLUMN_NULLABLE,COLUMN_NAME,0
SPI_OPTION_COLUMN_NULLABLE,CHANGE_DATE_TIME,0
SPI_OPTION_COLUMN_NULLABLE,CHANGE_UID,0
SPI_OPTION_EXCLD,DISTRICT,1
SPI_OPTION_EXCLD,SEARCH_TYPE,1
SPI_OPTION_EXCLD,TABLE_NAME,1
SPI_OPTION_EXCLD,COLUMN_NAME,1
SPI_OPTION_EXCLD,CHANGE_DATE_TIME,0
SPI_OPTION_EXCLD,CHANGE_UID,0
SPI_OPTION_LIST_FIELD,DISTRICT,1
SPI_OPTION_LIST_FIELD,SEARCH_TYPE,1
SPI_OPTION_LIST_FIELD,TABLE_NAME,1
SPI_OPTION_LIST_FIELD,COLUMN_NAME,1
SPI_OPTION_LIST_FIELD,DISPLAY_ORDER,0
SPI_OPTION_LIST_FIELD,IS_HIDDEN,0
SPI_OPTION_LIST_FIELD,FORMATTER,0
SPI_OPTION_LIST_FIELD,NAVIGATION_PARAM,0
SPI_OPTION_LIST_FIELD,COLUMN_LABEL,0
SPI_OPTION_LIST_FIELD,IS_SEC_BUILDING_COL,0
SPI_OPTION_LIST_FIELD,COLUMN_WIDTH,0
SPI_OPTION_LIST_FIELD,RESERVED,0
SPI_OPTION_LIST_FIELD,CHANGE_DATE_TIME,0
SPI_OPTION_LIST_FIELD,CHANGE_UID,0
SPI_OPTION_NAME,DISTRICT,1
SPI_OPTION_NAME,SEARCH_TYPE,1
SPI_OPTION_NAME,OPTION_NAME,0
SPI_OPTION_NAME,NAVIGATE_TO,0
SPI_OPTION_NAME,BTN_NEW_NAVIGATE,0
SPI_OPTION_NAME,USER_DEF_SCR_TYPE,0
SPI_OPTION_NAME,USE_PROGRAMS,0
SPI_OPTION_NAME,TARGET_TABLE,0
SPI_OPTION_NAME,DELETE_TABLE,0
SPI_OPTION_NAME,CHANGE_DATE_TIME,0
SPI_OPTION_NAME,CHANGE_UID,0
SPI_OPTION_SIMPLE_SEARCH,DISTRICT,1
SPI_OPTION_SIMPLE_SEARCH,SEARCH_TYPE,1
SPI_OPTION_SIMPLE_SEARCH,TABLE_NAME,1
SPI_OPTION_SIMPLE_SEARCH,COLUMN_NAME,1
SPI_OPTION_SIMPLE_SEARCH,ENVIRONMENT,1
SPI_OPTION_SIMPLE_SEARCH,DISPLAY_ORDER,0
SPI_OPTION_SIMPLE_SEARCH,OPERATOR,0
SPI_OPTION_SIMPLE_SEARCH,OVERRIDE_LABEL,0
SPI_OPTION_SIMPLE_SEARCH,RESERVED,0
SPI_OPTION_SIMPLE_SEARCH,CHANGE_DATE_TIME,0
SPI_OPTION_SIMPLE_SEARCH,CHANGE_UID,0
SPI_OPTION_TABLE,DISTRICT,1
SPI_OPTION_TABLE,SEARCH_TYPE,1
SPI_OPTION_TABLE,TABLE_NAME,1
SPI_OPTION_TABLE,SEQUENCE_NUM,0
SPI_OPTION_TABLE,SEC_PACKAGE,0
SPI_OPTION_TABLE,SEC_SUBPACKAGE,0
SPI_OPTION_TABLE,SEC_FEATURE,0
SPI_OPTION_TABLE,CHANGE_DATE_TIME,0
SPI_OPTION_TABLE,CHANGE_UID,0
SPI_OPTION_UPDATE,DISTRICT,1
SPI_OPTION_UPDATE,SEARCH_TYPE,1
SPI_OPTION_UPDATE,TABLE_NAME,1
SPI_OPTION_UPDATE,COLUMN_NAME,1
SPI_OPTION_UPDATE,UI_CONTROL_TYPE,0
SPI_OPTION_UPDATE,IS_REQUIRED,0
SPI_OPTION_UPDATE,ENTRY_FILTER,0
SPI_OPTION_UPDATE,CHANGE_DATE_TIME,0
SPI_OPTION_UPDATE,CHANGE_UID,0
SPI_POWERPACK_CONFIGURATION,DISTRICT,1
SPI_POWERPACK_CONFIGURATION,ROW_NUMBER,1
SPI_POWERPACK_CONFIGURATION,CUSTOM_CODE,0
SPI_POWERPACK_CONFIGURATION,CUSTOM_NAME,0
SPI_POWERPACK_CONFIGURATION,CUSTOM_DESCRIPTION,0
SPI_POWERPACK_CONFIGURATION,ACTIVE,0
SPI_POWERPACK_CONFIGURATION,CHANGE_DATE_TIME,0
SPI_POWERPACK_CONFIGURATION,CHANGE_UID,0
SPI_PRIVATE_FIELD,DISTRICT,1
SPI_PRIVATE_FIELD,TABLE_NAME,1
SPI_PRIVATE_FIELD,COLUMN_NAME,1
SPI_PRIVATE_FIELD,PACKAGE,0
SPI_PRIVATE_FIELD,SUBPACKAGE,0
SPI_PRIVATE_FIELD,FEATURE,0
SPI_RESOURCE,DISTRICT,1
SPI_RESOURCE,APPLICATION_ID,1
SPI_RESOURCE,RESOURCE_ID,1
SPI_RESOURCE,CULTURE_CODE,1
SPI_RESOURCE,RESOURCE_KEY,1
SPI_RESOURCE,RESOURCE_VALUE,0
SPI_RESOURCE,RESERVED,0
SPI_RESOURCE,CHANGE_DATE_TIME,0
SPI_RESOURCE,CHANGE_UID,0
SPI_RESOURCE_OVERRIDE,DISTRICT,1
SPI_RESOURCE_OVERRIDE,APPLICATION_ID,1
SPI_RESOURCE_OVERRIDE,RESOURCE_ID,1
SPI_RESOURCE_OVERRIDE,CULTURE_CODE,1
SPI_RESOURCE_OVERRIDE,RESOURCE_KEY,1
SPI_RESOURCE_OVERRIDE,OVERRIDE_VALUE,0
SPI_RESOURCE_OVERRIDE,RESERVED,0
SPI_RESOURCE_OVERRIDE,CHANGE_DATE_TIME,0
SPI_RESOURCE_OVERRIDE,CHANGE_UID,0
SPI_SEARCH_FAV,DISTRICT,1
SPI_SEARCH_FAV,LOGIN_ID,1
SPI_SEARCH_FAV,SEARCH_TYPE,1
SPI_SEARCH_FAV,SEARCH_NUMBER,1
SPI_SEARCH_FAV,SEARCH_NAME,0
SPI_SEARCH_FAV,DESCRIPTION,0
SPI_SEARCH_FAV,LAST_SEARCH,0
SPI_SEARCH_FAV,GROUPING_MASK,0
SPI_SEARCH_FAV,CATEGORY,0
SPI_SEARCH_FAV,PUBLISH,0
SPI_SEARCH_FAV,CHANGE_DATE_TIME,0
SPI_SEARCH_FAV,CHANGE_UID,0
SPI_SEARCH_FAV_SUBSCRIBE,DISTRICT,1
SPI_SEARCH_FAV_SUBSCRIBE,LOGIN_ID,1
SPI_SEARCH_FAV_SUBSCRIBE,PUB_LOGIN_ID,1
SPI_SEARCH_FAV_SUBSCRIBE,PUB_SEARCH_TYPE,1
SPI_SEARCH_FAV_SUBSCRIBE,PUB_SEARCH_NUMBER,1
SPI_SEARCH_FAV_SUBSCRIBE,CHANGE_DATE_TIME,0
SPI_SEARCH_FAV_SUBSCRIBE,CHANGE_UID,0
SPI_SECONDARY_KEY_USED,DISTRICT,1
SPI_SECONDARY_KEY_USED,TABLE_NAME,1
SPI_SECONDARY_KEY_USED,LAST_USED,0
SPI_SECONDARY_KEY_USED,CHANGE_DATE_TIME,0
SPI_SECONDARY_KEY_USED,CHANGE_UID,0
SPI_SESSION_STATE,SESSION_ID,1
SPI_SESSION_STATE,NAME,1
SPI_SESSION_STATE,VALUE,0
SPI_SESSION_STATE,CHANGE_DATE_TIME,0
SPI_SESSION_STATE,CHANGE_UID,0
SPI_STATE_REQUIREMENTS,ID,0
SPI_STATE_REQUIREMENTS,STATE,0
SPI_STATE_REQUIREMENTS,ASPPAGE,0
SPI_STATE_REQUIREMENTS,FRIENDLYNAME,0
SPI_STATE_REQUIREMENTS,SQL,0
SPI_STATE_REQUIREMENTS,WARNING,0
SPI_STATE_REQUIREMENTS,WARNINGTYPE,0
SPI_STATE_REQUIREMENTS,SCREENNAME,0
SPI_STATE_REQUIREMENTS,SHOWDDFORM,0
SPI_STATE_REQUIREMENTS,CHANGE_DATE_TIME,0
SPI_STATE_REQUIREMENTS,CHANGE_UID,0
SPI_TABLE_JOIN,DISTRICT,1
SPI_TABLE_JOIN,SOURCE_TABLE,1
SPI_TABLE_JOIN,TARGET_TABLE,1
SPI_TABLE_JOIN,SEQUENCE_NUMBER,1
SPI_TABLE_JOIN,JOIN_TABLE_1,0
SPI_TABLE_JOIN,JOIN_COLUMN_1,0
SPI_TABLE_JOIN,JOIN_TABLE_2,0
SPI_TABLE_JOIN,JOIN_COLUMN_2,0
SPI_TABLE_JOIN,CHANGE_DATE_TIME,0
SPI_TABLE_JOIN,CHANGE_UID,0
SPI_TABLE_NAMES,DISTRICT,1
SPI_TABLE_NAMES,TABLE_NAME,1
SPI_TABLE_NAMES,TABLE_DESCRIPTION,0
SPI_TABLE_NAMES,CHANGE_DATE_TIME,0
SPI_TABLE_NAMES,CHANGE_UID,0
SPI_TASK,DISTRICT,1
SPI_TASK,PARAM_KEY,1
SPI_TASK,TASK_KEY,0
SPI_TASK,TASK_TYPE,0
SPI_TASK,RELATED_PAGE,0
SPI_TASK,CLASSNAME,0
SPI_TASK,TASK_DESCRIPTION,0
SPI_TASK,TASK_FILE,0
SPI_TASK,SCHEDULED_TIME,0
SPI_TASK,TASK_STATUS,0
SPI_TASK,TASK_OWNER,0
SPI_TASK,TASK_SERVER,0
SPI_TASK,NEXT_RUN_TIME,0
SPI_TASK,LAST_RUN_TIME,0
SPI_TASK,SCHEDULE_TYPE,0
SPI_TASK,SCHD_INTERVAL,0
SPI_TASK,SCHD_DOW,0
SPI_TASK,QUEUE_POSITION,0
SPI_TASK,CHANGE_DATE_TIME,0
SPI_TASK,CHANGE_UID,0
SPI_TASK_ERR_DESC,PARAM_KEY,1
SPI_TASK_ERR_DESC,DESCRIPTION_INDEX,1
SPI_TASK_ERR_DESC,ERROR_DESCRIPTION,0
SPI_TASK_ERROR,PARAM_KEY,1
SPI_TASK_ERROR,DISTRICT,0
SPI_TASK_ERROR,ERROR_SOURCE,0
SPI_TASK_ERROR,ERROR_NUMBER,0
SPI_TASK_ERROR,ERROR_LINE,0
SPI_TASK_LB_STATS,DISTRICT,1
SPI_TASK_LB_STATS,SERVER_NAME,1
SPI_TASK_LB_STATS,TASK_DB_CONNECTION_STRING,0
SPI_TASK_LB_STATS,DEBUG_TASK_SERVICES,0
SPI_TASK_LB_STATS,TRACE_LB_SERVICE,0
SPI_TASK_LB_STATS,INCLUDE_WEB_SERVERS,0
SPI_TASK_LB_STATS,EXCLUDE_WEB_SERVERS,0
SPI_TASK_LB_STATS,CHANGE_DATE_TIME,0
SPI_TASK_LB_STATS,CHANGE_UID,0
SPI_TASK_LOG_DET,DISTRICT,1
SPI_TASK_LOG_DET,PARAM_KEY,1
SPI_TASK_LOG_DET,RUN_NUMBER,1
SPI_TASK_LOG_DET,MESSAGE_INDEX,1
SPI_TASK_LOG_DET,MESSAGE_NUMBER,0
SPI_TASK_LOG_DET,KEY_VALUE1,0
SPI_TASK_LOG_DET,KEY_VALUE2,0
SPI_TASK_LOG_DET,KEY_VALUE3,0
SPI_TASK_LOG_DET,KEY_VALUE4,0
SPI_TASK_LOG_DET,KEY_VALUE5,0
SPI_TASK_LOG_DET,KEY_VALUE6,0
SPI_TASK_LOG_DET,KEY_VALUE7,0
SPI_TASK_LOG_DET,KEY_VALUE8,0
SPI_TASK_LOG_DET,KEY_VALUE9,0
SPI_TASK_LOG_DET,KEY_VALUE10,0
SPI_TASK_LOG_DET,CHANGE_DATE_TIME,0
SPI_TASK_LOG_DET,CHANGE_UID,0
SPI_TASK_LOG_HDR,DISTRICT,1
SPI_TASK_LOG_HDR,PARAM_KEY,1
SPI_TASK_LOG_HDR,RUN_NUMBER,1
SPI_TASK_LOG_HDR,TASK_CODE,0
SPI_TASK_LOG_HDR,BASE_TASK_NAME,0
SPI_TASK_LOG_HDR,CUSTOM_TASK_NAME,0
SPI_TASK_LOG_HDR,TASK_OWNER,0
SPI_TASK_LOG_HDR,START_TIME,0
SPI_TASK_LOG_HDR,END_TIME,0
SPI_TASK_LOG_HDR,CHANGE_DATE_TIME,0
SPI_TASK_LOG_HDR,CHANGE_UID,0
SPI_TASK_LOG_MESSAGE,DISTRICT,1
SPI_TASK_LOG_MESSAGE,PARAM_KEY,1
SPI_TASK_LOG_MESSAGE,RUN_NUMBER,1
SPI_TASK_LOG_MESSAGE,MESSAGE_NUMBER,1
SPI_TASK_LOG_MESSAGE,MESSAGE_TYPE,0
SPI_TASK_LOG_MESSAGE,MESSAGE,0
SPI_TASK_LOG_MESSAGE,DATAFIELD1,0
SPI_TASK_LOG_MESSAGE,DATAFIELD2,0
SPI_TASK_LOG_MESSAGE,DATAFIELD3,0
SPI_TASK_LOG_MESSAGE,DATAFIELD4,0
SPI_TASK_LOG_MESSAGE,DATAFIELD5,0
SPI_TASK_LOG_MESSAGE,DATAFIELD6,0
SPI_TASK_LOG_MESSAGE,DATAFIELD7,0
SPI_TASK_LOG_MESSAGE,DATAFIELD8,0
SPI_TASK_LOG_MESSAGE,DATAFIELD9,0
SPI_TASK_LOG_MESSAGE,DATAFIELD10,0
SPI_TASK_LOG_MESSAGE,CHANGE_DATE_TIME,0
SPI_TASK_LOG_MESSAGE,CHANGE_UID,0
SPI_TASK_LOG_PARAMS,PARAM_KEY,1
SPI_TASK_LOG_PARAMS,RUN_NUMBER,1
SPI_TASK_LOG_PARAMS,PARAM_INDEX,1
SPI_TASK_LOG_PARAMS,IS_ENV_PARAM,0
SPI_TASK_LOG_PARAMS,PARAM_NAME,0
SPI_TASK_LOG_PARAMS,PARAM_VALUE,0
SPI_TASK_LOG_PARAMS,CHANGE_DATE_TIME,0
SPI_TASK_LOG_PARAMS,CHANGE_UID,0
SPI_TASK_PARAMS,PARAM_KEY,1
SPI_TASK_PARAMS,PARAM_IDX,1
SPI_TASK_PARAMS,IS_ENV_PARAM,0
SPI_TASK_PARAMS,PARAM_NAME,0
SPI_TASK_PARAMS,PARAM_VALUE,0
SPI_TASK_PARAMS,CHANGE_DATE_TIME,0
SPI_TASK_PARAMS,CHANGE_UID,0
SPI_TASK_PROG,PARAM_KEY,1
SPI_TASK_PROG,DISTRICT,0
SPI_TASK_PROG,LOGIN_ID,0
SPI_TASK_PROG,PROC_DESC,0
SPI_TASK_PROG,START_TIME,0
SPI_TASK_PROG,TOTAL_RECS,0
SPI_TASK_PROG,RECS_PROCESSED,0
SPI_TASK_PROG,END_TIME,0
SPI_TASK_PROG,DESCRIPTION,0
SPI_TASK_PROG,ERROR_OCCURRED,0
SPI_TIME_OFFSET,DISTRICT,1
SPI_TIME_OFFSET,OFFSET,0
SPI_TIME_OFFSET,DISTRICT_TIMEZONE,0
SPI_TMP_WATCH_LIST,DISTRICT,1
SPI_TMP_WATCH_LIST,LOGIN_ID,1
SPI_TMP_WATCH_LIST,WATCH_NAME,1
SPI_TMP_WATCH_LIST,STUDENT_ID,1
SPI_TMP_WATCH_LIST,CHANGE_DATE_TIME,0
SPI_TMP_WATCH_LIST,CHANGE_UID,0
SPI_TRIGGER_STATE,TRIGGER_NAME,1
SPI_TRIGGER_STATE,TRIGGER_STATE,1
SPI_TRIGGER_STATE,SPID,1
SPI_TRIGGER_STATE,CHANGE_DATE_TIME,0
SPI_TRIGGER_STATE,CHANGE_UID,0
SPI_USER_GRID,DISTRICT,1
SPI_USER_GRID,LOGIN_ID,1
SPI_USER_GRID,PAGE_CODE,1
SPI_USER_GRID,GRID_ID,1
SPI_USER_GRID,GRID_COLUMN_NAMES,0
SPI_USER_GRID,GRID_COLUMN_MODELS,0
SPI_USER_GRID,GRID_STATE,0
SPI_USER_GRID,CHANGE_DATE_TIME,0
SPI_USER_GRID,CHANGE_UID,0
SPI_USER_OPTION,DISTRICT,1
SPI_USER_OPTION,LOGIN_ID,1
SPI_USER_OPTION,PAGE_CODE,1
SPI_USER_OPTION,OPTION_CODE,1
SPI_USER_OPTION,OPTION_VALUE,0
SPI_USER_OPTION,CHANGE_DATE_TIME,0
SPI_USER_OPTION,CHANGE_UID,0
SPI_USER_OPTION_BLDG,DISTRICT,1
SPI_USER_OPTION_BLDG,LOGIN_ID,1
SPI_USER_OPTION_BLDG,BUILDING,1
SPI_USER_OPTION_BLDG,PAGE_CODE,1
SPI_USER_OPTION_BLDG,OPTION_CODE,1
SPI_USER_OPTION_BLDG,OPTION_VALUE,0
SPI_USER_OPTION_BLDG,CHANGE_DATE_TIME,0
SPI_USER_OPTION_BLDG,CHANGE_UID,0
SPI_USER_PROMPT,DISTRICT,1
SPI_USER_PROMPT,LOGIN_ID,1
SPI_USER_PROMPT,SEARCH_TYPE,1
SPI_USER_PROMPT,PROMPT_NAME,1
SPI_USER_PROMPT,PROMPT_VALUE,0
SPI_USER_PROMPT,CHANGE_DATE_TIME,0
SPI_USER_PROMPT,CHANGE_UID,0
SPI_USER_SEARCH,DISTRICT,1
SPI_USER_SEARCH,LOGIN_ID,1
SPI_USER_SEARCH,SEARCH_TYPE,1
SPI_USER_SEARCH,SEARCH_NUMBER,1
SPI_USER_SEARCH,SEQUENCE_NUM,1
SPI_USER_SEARCH,AND_OR_FLAG,0
SPI_USER_SEARCH,TABLE_NAME,0
SPI_USER_SEARCH,SCREEN_TYPE,0
SPI_USER_SEARCH,SCREEN_NUMBER,0
SPI_USER_SEARCH,PROGRAM_ID,0
SPI_USER_SEARCH,COLUMN_NAME,0
SPI_USER_SEARCH,FIELD_NUMBER,0
SPI_USER_SEARCH,OPERATOR,0
SPI_USER_SEARCH,SEARCH_VALUE1,0
SPI_USER_SEARCH,SEARCH_VALUE2,0
SPI_USER_SEARCH,CHANGE_DATE_TIME,0
SPI_USER_SEARCH,CHANGE_UID,0
SPI_USER_SEARCH_LIST_FIELD,DISTRICT,1
SPI_USER_SEARCH_LIST_FIELD,LOGIN_ID,1
SPI_USER_SEARCH_LIST_FIELD,SEARCH_TYPE,1
SPI_USER_SEARCH_LIST_FIELD,SEARCH_NUMBER,1
SPI_USER_SEARCH_LIST_FIELD,SEQUENCE_NUM,1
SPI_USER_SEARCH_LIST_FIELD,TABLE_NAME,0
SPI_USER_SEARCH_LIST_FIELD,SCREEN_TYPE,0
SPI_USER_SEARCH_LIST_FIELD,SCREEN_NUMBER,0
SPI_USER_SEARCH_LIST_FIELD,PROGRAM_ID,0
SPI_USER_SEARCH_LIST_FIELD,COLUMN_NAME,0
SPI_USER_SEARCH_LIST_FIELD,FIELD_NUMBER,0
SPI_USER_SEARCH_LIST_FIELD,CHANGE_DATE_TIME,0
SPI_USER_SEARCH_LIST_FIELD,CHANGE_UID,0
SPI_USER_SORT,DISTRICT,1
SPI_USER_SORT,LOGIN_ID,1
SPI_USER_SORT,SORT_TYPE,1
SPI_USER_SORT,SORT_NUMBER,1
SPI_USER_SORT,SEQUENCE_NUM,1
SPI_USER_SORT,TABLE_NAME,0
SPI_USER_SORT,SCREEN_TYPE,0
SPI_USER_SORT,SCREEN_NUMBER,0
SPI_USER_SORT,PROGRAM_ID,0
SPI_USER_SORT,COLUMN_NAME,0
SPI_USER_SORT,FIELD_NUMBER,0
SPI_USER_SORT,SORT_ORDER,0
SPI_USER_SORT,CHANGE_DATE_TIME,0
SPI_USER_SORT,CHANGE_UID,0
SPI_USER_TOKEN,DISTRICT,1
SPI_USER_TOKEN,LOGIN_ID,1
SPI_USER_TOKEN,PRODUCT,1
SPI_USER_TOKEN,TOKEN_TYPE,1
SPI_USER_TOKEN,TOKEN,0
SPI_USER_TOKEN,CHANGE_DATE_TIME,0
SPI_USER_TOKEN,CHANGE_UID,0
SPI_VAL_TABS,PACKAGE,1
SPI_VAL_TABS,REFTAB,1
SPI_VAL_TABS,REFCOL,1
SPI_VAL_TABS,SEQUENCE,1
SPI_VAL_TABS,VALTAB,0
SPI_VAL_TABS,VALCOL,0
SPI_VAL_TABS,VALDESC,0
SPI_VAL_TABS,PARAM,0
SPI_VAL_TABS,VALUE,0
SPI_VALIDATION_TABLES,DISTRICT,1
SPI_VALIDATION_TABLES,PACKAGE,1
SPI_VALIDATION_TABLES,TABLE_NAME,1
SPI_VALIDATION_TABLES,TABLE_DESCR,0
SPI_VALIDATION_TABLES,USER_DEFINED,1
SPI_VALIDATION_TABLES,CUSTOM_CODE,0
SPI_VALIDATION_TABLES,RESERVED,1
SPI_VALIDATION_TABLES,ACTIVE,0
SPI_VALIDATION_TABLES,CHANGE_DATE_TIME,0
SPI_VALIDATION_TABLES,CHANGE_UID,0
SPI_VALIDATION_TABLES,FEATURE_FLAG,0
SPI_VERSION,VERSION,0
SPI_VERSION,DB_VERSION,0
SPI_VERSION,IS_STUPLUS_CONV,0
SPI_VERSION,CHANGE_DATE_TIME,0
SPI_VERSION,CHANGE_UID,0
SPI_WATCH_LIST,DISTRICT,1
SPI_WATCH_LIST,LOGIN_ID,1
SPI_WATCH_LIST,WATCH_NUMBER,1
SPI_WATCH_LIST,WATCH_NAME,0
SPI_WATCH_LIST,CHANGE_DATE_TIME,0
SPI_WATCH_LIST,CHANGE_UID,0
SPI_WATCH_LIST_STUDENT,DISTRICT,1
SPI_WATCH_LIST_STUDENT,LOGIN_ID,1
SPI_WATCH_LIST_STUDENT,WATCH_NUMBER,1
SPI_WATCH_LIST_STUDENT,STUDENT_ID,1
SPI_WATCH_LIST_STUDENT,CHANGE_DATE_TIME,0
SPI_WATCH_LIST_STUDENT,CHANGE_UID,0
SPI_WORKFLOW_MESSAGES,DISTRICT,1
SPI_WORKFLOW_MESSAGES,USER_ID,1
SPI_WORKFLOW_MESSAGES,MSG_DATE,1
SPI_WORKFLOW_MESSAGES,MSG_SEQUENCE,1
SPI_WORKFLOW_MESSAGES,BUILDING,0
SPI_WORKFLOW_MESSAGES,MSG_TYPE,0
SPI_WORKFLOW_MESSAGES,MESSAGE_BODY,0
SPI_WORKFLOW_MESSAGES,URL,0
SPI_WORKFLOW_MESSAGES,STUDENT_ID,0
SPI_WORKFLOW_MESSAGES,SECTION_KEY,0
SPI_WORKFLOW_MESSAGES,STAFF_ID,0
SPI_WORKFLOW_MESSAGES,COURSE_SESSION,0
SPI_WORKFLOW_MESSAGES,SCHD_RESOLVED,0
SPI_WORKFLOW_MESSAGES,MESSAGE_DATE1,0
SPI_WORKFLOW_MESSAGES,MESSAGE_DATE2,0
SPI_WORKFLOW_MESSAGES,CHANGE_DATE_TIME,0
SPI_WORKFLOW_MESSAGES,CHANGE_UID,0
SPI_WORKFLOW_MESSAGES,FROM_BUILDING,0
SPI_Z_SCALE,DISTRICT,1
SPI_Z_SCALE,Z_INDEX,1
SPI_Z_SCALE,PERCENTILE,1
SPITB_SEARCH_FAV_CATEGORY,DISTRICT,1
SPITB_SEARCH_FAV_CATEGORY,CODE,1
SPITB_SEARCH_FAV_CATEGORY,DESCRIPTION,0
SPITB_SEARCH_FAV_CATEGORY,ACTIVE,0
SPITB_SEARCH_FAV_CATEGORY,RESERVED,0
SPITB_SEARCH_FAV_CATEGORY,CHANGE_DATE_TIME,0
SPITB_SEARCH_FAV_CATEGORY,CHANGE_UID,0
SSP_CFG,DISTRICT,1
SSP_CFG,BUILDING,1
SSP_CFG,TEA_STU_SUMM,0
SSP_CFG,SUB_STU_SUMM,0
SSP_CFG,TEA_SENS_PLAN,0
SSP_CFG,SUB_SENS_PLAN,0
SSP_CFG,TEA_SENS_INT,0
SSP_CFG,SUB_SENS_INT,0
SSP_CFG,TEA_SENS_INT_COMM,0
SSP_CFG,SUB_SENS_INT_COMM,0
SSP_CFG,TEA_INT_MNT,0
SSP_CFG,SUB_INT_MNT,0
SSP_CFG,TEA_GOAL_VIEW,0
SSP_CFG,SUB_GOAL_VIEW,0
SSP_CFG,TEA_GOAL_MNT,0
SSP_CFG,SUB_GOAL_MNT,0
SSP_CFG,TEA_GOAL_ACCESS,0
SSP_CFG,SUB_GOAL_ACCESS,0
SSP_CFG,TEA_INT_ACCESS,0
SSP_CFG,SUB_INT_ACCESS,0
SSP_CFG,CHANGE_DATE_TIME,0
SSP_CFG,CHANGE_UID,0
SSP_CFG_AUX,DISTRICT,1
SSP_CFG_AUX,BUILDING,1
SSP_CFG_AUX,TEA_PLAN_ENTRY,0
SSP_CFG_AUX,SUB_PLAN_ENTRY,0
SSP_CFG_AUX,TEA_PLAN_UPD,0
SSP_CFG_AUX,SUB_PLAN_UPD,0
SSP_CFG_AUX,TEA_PLAN_UPD_UNASGN,0
SSP_CFG_AUX,SUB_PLAN_UPD_UNASGN,0
SSP_CFG_AUX,TEA_PLAN_DEL,0
SSP_CFG_AUX,SUB_PLAN_DEL,0
SSP_CFG_AUX,TEA_PLAN_DEL_UNASGN,0
SSP_CFG_AUX,SUB_PLAN_DEL_UNASGN,0
SSP_CFG_AUX,TEA_PLAN_VIEW_UNASGN,0
SSP_CFG_AUX,SUB_PLAN_VIEW_UNASGN,0
SSP_CFG_AUX,TEA_INT_ENTRY,0
SSP_CFG_AUX,SUB_INT_ENTRY,0
SSP_CFG_AUX,TEA_INT_UPD,0
SSP_CFG_AUX,SUB_INT_UPD,0
SSP_CFG_AUX,TEA_INT_UPD_UNASGN,0
SSP_CFG_AUX,SUB_INT_UPD_UNASGN,0
SSP_CFG_AUX,TEA_INT_DEL,0
SSP_CFG_AUX,SUB_INT_DEL,0
SSP_CFG_AUX,TEA_INT_DEL_UNASGN,0
SSP_CFG_AUX,SUB_INT_DEL_UNASGN,0
SSP_CFG_AUX,TEA_INT_VIEW_UNASGN,0
SSP_CFG_AUX,SUB_INT_VIEW_UNASGN,0
SSP_CFG_AUX,TEA_INT_PROG_ENT_UNASGN,0
SSP_CFG_AUX,SUB_INT_PROG_ENT_UNASGN,0
SSP_CFG_AUX,TEA_INT_PROG_DEL,0
SSP_CFG_AUX,SUB_INT_PROG_DEL,0
SSP_CFG_AUX,TEA_INT_PROG_DEL_UNASGN,0
SSP_CFG_AUX,SUB_INT_PROG_DEL_UNASGN,0
SSP_CFG_AUX,TEA_GOAL_ENTRY,0
SSP_CFG_AUX,SUB_GOAL_ENTRY,0
SSP_CFG_AUX,TEA_GOAL_UPD,0
SSP_CFG_AUX,SUB_GOAL_UPD,0
SSP_CFG_AUX,TEA_GOAL_UPD_UNASGN,0
SSP_CFG_AUX,SUB_GOAL_UPD_UNASGN,0
SSP_CFG_AUX,TEA_GOAL_DEL,0
SSP_CFG_AUX,SUB_GOAL_DEL,0
SSP_CFG_AUX,TEA_GOAL_DEL_UNASGN,0
SSP_CFG_AUX,SUB_GOAL_DEL_UNASGN,0
SSP_CFG_AUX,TEA_GOAL_VIEW_UNASGN,0
SSP_CFG_AUX,SUB_GOAL_VIEW_UNASGN,0
SSP_CFG_AUX,TEA_GOAL_OBJ_ENT_UNASGN,0
SSP_CFG_AUX,SUB_GOAL_OBJ_ENT_UNASGN,0
SSP_CFG_AUX,TEA_GOAL_OBJ_DEL,0
SSP_CFG_AUX,SUB_GOAL_OBJ_DEL,0
SSP_CFG_AUX,TEA_GOAL_OBJ_DEL_UNASGN,0
SSP_CFG_AUX,SUB_GOAL_OBJ_DEL_UNASGN,0
SSP_CFG_AUX,CHANGE_DATE_TIME,0
SSP_CFG_AUX,CHANGE_UID,0
SSP_CFG_PLAN_GOALS,DISTRICT,1
SSP_CFG_PLAN_GOALS,BUILDING,1
SSP_CFG_PLAN_GOALS,PLAN_TYPE,1
SSP_CFG_PLAN_GOALS,GOAL,1
SSP_CFG_PLAN_GOALS,CHANGE_DATE_TIME,0
SSP_CFG_PLAN_GOALS,CHANGE_UID,0
SSP_CFG_PLAN_INTERVENTIONS,DISTRICT,1
SSP_CFG_PLAN_INTERVENTIONS,BUILDING,1
SSP_CFG_PLAN_INTERVENTIONS,PLAN_TYPE,1
SSP_CFG_PLAN_INTERVENTIONS,INTERVENTION,1
SSP_CFG_PLAN_INTERVENTIONS,CHANGE_DATE_TIME,0
SSP_CFG_PLAN_INTERVENTIONS,CHANGE_UID,0
SSP_CFG_PLAN_REASONS,DISTRICT,1
SSP_CFG_PLAN_REASONS,BUILDING,1
SSP_CFG_PLAN_REASONS,PLAN_TYPE,1
SSP_CFG_PLAN_REASONS,REASON_CODE,1
SSP_CFG_PLAN_REASONS,CHANGE_DATE_TIME,0
SSP_CFG_PLAN_REASONS,CHANGE_UID,0
SSP_CFG_PLAN_RESTRICTIONS,DISTRICT,1
SSP_CFG_PLAN_RESTRICTIONS,BUILDING,1
SSP_CFG_PLAN_RESTRICTIONS,PLAN_TYPE,1
SSP_CFG_PLAN_RESTRICTIONS,ACTIVE,0
SSP_CFG_PLAN_RESTRICTIONS,CHANGE_DATE_TIME,0
SSP_CFG_PLAN_RESTRICTIONS,CHANGE_UID,0
SSP_COORDINATOR,DISTRICT,1
SSP_COORDINATOR,BUILDING,1
SSP_COORDINATOR,REFER_SEQUENCE,1
SSP_COORDINATOR,SSP_REFER_TAG,0
SSP_COORDINATOR,REFER_TO,0
SSP_COORDINATOR,REFER_SEQ_ORDER,0
SSP_COORDINATOR,LOGIN_ID,0
SSP_COORDINATOR,USE_FILTER,0
SSP_COORDINATOR,CHANGE_DATE_TIME,0
SSP_COORDINATOR,CHANGE_UID,0
SSP_COORDINATOR_FILTER,DISTRICT,1
SSP_COORDINATOR_FILTER,BUILDING,1
SSP_COORDINATOR_FILTER,REFER_SEQUENCE,1
SSP_COORDINATOR_FILTER,SEQUENCE_NUM,1
SSP_COORDINATOR_FILTER,AND_OR_FLAG,0
SSP_COORDINATOR_FILTER,TABLE_NAME,0
SSP_COORDINATOR_FILTER,COLUMN_NAME,0
SSP_COORDINATOR_FILTER,OPERATOR,0
SSP_COORDINATOR_FILTER,SEARCH_VALUE1,0
SSP_COORDINATOR_FILTER,CHANGE_DATE_TIME,0
SSP_COORDINATOR_FILTER,CHANGE_UID,0
SSP_DISTRICT_CFG,DISTRICT,1
SSP_DISTRICT_CFG,USE_PERF_LEVEL,0
SSP_DISTRICT_CFG,CHANGE_DATE_TIME,0
SSP_DISTRICT_CFG,CHANGE_UID,0
SSP_GD_SCALE_DET,DISTRICT,1
SSP_GD_SCALE_DET,GRADING_SCALE_TYPE,1
SSP_GD_SCALE_DET,DISPLAY_ORDER,1
SSP_GD_SCALE_DET,MARK,0
SSP_GD_SCALE_DET,DESCRIPTION,0
SSP_GD_SCALE_DET,ACTIVE,0
SSP_GD_SCALE_DET,CHANGE_DATE_TIME,0
SSP_GD_SCALE_DET,CHANGE_UID,0
SSP_GD_SCALE_HDR,DISTRICT,1
SSP_GD_SCALE_HDR,GRADING_SCALE_TYPE,1
SSP_GD_SCALE_HDR,DESCRIPTION,0
SSP_GD_SCALE_HDR,DEFAULT_MARK,0
SSP_GD_SCALE_HDR,CHANGE_DATE_TIME,0
SSP_GD_SCALE_HDR,CHANGE_UID,0
SSP_INTER_FREQ_DT,DISTRICT,1
SSP_INTER_FREQ_DT,INTERVENTION,1
SSP_INTER_FREQ_DT,INTER_DATE,1
SSP_INTER_FREQ_DT,CHANGE_DATE_TIME,0
SSP_INTER_FREQ_DT,CHANGE_UID,0
SSP_INTER_MARKS,DISTRICT,1
SSP_INTER_MARKS,INTERVENTION,1
SSP_INTER_MARKS,MARK_TYPE,1
SSP_INTER_MARKS,GRADE_SCALE,0
SSP_INTER_MARKS,CHANGE_DATE_TIME,0
SSP_INTER_MARKS,CHANGE_UID,0
SSP_INTERVENTION,DISTRICT,1
SSP_INTERVENTION,INTERVENTION,1
SSP_INTERVENTION,DESCRIPTION,0
SSP_INTERVENTION,INTERVEN_TYPE,0
SSP_INTERVENTION,FREQUENCY,0
SSP_INTERVENTION,FREQ_WEEKDAY,0
SSP_INTERVENTION,STATE_COURSE_EQUIV,0
SSP_INTERVENTION,ACTIVE,0
SSP_INTERVENTION,CHANGE_DATE_TIME,0
SSP_INTERVENTION,CHANGE_UID,0
SSP_MARK_TYPES,DISTRICT,1
SSP_MARK_TYPES,MARK_TYPE,1
SSP_MARK_TYPES,MARK_ORDER,0
SSP_MARK_TYPES,DESCRIPTION,0
SSP_MARK_TYPES,ACTIVE,0
SSP_MARK_TYPES,DEFAULT_GRADE_SCALE,0
SSP_MARK_TYPES,CHANGE_DATE_TIME,0
SSP_MARK_TYPES,CHANGE_UID,0
SSP_PARENT_GOAL,DISTRICT,1
SSP_PARENT_GOAL,STUDENT_ID,1
SSP_PARENT_GOAL,PLAN_NUM,1
SSP_PARENT_GOAL,GOAL,1
SSP_PARENT_GOAL,COMPLETION_DATE,0
SSP_PARENT_GOAL,COMMENT,0
SSP_PARENT_GOAL,ENTERED_BY,0
SSP_PARENT_GOAL,CHANGE_DATE_TIME,0
SSP_PARENT_GOAL,CHANGE_UID,0
SSP_PARENT_OBJECTIVE,DISTRICT,1
SSP_PARENT_OBJECTIVE,STUDENT_ID,1
SSP_PARENT_OBJECTIVE,PLAN_NUM,1
SSP_PARENT_OBJECTIVE,GOAL,1
SSP_PARENT_OBJECTIVE,OBJECTIVE,0
SSP_PARENT_OBJECTIVE,SEQUENCE_NUM,1
SSP_PARENT_OBJECTIVE,COMMENT,0
SSP_PARENT_OBJECTIVE,COMMENT_ORDER,1
SSP_PARENT_OBJECTIVE,COMPLETION_DATE,0
SSP_PARENT_OBJECTIVE,CHANGE_DATE_TIME,0
SSP_PARENT_OBJECTIVE,CHANGE_UID,0
SSP_PERF_LEVEL_DET,DISTRICT,1
SSP_PERF_LEVEL_DET,PERF_CODE,1
SSP_PERF_LEVEL_DET,LEVEL,1
SSP_PERF_LEVEL_DET,SUBLEVEL,0
SSP_PERF_LEVEL_DET,GRADE,0
SSP_PERF_LEVEL_DET,RANGE_START,0
SSP_PERF_LEVEL_DET,RANGE_END,0
SSP_PERF_LEVEL_DET,CHANGE_DATE_TIME,0
SSP_PERF_LEVEL_DET,CHANGE_UID,0
SSP_PERF_LEVEL_HDR,DISTRICT,1
SSP_PERF_LEVEL_HDR,PERF_CODE,1
SSP_PERF_LEVEL_HDR,TEST_CODE,1
SSP_PERF_LEVEL_HDR,TEST_LEVEL,1
SSP_PERF_LEVEL_HDR,TEST_FORM,1
SSP_PERF_LEVEL_HDR,SUBTEST,1
SSP_PERF_LEVEL_HDR,SCORE_CODE,1
SSP_PERF_LEVEL_HDR,CHANGE_DATE_TIME,0
SSP_PERF_LEVEL_HDR,CHANGE_UID,0
SSP_QUAL_DET,DISTRICT,1
SSP_QUAL_DET,QUALIFICATION,1
SSP_QUAL_DET,QUAL_REASON,1
SSP_QUAL_DET,QUAL_TYPE,1
SSP_QUAL_DET,SEQUENCE_NUM,1
SSP_QUAL_DET,START_DATE,0
SSP_QUAL_DET,END_DATE,0
SSP_QUAL_DET,TEST_CODE,0
SSP_QUAL_DET,TEST_LEVEL,0
SSP_QUAL_DET,TEST_FORM,0
SSP_QUAL_DET,SUBTEST,0
SSP_QUAL_DET,GRADE,0
SSP_QUAL_DET,SCORE_CODE,0
SSP_QUAL_DET,CONDITION,0
SSP_QUAL_DET,QUAL_VALUE,0
SSP_QUAL_DET,AIS_QUALIFIER,0
SSP_QUAL_DET,CHANGE_DATE_TIME,0
SSP_QUAL_DET,CHANGE_UID,0
SSP_QUAL_HDR,DISTRICT,1
SSP_QUAL_HDR,QUALIFICATION,1
SSP_QUAL_HDR,DESCRIPTION,0
SSP_QUAL_HDR,QUAL_REASON,1
SSP_QUAL_HDR,CHANGE_DATE_TIME,0
SSP_QUAL_HDR,CHANGE_UID,0
SSP_QUAL_SEARCH,DISTRICT,1
SSP_QUAL_SEARCH,QUALIFICATION,1
SSP_QUAL_SEARCH,QUAL_REASON,1
SSP_QUAL_SEARCH,SEQUENCE_NUM,1
SSP_QUAL_SEARCH,AND_OR_FLAG,0
SSP_QUAL_SEARCH,TABLE_NAME,0
SSP_QUAL_SEARCH,SCREEN_TYPE,0
SSP_QUAL_SEARCH,SCREEN_NUMBER,0
SSP_QUAL_SEARCH,PROGRAM_ID,0
SSP_QUAL_SEARCH,COLUMN_NAME,0
SSP_QUAL_SEARCH,FIELD_NUMBER,0
SSP_QUAL_SEARCH,OPERATOR,0
SSP_QUAL_SEARCH,SEARCH_VALUE1,0
SSP_QUAL_SEARCH,SEARCH_VALUE2,0
SSP_QUAL_SEARCH,CHANGE_DATE_TIME,0
SSP_QUAL_SEARCH,CHANGE_UID,0
SSP_RSN_TEMP_GOAL,DISTRICT,1
SSP_RSN_TEMP_GOAL,QUAL_REASON,1
SSP_RSN_TEMP_GOAL,GRADE,1
SSP_RSN_TEMP_GOAL,GOAL,1
SSP_RSN_TEMP_GOAL,COMMENT,0
SSP_RSN_TEMP_GOAL,GOAL_MANAGER,0
SSP_RSN_TEMP_GOAL,GOAL_LEVEL,0
SSP_RSN_TEMP_GOAL,GOAL_DETAIL,0
SSP_RSN_TEMP_GOAL,BASELINE,0
SSP_RSN_TEMP_GOAL,CHANGE_DATE_TIME,0
SSP_RSN_TEMP_GOAL,CHANGE_UID,0
SSP_RSN_TEMP_GOAL_OBJ,DISTRICT,1
SSP_RSN_TEMP_GOAL_OBJ,QUAL_REASON,1
SSP_RSN_TEMP_GOAL_OBJ,GRADE,1
SSP_RSN_TEMP_GOAL_OBJ,GOAL,1
SSP_RSN_TEMP_GOAL_OBJ,OBJECTIVE,0
SSP_RSN_TEMP_GOAL_OBJ,SEQUENCE_NUM,1
SSP_RSN_TEMP_GOAL_OBJ,COMMENT,0
SSP_RSN_TEMP_GOAL_OBJ,CHANGE_DATE_TIME,0
SSP_RSN_TEMP_GOAL_OBJ,CHANGE_UID,0
SSP_RSN_TEMP_HDR,DISTRICT,1
SSP_RSN_TEMP_HDR,QUAL_REASON,1
SSP_RSN_TEMP_HDR,GRADE,1
SSP_RSN_TEMP_HDR,CHANGE_DATE_TIME,0
SSP_RSN_TEMP_HDR,CHANGE_UID,0
SSP_RSN_TEMP_INT,DISTRICT,1
SSP_RSN_TEMP_INT,QUAL_REASON,1
SSP_RSN_TEMP_INT,GRADE,1
SSP_RSN_TEMP_INT,INTERVENTION,1
SSP_RSN_TEMP_INT,SENSITIVE_FLAG,0
SSP_RSN_TEMP_INT,LEVEL,0
SSP_RSN_TEMP_INT,ROLE_EVALUATOR,0
SSP_RSN_TEMP_INT,FREQUENCY,0
SSP_RSN_TEMP_INT,FREQ_WEEKDAY,0
SSP_RSN_TEMP_INT,STAFF_ID,0
SSP_RSN_TEMP_INT,CHANGE_DATE_TIME,0
SSP_RSN_TEMP_INT,CHANGE_UID,0
SSP_RSN_TEMP_PARENT_GOAL,DISTRICT,1
SSP_RSN_TEMP_PARENT_GOAL,QUAL_REASON,1
SSP_RSN_TEMP_PARENT_GOAL,GRADE,1
SSP_RSN_TEMP_PARENT_GOAL,GOAL,1
SSP_RSN_TEMP_PARENT_GOAL,COMMENT,0
SSP_RSN_TEMP_PARENT_GOAL,CHANGE_DATE_TIME,0
SSP_RSN_TEMP_PARENT_GOAL,CHANGE_UID,0
SSP_RSN_TEMP_PARENT_GOAL_OBJ,DISTRICT,1
SSP_RSN_TEMP_PARENT_GOAL_OBJ,QUAL_REASON,1
SSP_RSN_TEMP_PARENT_GOAL_OBJ,GRADE,1
SSP_RSN_TEMP_PARENT_GOAL_OBJ,GOAL,1
SSP_RSN_TEMP_PARENT_GOAL_OBJ,OBJECTIVE,0
SSP_RSN_TEMP_PARENT_GOAL_OBJ,SEQUENCE_NUM,1
SSP_RSN_TEMP_PARENT_GOAL_OBJ,COMMENT,0
SSP_RSN_TEMP_PARENT_GOAL_OBJ,CHANGE_DATE_TIME,0
SSP_RSN_TEMP_PARENT_GOAL_OBJ,CHANGE_UID,0
SSP_STU_AT_RISK,DISTRICT,1
SSP_STU_AT_RISK,STUDENT_ID,1
SSP_STU_AT_RISK,QUAL_REASON,1
SSP_STU_AT_RISK,START_DATE,1
SSP_STU_AT_RISK,END_DATE,0
SSP_STU_AT_RISK,PLAN_NUM,0
SSP_STU_AT_RISK,PLAN_DATE,0
SSP_STU_AT_RISK,CHANGE_DATE_TIME,0
SSP_STU_AT_RISK,CHANGE_UID,0
SSP_STU_GOAL,DISTRICT,1
SSP_STU_GOAL,STUDENT_ID,1
SSP_STU_GOAL,PLAN_NUM,1
SSP_STU_GOAL,GOAL,1
SSP_STU_GOAL,COMPLETION_DATE,0
SSP_STU_GOAL,COMMENT,0
SSP_STU_GOAL,GOAL_LEVEL,0
SSP_STU_GOAL,GOAL_DETAIL,0
SSP_STU_GOAL,BASELINE,0
SSP_STU_GOAL,ENTERED_BY,0
SSP_STU_GOAL,CHANGE_DATE_TIME,0
SSP_STU_GOAL,CHANGE_UID,0
SSP_STU_GOAL_STAFF,DISTRICT,1
SSP_STU_GOAL_STAFF,STUDENT_ID,1
SSP_STU_GOAL_STAFF,PLAN_NUM,1
SSP_STU_GOAL_STAFF,GOAL,1
SSP_STU_GOAL_STAFF,STAFF_ID,1
SSP_STU_GOAL_STAFF,CHANGE_DATE_TIME,0
SSP_STU_GOAL_STAFF,CHANGE_UID,0
SSP_STU_GOAL_TEMP,DISTRICT,0
SSP_STU_GOAL_TEMP,STUDENT_ID,0
SSP_STU_GOAL_TEMP,PLAN_NUM,0
SSP_STU_GOAL_TEMP,GOAL,0
SSP_STU_GOAL_TEMP,COMPLETION_DATE,0
SSP_STU_GOAL_TEMP,COMMENT,0
SSP_STU_GOAL_TEMP,GOAL_MANAGER,0
SSP_STU_GOAL_TEMP,GOAL_LEVEL,0
SSP_STU_GOAL_TEMP,GOAL_DETAIL,0
SSP_STU_GOAL_TEMP,BASELINE,0
SSP_STU_GOAL_TEMP,ENTERED_BY,0
SSP_STU_GOAL_TEMP,CHANGE_DATE_TIME,0
SSP_STU_GOAL_TEMP,CHANGE_UID,0
SSP_STU_GOAL_USER,DISTRICT,1
SSP_STU_GOAL_USER,STUDENT_ID,1
SSP_STU_GOAL_USER,PLAN_NUM,1
SSP_STU_GOAL_USER,GOAL,1
SSP_STU_GOAL_USER,FIELD_NUMBER,1
SSP_STU_GOAL_USER,FIELD_VALUE,0
SSP_STU_GOAL_USER,CHANGE_DATE_TIME,0
SSP_STU_GOAL_USER,CHANGE_UID,0
SSP_STU_INT,DISTRICT,1
SSP_STU_INT,STUDENT_ID,1
SSP_STU_INT,PLAN_NUM,1
SSP_STU_INT,INTERVENTION,1
SSP_STU_INT,START_DATE,0
SSP_STU_INT,COMPLETION_DATE,0
SSP_STU_INT,SENSITIVE_FLAG,0
SSP_STU_INT,LEVEL,0
SSP_STU_INT,ROLE_EVALUATOR,0
SSP_STU_INT,FREQUENCY,0
SSP_STU_INT,FREQ_WEEKDAY,0
SSP_STU_INT,CHANGE_DATE_TIME,0
SSP_STU_INT,CHANGE_UID,0
SSP_STU_INT_COMM,DISTRICT,1
SSP_STU_INT_COMM,STUDENT_ID,1
SSP_STU_INT_COMM,PLAN_NUM,1
SSP_STU_INT_COMM,INTERVENTION,1
SSP_STU_INT_COMM,COMMENT_TYPE,1
SSP_STU_INT_COMM,SEQUENCE_NUM,1
SSP_STU_INT_COMM,COMMENT,0
SSP_STU_INT_COMM,COMMENT_ORDER,1
SSP_STU_INT_COMM,ENTRY_DATE,0
SSP_STU_INT_COMM,SENSITIVE_FLAG,0
SSP_STU_INT_COMM,CHANGE_DATE_TIME,0
SSP_STU_INT_COMM,CHANGE_UID,0
SSP_STU_INT_FREQ_DT,DISTRICT,1
SSP_STU_INT_FREQ_DT,STUDENT_ID,1
SSP_STU_INT_FREQ_DT,PLAN_NUM,1
SSP_STU_INT_FREQ_DT,INTERVENTION,1
SSP_STU_INT_FREQ_DT,ENTRY_DATE,1
SSP_STU_INT_FREQ_DT,CHANGE_DATE_TIME,0
SSP_STU_INT_FREQ_DT,CHANGE_UID,0
SSP_STU_INT_PROG,DISTRICT,1
SSP_STU_INT_PROG,STUDENT_ID,1
SSP_STU_INT_PROG,PLAN_NUM,1
SSP_STU_INT_PROG,INTERVENTION,1
SSP_STU_INT_PROG,ENTRY_DATE,1
SSP_STU_INT_PROG,MARK_TYPE,1
SSP_STU_INT_PROG,MARK_VALUE,0
SSP_STU_INT_PROG,CHANGE_DATE_TIME,0
SSP_STU_INT_PROG,CHANGE_UID,0
SSP_STU_INT_STAFF,DISTRICT,1
SSP_STU_INT_STAFF,STUDENT_ID,1
SSP_STU_INT_STAFF,PLAN_NUM,1
SSP_STU_INT_STAFF,INTERVENTION,1
SSP_STU_INT_STAFF,STAFF_ID,1
SSP_STU_INT_STAFF,CHANGE_DATE_TIME,0
SSP_STU_INT_STAFF,CHANGE_UID,0
SSP_STU_INT_TEMP,DISTRICT,0
SSP_STU_INT_TEMP,STUDENT_ID,0
SSP_STU_INT_TEMP,PLAN_NUM,0
SSP_STU_INT_TEMP,INTERVENTION,0
SSP_STU_INT_TEMP,START_DATE,0
SSP_STU_INT_TEMP,COMPLETION_DATE,0
SSP_STU_INT_TEMP,SENSITIVE_FLAG,0
SSP_STU_INT_TEMP,LEVEL,0
SSP_STU_INT_TEMP,ROLE_EVALUATOR,0
SSP_STU_INT_TEMP,FREQUENCY,0
SSP_STU_INT_TEMP,FREQ_WEEKDAY,0
SSP_STU_INT_TEMP,STAFF_ID,0
SSP_STU_INT_TEMP,CHANGE_DATE_TIME,0
SSP_STU_INT_TEMP,CHANGE_UID,0
SSP_STU_OBJ_USER,DISTRICT,1
SSP_STU_OBJ_USER,STUDENT_ID,1
SSP_STU_OBJ_USER,PLAN_NUM,1
SSP_STU_OBJ_USER,GOAL,1
SSP_STU_OBJ_USER,SEQUENCE_NUMBER,1
SSP_STU_OBJ_USER,FIELD_NUMBER,1
SSP_STU_OBJ_USER,FIELD_VALUE,0
SSP_STU_OBJ_USER,CHANGE_DATE_TIME,0
SSP_STU_OBJ_USER,CHANGE_UID,0
SSP_STU_OBJECTIVE,DISTRICT,1
SSP_STU_OBJECTIVE,STUDENT_ID,1
SSP_STU_OBJECTIVE,PLAN_NUM,1
SSP_STU_OBJECTIVE,GOAL,1
SSP_STU_OBJECTIVE,OBJECTIVE,0
SSP_STU_OBJECTIVE,SEQUENCE_NUM,1
SSP_STU_OBJECTIVE,COMMENT,0
SSP_STU_OBJECTIVE,COMMENT_ORDER,1
SSP_STU_OBJECTIVE,COMPLETION_DATE,0
SSP_STU_OBJECTIVE,CHANGE_DATE_TIME,0
SSP_STU_OBJECTIVE,CHANGE_UID,0
SSP_STU_PLAN,DISTRICT,1
SSP_STU_PLAN,STUDENT_ID,1
SSP_STU_PLAN,PLAN_NUM,1
SSP_STU_PLAN,PLAN_DATE,0
SSP_STU_PLAN,PLAN_TITLE,0
SSP_STU_PLAN,COMPLETION_DATE,0
SSP_STU_PLAN,STATUS,0
SSP_STU_PLAN,SENSITIVE_FLAG,0
SSP_STU_PLAN,PLAN_TYPE,0
SSP_STU_PLAN,PLAN_MANAGER,0
SSP_STU_PLAN,QUALIFICATIONS,0
SSP_STU_PLAN,COMPLETION_NOTES,0
SSP_STU_PLAN,CHANGE_DATE_TIME,0
SSP_STU_PLAN,CHANGE_UID,0
SSP_STU_PLAN_USER,DISTRICT,1
SSP_STU_PLAN_USER,STUDENT_ID,1
SSP_STU_PLAN_USER,PLAN_NUM,1
SSP_STU_PLAN_USER,FIELD_NUMBER,1
SSP_STU_PLAN_USER,FIELD_VALUE,0
SSP_STU_PLAN_USER,CHANGE_DATE_TIME,0
SSP_STU_PLAN_USER,CHANGE_UID,0
SSP_USER_FIELDS,DISTRICT,1
SSP_USER_FIELDS,PLAN_TYPE,1
SSP_USER_FIELDS,SCREEN_TYPE,1
SSP_USER_FIELDS,FIELD_NUMBER,1
SSP_USER_FIELDS,FIELD_LABEL,0
SSP_USER_FIELDS,FIELD_ORDER,0
SSP_USER_FIELDS,REQUIRED_FIELD,0
SSP_USER_FIELDS,FIELD_TYPE,0
SSP_USER_FIELDS,DATA_TYPE,0
SSP_USER_FIELDS,NUMBER_TYPE,0
SSP_USER_FIELDS,DATA_LENGTH,0
SSP_USER_FIELDS,FIELD_SCALE,0
SSP_USER_FIELDS,FIELD_PRECISION,0
SSP_USER_FIELDS,DEFAULT_VALUE,0
SSP_USER_FIELDS,DEFAULT_TABLE,0
SSP_USER_FIELDS,DEFAULT_COLUMN,0
SSP_USER_FIELDS,VALIDATION_LIST,0
SSP_USER_FIELDS,VALIDATION_TABLE,0
SSP_USER_FIELDS,CODE_COLUMN,0
SSP_USER_FIELDS,DESCRIPTION_COLUMN,0
SSP_USER_FIELDS,CHANGE_DATE_TIME,0
SSP_USER_FIELDS,CHANGE_UID,0
SSP_YEAREND_RUN,DISTRICT,1
SSP_YEAREND_RUN,SCHOOL_YEAR,1
SSP_YEAREND_RUN,RUN_KEY,1
SSP_YEAREND_RUN,RUN_DATE,0
SSP_YEAREND_RUN,RUN_STATUS,0
SSP_YEAREND_RUN,RESTORE_KEY,0
SSP_YEAREND_RUN,CLEAN_SSP_DATA,0
SSP_YEAREND_RUN,CHANGE_DATE_TIME,0
SSP_YEAREND_RUN,CHANGE_UID,0
SSPTB_AIS_LEVEL,DISTRICT,1
SSPTB_AIS_LEVEL,CODE,1
SSPTB_AIS_LEVEL,DESCRIPTION,0
SSPTB_AIS_LEVEL,ACTIVE,0
SSPTB_AIS_LEVEL,CHANGE_DATE_TIME,0
SSPTB_AIS_LEVEL,CHANGE_UID,0
SSPTB_AIS_TYPE,DISTRICT,1
SSPTB_AIS_TYPE,CODE,1
SSPTB_AIS_TYPE,DESCRIPTION,0
SSPTB_AIS_TYPE,ACTIVE,0
SSPTB_AIS_TYPE,CHANGE_DATE_TIME,0
SSPTB_AIS_TYPE,CHANGE_UID,0
SSPTB_GOAL,DISTRICT,1
SSPTB_GOAL,CODE,1
SSPTB_GOAL,DESCRIPTION,0
SSPTB_GOAL,HAC_STUDENT,0
SSPTB_GOAL,HAC_PARENT,0
SSPTB_GOAL,ACTIVE,0
SSPTB_GOAL,CHANGE_DATE_TIME,0
SSPTB_GOAL,CHANGE_UID,0
SSPTB_GOAL_LEVEL,DISTRICT,1
SSPTB_GOAL_LEVEL,LEVEL_CODE,1
SSPTB_GOAL_LEVEL,DESCRIPTION,0
SSPTB_GOAL_LEVEL,ACTIVE,0
SSPTB_GOAL_LEVEL,CHANGE_DATE_TIME,0
SSPTB_GOAL_LEVEL,CHANGE_UID,0
SSPTB_OBJECTIVE,DISTRICT,1
SSPTB_OBJECTIVE,CODE,1
SSPTB_OBJECTIVE,DESCRIPTION,0
SSPTB_OBJECTIVE,ACTIVE,0
SSPTB_OBJECTIVE,CHANGE_DATE_TIME,0
SSPTB_OBJECTIVE,CHANGE_UID,0
SSPTB_PLAN_STATUS,DISTRICT,1
SSPTB_PLAN_STATUS,CODE,1
SSPTB_PLAN_STATUS,DESCRIPTION,0
SSPTB_PLAN_STATUS,ACTIVE,0
SSPTB_PLAN_STATUS,CHANGE_DATE_TIME,0
SSPTB_PLAN_STATUS,CHANGE_UID,0
SSPTB_PLAN_TYPE,DISTRICT,1
SSPTB_PLAN_TYPE,PLAN_TYPE,1
SSPTB_PLAN_TYPE,DESCRIPTION,0
SSPTB_PLAN_TYPE,ACTIVE,0
SSPTB_PLAN_TYPE,CHANGE_DATE_TIME,0
SSPTB_PLAN_TYPE,CHANGE_UID,0
SSPTB_ROLE_EVAL,DISTRICT,1
SSPTB_ROLE_EVAL,CODE,1
SSPTB_ROLE_EVAL,DESCRIPTION,0
SSPTB_ROLE_EVAL,ACTIVE,0
SSPTB_ROLE_EVAL,CHANGE_DATE_TIME,0
SSPTB_ROLE_EVAL,CHANGE_UID,0
STATE_DISTDEF_SCREENS,DISTRICT,1
STATE_DISTDEF_SCREENS,SCREEN_USED_FOR,1
STATE_DISTDEF_SCREENS,SCREEN_TYPE,1
STATE_DISTDEF_SCREENS,SCREEN_NUMBER,1
STATE_DISTDEF_SCREENS,CHANGE_DATE_TIME,0
STATE_DISTDEF_SCREENS,CHANGE_UID,0
STATE_DNLD_SUM_INFO,DISTRICT,1
STATE_DNLD_SUM_INFO,STATE,1
STATE_DNLD_SUM_INFO,DOWNLOAD_TYPE,1
STATE_DNLD_SUM_INFO,TABLE_NAME,1
STATE_DNLD_SUM_INFO,MULTI_RECORDS,0
STATE_DNLD_SUM_INFO,DISPLAY_ORDER,0
STATE_DNLD_SUM_INFO,CHANGE_DATE_TIME,0
STATE_DNLD_SUM_INFO,CHANGE_UID,0
STATE_DNLD_SUM_TABLES,DISTRICT,1
STATE_DNLD_SUM_TABLES,STATE,1
STATE_DNLD_SUM_TABLES,DOWNLOAD_TYPE,1
STATE_DNLD_SUM_TABLES,TABLE_NAME,1
STATE_DNLD_SUM_TABLES,SESSION_FIELD,1
STATE_DNLD_SUM_TABLES,DOWNLOAD_FIELD,0
STATE_DNLD_SUM_TABLES,CHANGE_DATE_TIME,0
STATE_DNLD_SUM_TABLES,CHANGE_UID,0
STATE_DNLD_SUMMARY,DISTRICT,1
STATE_DNLD_SUMMARY,STATE,1
STATE_DNLD_SUMMARY,DOWNLOAD_TYPE,1
STATE_DNLD_SUMMARY,ALLOW_EDITS,0
STATE_DNLD_SUMMARY,SEARCH_TYPE,0
STATE_DNLD_SUMMARY,SEC_SUBPACKAGE,0
STATE_DNLD_SUMMARY,SEC_RESOURCE,0
STATE_DNLD_SUMMARY,SYSTEM_NAME,0
STATE_DNLD_SUMMARY,SEARCH_PAGE,0
STATE_DNLD_SUMMARY,LIST_PAGE,0
STATE_DNLD_SUMMARY,YEAR_COLUMN,0
STATE_DNLD_SUMMARY,CHANGE_DATE_TIME,0
STATE_DNLD_SUMMARY,CHANGE_UID,0
STATE_DOWNLOAD_AUDIT,DISTRICT,1
STATE_DOWNLOAD_AUDIT,TABLE_NAME,1
STATE_DOWNLOAD_AUDIT,KEYFIELD01,1
STATE_DOWNLOAD_AUDIT,KEYVALUE01,0
STATE_DOWNLOAD_AUDIT,KEYFIELD02,1
STATE_DOWNLOAD_AUDIT,KEYVALUE02,0
STATE_DOWNLOAD_AUDIT,KEYFIELD03,1
STATE_DOWNLOAD_AUDIT,KEYVALUE03,0
STATE_DOWNLOAD_AUDIT,KEYFIELD04,1
STATE_DOWNLOAD_AUDIT,KEYVALUE04,0
STATE_DOWNLOAD_AUDIT,KEYFIELD05,1
STATE_DOWNLOAD_AUDIT,KEYVALUE05,0
STATE_DOWNLOAD_AUDIT,KEYFIELD06,1
STATE_DOWNLOAD_AUDIT,KEYVALUE06,0
STATE_DOWNLOAD_AUDIT,KEYFIELD07,1
STATE_DOWNLOAD_AUDIT,KEYVALUE07,0
STATE_DOWNLOAD_AUDIT,KEYFIELD08,1
STATE_DOWNLOAD_AUDIT,KEYVALUE08,0
STATE_DOWNLOAD_AUDIT,KEYFIELD09,1
STATE_DOWNLOAD_AUDIT,KEYVALUE09,0
STATE_DOWNLOAD_AUDIT,KEYFIELD10,1
STATE_DOWNLOAD_AUDIT,KEYVALUE10,0
STATE_DOWNLOAD_AUDIT,CHANGE_TYPE,0
STATE_DOWNLOAD_AUDIT,FIELD_CHANGED,1
STATE_DOWNLOAD_AUDIT,OLD_VALUE,0
STATE_DOWNLOAD_AUDIT,NEW_VALUE,0
STATE_DOWNLOAD_AUDIT,CHANGE_DATE_TIME,1
STATE_DOWNLOAD_AUDIT,CHANGE_UID,0
STATE_DWNLD_COLUMN_NAME,DISTRICT,1
STATE_DWNLD_COLUMN_NAME,TABLE_NAME,1
STATE_DWNLD_COLUMN_NAME,COLUMN_NAME,1
STATE_DWNLD_COLUMN_NAME,SUBMISSION_PERIOD,1
STATE_DWNLD_COLUMN_NAME,FIRST_SCHOOL_YEAR,1
STATE_DWNLD_COLUMN_NAME,COLUMN_DESCRIPTION,0
STATE_DWNLD_COLUMN_NAME,CHANGE_DATE_TIME,0
STATE_DWNLD_COLUMN_NAME,CHANGE_UID,0
STATE_OCR_BLDG_CFG,DISTRICT,1
STATE_OCR_BLDG_CFG,SCHOOL_YEAR,1
STATE_OCR_BLDG_CFG,BUILDING,1
STATE_OCR_BLDG_CFG,FEDERAL_CODE_EQUIV,0
STATE_OCR_BLDG_CFG,UNGRADED_DETAIL,0
STATE_OCR_BLDG_CFG,DISABILITY_SCHOOL,0
STATE_OCR_BLDG_CFG,MAGNET_SCHOOL,0
STATE_OCR_BLDG_CFG,MAGNET_ENTIRE_SCHOOL,0
STATE_OCR_BLDG_CFG,CHARTER_SCHOOL,0
STATE_OCR_BLDG_CFG,ALTERNATIVE_SCHOOL,0
STATE_OCR_BLDG_CFG,ALT_ACADEMIC_STUDENTS,0
STATE_OCR_BLDG_CFG,ALT_DISCIPLINE_STUDENTS,0
STATE_OCR_BLDG_CFG,ALT_OTHER_STUDENTS,0
STATE_OCR_BLDG_CFG,ALT_OTHER_COMMENTS,0
STATE_OCR_BLDG_CFG,ABILITY_GROUPED_SCHOOL,0
STATE_OCR_BLDG_CFG,AP_SELF_SELECT,0
STATE_OCR_BLDG_CFG,CLASSROOM_TEACHER_FTE,0
STATE_OCR_BLDG_CFG,LICENSED_TEACHER_FTE,0
STATE_OCR_BLDG_CFG,FTE_TEACHERS_NOTMEETSTATEREQ,0
STATE_OCR_BLDG_CFG,FIRST_YEAR_TEACHER_FTE,0
STATE_OCR_BLDG_CFG,SECOND_YEAR_TEACHER_FTE,0
STATE_OCR_BLDG_CFG,COUNSELOR_FTE,0
STATE_OCR_BLDG_CFG,BUILDING_COMMENTS,0
STATE_OCR_BLDG_CFG,DUAL_ENROLL,0
STATE_OCR_BLDG_CFG,INTERSCH_ATHLETICS,0
STATE_OCR_BLDG_CFG,INTERSCH_SPORTS_MALE,0
STATE_OCR_BLDG_CFG,INTERSCH_SPORTS_FEMALE,0
STATE_OCR_BLDG_CFG,INTERSCH_TEAMS_MALE,0
STATE_OCR_BLDG_CFG,INTERSCH_TEAMS_FEMALE,0
STATE_OCR_BLDG_CFG,INTERSCH_PARTIC_MALE,0
STATE_OCR_BLDG_CFG,INTERSCH_PARTIC_FEMALE,0
STATE_OCR_BLDG_CFG,HS_AGE_IN_UNGRADED,0
STATE_OCR_BLDG_CFG,ABSENT_TEN_DAY_FTE,0
STATE_OCR_BLDG_CFG,TOTAL_PERS_SALARY,0
STATE_OCR_BLDG_CFG,TOTAL_PERS_SALARY_FED_ST_LOC,0
STATE_OCR_BLDG_CFG,INSTR_PERS_SALARY,0
STATE_OCR_BLDG_CFG,NON_PERS_EXP,0
STATE_OCR_BLDG_CFG,NON_PERS_EXP_FED_ST_LOC,0
STATE_OCR_BLDG_CFG,TEACH_PERS_SALARY,0
STATE_OCR_BLDG_CFG,TEACHER_SALARY_FED_ST_LOC,0
STATE_OCR_BLDG_CFG,TEACHER_SALARY_FTE,0
STATE_OCR_BLDG_CFG,BUILDING_COMMENTS2,0
STATE_OCR_BLDG_CFG,OTHER_BUILDING_LIST,0
STATE_OCR_BLDG_CFG,JUSTICE_FACILITY,0
STATE_OCR_BLDG_CFG,JUSTFAC_NUM_DAYS,0
STATE_OCR_BLDG_CFG,JUSTFAC_HOURS_PERWEEK,0
STATE_OCR_BLDG_CFG,JUSTFAC_EDUPROG_LESS15,0
STATE_OCR_BLDG_CFG,JUSTFAC_EDUPROG_15TO30,0
STATE_OCR_BLDG_CFG,JUSTFAC_EDUPROG_31TO90,0
STATE_OCR_BLDG_CFG,JUSTFAC_EDUPROG_91TO180,0
STATE_OCR_BLDG_CFG,JUSTFAC_EDUPROG_MORE180,0
STATE_OCR_BLDG_CFG,PRES_AGE3,0
STATE_OCR_BLDG_CFG,PRES_AGE4,0
STATE_OCR_BLDG_CFG,PRES_AGE5,0
STATE_OCR_BLDG_CFG,PRES_ONLY_IDEA,0
STATE_OCR_BLDG_CFG,CREDIT_RECOV,0
STATE_OCR_BLDG_CFG,CREDIT_RECOV_STUDENTS,0
STATE_OCR_BLDG_CFG,LAW_ENFORCE_OFF,0
STATE_OCR_BLDG_CFG,HOMICIDE_DEATHS,0
STATE_OCR_BLDG_CFG,FIREARM_USE,0
STATE_OCR_BLDG_CFG,FTE_PSYCHOLOGISTS,0
STATE_OCR_BLDG_CFG,FTE_SOCIAL_WORKERS,0
STATE_OCR_BLDG_CFG,FTE_NURSES,0
STATE_OCR_BLDG_CFG,FTE_SECURITY_GUARDS,0
STATE_OCR_BLDG_CFG,FTE_LAW_ENFORCEMENT,0
STATE_OCR_BLDG_CFG,FTE_INSTRUCTIONAL_AIDES_ST_LOC,0
STATE_OCR_BLDG_CFG,INST_AIDE_PERS_SALARY_ST_LOC,0
STATE_OCR_BLDG_CFG,FTE_SUPPORT_STAFF_ST_LOC,0
STATE_OCR_BLDG_CFG,SUPP_STAFF_PERS_SALARY_ST_LOC,0
STATE_OCR_BLDG_CFG,FTE_SCHOOL_ADMIN_ST_LOC,0
STATE_OCR_BLDG_CFG,SCHOOL_ADMIN_PERS_SALARY_ST_LOC,0
STATE_OCR_BLDG_CFG,FTE_INSTRUCTIONAL_AIDES_FED_ST_LOC,0
STATE_OCR_BLDG_CFG,INST_AIDE_PERS_SALARY_FED_ST_LOC,0
STATE_OCR_BLDG_CFG,FTE_SUPPORT_STAFF_FED_ST_LOC,0
STATE_OCR_BLDG_CFG,SUPP_STAFF_PERS_SALARY_FED_ST_LOC,0
STATE_OCR_BLDG_CFG,FTE_SCHOOL_ADMIN_FED_ST_LOC,0
STATE_OCR_BLDG_CFG,SCHOOL_ADMIN_PERS_SALARY_FED_ST_LOC,0
STATE_OCR_BLDG_CFG,CUR_YEAR_TEACHERS,0
STATE_OCR_BLDG_CFG,PRIOR_YEAR_TEACHERS,0
STATE_OCR_BLDG_CFG,RETAINED_USE_FED_OR_LOC_GRADE_CODE,0
STATE_OCR_BLDG_CFG,INTERNET_FIBER,0
STATE_OCR_BLDG_CFG,INTERNET_WIFI,0
STATE_OCR_BLDG_CFG,INTERNET_SCHOOL_ISSUED_DEVICE,0
STATE_OCR_BLDG_CFG,INTERNET_STUDENT_OWNED_DEVICE,0
STATE_OCR_BLDG_CFG,INTERNET_WIFI_ENABLED_DEVICES,0
STATE_OCR_BLDG_CFG,CHANGE_DATE_TIME,0
STATE_OCR_BLDG_CFG,CHANGE_UID,0
STATE_OCR_BLDG_CFG,DIND_INSTRUCTION_TYPE,0
STATE_OCR_BLDG_CFG,DIND_VIRTUAL_TYPE,0
STATE_OCR_BLDG_CFG,FULLY_VIRTUAL,0
STATE_OCR_BLDG_CFG,REMOTE_INSTRUCTION_AMOUNT,0
STATE_OCR_BLDG_CFG,REMOTE_INSTRUCTION_PERCENT,0
STATE_OCR_BLDG_CFG,INTERSCH_SPORTS_ALL,0
STATE_OCR_BLDG_CFG,INTERSCH_TEAMS_ALL,0
STATE_OCR_BLDG_CFG,INTERSCH_PARTIC_NONBINARY,0
STATE_OCR_BLDG_CFG,FTE_MATH_TEACHERS,0
STATE_OCR_BLDG_CFG,FTE_SCIENCE_TEACHERS,0
STATE_OCR_BLDG_CFG,FTE_EL_TEACHERS,0
STATE_OCR_BLDG_CFG,FTE_SPECIAL_ED_TEACHERS,0
STATE_OCR_BLDG_CFG,TEACHERS_RETAINED,0
STATE_OCR_BLDG_CFG,INTERNET_WIFI_ENABLED_DEVICES_NEEDED,0
STATE_OCR_BLDG_CFG,INTERNET_WIFI_HOTSPOTS_NEEDED,0
STATE_OCR_BLDG_CFG,INTERNET_WIFI_ENABLED_DEVICES_RECEIVED,0
STATE_OCR_BLDG_CFG,INTERNET_WIFI_HOTSPOTS_RECEIVED,0
STATE_OCR_BLDG_CFG,PRES_ENG_LEARNER_INDICATOR,0
STATE_OCR_BLDG_CFG,PRES_ENG_LEARNER_IDENTIFICATION,0
STATE_OCR_BLDG_CFG,PRES_SEC504_INDICATOR,0
STATE_OCR_BLDG_CFG,PRES_SEC504_IDENTIFICATION,0
STATE_OCR_BLDG_CFG,DISC_ENG_LEARNER_INDICATOR,0
STATE_OCR_BLDG_CFG,DISC_ENG_LEARNER_IDENTIFICATION,0
STATE_OCR_BLDG_CFG,DISC_SEC504_INDICATOR,0
STATE_OCR_BLDG_CFG,DISC_SEC504_IDENTIFICATION,0
STATE_OCR_BLDG_MARK_TYPE,DISTRICT,1
STATE_OCR_BLDG_MARK_TYPE,SCHOOL_YEAR,1
STATE_OCR_BLDG_MARK_TYPE,BUILDING,1
STATE_OCR_BLDG_MARK_TYPE,MARK_TYPE,1
STATE_OCR_BLDG_MARK_TYPE,MARK_ORDER,0
STATE_OCR_BLDG_MARK_TYPE,CHANGE_DATE_TIME,0
STATE_OCR_BLDG_MARK_TYPE,CHANGE_UID,0
STATE_OCR_BLDG_RET_EXCLUDED_CALENDAR,DISTRICT,1
STATE_OCR_BLDG_RET_EXCLUDED_CALENDAR,SCHOOL_YEAR,1
STATE_OCR_BLDG_RET_EXCLUDED_CALENDAR,BUILDING,1
STATE_OCR_BLDG_RET_EXCLUDED_CALENDAR,CALENDAR,1
STATE_OCR_BLDG_RET_EXCLUDED_CALENDAR,CHANGE_DATE_TIME,0
STATE_OCR_BLDG_RET_EXCLUDED_CALENDAR,CHANGE_UID,0
STATE_OCR_DETAIL,DISTRICT,1
STATE_OCR_DETAIL,SCHOOL_YEAR,1
STATE_OCR_DETAIL,OCR_PART,1
STATE_OCR_DETAIL,STUDENT_ID,1
STATE_OCR_DETAIL,RECORD_TYPE,1
STATE_OCR_DETAIL,BUILDING,1
STATE_OCR_DETAIL,FED_GRADE,0
STATE_OCR_DETAIL,FED_RACE,0
STATE_OCR_DETAIL,GENDER,0
STATE_OCR_DETAIL,DETAIL_RECORD_COUNT,0
STATE_OCR_DETAIL,CHANGE_DATE_TIME,0
STATE_OCR_DETAIL,CHANGE_UID,0
STATE_OCR_DIST_ATT,DISTRICT,1
STATE_OCR_DIST_ATT,SCHOOL_YEAR,1
STATE_OCR_DIST_ATT,ATT_CODE,1
STATE_OCR_DIST_ATT,CHANGE_DATE_TIME,0
STATE_OCR_DIST_ATT,CHANGE_UID,0
STATE_OCR_DIST_CFG,DISTRICT,1
STATE_OCR_DIST_CFG,SCHOOL_YEAR,1
STATE_OCR_DIST_CFG,FEDERAL_CODE_EQUIV,0
STATE_OCR_DIST_CFG,ENROLL_DATE,0
STATE_OCR_DIST_CFG,IDEA_DATE,0
STATE_OCR_DIST_CFG,SEMESTER2_DATE,0
STATE_OCR_DIST_CFG,YEAR_START_DATE,0
STATE_OCR_DIST_CFG,YEAR_END_DATE,0
STATE_OCR_DIST_CFG,RACE_CATEGORY,0
STATE_OCR_DIST_CFG,GED_PREP,0
STATE_OCR_DIST_CFG,TOT_PUB_SCHOOLS,0
STATE_OCR_DIST_CFG,TOT_PUB_MEMBERSHIP,0
STATE_OCR_DIST_CFG,TOT_PUB_SERVED,0
STATE_OCR_DIST_CFG,TOT_PUB_WAITING,0
STATE_OCR_DIST_CFG,DESEGRAGATION_PLAN,0
STATE_OCR_DIST_CFG,KG_FULL,0
STATE_OCR_DIST_CFG,KG_FULL_FREE,0
STATE_OCR_DIST_CFG,KG_FULL_PARTORFULL,0
STATE_OCR_DIST_CFG,KG_PART,0
STATE_OCR_DIST_CFG,KG_PART_FREE,0
STATE_OCR_DIST_CFG,KG_PART_PARTORFULL,0
STATE_OCR_DIST_CFG,KG_NONE,0
STATE_OCR_DIST_CFG,KG_REQ_BY_STATUTE,0
STATE_OCR_DIST_CFG,PREK_FULL,0
STATE_OCR_DIST_CFG,PREK_FULL_FREE,0
STATE_OCR_DIST_CFG,PREK_FULL_PARTORFULL,0
STATE_OCR_DIST_CFG,PREK_PART,0
STATE_OCR_DIST_CFG,PREK_PART_FREE,0
STATE_OCR_DIST_CFG,PREK_PART_PARTORFULL,0
STATE_OCR_DIST_CFG,PREK_NONE,0
STATE_OCR_DIST_CFG,PREK_FOR_ALL,0
STATE_OCR_DIST_CFG,PREK_FOR_IDEA,0
STATE_OCR_DIST_CFG,PREK_FOR_TITLE1,0
STATE_OCR_DIST_CFG,PREK_FOR_LOWINCOME,0
STATE_OCR_DIST_CFG,PREK_FOR_OTHER,0
STATE_OCR_DIST_CFG,PREK_AGE_2,0
STATE_OCR_DIST_CFG,PREK_AGE_3,0
STATE_OCR_DIST_CFG,PREK_AGE_4,0
STATE_OCR_DIST_CFG,PREK_AGE_5,0
STATE_OCR_DIST_CFG,PREK_AGE_NONE,0
STATE_OCR_DIST_CFG,PREK_AGE_2_STU_COUNT,0
STATE_OCR_DIST_CFG,PREK_AGE_3_STU_COUNT,0
STATE_OCR_DIST_CFG,PREK_AGE_4_STU_COUNT,0
STATE_OCR_DIST_CFG,PREK_AGE_5_STU_COUNT,0
STATE_OCR_DIST_CFG,EARLY_CHILD_0_2,0
STATE_OCR_DIST_CFG,EARLY_CHILD_0_2_NON_IDEA,0
STATE_OCR_DIST_CFG,CIV_RIGHTS_COORD_GNDR_ID,0
STATE_OCR_DIST_CFG,CIV_RIGHTS_COORD_GNDR_PHONE,0
STATE_OCR_DIST_CFG,CIV_RIGHTS_COORD_GNDR_EXT,0
STATE_OCR_DIST_CFG,CIV_RIGHTS_COORD_RACE_ID,0
STATE_OCR_DIST_CFG,CIV_RIGHTS_COORD_RACE_PHONE,0
STATE_OCR_DIST_CFG,CIV_RIGHTS_COORD_RACE_EXT,0
STATE_OCR_DIST_CFG,CIV_RIGHTS_COORD_DIS_ID,0
STATE_OCR_DIST_CFG,CIV_RIGHTS_COORD_DIS_PHONE,0
STATE_OCR_DIST_CFG,CIV_RIGHTS_COORD_DIS_EXT,0
STATE_OCR_DIST_CFG,HAR_POL_NONE,0
STATE_OCR_DIST_CFG,HAR_POL_SEX,0
STATE_OCR_DIST_CFG,HAR_POL_DIS,0
STATE_OCR_DIST_CFG,HAR_POL_RACE,0
STATE_OCR_DIST_CFG,HAR_POL_ANY,0
STATE_OCR_DIST_CFG,HAR_POL_WEBLINK,0
STATE_OCR_DIST_CFG,CERTIFIED,0
STATE_OCR_DIST_CFG,CERT_NAME,0
STATE_OCR_DIST_CFG,CERT_TITLE,0
STATE_OCR_DIST_CFG,CERT_PHONE,0
STATE_OCR_DIST_CFG,CERT_DATE,0
STATE_OCR_DIST_CFG,CERT_AUTH,0
STATE_OCR_DIST_CFG,CERT_EMAIL,0
STATE_OCR_DIST_CFG,ATT_VIEW_TYPE,0
STATE_OCR_DIST_CFG,ENROLL_DIST_EDU_CRS,0
STATE_OCR_DIST_CFG,RETENTION_POLICY,0
STATE_OCR_DIST_CFG,NUM_STU_NON_LEA,0
STATE_OCR_DIST_CFG,STU_DISC_TRANSFER,0
STATE_OCR_DIST_CFG,CHANGE_DATE_TIME,0
STATE_OCR_DIST_CFG,CHANGE_UID,0
STATE_OCR_DIST_CFG,REPORT_NONBINARY_COUNTS,0
STATE_OCR_DIST_CFG,DETERMINE_STUDENT_GENDER,0
STATE_OCR_DIST_CFG,EARLY_CHILD,0
STATE_OCR_DIST_CFG,EARLY_CHILD_NON_IDEA,0
STATE_OCR_DIST_CFG,HAR_POL_SEX_WEBLINK,0
STATE_OCR_DIST_CFG,HAR_POL_GENDER,0
STATE_OCR_DIST_CFG,HAR_POL_GENDER_WEBLINK,0
STATE_OCR_DIST_CFG,HAR_POL_RELIGION,0
STATE_OCR_DIST_CFG,HAR_POL_RELIGION_WEBLINK,0
STATE_OCR_DIST_COM,DISTRICT,1
STATE_OCR_DIST_COM,SCHOOL_YEAR,1
STATE_OCR_DIST_COM,COMMENT_TYPE,1
STATE_OCR_DIST_COM,COMMENT,0
STATE_OCR_DIST_COM,CHANGE_DATE_TIME,0
STATE_OCR_DIST_COM,CHANGE_UID,0
STATE_OCR_DIST_DISC,DISTRICT,1
STATE_OCR_DIST_DISC,SCHOOL_YEAR,1
STATE_OCR_DIST_DISC,DISC_CODE_ID,1
STATE_OCR_DIST_DISC,CODE_OR_SUBCODE,1
STATE_OCR_DIST_DISC,DISC_CODE,1
STATE_OCR_DIST_DISC,CHANGE_DATE_TIME,0
STATE_OCR_DIST_DISC,CHANGE_UID,0
STATE_OCR_DIST_EXP,DISTRICT,1
STATE_OCR_DIST_EXP,SCHOOL_YEAR,1
STATE_OCR_DIST_EXP,EXPENDITURE_ID,1
STATE_OCR_DIST_EXP,EXPENDITURE_INCL,0
STATE_OCR_DIST_EXP,CHANGE_DATE_TIME,0
STATE_OCR_DIST_EXP,CHANGE_UID,0
STATE_OCR_DIST_LTDB_TEST,DISTRICT,1
STATE_OCR_DIST_LTDB_TEST,SCHOOL_YEAR,1
STATE_OCR_DIST_LTDB_TEST,TEST_TYPE,1
STATE_OCR_DIST_LTDB_TEST,AP_SUBJECT_CODE,1
STATE_OCR_DIST_LTDB_TEST,TEST_CODE,1
STATE_OCR_DIST_LTDB_TEST,TEST_LEVEL,1
STATE_OCR_DIST_LTDB_TEST,TEST_FORM,1
STATE_OCR_DIST_LTDB_TEST,SUBTEST,1
STATE_OCR_DIST_LTDB_TEST,SCORE_CODE,1
STATE_OCR_DIST_LTDB_TEST,CHANGE_DATE_TIME,0
STATE_OCR_DIST_LTDB_TEST,CHANGE_UID,0
STATE_OCR_DIST_STU_DISC_XFER,DISTRICT,1
STATE_OCR_DIST_STU_DISC_XFER,SCHOOL_YEAR,1
STATE_OCR_DIST_STU_DISC_XFER,REG_OR_ALT,1
STATE_OCR_DIST_STU_DISC_XFER,CODE_VALUE,1
STATE_OCR_DIST_STU_DISC_XFER,CHANGE_DATE_TIME,0
STATE_OCR_DIST_STU_DISC_XFER,CHANGE_UID,0
STATE_OCR_NON_STU_DET,DISTRICT,1
STATE_OCR_NON_STU_DET,SCHOOL_YEAR,1
STATE_OCR_NON_STU_DET,BUILDING,1
STATE_OCR_NON_STU_DET,COUNT_TYPE,1
STATE_OCR_NON_STU_DET,OCR_PART,0
STATE_OCR_NON_STU_DET,COUNT_VALUE,0
STATE_OCR_NON_STU_DET,OVERRIDE,0
STATE_OCR_NON_STU_DET,CHANGE_DATE_TIME,0
STATE_OCR_NON_STU_DET,CHANGE_UID,0
STATE_OCR_QUESTION,DISTRICT,1
STATE_OCR_QUESTION,SCHOOL_YEAR,1
STATE_OCR_QUESTION,OCR_PART,1
STATE_OCR_QUESTION,FORM_TYPE,1
STATE_OCR_QUESTION,QUESTION_ID,1
STATE_OCR_QUESTION,RECORD_TYPE,1
STATE_OCR_QUESTION,QUESTION_ORDER,0
STATE_OCR_QUESTION,DESCRIPTION,0
STATE_OCR_QUESTION,CHANGE_DATE_TIME,0
STATE_OCR_QUESTION,CHANGE_UID,0
STATE_OCR_SUMMARY,DISTRICT,1
STATE_OCR_SUMMARY,SCHOOL_YEAR,1
STATE_OCR_SUMMARY,OCR_PART,1
STATE_OCR_SUMMARY,RECORD_TYPE,1
STATE_OCR_SUMMARY,BUILDING,1
STATE_OCR_SUMMARY,FED_RACE,1
STATE_OCR_SUMMARY,GENDER,1
STATE_OCR_SUMMARY,QUESTION_ID,1
STATE_OCR_SUMMARY,COUNT,0
STATE_OCR_SUMMARY,OVERRIDE,0
STATE_OCR_SUMMARY,CHANGE_DATE_TIME,0
STATE_OCR_SUMMARY,CHANGE_UID,0
STATE_TASK_LOG_CFG,DISTRICT,1
STATE_TASK_LOG_CFG,TASK_CODE,1
STATE_TASK_LOG_CFG,TASK_NAME,0
STATE_TASK_LOG_CFG,KEYFIELD01,0
STATE_TASK_LOG_CFG,KEYFIELD02,0
STATE_TASK_LOG_CFG,KEYFIELD03,0
STATE_TASK_LOG_CFG,KEYFIELD04,0
STATE_TASK_LOG_CFG,KEYFIELD05,0
STATE_TASK_LOG_CFG,KEYFIELD06,0
STATE_TASK_LOG_CFG,KEYFIELD07,0
STATE_TASK_LOG_CFG,KEYFIELD08,0
STATE_TASK_LOG_CFG,KEYFIELD09,0
STATE_TASK_LOG_CFG,KEYFIELD10,0
STATE_TASK_LOG_CFG,CHANGE_DATE_TIME,0
STATE_TASK_LOG_CFG,CHANGE_UID,0
STATE_TASK_LOG_DET,DISTRICT,1
STATE_TASK_LOG_DET,PARAM_KEY,1
STATE_TASK_LOG_DET,RUN_NUMBER,1
STATE_TASK_LOG_DET,KEY_VALUE01,1
STATE_TASK_LOG_DET,KEY_VALUE02,1
STATE_TASK_LOG_DET,KEY_VALUE03,1
STATE_TASK_LOG_DET,KEY_VALUE04,1
STATE_TASK_LOG_DET,KEY_VALUE05,1
STATE_TASK_LOG_DET,KEY_VALUE06,1
STATE_TASK_LOG_DET,KEY_VALUE07,1
STATE_TASK_LOG_DET,KEY_VALUE08,1
STATE_TASK_LOG_DET,KEY_VALUE09,1
STATE_TASK_LOG_DET,KEY_VALUE10,1
STATE_TASK_LOG_DET,MESSAGE_INDEX,1
STATE_TASK_LOG_DET,MESSAGE_TYPE,0
STATE_TASK_LOG_DET,MESSAGE,0
STATE_TASK_LOG_DET,CHANGE_DATE_TIME,0
STATE_TASK_LOG_DET,CHANGE_UID,0
STATE_TASK_LOG_HDR,DISTRICT,1
STATE_TASK_LOG_HDR,PARAM_KEY,1
STATE_TASK_LOG_HDR,RUN_NUMBER,1
STATE_TASK_LOG_HDR,TASK_CODE,0
STATE_TASK_LOG_HDR,CUSTOM_TASK_NAME,0
STATE_TASK_LOG_HDR,USER_ID,0
STATE_TASK_LOG_HDR,START_TIME,0
STATE_TASK_LOG_HDR,CHANGE_DATE_TIME,0
STATE_TASK_LOG_HDR,CHANGE_UID,0
STATE_VLD_GROUP,DISTRICT,1
STATE_VLD_GROUP,GROUP_ID,1
STATE_VLD_GROUP,GROUP_DESC,0
STATE_VLD_GROUP,CHANGE_DATE_TIME,0
STATE_VLD_GROUP,CHANGE_UID,0
STATE_VLD_GRP_MENU,DISTRICT,1
STATE_VLD_GRP_MENU,GROUP_ID,1
STATE_VLD_GRP_MENU,MENU_ID,1
STATE_VLD_GRP_MENU,CHANGE_DATE_TIME,0
STATE_VLD_GRP_MENU,CHANGE_UID,0
STATE_VLD_GRP_RULE,DISTRICT,1
STATE_VLD_GRP_RULE,GROUP_ID,1
STATE_VLD_GRP_RULE,RULE_ID,1
STATE_VLD_GRP_RULE,ERROR_MSG,0
STATE_VLD_GRP_RULE,ERROR_TYPE,0
STATE_VLD_GRP_RULE,CHANGE_DATE_TIME,0
STATE_VLD_GRP_RULE,CHANGE_UID,0
STATE_VLD_GRP_USER,DISTRICT,1
STATE_VLD_GRP_USER,GROUP_ID,1
STATE_VLD_GRP_USER,USER_ID,1
STATE_VLD_GRP_USER,CHANGE_DATE_TIME,0
STATE_VLD_GRP_USER,CHANGE_UID,0
STATE_VLD_RESULTS,DISTRICT,1
STATE_VLD_RESULTS,RULE_ID,1
STATE_VLD_RESULTS,STUDENT_ID,1
STATE_VLD_RESULTS,EXCLUDE,0
STATE_VLD_RESULTS,ERROR_MESSAGE,0
STATE_VLD_RESULTS,CHANGE_DATE_TIME,0
STATE_VLD_RESULTS,CHANGE_UID,0
STATE_VLD_RULE,DISTRICT,1
STATE_VLD_RULE,RULE_ID,1
STATE_VLD_RULE,RULE_DESCRIPTION,0
STATE_VLD_RULE,ERROR_MESSAGE,0
STATE_VLD_RULE,ERROR_TYPE,0
STATE_VLD_RULE,SQL_SCRIPT,0
STATE_VLD_RULE,STORED_PROC,0
STATE_VLD_RULE,RETURNS_STUDENT_ID,0
STATE_VLD_RULE,SQL_SCRIPT_ACTION,0
STATE_VLD_RULE,STORED_PROC_ACTION,0
STATE_VLD_RULE,ACTION_DESCRIPTION,0
STATE_VLD_RULE,EXPCTD_REC_CNT,0
STATE_VLD_RULE,NAVIGATE_TO,0
STATE_VLD_RULE,ERROR_PARAMS,0
STATE_VLD_RULE,RUN_ORDER,0
STATE_VLD_RULE,ACTIVE,0
STATE_VLD_RULE,CHANGE_DATE_TIME,0
STATE_VLD_RULE,CHANGE_UID,0
STATETB_AP_SUBJECT,DISTRICT,1
STATETB_AP_SUBJECT,CODE,1
STATETB_AP_SUBJECT,DESCRIPTION,0
STATETB_AP_SUBJECT,ACTIVE,0
STATETB_AP_SUBJECT,CHANGE_DATE_TIME,0
STATETB_AP_SUBJECT,CHANGE_UID,0
STATETB_DEF_CLASS,DISTRICT,1
STATETB_DEF_CLASS,CODE,1
STATETB_DEF_CLASS,DESCRIPTION,0
STATETB_DEF_CLASS,STATE_CODE_EQUIV,0
STATETB_DEF_CLASS,ACTIVE,0
STATETB_DEF_CLASS,CHANGE_DATE_TIME,0
STATETB_DEF_CLASS,CHANGE_UID,0
STATETB_ENTRY_SOURCE,DISTRICT,1
STATETB_ENTRY_SOURCE,TABLE_NAME,1
STATETB_ENTRY_SOURCE,COLUMN_NAME,1
STATETB_ENTRY_SOURCE,DESCRIPTION,0
STATETB_ENTRY_SOURCE,SOURCE_PAGE,0
STATETB_ENTRY_SOURCE,SOURCE_DESCRIPTION,0
STATETB_ENTRY_SOURCE,FORMATTER,0
STATETB_ENTRY_SOURCE,CHANGE_DATE_TIME,0
STATETB_ENTRY_SOURCE,CHANGE_UID,0
STATETB_OCR_COM_TYPE,DISTRICT,1
STATETB_OCR_COM_TYPE,COMMENT_TYPE,1
STATETB_OCR_COM_TYPE,DESCRIPTION,0
STATETB_OCR_COM_TYPE,CHANGE_DATE_TIME,0
STATETB_OCR_COM_TYPE,CHANGE_UID,0
STATETB_OCR_COUNT_TYPE,DISTRICT,0
STATETB_OCR_COUNT_TYPE,SECTION,1
STATETB_OCR_COUNT_TYPE,ORDER_NUMBER,1
STATETB_OCR_COUNT_TYPE,SEQUENCE,1
STATETB_OCR_COUNT_TYPE,COUNT_TYPE,1
STATETB_OCR_COUNT_TYPE,CHANGE_DATE_TIME,0
STATETB_OCR_COUNT_TYPE,CHANGE_UID,0
STATETB_OCR_DISC_TYPE,DISTRICT,1
STATETB_OCR_DISC_TYPE,DISC_CODE_ID,1
STATETB_OCR_DISC_TYPE,DESCRIPTION,0
STATETB_OCR_DISC_TYPE,INCIDENT_OR_ACTION,0
STATETB_OCR_DISC_TYPE,DISC_CODE_ORDER,0
STATETB_OCR_DISC_TYPE,CHANGE_DATE_TIME,0
STATETB_OCR_DISC_TYPE,CHANGE_UID,0
STATETB_OCR_EXP_TYPE,DISTRICT,1
STATETB_OCR_EXP_TYPE,EXPENDITURE_ID,1
STATETB_OCR_EXP_TYPE,EXPENDITURE_ORDER,0
STATETB_OCR_EXP_TYPE,DESCRIPTION,0
STATETB_OCR_EXP_TYPE,EXPENDITURE_TYPE,0
STATETB_OCR_EXP_TYPE,ED_PREFERRED,0
STATETB_OCR_EXP_TYPE,CHANGE_DATE_TIME,0
STATETB_OCR_EXP_TYPE,CHANGE_UID,0
Statetb_Ocr_Record_types,district,1
Statetb_Ocr_Record_types,record_type,1
Statetb_Ocr_Record_types,school_year,1
Statetb_Ocr_Record_types,ocr_part,1
Statetb_Ocr_Record_types,description,0
Statetb_Ocr_Record_types,change_date_time,0
Statetb_Ocr_Record_types,change_uid,0
STATETB_RECORD_FIELDS,DISTRICT,1
STATETB_RECORD_FIELDS,RECORD_TYPE,1
STATETB_RECORD_FIELDS,FIELD_NAME,1
STATETB_RECORD_FIELDS,FIELD_ORDER,0
STATETB_RECORD_FIELDS,CHANGE_DATE_TIME,0
STATETB_RECORD_FIELDS,CHANGE_UID,0
STATETB_RECORD_TYPES,DISTRICT,1
STATETB_RECORD_TYPES,STATE,1
STATETB_RECORD_TYPES,RECORD_TYPE,1
STATETB_RECORD_TYPES,DESCRIPTION,0
STATETB_RECORD_TYPES,TABLE_NAME,1
STATETB_RECORD_TYPES,ACTIVE,0
STATETB_RECORD_TYPES,STUDENTSEARCH,0
STATETB_RECORD_TYPES,SORTORDER,0
STATETB_RECORD_TYPES,SUBMISSIONS,0
STATETB_RECORD_TYPES,DOWNLOAD_TYPES,0
STATETB_RECORD_TYPES,DISTRICTSEARCH,0
STATETB_RECORD_TYPES,COURSESEARCH,0
STATETB_RECORD_TYPES,STAFFSEARCH,0
STATETB_RECORD_TYPES,CHANGE_DATE_TIME,0
STATETB_RECORD_TYPES,CHANGE_UID,0
STATETB_RELIGION,DISTRICT,1
STATETB_RELIGION,CODE,1
STATETB_RELIGION,DESCRIPTION,0
STATETB_RELIGION,ACTIVE,0
STATETB_RELIGION,STATE_CODE_EQUIV,0
STATETB_RELIGION,CHANGE_DATE_TIME,0
STATETB_RELIGION,CHANGE_UID,0
STATETB_STAFF_ROLE,DISTRICT,1
STATETB_STAFF_ROLE,CODE,1
STATETB_STAFF_ROLE,DESCRIPTION,0
STATETB_STAFF_ROLE,STATE_CODE_EQUIV,0
STATETB_STAFF_ROLE,ACTIVE,0
STATETB_STAFF_ROLE,CHANGE_DATE_TIME,0
STATETB_STAFF_ROLE,CHANGE_UID,0
STATETB_SUBMISSION_COL,DISTRICT,1
STATETB_SUBMISSION_COL,STATE,1
STATETB_SUBMISSION_COL,COLUMN_NAME,1
STATETB_SUBMISSION_COL,CHANGE_DATE_TIME,0
STATETB_SUBMISSION_COL,CHANGE_UID,0
STATETB_SUBMISSIONS,DISTRICT,1
STATETB_SUBMISSIONS,STATE,1
STATETB_SUBMISSIONS,CODE,1
STATETB_SUBMISSIONS,DESCRIPTION,0
STATETB_SUBMISSIONS,START_DATE,0
STATETB_SUBMISSIONS,END_DATE,0
STATETB_SUBMISSIONS,ACTIVE,0
STATETB_SUBMISSIONS,CHANGE_DATE_TIME,0
STATETB_SUBMISSIONS,CHANGE_UID,0
TAC_CFG,DISTRICT,1
TAC_CFG,BUILDING,1
TAC_CFG,TEA_OVR_GB_AVG,0
TAC_CFG,SUB_OVR_GB_AVG,0
TAC_CFG,SHOW_ALL_TAB,0
TAC_CFG,DEFAULT_TAB_TYPE,0
TAC_CFG,DEFAULT_TAB,0
TAC_CFG,TEA_ISSUES,0
TAC_CFG,SUB_ISSUES,0
TAC_CFG,TEA_CONDUCT_REFER,0
TAC_CFG,SUB_CONDUCT_REFER,0
TAC_CFG,SET_ROLES_ON_REFER,0
TAC_CFG,SET_TYPE_ON_REFER,0
TAC_CFG,DEFAULT_ISSUE_TYPE,0
TAC_CFG,TEA_DISABLE_STD,0
TAC_CFG,TEA_DISABLE_RUBRIC,0
TAC_CFG,TEA_PUBLIC_RUBRIC,0
TAC_CFG,TEA_PERFORMANCEPLUS,0
TAC_CFG,SUB_PERFORMANCEPLUS,0
TAC_CFG,FREE_TEXT_OPTION,0
TAC_CFG,TEA_STU_ACCESS,0
TAC_CFG,SUB_STU_ACCESS,0
TAC_CFG,TEA_MEDALERTS,0
TAC_CFG,SUB_MEDALERTS,0
TAC_CFG,DISC_REFER,0
TAC_CFG,SSP_REFER,0
TAC_CFG,TEA_EFP_BP,0
TAC_CFG,SUB_EFP_BP,0
TAC_CFG,AUTO_PUBLISH_SCORES,0
TAC_CFG,TEACHER_EXTRA_CREDIT_CREATION,0
TAC_CFG,POINTS,0
TAC_CFG,POINTS_OVERRIDE,0
TAC_CFG,WEIGHT,0
TAC_CFG,WEIGHT_OVERRIDE,0
TAC_CFG,PUBLISH,0
TAC_CFG,PUBLISH_OVERRIDE,0
TAC_CFG,CHANGE_DATE_TIME,0
TAC_CFG,CHANGE_UID,0
TAC_CFG,TEA_UPD_PM_ASMT_SCORE,0
TAC_CFG,ALLOW_TURNED_IN,0
TAC_CFG_ABS_SCRN,DISTRICT,1
TAC_CFG_ABS_SCRN,BUILDING,1
TAC_CFG_ABS_SCRN,TEA_SCREEN_ACCESS,0
TAC_CFG_ABS_SCRN,TEA_PREV_MP_ACCESS,0
TAC_CFG_ABS_SCRN,SUB_SCREEN_ACCESS,0
TAC_CFG_ABS_SCRN,SUB_PREV_MP_ACCESS,0
TAC_CFG_ABS_SCRN,CHANGE_DATE_TIME,0
TAC_CFG_ABS_SCRN,CHANGE_UID,0
TAC_CFG_ABS_SCRN_CODES,DISTRICT,1
TAC_CFG_ABS_SCRN_CODES,BUILDING,1
TAC_CFG_ABS_SCRN_CODES,SEQUENCE,1
TAC_CFG_ABS_SCRN_CODES,ABS_CODE,1
TAC_CFG_ABS_SCRN_CODES,CHANGE_DATE_TIME,0
TAC_CFG_ABS_SCRN_CODES,CHANGE_UID,0
TAC_CFG_ABS_SCRN_DET,DISTRICT,1
TAC_CFG_ABS_SCRN_DET,BUILDING,1
TAC_CFG_ABS_SCRN_DET,SEQUENCE,1
TAC_CFG_ABS_SCRN_DET,UPPER_LABEL,0
TAC_CFG_ABS_SCRN_DET,LOWER_LABEL,0
TAC_CFG_ABS_SCRN_DET,TOTAL_TYPE,0
TAC_CFG_ABS_SCRN_DET,ACTIVE,0
TAC_CFG_ABS_SCRN_DET,CHANGE_DATE_TIME,0
TAC_CFG_ABS_SCRN_DET,CHANGE_UID,0
TAC_CFG_ATTACH,DISTRICT,1
TAC_CFG_ATTACH,BUILDING,1
TAC_CFG_ATTACH,TEA_STU_ATTACH,0
TAC_CFG_ATTACH,TEA_STU_ATTACH_CAT_ALL,0
TAC_CFG_ATTACH,SUB_STU_ATTACH,0
TAC_CFG_ATTACH,SUB_STU_ATTACH_CAT_ALL,0
TAC_CFG_ATTACH,TEA_OTHER_ATTACH,0
TAC_CFG_ATTACH,TEA_OTHER_ATTACH_CAT_ALL,0
TAC_CFG_ATTACH,SUB_OTHER_ATTACH,0
TAC_CFG_ATTACH,SUB_OTHER_ATTACH_CAT_ALL,0
TAC_CFG_ATTACH,CHANGE_DATE_TIME,0
TAC_CFG_ATTACH,CHANGE_UID,0
TAC_CFG_ATTACH_CATEGORIES,DISTRICT,1
TAC_CFG_ATTACH_CATEGORIES,BUILDING,1
TAC_CFG_ATTACH_CATEGORIES,CATEGORY_TYPE,1
TAC_CFG_ATTACH_CATEGORIES,CATEGORY_CODE,1
TAC_CFG_ATTACH_CATEGORIES,CHANGE_DATE_TIME,0
TAC_CFG_ATTACH_CATEGORIES,CHANGE_UID,0
TAC_CFG_HAC,DISTRICT,1
TAC_CFG_HAC,BUILDING,1
TAC_CFG_HAC,USE_TEA_NEWS,0
TAC_CFG_HAC,CHANGE_DATE_TIME,0
TAC_CFG_HAC,CHANGE_UID,0
TAC_DISTRICT_CFG,DISTRICT,1
TAC_DISTRICT_CFG,ALLOW_EMAIL_ATTACH,0
TAC_DISTRICT_CFG,MAX_ATTACH_SIZE,0
TAC_DISTRICT_CFG,ATT_FILE_TYPES,0
TAC_DISTRICT_CFG,FROM_ADDR_TYPE,0
TAC_DISTRICT_CFG,FROM_ADDRESS,0
TAC_DISTRICT_CFG,FROM_NAME,0
TAC_DISTRICT_CFG,ALLOW_REPLY,0
TAC_DISTRICT_CFG,USE_DEFAULT_MSG,0
TAC_DISTRICT_CFG,DO_NOT_REPLY_MSG,0
TAC_DISTRICT_CFG,CRN_FROM_TAC,0
TAC_DISTRICT_CFG,PRIVACY_STATEMENT,0
TAC_DISTRICT_CFG,SHOW_USERVOICE,0
TAC_DISTRICT_CFG,ALLOW_TEACHER_STUDENT_ACCESS,0
TAC_DISTRICT_CFG,ALLOW_SUBSTITUTE_STUDENT_ACCESS,0
TAC_DISTRICT_CFG,CHANGE_DATE_TIME,0
TAC_DISTRICT_CFG,CHANGE_UID,0
TAC_ISSUE,DISTRICT,1
TAC_ISSUE,SCHOOL_YEAR,0
TAC_ISSUE,SUMMER_SCHOOL,0
TAC_ISSUE,BUILDING,0
TAC_ISSUE,STAFF_ID,0
TAC_ISSUE,ISSUE_ID,1
TAC_ISSUE,ISSUE_CODE,0
TAC_ISSUE,ISSUE_DATE,0
TAC_ISSUE,ISSUE_TIME,0
TAC_ISSUE,LOCATION,0
TAC_ISSUE,ISSUE_STATUS,0
TAC_ISSUE,ISSUE_SOURCE,0
TAC_ISSUE,ISSUE_SOURCE_DETAIL,0
TAC_ISSUE,COURSE_SESSION,0
TAC_ISSUE,ISSUE_RESOLVED,0
TAC_ISSUE,COMMENTS,0
TAC_ISSUE,CHANGE_DATE_TIME,0
TAC_ISSUE,CHANGE_UID,0
TAC_ISSUE_ACTION,DISTRICT,1
TAC_ISSUE_ACTION,ISSUE_ID,1
TAC_ISSUE_ACTION,ENTERED_DATE,1
TAC_ISSUE_ACTION,ENTERED_SEQUENCE,1
TAC_ISSUE_ACTION,ACTION_CODE,0
TAC_ISSUE_ACTION,START_DATE,0
TAC_ISSUE_ACTION,END_DATE,0
TAC_ISSUE_ACTION,START_TIME,0
TAC_ISSUE_ACTION,END_TIME,0
TAC_ISSUE_ACTION,ACTION_COMPLETED,0
TAC_ISSUE_ACTION,PARENTS_CONTACTED,0
TAC_ISSUE_ACTION,COMMENTS,0
TAC_ISSUE_ACTION,CHANGE_DATE_TIME,0
TAC_ISSUE_ACTION,CHANGE_UID,0
TAC_ISSUE_KEY,DISTRICT,1
TAC_ISSUE_KEY,ISSUE_ID,0
TAC_ISSUE_KEY,CHANGE_DATE_TIME,0
TAC_ISSUE_KEY,CHANGE_UID,0
TAC_ISSUE_REFER,DISTRICT,1
TAC_ISSUE_REFER,ISSUE_ID,1
TAC_ISSUE_REFER,REFER_DATE,1
TAC_ISSUE_REFER,REFER_SEQUENCE,1
TAC_ISSUE_REFER,REFER_STATUS,0
TAC_ISSUE_REFER,REFER_STAFF_ID,0
TAC_ISSUE_REFER,DISC_INCIDENT_ID,0
TAC_ISSUE_REFER,COMMENTS,0
TAC_ISSUE_REFER,CHANGE_DATE_TIME,0
TAC_ISSUE_REFER,CHANGE_UID,0
TAC_ISSUE_REFER_SSP,DISTRICT,1
TAC_ISSUE_REFER_SSP,ISSUE_ID,1
TAC_ISSUE_REFER_SSP,REFER_DATE,1
TAC_ISSUE_REFER_SSP,REFER_SEQUENCE,1
TAC_ISSUE_REFER_SSP,REFER_STATUS,0
TAC_ISSUE_REFER_SSP,REFER_TO,0
TAC_ISSUE_REFER_SSP,REFER_COORDINATOR,0
TAC_ISSUE_REFER_SSP,SSP_PLAN_NUM,0
TAC_ISSUE_REFER_SSP,SSP_QUAL_REASON,0
TAC_ISSUE_REFER_SSP,SSP_QUAL_REASON_START,0
TAC_ISSUE_REFER_SSP,COMMENTS,0
TAC_ISSUE_REFER_SSP,CHANGE_DATE_TIME,0
TAC_ISSUE_REFER_SSP,CHANGE_UID,0
TAC_ISSUE_RELATED,DISTRICT,1
TAC_ISSUE_RELATED,ISSUE_ID,1
TAC_ISSUE_RELATED,RELATED_ISSUE_ID,1
TAC_ISSUE_RELATED,CHANGE_DATE_TIME,0
TAC_ISSUE_RELATED,CHANGE_UID,0
TAC_ISSUE_STUDENT,DISTRICT,1
TAC_ISSUE_STUDENT,ISSUE_ID,1
TAC_ISSUE_STUDENT,STUDENT_ID,1
TAC_ISSUE_STUDENT,STUDENT_ROLE,0
TAC_ISSUE_STUDENT,ADMIN_ROLE,0
TAC_ISSUE_STUDENT,COMMENTS,0
TAC_ISSUE_STUDENT,CHANGE_DATE_TIME,0
TAC_ISSUE_STUDENT,CHANGE_UID,0
TAC_LINK,DISTRICT,1
TAC_LINK,BUILDING,1
TAC_LINK,TAC_PAGE,1
TAC_LINK,SORT_ORDER,1
TAC_LINK,LINK_URL,0
TAC_LINK,LINK_DESCRIPTION,0
TAC_LINK,LINK_COLOR,0
TAC_LINK,NEW_UNTIL,0
TAC_LINK,POP_UP,0
TAC_LINK,CHANGE_DATE_TIME,0
TAC_LINK,CHANGE_UID,0
TAC_LINK_MACRO,DISTRICT,1
TAC_LINK_MACRO,BUILDING,1
TAC_LINK_MACRO,MACRO_NAME,1
TAC_LINK_MACRO,MACRO_VALUE,0
TAC_LINK_MACRO,CHANGE_DATE_TIME,0
TAC_LINK_MACRO,CHANGE_UID,0
TAC_LUNCH_COUNTS,DISTRICT,1
TAC_LUNCH_COUNTS,BUILDING,1
TAC_LUNCH_COUNTS,LUNCH_TYPE,1
TAC_LUNCH_COUNTS,STAFF_ID,1
TAC_LUNCH_COUNTS,TEACHER,0
TAC_LUNCH_COUNTS,LUNCH_DATE,1
TAC_LUNCH_COUNTS,LUNCH_COUNT,0
TAC_LUNCH_COUNTS,CHANGE_DATE_TIME,0
TAC_LUNCH_COUNTS,CHANGE_UID,0
TAC_LUNCH_TYPES,DISTRICT,1
TAC_LUNCH_TYPES,BUILDING,1
TAC_LUNCH_TYPES,LUNCH_TYPE,1
TAC_LUNCH_TYPES,DESCRIPTION,0
TAC_LUNCH_TYPES,ACTIVE,0
TAC_LUNCH_TYPES,CHANGE_DATE_TIME,0
TAC_LUNCH_TYPES,CHANGE_UID,0
TAC_MENU_ITEMS,DISTRICT,1
TAC_MENU_ITEMS,PARENT_MENU_ID,1
TAC_MENU_ITEMS,SEQUENCE,1
TAC_MENU_ITEMS,MENU_ID,0
TAC_MENU_ITEMS,TITLE,0
TAC_MENU_ITEMS,CONTROLLER,0
TAC_MENU_ITEMS,ACTION,0
TAC_MENU_ITEMS,AREA,0
TAC_MENU_ITEMS,RESERVED,0
TAC_MENU_ITEMS,CHANGE_DATE_TIME,0
TAC_MENU_ITEMS,CHANGE_UID,0
TAC_MESSAGES,DISTRICT,1
TAC_MESSAGES,STAFF_ID,1
TAC_MESSAGES,MSG_DATE,1
TAC_MESSAGES,MSG_SEQUENCE,1
TAC_MESSAGES,BUILDING,0
TAC_MESSAGES,MSG_TYPE,0
TAC_MESSAGES,MESSAGE_BODY,0
TAC_MESSAGES,STUDENT_ID,0
TAC_MESSAGES,SECTION_KEY,0
TAC_MESSAGES,COURSE_SESSION,0
TAC_MESSAGES,SCHD_RESOLVED,0
TAC_MESSAGES,MESSAGE_DATE1,0
TAC_MESSAGES,MESSAGE_DATE2,0
TAC_MESSAGES,CHANGE_DATE_TIME,0
TAC_MESSAGES,CHANGE_UID,0
TAC_MS_SCHD,DISTRICT,1
TAC_MS_SCHD,BUILDING,1
TAC_MS_SCHD,PARAM_KEY,1
TAC_MS_SCHD,MS_TYPE,1
TAC_MS_SCHD,START_TIME,0
TAC_MS_SCHD,SUNDAY,0
TAC_MS_SCHD,MONDAY,0
TAC_MS_SCHD,TUESDAY,0
TAC_MS_SCHD,WEDNESDAY,0
TAC_MS_SCHD,THURSDAY,0
TAC_MS_SCHD,FRIDAY,0
TAC_MS_SCHD,SATURDAY,0
TAC_MS_SCHD,MS_PARAMETERS,0
TAC_MS_SCHD,EMAIL_TEACHERS,0
TAC_MS_SCHD,CHANGE_DATE_TIME,0
TAC_MS_SCHD,CHANGE_UID,0
TAC_MS_SCHD,GRACE_PERIOD,0
TAC_MSG_CRS_DATES,DISTRICT,1
TAC_MSG_CRS_DATES,STUDENT_ID,1
TAC_MSG_CRS_DATES,SECTION_KEY,1
TAC_MSG_CRS_DATES,MODELED,1
TAC_MSG_CRS_DATES,DATE_RANGE_KEY,1
TAC_MSG_CRS_DATES,DATE_ADDED,0
TAC_MSG_CRS_DATES,DATE_DROPPED,0
TAC_MSG_CRS_DATES,RESOLVED_CONFLICT,0
TAC_MSG_CRS_DATES,CHANGE_DATE_TIME,0
TAC_PRINT_RC,DISTRICT,1
TAC_PRINT_RC,LAUNCHER_ID,1
TAC_PRINT_RC,TAC_NAME,1
TAC_PRINT_RC,APP_TITLE,0
TAC_PRINT_RC,PROJECT_NUM,0
TAC_PRINT_RC,RC_NAME,0
TAC_PRINT_RC,REPORT_PATH,0
TAC_PRINT_RC,LOG_PATH,0
TAC_PRINT_RC,PRINTOFFICECOPY,0
TAC_PRINT_RC,SCSPI_ALTLANG,0
TAC_PRINT_RC,GENERAL_A,0
TAC_PRINT_RC,GENERAL_B,0
TAC_PRINT_RC,GENERAL_C,0
TAC_PRINT_RC,GENERAL_D,0
TAC_PRINT_RC,GENERAL_E,0
TAC_PRINT_RC,CHANGE_DATE_TIME,0
TAC_PRINT_RC,CHANGE_UID,0
TAC_SEAT_CRS_DET,DISTRICT,1
TAC_SEAT_CRS_DET,SECTION_KEY,1
TAC_SEAT_CRS_DET,COURSE_SESSION,1
TAC_SEAT_CRS_DET,STUDENT_ID,1
TAC_SEAT_CRS_DET,HORIZONTAL_POS,0
TAC_SEAT_CRS_DET,VERTICAL_POS,0
TAC_SEAT_CRS_DET,GRID_ROW_LOCATION,0
TAC_SEAT_CRS_DET,GRID_COL_LOCATION,0
TAC_SEAT_CRS_DET,CHANGE_DATE_TIME,0
TAC_SEAT_CRS_DET,CHANGE_UID,0
TAC_SEAT_CRS_HDR,DISTRICT,1
TAC_SEAT_CRS_HDR,SECTION_KEY,1
TAC_SEAT_CRS_HDR,COURSE_SESSION,1
TAC_SEAT_CRS_HDR,LAYOUT_TYPE,0
TAC_SEAT_CRS_HDR,NUM_GRID_COLS,0
TAC_SEAT_CRS_HDR,NUM_GRID_ROWS,0
TAC_SEAT_CRS_HDR,CHANGE_DATE_TIME,0
TAC_SEAT_CRS_HDR,CHANGE_UID,0
TAC_SEAT_HRM_DET,DISTRICT,1
TAC_SEAT_HRM_DET,BUILDING,1
TAC_SEAT_HRM_DET,SCHOOL_YEAR,1
TAC_SEAT_HRM_DET,SUMMER_SCHOOL,1
TAC_SEAT_HRM_DET,HOMEROOM_TYPE,1
TAC_SEAT_HRM_DET,HOMEROOM,1
TAC_SEAT_HRM_DET,STUDENT_ID,1
TAC_SEAT_HRM_DET,HORIZONTAL_POS,0
TAC_SEAT_HRM_DET,VERTICAL_POS,0
TAC_SEAT_HRM_DET,GRID_ROW_LOCATION,0
TAC_SEAT_HRM_DET,GRID_COL_LOCATION,0
TAC_SEAT_HRM_DET,CHANGE_DATE_TIME,0
TAC_SEAT_HRM_DET,CHANGE_UID,0
TAC_SEAT_HRM_HDR,DISTRICT,1
TAC_SEAT_HRM_HDR,BUILDING,1
TAC_SEAT_HRM_HDR,SCHOOL_YEAR,1
TAC_SEAT_HRM_HDR,SUMMER_SCHOOL,1
TAC_SEAT_HRM_HDR,HOMEROOM_TYPE,1
TAC_SEAT_HRM_HDR,HOMEROOM,1
TAC_SEAT_HRM_HDR,LAYOUT_TYPE,0
TAC_SEAT_HRM_HDR,NUM_GRID_COLS,0
TAC_SEAT_HRM_HDR,NUM_GRID_ROWS,0
TAC_SEAT_HRM_HDR,CHANGE_DATE_TIME,0
TAC_SEAT_HRM_HDR,CHANGE_UID,0
TAC_SEAT_PER_DET,DISTRICT,1
TAC_SEAT_PER_DET,BUILDING,1
TAC_SEAT_PER_DET,SCHOOL_YEAR,1
TAC_SEAT_PER_DET,SUMMER_SCHOOL,1
TAC_SEAT_PER_DET,PERIOD_LIST,1
TAC_SEAT_PER_DET,STUDENT_ID,1
TAC_SEAT_PER_DET,HORIZONTAL_POS,0
TAC_SEAT_PER_DET,VERTICAL_POS,0
TAC_SEAT_PER_DET,GRID_ROW_LOCATION,0
TAC_SEAT_PER_DET,GRID_COL_LOCATION,0
TAC_SEAT_PER_DET,CHANGE_DATE_TIME,0
TAC_SEAT_PER_DET,CHANGE_UID,0
TAC_SEAT_PER_HDR,DISTRICT,1
TAC_SEAT_PER_HDR,BUILDING,1
TAC_SEAT_PER_HDR,SCHOOL_YEAR,1
TAC_SEAT_PER_HDR,SUMMER_SCHOOL,1
TAC_SEAT_PER_HDR,PERIOD_LIST,1
TAC_SEAT_PER_HDR,LAYOUT_TYPE,0
TAC_SEAT_PER_HDR,NUM_GRID_COLS,0
TAC_SEAT_PER_HDR,NUM_GRID_ROWS,0
TAC_SEAT_PER_HDR,CHANGE_DATE_TIME,0
TAC_SEAT_PER_HDR,CHANGE_UID,0
TACTB_ISSUE,DISTRICT,1
TACTB_ISSUE,CODE,1
TACTB_ISSUE,DESCRIPTION,0
TACTB_ISSUE,USE_IN_CLASS,0
TACTB_ISSUE,USE_IN_REFER,0
TACTB_ISSUE,DISC_REFER,0
TACTB_ISSUE,SSP_REFER,0
TACTB_ISSUE,SSP_REFER_TAG,0
TACTB_ISSUE,STATE_CODE_EQUIV,0
TACTB_ISSUE,ACTIVE,0
TACTB_ISSUE,CHANGE_DATE_TIME,0
TACTB_ISSUE,CHANGE_UID,0
TACTB_ISSUE_ACTION,DISTRICT,1
TACTB_ISSUE_ACTION,CODE,1
TACTB_ISSUE_ACTION,DESCRIPTION,0
TACTB_ISSUE_ACTION,STATE_CODE_EQUIV,0
TACTB_ISSUE_ACTION,ACTIVE,0
TACTB_ISSUE_ACTION,CHANGE_DATE_TIME,0
TACTB_ISSUE_ACTION,CHANGE_UID,0
TACTB_ISSUE_LOCATION,DISTRICT,1
TACTB_ISSUE_LOCATION,CODE,1
TACTB_ISSUE_LOCATION,DESCRIPTION,0
TACTB_ISSUE_LOCATION,DISC_CODE,0
TACTB_ISSUE_LOCATION,STATE_CODE_EQUIV,0
TACTB_ISSUE_LOCATION,ACTIVE,0
TACTB_ISSUE_LOCATION,CHANGE_DATE_TIME,0
TACTB_ISSUE_LOCATION,CHANGE_UID,0
tmp_medtb_vis_exam_ark,DISTRICT,0
tmp_medtb_vis_exam_ark,FOLLOWUP_CODE,0
tmp_medtb_vis_exam_ark,CONFIRMED_NORMAL,0
tmp_medtb_vis_exam_ark,CHANGE_DATE_TIME,0
tmp_medtb_vis_exam_ark,CHANGE_UID,0
WSSecAuthenticationLogTbl,WSSecAuthenticationLogID,1
WSSecAuthenticationLogTbl,WSSecApplicationID,0
WSSecAuthenticationLogTbl,WSSecCustomerID,0
WSSecAuthenticationLogTbl,NOnce,0
WSSecAuthenticationLogTbl,CreatedDate,0
WSSecAuthenticationLogTbl,ExpiresDate,0
WSSecAuthenticationLogTbl,AuthenticInd,0
WSSecAuthenticationLogTbl,FailedDesc,0
'@

return $espDatabase | ConvertFrom-Csv
}

function ConvertTo-FileSizeString {
    <#
    
    .LINK
    Author: Lee Dailey
    https://pastebin.com/s8mH5gdP
    
    #>
    [CmdletBinding()]
    Param
        (
        [Parameter (
            Position = 0,
            Mandatory)]
            [int64]
            $Size
        )
    
    switch ($Size)
        {
        {$_ -gt 1TB} 
            {[string]::Format("{0:0.00} TB", $Size / 1TB); break}
        {$_ -gt 1GB} 
            {[string]::Format("{0:0.00} GB", $Size / 1GB); break}
        {$_ -gt 1MB} 
            {[string]::Format("{0:0.00} MB", $Size / 1MB); break}
        {$_ -gt 1KB} 
            {[string]::Format("{0:0.00} KB", $Size / 1KB); break}
        {$_ -gt 0}
            {[string]::Format("{0} B", $Size); break}
        {$_ -eq 0}
            {"0 KB"; break}
        default  
            {"0 KB"}
        }
    } # end >> function Format-FileSizeString

function Get-eSPAdditionalREGMAINTTables {
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