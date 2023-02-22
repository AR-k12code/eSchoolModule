#Requires -Version 7
#Requires -Modules eSchoolModule,SimplySQL

<#

    .SYNOPSIS
    This script will download the REG, SCHD, ATT, AND MR CSV files.

    .DESCRIPTION
    There will be a 00 (all), 03 (3 hour diff), 12 (12 hour), 24 (24 hour), 1M (1 Month), 1Y (1 Year)
    The 00 (all) definition will contain the entire table. The differentials will be limited to the current school year.

#>

Param(
    [Parameter(Mandatory=$false)][switch]$SkipRunningDownloadDefinition, #if you skip you'll want to specify a $FilesAfter date.
    [Parameter(Mandatory=$false)][ValidateSet('00','03','12','24','1M','1Y')][string]$Differential = '03',
    [Parameter(Mandatory=$false)][datetime]$FilesAfter = (Get-Date) #You can specify a date/time that only files after that will be downloaded.
)

#We really should verify the download definitions exists here.

Assert-eSPSession

if (-Not($SkipRunningDownloadDefinition)) {
    $tasks = @()

    @("REG","SCH",'MR0','ATT') | ForEach-Object {
        $tasks += "$($PSitem)$($Differential)"
        Invoke-eSPDownloadDefinition -InterfaceID "$($PSitem)$($Differential)"
        Write-Progress -Activity "Running Download Definitions" -Status "Running" -Id 1
    }

    do {

        Write-Progress -Activity "Running Download Definitions" -Status "Running" -Id 1

        $progressbars = Get-eSPTaskList -ActiveTasksOnly -SilentErrors | Where-Object { $tasks -contains $PSitem.TaskName } | Select-Object -Property TaskName,StartTime,ProgressDescription,RecordsProcessed,TotalRecords | Group-Object -Property TaskName -AsHashTable

        $tasks | ForEach-Object {
            $task = $progressbars.$PSitem
            if ($task) {
                $percent = [Math]::Floor( (($task.RecordsProcessed)/($task.TotalRecords) * 100) )
                Write-Progress -Activity "$PSitem" -Status "$($task.ProgressDescription)" -PercentComplete $percent -ParentId 1
            } else {
                Write-Progress -Activity "$PSitem" -PercentComplete "100" -ParentId 1
            }
        }

        Start-Sleep -Seconds 3
    } while (Get-eSPTaskList -ActiveTasksOnly -SilentErrors)
}

$dateTime = Get-Date -Format 'yyyy-MM-dd-HH-mm-ss'

Open-SQLiteConnection -DataSource ".\gentrysms.sqlite3"

$eSPFiles = Get-eSPFileList | Where-Object { 
    $PSitem.FileExtension -eq '.csv' -and
    $PSitem.ModifiedDate -ge $FilesAfter
}

@('REG','SCHD_','MR_','ATT_') | ForEach-Object {

    $prefix = $PSItem

    $files = $eSPFiles | Where-Object { 
        $PSItem.RawFileName -like "$($prefix)*"
    }
    
    #Download all files and processes multi threaded.
    $files | ForEach-Object -Parallel {

        #Pull in eSchoolSession Variable.
        $eSchoolSession = $using:eSchoolSession

        $tableName = $PSitem.RawFileName -replace '.csv',''

        #New-Variable -Name $PSItem -Value (Get-eSPFile -FileName "$($PSItem).csv" -Raw | ConvertFrom-CSV -Delimiter '|' | Select-Object -ExcludeProperty '#!#') -Force
        Write-Host "Downloading file $($PSItem.RawFileName)"
        (Get-eSPFile -FileName "$($PSItem.RawFileName)" -Raw) -replace "`n",'{LF}' -replace "`r",'{CR}' -replace '\|#!#{CR}{LF}',"`r`n" | Out-File "$($PSItem.RawFileName)" -NoNewline

        #verify columns and output file.
        & csvclean.exe -d '|' "$($PSItem.RawFileName)" --encoding windows-1252

        #import csv directly to database.
        & csvsql.exe -I --db "sqlite:///gentrysms.sqlite3" -d ',' -y 0 --insert --overwrite --blanks --tables "z_import_$($tableName)" "$($tableName)_out.csv"
       
        Write-Host "Backing up $($tableName).csv to archives\$($tableName)-$($dateTime).csv"
        Move-Item -Path "$($tableName).csv" -Destination "archives\$($tableName)-$($dateTime).csv" -Force -Verbose

    } -ThrottleLimit 10

    #import into sqlite3 database one by one so we don't lock the file.
    $files | ForEach-Object {

        $tableName = $PSitem.RawFileName -replace '.csv',''

        #import csv directly to database.
        Write-Host "Importing file $($tableName)_out.csv ..."
        & csvsql.exe -I --db "sqlite:///gentrysms.sqlite3" -d ',' -y 0 --insert --overwrite --blanks --tables "z_import_$($tableName)" "$($tableName)_out.csv"

    }

}
