#Requires -Version 7
#Requires -Modules eSchoolModule

<#

    .SYNOPSIS
    This script will create the download definitions for you for REG, SCHD, ATT, AND MR tables.

    .DESCRIPTION
    There will be a 00 (all), 03 (3 hour diff), 12 (12 hour), 24 (24 hour), 1M (1 Month), 1Y (1 Year)
    The 00 (all) definition will contain the entire table. The differentials will be limited to the current school
    year.

#>

Connect-ToeSchool

@( 
    @{
        Name = 'REG'
        Prefix = 'REG'
    }
    @{
        Name = 'SCH'
        Prefix = 'SCHD_'
    },
    @{
        Name = 'MR0'
        Prefix = 'MR_'
    },
    @{
        Name = 'ATT'
        Prefix = 'ATT_'
    }
) | ForEach-Object {

    $defname = $PSitem.Name
    $table_prefix = $PSItem.Prefix
    $tables = Get-Content .\resources\Tables_That_Can_Be_Exported.txt | Where-Object { $PSitem -like "$($table_prefix)*" }

    @(
        @{ DefinitionName = "$($defname)00"; tables = $tables; 'DoNotLimitSchoolYear' = $True }, #all
        @{ DefinitionName = "$($defname)03"; tables = $tables; sql = 'WHERE CONVERT(DATETIME,CHANGE_DATE_TIME,101) >= DateAdd(Hour, DateDiff(Hour, 0, GetDate())-3, 0)' }, #3 hour
        @{ DefinitionName = "$($defname)12"; tables = $tables; sql = 'WHERE CONVERT(DATETIME,CHANGE_DATE_TIME,101) >= DateAdd(Hour, DateDiff(Hour, 0, GetDate())-12, 0)' }, #12 hour
        @{ DefinitionName = "$($defname)24"; tables = $tables; sql = 'WHERE CONVERT(DATETIME,CHANGE_DATE_TIME,101) >= DateAdd(Hour, DateDiff(Hour, 0, GetDate())-24, 0)' }, #24 hour
        @{ DefinitionName = "$($defname)1M"; tables = $tables; sql = 'WHERE CONVERT(DATETIME,CHANGE_DATE_TIME,101) >= DateAdd(Hour, DateDiff(Hour, 0, GetDate())-720, 0) '}, #1 month
        @{ DefinitionName = "$($defname)1Y"; tables = $tables; sql = 'WHERE CONVERT(DATETIME,CHANGE_DATE_TIME,101) >= DateAdd(Hour, DateDiff(Hour, 0, GetDate())-8760, 0)' } #1 Year
    ) | ForEach-Object {
        try {
            $PSItem
            New-ESPDownloadDefinition @PSItem | Format-List #-Verbose
        } catch {
            $psitem
        }
    }
}
