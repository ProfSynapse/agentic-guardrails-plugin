param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("create", "edit")]
    [string]$Operation,
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [string]$Cell = "B2",
    [string]$Value = "edited-by-excel"
)

$ErrorActionPreference = "Stop"
$excel = $null
$workbook = $null
$macroInjected = $false
try {
    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false
    # msoAutomationSecurityForceDisable: opening the fixture must not run macros.
    $excel.AutomationSecurity = 3
    if ($Operation -eq "create") {
        $workbook = $excel.Workbooks.Add()
        $worksheet = $workbook.Worksheets.Item(1)
        $worksheet.Name = "Data"
        $worksheet.Range("A1").Value2 = "AGW XLSM integration fixture"
        try {
            $component = $workbook.VBProject.VBComponents.Add(1)
            $component.Name = "AgwSmokeModule"
            $component.CodeModule.AddFromString(
                "Public Sub AgwSmokeMacro()`r`n    Range(""Z1"").Value = ""macro-not-run""`r`nEnd Sub"
            )
            $macroInjected = $true
        }
        catch {
            # Trust Center commonly disables programmatic VBA-project access.
            # The macro-enabled package still exercises native Excel save/publish.
            $macroInjected = $false
        }
        # xlOpenXMLWorkbookMacroEnabled
        $workbook.SaveAs($Path, 52)
    }
    else {
        $workbook = $excel.Workbooks.Open($Path, 0, $false)
        $worksheet = $workbook.Worksheets.Item("Data")
        $worksheet.Range($Cell).Value2 = $Value
        $workbook.Save()
    }
    [ordered]@{
        ok = $true
        operation = $Operation
        path = $Path
        macro_injected = $macroInjected
    } | ConvertTo-Json -Compress
}
finally {
    if ($null -ne $workbook) {
        $workbook.Close($false)
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($workbook)
    }
    if ($null -ne $excel) {
        $excel.Quit()
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($excel)
    }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}
