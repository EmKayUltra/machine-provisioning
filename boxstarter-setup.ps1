# 1. Install Chocolatey (which installs Boxstarter)
<#
Set-ExecutionPolicy RemoteSigned -Force
# Create empty profile (so profile-integration scripts have something to append to)
if (-not (Test-Path $PROFILE)) {
    $directory = [IO.Path]::GetDirectoryName($PROFILE)
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory $directory | Out-Null
    }
    
    "# Profile" > $PROFILE
}

iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco install -y boxstarter
#>


# 1a. (ALTERNATIVE) Install Boxstarter first (which installs Chocolatey) - less recommended
<#

Set-ExecutionPolicy RemoteSigned -Force
# Create empty profile (so profile-integration scripts have something to append to)
if (-not (Test-Path $PROFILE)) {
    $directory = [IO.Path]::GetDirectoryName($PROFILE)
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory $directory | Out-Null
    }
    
    "# Profile" > $PROFILE
}

iex ((New-Object System.Net.WebClient).DownloadString('http://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force

#>


# 2. Run Boxstarter
<# 

$cred = Get-Credential domain\username
$urlOrFilePathOfThisScript = ""
Install-BoxstarterPackage -PackageName $urlOrFilePathOfThisScript -Credential $cred

#>


# Boxstarter options
$Boxstarter.RebootOk=$true # Allow reboots?
$Boxstarter.NoPassword=$false # Is this a machine with no login password?
$Boxstarter.AutoLogin=$true # Save my password securely and auto-login after a reboot


#---- TEMPORARY ---
Write-Output "--Temporary settings--"

Write-Output "Removing legal splash"
# remove legal splash, which prevents reboots from working effectively - be sure to save these values and paste them in below!
set-itemproperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system" -name "legalnoticecaption" -value ""
set-itemproperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system" -name "legalnoticetext" -value ""

Write-Output "Disabling UAC"
Disable-UAC

#--- Apps ---
Write-Output "--Installing apps via Chocolatey--"


# establish static cache location
# - needed because some packages end up trying to install in increasingly-nested directories (b/c the cacheLocation defaults to a relative path)
# - see https://github.com/mwrock/boxstarter/issues/241#issuecomment-336028348
New-Item -Path "$env:userprofile\AppData\Local\ChocoCache" -ItemType directory -Force | Out-Null

$common = "" # "--cacheLocation `"$env:userprofile\AppData\Local\ChocoCache`""
choco config set cacheLocation "$env:userprofile\AppData\Local\ChocoCache" 

## langs
choco install -y nodejs.install

## browsers
choco install -y googlechrome $common
choco install -y firefox $common

## text editors
choco install -y VSCode $common
choco install -y VSCode-Powershell $common
choco install -y VSCode-CSharp $common
choco install -y SublimeText3 $common
choco install -y notepadplusplus $common

## other tools
choco install -y sysinternals $common
choco install -y microsoft-teams $common
choco install -y beyondcompare $common
choco install -y winscp $common
choco install -y filezilla $common
choco install -y ilspy $common
choco install -y 7zip $common
choco install -y 7zip.commandline $common
choco install -y git $common
choco install -y git-credential-manager-for-windows $common
choco install -y git-credential-winstore $common
choco install -y gitextensions $common
choco install -y poshgit $common
choco install -y nuget.commandline $common
choco install -y paint.net $common
choco install -y keypirinha $common
choco install -y citrix-receiver $common
choco install -y rdtabs $common
choco install -y microsoft-windows-terminal $common
choco install -y postman $common

## cloud cli
choco install -y awscli $common
choco install -y awstools.powershell $common


## visual studio
choco install -y visualstudio2017professional $common
choco install -y netfx-4.7.2-devpack $common
choco install -y visualstudio2017-workload-manageddesktop --includeOptional $common
choco install -y visualstudio2017-workload-netcoretools --includeOptional $common
choco install -y visualstudio2017-workload-netweb --includeOptional $common
choco install -y visualstudio2017-workload-webcrossplat --includeOptional $common
# choco install -y visualstudio2019-workload-manageddesktop --includeOptional $common
# choco install -y visualstudio2019-workload-netcoretools --includeOptional $common
# choco install -y visualstudio2019-workload-netweb --includeOptional $common
# choco install -y visualstudio2019-workload-webcrossplat --includeOptional $common

## sql server
choco install -y sql-server-management-studio $common
choco install -y sql-server-2017 $common
choco install -y sqlsearch $common
choco install -y sqlserver-cmdlineutils $common
choco install -y sql2017-dacframework $common

# Manually downloaded software
Write-Output "--Installing apps manually--"

$UtilDownloadPath = join-path $env:homepath 'Downloads'
If (-not (Test-Path $UtilDownloadPath)) {
    mkdir $UtilDownloadPath -Force
}
Push-Location $UtilDownloadPath

$ManualDownloadInstall = @{}

Foreach ($software in $ManualDownloadInstall.keys) {
    Write-Output "Downloading $software"
    if ( -not (Test-Path $software) ) {
        try {
            Invoke-WebRequest $ManualDownloadInstall[$software] -OutFile $software -UseBasicParsing
            $FilesDownloaded += $software
        }
        catch {}
    }
    else {
        Write-Warning "File is already downloaded, skipping: $software"
    }
}

# Extracting self-contained binaries (zip files) to our bin folder
Write-Output 'Extracting self-contained binaries (zip files) to our bin folder'
Get-ChildItem -Path $UtilDownloadPath -File -Filter '*.zip' | Where-Object {$FilesDownloaded -contains $_.Name} | ForEach-Object {
    Expand-Archive -Path $_.FullName -DestinationPath $UtilBinPath -Force
}

# Kick off exe installs
Get-ChildItem -Path $UtilDownloadPath -File -Filter '*.exe' | Where-Object {$FilesDownloaded -contains $_.Name} | ForEach-Object {
    Start-Proc -Exe $_.FullName -waitforexit
}

# Kick off msi installs
Get-ChildItem -Path $UtilDownloadPath -File -Filter '*.msi' | Where-Object {$FilesDownloaded -contains $_.Name} | ForEach-Object {
    Start-Proc -Exe $_.FullName -waitforexit
}
Pop-Location



#--- Windows Settings ---
Write-Output "--Modifying Windows Settings--"

Write-Output "Modifying Explorer options"
Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowFullPathInTitleBar
Set-WindowsExplorerOptions -DisableShowRecentFilesInQuickAccess -DisableShowFrequentFoldersInQuickAccess

Write-Output "Modifying taskbar options"
Set-TaskbarOptions -Dock Bottom -Combine Always -AlwaysShowIconsOn

# disabled bing search in start menu
Write-Output "Disabling Bing Search in start menu"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {  
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1


# Change Explorer home screen back to "This PC"
Write-Output "Changing explorer home to 'This PC'"
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1
# Change it back to "Quick Access" (Windows 10 default)
# Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 2

# show this pc on desktop
Write-Output "Showing 'This PC' on desktop"
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0

# show user folder on desktop
Write-Output "Showing user home on desktop"
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0

Write-Output "Hiding Music"
# hide music from this pc
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue

# hide music from explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"

Write-Output "Hiding Pictures"
# hide photos from this pc
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue

# hide photos from explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"

Write-Output "Hiding Videos"
# hide videos from this pc
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue

# hide videos from explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"

Write-Output "Hiding 3D objects"
# hide 3d objects from this pc
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

# hide 3d objects from explorer
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"


# show file extensions
# being done with boxstarter now
# Write-Output "Showing file extensions"
# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

# show hidden files
# being done with boxstarter now
# Write-Output "Showing hidden files"
# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

# Disable Cortana
Write-Output "Disabling Cortana"
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

# Hide taskbar search box
Write-Output "Hiding task bar search box"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

# Hide Task View
Write-Output "Hiding task view"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

# Hide task Bar People icon
Write-Output "Hiding task bar people icon"
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

# Disable auto-hide taskbar
# being done with boxstarter now
# Write-Output "Disabling auto-hide taskbar"
# try {
#     $CurrSettings = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3').Settings
#     $CurrSettings[8] = 2
#     Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name StuckRects3 -Value $CurrSettings -Type Binary
# }
# catch {
#     Write-Warning "Unable to pull the current registry settings!"
# }

# show tray icons
# being done with boxstarter now
# Write-Output "Showing all tray icons"
# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0

#--- Setup Environment ---

## Establish dev directories
Write-Output "Setting up dev directories"
if (!(Test-Path "$home\code")) { mkdir "$home\code" }

## Create shortcuts on desktop
Write-Output "Creating Desktop Shortcuts"
$WshShell = New-Object -comObject WScript.Shell

# $Shortcut = $WshShell.CreateShortcut("$home\Desktop\SHORTCUT_NAME.url")
# $Shortcut.TargetPath = "SHORTCUT_URL"
# $Shortcut.Save()

Write-Output "Modifying Quick Access" # quick access - https://gallery.technet.microsoft.com/scriptcenter/Set-QuickAccess-117e9a89
$QuickAccess = New-Object -ComObject shell.application 

## Pin items to home
$TargetObject = $QuickAccess.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}").Items() | Where-Object {$_.Path -eq "$home"}
if ($TargetObject -eq $null -And (Test-Path $home)) 
{
    $QuickAccess.Namespace("$home").Self.InvokeVerb("pintohome")
}

$TargetObject = $QuickAccess.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}").Items() | Where-Object {$_.Path -eq "$home\code"}
if ($TargetObject -eq $null -And (Test-Path "$home\code")) 
{
    $QuickAccess.Namespace("$home\code").Self.InvokeVerb("pintohome")
}

## Unpin items from home
$TargetObject = $QuickAccess.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}").Items() | Where-Object {$_.Path -eq "$home\Pictures"}
if ($TargetObject -ne $null) 
{
    $TargetObject.InvokeVerb("unpinfromhome") 
}

$TargetObject = $QuickAccess.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}").Items() | Where-Object {$_.Path -eq "$home\Documents"}
if ($TargetObject -ne $null) 
{
    $TargetObject.InvokeVerb("unpinfromhome") 
}

$TargetObject = $QuickAccess.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}").Items() | Where-Object {$_.Path -eq "$home\Downloads"}
if ($TargetObject -ne $null) 
{
    $TargetObject.InvokeVerb("unpinfromhome") 
}

## Create taskbar shortcuts
Write-Output "Creating taskbar shortcuts"
Install-ChocolateyPinnedTaskBarItem "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
Install-ChocolateyPinnedTaskBarItem "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Professional\Common7\IDE\devenv.exe"
Install-ChocolateyPinnedTaskBarItem "$home\AppData\Local\Programs\Microsoft VS Code\Code.exe"

## Create PROVISIONING_README.txt
Write-Output "Creating PROVISIONING_README.txt"
@"
## What's Done`r`n
`t1. Various Windows UI tweaks`r`n
`t2. Installed various software`r`n
`t3. Created default work directories`r`n
`t4. Windows Updated`r`n`r`n
"@ | Out-File "$home\Desktop\PROVISIONING_README.txt" -Force;

if (!(Test-Path $profile)) {
    Write-Output "Creating Powershell profile"
    ni $profile;

    @'
# add PATH settings to profile
if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer") {
    $env:Path += ";C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer";
}
if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\MSBuild\15.0\Bin") {
    $env:Path += ";C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\MSBuild\15.0\Bin"; # 2017
}

'@ | Out-File $profile -Append;
}


# windows updates
Write-Output "Installing Windows Updates"
Install-WindowsUpdate -AcceptEula -GetUpdatesFromMS

#--- Restore Temporary Settings ---
# restore legal splash
set-itemproperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system" -name "legalnoticecaption" -value "OLD_LEGAL_NOTICE_CAPTION_VALUE"
set-itemproperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system" -name "legalnoticetext" -value "OLD_LEGAL_NOTICE_TEXT_VALUE"

Write-Output "Enabling UAC"
Enable-UAC

Read-Host "Restart required for some modifications to take effect. Please reboot."
