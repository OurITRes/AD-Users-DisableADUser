[CmdLetBinding(DefaultParameterSetName = 'Default')]
Param(
    [Parameter(ParameterSetName='Default',Mandatory=$true)]
    [String[]]
    $List,

    [Parameter(ParameterSetName='Default',Mandatory=$false)]
    [String]
    $Reference = "No REFs"
)

#region Preparation

    Clear-Host

    $savedLogs = @()

    #region Renew AD information Function

        Function Get-RenewedData
        {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
                [String]$Account,

                [Parameter(Mandatory=$false)]
                [String]$Pdc = (Get-ADDomain).PDCEmulator
            )

            $output = Get-ADUser -filter {samaccountname -eq $Account} -properties isCriticalSystemObject,
                                                                                       Description,
                                                                                       Enabled,
                                                                                       Name,
                                                                                       DisplayName,
                                                                                       SmartcardLogonRequired,
                                                                                       PasswordExpired,
                                                                                       PasswordNotRequired -server $Pdc
            return $output
        }

    #endregion

    #region Pwd Function

        Function Get-StrongPassword

        {

            [CmdletBinding()]

            Param(

                [Parameter(Mandatory=$true,ValueFromPipeline=$true)]

                [int]$PasswordLength

            )

            Add-Type -AssemblyName System.Web

            $PassComplexCheck = $false

            do {

                $newPassword=[System.Web.Security.Membership]::GeneratePassword($PasswordLength,1)

                If ( ($newPassword -cmatch "[A-Z\p{Lu}\s]") -and

                        ($newPassword -cmatch "[a-z\p{Ll}\s]") -and

                        ($newPassword -match "[\d]") -and

                        ($newPassword -match "[^\w]") )

                {

                    $PassComplexCheck=$True

                }

            } While ($PassComplexCheck -eq $false)

            return $newPassword

        }

    #endregion

    #region Log Functions

        Function Set-Log {

            [CmdLetBinding()]

            param (

                [Parameter(Mandatory=$true,

                            ValueFromPipeline=$true)]

                [ValidateNotNullOrEmpty()]

                [String]

                $message,

 

                [Parameter(Mandatory=$false)]

                [ValidateSet("Success","Info","Warning","Error","No")]

                [String]

                $severity="Info",

 

                [Parameter(Mandatory=$false)]

                [Switch]

                $hold

            )

            if ($severity -ne "No") {

                $message = "`t" + $severity.toupper() + ":`t"+ $message

            }

            else {

                $message = "`t"+ $message

            }

            if ($hold.IsPresent) {

                return ($(([datetime]::Now).toString("HH:mm:ss") + " " + $message))

            }

            else

            {

                Write-Host $(([datetime]::Now).toString("HH:mm:ss") + " " + $message)

            }

        }

 

        Function Set-ErrorToLog {

            [CmdLetBinding()]

            param (

                [Parameter(Mandatory=$true,

                            ValueFromPipeline=$true)]

                [ValidateNotNullOrEmpty()]

                [object]

                $theError

            )

            ("Message: `t" + $theError.Exception.Message) | Set-Log -severity No

            ("Activity: `t" + $theError.CategoryInfo.Activity) | Set-Log -severity No

            ("Category: `t" + $theError.CategoryInfo.Category) | Set-Log -severity No

            ("Reason: `t" + $theError.CategoryInfo.Reason) | Set-Log -severity No

            ("Target: `t" + $theError.CategoryInfo.TargetName) | Set-Log -severity No

        }

    #endregion

    #region Time / Date Info

 

        $DateRef         = [datetime]::Now

        $Timer           = [system.diagnostics.stopwatch]::StartNew()

        $dateSimple      = $DateRef.toString("yyyyMMdd")

        $dateStamped     = $DateRef.ToString("yyyyMMdd.HHmmss")

 

    #endregion

    #region Locations

        #region Declaration

            $Paths = @{

                    Logs    = ""

                    Results = ""

                    Script  = ""

                    grouped = "ADObjectsDisabled"

            }

        #endregion

 

        #region Script Location

 

            function Get-ScriptName {

                return $MyInvocation.ScriptName | Split-Path -Leaf

            }

 

            # Gets Script Name

            $scriptFullName = Get-ScriptName

            $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($scriptFullName)

   

            # Determine script location for PowerShell

            $Paths.Script = split-path -parent $MyInvocation.MyCommand.Definition

 

            # Determine current location

            Push-Location

            $SAVWorkDir = Get-Location

 

            # Force WorkDir to be the same as Script location

            if ($SAVWorkDir.Path -ne $Paths.Script) {

                Set-Location $Paths.Script

            }

 

            $savedLogs += ("Script name is: $($scriptName)"  | Set-Log -hold)

 

        #endregion

 

        #region Location Grouping

            if($Paths.grouped -ne "") {

                $rep = $Paths.grouped

                $savedLogs += ("Folder(s) will be with: $($Paths.grouped)"  | Set-Log -hold)

            }

            else {

                $rep = $scriptName

                $savedLogs += ("Folder(s) will be with: $($rep)"  | Set-Log -hold)

            }

        #endregion

 

        #region Logs Location 

    

            # Looks where the logs folder should be

            $Paths.Logs =  "D:\_logs\" + $rep

 

            # Check for existing Log location or creates it

            if (-not(Test-Path "D:\_logs")) {

                New-Item -Path "D:\" -Name "_logs" -ItemType "directory" | out-Null

                $savedLogs += ("Creation of directory D:\_logs"  | Set-Log -hold)

            }

            if (-not(Test-Path $Paths.Logs)) {

                New-Item -Path "D:\_logs\" -Name $rep -ItemType "directory" | out-Null

                $savedLogs += ("Creation of directory $($Paths.Logs)"  | Set-Log -hold)

            }

 

        #endregion

 

        #region Result Location 

    

            # Looks where the Result folder should be

            $Paths.Results =  "D:\_results\" + $rep

 

            # Check for existing Result location or creates it

            if (-not(Test-Path "D:\_results" )) {

                New-Item -Path "D:\" -Name "_results" -ItemType "directory" | out-Null

                $savedLogs += ("Creation of directory D:\_results"  | Set-Log -hold)

            }

            if (-not(Test-Path $Paths.Results)) {

                New-Item -Path "D:\_results\" -Name $rep -ItemType "directory" | out-Null

                $savedLogs += ("Creation of directory $($Paths.Results)"  | Set-Log -hold)

            }

 

        #endregion

    #endregion

    #region Load AD Module

 

        try{

            Import-Module ActiveDirectory -ErrorAction Stop

        }

        catch{

            $savedLogs += ("Unable to load Active Directory PowerShell Module"  | Set-Log -severity Warning -hold)

        }

 

    #endregion

    #region Gather Active Directory Data

       

        $domainInfo = Get-ADDomain

        $savedLogs += ("Working in domain: $($domainInfo.NetBIOSName)"  | Set-Log -hold)

        $PDC = $domainInfo.PDCEmulator

 

    #endregion

    #region System Settings

 

        # Parameters for Import and Export CSV

        $Param4CSV = @{

            Delimiter         = ';'

            Encoding          = "UTF8"

            NoTypeInformation = $true

            Path              = ""

        }

 

        class Issue

        {

            [String]$SamAccountName

            Issue(){}

            Issue([String]$name)

            {

                $this.SamAccountName = $name

            }

        }

        class User

        {

            [String]$DescriptionOld

            [String]$Description

            [Boolean]$CheckDescription

 

            [String]$DisplayNameOld

            [String]$DisplayName

            [Boolean]$CheckDisplayName

 

            [Boolean]$EnabledOld

            [Boolean]$Enabled

            [Boolean]$CheckEnabled

 

            [Boolean]$isCriticalSystemObjectOld

            [Boolean]$isCriticalSystemObject

            [Boolean]$CheckisCriticalSystemObject

 

            [Boolean]$ProtectedFromAccidentalDeletionOld

            [Boolean]$ProtectedFromAccidentalDeletion

            [Boolean]$CheckProtectedFromAccidentalDeletion

 

            [String]$NameOld 

            [String]$Name 

            [Boolean]$CheckName

 

            [String]$ObjectClass

            [String]$ObjectGUID 

            [String]$SamAccountName

            [String]$SID 

            [String]$DistinguishedNameOld

            [String]$DistinguishedName

            [String]$UserPrincipalNameOld

            [String]$UserPrincipalName

 

 

            User ([Object]$adData, [String]$newDescription, [String]$ritm)

            {

                # Store old Values

                $this.DescriptionOld = $adData.Description

                $this.DistinguishedNameOld = $adData.DistinguishedName

                $this.EnabledOld = $adData.Enabled

                $this.isCriticalSystemObjectOld = $adData.isCriticalSystemObject

                $this.NameOld = $adData.Name

                $this.DisplayNameOld = $adData.DisplayName

 

                #Store value that do not change

                $this.ObjectClass = $adData.ObjectClass

                $this.ObjectGUID = $adData.ObjectGUID

                $this.SamAccountName = $adData.SamAccountName

                $this.SID = $adData.SID

                $this.UserPrincipalNameOld = $adData.UserPrincipalName

 

                #Register the new value we want

                $this.Enabled = $false

                $this.isCriticalSystemObject = $false             

                $this.ProtectedFromAccidentalDeletion = $false

                if ($this.NameOld -notlike "_disable_*")

                {

                    $this.Name = "_disable_" + $this.NameOld + "_" + (Get-Date).ToString("yyyy-MM-dd")

                }

                else

                {

                    $this.Name = $this.NameOld

                }

                if ($this.DisplayNameOld -notlike "*TO BE DELETED*")

                {

                    $this.DisplayName = ( '*** TO BE DELETED *** ' + $this.DisplayNameOld)

                }

                else

                {

                    $this.DisplayName = $this.DisplayNameOld

                }

                if ($this.DescriptionOld -notlike "$ritm*")

                {

                    $this.Description = ( $ritm + ';' + $this.DescriptionOld)

                }

                else

                {

                    $this.Description = $this.DescriptionOld

                }

            }

 

            Check ([Object]$data)

            {

                $this.DistinguishedName = $data.DistinguishedName

                $this.UserPrincipalName = $data.UserPrincipalName

                $this.CheckDescription = if ($data.Description -eq $this.Description){$true}else{$false}

                $this.CheckDisplayName = if ($data.DisplayName -eq $this.DisplayName){$true}else{$false}

                $this.CheckEnabled = if ($data.Enabled -eq $this.Enabled){$true}else{$false}

                $this.CheckisCriticalSystemObject = if ($data.isCriticalSystemObject -eq $null -and $this.isCriticalSystemObject -eq $false){$true}else{$false}

               

                $this.CheckProtectedFromAccidentalDeletion = if ($this.ProtectedFromAccidentalDeletion -eq $this.ProtectedFromAccidentalDeletionOld){$true}else{$false}

                $this.CheckName = if ($data.Name -eq $this.Name){$true}else{$false}

            }

 

        }

 

    #endregion System Settings

    #region User Variables

 

        # Fichier de Logs

        $logFile    = "$($Paths.Logs)\" + $dateStamped + "." + $scriptName + ".log"

        $savedLogs += ("LOG File : $($logFile)" | Set-Log -hold)

 

        # Fichier CSV

        $csvFile    = "$($Paths.Results)\" + $dateStamped + "." + $domainInfo.DNSRoot + $scriptName + ".csv"

        $savedLogs += ("CSV File : $($csvFile)" | Set-Log -hold)

 

        # Cleaning old logs

        $savedLogs += ("Cleaning old log files" | Set-Log -hold)

        $Paths.Logs | Get-ChildItem  -File |

            Where-object {$_.Name -like "*$($scriptName)*" -and $_.CreationTime -lt $((get-date).adddays(-1))} |

            Remove-ItemProperty -Force -ErrorAction SilentlyContinue

 

   

        # Cleaning old results

        $savedLogs += ("Cleaning old results files" | Set-Log -hold)

        $Paths.Results | Get-ChildItem -File |

            Where-object {$_.Name -like "*$($scriptName)*" -and $_.CreationTime -lt $((get-date).adddays(-2))} |

            Remove-Item -Force -ErrorAction SilentlyContinue

 

    #endregion

 

    Start-Transcript -Path $logFile -Force | Set-Log

 

    # Show what happened before

    $savedLogs | ForEach {Write-Host $_}

 

#endregion

 

#region MAIN

    $howMany = ( $List | Measure-Object ).Count

    $notDone = @()

    $upderrors = @()

    $done = @()

    $counter = 0

    ForEach ($element in $list)

    {

        "Dealing with Number $counter" | Set-Log

        $userAccount = $element

        $thisUser = Get-RenewedData -Account $userAccount -Pdc $PDC

   

        if (($thisUser | Measure-Object).count -eq 1)

        {

            "$userAccount has been found" | Set-Log

 

            $userObject = [User]::new($thisUser, $Description, $Reference)

 

            if ($thisUser.enabled -eq $true -and $thisUser.Description -notlike "*TO BE DELETED*")

            {

                Try

                {

                    # Changing Password to a very difficult one

                    #$password = Get-StrongPassword -PasswordLength 32

                    #$thisUser | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)

                    #$thisUser = Get-RenewedData -Account $userAccount -Pdc $PDC

 

                    # Change Password at next logon

                    $thisUser | Set-ADUser -ChangePasswordAtLogon:$true -server $PDC

                    $thisUser = Get-RenewedData -Account $userAccount -Pdc $PDC

 

                    # Use Smart card for interactive logon

                    $thisUser | Set-ADUser -SmartcardLogonRequired $true -server $PDC

                    $thisUser = Get-RenewedData -Account $userAccount -Pdc $PDC

                   

                    # Critical System Object

                    if ($userObject.isCriticalSystemObjectOld -eq $true)

                               {

                        $thisUser.isCriticalSystemObject = $userObject.isCriticalSystemObject

                    }

                   

                    # Protected From Accidental Deletion

                    if ( ($thisUser | Get-adobject -properties ProtectedFromAccidentalDeletion  -server $PDC | Select-object ProtectedFromAccidentalDeletion) -eq $true )

                    {

                        $thisUser | Set-adobject -ProtectedFromAccidentalDeletion $userObject.ProtectedFromAccidentalDeletion

                    }

 

                    # Description

                    if ($userObject.Description -ne $thisUser.Description)

                    {

                        $thisUser.Description = $userObject.Description

                    }

 

                    # Display Name

                    if ($userObject.DisplayName -ne $thisUser.DisplayName)

                    {

                        $thisUser.DisplayName = $userObject.DisplayName

                    }

 

                    # Enabled

                    if ($userObject.enabledOld -eq $true)

                    {

                        $thisUser.enabled = $userObject.Enabled

                    }

 

                    # apply these changes

                    Set-ADUser -Instance $thisUser

                    $thisUser = Get-RenewedData -Account $userAccount -Pdc $PDC

 

                     # Renaming of user

                    $thisUser | Rename-ADObject -NewName ($userObject.Name)

 

                    $done += $userObject

                    "$element done" | Set-Log

                }

                catch

                {

                    "$element in error" | Set-Log -severity Warning

                    $upderrors += [Issue]::New($userAccount)

                }

            }

            else

            {

                "Changes already applied to user"  | Set-Log

                $done += $userAccount

            }

            $andNow = Get-RenewedData -Account $userAccount -Pdc $PDC

            $userObject.ProtectedFromAccidentalDeletion = ($andNow | Get-adobject -properties ProtectedFromAccidentalDeletion -server $PDC | Select-object ProtectedFromAccidentalDeletion)

            $attempt = 2

            Do

            {

                $andNow | Set-adobject -ProtectedFromAccidentalDeletion $false

                $userObject.ProtectedFromAccidentalDeletion = ($andNow | Get-adobject -properties ProtectedFromAccidentalDeletion  -server $PDC | Select-object -ExpandProperty ProtectedFromAccidentalDeletion)

                $attempt--

            } until ($userObject.ProtectedFromAccidentalDeletion -eq $false -or $attempt -eq 0)

            $userObject.check((Get-RenewedData -Account $userAccount -Pdc $PDC))

        }

        else

        {

            "$element not found" | Set-Log -severity Error

            $notDone += [Issue]::New($userAccount)

        }

        $counter++

    }

    $howManyDone = ( $done | Measure-Object ).Count

    $howManyNot  = ( $notDone | Measure-Object ).Count

    $howManyErr  = ( $upderrors | Measure-Object ).Count

 

    "$counter have been done" | Set-Log -severity Success

    if ($counter -gt 0)

    {

        $Param4CSV.path = "$($Paths.Results)\" + $dateStamped + "." + $domainInfo.DNSRoot + $scriptName + "Done.csv"

        $done | Export-Csv @Param4CSV

        "User(s) done exported to: $($Param4CSV.path)" | Set-Log

    }

 

    "$howManyErr have encountered an error" | Set-Log -severity Warning

    if ($howManyErr -gt 0)

    {

        $Param4CSV.path = "$($Paths.Results)\" + $dateStamped + "." + $domainInfo.DNSRoot + $scriptName + "In.Error.csv"

        $upderrors | Export-Csv @Param4CSV

        "User(s) with errors exported to: $($Param4CSV.path)" | Set-Log

    }

 

    "$howManyNot have not been done" | Set-Log -severity Error

    if ($howManyNot -gt 0)

    {

        $Param4CSV.path = "$($Paths.Results)\" + $dateStamped + "." + $domainInfo.DNSRoot + $scriptName + "Not.Done.csv"

        $notdone | Export-Csv @Param4CSV

        "Not done user(s) exported to: $($Param4CSV.path)" | Set-Log

    }

 

    "Last check: Done ($howManyDone) + With Error($howManyErr) + Not Done ($howManyNot) = $($howManyDone + $howManyErr + $howManyNot)." | Set-Log

    "If this equal to $howMany then everything as been treated" | Set-Log

#endregion

#region End

 

    #region Final

 

        $Timer.Stop()

 

        $runTime = "$($Timer.Elapsed)"

 

        "Script Runtime full: $runtime" | Set-Log

 

        "The End." | Set-Log

 

        # Stops log

        Stop-Transcript | Set-Log

 

        # Restore location

        Pop-Location

 

    #endregion

 

#endregion

