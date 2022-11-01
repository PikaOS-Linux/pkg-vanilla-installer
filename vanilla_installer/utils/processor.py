# processor.py
#
# Copyright 2022 mirkobrombin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundationat version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import logging
import tempfile
import subprocess


logger = logging.getLogger("Installer::Processor")


class Processor:

    @staticmethod
    def gen_install_script(log_path, pre_run, post_run, finals):
        logger.info("processing the following final data: %s", finals)

        #manifest_remove = "/cdrom/casper/filesystem.manifest-remove"
        #if not os.path.exists(manifest_remove):
        manifest_remove = "/tmp/filesystem.manifest-remove"
        open(manifest_remove, "w").close()

        arguments = [
            "sudo", "distinst",
            "-s", "'/cdrom/casper/filesystem.squashfs'",
            "-r", f"'{manifest_remove}'",
            "-h", "'vanilla'",
        ]

        for final in finals:
            for key, value in final.items():
                if key == "users":
                    arguments = ["echo", f"'{value['password']}'", "|"] + arguments
                    arguments += ["--username", f"'{value['username']}'"]
                    arguments += ["--realname", f"'{value['fullname']}'"]
                    arguments += ["--profile_icon", "'/usr/share/pixmaps/faces/yellow-rose.jpg'"]
                elif key == "timezone":
                    arguments += ["--tz", "'{}/{}'".format(value["region"], value["zone"])]
                elif key == "language":
                    arguments += ["-l", f"'{value}'"]
                elif key == "keyboard":
                    arguments += ["-k", f"'{value}'"]
                elif key == "disk":
                    if "auto" in value:
                        arguments += ["-b", f"'{value['auto']['disk']}'"]
                        arguments += ["-t", "'{}:gpt'".format(value["auto"]["disk"])]
                        arguments += ["-n", "'{}:primary:start:512M:fat32:mount=/boot/efi:flags=esp'".format(value["auto"]["disk"])]
                        arguments += ["-n", "'{}:primary:512M:1024M:ext4:mount=/boot'".format(value["auto"]["disk"])]
                        arguments += ["-n", "'{}:primary:1536M:-4096M:btrfs:mount=/'".format(value["auto"]["disk"])]
                        arguments += ["-n", "'{}:primary:-4096M:end:swap'".format(value["auto"]["disk"])]
                    else:
                        for partition, values in value.items():
                            if partition == "disk":
                                arguments += ["-b", f"'{values}'"]
                                arguments += ["-t", "'{}:gpt'".format(values)]
                                continue
                            if values["mp"] == "/":
                                arguments += ["-n", "'{}:primary:start:-{}M:btrfs:mount=/'".format(partition, values["size"])]
                            elif values["mp"] == "/boot/efi":
                                arguments += ["-n", "'{}:primary:start:512M:fat32:mount=/boot/efi:flags=esp'".format(partition)]
                            elif values["mp"] == "swap":
                                arguments += ["-n", "'{}:primary:-{}M:end:swap'".format(partition, values["size"])]
                            else:
                                arguments += ["-n", "'{}:primary:-{}M:end:{}:mount={}'".format(partition, values["size"], values["fs"], values["mp"])]
        
        # generating a temporary file to store the distinst command and
        # arguments parsed from the final data
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("#!/bin/sh\n")
            f.write("# This file was created by the Vanilla Installer.\n")
            f.write("# Do not edit this file manually!\n\n")
            f.write("set -e -x\n\n")

            if "VANILLA_FAKE" in os.environ:
                logger.info("VANILLA_FAKE is set, skipping the installation process.")
                f.write("echo 'VANILLA_FAKE is set, skipping the installation process.'\n")
                f.write("echo 'Printing the configuration instead:'\n")
                f.write("echo '----------------------------------'\n")
                f.write('echo "{}"\n'.format(finals))
                f.write("echo '----------------------------------'\n")
                f.write("sleep 1000\n")
            else:
                for arg in arguments:
                    f.write(arg + " ")

            f.flush()
            f.close()

            # setting the file executable
            os.chmod(f.name, 0o755)
                
            return f.name
