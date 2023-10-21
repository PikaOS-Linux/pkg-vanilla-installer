# processor.py
#
# Copyright 2023 mirkobrombin
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

import json
import logging
import os
import re
import tempfile
from datetime import datetime
from typing import Any, Union

from vanilla_installer.core.system import Systeminfo

logger = logging.getLogger("Installer::Processor")

_REFIND_SETUP_FILE = """#!/usr/bin/bash
rm -rfv /mnt/a/boot/*arch*
touch /mnt/a/boot/refind_linux.conf
echo '"'Boot with standard options'"'  '"'nvidia-drm.modeset=1 root=UUID=$(blkid -s UUID -o value $(df /mnt/a | grep "$MOUNTPOINT\$"| cut -f1 -d" ") quiet splash ---'"'  > /mnt/a/boot/refind_linux.conf
echo '"'Boot with logging'"'  '"'nvidia-drm.modeset=1 root=UUID=$(blkid -s UUID -o value $(df /mnt/a | grep "$MOUNTPOINT\$"| cut -f1 -d" ") ---'"'  >>  /mnt/a/boot/refind_linux.conf
echo '"'Boot with safe graphics'"'  '"'nvidia-drm.modeset=1 root=UUID=$(blkid -s UUID -o value $(df /mnt/a | grep "$MOUNTPOINT\$"| cut -f1 -d" ") nomodeset ---'"'  >>  /mnt/a/boot/refind_linux.conf
"""

_CRYPTTAB_SETUP_FILE = """#!/usr/bin/bash
cat /mnt/a/etc/crypttab
echo "crypt_root	UUID={ROOT_PART_UUID}	none	luks,discard" > /mnt/a/etc/crypttab
echo "crypt_home	UUID={HOME_PART_UUID}	/keyfile.txt    	luks" >> /mnt/a/etc/crypttab
touch /mnt/a/keyfile.txt
openssl genrsa > /mnt/a/keyfile.txt
echo "{LUKS_PASSWD}" | cryptsetup luksAddKey UUID={HOME_PART_UUID}	/mnt/a/keyfile.txt -
"""

AlbiusSetupStep = dict[str, Union[str, list[Any]]]
AlbiusMountpoint = dict[str, str]
AlbiusInstallation = dict[str, str, list[str], list[str]]
AlbiusPostInstallStep = dict[str, Union[bool, str, list[Any]]]


class AlbiusRecipe:
    def __init__(self) -> None:
        self.setup: list[AlbiusSetupStep] = []
        self.mountpoints: list[AlbiusMountpoint] = []
        self.installation: AlbiusInstallation = {}
        self.postInstallation: list[AlbiusPostInstallStep] = []
        self.latePostInstallation: list[AlbiusPostInstallStep] = []

    def add_setup_step(self, disk: str, operation: str, params: list[Any]) -> None:
        self.setup.append(
            {
                "disk": disk,
                "operation": operation,
                "params": params,
            }
        )

    def add_mountpoint(self, partition: str, target: str) -> None:
        self.mountpoints.append(
            {
                "partition": partition,
                "target": target,
            }
        )

    def set_installation(self, method: str, source: str) -> None:
        self.installation = {
            "method": method,
            "source": source,
            "initramfsPre": ["echo this_is_initramfsPre"],
            "initramfsPost": ["echo this_is_initramfsPost"],
        }

    def add_postinstall_step(
        self, operation: str, params: list[Any], chroot: bool = False, late=False
    ):
        if not late:
            self.postInstallation.append(
                {
                    "chroot": chroot,
                    "operation": operation,
                    "params": params,
                }
            )
        else:
            self.latePostInstallation.append(
                {
                    "chroot": chroot,
                    "operation": operation,
                    "params": params,
                }
            )

    def merge_postinstall_steps(self):
        for step in self.latePostInstallation:
            self.postInstallation.append(step)
        del self.latePostInstallation


class Processor:
    @staticmethod
    def __gen_auto_partition_steps(
        disk: str, encrypt: bool, root_size: int, password: str | None = None
    ):
        setup_steps = []
        mountpoints = []
        post_install_steps = []

        setup_steps.append([disk, "label", ["gpt"]])

        # Boot
        setup_steps.append([disk, "mkpart", ["linux-boot", "ext4", 1, 1025]])
        if Systeminfo.is_uefi():
            setup_steps.append([disk, "mkpart", ["linux-efi", "fat32", 1025, 1537]])
            part_offset = 1537
        else:
            setup_steps.append([disk, "mkpart", ["BIOS", "fat32", 1025, 1026]])
            setup_steps.append([disk, "setflag", ["2", "bios_grub", True]])
            part_offset = 1026

        # Should we encrypt?
        if encrypt:
            fs = "luks-btrfs"
        else:
            fs = "btrfs"

        def _params(*args):
            base_params = [*args]
            if encrypt:
                assert isinstance(password, str)
                base_params.append(password)
            return base_params

        # Root
        setup_steps.append(
            [
                disk,
                "mkpart",
                _params("linux-root", fs, part_offset, part_offset + root_size),
            ]
        )
        part_offset += root_size

        # Home
        setup_steps.append([disk, "mkpart", _params("linux-home", fs, part_offset, -1)])

        # Mountpoints
        if not re.match(r"[0-9]", disk[-1]):
            part_prefix = f"{disk}"
        else:
            part_prefix = f"{disk}p"

        mountpoints.append([part_prefix + "1", "/boot"])

        if Systeminfo.is_uefi():
            mountpoints.append([part_prefix + "2", "/boot/efi"])

        mountpoints.append([part_prefix + "3", "/"])
        mountpoints.append([part_prefix + "4", "/home"])

        return setup_steps, mountpoints, post_install_steps

    @staticmethod
    def __gen_manual_partition_steps(
        disk_final: dict, encrypt: bool, password: str | None = None
    ):
        setup_steps = []
        mountpoints = []
        post_install_steps = []

        # Since manual partitioning uses GParted to handle partitions (for now),
        # we don't need to create any partitions or label disks (for now).
        # But we still need to format partitions.
        root_set = False
        for part, values in disk_final.items():
            part_disk = re.match(
                r"^/dev/[a-zA-Z]+([0-9]+[a-z][0-9]+)?", part, re.MULTILINE
            )[0]
            part_number = re.sub(r".*[a-z]([0-9]+)", r"\1", part)

            # Should we encrypt?
            if encrypt and values["mp"] in ["/", "/home"]:
                operation = "luks-format"
            else:
                operation = "format"

            def _params(*args):
                base_params = [*args]
                if encrypt and values["mp"] in ["/", "/home"]:
                    assert isinstance(password, str)
                    base_params.append(password)
                return base_params

            setup_steps.append(
                [part_disk, operation, _params(part_number, values["fs"])]
            )

            if not Systeminfo.is_uefi() and values["mp"] == "":
                setup_steps.append(
                    [part_disk, "setflag", [part_number, "bios_grub", True]]
                )

            # Set partition labels for Linux
            part_name = ""
            if values["mp"] == "/":
                part_name = "linux-root"
            elif values["mp"] == "/boot":
                part_name = "linux-boot"
            elif values["mp"] == "/boot/efi":
                part_name = "linux-efi"
            elif values["mp"] == "/home":
                part_name = "linux-home"

            setup_steps.append([part_disk, "namepart", [part_number, part_name]])

            if values["mp"] == "swap":
                post_install_steps.append(["swapon", [part], True])
            else:
                mountpoints.append([part, values["mp"]])

        return setup_steps, mountpoints, post_install_steps

    @staticmethod
    def __find_partitions(recipe):
        boot_partition = None
        efi_partition = None
        root_partition = None
        home_partition = None

        for mnt in recipe.mountpoints:
            if mnt["target"] == "/boot":
                boot_partition = mnt["partition"]
            elif mnt["target"] == "/boot/efi":
                efi_partition = mnt["partition"]
            elif mnt["target"] == "/":
                root_partition = mnt["partition"]
            elif mnt["target"] == "/home":
                home_partition = mnt["partition"]

        return (
            boot_partition,
            efi_partition,
            root_partition,
            home_partition,
        )

    @staticmethod
    def gen_install_recipe(log_path, finals, sys_recipe):
        logger.info("processing the following final data: %s", finals)

        recipe = AlbiusRecipe()

        images = sys_recipe.get("images")
        root_size = sys_recipe.get("default_root_size")
        oci_image = images["default"]
        image_method = sys_recipe.get("image_type")

        # Setup encryption if user selected it
        encrypt = False
        password = None
        for final in finals:
            if "encryption" in final.keys():
                encrypt = final["encryption"]["use_encryption"]
                password = final["encryption"]["encryption_key"] if encrypt else None

        # Setup disks and mountpoints
        for final in finals:
            if "disk" in final.keys():
                if "auto" in final["disk"].keys():
                    part_info = Processor.__gen_auto_partition_steps(
                        final["disk"]["auto"]["disk"], encrypt, root_size, password
                    )
                else:
                    part_info = Processor.__gen_manual_partition_steps(
                        final["disk"], encrypt, password
                    )

                setup_steps, mountpoints, post_install_steps = part_info
                for step in setup_steps:
                    recipe.add_setup_step(*step)
                for mount in mountpoints:
                    recipe.add_mountpoint(*mount)
                for step in post_install_steps:
                    recipe.add_postinstall_step(*step)
            elif "nvidia" in final.keys():
                if final["nvidia"]["use-proprietary"]:
                    oci_image = images["nvidia"]

        # Installation
        recipe.set_installation(image_method, oci_image)

        # Post-installation
        (
            boot_part,
            efi_part,
            root_part,
            home_part,
        ) = Processor.__find_partitions(recipe)
        boot_disk = re.match(
            r"^/dev/[a-zA-Z]+([0-9]+[a-z][0-9]+)?", boot_part, re.MULTILINE
        )[0]

        if "VANILLA_SKIP_POSTINSTALL" not in os.environ:
            # Get UUIDs of parts
            boot_part_uuid = f"$(lsblk -d -y -n -o UUID {boot_part})"
            efi_part_uuid = f"$(lsblk -d -y -n -o UUID {efi_part})"
            root_part_uuid = f"$(lsblk -d -y -n -o UUID {root_part})"
            home_part_uuid = f"$(lsblk -d -y -n -o UUID {home_part})"
            # Mount all what's in fstab
            recipe.add_postinstall_step(
                "shell",
                [
                    "mount --rbind /dev /mnt/a/dev",
                    "mount --rbind /dev/pts /mnt/a/dev/pts",
                    "mount --rbind /proc /mnt/a/proc",
                    "mount --rbind /sys /mnt/a/sys",
                    "mount --rbind /run /mnt/a/run",
                    "mkdir -p /mnt/a/var/cache/apt/archives",
                    "cp -rvf /cdrom/pool/main/* /mnt/a/var/cache/apt/archives/",
                ],
            )
            recipe.add_postinstall_step(
                "shell",
                [
                    "mount -av",
                ],
                chroot=True,
            )

            # if the system is encrypted create /etc/crypttab
            if encrypt:
                with open("/tmp/albius-crypttab.sh", "w") as file:
                    albius_crypttab_file = _CRYPTTAB_SETUP_FILE.format(
                        ROOT_PART_UUID=root_part_uuid,
                        HOME_PART_UUID=home_part_uuid,
                        LUKS_PASSWD=password,
                    )
                    file.write(albius_crypttab_file)
                recipe.add_postinstall_step(
                    "shell",
                    [
                        "chmod +x /tmp/albius-crypttab.sh",
                        "/tmp/albius-crypttab.sh",
                    ],
                    late=True,
                )

            # Create default user
            # This needs to be done after mounting `/etc` overlay, so set it as
            # late post-install
            recipe.add_postinstall_step(
                "adduser",
                [
                    "pikaos",
                    "pikaos",
                    ["sudo", "lpadmin"],
                    "pikaos",
                ],
                chroot=True,
                late=True,
            )

            # Set pikaos user to autologin
            recipe.add_postinstall_step(
                "shell",
                [
                    "mkdir -p /etc/gdm3",
                    "echo '[daemon]\nAutomaticLogin=pikaos\nAutomaticLoginEnable=True' > /etc/gdm3/daemon.conf",
                    "mkdir -p /home/pikaos/.config/dconf",
                    "chmod 700 /home/pikaos/.config/dconf",
                ],
                chroot=True,
            )

            # Make sure the pikaos user uses the first-setup session
            recipe.add_postinstall_step(
                "shell",
                [
                    "mkdir -p /var/lib/AccountsService/users",
                    "echo '[User]\nSession=firstsetup' > /var/lib/AccountsService/users/pikaos",
                ],
                chroot=True,
            )

            # Add autostart script to pika-first-setup
            recipe.add_postinstall_step(
                "shell",
                [
                    "mkdir -p /home/pikaos/.config/autostart",
                    "cp /usr/share/applications/pika-first-setup.desktop /home/pikaos/.config/autostart",
                ],
                chroot=True,
                late=True,
            )

            # Install Refind if target is UEFI, Install grub-pc if target is BIOS
            # Run `grub-install` with the boot partition as target
            if Systeminfo.is_uefi():
                with open("/tmp/albius-refind_linux.sh", "w+") as albius_refind_file:
                    albius_refind_file.write(albius_refind_file.read())

                recipe.add_postinstall_step(
                    "shell",
                    [
                        "chmod +x /tmp/albius-refind_linux.sh",
                        "/tmp/albius-refind_linux.sh",
                    ],
                    late=True,
                )
                recipe.add_postinstall_step(
                    "shell",
                    [
                        f"refind-install --usedefault {efi_part}",
                    ],
                    late=True,
                )
                recipe.add_postinstall_step(
                    "shell",
                    [
                        f"refind-install --usedefault {efi_part}",
                        "apt install -y /var/cache/apt/archives/pika-refind-theme*.deb",
                        "apt install -y /var/cache/apt/archives/booster*.deb",
                        "apt remove casper vanilla-installer -y",
                        "apt autoremove -y",
                    ],
                    late=True,
                    chroot=True,
                )

            else:
                grub_type = "bios"
                recipe.add_postinstall_step(
                    "grub-install", ["/mnt/a/boot", boot_disk, grub_type]
                )
                recipe.add_postinstall_step(
                    "grub-install", ["/boot", boot_disk, grub_type], chroot=True
                )
                # Run `grub-mkconfig` to generate files for the boot partition
                recipe.add_postinstall_step(
                    "grub-mkconfig", ["/boot/grub/grub.cfg"], chroot=True
                )

        # Set hostname
        recipe.add_postinstall_step("hostname", ["pikaos"], chroot=True)
        for final in finals:
            for key, value in final.items():
                # Set timezone
                if key == "timezone":
                    recipe.add_postinstall_step(
                        "timezone", [f"{value['region']}/{value['zone']}"], chroot=True
                    )
                # Set locale
                if key == "language":
                    recipe.add_postinstall_step("locale", [value], chroot=True)
                # Set keyboard
                if key == "keyboard":
                    recipe.add_postinstall_step(
                        "keyboard",
                        [
                            value["layout"],
                            value["model"],
                            value["variant"],
                        ],
                        chroot=True,
                    )

        # Set the default user as the owned of it's home directory
        recipe.add_postinstall_step(
            "shell",
            ["chown -R pikaos:pikaos /home/pikaos"],
            chroot=True,
            late=True,
        )

        recipe.merge_postinstall_steps()

        if "VANILLA_FAKE" in os.environ:
            logger.info(json.dumps(recipe, default=vars))
            return None

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(json.dumps(recipe, default=vars))
            f.flush()
            f.close()

            # setting the file executable
            os.chmod(f.name, 0o755)

            return f.name
