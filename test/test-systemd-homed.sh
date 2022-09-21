#!/bin/bash

set -ex

if true; then

    sudo homectl deactivate-all || :
    sudo homectl remove testuser || :

    sudo rm -rf /run/cryptsetup /var/lib/systemd/home /run/systemd/home /run/systemd/user-home-mount

    sudo systemctl restart systemd-homed
    sudo restorecon -nvR /run /var/lib/systemd /usr/lib/systemd

    echo "OK> "
    read

fi

sudo homectl deactivate-all || :
sudo homectl remove testuser || :
sudo homectl list
sudo homectl create testuser --real-name="Test User" --disk-size=1G --fs-type=btrfs --storage=luks  --timezone=Europe/Helsinki --language=fi_FI.utf8
# This is missing from homectl create actions so filesystem has only unlabeled_t
sudo homectl with testuser -- restorecon -vFR /home/testuser
sudo homectl list

sudo homectl with testuser -- bash -c 'ls -laZ;id -a;iostat;restorecon -nvR /run /var/lib/systemd /usr/lib/systemd; grep /run /proc/mounts'

sudo homectl activate testuser

echo "Login and then test> "
read

sudo homectl inspect testuser
ls -laZ /home/testuser.home
sudo homectl resize testuser 1100M
sudo homectl update testuser || :
ls -laZ /home/testuser.home
sudo homectl inspect testuser

sudo homectl deactivate-all

sudo homectl activate testuser
sudo homectl inspect testuser

sudo homectl lock testuser
sudo homectl unlock testuser

sudo homectl lock-all
sudo homectl unlock testuser || :

sudo homectl deactivate-all

sudo homectl remove testuser

if true; then

    echo "OK> "
    read

    # for s in luks fscrypt directory subvolume cifs; do
    for s in luks directory subvolume; do
        for f in xfs ext4 btrfs; do
            sudo homectl create testuser --real-name="Test User" --disk-size=1G --fs-type="$f" --storage="$s"  --timezone=Europe/Helsinki --language=fi_FI.utf8
            # This is missing from homectl create actions so filesystem has only unlabeled_t
            sudo homectl with testuser -- restorecon -vFR /home/testuser
            sudo homectl remove testuser
        done
    done

fi
