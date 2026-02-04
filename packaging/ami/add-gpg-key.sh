#!/bin/bash
# KIWI-NG repository customization script
# Adds GPG key configuration for Amazon Linux 2023 repository

repo_file=$1
echo "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-amazon-linux-2023" >> "${repo_file}"
