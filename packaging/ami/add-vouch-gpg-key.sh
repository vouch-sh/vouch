#!/bin/bash
# Add the Vouch public key to the kiwi build repository

repo_file=$1
echo "gpgkey=https://packages.vouch.sh/gpg/vouch.asc" >> ${repo_file}
