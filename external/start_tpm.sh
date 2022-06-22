#!/bin/sh
tpm_server &
sudo tpm2-abrmd --tcti=mssim --allow-root &
