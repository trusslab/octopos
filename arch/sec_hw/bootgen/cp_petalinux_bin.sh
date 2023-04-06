# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

if [[ ${PETALINUX_PRODUCTS} == ${OCTOPOS_DIR}* ]]; then
	echo "PETALINUX_PRODUCTS is local"
else
	cp -r ${PETALINUX_PRODUCTS%/} ${OCTOPOS_DIR}/bin/
	echo "Copying PETALINUX_PRODUCTS to local"
fi

