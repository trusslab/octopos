if [[ ${PETALINUX_PRODUCTS} == ${OCTOPOS_DIR}* ]]; then
	echo "PETALINUX_PRODUCTS is local"
else
	cp -r ${PETALINUX_PRODUCTS%/} ${OCTOPOS_DIR}/bin/
	echo "Copying PETALINUX_PRODUCTS to local"
fi

