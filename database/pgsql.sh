sed \
	-e 's/@PRELOAD@/SET CONSTRAINTS ALL DEFERRED;/' \
	-e 's/@POSTLOAD@//' \
	-e 's/@CREATE_TABLE_SUFFIX@//' \
	-e 's/@SERIAL_TYPE@/SERIAL/' \
	-e 's/@BIG_INTEGER@/INT8/' \
	-e 's/@SERIAL_REF_TYPE@/INT8/'
