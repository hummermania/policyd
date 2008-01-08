sed \
	-e 's/@PRELOAD@//' \
	-e 's/@POSTLOAD@//' \
	-e 's/@CREATE_TABLE_SUFFIX@//' \
	-e 's/@SERIAL_TYPE@/INTEGER PRIMARY KEY AUTOINCREMENT/' \
	-e 's/@BIG_INTEGER@/INT8/' \
	-e 's/@SERIAL_REF_TYPE@/INT8/'
