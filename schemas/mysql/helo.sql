SET SESSION table_type = 'InnoDB';

DROP TABLE IF EXISTS helo_whitelist;
CREATE TABLE helo_whitelist (
	ID			SERIAL PRIMARY KEY,
	client_address		VARCHAR(255) NOT NULL,
	comment			TINYTEXT,

	UNIQUE INDEX (client_address)
);

DROP TABLE IF EXISTS helo_tracking;
CREATE TABLE helo_tracking (
	ID			SERIAL,
	client_address		VARCHAR(255) NOT NULL,
	helo_name		VARCHAR(255) NOT NULL,
	timestamp		BIGINT UNSIGNED NOT NULL,

	UNIQUE INDEX (client_address,helo_name)
);

