CREATE TABLE accounts (
	id INTEGER PRIMARY KEY AUTO_INCREMENT ,
	login VARCHAR(64) NOT NULL UNIQUE ,
	password VARCHAR(64) NOT NULL DEFAULT '' ,
	privs BIGINT UNSIGNED NOT NULL DEFAULT 0 ,
	name VARCHAR(64) NOT NULL DEFAULT '' ,
	fileRoot VARCHAR(255) NOT NULL DEFAULT '' ,
	bytesDownloaded BIGINT UNSIGNED NOT NULL DEFAULT 0 ,
	bytesUploaded BIGINT UNSIGNED NOT NULL DEFAULT 0 ,
	lastLogin DATETIME
);

INSERT INTO accounts ( login , password , privs , name ) VALUES ( 'admin' , '25e4ee4e9229397b6b17776bfceaf8e7' , -1 , 'Administrator' );
INSERT INTO accounts ( login , password , privs , name ) VALUES ( 'guest' , 'd41d8cd98f00b204e9800998ecf8427e' , 27021597764222976 , 'Guest Account' );

CREATE TABLE news (
	id INTEGER PRIMARY KEY AUTO_INCREMENT ,
	nick VARCHAR(64) NOT NULL ,
	login VARCHAR(64) NOT NULL ,
	post TEXT NOT NULL DEFAULT '' ,
	date DATETIME
);

CREATE TABLE log (
	type INTEGER NOT NULL DEFAULT 0 ,
	login VARCHAR(64) NOT NULL DEFAULT '' ,
	nick VARCHAR(64) NOT NULL DEFAULT '' ,
	ip VARCHAR(16) NOT NULL DEFAULT '' ,
	entry TEXT NOT NULL DEFAULT '' ,
	date DATETIME
);

CREATE TABLE log_types (
	type INTEGER NOT NULL ,
	description VARCHAR(255) NOT NULL
);

INSERT INTO log_types VALUES( 1 , 'General' );	-- general server events
INSERT INTO log_types VALUES( 2 , 'Login' );	-- login related events
INSERT INTO log_types VALUES( 3 , 'Users' );	-- user related events (kicks, bans)
INSERT INTO log_types VALUES( 4 , 'Accounts' );	-- account related events
INSERT INTO log_types VALUES( 5 , 'Files' ); 	-- file related events (excluding transfers)
INSERT INTO log_types VALUES( 6 , 'Transfers' );-- transfer events (uploads, downloads)
INSERT INTO log_types VALUES( 99 , 'Errors' );	-- errors

CREATE TABLE banlist (
	address VARCHAR(32) PRIMARY KEY ,
	reason VARCHAR(255) NOT NULL DEFAULT ''
);
