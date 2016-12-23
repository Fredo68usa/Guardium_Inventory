-- DROP DATABASE staps;
---DROP DATABASE GUARDIUM_INVENTORY;

-- CREATE DATABASE staps;
---CREATE DATABASE GUARDIUM_INVENTORY;
USE GUARDIUM_INVENTORY;
Select "-----START ----" from dual;

-- =============================
-- LOCATIONS
-- =============================
DROP TABLE LOCATIONS;

CREATE TABLE LOCATIONS 
(
LOCATION 	CHAR(16),
LOC_CODE	CHAR(2)	
);


ALTER TABLE LOCATIONS ADD CONSTRAINT PRIMARY KEY (LOC_CODE);
INSERT INTO LOCATIONS VALUES ('CDC1','1');
INSERT INTO LOCATIONS VALUES ('CDC2','2');

select "LOCATIONS Created" from dual;

select * from LOCATIONS;

-- =============================
-- CM
-- =============================
DROP TABLE CM;

CREATE TABLE CM
(
CM_IP  		CHAR(16),
LOC_CODE	CHAR(2),
STATE		CHAR(2)	/* (P)lanned, (D)eployed*/
);

ALTER TABLE CM ADD CONSTRAINT PRIMARY KEY (CM_IP);
INSERT INTO CM  VALUES ('CM1','1','P');

select "CM Created" from dual;
select * from CM;

-- =============================
-- AGGREGATORS
-- =============================
DROP TABLE AGGREGATORS;

CREATE TABLE AGGREGATORS
(
AGG_IP  	CHAR(16),
LOC_CODE	CHAR(2),
STATE		CHAR(2),	/* (P)lanned, (D)eployed*/
CM_IP  		CHAR(16)
);

ALTER TABLE AGGREGATORS ADD CONSTRAINT PRIMARY KEY (AGG_IP);
ALTER TABLE AGGREGATORS ADD CONSTRAINT FOREIGN KEY (LOC_CODE) REFERENCES LOCATIONS (LOC_CODE);
INSERT INTO AGGREGATORS VALUES ('AGG1','1','P','CM1');
INSERT INTO AGGREGATORS VALUES ('AGG2','2','P','CM1');

select "AGGREGATORS Created" from dual;
select * from AGGREGATORS;
-- =============================
-- COLLECTORS
-- =============================
DROP TABLE COLLECTORS;

CREATE TABLE COLLECTORS
(
COLL_IP  	CHAR(16),
LOC_CODE	CHAR(2),
STATE		CHAR(2),	/* (P)lanned, (D)eployed*/
TZ		CHAR(4),
AGG_IP  	CHAR(16)
);

ALTER TABLE COLLECTORS ADD CONSTRAINT PRIMARY KEY (COLL_IP);
ALTER TABLE COLLECTORS ADD CONSTRAINT FOREIGN KEY (LOC_CODE) REFERENCES LOCATIONS (LOC_CODE);
INSERT INTO COLLECTORS VALUES ('COLL1','1','P','-5','AGG1');
INSERT INTO COLLECTORS VALUES ('COLL2','1','P','-5','AGG1');
INSERT INTO COLLECTORS VALUES ('COLL3','1','P','-5','AGG1');
INSERT INTO COLLECTORS VALUES ('COLL4','2','P','-6','AGG2');

select "COLLECTORS Created" from dual;
select * from COLLECTORS;
-- =================================
-- STAPS
-- =================================
DROP TABLE STAPS;

CREATE TABLE STAPS
(
STAP_NAME	CHAR(128), 	-- Can be either a FQDN or an IP
STAP_OS		CHAR(16),	-- U: unix, W: windows, L: linux
STAP_OS_TYPE	CHAR(16),	-- Solaris etc....
STAP_VERSION	CHAR(32),
STATE		CHAR(2),	-- (P)lanned, (D)eployed
LOC_CODE	CHAR(2),
INSTALL_DATE	DATE,
TZ		CHAR(4),
PVU		INT
);

ALTER TABLE STAPS  ADD CONSTRAINT PRIMARY KEY (STAP_NAME);
ALTER TABLE STAPS  ADD CONSTRAINT FOREIGN KEY (LOC_CODE) REFERENCES LOCATIONS (LOC_CODE);
-- INSERT INTO STAPS  VALUES ('STAP1','U','Solaris','10','P',DATE(365),250);
INSERT INTO STAPS  VALUES ('STAP1','U','Solaris','10','P','1',DATE(NOW()),'-5',250);
INSERT INTO STAPS  VALUES ('STAP2','U','Solaris','10','P','1',DATE(NOW()),'-5',250);
INSERT INTO STAPS  VALUES ('STAP3','U','Solaris','10','P','1',DATE(NOW()),'-5',250);
INSERT INTO STAPS  VALUES ('STAP4','U','Solaris','10','P','2',DATE(NOW()),'-5',250);
INSERT INTO STAPS  VALUES ('STAP5','U','OE','5','P','1',"2012-04-12",'-5',350);
INSERT INTO STAPS  VALUES ('STAP6','U','OE','5','P','2',"2012-04-12",'-6',350);
INSERT INTO STAPS  VALUES ('STAP7','U','OE','5','P','1',"2012-04-12",'-5',350);
INSERT INTO STAPS  VALUES ('STAP8','U','OE','5','P','1',"2012-04-12",'-5',350);

select "STAPs Created" from dual;
select * from STAPS;
-- =================================
-- COLLS STAPS PAIRING
-- =================================
DROP TABLE PAIRING_STAP_COLL;

CREATE TABLE PAIRING_STAP_COLL
(
STAP_NAME 	CHAR(128), 	-- Can be either a FQDN or an IP
COLL_IP		CHAR(16),
USE_TYPE	CHAR(2),	-- (PR)rimary, (FO) Fail over, (LB) Load Balancing
STATE		CHAR(2)		-- (P)lanned, (D)eployed
);
ALTER TABLE PAIRING_STAP_COLL ADD CONSTRAINT PRIMARY KEY (STAP_NAME,COLL_IP);
ALTER TABLE PAIRING_STAP_COLL ADD CONSTRAINT FOREIGN KEY (STAP_NAME) REFERENCES STAPS (STAP_NAME);
ALTER TABLE PAIRING_STAP_COLL ADD CONSTRAINT FOREIGN KEY (COLL_IP) REFERENCES COLLECTORS (COLL_IP);

-- INSERT INTO PAIRING_STAP_COLL VALUES ('STAP1','COLL1','PR', 'P');
-- INSERT INTO PAIRING_STAP_COLL VALUES ('STAP2','COLL2','PR', 'P');
-- INSERT INTO PAIRING_STAP_COLL VALUES ('STAP3','COLL3','PR', 'P');
-- INSERT INTO PAIRING_STAP_COLL VALUES ('STAP4','COLL4','PR', 'P');
-- INSERT INTO PAIRING_STAP_COLL VALUES ('STAP5','COLL1','FO', 'P');
-- INSERT INTO PAIRING_STAP_COLL VALUES ('STAP6','COLL2','PR', 'P');
-- INSERT INTO PAIRING_STAP_COLL VALUES ('STAP7','COLL3','PR', 'P');
-- INSERT INTO PAIRING_STAP_COLL VALUES ('STAP8','COLL4','PR', 'P');

select "PAIRING_STAP_COLL Created" from dual;
select * from PAIRING_STAP_COLL;

-- =================================
-- DB Instances
-- =================================
DROP TABLE DBASES;
CREATE TABLE DBASES
(
CLUSTER_VIP CHAR(128), 	-- Can be either a FQDN or an IP
DBASE    CHAR(128), 	-- Whatever name the databases are known under
DBASE_TYPE    CHAR(16) 	-- DB Type
);
ALTER TABLE DBASES ADD CONSTRAINT PRIMARY KEY (CLUSTER_VIP);
INSERT INTO DBASES VALUES ('CLUSTER_VIP_1','DATABASE1','ORACLE');
INSERT INTO DBASES VALUES ('CLUSTER_VIP_2','DATABASE2','DB2');
INSERT INTO DBASES VALUES ('CLUSTER_VIP_3','DATABASE3','MSSQL');

select "DBASES" from dual;
select * from  DBASES;

-- =================================
-- PAIRING DBInstance / STAP
-- =================================
DROP TABLE PAIRING_DBASE_STAP;
CREATE TABLE PAIRING_DBASE_STAP
(
DBASE    CHAR(128), 	-- Whatever name the databases are known under
SERVER_NAME CHAR(128) 	-- Can be either a FQDN or an IP
);
ALTER TABLE PAIRING_DBASE_STAP ADD CONSTRAINT FOREIGN KEY (SERVER_NAME) REFERENCES STAPS (STAP_NAME);
ALTER TABLE PAIRING_DBASE_STAP ADD CONSTRAINT FOREIGN KEY (DBASE) REFERENCES DBASES(DBASE);

INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE1','STAP1');INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE1','STAP2');
INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE1','STAP3');
INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE1','STAP4');

INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE2','STAP4');INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE2','STAP6');
INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE2','STAP7');
INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE2','STAP8');

INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE3','STAP2');INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE3','STAP4');INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE3','STAP6');INSERT INTO PAIRING_DBASE_STAP VALUES ('DATABASE3','STAP8');
select "PAIRING_DBASE_STAP" from dual;
select * from  PAIRING_DBASE_STAP;
-- ======================================
--	STAGING TABLES and UPLOADING
-- ======================================

DROP TABLE ENT_STAP_VIEW;
CREATE TABLE ENT_STAP_VIEW
(
STAP			CHAR(16), 	-- Whatever name the databases are known under
PRIMARY_COLL		CHAR(16), 	-- Can be either a FQDN or an IP
CURRENT_COLL		CHAR(16), 	-- Can be either a FQDN or an IP
STATUS			CHAR(2),	-- Active, Inactive, Synchronizing
STAP_VERSION		CHAR(2),	-- Active, Inactive, Synchronizing
TIME_STAMP		CHAR(2)	-- Active, Inactive, Synchronizing

);
-- LOAD FROM 'test.txt' INSERT INTO STAGINGTABLE;

-- =================================
-- IE WINDOWS (MS SQL)
-- =================================

DROP TABLE IE_MS_SQL;
CREATE TABLE IE_MS_SQL
(
DBASE		CHAR(128), 	
TCP_PORT_LOW	INT,
TCP_PORT_HIGH	INT,
PROCESS_NAME	CHAR(128), 	-- Is the Executable actually
INSTANCE_NAME	CHAR(64),
NAMED_PIPE		BOOLEAN
);

ALTER TABLE IE_MS_SQL ADD CONSTRAINT FOREIGN KEY (DBASE) REFERENCES DBASES (DBASE);
INSERT INTO IE_MS_SQL VALUES ('DB0',1433,1435,'SQLSVR.EXE','','t');

select * from IE_MS_SQL;
-- =================================
-- IE WINDOWS (ORACLE)
-- =================================
DROP TABLE IE_MS_ORACLE;
CREATE TABLE IE_MS_ORACLE
(
DBASE		CHAR(128), 	
TCP_PORT_LOW	INT,
TCP_PORT_HIGH	INT,
PROCESS_NAME	CHAR(128), 	-- Is the Executable actually
INSTANCE_NAME	CHAR(64),
NAMED_PIPE		BOOLEAN
);

ALTER TABLE IE_MS_ORACLE ADD CONSTRAINT FOREIGN KEY (DBASE) REFERENCES DBASES (DBASE);
INSERT INTO IE_MS_ORACLE VALUES ('DB1',1433,1435,'ORA.EXE','','t');

select * from IE_MS_ORACLE;
-- =================================
-- IE ORACLE NIX
-- =================================
DROP TABLE IE_ORACLE_NIX;
CREATE TABLE IE_ORACLE_NIX
(
DBASE		CHAR(128), 	
TCP_PORT_LOW	INT,
TCP_PORT_HIGH	INT,
DB_INSTALL_DIR	CHAR(128), 	
PROCESS_NAME	CHAR(128) 	-- Is the Executable actually
);

ALTER TABLE IE_ORACLE_NIX ADD CONSTRAINT FOREIGN KEY (DBASE) REFERENCES DBASES (DBASE);
INSERT INTO IE_ORACLE_NIX VALUES ('DB2',1433,1435,"/usr/local/bin","/usr/local/bin/oracle");

select * from IE_ORACLE_NIX;
-- =================================
-- IE DB2 NIX
-- =================================
DROP TABLE IE_DB2_NIX;
CREATE TABLE IE_DB2_NIX
(
DBASE				CHAR(128), 	
TCP_PORT_LOW			INT,
TCP_PORT_HIGH			INT,
DB_INSTALL_DIR			CHAR(128), 	
PROCESS_NAME			CHAR(128), 	-- Is the Executable actually
PACKET_HEADER_SIZE		INT, 		-- Shared memory variables 
CLIENT_IO_AREA_OFFSET		INT, 		-- Shared memory variables 
DB2_SHARED_MEMORY		INT 		-- Shared memory variables 
);

ALTER TABLE IE_DB2_NIX ADD CONSTRAINT FOREIGN KEY (DBASE) REFERENCES DBASES (DBASE);
INSERT INTO IE_DB2_NIX VALUES ('DB3',1433,1435,'usrlocal','usrlocal',20,500,250);

select * from IE_DB2_NIX;
-- =================================
-- IE SYBASE NIX
-- =================================
DROP TABLE IE_SYBASE_NIX;
CREATE TABLE IE_SYBASE_NIX
(
DBASE	CHAR(128), 	-- Can be either a FQDN or an IP
TCP_PORT_LOW	INT,
TCP_PORT_HIGH	INT
);

ALTER TABLE IE_SYBASE_NIX ADD CONSTRAINT FOREIGN KEY (DBASE) REFERENCES DBASES (DBASE);
INSERT INTO IE_SYBASE_NIX VALUES ('DB4',1433,1435);

select * from IE_SYBASE_NIX;
-- =================================
-- IE INFORMIX NIX
-- =================================
DROP TABLE IE_INFORMIX_NIX;
CREATE TABLE IE_INFORMIX_NIX
(
DBASE	CHAR(128), 	
TCP_PORT_LOW	INT,
TCP_PORT_HIGH	INT,
DB_INSTALL_DIR	CHAR(128), 	
PROCESS_NAME	CHAR(128) 	-- Is the Executable actually
);

ALTER TABLE IE_INFORMIX_NIX ADD CONSTRAINT FOREIGN KEY (DBASE) REFERENCES DBASES (DBASE);
INSERT INTO IE_INFORMIX_NIX VALUES ('DB5',1433,1435,"/usr/local/bin","/usr/local/bin/informix");

select * from IE_INFORMIX_NIX;

-- =======================================
--  Daily imports per Coll and Aggs 
-- =======================================
DROP TABLE DAILY_IMPORTS;
CREATE TABLE DAILY_IMPORTS
(
AGG		CHAR(128), 	
COLL		CHAR(128), 	
DAY_NBR		INT,
DAY_OF_DATA	DATE,
WEEK_NBR	INT,
MONTH_NBR	INT,
AMOUNT_IN_MG	INT
);

ALTER TABLE DAILY_IMPORTS ADD CONSTRAINT FOREIGN KEY (COLL) REFERENCES COLLECTORS(COLL_IP);
-- ==============================================
--  MySQL Disk Usage (Agg only) & VAR Disk Usage
-- ==============================================
DROP TABLE DISK_USAGE;
CREATE TABLE DISK_USAGE
(
AGG			CHAR(128), 	
DATE_HOUR		DATE,
MYSQL_DISK_USAGE	INT,
VAR_DISK_USAGE		INT
);

-- =======================================
--  Daily Sniffer Perf 
-- =======================================
DROP TABLE SNIF_PERFS;
CREATE TABLE SNIF_PERFS
(
COLL		CHAR(128), 	
SNIF_PID	INT, 	
START_TIME	DATE,
END_TIME	DATE,
SNIF_MEM_MAX	INT, 	
ANA_RATE_MIN	INT, 	
ANA_RATE_AVG	FLOAT, 	
ANA_RATE_MAX	INT, 	
ANA_QUE_MIN	INT, 	
ANA_QUE_AVG	FLOAT, 	
ANA_QUE_MAX	INT, 	
LOG_RATE_MIN	INT, 	
LOG_RATE_AVG	FLOAT, 	
LOG_RATE_MAX	INT, 	
LOG_QUE_MIN	INT, 	
LOG_QUE_AVG	FLOAT, 	
LOG_QUE_MAX	INT,
CPU_LOAD_MIN	INT, 	
CPU_LOAD_AVG	FLOAT, 	
CPU_LOAD_MAX	INT, 	
LOG_FILE_MIN	INT, 	
LOG_FILE_AVG	FLOAT, 	
LOG_FILE_MAX	INT
); 	

-- =======================================
--  Audit Process Report 
-- =======================================
DROP TABLE APL_SUMMARY;
CREATE TABLE APL_SUMMARY
(
AGG		CHAR(128), 	
AUDIT_ID	INT, 	
AUDIT_NAME	CHAR(128), 	
TASK_ID		INT, 	
TASK_NAME	CHAR(128), 	
START_TIME	DATE,
END_TIME	DATE,
DURATION	DATE
);


-- =======================================
--  Traffic Volume Analysis
-- =======================================
DROP TABLE TRAFFIC_VOLUME;
CREATE TABLE TRAFFIC_VOLUME
(
AGG			CHAR(128), 	
DAY_OF_DATA		DATE,
WEEK_NBR		INT,
MONTH_NBR		INT,
SESSION_ID_COUNT	INT, 	
INSTANCE_ID_COUNT	INT, 	
CONSTRUCT_ID_COUNT	INT, 	
TOTAL_ACCESS		INT
); 	


-- =======================================
--  Traffic Component Analysis
-- =======================================
DROP TABLE TRAFFIC_COMPONENT;
CREATE TABLE TRAFFIC_COMPONENT
(
AGG			CHAR(128), 	
DAY_OF_DATA		DATE,
WEEK_NBR		INT,
MONTH_NBR		INT,
SERVER_IP		CHAR(128), 	
CLIENT_IP_COUNT		INT, 	
DB_USER			CHAR(128), 	
SERVICE_NAME		CHAR(128), 	
SOURCE_PROGRAM		CHAR(128), 	
OBJECT_COUNT		INT, 	
COMMAND_COUNT		INT, 	
TOTAL_ACCESS		INT
); 	


-- =======================================
--  STAP COLL Association
-- =======================================
DROP TABLE STAP_COLL_ASSOC;
CREATE TABLE STAP_COLL_ASSOC
(
COLL		CHAR(128), 	
STAP		CHAR(128), 	-- Whatever name the databases are known under
START_TIME	DATE,
END_TIME	DATE
);


select * from STAP_COLL_ASSOC;

-- =============
--  STAP Events
-- =============
DROP TABLE STAP_EVENTS;
CREATE TABLE STAP_EVENTS
(
STAP		CHAR(128), 	-- 
TIME_STAMP	DATE,
EVENT_TYPE	CHAR(32), 	-- 
STAP_MSG	TEXT(256) 	-- 
);

-- =======================================
--  Verification of Colocation - STAP/Coll
-- =======================================


-- ===========================================
--  Verification of Cluster/Agg consistency
-- ===========================================


-- ===========================================
--  Verification of DB Instance/STAP consistency
-- ===========================================


