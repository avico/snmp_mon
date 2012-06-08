USE snmp;
CREATE TABLE alist (
   datetime	timestamp DEFAULT current_timestamp, 
   target	varchar(60),
   problem	varchar(60),
   trap		varchar(100),
   varbinds	text
); 
