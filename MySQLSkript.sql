/*Script for anonymization of homer 5+ datas for future analysis*/

drop function if exists homer_data.pepper;
drop function if exists homer_data.hash_length;
drop function if exists homer_data.hash_algorithm;
drop function if exists homer_data.retype;
drop procedure if exists homer_data.Anonymize_table;
drop event if exists homer_data.anonymization;



create function homer_data.pepper() returns INTEGER NO SQL return 85219041;
create function homer_data.hash_length() returns INTEGER NO SQL return 256;
create function homer_data.retype(s varchar(128)) returns varchar(64) NO SQL return s;


drop user if exists homer_anonymized;
create user homer_anonymized identified by '123456Lucida!';

grant create temporary tables on homer_data.* to homer_anonymized;


drop procedure if exists homer_data.Anonymize_table;
delimiter //
create procedure homer_data.Anonymize_table()
begin
    declare numb_of_tables INT;
    declare f INT;
    SET @user = 'homer_anonymized';
    SET f = 0;

    select count(*) from information_schema.TABLES where TABLE_NAME like 'sip_capture_%' and TABLE_TYPE like 'BASE TABLE' INTO numb_of_tables;

  while f < numb_of_tables DO
        select TABLE_NAME from information_schema.TABLES where TABLE_NAME like 'sip_capture_%' and TABLE_TYPE like 'BASE TABLE' LIMIT f,1 INTO @tables;
        select concat('anonymized_view_',TABLE_NAME) from information_schema.TABLES where TABLE_NAME like 'sip_capture_%' and TABLE_TYPE like 'BASE TABLE' LIMIT f,1 INTO @nameOfView;

        SET @s = concat('CREATE OR REPLACE VIEW ', @nameOfView,
            concat(' AS SELECT
            id, date, micro_ts, method, reply_reason,
            IF(ruri != "",retype(SHA2(CONCAT(ruri,pepper()),hash_length())),"") as ruri,
            IF(ruri_user != "",retype(SHA2(CONCAT(ruri_user,pepper()),hash_length())),"") as ruri_user,
            IF(ruri_domain != "",retype(SHA2(CONCAT(ruri_domain,pepper()),hash_length())),"") as ruri_domain,
            IF(from_user != "",retype(SHA2(CONCAT(from_user,pepper()),hash_length())),"") as from_user,
            IF(from_domain != "",retype(SHA2(CONCAT(from_domain,pepper()),hash_length())),"") as from_domain,
            from_tag,
            IF(to_user != "",retype(SHA2(CONCAT(to_user,pepper()),hash_length())),"") as to_user,
            IF(to_domain != "",retype(SHA2(CONCAT(to_domain,pepper()),hash_length())),"") as to_domain,
            to_tag,
            IF(pid_user != "",retype(SHA2(CONCAT(pid_user,pepper()),hash_length())),"") as pid_user,
            IF(contact_user != "",retype(SHA2(CONCAT(contact_user,pepper()),hash_length())),"") as contact_user,
            IF(auth_user != "",retype(SHA2(CONCAT(auth_user,pepper()),hash_length())),"") as auth_user,
            callid, callid_aleg, via_1_branch, cseq,diversion,reason,content_type,auth,
            user_agent,
            IF(source_ip != "",retype(SHA2(CONCAT(source_ip,pepper()),hash_length())),"") as source_ip,
            IF(source_port != "",retype(SHA2(CONCAT(source_port,pepper()),hash_length())),"") as source_port,
            IF(destination_ip != "",retype(SHA2(CONCAT(destination_ip,pepper()),hash_length())),"") as destination_ip,
            IF(destination_port != "",retype(SHA2(CONCAT(destination_port,pepper()),hash_length())),"") as destination_port,
            IF(contact_ip != "",retype(SHA2(CONCAT(contact_ip,pepper()),hash_length())),"") as contact_ip,
            IF(contact_port != "",retype(SHA2(CONCAT(contact_port,pepper()),hash_length())),"") as contact_port,
            IF(originator_ip != "",retype(SHA2(CONCAT(originator_ip,pepper()),hash_length())),"") as originator_ip,
            IF(originator_port != "",retype(SHA2(CONCAT(originator_port,pepper()),hash_length())),"") as originator_port,
            correlation_id, proto,family, rtp_stat, type,node
            FROM '),
            concat(@tables,';'));
        PREPARE anonymize FROM @s;
        EXECUTE anonymize;
        DEALLOCATE PREPARE anonymize;


        SET @query = CONCAT('GRANT SELECT ON ',CONCAT(@nameOfView,' TO '), @user);
        PREPARE stmt FROM @query;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;

        SET f = f + 1;
    END while;
end //
delimiter ;

call Anonymize_table();

SET GLOBAL event_scheduler = 1;

CREATE EVENT homer_data.anonymization
ON SCHEDULE
    EVERY 1 DAY
    STARTS (TIMESTAMP(CURRENT_DATE) + INTERVAL 1 DAY + INTERVAL 1 HOUR)
ON COMPLETION NOT PRESERVE
  DO call homer_data.Anonymize_table();
