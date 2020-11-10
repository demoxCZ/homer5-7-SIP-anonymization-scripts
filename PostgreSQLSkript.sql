/*Script for anonymization of homer 7+ datas for future analysis*/


CREATE EXTENSION if not exists pgcrypto;
CREATE EXTENSION if not exists pgagent;

create or replace function pepper() returns integer as 'select 842173::integer' language SQL;
create or replace function hash_algorithm() returns text as $$select 'sha256'::text$$ language SQL;
create or replace function encode_type() returns text as $$select 'hex'::text$$  language SQL;
create or replace function retype(s text) returns varchar(64) as $$select s::varchar(64)$$ language SQL;


drop function if exists AnonymizeTable();
DROP USER if exists homer_anonymized;
create user homer_anonymized with password '123456Lucida!';


CREATE OR REPLACE function AnonymizeTable()
    RETURNS void AS
$BODY$
DECLARE
    numb_of_tables  integer;
    name_of_table varchar;
    name_of_view varchar;
    role varchar;
    i integer;
BEGIN
    i := 0;
    role = 'homer_anonymized';
    select count(*) from pg_catalog.pg_tables where tablename like 'sip_capture%' into numb_of_tables;
    WHILE (i < numb_of_tables)
    loop
        name_of_table := (select tablename from pg_catalog.pg_tables where tablename like 'sip_capture_%' limit 1 offset i);
        name_of_view := (select concat('anonymized_view_',tablename) from pg_catalog.pg_tables where tablename like 'sip_capture_%' limit 1 offset i);


    EXECUTE 'CREATE OR REPLACE VIEW ' ||
            name_of_view  || ' AS SELECT ' ||
            'id, date, micro_ts, reply_reason,
            case ruri when '''' then '''' else retype(encode(digest(CONCAT(ruri,pepper()),hash_algorithm()),encode_type())) end as ruri,
            case ruri_user when '''' then '''' else retype(encode(digest(CONCAT(ruri_user,pepper()),hash_algorithm()),encode_type())) end as ruri_user,
            case ruri_domain when '''' then '''' else retype(encode(digest(CONCAT(ruri_domain,pepper()),hash_algorithm()),encode_type())) end as ruri_domain,
            case from_user when '''' then '''' else retype(encode(digest(CONCAT(from_user,pepper()),hash_algorithm()),encode_type())) end as from_user,
            case from_domain when '''' then '''' else retype(encode(digest(CONCAT(from_domain,pepper()),hash_algorithm()),encode_type())) end as from_domain,
            from_tag,
            case from_user when '''' then '''' else retype(encode(digest(CONCAT(to_user,pepper()),hash_algorithm()),encode_type())) end as to_user,
            case to_domain when '''' then '''' else retype(encode(digest(CONCAT(to_domain,pepper()),hash_algorithm()),encode_type())) end as to_domain,
            to_tag,
            case pid_user when '''' then '''' else retype(encode(digest(CONCAT(pid_user,pepper()),hash_algorithm()),encode_type())) end as pid_user,
            case contact_user when '''' then '''' else retype(encode(digest(CONCAT(contact_user,pepper()),hash_algorithm()),encode_type())) end as contact_user,
            case auth_user when '''' then '''' else retype(encode(digest(CONCAT(auth_user,pepper()),hash_algorithm()),encode_type())) end as auth_user,
            callid, callid_aleg, via_1_branch, cseq, diversion, reason, content_type, auth, user_agent,
            case source_ip when '''' then '''' else retype(encode(digest(CONCAT(source_ip,pepper()),hash_algorithm()),encode_type())) end as source_ip,
            case source_port when 0 then CAST(0 as text) else retype(encode(digest(CONCAT(source_port,pepper()),hash_algorithm()),encode_type())) end as source_port,
            case destination_ip when '''' then '''' else retype(encode(digest(CONCAT(destination_ip,pepper()),hash_algorithm()),encode_type())) end as destination_ip,
            case destination_port when 0 then CAST(0 as text) else retype(encode(digest(CONCAT(destination_port,pepper()),hash_algorithm()),encode_type())) end as destination_port,
            case contact_ip when '''' then '''' else retype(encode(digest(CONCAT(contact_ip,pepper()),hash_algorithm()),encode_type())) end as contact_ip,
            case contact_port when 0 then CAST(0 as text) else retype(encode(digest(CONCAT(contact_port,pepper()),hash_algorithm()),encode_type())) end as contact_port,
            case originator_ip when '''' then '''' else retype(encode(digest(CONCAT(originator_ip,pepper()),hash_algorithm()),encode_type())) end as originator_ip,
            case originator_port when 0 then CAST(0 as text) else retype(encode(digest(CONCAT(originator_port,pepper()),hash_algorithm()), encode_type())) end as originator_port,
            correlation_id, proto, family, rtp_stat, type ,node' ||
            ' FROM ' || name_of_table;
    EXECUTE 'grant select on ' || name_of_view || ' to ' || role;
    i = i + 1;
    end loop;
    RETURN;
  END
$BODY$
    LANGUAGE plpgsql;

select anonymizetable();

DO $$
DECLARE
    jid integer;
    scid integer;
BEGIN
-- Vytvoreni noveho jobu
INSERT INTO pgagent.pga_job(
    jobjclid, jobname, jobdesc, jobhostagent, jobenabled
) VALUES (
    1::integer, 'Anonymization_job'::text, ''::text, ''::text, true
) RETURNING jobid INTO jid;

-- Kroky
-- Vlozeni kroku (jobid: NULL)
INSERT INTO pgagent.pga_jobstep (
    jstjobid, jstname, jstenabled, jstkind,
    jstconnstr, jstdbname, jstonerror,
    jstcode, jstdesc
) VALUES (
    jid, 'MyStep'::text, true, 's'::character(1),
    ''::text, 'postgres'::name, 'f'::character(1),
    'select anonymizetable();'::text, ''::text
) ;

-- Plan
-- Vlozeni planu
INSERT INTO pgagent.pga_schedule(
    jscjobid, jscname, jscdesc, jscenabled,
    jscstart,     jscminutes, jschours, jscweekdays, jscmonthdays, jscmonths
) VALUES (
    jid, 'MySchedule'::text, ''::text, true,
    '2020-01-01 00:00:00+02'::timestamp with time zone,
    -- Minuty
    ARRAY[true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false]::boolean[],
    -- Hodiny
    ARRAY[false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false]::boolean[],
    -- Dny v tydnu
    ARRAY[true, true, true, true, true, true, true]::boolean[],
    -- Dny v mesici
    ARRAY[true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true]::boolean[],
    -- Mesice
    ARRAY[true, true, true, true, true, true, true, true, true, true, true, true]::boolean[]
) RETURNING jscid INTO scid;
END
$$;
