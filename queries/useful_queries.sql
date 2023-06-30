-- user store
select * from authuserstore aus
-- left join authuserpwd aup on aup.userid = aus.userid
-- left join authsession on authsession.userid = aus.userid
-- left join authgroup ag on ag.id = aus.userid
-- where
where email ilike '%haarhoff%' or firstname ilike '%amanda%' or lastname ilike '%haarhoff%'
    and modified >= '2023-06-29'

-- permission sets
select * from authuserpwd where userid in (1071,
                                           1500)

-- oauth
select * from oauthsession limit 10

-- authsession / oauthsession
select * from authsession
                  left join oauthsession oa on oa.id = authsession.oauthid
where userid in (1071,
                 1500)
limit 10