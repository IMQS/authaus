-- all users
select * from authuserstore
where username ilike '%laiqa%'
limit 10

-- all users
SELECT userid FROM authuserstore WHERE (LOWER(email) = LOWER('Laiqa.Callaghan@westerncape.gov.za')
    OR LOWER(username) = lower('Laiqa.Callaghan@westerncape.gov.za'))
                                   AND (archived = false OR archived IS NULL)

-- authsession, oauthsession
select aus.id, sessionkey, expires, userid, oas.id, oas.created, oas.updated, token->>'expires_in' from authsession aus
    left join oauthsession oas on oas.id = aus.oauthid
where userid in (96,1049)
order by expires desc
limit 10
-- update authsession set expires = '2023-07-27 18:24:41.794828' where userid = 96
-- update oauthsession set expires = '2023-07-27 06:18:09.142898' where id = 12889

-- oauthsession, authsession, authuserstore 
select * from oauthsession
                  left join authsession on oauthsession.id = authsession.oauthid
                  left join authuserstore aus on aus.userid = authsession.userid
where
        authsession.userid = 96
-- authsession.userid = 1049 
-- and 
-- authsession.oauthid ilike 'rKWilB%'
-- order by 
order by expires desc
-- limit 10
-- select * from authsession
-- select * from authsession
-- order by expires desc
-- where
-- sessionkey = 'zyvAPZfMfbqPCCVa5alSsgnZlHma6G'

-- oauthsession
select * from oauthsession
-- left join authuserstore aus on aus.sessionkey = authuserstore
where id = 'iX6ThdqkIdaCWR3Lfbws66d0MosNzW'
limit 10

-- authuserpwd
select * from authuserpwd --where permit is not null and permit != ''
where userid in (0,96,859,1049)
order by updated desc

-- authuserstore, authuserpwd
select *
FROM authuserstore aus LEFT JOIN authuserpwd pwd ON aus.userid = pwd.userid
WHERE --(LOWER(aus.email) = 'laiqa.callaghan@westerncape.gov.za' ) OR 
      LOWER(aus.lastname) ilike '%callag%' --'.callaghan@westerncape.gov.za') AND (aus.archived = false OR aus.archived IS NULL)


