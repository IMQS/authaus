SELECT userid, email, username, firstname, lastname, mobile, archived, authusertype, phone, remarks, created, createdby, modified, modifiedby, externaluuid, internaluuid
	FROM public.authuserstore
-- 	where userid = 18
	where (email ilike 'jaco.vosloo@imqs.co.za' 
	or username ilike 'jaco.vosloo@imqs.co.za'
	or externaluuid = 'cb682f69-95bb-4c77-a7a4-981256c69d35')
	order by userid desc
-- 	and (archived is null or archived = false)
-- 	where 

-- update authuserstore set archived = true where userid = 18

-- select * from authuserpwd where userid = 1728