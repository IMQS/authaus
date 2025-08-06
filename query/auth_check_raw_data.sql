SELECT *
FROM public.session_check_logs
ORDER BY
  id ASC LIMIT 100

select scl.*, aus.username, aus.email
from
  public.session_check_logs scl
-- left join authsession a on a.sessionkey = scl.session_token
    left join authuserstore aus on aus.userid = scl.user_id