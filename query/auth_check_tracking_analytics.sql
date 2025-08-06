WITH time_buckets AS (
  SELECT
    date_trunc('minute', ts) - (extract(minute from ts)::int % 5) * interval '1 minute' AS time_bucket,
  user_id,
  COUNT(*) AS user_requests
FROM public.session_check_logs
GROUP BY time_bucket, user_id
  ),
  stats AS (
SELECT
  time_bucket,
  COUNT(*) AS unique_users,
  SUM(user_requests) AS total_requests,
  AVG(user_requests::numeric) AS mean_requests,
  STDDEV_POP(user_requests::numeric) AS stddev_requests
FROM time_buckets
GROUP BY time_bucket
  )
SELECT
  time_bucket,
  unique_users,
  total_requests,
  ROUND(mean_requests, 2) AS mean_requests,
  ROUND(stddev_requests, 2) AS stddev_requests,
  ROUND(
    CASE
      WHEN mean_requests > 0 THEN stddev_requests / mean_requests
      ELSE NULL
      END, 2
  ) AS coefficient_of_variation
FROM stats
ORDER BY time_bucket;
