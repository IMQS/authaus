#!/bin/bash
set -e

# You'd never use these settings on a production DB, for they're useful for
# speeding up unit tests.
echo "wal_level = minimal" >> "$PGDATA/postgresql.conf"
echo "max_wal_senders = 0" >> "$PGDATA/postgresql.conf"
echo "fsync = off" >> "$PGDATA/postgresql.conf"
echo "synchronous_commit = off" >> "$PGDATA/postgresql.conf"
echo "full_page_writes = off" >> "$PGDATA/postgresql.conf"
