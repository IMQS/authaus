#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE USER unit_test_user WITH SUPERUSER PASSWORD 'unit_test_password';
EOSQL

