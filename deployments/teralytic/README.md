# Teralytic Backend Services

The default teralytic backend is SQL (PostgreSQL). This docker-compose script will start the postgres server
and initialize the database.

This should be run from the workspace root.

```bash
> docker-compose -f ./deployments/teralytic/docker-compose.yml up
```
