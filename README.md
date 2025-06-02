# Go Backend 
A simple backend with REST API based on Go and its standard libary net/http.

Stack dependency:
* Go
* PostgreSQL
* Docker compose
* golang-migrate
* sqlc
* Air

## Getting Started

Start the backend app and the PostgreSQL database with the hot reloading. Then migrate the database schema:
```
docker compose --env-file .env up -d
migrate -path internal/db/migrations -database "postgres://${DB_USER}$:${DB_PASSWORD}@localhost:5432/${DB_NAME}$?sslmode=disable" up
```

Stop and clean the docker compose images:
```
docker compose down --rmi all -v
```

Check the database table in the docker compose:
```
docker exec -it $(docker ps --filter name=gobackend-db-1 -q) psql -U postgres -d gobackend -c "\dt"
```

Print the application logs for debugging:
```
docker compose logs
```

Start the backend app without the docker compose and database:

```
make build
make run
```
