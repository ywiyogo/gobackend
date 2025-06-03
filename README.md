# Modern Go Backend 
A simple backend with REST API based on Go and its standard library net/http with hot reloading.

Stack dependency:
* Go
* PostgreSQL
* Docker compose
* golang-migrate
* sqlc
* Air
* Make

Features:
* Authentication and protected endpoints
* Rate Limiter

## Getting Started

Start the backend app and the PostgreSQL database with the hot reloading. Then migrate the database schema:
```
docker compose --env-file .env up -d
migrate -path internal/db/migrations -database "postgres://${DB_USER}$:${DB_PASSWORD}@localhost:5432/${DB_NAME}$?sslmode=disable" up
```

Stop and clean the docker compose images:
```
docker compose down --rmi local -v
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

Run the test cases:
```
go test -v ./internal/auth/
```
