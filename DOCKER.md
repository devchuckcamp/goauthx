# Docker Setup for goauthx

## Quick Start

### Start PostgreSQL Database

```bash
docker-compose up -d
```

This will:
- Start a PostgreSQL 16 container
- Create a database named `authdb`
- Create a user `authdb` with password `authdb`
- Expose PostgreSQL on port `5432`
- Persist data in a Docker volume

### Check Database Status

```bash
# Check if container is running
docker-compose ps

# View logs
docker-compose logs -f postgres

# Check database health
docker-compose exec postgres pg_isready -U authdb
```

### Connect to Database

```bash
# Using psql from the container
docker-compose exec postgres psql -U authdb -d authdb

# From your host machine (if you have psql installed)
psql postgres://authdb:authdb@localhost:5432/authdb
```

### Run Migrations

Once the database is running, you can run migrations:

```bash
# Build the migration tool
cd cmd/goauthx-migrate
go build

# Run migrations
./goauthx-migrate \
  --dsn "postgres://authdb:authdb@localhost:5432/authdb?sslmode=disable" \
  --driver postgres \
  up
```

Or run the example application (which includes migrations):

```bash
cd examples/basic-nethttp
go run main.go
```

### Stop Database

```bash
# Stop but keep data
docker-compose stop

# Stop and remove container (data persists in volume)
docker-compose down

# Stop, remove container, and delete data
docker-compose down -v
```

## Database Connection String

The connection string for your application:

```
postgres://authdb:authdb@localhost:5432/authdb?sslmode=disable
```

## Docker Commands Reference

```bash
# Start database in foreground (see logs)
docker-compose up

# Start database in background
docker-compose up -d

# Stop database
docker-compose stop

# Restart database
docker-compose restart

# View logs
docker-compose logs
docker-compose logs -f  # Follow logs

# Execute commands in container
docker-compose exec postgres psql -U authdb -d authdb

# Remove everything (including volumes)
docker-compose down -v
```

## Backup and Restore

### Backup Database

```bash
docker-compose exec -T postgres pg_dump -U authdb authdb > backup.sql
```

### Restore Database

```bash
docker-compose exec -T postgres psql -U authdb -d authdb < backup.sql
```

## Environment Variables

You can customize the database settings by creating a `.env` file:

```env
POSTGRES_USER=authdb
POSTGRES_PASSWORD=authdb
POSTGRES_DB=authdb
POSTGRES_PORT=5432
```

Then update `docker-compose.yml` to use environment variables:

```yaml
environment:
  POSTGRES_USER: ${POSTGRES_USER:-authdb}
  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-authdb}
  POSTGRES_DB: ${POSTGRES_DB:-authdb}
ports:
  - "${POSTGRES_PORT:-5432}:5432"
```

## Troubleshooting

### Port Already in Use

If port 5432 is already in use, change the port mapping in `docker-compose.yml`:

```yaml
ports:
  - "5433:5432"  # Use port 5433 on host
```

Then update your connection string:
```
postgres://authdb:authdb@localhost:5433/authdb?sslmode=disable
```

### Permission Issues

If you encounter permission issues with the data volume:

```bash
docker-compose down -v
docker-compose up -d
```

### View Container Details

```bash
docker-compose ps
docker inspect goauthx-postgres
```

## Production Considerations

For production use, consider:

1. **Use secrets** instead of plain text passwords
2. **Configure SSL/TLS** (change `sslmode=require`)
3. **Set up regular backups**
4. **Use a `.env` file** for sensitive data (add to `.gitignore`)
5. **Limit container resources** (add `deploy.resources` in docker-compose.yml)
6. **Use specific version tags** instead of `latest`
7. **Configure logging** (add logging driver configuration)

Example production-ready configuration:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    container_name: goauthx-postgres
    restart: always
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./postgres.conf:/etc/postgresql/postgresql.conf  # Custom config
    command: postgres -c config_file=/etc/postgresql/postgresql.conf
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  postgres_data:
    driver: local

networks:
  default:
    name: goauthx_network
```
