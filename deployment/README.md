# 🚀 Deployment Guide

Optimized deployment for Go Backend with multi-tenant support using pre-built Docker images.

## 🎯 Quick Start

### Production Deployment

```bash
# 1. Configure environment
cd deployment/production
cp .env.example .env
# Edit .env with your production values

# 2. Deploy
./deploy.sh
```

## 🏗️ Optimized Workflow

Instead of building on your VPS (saves CPU/memory):

# 1. **Build locally**: `./build-and-push.sh`
2. **Push to Docker Hub**: Automatic
3. **Deploy on VPS**: `./deploy.sh` (pulls pre-built image)

### Build & Push (Local Machine)

```bash
# Navigate to production directory
cd deployment/production

# Basic build and push
./build-and-push.sh

# With commit hash (recommended)
./build-and-push.sh --tag-with-commit

# Build only (no push)
./build-and-push.sh --no-push
```

## 🔧 Configuration

### Environment Variables (.env)

```bash
# Database
DB_USER=postgres
DB_PASSWORD=your_strong_password
DB_NAME=gobackend_production
DB_HOST=db
DB_PORT=5432

# Docker Image (Docker Hub)
DOCKER_USERNAME=your_dockerhub_username
DOCKER_IMAGE_NAME=gobackend
DOCKER_IMAGE_TAG=latest

# SMTP for OTP
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
EMAIL_MODE=production
```

### Docker Hub Setup

```bash
# Login to Docker Hub
docker login
```

## 🚀 Deployment Process

The deployment script automatically:
1. ✅ Pulls latest code from Git
2. ✅ Pulls pre-built Docker image
3. ✅ Stops old containers
4. ✅ Starts new containers with migrations
5. ✅ Runs health checks

## 🔍 Health Monitoring

### Endpoints
- `/health` - Comprehensive health check (database + tenants)
- `/ready` - Readiness check (database connectivity)
- `/live` - Liveness check (always OK)

### Commands
```bash
# View logs
docker compose logs -f

# Check status
docker compose ps

# Restart services
docker compose restart

# Monitor resources
docker stats
```

## 📦 Services

- **db**: PostgreSQL 15 with health checks
- **migrate**: Database migrations (runs once)
- **backend**: Go application (pulls from Docker Hub)

## 🛠️ Troubleshooting

### Build Issues
```bash
# Check Docker
docker info

# Test local build
docker build -f deployment/production/Dockerfile -t test .
```

### Registry Issues
```bash
# Re-login
docker login

# Test pull
docker pull your-username/gobackend:latest
```

### Deployment Issues
```bash
# Check logs
docker compose logs -f backend

# Reset services
docker compose down && docker compose up -d

# Test health
curl http://localhost:8090/health
```

## 🔒 Security Features

- ✅ Non-root container user
- ✅ Health checks every 60s
- ✅ Database isolation (no external ports)
- ✅ Tenant table validation

## 📈 Benefits

**Resource Savings on VPS:**
- **CPU**: No compilation during deployment
- **Memory**: No build-time usage
- **Time**: 2-3x faster deployments
- **Reliability**: Pre-tested images

## 🔄 Development Workflow

```bash
# Local development
1. Make changes
2. Test locally
3. Commit to Git
4. cd deployment/production && ./build-and-push.sh --tag-with-commit
5. SSH to VPS: ./deploy.sh
```

## 📋 Prerequisites

### Local Machine
- Docker installed
- Docker Hub account
- Git access

### VPS
- Docker & Docker Compose
- Git access
- Internet connection (for pulling images)

## 🏷️ Image Tagging

```bash
# Latest tag
./build-and-push.sh

# Commit hash (recommended)
./build-and-push.sh --tag-with-commit

# Custom tag
DOCKER_IMAGE_TAG=v1.0.0 ./build-and-push.sh
```

## 🚨 Emergency Rollback

```bash
# Backup database first
docker compose exec db pg_dump -U $DB_USER $DB_NAME > backup.sql

# Rollback migration
docker compose --profile emergency run --rm migrate-down

# Restart
docker compose restart backend
```

## 📞 Support

**Quick Diagnosis:**
1. `docker compose ps` - Check service status
2. `docker compose logs backend` - Check application logs
3. `curl localhost:8090/health` - Test health endpoint
4. `docker stats` - Check resource usage

**Common Issues:**
- **Build fails**: Check Docker daemon, Dockerfile path
- **Push fails**: Re-run `docker login`
- **Deploy fails**: Check .env file, Docker Hub access
- **Health fails**: Check database connectivity, migrations