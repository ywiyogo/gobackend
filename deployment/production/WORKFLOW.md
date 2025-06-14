# Production Deployment Workflow

## 🔄 Complete Workflow Example

### 1. Initial Setup (One-time)

```bash
# On your local machine
cd gobackend/deployment/production

# Configure production environment
cp .env.example .env
# Edit .env with your production values:
# - Database credentials
# - SMTP settings  
# - Docker Hub username

# Login to Docker Hub
docker login
```

### 2. Development & Deployment Cycle

```bash
# Local Development
cd gobackend/
# Make code changes...
# Test locally...
git add .
git commit -m "Add new feature"

# Build & Push (from deployment/production)
cd deployment/production
./build-and-push.sh --tag-with-commit

# Deploy on VPS (SSH to your server)
ssh user@your-vps
cd /path/to/gobackend/deployment/production
git pull origin main
./deploy.sh
```

## 📁 Environment File Structure

```
gobackend/
├── .env                              # Local development
└── deployment/production/
    ├── .env                          # Production (for building & deploying)
    ├── .env.example                  # Template
    ├── build-and-push.sh             # Build script (uses production .env)
    └── deploy.sh                     # Deploy script (uses production .env)
```

## ⚡ Quick Commands

### Local Machine (Build & Push)
```bash
cd deployment/production

# Quick build & push
./build-and-push.sh

# Production build with version
./build-and-push.sh --tag-with-commit

# Test build only
./build-and-push.sh --no-push
```

### VPS (Deploy)
```bash
cd deployment/production

# Quick deploy
./deploy.sh

# Check status
docker compose ps
docker compose logs -f backend

# Health check
curl http://localhost:8090/health
```

## 🎯 Why This Structure?

### ✅ Benefits
- **Separation**: Dev vs prod environments clearly separated
- **Security**: Production secrets stay on production systems
- **Consistency**: Same .env used for building and deploying
- **Simplicity**: All production tools in one directory

### 🔧 Configuration Management
- **Local .env**: Development database, local settings
- **Production .env**: VPS database, production SMTP, Docker Hub config
- **Same Docker config**: Ensures build and deploy use same image

## 📋 Typical Day Workflow

```bash
# Morning: Start development
cd gobackend/
# Work with local .env for development

# Afternoon: Ready to deploy
cd deployment/production
# Use production .env for building
./build-and-push.sh --tag-with-commit

# Deploy to VPS
ssh vps
cd app/deployment/production  
git pull && ./deploy.sh
```

## 🚨 Emergency Procedures

### Rollback Deployment
```bash
# On VPS
cd deployment/production

# Backup database
docker compose exec db pg_dump -U $DB_USER $DB_NAME > backup.sql

# Rollback migration
docker compose --profile emergency run --rm migrate-down

# Restart with previous image
docker compose restart backend
```

### Fix Build Issues
```bash
# On local machine
cd deployment/production

# Check configuration
cat .env | grep DOCKER

# Test build locally
docker build -f Dockerfile -t test-image ../../

# Debug container
docker run -it test-image /bin/sh
```

## 📊 Monitoring

### Health Checks
```bash
# Quick health check
curl http://localhost:8090/health

# Detailed status
curl http://localhost:8090/health | jq .

# Check all endpoints
curl http://localhost:8090/live
curl http://localhost:8090/ready
```

### Resource Monitoring
```bash
# Container stats
docker stats

# Service status
docker compose ps

# Recent logs
docker compose logs --tail=50 backend
```
