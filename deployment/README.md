# 🚀 Deployment Guide

Simple deployment configurations for the Go Backend application with multi-tenant support.

## 📁 Directory Structure

```
deployment/
├── production/           # Production deployment files
│   ├── docker-compose.yml
│   ├── Caddyfile
│   ├── deploy.sh
│   └── .env.example
└── README.md           # This file
```

## 🎯 Quick Start

### Production Deployment

```bash
# 1. Navigate to production deployment
cd deployment/production

# 2. Configure environment
cp .env.example .env
# Edit .env with your production values

# 3. Update domains in Caddyfile
# Edit Caddyfile with your actual domains

# 4. Deploy
chmod +x deploy.sh
./deploy.sh
```

## 🏗️ Production Environment

**Features:**
- Automatic HTTPS with Let's Encrypt
- Rate limiting and security headers
- Multi-tenant domain support
- Database migrations
- Health checks

**Requirements:**
- Valid domain names pointed to your server
- Email for Let's Encrypt certificates
- Docker and Docker Compose installed

**Ports:**
- `80` - HTTP (redirects to HTTPS)
- `443` - HTTPS
- `2019` - Caddy admin interface

## 🔧 Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Database
DB_USER=gobackend_prod
DB_PASSWORD=your_strong_password
DB_NAME=gobackend_production

# SSL Configuration
ACME_EMAIL=your-email@example.com
```

### Domain Configuration

Edit the `Caddyfile` to include your domains:

```
your-domain.com, api.your-domain.com {
    # Configuration is already set up
    # Just replace the example domains
}
```

## 🚀 Deployment

The deployment script will:
1. Check prerequisites
2. Pull latest code changes
3. Build and start containers
4. Run database migrations
5. Perform health checks

```bash
./deploy.sh
```

## 🔍 Monitoring

### Health Check Endpoints

- `/health` - Basic health status
- `/ready` - Readiness check
- `/live` - Liveness check

### Useful Commands

```bash
# View logs
docker-compose logs -f

# Check service status
docker-compose ps

# Restart services
docker-compose restart

# Access database
docker-compose exec db psql -U $DB_USER $DB_NAME

# Monitor resources
docker stats
```

## 🔒 Security

### Automatic Security Features
- ✅ HTTPS with Let's Encrypt
- ✅ Security headers (HSTS, XSS protection)
- ✅ Rate limiting
- ✅ Secure database setup

### Recommended Firewall Rules
```bash
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## 🛠️ Troubleshooting

### Common Issues

**SSL Certificate Problems**
```bash
# Check Caddy logs
docker-compose logs caddy

# Reload configuration
docker-compose exec caddy caddy reload
```

**Database Connection Issues**
```bash
# Check database status
docker-compose ps db

# Test connection
docker-compose exec db pg_isready -h localhost -p 5432
```

**Application Not Starting**
```bash
# Check application logs
docker-compose logs backend

# Test health endpoint
curl -f http://localhost/health
```

## 📝 Deployment Checklist

### Before Production Deployment

- [ ] Domain names configured and pointing to server
- [ ] SSL email configured in .env file
- [ ] Strong database passwords set
- [ ] Domains updated in Caddyfile
- [ ] Firewall rules configured
- [ ] Docker and Docker Compose installed

## 🔄 CI/CD Integration

The deployment integrates with GitHub Actions for automated deployments on push to main branch. See `.github/workflows/deploy.yml` for the full pipeline.

## 📞 Support

For deployment issues:

1. Check logs: `docker-compose logs -f`
2. Verify configuration files
3. Test health endpoints
4. Check firewall and DNS settings

**Resources:**
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Caddy Documentation](https://caddyserver.com/docs/)