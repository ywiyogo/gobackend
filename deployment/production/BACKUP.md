# PostgreSQL Backup and Restore Guide

This guide provides a simplified, unified approach to PostgreSQL database backup and restore operations using SQL dumps.

## 📋 Quick Reference

### Create Backup
```bash
./scripts/backup-sql.sh
```

### Restore Backup
```bash
./scripts/restore-sql.sh postgres_dump_20241214_120000.sql.gz
```

### List Available Backups
```bash
./scripts/restore-sql.sh --list
```

## 🗄️ Backup System Overview

Our backup system uses **PostgreSQL SQL dumps** compressed with gzip. This approach provides:

- **Universal compatibility** across PostgreSQL versions
- **Human-readable** SQL format when decompressed
- **Efficient compression** to minimize storage space
- **Complete database** schema and data backup
- **Metadata tracking** for each backup

## 📦 Backup Creation

### Manual Backup

Create an immediate backup of your database:

```bash
./scripts/backup-sql.sh
```

**What happens:**
1. Connects to PostgreSQL container
2. Creates SQL dump using `pg_dump`
3. Compresses with gzip
4. Generates metadata file
5. Verifies backup integrity

### Backup Options

```bash
# Basic backup
./scripts/backup-sql.sh

# Backup with integrity test
./scripts/backup-sql.sh --test

# Backup with automatic cleanup (keeps only 7 days)
./scripts/backup-sql.sh --retention 7
```

### Backup Files Generated

Each backup creates two files:

```
backups/
├── postgres_dump_20241214_120000.sql.gz      # Compressed SQL dump
└── postgres_dump_20241214_120000.metadata.json # Backup information
```

**Metadata contains:**
- Backup timestamp and size
- Database version and size
- Table count
- Environment information

## 🔄 Backup Restore

### List Available Backups

```bash
./scripts/restore-sql.sh --list
```

Shows all available backups with their metadata.

### Standard Restore

```bash
./scripts/restore-sql.sh postgres_dump_20241214_120000.sql.gz
```

**Restore process:**
1. **Confirmation** - Prompts for user confirmation
2. **Safety backup** - Creates backup of current database
3. **Service shutdown** - Stops backend services
4. **Database recreation** - Drops and recreates database
5. **Data restoration** - Imports data from backup file
6. **Service restart** - Starts all services
7. **Verification** - Confirms successful restore

### Quick Restore (Skip Safety Backup)

```bash
./scripts/restore-sql.sh --skip-safety-backup postgres_dump_20241214_120000.sql.gz
```

Use when you're confident about the restore or in emergency situations.

## ⏰ Automated Backups

### Setup Automated Backups

```bash
# Daily backups at 2 AM (keeps 7 days)
./scripts/setup-automated-backup.sh setup daily

# Weekly backups at 3 AM Sunday (keeps 30 days)  
./scripts/setup-automated-backup.sh setup weekly

# Monthly backups at 4 AM on 1st (keeps 365 days)
./scripts/setup-automated-backup.sh setup monthly

# Setup all schedules
./scripts/setup-automated-backup.sh setup all
```

### Manage Automated Backups

```bash
# Check status
./scripts/setup-automated-backup.sh status

# View logs
./scripts/setup-automated-backup.sh logs

# Test backup
./scripts/setup-automated-backup.sh test

# Remove automation
./scripts/setup-automated-backup.sh remove
```

## 🎯 Common Scenarios

### Daily Operations

```bash
# Before major updates
./scripts/backup-sql.sh

# After updates (verify everything works)
./scripts/backup-sql.sh --test
```

### Data Recovery

```bash
# 1. List backups to find the right one
./scripts/restore-sql.sh --list

# 2. Restore from specific backup
./scripts/restore-sql.sh postgres_dump_20241213_180000.sql.gz
```

### Emergency Recovery

```bash
# Quick restore without safety backup
./scripts/restore-sql.sh --skip-safety-backup latest_backup.sql.gz
```

### System Migration

```bash
# 1. Create backup on old system
./scripts/backup-sql.sh

# 2. Copy backup files to new system
scp backups/postgres_dump_*.* user@newserver:/path/to/backups/

# 3. Restore on new system
./scripts/restore-sql.sh postgres_dump_20241214_120000.sql.gz
```

## 🔒 Best Practices

### Security

```bash
# Secure backup directory
chmod 750 backups/
chmod 640 backups/*

# For sensitive data, encrypt backups
gpg --symmetric --cipher-algo AES256 postgres_dump_20241214_120000.sql.gz
```

### Storage Management

**Retention Schedule:**
- **Development:** 3 days
- **Staging:** 7 days  
- **Production:** 30 days + monthly archives

**Storage Layout:**
```
/var/backups/gobackend/
├── daily/          # Recent backups (7-30 days)
├── weekly/         # Weekly backups (8 weeks)
├── monthly/        # Monthly archives (12 months)
└── emergency/      # Manual/emergency backups
```

### Monitoring

```bash
# Check backup integrity
gzip -t backups/postgres_dump_20241214_120000.sql.gz

# View backup contents (first 20 lines)
gunzip -c backups/postgres_dump_20241214_120000.sql.gz | head -20

# Check database connectivity
docker exec production-db-1 pg_isready -U postgres -d gobackend
```

## 🔧 Troubleshooting

### Backup Issues

**"Connection refused"**
```bash
# Check database status
docker compose ps db
docker compose logs db

# Restart if needed
docker compose restart db
```

**"Permission denied"**
```bash
# Fix script permissions
chmod +x scripts/*.sh

# Fix directory permissions
chmod 750 backups/
```

**Empty backup file**
```bash
# Check database connection
docker exec production-db-1 psql -U postgres -d gobackend -c "\l"

# Verify environment variables
cat .env | grep DB_
```

### Restore Issues

**"Database does not exist"**
```bash
# Check database service
docker compose ps db

# Create database manually if needed
docker exec production-db-1 createdb -U postgres gobackend
```

**Services won't start after restore**
```bash
# Check logs
docker compose logs backend
docker compose logs db

# Restart services
docker compose restart
```

### Health Checks

```bash
# System status
docker compose ps
docker --version

# Database status  
docker exec production-db-1 psql -U postgres -c "SELECT version();"

# Backup statistics
ls -lah backups/
df -h backups/
```

## 📋 Emergency Checklist

When things go wrong:

1. **Stop damage** - Identify and halt the problem
2. **Create emergency backup** - `./scripts/backup-sql.sh`
3. **Find good backup** - `./scripts/restore-sql.sh --list`
4. **Test in dev first** - If possible, test restore process
5. **Restore production** - `./scripts/restore-sql.sh backup_file.sql.gz`
6. **Verify data** - Check application functionality
7. **Monitor system** - Watch for any issues

## 📚 File Reference

### Backup Scripts
- `scripts/backup-sql.sh` - Create SQL dump backups
- `scripts/restore-sql.sh` - Restore from SQL dump backups
- `scripts/setup-automated-backup.sh` - Manage automated backups

### Configuration Files
- `.env` - Database connection settings
- `docker-compose.yml` - Container configuration

### Backup Files
- `*.sql.gz` - Compressed SQL dump files
- `*.metadata.json` - Backup information and metadata

---

**Last Updated:** January 2025  
**Version:** 2.0 - Simplified unified approach