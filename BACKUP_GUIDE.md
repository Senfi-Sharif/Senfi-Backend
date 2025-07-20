# Database Backup & Recovery Guide

## Overview
This guide covers the database backup and recovery system for Senfi Django Backend.

## Backup System Features

### ✅ **Automatic Features**
- **Timestamped backups**: Each backup has unique timestamp
- **Metadata tracking**: Backup size, creation time, version info
- **Integrity verification**: SQLite database validation
- **Auto-cleanup**: Keeps last 10 backups, removes old ones
- **Pre-restore backup**: Creates backup before restore operation

### ✅ **Safety Features**
- **Confirmation prompts**: Prevents accidental restores
- **Recent backup check**: Warns if backup was created recently
- **Force option**: Override recent backup check
- **Error handling**: Comprehensive error logging

## Commands

### Create Backup
```bash
# Create backup (checks for recent backup)
python3 manage.py backup_db

# Force backup (ignores recent backup check)
python3 manage.py backup_db --force
```

### List Backups
```bash
# List basic backup info
python3 manage.py list_backups

# List detailed backup info
python3 manage.py list_backups --detailed
```

### Restore Backup
```bash
# Restore with confirmation prompt
python3 manage.py restore_db users_backup_20250719_014225.db

# Restore without confirmation
python3 manage.py restore_db users_backup_20250719_014225.db --no-confirm
```

### Standalone Backup Tool
```bash
# Create backup
python3 backup_management.py create

# List backups
python3 backup_management.py list

# Restore backup
python3 backup_management.py restore users_backup_20250719_014225.db

# Verify backup
python3 backup_management.py verify users_backup_20250719_014225.db

# Show backup statistics
python3 backup_management.py stats
```

## Backup Structure

### Directory Structure
```
backups/
├── users_backup_20250719_014225.db    # Database backup
├── users_backup_20250719_014225.json  # Metadata
├── users_backup_20250719_014215.db    # Previous backup
└── users_backup_20250719_014215.json  # Previous metadata
```

### Metadata Format
```json
{
  "timestamp": "20250719_014225",
  "created_at": "2025-07-19T01:42:25.123456",
  "original_size": 167936,
  "backup_size": 167936,
  "version": "1.0.0",
  "django_version": "5.2.4"
}
```

## Recovery Procedures

### Standard Recovery
1. **Stop Django server**
2. **List available backups**: `python3 manage.py list_backups`
3. **Verify backup integrity**: Check backup file exists and is valid
4. **Restore backup**: `python3 manage.py restore_db <backup_name>`
5. **Confirm restore**: Type 'y' when prompted
6. **Start Django server**

### Emergency Recovery
1. **Stop all services**
2. **Create emergency backup**: `python3 manage.py backup_db --force`
3. **Restore from backup**: `python3 manage.py restore_db <backup_name> --no-confirm`
4. **Verify database**: Check if tables and data are intact
5. **Restart services**

### Data Loss Prevention
- **Regular backups**: Create backups before major changes
- **Test restores**: Periodically test restore procedures
- **Multiple backups**: Keep backups in different locations
- **Backup verification**: Always verify backup integrity

## Best Practices

### Backup Schedule
- **Daily**: Automatic backup before deployment
- **Before changes**: Manual backup before schema changes
- **After changes**: Backup after successful deployment
- **Weekly**: Full backup verification

### Storage
- **Local storage**: Keep recent backups locally
- **Remote storage**: Backup important backups to remote location
- **Version control**: Track backup metadata in version control
- **Monitoring**: Monitor backup directory size

### Security
- **Access control**: Restrict access to backup directory
- **Encryption**: Consider encrypting sensitive backups
- **Audit trail**: Log all backup/restore operations
- **Testing**: Regularly test backup/restore procedures

## Troubleshooting

### Common Issues

#### Backup Fails
```bash
# Check disk space
df -h

# Check file permissions
ls -la backups/

# Check database file
ls -la users.db
```

#### Restore Fails
```bash
# Verify backup file
python3 manage.py list_backups --detailed

# Check backup integrity
python3 backup_management.py verify <backup_name>

# Check database path
python3 manage.py shell -c "from django.conf import settings; print(settings.DATABASES)"
```

#### Permission Issues
```bash
# Fix backup directory permissions
chmod 755 backups/
chown www-data:www-data backups/

# Fix database file permissions
chmod 644 users.db
chown www-data:www-data users.db
```

### Log Files
- **Backup logs**: `backup.log`
- **Django logs**: `django.log`
- **System logs**: `/var/log/syslog`

## Monitoring

### Backup Health Checks
```bash
# Check backup count
python3 manage.py list_backups | grep "Found"

# Check backup age
find backups/ -name "*.db" -mtime +7

# Check backup size
du -sh backups/
```

### Automated Monitoring
- **Backup age**: Alert if no backup in 24 hours
- **Backup size**: Alert if backup size changes significantly
- **Backup count**: Alert if backup count drops
- **Disk space**: Alert if backup directory is full

## Integration

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
- name: Create backup before deployment
  run: |
    python3 manage.py backup_db --force
    python3 manage.py list_backups
```

### Cron Jobs
```bash
# Daily backup at 2 AM
0 2 * * * cd /path/to/senfi_django_backend && python3 manage.py backup_db

# Weekly backup verification
0 3 * * 0 cd /path/to/senfi_django_backend && python3 manage.py list_backups --detailed
```

## Support

For backup and recovery issues:
1. Check this guide first
2. Review backup logs: `tail -f backup.log`
3. Verify backup integrity
4. Test restore procedure
5. Contact system administrator 