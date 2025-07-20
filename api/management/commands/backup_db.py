from django.core.management.base import BaseCommand
from django.conf import settings
import os
import shutil
import json
from datetime import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Create database backup'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force backup even if recent backup exists',
        )

    def handle(self, *args, **options):
        try:
            # Get database path
            db_path = settings.DATABASES['default']['NAME']
            if db_path == ':memory:':
                self.stdout.write(
                    self.style.ERROR('Cannot backup in-memory database')
                )
                return
            
            # Create backup directory
            backup_dir = Path('backups')
            backup_dir.mkdir(exist_ok=True)
            
            # Check if recent backup exists (within 1 hour)
            if not options['force']:
                recent_backups = list(backup_dir.glob('users_backup_*.db'))
                if recent_backups:
                    latest_backup = max(recent_backups, key=os.path.getctime)
                    backup_age = datetime.now().timestamp() - os.path.getctime(latest_backup)
                    
                    if backup_age < 3600:  # 1 hour
                        self.stdout.write(
                            self.style.WARNING(
                                f'Recent backup exists: {latest_backup.name} '
                                f'({backup_age/60:.1f} minutes ago)'
                            )
                        )
                        self.stdout.write(
                            'Use --force to create backup anyway'
                        )
                        return
            
            # Create backup
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f'users_backup_{timestamp}.db'
            backup_path = backup_dir / backup_name
            
            shutil.copy2(db_path, backup_path)
            
            # Create metadata
            metadata = {
                'timestamp': timestamp,
                'created_at': datetime.now().isoformat(),
                'original_size': os.path.getsize(db_path),
                'backup_size': os.path.getsize(backup_path),
                'version': '1.0.0',
                'django_version': '5.2.4'
            }
            
            metadata_path = backup_path.with_suffix('.json')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Clean old backups (keep last 10)
            self._cleanup_old_backups(backup_dir)
            
            size_mb = os.path.getsize(backup_path) / (1024 * 1024)
            self.stdout.write(
                self.style.SUCCESS(
                    f'Backup created: {backup_name} ({size_mb:.2f} MB)'
                )
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Backup failed: {str(e)}')
            )
    
    def _cleanup_old_backups(self, backup_dir):
        """Remove old backups beyond limit"""
        backups = list(backup_dir.glob('users_backup_*.db'))
        backups.sort(key=os.path.getctime, reverse=True)
        
        max_backups = 10
        if len(backups) > max_backups:
            backups_to_remove = backups[max_backups:]
            
            for backup in backups_to_remove:
                try:
                    backup.unlink()
                    metadata_path = backup.with_suffix('.json')
                    if metadata_path.exists():
                        metadata_path.unlink()
                    
                    self.stdout.write(
                        f'Removed old backup: {backup.name}'
                    )
                except Exception as e:
                    self.stdout.write(
                        self.style.WARNING(
                            f'Failed to remove {backup.name}: {str(e)}'
                        )
                    ) 