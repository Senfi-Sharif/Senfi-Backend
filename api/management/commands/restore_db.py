from django.core.management.base import BaseCommand
from django.conf import settings
import os
import shutil
import json
from datetime import datetime
from pathlib import Path
import sqlite3
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Restore database from backup'

    def add_arguments(self, parser):
        parser.add_argument(
            'backup_name',
            type=str,
            help='Name of backup file to restore from'
        )
        parser.add_argument(
            '--no-confirm',
            action='store_true',
            help='Skip confirmation prompt',
        )

    def handle(self, *args, **options):
        backup_name = options['backup_name']
        backup_dir = Path('backups')
        backup_path = backup_dir / backup_name
        
        # Check if backup exists
        if not backup_path.exists():
            self.stdout.write(
                f'Backup not found: {backup_name}'
            )
            return
        
        # Verify backup integrity
        is_valid, message = self._verify_backup(backup_path)
        if not is_valid:
            self.stdout.write(
                f'Backup verification failed: {message}'
            )
            return
        
        # Get backup metadata
        metadata_path = backup_path.with_suffix('.json')
        metadata = {}
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
        
        # Show backup info
        self.stdout.write(f'Backup: {backup_name}')
        self.stdout.write(f'Created: {metadata.get("created_at", "Unknown")}')
        self.stdout.write(f'Size: {os.path.getsize(backup_path) / (1024 * 1024):.2f} MB')
        
        # Confirmation
        if not options['no_confirm']:
            confirm = input('\nThis will overwrite the current database. Continue? (y/N): ')
            if confirm.lower() != 'y':
                self.stdout.write('Restore cancelled')
                return
        
        try:
            # Get current database path
            db_path = settings.DATABASES['default']['NAME']
            if db_path == ':memory:':
                self.stdout.write(
                    'Cannot restore to in-memory database'
                )
                return
            
            # Create backup of current database before restore
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            pre_restore_backup = f'pre_restore_backup_{timestamp}.db'
            pre_restore_path = backup_dir / pre_restore_backup
            
            shutil.copy2(db_path, pre_restore_path)
            self.stdout.write(f'Created pre-restore backup: {pre_restore_backup}')
            
            # Restore database
            shutil.copy2(backup_path, db_path)
            
            self.stdout.write(
                f'Database restored from: {backup_name}'
            )
            self.stdout.write(
                f'Pre-restore backup saved as: {pre_restore_backup}'
            )
            
        except Exception as e:
            self.stdout.write(
                f'Restore failed: {str(e)}'
            )
    
    def _verify_backup(self, backup_path):
        """Verify backup integrity"""
        try:
            # Try to open SQLite database
            conn = sqlite3.connect(backup_path)
            cursor = conn.cursor()
            
            # Check if tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            conn.close()
            
            if not tables:
                return False, "No tables found in backup"
            
            return True, f"Backup verified. Found {len(tables)} tables"
            
        except Exception as e:
            return False, f"Verification failed: {str(e)}" 