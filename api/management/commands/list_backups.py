from django.core.management.base import BaseCommand
import os
import json
from pathlib import Path
from datetime import datetime

class Command(BaseCommand):
    help = 'List available database backups'

    def add_arguments(self, parser):
        parser.add_argument(
            '--detailed',
            action='store_true',
            help='Show detailed backup information',
        )

    def handle(self, *args, **options):
        backup_dir = Path('backups')
        
        if not backup_dir.exists():
            self.stdout.write('No backup directory found')
            return
        
        backups = list(backup_dir.glob('users_backup_*.db'))
        
        if not backups:
            self.stdout.write('No backups found')
            return
        
        # Sort by creation time (newest first)
        backups.sort(key=os.path.getctime, reverse=True)
        
        self.stdout.write(f'Found {len(backups)} backup(s):\n')
        
        for i, backup in enumerate(backups, 1):
            size_mb = os.path.getsize(backup) / (1024 * 1024)
            created_time = datetime.fromtimestamp(os.path.getctime(backup))
            
            self.stdout.write(f'{i}. {backup.name}')
            self.stdout.write(f'   Size: {size_mb:.2f} MB')
            self.stdout.write(f'   Created: {created_time.strftime("%Y-%m-%d %H:%M:%S")}')
            
            # Show metadata if available
            if options['detailed']:
                metadata_path = backup.with_suffix('.json')
                if metadata_path.exists():
                    try:
                        with open(metadata_path, 'r') as f:
                            metadata = json.load(f)
                        
                        self.stdout.write(f'   Original size: {metadata.get("original_size", "Unknown")} bytes')
                        self.stdout.write(f'   Version: {metadata.get("version", "Unknown")}')
                        if 'django_version' in metadata:
                            self.stdout.write(f'   Django version: {metadata["django_version"]}')
                    except Exception as e:
                        self.stdout.write(f'   Metadata error: {str(e)}')
            
            self.stdout.write('')
        
        # Show total size
        total_size = sum(os.path.getsize(backup) for backup in backups)
        total_size_mb = total_size / (1024 * 1024)
        self.stdout.write(f'Total size: {total_size_mb:.2f} MB') 