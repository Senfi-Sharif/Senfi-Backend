from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = 'Reset password for a user by email'

    def add_arguments(self, parser):
        parser.add_argument('email', type=str)
        parser.add_argument('password', type=str)

    def handle(self, *args, **options):
        User = get_user_model()
        email = options['email']
        password = options['password']
        try:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            self.stdout.write(self.style.SUCCESS(f'Password for {email} reset successfully.'))
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'User with email {email} does not exist.')) 