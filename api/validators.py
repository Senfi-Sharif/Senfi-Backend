from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from django.contrib.auth.password_validation import (
    UserAttributeSimilarityValidator,
    MinimumLengthValidator,
    CommonPasswordValidator,
    NumericPasswordValidator
)
import re

class PersianMinimumLengthValidator(MinimumLengthValidator):
    """
    Persian version of MinimumLengthValidator
    """
    def validate(self, password, user=None):
        if len(password) < self.min_length:
            raise ValidationError(
                f'رمز عبور باید حداقل {self.min_length} کاراکتر باشد.',
                code='password_too_short',
            )

    def get_help_text(self):
        return f'رمز عبور شما باید حداقل {self.min_length} کاراکتر باشد.'

class PersianCommonPasswordValidator(CommonPasswordValidator):
    """
    Persian version of CommonPasswordValidator
    """
    def validate(self, password, user=None):
        if password.lower().strip() in self.passwords:
            raise ValidationError(
                'این رمز عبور خیلی ساده است. لطفاً رمز عبور قوی‌تری انتخاب کنید.',
                code='password_too_common',
            )

    def get_help_text(self):
        return 'رمز عبور شما نمی‌تواند رمز عبور ساده و رایج باشد.'

class PersianNumericPasswordValidator(NumericPasswordValidator):
    """
    Persian version of NumericPasswordValidator
    """
    def validate(self, password, user=None):
        if password.isdigit():
            raise ValidationError(
                'رمز عبور نمی‌تواند فقط شامل اعداد باشد.',
                code='password_entirely_numeric',
            )

    def get_help_text(self):
        return 'رمز عبور شما نمی‌تواند فقط شامل اعداد باشد.'

class PersianUserAttributeSimilarityValidator(UserAttributeSimilarityValidator):
    """
    Persian version of UserAttributeSimilarityValidator
    """
    def validate(self, password, user=None):
        if not user:
            return

        for attribute_name in self.user_attributes:
            value = getattr(user, attribute_name, None)
            if value is None:
                continue
            value_parts = value.replace('_', '').replace('-', '').lower().split()
            for value_part in value_parts:
                if value_part in password.lower():
                    raise ValidationError(
                        'رمز عبور شما خیلی شبیه اطلاعات شخصی شما است.',
                        code='password_too_similar',
                    )

    def get_help_text(self):
        return 'رمز عبور شما نمی‌تواند خیلی شبیه اطلاعات شخصی شما باشد.'

class PasswordComplexityValidator:
    """
    Custom password validator for additional complexity requirements
    """
    def __init__(self, min_length=8):
        self.min_length = min_length

    def validate(self, password, user=None):
        if len(password) < self.min_length:
            raise ValidationError(
                f'رمز عبور باید حداقل {self.min_length} کاراکتر باشد.',
                code='password_too_short',
            )
        
        if not re.search(r'[A-Z]', password):
            raise ValidationError(
                'رمز عبور باید حداقل یک حرف بزرگ داشته باشد.',
                code='password_no_upper',
            )
        
        if not re.search(r'[a-z]', password):
            raise ValidationError(
                'رمز عبور باید حداقل یک حرف کوچک داشته باشد.',
                code='password_no_lower',
            )
        
        if not re.search(r'\d', password):
            raise ValidationError(
                'رمز عبور باید حداقل یک عدد داشته باشد.',
                code='password_no_number',
            )
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError(
                'رمز عبور باید حداقل یک کاراکتر خاص (!@#$%^&*(),.?":{}|<>) داشته باشد.',
                code='password_no_special',
            )

    def get_help_text(self):
        return f'رمز عبور شما باید حداقل {self.min_length} کاراکتر باشد و شامل حروف بزرگ، کوچک، اعداد و کاراکترهای خاص باشد.' 