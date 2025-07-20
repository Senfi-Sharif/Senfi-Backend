# Environment Setup Guide

## Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd senfi_django_backend
   ```

2. **Create virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

5. **Run migrations**
   ```bash
   python3 manage.py migrate
   ```

6. **Create superuser**
   ```bash
   python3 manage.py createsuperuser
   ```

7. **Run the server**
   ```bash
   python3 manage.py runserver 127.0.0.1:8000
   ```

## Required Environment Variables

Create a `.env` file in the project root with the following variables:

### Essential Variables
```bash
# Django Settings
DJANGO_SECRET_KEY=your-secure-secret-key-here
DJANGO_DEBUG=True
DJANGO_CORS_ALLOW_ALL_ORIGINS=True

# Email Settings (for verification codes)
EMAIL_SERVER=mail.senfi-sharif.ir
EMAIL_USER=admin@senfi-sharif.ir
EMAIL_PASS=xxxx
```

### Optional Variables
```bash
# CORS Settings
DJANGO_CORS_ALLOWED_ORIGINS=https://yourdomain.com

# Security Headers
DJANGO_SECURE_BROWSER_XSS_FILTER=False
DJANGO_SECURE_CONTENT_TYPE_NOSNIFF=False
DJANGO_X_FRAME_OPTIONS=SAMEORIGIN

# HTTPS Settings
DJANGO_SECURE_SSL_REDIRECT=False
DJANGO_SECURE_HSTS_SECONDS=0
DJANGO_SESSION_COOKIE_SECURE=False
```

## Generating a Secure Secret Key

```bash
python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

## Gmail App Password Setup

1. Go to your Google Account settings
2. Enable 2-factor authentication
3. Generate an app password for "Mail"
4. Use the generated password in `EMAIL_PASS`

## Development vs Production

### Development Settings
```bash
DJANGO_DEBUG=True
DJANGO_CORS_ALLOW_ALL_ORIGINS=True
DJANGO_SECURE_SSL_REDIRECT=False
```

### Production Settings
```bash
DJANGO_DEBUG=False
DJANGO_CORS_ALLOW_ALL_ORIGINS=False
DJANGO_CORS_ALLOWED_ORIGINS=https://yourdomain.com
DJANGO_SECURE_SSL_REDIRECT=True
DJANGO_SECURE_HSTS_SECONDS=31536000
```

## Security Features

This project includes comprehensive security features:

- **Environment-based configuration** - No hardcoded secrets
- **JWT token security** - Token rotation and blacklisting
- **Rate limiting** - Protection against brute force attacks
- **Input validation** - Comprehensive sanitization
- **Security logging** - Complete audit trail
- **CORS protection** - Cross-origin request control
- **Security headers** - XSS and clickjacking protection

## Available Commands

### Database Management
```bash
python3 manage.py backup_db [--force]
python3 manage.py restore_db <backup_name> [--no-confirm]
python3 manage.py list_backups [--detailed]
```

### Performance Monitoring
```bash
python3 manage.py monitor_performance [--interval 60] [--duration 3600] [--save]
```

### Development
```bash
python3 manage.py runserver 127.0.0.1:8000
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py createsuperuser
```

## API Documentation

Once the server is running, visit:
- **Swagger UI**: http://127.0.0.1:8000/api/docs/
- **ReDoc**: http://127.0.0.1:8000/api/redoc/
- **OpenAPI Schema**: http://127.0.0.1:8000/api/schema/

## Troubleshooting

### Common Issues

1. **Module not found errors**
   ```bash
   pip install -r requirements.txt
   ```

2. **Database errors**
   ```bash
   python3 manage.py migrate
   ```

3. **Email not working**
   - Check Gmail app password
   - Enable "Less secure app access" or use app password

4. **CORS errors**
   - Set `DJANGO_CORS_ALLOW_ALL_ORIGINS=True` for development
   - Configure `DJANGO_CORS_ALLOWED_ORIGINS` for production

5. **Permission errors**
   ```bash
   chmod +x manage.py
   ```

### Getting Help

- Check the logs in `security.log` and `backup.log`
- Review the documentation in the `docs/` folder
- Check the security audit report: `SECURITY_AUDIT_REPORT.md`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Code Style

- Follow PEP 8 for Python code
- Use meaningful variable names
- Add docstrings to functions and classes
- Include type hints where appropriate

### Security Guidelines

- Never commit `.env` files or secrets
- Use environment variables for configuration
- Validate all user inputs
- Follow the principle of least privilege
- Log security events appropriately

## License

This project is open source. Please review the LICENSE file for details. 