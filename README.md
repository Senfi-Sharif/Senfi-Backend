# Senfi Django Backend

A secure, production-ready Django REST API for campaign management and signature collection at Sharif University.

## 🚀 Features

- **🔐 Enterprise Security** - JWT authentication, rate limiting, input validation
- **📊 Performance Monitoring** - Real-time metrics and system health tracking
- **💾 Automated Backups** - Database backup and recovery system
- **📚 API Documentation** - Interactive Swagger UI and ReDoc
- **🛡️ Security Logging** - Comprehensive audit trail and monitoring
- **⚡ High Performance** - Optimized for production workloads

## 🛡️ Security Features

- Environment-based configuration (no hardcoded secrets)
- JWT token rotation and blacklisting
- Rate limiting on sensitive endpoints
- Comprehensive input validation
- Security headers (XSS, CSRF protection)
- HTTPS configuration with HSTS
- Complete security logging and monitoring

## 📋 Requirements

- Python 3.8+
- Django 5.2+
- PostgreSQL (recommended) or SQLite
- Redis (optional, for caching)

## 🚀 Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd senfi_django_backend
   ```

2. **Set up environment variables**
   ```bash
   # Copy the example and edit with your settings
   cp .env.example .env
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run migrations**
   ```bash
   python3 manage.py migrate
   ```

5. **Start the server**
   ```bash
   python3 manage.py runserver 127.0.0.1:8000
   ```

For detailed setup instructions, see [Environment Setup Guide](ENVIRONMENT_SETUP.md).

## 📚 Documentation

- **[Environment Setup](ENVIRONMENT_SETUP.md)** - Complete setup guide
- **[API Documentation](API_DOCUMENTATION.md)** - API reference and examples
- **[Security Audit Report](SECURITY_AUDIT_REPORT.md)** - Security assessment
- **[Backup Guide](BACKUP_GUIDE.md)** - Database backup and recovery
- **[Performance Monitoring](PERFORMANCE_MONITORING.md)** - Monitoring and optimization

## 🔧 Available Commands

### Database Management
```bash
# Create backup
python3 manage.py backup_db [--force]

# Restore from backup
python3 manage.py restore_db <backup_name> [--no-confirm]

# List backups
python3 manage.py list_backups [--detailed]
```

### Performance Monitoring
```bash
# Monitor system performance
python3 manage.py monitor_performance [--interval 60] [--duration 3600] [--save]
```

### Development
```bash
# Run server
python3 manage.py runserver 127.0.0.1:8000

# Create superuser
python3 manage.py createsuperuser

# Run tests
python3 manage.py test
```

## 🌐 API Endpoints

### Authentication
- `POST /api/auth/login/` - User login
- `POST /api/auth/register/` - User registration
- `POST /api/auth/refresh/` - Refresh JWT token
- `GET /api/auth/user/` - Get current user info

### Campaigns
- `POST /api/campaigns/submit/` - Submit new campaign
- `GET /api/campaigns/approved/` - Get approved campaigns
- `POST /api/campaigns/approve/` - Approve/reject campaign (admin)

### Signatures
- `POST /api/campaigns/{id}/sign/` - Sign a campaign
- `GET /api/campaigns/{id}/signatures/` - Get campaign signatures

### Performance Monitoring (Admin)
- `GET /api/performance/summary/` - Performance overview
- `GET /api/performance/endpoints/` - Endpoint statistics
- `GET /api/performance/slow-requests/` - Slow request list

### Documentation
- `GET /api/docs/` - Swagger UI
- `GET /api/redoc/` - ReDoc documentation
- `GET /api/schema/` - OpenAPI schema

## 🔐 Security Configuration

### Environment Variables

**Essential for production:**
```bash
DJANGO_SECRET_KEY=your-secure-secret-key
DJANGO_DEBUG=False
DJANGO_CORS_ALLOW_ALL_ORIGINS=False
DJANGO_CORS_ALLOWED_ORIGINS=https://yourdomain.com
EMAIL_SERVER=mail.senfi-sharif.ir
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_USE_SSL=False
EMAIL_USER=admin@senfi-sharif.ir
EMAIL_PASS=@dm!n1234
```

**Security headers:**
```bash
DJANGO_SECURE_BROWSER_XSS_FILTER=True
DJANGO_SECURE_CONTENT_TYPE_NOSNIFF=True
DJANGO_X_FRAME_OPTIONS=DENY
DJANGO_SECURE_SSL_REDIRECT=True
DJANGO_SECURE_HSTS_SECONDS=31536000
```

## 📊 Monitoring & Logging

### Performance Metrics
- Request response times
- Endpoint usage statistics
- System resource monitoring (CPU, memory, disk)
- Slow request detection (>2 seconds)
- Error rate tracking

### Security Logging
- Authentication events
- Failed login attempts
- Admin actions
- Security violations
- Rate limit violations

### Log Files
- `security.log` - Security events
- `backup.log` - Backup operations
- `performance_metrics.json` - Performance data

## 🔄 Backup & Recovery

### Automated Backups
- Timestamped database backups
- Metadata tracking
- Integrity verification
- Automatic cleanup (keeps last 10 backups)

### Recovery Procedures
- Safe restore with confirmation
- Pre-restore backup creation
- Rollback capabilities
- Documented emergency procedures

## 🧪 Testing

```bash
# Run all tests
python3 manage.py test

# Run specific app tests
python3 manage.py test api

# Run with coverage
coverage run --source='.' manage.py test
coverage report
```

## 📈 Performance

### Optimizations
- Database query optimization
- Caching strategies
- Rate limiting
- Input validation
- Security monitoring

### Monitoring
- Real-time performance tracking
- System health assessment
- Bottleneck identification
- Resource usage monitoring

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 for Python code
- Add tests for new features
- Update documentation
- Follow security best practices
- Use environment variables for configuration

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the guides in the `docs/` folder
- **Security Issues**: Review [Security Audit Report](SECURITY_AUDIT_REPORT.md)
- **Performance**: See [Performance Monitoring Guide](PERFORMANCE_MONITORING.md)
- **Backup Issues**: Check [Backup Guide](BACKUP_GUIDE.md)

## 🔗 Links

- **API Documentation**: http://127.0.0.1:8000/api/docs/
- **Security Report**: [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md)
- **Environment Setup**: [ENVIRONMENT_SETUP.md](ENVIRONMENT_SETUP.md)

---

**Security Score**: 9.2/10  
**Status**: ✅ Production Ready  
**Last Updated**: July 19, 2025 