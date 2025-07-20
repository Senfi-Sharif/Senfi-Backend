# Performance Monitoring Guide

## Overview
This guide covers the performance monitoring system for Senfi Django Backend.

## Performance Monitoring Features

### ✅ **Real-time Monitoring**
- **Request tracking**: All API requests monitored
- **Response times**: Average, min, max response times
- **Error rates**: Track 4xx/5xx errors
- **Slow requests**: Identify requests >2 seconds
- **System metrics**: CPU, memory, disk usage

### ✅ **Analytics**
- **Endpoint statistics**: Performance per endpoint
- **User tracking**: Performance by user
- **System health**: Overall system assessment
- **Trends**: Historical performance data
- **Alerts**: Automatic warnings for issues

## Monitoring Components

### Performance Monitor
- **Location**: `api/performance.py`
- **Features**: Thread-safe metrics collection
- **Storage**: JSON file persistence
- **Memory**: In-memory with size limits

### Middleware Integration
- **Location**: `api/middleware.py`
- **Function**: Automatic request tracking
- **Metrics**: Response time, status code, user
- **Logging**: Slow requests and errors

### Management Commands
- **Location**: `api/management/commands/`
- **Commands**: `monitor_performance`
- **Features**: Real-time monitoring
- **Options**: Interval, duration, save

## Usage

### Command Line Monitoring
```bash
# Basic monitoring (60 seconds, 60 second intervals)
python3 manage.py monitor_performance

# Custom monitoring (10 seconds, 1 hour)
python3 manage.py monitor_performance --interval 10 --duration 3600

# Save metrics to file
python3 manage.py monitor_performance --save

# Short monitoring for testing
python3 manage.py monitor_performance --interval 5 --duration 30
```

### API Endpoints
```bash
# Get performance summary
GET /api/performance/summary

# Get endpoint performance
GET /api/performance/endpoints
GET /api/performance/endpoints/POST%20/api/auth/login

# Get slow requests
GET /api/performance/slow-requests?limit=20

# Get system metrics
GET /api/performance/system-metrics?hours=24
```

## Metrics Collected

### Request Metrics
```json
{
  "timestamp": "2025-07-19T01:42:25.123456",
  "endpoint": "/api/auth/login",
  "method": "POST",
  "response_time": 0.234,
  "status_code": 200,
  "user_email": "user@sharif.edu"
}
```

### Endpoint Statistics
```json
{
  "POST /api/auth/login": {
    "count": 150,
    "total_time": 35.2,
    "avg_time": 0.235,
    "min_time": 0.123,
    "max_time": 1.456,
    "errors": 5
  }
}
```

### System Metrics
```json
{
  "timestamp": "2025-07-19T01:42:25.123456",
  "cpu_percent": 15.2,
  "memory_percent": 45.8,
  "memory_available": 8589934592,
  "disk_percent": 67.3,
  "disk_free": 21474836480
}
```

### Performance Summary
```json
{
  "total_requests": 1250,
  "avg_response_time": 0.234,
  "slow_requests": 12,
  "error_rate": 2.4,
  "top_endpoints": [
    {
      "endpoint": "POST /api/auth/login",
      "count": 150,
      "avg_time": 0.235,
      "error_rate": 3.3
    }
  ],
  "system_health": "healthy"
}
```

## System Health Assessment

### Health Levels
- **healthy**: All metrics within normal ranges
- **warning**: Some metrics approaching limits
- **critical**: Metrics at dangerous levels
- **unknown**: No system metrics available

### Thresholds
- **CPU**: >70% warning, >90% critical
- **Memory**: >70% warning, >90% critical
- **Disk**: >80% warning, >95% critical

## Performance Analysis

### Identifying Bottlenecks
1. **Check slow requests**: Look for requests >2 seconds
2. **Analyze endpoint performance**: Find slowest endpoints
3. **Monitor error rates**: Identify problematic endpoints
4. **Track system resources**: Check CPU/memory usage
5. **User patterns**: Identify heavy users

### Optimization Strategies
- **Database queries**: Optimize slow database operations
- **Caching**: Implement caching for frequent requests
- **Rate limiting**: Prevent abuse from heavy users
- **Resource scaling**: Add more CPU/memory if needed
- **Code optimization**: Profile and optimize slow code

## Monitoring Best Practices

### Regular Monitoring
- **Daily**: Check performance summary
- **Weekly**: Analyze trends and patterns
- **Monthly**: Review optimization opportunities
- **Alerts**: Set up automated alerts for issues

### Data Management
- **Retention**: Keep metrics for 30 days
- **Cleanup**: Remove old metrics automatically
- **Backup**: Backup performance data
- **Analysis**: Regular performance reviews

### Alerting
- **Slow requests**: Alert on requests >5 seconds
- **High error rates**: Alert on error rates >10%
- **System resources**: Alert on high CPU/memory
- **Service degradation**: Alert on performance drops

## Troubleshooting

### Common Issues

#### High Response Times
```bash
# Check slow requests
GET /api/performance/slow-requests

# Analyze endpoint performance
GET /api/performance/endpoints

# Check system resources
GET /api/performance/system-metrics
```

#### High Error Rates
```bash
# Check error rates by endpoint
GET /api/performance/endpoints

# Look for patterns in slow requests
GET /api/performance/slow-requests?limit=50
```

#### System Resource Issues
```bash
# Check system metrics
GET /api/performance/system-metrics?hours=1

# Monitor in real-time
python3 manage.py monitor_performance --interval 5
```

### Performance Optimization

#### Database Optimization
- **Indexes**: Add database indexes
- **Queries**: Optimize slow queries
- **Connection pooling**: Use connection pooling
- **Caching**: Implement query caching

#### Application Optimization
- **Code profiling**: Profile slow functions
- **Caching**: Cache frequently accessed data
- **Async operations**: Use async for I/O operations
- **Resource limits**: Set appropriate limits

#### Infrastructure Optimization
- **Scaling**: Scale horizontally/vertically
- **Load balancing**: Distribute load
- **CDN**: Use CDN for static content
- **Monitoring**: Continuous monitoring

## Integration

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
- name: Performance Test
  run: |
    python3 manage.py monitor_performance --interval 5 --duration 60
    # Check if performance is acceptable
```

### Automated Alerts
```bash
# Cron job for regular monitoring
0 */6 * * * cd /path/to/senfi_django_backend && python3 manage.py monitor_performance --save
```

### Dashboard Integration
- **Grafana**: Create performance dashboards
- **Prometheus**: Export metrics to Prometheus
- **Custom dashboards**: Build custom monitoring UI
- **Email alerts**: Send performance alerts

## Security Considerations

### Access Control
- **Admin only**: Performance endpoints require admin role
- **Authentication**: All endpoints require authentication
- **Rate limiting**: Prevent abuse of monitoring endpoints
- **Data privacy**: Don't log sensitive user data

### Data Protection
- **Anonymization**: Anonymize user data in metrics
- **Retention**: Limit data retention period
- **Encryption**: Encrypt stored metrics
- **Access logs**: Log access to performance data

## Support

For performance monitoring issues:
1. Check this guide first
2. Review performance logs
3. Analyze metrics data
4. Test monitoring commands
5. Contact system administrator 