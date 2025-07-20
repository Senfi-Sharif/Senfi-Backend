from django.core.management.base import BaseCommand
from api.performance import performance_monitor
import time
import json
from pathlib import Path

class Command(BaseCommand):
    help = 'Monitor system performance and save metrics'

    def add_arguments(self, parser):
        parser.add_argument(
            '--interval',
            type=int,
            default=60,
            help='Monitoring interval in seconds (default: 60)',
        )
        parser.add_argument(
            '--duration',
            type=int,
            default=3600,
            help='Monitoring duration in seconds (default: 3600)',
        )
        parser.add_argument(
            '--save',
            action='store_true',
            help='Save metrics to file',
        )

    def handle(self, *args, **options):
        interval = options['interval']
        duration = options['duration']
        save_metrics = options['save']
        
        self.stdout.write(f'Starting performance monitoring...')
        self.stdout.write(f'Interval: {interval} seconds')
        self.stdout.write(f'Duration: {duration} seconds')
        self.stdout.write(f'Save metrics: {save_metrics}')
        self.stdout.write('')
        
        start_time = time.time()
        iteration = 0
        
        try:
            while time.time() - start_time < duration:
                iteration += 1
                
                # Record system metrics
                performance_monitor.record_system_metrics()
                
                # Get performance summary
                summary = performance_monitor.get_performance_summary()
                
                # Display current status
                self.stdout.write(f'Iteration {iteration}:')
                self.stdout.write(f'  System Health: {summary["system_health"]}')
                self.stdout.write(f'  Total Requests: {summary["total_requests"]}')
                self.stdout.write(f'  Avg Response Time: {summary["avg_response_time"]:.3f}s')
                self.stdout.write(f'  Slow Requests: {summary["slow_requests"]}')
                self.stdout.write(f'  Error Rate: {summary["error_rate"]:.2f}%')
                
                # Show top endpoints
                if summary['top_endpoints']:
                    self.stdout.write('  Top Endpoints:')
                    for endpoint in summary['top_endpoints'][:3]:
                        self.stdout.write(f'    {endpoint["endpoint"]}: {endpoint["count"]} requests')
                
                self.stdout.write('')
                
                # Save metrics if requested
                if save_metrics:
                    performance_monitor.save_metrics()
                
                # Wait for next iteration
                if time.time() - start_time < duration:
                    time.sleep(interval)
                    
        except KeyboardInterrupt:
            self.stdout.write('\nMonitoring stopped by user')
        
        # Final summary
        self.stdout.write('Final Performance Summary:')
        final_summary = performance_monitor.get_performance_summary()
        
        self.stdout.write(f'Total Requests: {final_summary["total_requests"]}')
        self.stdout.write(f'Average Response Time: {final_summary["avg_response_time"]:.3f}s')
        self.stdout.write(f'Slow Requests: {final_summary["slow_requests"]}')
        self.stdout.write(f'Error Rate: {final_summary["error_rate"]:.2f}%')
        self.stdout.write(f'System Health: {final_summary["system_health"]}')
        
        if save_metrics:
            performance_monitor.save_metrics()
            self.stdout.write('Metrics saved to performance_metrics.json') 