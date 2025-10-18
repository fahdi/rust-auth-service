#!/usr/bin/env python3
"""
Coverage Trend Tracking for Rust Auth Service

This script analyzes coverage trends over time, generates reports,
and provides insights for coverage improvement.
"""

import json
import os
import sys
import sqlite3
import argparse
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
from typing import Dict, List, Optional, Tuple


class CoverageTrendTracker:
    """Tracks and analyzes test coverage trends over time."""
    
    def __init__(self, db_path: str = "coverage_trends.db"):
        """Initialize the coverage trend tracker."""
        self.db_path = db_path
        self.project_root = Path(__file__).parent.parent
        self.coverage_dir = self.project_root / "coverage"
        self.init_database()
    
    def init_database(self):
        """Initialize the SQLite database for tracking coverage trends."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create coverage_history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS coverage_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                date TEXT NOT NULL,
                coverage_percent REAL NOT NULL,
                lines_total INTEGER,
                lines_covered INTEGER,
                branch_total INTEGER,
                branch_covered INTEGER,
                function_total INTEGER,
                function_covered INTEGER,
                git_branch TEXT,
                git_commit TEXT,
                git_author TEXT,
                workflow_run_id TEXT,
                environment TEXT DEFAULT 'local'
            )
        """)
        
        # Create module_coverage table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS module_coverage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                history_id INTEGER,
                module_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                coverage_percent REAL NOT NULL,
                lines_total INTEGER,
                lines_covered INTEGER,
                FOREIGN KEY (history_id) REFERENCES coverage_history (id)
            )
        """)
        
        # Create coverage_goals table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS coverage_goals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_name TEXT UNIQUE NOT NULL,
                target_percent REAL NOT NULL,
                minimum_percent REAL NOT NULL,
                priority TEXT DEFAULT 'medium',
                last_updated TEXT NOT NULL
            )
        """)
        
        # Insert default coverage goals
        cursor.execute("SELECT COUNT(*) FROM coverage_goals")
        if cursor.fetchone()[0] == 0:
            default_goals = [
                ('auth_handlers', 85.0, 75.0, 'critical'),
                ('jwt_utils', 90.0, 80.0, 'critical'),
                ('password_utils', 85.0, 75.0, 'critical'),
                ('user_models', 90.0, 80.0, 'critical'),
                ('database_layer', 75.0, 65.0, 'high'),
                ('cache_layer', 70.0, 60.0, 'high'),
                ('rate_limiting', 85.0, 75.0, 'critical'),
                ('mfa_components', 80.0, 70.0, 'high'),
                ('email_services', 60.0, 50.0, 'medium'),
                ('config_validation', 75.0, 65.0, 'high'),
                ('observability', 50.0, 40.0, 'low'),
                ('user_management', 60.0, 50.0, 'medium'),
            ]
            
            for goal in default_goals:
                cursor.execute("""
                    INSERT INTO coverage_goals 
                    (module_name, target_percent, minimum_percent, priority, last_updated)
                    VALUES (?, ?, ?, ?, ?)
                """, (*goal, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def record_coverage(self, coverage_data: Dict) -> int:
        """Record a new coverage measurement."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get Git information
        git_info = self._get_git_info()
        
        # Insert coverage history record
        cursor.execute("""
            INSERT INTO coverage_history 
            (timestamp, date, coverage_percent, lines_total, lines_covered,
             branch_total, branch_covered, function_total, function_covered,
             git_branch, git_commit, git_author, workflow_run_id, environment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            coverage_data.get('timestamp', datetime.now().strftime('%Y%m%d_%H%M%S')),
            coverage_data.get('date', datetime.now().isoformat()),
            coverage_data.get('coverage_percent', 0.0),
            coverage_data.get('lines_total', 0),
            coverage_data.get('lines_covered', 0),
            coverage_data.get('branch_total', 0),
            coverage_data.get('branch_covered', 0),
            coverage_data.get('function_total', 0),
            coverage_data.get('function_covered', 0),
            git_info.get('branch', 'unknown'),
            git_info.get('commit', 'unknown'),
            git_info.get('author', 'unknown'),
            coverage_data.get('workflow_run_id'),
            coverage_data.get('environment', 'local')
        ))
        
        history_id = cursor.lastrowid
        
        # Insert module coverage data if available
        if 'modules' in coverage_data:
            for module_data in coverage_data['modules']:
                cursor.execute("""
                    INSERT INTO module_coverage 
                    (history_id, module_name, file_path, coverage_percent, 
                     lines_total, lines_covered)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    history_id,
                    module_data.get('name'),
                    module_data.get('path'),
                    module_data.get('coverage_percent', 0.0),
                    module_data.get('lines_total', 0),
                    module_data.get('lines_covered', 0)
                ))
        
        conn.commit()
        conn.close()
        return history_id
    
    def _get_git_info(self) -> Dict[str, str]:
        """Get current Git information."""
        try:
            branch = subprocess.check_output(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                cwd=self.project_root, text=True
            ).strip()
            
            commit = subprocess.check_output(
                ['git', 'rev-parse', '--short', 'HEAD'],
                cwd=self.project_root, text=True
            ).strip()
            
            author = subprocess.check_output(
                ['git', 'log', '-1', '--pretty=format:%an'],
                cwd=self.project_root, text=True
            ).strip()
            
            return {'branch': branch, 'commit': commit, 'author': author}
        except subprocess.CalledProcessError:
            return {'branch': 'unknown', 'commit': 'unknown', 'author': 'unknown'}
    
    def get_coverage_trend(self, days: int = 30) -> List[Dict]:
        """Get coverage trend for the last N days."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        cursor.execute("""
            SELECT timestamp, date, coverage_percent, lines_total, lines_covered,
                   git_branch, git_commit, environment
            FROM coverage_history 
            WHERE date >= ?
            ORDER BY date DESC
        """, (since_date,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'timestamp': row[0],
                'date': row[1],
                'coverage_percent': row[2],
                'lines_total': row[3],
                'lines_covered': row[4],
                'git_branch': row[5],
                'git_commit': row[6],
                'environment': row[7]
            })
        
        conn.close()
        return results
    
    def analyze_coverage_regression(self) -> Dict:
        """Analyze potential coverage regressions."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get last 10 measurements
        cursor.execute("""
            SELECT coverage_percent, date, git_commit
            FROM coverage_history 
            ORDER BY date DESC 
            LIMIT 10
        """)
        
        measurements = cursor.fetchall()
        
        if len(measurements) < 2:
            return {'status': 'insufficient_data'}
        
        current_coverage = measurements[0][0]
        previous_coverage = measurements[1][0]
        
        # Calculate trend
        if len(measurements) >= 5:
            recent_avg = sum(m[0] for m in measurements[:5]) / 5
            older_avg = sum(m[0] for m in measurements[5:]) / len(measurements[5:])
            trend = recent_avg - older_avg
        else:
            trend = current_coverage - previous_coverage
        
        # Determine status
        if trend < -2.0:  # Significant regression
            status = 'regression'
        elif trend < -0.5:  # Minor regression
            status = 'minor_regression'
        elif trend > 2.0:  # Significant improvement
            status = 'improvement'
        elif trend > 0.5:  # Minor improvement
            status = 'minor_improvement'
        else:
            status = 'stable'
        
        conn.close()
        
        return {
            'status': status,
            'current_coverage': current_coverage,
            'previous_coverage': previous_coverage,
            'trend': trend,
            'measurements_count': len(measurements)
        }
    
    def generate_coverage_report(self, output_file: str):
        """Generate a comprehensive coverage trend report."""
        trend_data = self.get_coverage_trend(30)
        regression_analysis = self.analyze_coverage_regression()
        
        # Get coverage goals
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT module_name, target_percent, minimum_percent, priority
            FROM coverage_goals 
            ORDER BY priority, target_percent DESC
        """)
        goals = cursor.fetchall()
        conn.close()
        
        # Generate markdown report
        report = self._generate_markdown_report(trend_data, regression_analysis, goals)
        
        with open(output_file, 'w') as f:
            f.write(report)
        
        print(f"Coverage trend report generated: {output_file}")
    
    def _generate_markdown_report(self, trend_data: List[Dict], 
                                 regression_analysis: Dict, 
                                 goals: List[Tuple]) -> str:
        """Generate markdown coverage report."""
        current_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        report = f"""# Coverage Trend Analysis Report

**Generated**: {current_date}
**Analysis Period**: Last 30 days
**Total Measurements**: {len(trend_data)}

## Current Status

"""
        
        if trend_data:
            latest = trend_data[0]
            report += f"""- **Current Coverage**: {latest['coverage_percent']:.2f}%
- **Lines Covered**: {latest['lines_covered']}/{latest['lines_total']}
- **Latest Branch**: {latest['git_branch']}
- **Latest Commit**: {latest['git_commit']}
- **Environment**: {latest['environment']}

"""
        
        # Regression analysis
        report += "## Trend Analysis\n\n"
        
        status_emoji = {
            'regression': '🔴',
            'minor_regression': '🟡', 
            'stable': '🟢',
            'minor_improvement': '🟢',
            'improvement': '🟢',
            'insufficient_data': '⚪'
        }
        
        status = regression_analysis.get('status', 'unknown')
        emoji = status_emoji.get(status, '❓')
        
        report += f"{emoji} **Status**: {status.replace('_', ' ').title()}\n"
        
        if 'trend' in regression_analysis:
            trend = regression_analysis['trend']
            if trend > 0:
                report += f"📈 **Trend**: +{trend:.2f}% improvement\n"
            else:
                report += f"📉 **Trend**: {trend:.2f}% change\n"
        
        report += "\n"
        
        # Coverage goals
        report += "## Coverage Goals Status\n\n"
        report += "| Module | Target | Minimum | Priority | Status |\n"
        report += "|--------|--------|---------|----------|--------|\n"
        
        for goal in goals:
            module_name, target, minimum, priority = goal
            status_icon = "⏳"  # Default pending status
            report += f"| {module_name} | {target}% | {minimum}% | {priority} | {status_icon} |\n"
        
        # Historical trend
        if len(trend_data) > 1:
            report += "\n## Historical Trend (Last 30 days)\n\n"
            report += "| Date | Coverage | Change | Branch | Commit |\n"
            report += "|------|----------|--------|--------|---------|\n"
            
            for i, data in enumerate(trend_data[:10]):  # Show last 10 measurements
                change = ""
                if i < len(trend_data) - 1:
                    prev_coverage = trend_data[i + 1]['coverage_percent']
                    change_val = data['coverage_percent'] - prev_coverage
                    if change_val > 0:
                        change = f"+{change_val:.2f}%"
                    elif change_val < 0:
                        change = f"{change_val:.2f}%"
                    else:
                        change = "0.00%"
                
                date_str = data['date'][:10]  # Just the date part
                report += f"| {date_str} | {data['coverage_percent']:.2f}% | {change} | {data['git_branch']} | {data['git_commit']} |\n"
        
        # Recommendations
        report += "\n## Recommendations\n\n"
        
        if status == 'regression':
            report += "🔴 **Immediate Action Required**\n"
            report += "- Coverage has regressed significantly\n"
            report += "- Review recent changes and add missing tests\n"
            report += "- Consider blocking further changes until coverage improves\n\n"
        elif status == 'minor_regression':
            report += "🟡 **Attention Needed**\n"
            report += "- Minor coverage regression detected\n"
            report += "- Review recent commits for untested code\n"
            report += "- Add tests for new functionality\n\n"
        elif status == 'stable':
            report += "🟢 **Stable Coverage**\n"
            report += "- Coverage is stable\n"
            report += "- Continue current testing practices\n"
            report += "- Look for opportunities to improve critical modules\n\n"
        else:
            report += "🟢 **Positive Trend**\n"
            report += "- Coverage is improving\n"
            report += "- Great work on testing!\n"
            report += "- Continue focusing on high-priority modules\n\n"
        
        # Action items
        report += "### Action Items\n\n"
        report += "1. **Review Critical Modules**: Focus on authentication, JWT, and password modules\n"
        report += "2. **Integration Testing**: Expand end-to-end test coverage\n"
        report += "3. **Error Scenarios**: Test failure cases and edge conditions\n"
        report += "4. **Documentation**: Update test documentation and examples\n"
        
        return report
    
    def parse_tarpaulin_output(self, tarpaulin_log: str) -> Dict:
        """Parse tarpaulin output to extract coverage data."""
        coverage_data = {
            'timestamp': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'date': datetime.now().isoformat(),
            'modules': []
        }
        
        try:
            with open(tarpaulin_log, 'r') as f:
                content = f.read()
            
            # Extract overall coverage percentage
            import re
            coverage_match = re.search(r'(\d+\.\d+)% coverage', content)
            if coverage_match:
                coverage_data['coverage_percent'] = float(coverage_match.group(1))
            
            # Extract lines covered
            lines_match = re.search(r'(\d+)/(\d+) lines covered', content)
            if lines_match:
                coverage_data['lines_covered'] = int(lines_match.group(1))
                coverage_data['lines_total'] = int(lines_match.group(2))
            
            # Extract module-specific data
            module_pattern = r'src/([^:]+):\s*(\d+)/(\d+)'
            for match in re.finditer(module_pattern, content):
                module_data = {
                    'name': match.group(1).replace('/', '_'),
                    'path': f"src/{match.group(1)}",
                    'lines_covered': int(match.group(2)),
                    'lines_total': int(match.group(3)),
                    'coverage_percent': (int(match.group(2)) / int(match.group(3))) * 100 if int(match.group(3)) > 0 else 0
                }
                coverage_data['modules'].append(module_data)
        
        except Exception as e:
            print(f"Error parsing tarpaulin output: {e}")
        
        return coverage_data


def main():
    """Main entry point for the coverage trend tracker."""
    parser = argparse.ArgumentParser(description='Coverage Trend Tracking')
    parser.add_argument('--record', help='Record coverage from tarpaulin log file')
    parser.add_argument('--report', help='Generate trend report to file')
    parser.add_argument('--analyze', action='store_true', help='Analyze coverage trends')
    parser.add_argument('--days', type=int, default=30, help='Number of days for trend analysis')
    
    args = parser.parse_args()
    
    tracker = CoverageTrendTracker()
    
    if args.record:
        coverage_data = tracker.parse_tarpaulin_output(args.record)
        history_id = tracker.record_coverage(coverage_data)
        print(f"Coverage recorded with ID: {history_id}")
        print(f"Coverage: {coverage_data.get('coverage_percent', 0):.2f}%")
    
    if args.report:
        tracker.generate_coverage_report(args.report)
    
    if args.analyze:
        trend_data = tracker.get_coverage_trend(args.days)
        regression = tracker.analyze_coverage_regression()
        
        print(f"Coverage Trend Analysis ({args.days} days)")
        print("=" * 40)
        print(f"Measurements: {len(trend_data)}")
        
        if trend_data:
            latest = trend_data[0]
            print(f"Current Coverage: {latest['coverage_percent']:.2f}%")
            print(f"Latest Branch: {latest['git_branch']}")
            print(f"Latest Commit: {latest['git_commit']}")
        
        print(f"Status: {regression.get('status', 'unknown')}")
        if 'trend' in regression:
            trend = regression['trend']
            if trend > 0:
                print(f"Trend: +{trend:.2f}% improvement")
            else:
                print(f"Trend: {trend:.2f}% change")


if __name__ == '__main__':
    main()