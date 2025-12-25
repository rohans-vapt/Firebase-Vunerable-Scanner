#!/usr/bin/env python3
"""
FIREBASE PARALLEL SECURITY SCANNER WITH ANIMATION
Scans multiple Firebase projects in parallel with visual feedback
"""

import requests
import json
import sys
import re
import time
import os
import uuid
import threading
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import argparse
import queue
import itertools
import random

class Animation:
    """ASCII animation for scanning process."""
    
    SPINNER_FRAMES = [
        "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
    ]
    
    SCANNING_FRAMES = [
        "[▰▱▱▱▱] 10%",
        "[▰▰▱▱▱] 20%",
        "[▰▰▰▱▱] 40%",
        "[▰▰▰▰▱] 60%",
        "[▰▰▰▰▰] 80%",
        "[▰▰▰▰▰] 100%"
    ]
    
    FIRE_ANIMATION = [
        """
        (          )
         )        (
        (          )
    .-'----------`-.
   ( C\/       \/A )
    \_/\/     \/ \_/
      \_/     \_/
        \_____/
        """,
        """
        (   🔥    )
         )        (
        (   🔥    )
    .-'----------`-.
   ( C\/       \/A )
    \_/\/     \/ \_/
      \_/     \_/
        \_____/
        """,
        """
        (   🔥🔥  )
         )  🔥    (
        (   🔥🔥  )
    .-'----------`-.
   ( C\/       \/A )
    \_/\/     \/ \_/
      \_/     \_/
        \_____/
        """,
        """
        (  🔥🔥🔥 )
         ) 🔥🔥  (
        (  🔥🔥🔥 )
    .-'----------`-.
   ( C\/       \/A )
    \_/\/     \/ \_/
      \_/     \_/
        \_____/
        """
    ]
    
    @staticmethod
    def spinner(frame: int) -> str:
        """Get spinner frame."""
        return Animation.SPINNER_FRAMES[frame % len(Animation.SPINNER_FRAMES)]
    
    @staticmethod
    def progress_bar(percent: int, width: int = 20) -> str:
        """Create a progress bar."""
        filled = int(width * percent / 100)
        bar = "█" * filled + "░" * (width - filled)
        return f"[{bar}] {percent}%"
    
    @staticmethod
    def fire_animation(frame: int) -> str:
        """Get fire animation frame for vulnerabilities."""
        return Animation.FIRE_ANIMATION[frame % len(Animation.FIRE_ANIMATION)]
    
    @staticmethod
    def scanning_animation(frame: int) -> str:
        """Get scanning animation frame."""
        idx = frame % len(Animation.SCANNING_FRAMES)
        return Animation.SCANNING_FRAMES[idx]

class FirestoreParallelScanner:
    def __init__(self, max_workers: int = 5):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Firestore-Parallel-Scanner/3.0',
            'Content-Type': 'application/json'
        })
        self.timeout = 10
        self.max_workers = max_workers
        self.results_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self.animation_running = False
        self.animation_thread = None
        
    def display_banner(self):
        """Display animated banner."""
        banner = """
╔══════════════════════════════════════════════════════════╗
║      🔥 FIREBASE PARALLEL SECURITY SCANNER 🔥            ║
║                                                          ║
║  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   ║
║  ░███╗░░░███╗░█████╗░██████╗░██╗░░░░░░██████╗░░░░░░░░   ║
║  ░████╗░████║██╔══██╗██╔══██╗██║░░░░░██╔════╝░░░░░░░░   ║
║  ░██╔████╔██║███████║██████╔╝██║░░░░░╚█████╗░░░░░░░░░   ║
║  ░██║╚██╔╝██║██╔══██║██╔═══╝░██║░░░░░░╚═══██╗░░░░░░░░   ║
║  ░██║░╚═╝░██║██║░░██║██║░░░░░███████╗██████╔╝░░░░░░░░   ║
║  ░╚═╝░░░░░╚═╝╚═╝░░╚═╝╚═╝░░░░░╚══════╝╚═════╝░░░░░░░░░   ║
║  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   ║
║                                                          ║
║  ⚡ Parallel Scanning • 🎯 Real-time Results • 📊 Analytics ║
╚══════════════════════════════════════════════════════════╝
        """
        print(banner)
        
        # Animated loading message
        for i in range(3):
            dots = "." * (i + 1)
            print(f"\r[*] Initializing Parallel Scanner{dots}", end="")
            time.sleep(0.3)
        print()
    
    def animate_scanning(self, total_projects: int):
        """Display animated scanning progress."""
        self.animation_running = True
        frame = 0
        
        while self.animation_running:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            # Get current progress from queue
            current_results = []
            while not self.progress_queue.empty():
                current_results.append(self.progress_queue.get())
            
            completed = len([r for r in current_results if r.get('completed', False)])
            vulnerable = len([r for r in current_results if r.get('vulnerable', False)])
            
            # Display animation
            print("\n" + "="*70)
            print("🔥 PARALLEL FIREBASE SECURITY SCAN IN PROGRESS 🔥")
            print("="*70)
            
            # Spinner and progress
            spinner = Animation.spinner(frame)
            progress = int((completed / total_projects) * 100) if total_projects > 0 else 0
            progress_bar = Animation.progress_bar(progress)
            
            print(f"\n{spinner} {progress_bar}")
            print(f"📊 Progress: {completed}/{total_projects} projects scanned")
            print(f"⚠️  Vulnerable: {vulnerable} project(s) found")
            
            # Show scanning animation
            scan_anim = Animation.scanning_animation(frame)
            print(f"\n{scan_anim}")
            
            # Show current scans
            print(f"\n{'─'*70}")
            print("CURRENT SCANS:")
            print(f"{'─'*70}")
            
            for result in current_results[-5:]:  # Show last 5 results
                project = result.get('project_id', 'Unknown')
                status = result.get('status', 'Scanning...')
                if result.get('completed', False):
                    if result.get('vulnerable', False):
                        status = "🔴 VULNERABLE"
                    else:
                        status = "✅ SECURE"
                
                print(f"  {Animation.spinner(frame)} {project}: {status}")
            
            # Show fire animation if vulnerabilities found
            if vulnerable > 0:
                print(f"\n{'!'*70}")
                fire = Animation.fire_animation(frame)
                print(fire)
                print(f"    ⚠️  {vulnerable} VULNERABLE PROJECT(S) DETECTED! ⚠️  ")
                print(f"{'!'*70}")
            
            frame += 1
            time.sleep(0.1)
    
    def test_single_project(self, project_id: str) -> Dict:
        """Test a single Firebase project for vulnerabilities."""
        result = {
            'project_id': project_id,
            'vulnerable': False,
            'severity': 'NONE',
            'issues': [],
            'start_time': datetime.now(timezone.utc).isoformat(),
            'completed': False
        }
        
        # Update progress
        self.progress_queue.put(result)
        
        try:
            # Test Firestore endpoints
            endpoints = [
                f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents",
                f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/test",
            ]
            
            for endpoint in endpoints:
                try:
                    # Test READ access
                    response = self.session.get(endpoint, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        result['vulnerable'] = True
                        result['severity'] = 'CRITICAL'
                        result['issues'].append({
                            'endpoint': endpoint,
                            'access': 'READ',
                            'status_code': 200
                        })
                        break
                    
                    # Test WRITE access if collection doesn't exist
                    elif response.status_code == 404:
                        test_data = {
                            'fields': {
                                'scanner_test': {'stringValue': 'security_scan'},
                                'timestamp': {'integerValue': int(time.time())}
                            }
                        }
                        
                        write_response = self.session.post(endpoint, json=test_data, timeout=self.timeout)
                        
                        if write_response.status_code in [200, 201]:
                            result['vulnerable'] = True
                            result['severity'] = 'CRITICAL'
                            result['issues'].append({
                                'endpoint': endpoint,
                                'access': 'WRITE',
                                'status_code': write_response.status_code
                            })
                            
                            # Clean up
                            try:
                                write_data = write_response.json()
                                if 'name' in write_data:
                                    delete_url = write_data['name']
                                    self.session.delete(delete_url, timeout=5)
                            except:
                                pass
                            break
                
                except requests.exceptions.RequestException:
                    continue
            
            result['completed'] = True
            result['end_time'] = datetime.now(timezone.utc).isoformat()
            result['duration'] = (datetime.fromisoformat(result['end_time'].replace('Z', '+00:00')) - 
                                 datetime.fromisoformat(result['start_time'].replace('Z', '+00:00'))).total_seconds()
            
            # Update progress with completed result
            self.progress_queue.put(result)
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            result['completed'] = True
            self.progress_queue.put(result)
            return result
    
    def log_alert_to_firestore(self, project_id: str, scan_result: Dict) -> bool:
        """Log security alert to Firestore."""
        if not scan_result['vulnerable']:
            return False
        
        alert_data = {
            'fields': {
                'alert_id': {'stringValue': str(uuid.uuid4())},
                'project_id': {'stringValue': project_id},
                'timestamp': {'stringValue': datetime.now(timezone.utc).isoformat()},
                'severity': {'stringValue': scan_result['severity']},
                'message': {'stringValue': f"Firestore project '{project_id}' is VULNERABLE! Immediate action required to secure your database."},
                'scanner': {'stringValue': 'Firebase Parallel Scanner v3.0'},
                'action_required': {'stringValue': 'Update Firestore security rules immediately'}
            }
        }
        
        alerts_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/alerts"
        
        try:
            response = self.session.post(alerts_url, json=alert_data, timeout=self.timeout)
            return response.status_code in [200, 201]
        except:
            return False
    
    def scan_projects_parallel(self, project_ids: List[str], log_alerts: bool = True) -> List[Dict]:
        """Scan multiple projects in parallel."""
        print(f"\n🚀 Starting parallel scan of {len(project_ids)} project(s)...")
        print(f"👥 Using {self.max_workers} parallel workers")
        print(f"⏱️  Estimated time: {len(project_ids) * 2 // self.max_workers} seconds\n")
        
        # Start animation thread
        self.animation_thread = threading.Thread(
            target=self.animate_scanning,
            args=(len(project_ids),),
            daemon=True
        )
        self.animation_thread.start()
        
        time.sleep(1)  # Let animation start
        
        all_results = []
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all scan tasks
            future_to_project = {
                executor.submit(self.test_single_project, project_id): project_id
                for project_id in project_ids
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_project):
                project_id = future_to_project[future]
                try:
                    result = future.result()
                    all_results.append(result)
                    
                    # Log alert if vulnerable
                    if result['vulnerable'] and log_alerts:
                        executor.submit(self.log_alert_to_firestore, project_id, result)
                    
                except Exception as e:
                    print(f"[!] Error scanning {project_id}: {e}")
        
        # Stop animation
        self.animation_running = False
        if self.animation_thread:
            self.animation_thread.join(timeout=1)
        
        return all_results
    
    def generate_summary_report(self, results: List[Dict]) -> str:
        """Generate summary report with ASCII art."""
        vulnerable = [r for r in results if r.get('vulnerable', False)]
        secure = [r for r in results if not r.get('vulnerable', False)]
        errors = [r for r in results if r.get('error')]
        
        report = []
        
        # ASCII Art Header based on results
        if vulnerable:
            report.append("""
    ╔══════════════════════════════════════════════════════╗
    ║                    🔥 CRITICAL ALERT 🔥               ║
    ║                  VULNERABILITIES FOUND                ║
    ╚══════════════════════════════════════════════════════╝
            """)
        else:
            report.append("""
    ╔══════════════════════════════════════════════════════╗
    ║                     ✅ ALL CLEAR ✅                   ║
    ║                   NO VULNERABILITIES                  ║
    ╚══════════════════════════════════════════════════════╝
            """)
        
        report.append("\n" + "="*70)
        report.append("📊 PARALLEL SCAN SUMMARY REPORT")
        report.append("="*70)
        
        # Stats with emojis
        report.append(f"\n📈 SCAN STATISTICS:")
        report.append(f"   • 📋 Total Projects: {len(results)}")
        report.append(f"   • 🔴 Vulnerable: {len(vulnerable)}")
        report.append(f"   • ✅ Secure: {len(secure)}")
        report.append(f"   • ⚠️  Errors: {len(errors)}")
        
        if vulnerable:
            report.append(f"\n🚨 VULNERABLE PROJECTS (REQUIRE IMMEDIATE ACTION):")
            report.append("─" * 50)
            for i, result in enumerate(vulnerable, 1):
                project = result['project_id']
                severity = result.get('severity', 'UNKNOWN')
                issues = len(result.get('issues', []))
                
                report.append(f"\n{i}. 🔥 {project}")
                report.append(f"   ├─ Severity: {severity}")
                report.append(f"   ├─ Issues Found: {issues}")
                report.append(f"   └─ Message: Firestore project '{project}' is VULNERABLE!")
                report.append(f"      Immediate action required to secure your database.")
        
        if secure:
            report.append(f"\n✅ SECURE PROJECTS:")
            report.append("─" * 50)
            for i, result in enumerate(secure[:5], 1):  # Show first 5 only
                project = result['project_id']
                report.append(f"{i}. {project}")
            
            if len(secure) > 5:
                report.append(f"... and {len(secure) - 5} more secure projects")
        
        # Recommendations
        report.append("\n" + "="*70)
        report.append("🎯 IMMEDIATE ACTION REQUIRED")
        report.append("="*70)
        
        if vulnerable:
            report.append("\nFor each vulnerable project, immediately:")
            report.append("1. 🔧 Go to Firebase Console → Firestore → Rules")
            report.append("2. 🔒 Replace any 'if true' with 'request.auth != null'")
            report.append("3. 🚀 Deploy updated rules")
            report.append("4. 🧪 Test in Rules Playground")
            report.append("5. 👀 Monitor access logs")
            
            report.append("\n📝 Sample secure rules:")
            report.append("""
   service cloud.firestore {
     match /databases/{database}/documents {
       match /{document=**} {
         allow read, write: if request.auth != null;
       }
     }
   }
            """)
        else:
            report.append("\n✅ All projects appear secure. Maintain security by:")
            report.append("   • 🔄 Regular security reviews")
            report.append("   • 🛡️  Enabling Firebase App Check")
            report.append("   • 📊 Monitoring access patterns")
            report.append("   • 🧪 Regular penetration testing")
        
        report.append("\n" + "="*70)
        report.append("Generated by Firebase Parallel Security Scanner v3.0")
        report.append("="*70)
        
        return "\n".join(report)
    
    def save_ascii_report(self, report: str, filename: str = None):
        """Save report with ASCII art."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"firebase_parallel_scan_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            return True, filename
        except Exception as e:
            return False, str(e)
    
    def create_visual_chart(self, results: List[Dict]):
        """Create ASCII visual chart of results."""
        vulnerable = len([r for r in results if r.get('vulnerable', False)])
        secure = len([r for r in results if not r.get('vulnerable', False)])
        total = len(results)
        
        if total == 0:
            return "No data to display"
        
        vuln_percent = (vulnerable / total) * 100
        secure_percent = (secure / total) * 100
        
        chart = []
        chart.append("\n📊 VISUAL DISTRIBUTION CHART")
        chart.append("="*50)
        
        # Bar chart for vulnerabilities
        vuln_bar = "█" * int(vuln_percent / 2)
        secure_bar = "█" * int(secure_percent / 2)
        
        chart.append(f"\nVULNERABLE [{vulnerable}/{total}]")
        chart.append(f"{vuln_bar} {vuln_percent:.1f}%")
        
        chart.append(f"\nSECURE [{secure}/{total}]")
        chart.append(f"{secure_bar} {secure_percent:.1f}%")
        
        # Pie chart ASCII
        chart.append("\n\n🍰 PIE CHART REPRESENTATION:")
        if vulnerable > 0 and secure > 0:
            chart.append("""
       ______
     /        \\
    /    🔴    \\
   |  {0:.0f}%   |  Vulnerable
    \\    🟢    /
     \\______/
        """.format(vuln_percent))
        elif vulnerable > 0:
            chart.append("""
       ______
     /        \\
    /   ALL    \\
   |   🔴🔥   |  ALL VULNERABLE!
    \\          /
     \\______/
            """)
        else:
            chart.append("""
       ______
     /        \\
    /   ALL    \\
   |   🟢✅    |  ALL SECURE!
    \\          /
     \\______/
            """)
        
        return "\n".join(chart)

def main():
    """Main entry point with command line interface."""
    parser = argparse.ArgumentParser(
        description="Firebase Parallel Security Scanner with Animation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single project
  python scanner.py messagesystem-eeeff
  
  # Scan multiple projects with 10 workers
  python scanner.py --file projects.txt --workers 10
  
  # Scan without alert logging
  python scanner.py project1 project2 project3 --no-alerts
  
  # Quick scan with minimal output
  python scanner.py --quick project-id

Visual Features:
  • Real-time ASCII animations
  • Parallel processing
  • Progress bars and spinners
  • Colorful ASCII art reports
  • Visual charts and graphs

Legal: Only scan projects you own or have permission to test.
        """
    )
    
    parser.add_argument("projects", nargs="*", help="Project IDs to scan")
    parser.add_argument("--file", help="File containing project IDs (one per line)")
    parser.add_argument("--workers", type=int, default=5, help="Number of parallel workers (default: 5)")
    parser.add_argument("--no-alerts", action="store_true", help="Don't log alerts to Firestore")
    parser.add_argument("--quick", action="store_true", help="Quick scan mode (no animation)")
    parser.add_argument("--output", help="Output report filename")
    parser.add_argument("--visual", action="store_true", help="Generate visual charts")
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = FirestoreParallelScanner(max_workers=args.workers)
    
    # Display banner
    scanner.display_banner()
    
    # Authorization check
    print("\n" + "="*60)
    print("🔐 AUTHORIZATION REQUIRED")
    print("="*60)
    print("\nThis tool is for AUTHORIZED security testing only.")
    print("You must OWN the projects or have WRITTEN PERMISSION.\n")
    
    auth = input("Type 'AUTHORIZE' to continue: ").strip().upper()
    if auth != "AUTHORIZE":
        print("\n[!] Authorization not confirmed. Exiting.")
        sys.exit(1)
    
    # Collect project IDs
    project_ids = []
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                project_ids = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(project_ids)} projects from {args.file}")
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            sys.exit(1)
    
    project_ids.extend(args.projects)
    
    if not project_ids:
        print("\n[!] No projects specified.")
        print("[*] Provide project IDs or use --file option")
        parser.print_help()
        sys.exit(1)
    
    print(f"\n🎯 Target Projects: {len(project_ids)}")
    print(f"⚡ Parallel Workers: {args.workers}")
    print(f"📡 Alert Logging: {'Disabled' if args.no_alerts else 'Enabled'}")
    print(f"🎨 Animation: {'Disabled' if args.quick else 'Enabled'}")
    
    input("\nPress Enter to start scanning...")
    
    try:
        # Run parallel scan
        if args.quick:
            print(f"\n[*] Starting quick scan...")
            results = []
            for i, project_id in enumerate(project_ids, 1):
                print(f"  [{i}/{len(project_ids)}] Scanning {project_id}...", end="\r")
                result = scanner.test_single_project(project_id)
                results.append(result)
                if result['vulnerable'] and not args.no_alerts:
                    scanner.log_alert_to_firestore(project_id, result)
            print()
        else:
            results = scanner.scan_projects_parallel(
                project_ids,
                log_alerts=not args.no_alerts
            )
        
        # Generate and display report
        print("\n" + "="*70)
        print("📋 GENERATING FINAL REPORT")
        print("="*70)
        
        time.sleep(1)  # Dramatic pause
        
        report = scanner.generate_summary_report(results)
        print(report)
        
        # Add visual chart if requested
        if args.visual:
            chart = scanner.create_visual_chart(results)
            print(chart)
        
        # Save report
        success, filename = scanner.save_ascii_report(
            report,
            args.output if args.output else None
        )
        
        if success:
            print(f"\n💾 Report saved to: {filename}")
        else:
            print(f"\n[!] Error saving report: {filename}")
        
        # Final status with emoji
        vulnerable = len([r for r in results if r.get('vulnerable', False)])
        if vulnerable > 0:
            print(f"\n{'!'*70}")
            print(f"🔥 FINAL STATUS: {vulnerable} VULNERABLE PROJECT(S) FOUND!")
            print(f"   Immediate action required to secure these databases.")
            print(f"{'!'*70}")
            sys.exit(2)
        else:
            print(f"\n{'='*70}")
            print(f"🎉 FINAL STATUS: ALL PROJECTS SECURE!")
            print(f"   Continue regular security monitoring.")
            print(f"{'='*70}")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(f"\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Simple demo mode if no arguments
    if len(sys.argv) == 1:
        scanner = FirestoreParallelScanner()
        scanner.display_banner()
        
        print("\n" + "="*60)
        print("🎮 DEMO MODE - FIREBASE SECURITY SCANNER")
        print("="*60)
        print("\nChoose an option:")
        print("1. 📋 Scan single project")
        print("2. 🚀 Parallel scan multiple projects")
        print("3. 📊 View sample report")
        print("4. 🆘 Help")
        print("5. 🚪 Exit")
        
        choice = input("\nEnter choice (1-5): ").strip()
        
        if choice == "1":
            project_id = input("Enter project ID: ").strip()
            if project_id:
                print(f"\n[*] Scanning {project_id}...")
                result = scanner.test_single_project(project_id)
                
                if result['vulnerable']:
                    print(f"\n{'!'*50}")
                    print(f"  Firestore project '{project_id}' is VULNERABLE!")
                    print(f"  Immediate action required to secure your database.")
                    print(f"{'!'*50}")
                else:
                    print(f"\nFirestore project '{project_id}' appears secure.")
        
        elif choice == "2":
            print("\nEnter project IDs (one per line, empty line to finish):")
            projects = []
            while True:
                project = input(f"Project {len(projects) + 1}: ").strip()
                if not project:
                    break
                projects.append(project)
            
            if projects:
                print(f"\n[*] Starting parallel scan of {len(projects)} projects...")
                results = scanner.scan_projects_parallel(projects, log_alerts=False)
                
                vulnerable = len([r for r in results if r['vulnerable']])
                if vulnerable > 0:
                    print(f"\nFound {vulnerable} vulnerable project(s)!")
                else:
                    print(f"\nAll projects appear secure!")
        
        elif choice == "3":
            print("\n📊 SAMPLE REPORT PREVIEW:")
            print("="*60)
            sample_results = [
                {'project_id': 'test-project-1', 'vulnerable': True, 'severity': 'CRITICAL'},
                {'project_id': 'test-project-2', 'vulnerable': False},
                {'project_id': 'test-project-3', 'vulnerable': True, 'severity': 'HIGH'},
            ]
            report = scanner.generate_summary_report(sample_results)
            print(report)
        
        elif choice == "4":
            print("\n" + "="*60)
            print("HELP - FIREBASE SECURITY SCANNER")
            print("="*60)
            print("\nThis tool scans Firebase Firestore databases for")
            print("public access vulnerabilities.")
            print("\nKey Features:")
            print("• 🔍 Detects public read/write access")
            print("• ⚡ Parallel scanning for multiple projects")
            print("• 🎨 Real-time ASCII animations")
            print("• 📊 Visual reports with charts")
            print("• 🔔 Alert logging to vulnerable databases")
            print("\nUsage: python scanner.py [OPTIONS] PROJECT_ID...")
            print("\nFor command-line options, run: python scanner.py --help")
        
        elif choice == "5":
            print("\n👋 Exiting... Stay secure!")
        
        else:
            print("\n[!] Invalid choice")
    
    else:
        main()