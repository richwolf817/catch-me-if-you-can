import tkinter as tk
import subprocess
import sqlite3
import psutil
import os
from datetime import datetime

TCC_DB = os.path.expanduser(
    '~/Library/Application Support/com.apple.TCC/TCC.db'
)

SENSITIVE_SERVICES = {
    'kTCCServiceScreenCapture': 'Screen Recording',
    'kTCCServiceListenEvent': 'Input Monitoring',
    'kTCCServiceAccessibility': 'Accessibility Control',
    'kTCCServiceMicrophone': 'Microphone',
    'kTCCServiceCamera': 'Camera',
    'kTCCServiceSystemPolicyAllFiles': 'Full Disk Access'
}

SUSPICIOUS_NAMES = [
    'nc',
    'netcat',
    'socat',
    'screenconnect',
    'teamviewer',
    'anydesk',
    'rustdesk',
    'vnc',
    'logmein'
]


class SecurityMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title('Security Monitor')
        self.root.geometry('500x600')
        self.root.attributes('-topmost', True)

        self.text = tk.Text(root, bg='black', fg='lime', font=('Menlo', 11))
        self.text.pack(fill=tk.BOTH, expand=True)

        self.update_dashboard()

    def log(self, msg):
        self.text.insert(tk.END, msg + '\n')

    def clear(self):
        self.text.delete('1.0', tk.END)

    def check_tcc_permissions(self):
        results = []

        try:
            conn = sqlite3.connect(TCC_DB)
            cursor = conn.cursor()

            cursor.execute(
                'SELECT client,service,auth_value FROM access'
            )

            rows = cursor.fetchall()

            for client, service, auth in rows:
                if service in SENSITIVE_SERVICES and auth == 2:
                    results.append(
                        f'{SENSITIVE_SERVICES[service]} -> {client}'
                    )

            conn.close()

        except Exception as e:
            results.append(f'TCC ERROR: {e}')

        return results

    def check_screen_capture_processes(self):
        suspicious = []

        try:
            output = subprocess.check_output(
                ['lsof', '-nP'], text=True
            )

            for line in output.splitlines():
                lower = line.lower()

                if 'screencapture' in lower:
                    suspicious.append(line)

                if 'capturekit' in lower:
                    suspicious.append(line)

        except Exception as e:
            suspicious.append(f'SCREEN CHECK ERROR: {e}')

        return suspicious

    def check_network_listeners(self):
        listeners = []

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    pid = conn.pid

                    try:
                        proc = psutil.Process(pid)
                        pname = proc.name()
                    except:
                        pname = 'unknown'

                    listeners.append(
                        f'{pname} listening on {conn.laddr.port}'
                    )

        except Exception as e:
            listeners.append(f'NETWORK ERROR: {e}')

        return listeners

    def check_suspicious_processes(self):
        findings = []

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()

                for bad in SUSPICIOUS_NAMES:
                    if bad in name:
                        findings.append(
                            f'Suspicious process: {name} PID={proc.info["pid"]}'
                        )

            except:
                pass

        return findings

    def update_dashboard(self):
        self.clear()

        self.log('=' * 60)
        self.log('MACOS SECURITY MONITOR')
        self.log(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        self.log('=' * 60)
        self.log('')

        self.log('[ Sensitive Permissions ]')

        perms = self.check_tcc_permissions()

        if perms:
            for p in perms:
                self.log(f'  {p}')
        else:
            self.log('  No sensitive permissions found')

        self.log('')
        self.log('[ Screen Capture Activity ]')

        captures = self.check_screen_capture_processes()

        if captures:
            for c in captures:
                self.log(f'  {c}')
        else:
            self.log('  No screen capture processes detected')

        self.log('')
        self.log('[ Listening Ports ]')

        listeners = self.check_network_listeners()

        for l in listeners:
            self.log(f'  {l}')

        self.log('')
        self.log('[ Suspicious Process Names ]')

        suspicious = self.check_suspicious_processes()

        if suspicious:
            for s in suspicious:
                self.log(f'  {s}')
        else:
            self.log('  None detected')

        self.root.after(5000, self.update_dashboard)


if __name__ == '__main__':
    root = tk.Tk()
    app = SecurityMonitor(root)
    root.mainloop()
