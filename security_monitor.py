import tkinter as tk
import subprocess
import sqlite3
import psutil
import os
import time
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

root.mainloop()