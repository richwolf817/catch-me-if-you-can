import sys
import psutil
import sqlite3
import os
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QLabel,
    QTextEdit,
    QGridLayout,
    QFrame,
)

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont

TCC_DB = os.path.expanduser(
    "~/Library/Application Support/com.apple.TCC/TCC.db"
)

SERVICES = {
    "kTCCServiceScreenCapture": "Screen Access",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
}

SUSPICIOUS = [
    "nc",
    "netcat",
    "teamviewer",
    "anydesk",
    "rustdesk",
    "screenconnect",
    "logmein",
    "vnc",
]

BG = "#0f172a"
CARD = "#111827"
GREEN = "#22c55e"
RED = "#ef4444"
TEXT = "#e5e7eb"


class Card(QFrame):
    def __init__(self, title):
        super().__init__()

        self.setStyleSheet(f"""
            background-color: {CARD};
            border-radius: 18px;
            padding: 14px;
        """)

        layout = QVBoxLayout()

        self.title = QLabel(title)
        self.title.setStyleSheet(
            "color: white; font-size: 16px; font-weight: bold;"
        )

        self.status = QLabel("OK")
        self.status.setStyleSheet(
            f"color: {GREEN}; font-size: 28px; font-weight: bold;"
        )

        self.detail = QLabel("No detections")
        self.detail.setStyleSheet(
            f"color: {TEXT}; font-size: 12px;"
        )

        layout.addWidget(self.title)
        layout.addWidget(self.status)
        layout.addWidget(self.detail)

        self.setLayout(layout)


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Security Dashboard")
        self.setGeometry(100, 100, 1280, 860)

        self.setStyleSheet(f"""
            background-color: {BG};
        """)

        main = QVBoxLayout()

        title = QLabel("🛡 macOS Security Dashboard")
        title.setStyleSheet(
            "color: white; font-size: 30px; font-weight: bold;"
        )

        main.addWidget(title)

        grid = QGridLayout()

        self.cards = {}

        names = [
            "Screen Access",
            "Input Monitoring",
            "Accessibility",
            "Microphone",
            "Camera",
            "Full Disk Access",
        ]

        for i, name in enumerate(names):

            row = i // 3
            col = i % 3

            card = Card(name)

            self.cards[name] = card

            grid.addWidget(card, row, col)

        main.addLayout(grid)

        self.log = QTextEdit()
        self.log.setReadOnly(True)

        self.log.setStyleSheet(f"""
            background-color: {CARD};
            color: {TEXT};
            border-radius: 18px;
            padding: 12px;
            font-size: 13px;
        """)

        main.addWidget(self.log)

        self.setLayout(main)

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(5000)

        self.refresh()

    def get_permissions(self):
        findings = {}

        try:
            conn = sqlite3.connect(TCC_DB)
            cur = conn.cursor()

            cur.execute(
                "SELECT client,service,auth_value FROM access"
            )

            rows = cur.fetchall()

            for client, service, auth in rows:

                if auth == 2 and service in SERVICES:

                    category = SERVICES[service]

                    findings.setdefault(category, []).append(client)

            conn.close()

        except Exception as e:
            self.log.append(str(e))

        return findings

    def get_suspicious(self):

        results = []

        for proc in psutil.process_iter(["pid", "name"]):

            try:
                name = proc.info["name"]

                if not name:
                    continue

                low = name.lower()

                for s in SUSPICIOUS:

                    if s in low:

                        results.append(
                            f"Suspicious Process: {name} PID={proc.info['pid']}"
                        )

            except Exception:
                pass

        return results

    def refresh(self):

        permissions = self.get_permissions()

        for name, card in self.cards.items():

            if name in permissions:

                card.status.setText("ACTIVE")

                card.status.setStyleSheet(
                    f"color: {RED}; font-size: 28px; font-weight: bold;"
                )

                card.detail.setText(
                    ", ".join(permissions[name])[:80]
                )

            else:

                card.status.setText("OK")

                card.status.setStyleSheet(
                    f"color: {GREEN}; font-size: 28px; font-weight: bold;"
                )

                card.detail.setText("No detections")

        self.log.clear()

        suspicious = self.get_suspicious()

        if suspicious:

            for s in suspicious:

                self.log.append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] {s}"
                )

        else:

            self.log.append(
                f"[{datetime.now().strftime('%H:%M:%S')}] System clean"
            )


app = QApplication(sys.argv)

font = QFont("SF Pro Display", 11)
app.setFont(font)

window = Dashboard()
window.show()

sys.exit(app.exec())
