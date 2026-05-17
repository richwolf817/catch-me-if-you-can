# macOS Security Monitor

## Install dependency

pip3 install psutil

## Run

python3 security_monitor.py

## Notes

- Grant Terminal Full Disk Access in:
  System Settings -> Privacy & Security -> Full Disk Access

- The monitor checks:
  - Screen recording permissions
  - Input monitoring permissions
  - Accessibility permissions
  - Listening ports
  - Suspicious process names
