#!/bin/bash

source .venv/bin/activate

python3 -m pip install -r requirements.txt

python3 security_dashboard.py
