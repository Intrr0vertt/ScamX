#!/bin/bash
echo ""
echo " ScamX - AI CyberShield Platform"
echo " Starting Flask backend..."
echo ""
cd "$(dirname "$0")/backend"
pip install -r requirements.txt --quiet
python main.py
