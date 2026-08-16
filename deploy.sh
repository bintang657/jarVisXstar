#!/data/data/com.termux/files/usr/bin/bash
set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  jarVisXstar Auto-Deploy Script    ${NC}"
echo -e "${GREEN}======================================${NC}"
OS="unknown"
if [[ -f /data/data/com.termux/files/usr/bin/bash ]]; then
    OS="termux"
    PKG_MANAGER="pkg"
    PYTHON_CMD="python3"
    PIP_CMD="python3 -m pip"
elif [[ -f /etc/os-release ]]; then
    OS="linux"
    PKG_MANAGER="apt"
    PYTHON_CMD="python3"
    PIP_CMD="python3 -m pip"
else
    echo -e "${RED}OS tidak dikenali. Hanya Termux dan Linux didukung.${NC}"
    exit 1
fi
echo -e "${YELLOW}OS terdeteksi: $OS${NC}"
echo -e "${YELLOW}Installing system dependencies...${NC}"
if [[ $OS == "termux" ]]; then
    $PKG_MANAGER update -y
    $PKG_MANAGER install python rust binutils libffi openssl redis -y
else
    sudo $PKG_MANAGER update -y
    sudo $PKG_MANAGER install python3 python3-pip git redis-server -y
fi
echo -e "${YELLOW}Installing Python dependencies...${NC}"
$PIP_CMD install --upgrade pip
$PIP_CMD install -r requirements.txt || $PIP_CMD install PyJWT redis bleach cryptography bcrypt flask django fastapi requests
if [[ ! -f .env ]]; then
    cat > .env << EOF
THRESHOLD=25
ADAPTIVE_THRESHOLD=True
HONEYPOT_RESPONSE_TYPE=fake_admin
REDIS_HOST=localhost
REDIS_PORT=6379
WEBHOOK_URL=
EOF
    echo -e "${GREEN}.env file created${NC}"
fi
if [[ $OS == "linux" ]]; then
    echo -e "${YELLOW}Setting up systemd service...${NC}"
    sudo cat > /etc/systemd/system/jarvisxstar.service << EOF
[Unit]
Description=jarVisXstar WAF Service
After=network.target redis.service
[Service]
Type=simple
User=$USER
WorkingDirectory=$PWD
ExecStart=/usr/bin/python3 examples/app_example.py
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable jarvisxstar.service
    sudo systemctl start jarvisxstar.service
    echo -e "${GREEN}Service started. Check status: sudo systemctl status jarvisxstar${NC}"
elif [[ $OS == "termux" ]]; then
    echo -e "${YELLOW}Termux: no systemd. Use cron or run manually.${NC}"
    echo -e "To run: python3 examples/app_example.py &"
    echo -e "To auto-start: add to ~/.bashrc"
fi
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}DEPLOYMENT COMPLETE!${NC}"
echo -e "${GREEN}======================================${NC}"