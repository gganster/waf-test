#!/bin/bash
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

cd /opt
git clone https://github.com/gganster/waf-test.git
cd waf-test
npm install

cat > /etc/systemd/system/waf-test.service << EOF
[Unit]
After=network.target

[Service]
ExecStart=/usr/bin/node /opt/waf-test/index.js
Restart=always
Environment=PORT=8080

[Install]
WantedBy=multi-user.target
EOF

systemctl enable waf-test
systemctl start waf-test
