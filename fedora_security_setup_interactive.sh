#!/bin/bash

set -e

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
BOLD="\e[1m"
RESET="\e[0m"

show_help() {
  echo -e "${BOLD}Fedora Security Workstation Setup Script${RESET}"
  echo ""
  echo -e "${YELLOW}Usage:${RESET} ./fedora_security_setup_interactive.sh [--help] [--update]"
  echo ""
  echo "Options:"
  echo "  --help        Show this help message"
  echo "  --update      Only update all installed packages and check OS"
  echo ""
  echo "This script installs tools and configurations tailored for:"
  echo " - Developer productivity"
  echo " - Offensive security (red team)"
  echo " - Defensive security and DFIR (blue team)"
  echo " - Cloud and container engineering"
  echo " - Privacy and sandboxing environments"
  echo ""
  echo "You'll be prompted to select which categories to install."
  echo ""
  exit 0
}

declare -A install_status

map_package_name() {
  case "$1" in
    postgresql-devel) echo "libpq-devel" ;;
    zlib-devel) echo "zlib-ng-devel" ;;
    volatility3) echo "python3-volatility3" ;; # if available or fallback to pip
    auditd) echo "audit" ;;
    *) echo "$1" ;;
  esac
}

safe_install() {
  for pkg in "$@"; do
    resolved_pkg=$(map_package_name "$pkg")
    if ! dnf5 info "$resolved_pkg" >/dev/null 2>&1; then
      echo -e "${YELLOW}⚠️  Package not found:${RESET} $pkg — skipping."
      install_status["$pkg"]="❌ Not Found"
      install_fallback "$pkg"
    else
      echo -e "${BLUE}📦 Installing:${RESET} $resolved_pkg"
      if sudo dnf5 install --allowerasing -y "$resolved_pkg"; then
        install_status["$pkg"]="✅ Success"
      else
        install_status["$pkg"]="❌ Failed"
        install_fallback "$pkg"
      fi
    fi
  done
}

install_fallback() {
  case "$1" in
    sqlmap)
      echo -e "${YELLOW}⚠️ Installing sqlmap via pip...${RESET}"
      if pip3 install sqlmap; then
        install_status["sqlmap"]="✅ Installed via pip"
      else
        install_status["sqlmap"]="❌ Fallback Failed"
      fi
      ;;
    burpsuite)
      echo -e "${YELLOW}⚠️ Burp Suite not available via Flatpak. Manual download required.${RESET}"
      echo -e "${YELLOW}👉 Download from:${RESET} https://portswigger.net/burp"
      install_status["burpsuite"]="⚠️ Manual download required - https://portswigger.net/burp"
      ;;
    ghidra)
      echo -e "${YELLOW}⚠️ Installing Ghidra via Flatpak...${RESET}"
      if flatpak install -y flathub org.ghidra_sre.Ghidra; then
        install_status["ghidra"]="✅ Installed via flatpak"
      else
        install_status["ghidra"]="❌ Flatpak install failed"
      fi
      ;;
    tcptraceroute)
      echo -e "${YELLOW}⚠️ Creating traceroute -T alias for tcptraceroute...${RESET}"
      echo 'alias tcptraceroute="traceroute -T"' >> ~/.bashrc
      echo 'alias tcptraceroute="traceroute -T"' >> ~/.zshrc
      install_status["tcptraceroute"]="✅ Redirected to traceroute -T"
      ;;
    dirb)
      echo -e "${YELLOW}⚠️ Cloning and building DIRB from GitHub...${RESET}"
      mkdir -p ~/Tools
      if [ ! -d ~/Tools/dirb ]; then
        git clone https://github.com/v0re/dirb.git ~/Tools/dirb && install_status["dirb"]="✅ Cloned from GitHub" || install_status["dirb"]="❌ Fallback Failed"
      else
        echo -e "${GREEN}✔️ DIRB already cloned. Pulling latest changes...${RESET}"
        cd ~/Tools/dirb && git pull && install_status["dirb"]="✅ Updated"
      fi
      ;;
    nikto)
      echo -e "${YELLOW}⚠️ Cloning Nikto from GitHub...${RESET}"
      mkdir -p ~/Tools
      if [ ! -d ~/Tools/nikto ]; then
        git clone https://github.com/sullo/nikto ~/Tools/nikto && install_status["nikto"]="✅ Cloned from GitHub" || install_status["nikto"]="❌ Fallback Failed"
      else
        echo -e "${GREEN}✔️ Nikto already cloned. Pulling latest changes...${RESET}"
        cd ~/Tools/nikto && git pull && install_status["nikto"]="✅ Updated"
      fi
      ;;
    metasploit)
      echo -e "${YELLOW}⚠️ Installing Metasploit Framework manually...${RESET}"
      safe_install ruby ruby-devel zlib-devel libxml2-devel libxslt-devel postgresql-devel libpq-devel gcc make
      if ! command -v bundler >/dev/null; then
        echo -e "${YELLOW}📦 Installing bundler...${RESET}"
        gem install bundler && install_status["bundler"]="✅ Installed" || install_status["bundler"]="❌ Failed"
      else
        install_status["bundler"]="✅ Already Installed"
      fi
      mkdir -p ~/Tools
      if [ ! -d ~/Tools/metasploit ]; then
        if git clone https://github.com/rapid7/metasploit-framework ~/Tools/metasploit; then
          cd ~/Tools/metasploit
          missing_gems=$(bundle check || true)
          if [[ "$missing_gems" == *"Install missing gems"* ]]; then
            echo -e "${BLUE}📦 Installing missing gems with bundle install...${RESET}"
            if bundle install --path vendor/bundle; then
              install_status["metasploit"]="✅ Installed from GitHub"
            else
              install_status["metasploit"]="❌ Bundle install failed"
            fi
          else
            install_status["metasploit"]="✅ Already satisfied"
          fi
        else
          install_status["metasploit"]="❌ Git clone failed"
        fi
      else
        echo -e "${GREEN}✔️ Metasploit already cloned. Pulling latest changes...${RESET}"
        cd ~/Tools/metasploit && git pull
        missing_gems=$(bundle check || true)
        if [[ "$missing_gems" == *"Install missing gems"* ]]; then
          echo -e "${BLUE}📦 Installing missing gems with bundle install...${RESET}"
          if bundle install --path vendor/bundle; then
            install_status["metasploit"]="✅ Updated from GitHub"
          else
            install_status["metasploit"]="❌ Bundle update failed"
          fi
        else
          install_status["metasploit"]="✅ Already satisfied"
        fi
      fi
      ;;
    zap)
      echo -e "${YELLOW}⚠️ Installing OWASP ZAP via Flatpak...${RESET}"
      if flatpak install -y flathub org.zaproxy.ZAP; then
        install_status["zap"]="✅ Installed via flatpak"
      else
        install_status["zap"]="❌ Flatpak install failed"
      fi
      ;;
    volatility3)
      echo -e "${YELLOW}⚠️ Installing Volatility3 via pip fallback...${RESET}"
      if pip install volatility3; then
        install_status["volatility3"]="✅ Installed via pip"
      else
        install_status["volatility3"]="❌ Fallback Failed"
      fi
      ;;
    auditd)
      echo -e "${YELLOW}⚠️ Attempting to install 'audit' package for auditd functionality...${RESET}"
      if sudo dnf5 install -y audit; then
        sudo systemctl enable --now auditd || true
        install_status["auditd"]="✅ Installed via audit package"
      else
        install_status["auditd"]="❌ Fallback Failed"
      fi
      ;;
    terraform)
      echo -e "${YELLOW}⚠️ Installing Terraform via direct binary fallback...${RESET}"
      TERRAFORM_VERSION=$(curl -s https://checkpoint-api.hashicorp.com/v1/check/terraform | jq -r .current_version)
      curl -LO "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip"
      unzip terraform_${TERRAFORM_VERSION}_linux_amd64.zip
      sudo mv terraform /usr/local/bin/
      rm terraform_${TERRAFORM_VERSION}_linux_amd64.zip
      install_status["terraform"]="✅ Installed via fallback"
      ;;

    kubectl)
      echo -e "${YELLOW}⚠️ Installing kubectl via official release...${RESET}"
      curl -LO "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
      chmod +x kubectl && sudo mv kubectl /usr/local/bin/
      install_status["kubectl"]="✅ Installed via fallback"
      ;;

    awscli)
      echo -e "${YELLOW}⚠️ Installing AWS CLI via pip fallback...${RESET}"
      if pip install awscli --upgrade; then
        install_status["awscli"]="✅ Installed via pip"
      else
        install_status["awscli"]="❌ Fallback Failed"
      fi
      ;;

    google-cloud-sdk)
      echo -e "${YELLOW}⚠️ Installing Google Cloud SDK via fallback...${RESET}"
      mkdir -p ~/Tools/gcloud-install
      cd ~/Tools/gcloud-install || exit
      GCS_URL="https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-456.0.0-linux-x86_64.tar.gz"
      curl -LO "$GCS_URL"
      if tar -xf google-cloud-cli-*-linux-x86_64.tar.gz; then
        ./google-cloud-sdk/install.sh --quiet
        install_status["google-cloud-sdk"]="✅ Installed via fallback"
      else
        echo -e "${RED}❌ Failed to extract Google Cloud SDK archive.${RESET}"
        install_status["google-cloud-sdk"]="❌ Fallback Failed"
      fi
      ;;
    virtualbox)
      echo -e "${YELLOW}⚠️ Installing VirtualBox from Oracle repository...${RESET}"
      sudo bash -c 'cat > /etc/yum.repos.d/virtualbox.repo <<"EOF"
[virtualbox]
name=VirtualBox for Fedora $releasever - $basearch
baseurl=https://download.virtualbox.org/virtualbox/rpm/fedora/$releasever/$basearch
enabled=1
gpgcheck=1
gpgkey=https://www.virtualbox.org/download/oracle_vbox.asc
EOF'
      if sudo dnf5 install -y VirtualBox; then
        install_status["virtualbox"]="✅ Installed via fallback"
      else
        install_status["virtualbox"]="❌ Fallback Failed"
      fi
      ;;
    packer)
      echo -e "${YELLOW}⚠️ Installing Packer via direct binary fallback...${RESET}"
      PACKER_VERSION=$(curl -s https://checkpoint-api.hashicorp.com/v1/check/packer | jq -r .current_version)
      curl -LO "https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_linux_amd64.zip"
      unzip packer_${PACKER_VERSION}_linux_amd64.zip
      sudo mv packer /usr/local/bin/
      rm packer_${PACKER_VERSION}_linux_amd64.zip
      install_status["packer"]="✅ Installed via fallback"
      ;;
    firejail-profiles)
      echo -e "${YELLOW}⚠️ firejail-profiles is no longer packaged separately.${RESET}"
      echo -e "${YELLOW}✅ Default profiles are included with firejail itself.${RESET}"
      install_status["firejail-profiles"]="✅ Included with firejail"
      ;;

  esac
}

if [[ "$1" == "--update" ]]; then
  echo -e "${BOLD}${BLUE}🔄 Updating system packages...${RESET}"
  sudo dnf5 upgrade -y
  if [ -f /var/run/reboot-required ]; then
    echo -e "${RED}🚨 Reboot required to complete updates.${RESET}"
  else
    echo -e "${GREEN}✅ No reboot required.${RESET}"
  fi
  exit 0
fi

if [[ "$1" == "--help" ]]; then
  show_help
fi

echo -e "${BOLD}${BLUE}🔧 Fedora Workstation Setup - Interactive Mode${RESET}"
echo ""
echo -e "${YELLOW}Select categories to install:${RESET}"
echo "1) Developer Tools"
echo "2) Offensive Security Tools"
echo "3) Defensive Security & DFIR"
echo "4) Cloud & Container Tools"
echo "5) Privacy & App Sandboxing"
echo "6) All of the above"
echo ""

read -p "Enter your choice (e.g. 1 2 5): " choices

install_dev_tools() {
  echo -e "${BLUE}🔨 Installing Developer Tools...${RESET}"
  safe_install gcc gcc-c++ make automake autoconf kernel-devel cmake gdb pkgconf-pkg-config \
    glibc-devel libstdc++-devel zsh git curl wget2-wget vim-enhanced tmux neovim htop \
    python3 python3-pip nodejs golang rust cargo java-latest-openjdk toolbox \
    podman podman-docker podman-compose lsd

  if [[ ! -f /usr/bin/wget && -f /usr/bin/wget2 ]]; then
    sudo ln -sf /usr/bin/wget2 /usr/local/bin/wget
    install_status["wget"]="✅ Symlinked wget2"
  fi

  if ! command -v starship >/dev/null; then
    echo -e "${BLUE}🌟 Installing starship prompt...${RESET}"
    if curl -sS https://starship.rs/install.sh | sh -s -- -y; then
      install_status["starship"]="✅ Success"
    else
      install_status["starship"]="❌ Failed"
    fi
  else
    install_status["starship"]="✅ Already Installed"
  fi
}

install_offensive_tools() {
  echo -e "${BLUE}🧨 Installing Offensive Security Tools...${RESET}"
  safe_install wireshark nmap metasploit hydra aircrack-ng hashcat john burpsuite \
    gobuster nikto sqlmap dirb radare2 gdb strace ghex binwalk ghidra \
    netcat tcpdump openvpn proxychains-ng ettercap ngrep zmap zap tcptraceroute \
    python3-pwntools python3-scapy python3-click python3-rich

  mkdir -p ~/Tools
  cd ~/Tools || exit
  git clone https://github.com/danielmiessler/SecLists || true
  git clone https://github.com/projectdiscovery/nuclei || true

  echo -e "${BLUE}📥 Installing nuclei via Go proxy fallback...${RESET}"
  GOPROXY=https://proxy.golang.org,direct go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest \
    && install_status["nuclei"]="✅ Installed from source" \
    || install_status["nuclei"]="❌ Failed to build"
}

install_defensive_tools() {
  echo -e "${BLUE}🛡️ Installing Defensive & DFIR Tools...${RESET}"
  safe_install volatility3 sleuthkit yara clamav auditd rsyslog logrotate logwatch \
    chkrootkit lynis aide keepassxc pass gnupg2 timeshift restic borgbackup
}

install_cloud_tools() {
  echo -e "${BLUE}☁️ Installing Cloud & Container Tools...${RESET}"
  safe_install terraform awscli kubectl azure-cli google-cloud-sdk \
    vagrant ansible virtualbox packer
}

install_privacy_tools() {
  echo -e "${BLUE}🔐 Installing Privacy & App Sandboxing Tools...${RESET}"
  safe_install firewalld firejail
  sudo systemctl enable --now firewalld
  sudo firewall-cmd --set-default-zone=block
  sudo mkdir -p /etc/firejail
  sudo cp /usr/share/doc/firejail/example.profile /etc/firejail/default.profile || true
}

for choice in $choices; do
  case $choice in
    1) install_dev_tools ;;
    2) install_offensive_tools ;;
    3) install_defensive_tools ;;
    4) install_cloud_tools ;;
    5) install_privacy_tools ;;
    6)
      install_dev_tools
      install_offensive_tools
      install_defensive_tools
      install_cloud_tools
      install_privacy_tools
      ;;
    *) echo -e "${RED}❌ Invalid choice: $choice${RESET}" ;;
  esac
done

if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo -e "${YELLOW}📍 Adding ~/.local/bin to PATH in ~/.bashrc and ~/.zshrc...${RESET}"
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
fi

echo -e "${BLUE}🌀 Changing shell to zsh...${RESET}"
chsh -s "$(which zsh)"

echo ""
echo -e "${BOLD}${YELLOW}📊 Installation Summary${RESET}"
echo "=========================="
printf "%-40s %s\n" "Package" "Status"
printf "%-40s %s\n" "-------" "------"
for pkg in "${!install_status[@]}"; do
  printf "%-40s %s\n" "$pkg" "${install_status[$pkg]}"
done

echo ""
echo -e "${GREEN}✅ Setup complete. Reboot and apply any custom dotfiles or configs.${RESET}"
