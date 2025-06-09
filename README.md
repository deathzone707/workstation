# 🛡️ Fedora Security Workstation Setup

This script bootstraps a world-class Fedora workstation environment tailored for:

- 👨‍💻 Principal Security Engineers  
- 🧑‍💻 Software Developers  
- 🛡️ Red & Blue Team Operators  
- ☁️ Cloud and Infrastructure Security Practitioners  
- 🧰 Power Users migrating from macOS or Kali Linux  

---

## 🚀 Features

✅ Interactive setup with selectable tool categories  
✅ Option to install everything in one shot  
✅ App sandboxing with Firejail and Flatpak  
✅ Toolbox-based developer environments  
✅ Full offensive & defensive security toolchain (Kali-like)  
✅ Secure-by-default Fedora configuration (SELinux, Firewalld, TPM-ready)
✅ Developer stack for modern languages and IaC workflows
✅ Local virtualization with VirtualBox, Vagrant, Packer, and Ansible
   (uses official upstream sources if not in Fedora repos)
=======

---

## 🧪 Categories You Can Install

1. **Developer Tools** – Compilers, languages, containers, shells  
2. **Offensive Security** – Pentesting tools, password crackers, fuzzers  
3. **Defensive Security** – DFIR, forensic suites, system auditing  
4. **Cloud & Container** – AWS/GCP/Azure CLIs, Kubernetes, Terraform, Vagrant, Ansible, VirtualBox, Packer
5. **Privacy & Sandboxing** – Firejail, firewall setup, application isolation  
6. **All of the Above** – Complete workstation deployment  

---

## 📦 Usage

### 1. Clone or download the script

```bash
git clone git@github.com:deathzone707/workstation.git
chmod +x fedora_security_setup_interactive.sh
```

### 2. Run it

```bash
./fedora_security_setup_interactive.sh
```

### 3. See help

```bash
./fedora_security_setup_interactive.sh --help
```

---

## 🧰 Notes

- You must run this on **Fedora Workstation 40+**.
- The script uses `dnf` and `flatpak` (where applicable).
- SELinux is enforced and Secure Boot is supported by default.
- Script sets `zsh` as the default shell and prepares for dotfile syncing.

---

## 📝 Future Improvements

- [ ] Zenity or TUI interactive menu  
- [ ] Dry-run / audit logging support  
- [ ] Ansible-based deployment for team-wide rollout  
- [ ] Btrfs snapshot integration pre/post install  

---

## 📜 License

MIT License. Feel free to fork, improve, or adapt to your team’s needs.

---

## ✉️ Maintainer

**Austin Dunn**  
Security Engineer  
austin@austindunn.us