# [KSIĄŻKA] Debian GNU/Linux 12. Rozpoczecie pracy.

Treść komend, skryptów oraz plików konfiguracyjnych, użytych w książce:

## strona 59

```bash
sudo apt update
sudo apt install kleopatra
```


## strona 64

```bash
sha512sum debian-12.10.0-amd64-netinst.iso
```


## strona 66

```bash
sudo lsblk
```


## strona 67

```bash
sudo dd if=/ścieżka/do/obrazu.iso of=/dev/sdb bs=4M conv=noerror,sync oflag=sync status=progress
```


## strona 69

```bash
cd ventoy-1.0.99
chmod u+x ./Ventoy2Disk
```


---

## strona 102

```bash
sudo parted /dev/sda
```


## strona 104

```bash
sudo dd if=/dev/zero of=/dev/<dysk> bs=1M
sudo dd if=/dev/urandom of=/dev/<dysk> bs=1M
```


---

## strona 122

```bash
su
sudo <komenda>
ls
```


## strona 123

```bash
pwd
cd Dokumenty
touch nowy_plik.txt
rm nowy_plik.txt
mkdir nowy_katalog
rmdir nowy_katalog
```


## strona 124

```bash
cp plik.txt kopia_plik.txt
mv kopia_plik.txt nowa_nazwa.txt
mv nowa_nazwa.txt Dokumenty/
cat plik.txt
grep "przykład" plik.txt
```


## strona 125

```bash
chown lech skrypt.sh
chown lech:users skrypt.sh
whoami
df -h
```


## strona 126

```bash
uname
uname -a
uname -r
top
```


## strona 127

```bash
find ~ -type f -iname Zrzut*
free -h
ps aux
```


## strona 128

```bash
uptime
uptime -p
uptime -s
lscpu
```


## strona 129

```bash
lspci
```


## strona 130

```bash
lsusb
lsblk
```


## strona 131

```bash
sudo blkid
```


## strona 132

```bash
echo $?
skrypt.sh
./skrypt.sh
```


## strona 133

```bash
ls /etc
cd Documents
```


## strona 134

```bash
cat notatka
cd ..
cat plik.txt | grep "ważne"
echo "Bookworm" > ./Debian
echo "GNU" >> ./Debian
```


## strona 135

```bash
cat ./Debian | sort
man <komenda>
man ls
man fstab
```


## strona 136

```bash
help cd
```


## strona 137

```bash
lsblk --help
```


## strona 138

```bash
su -
usermod -aG sudo lech
groups lech
sudo su -
```


## strona 139

```bash
sudo passwd -l root
```


## strona 140

```bash
sudo gnome-text-editor <nazwa_pliku>
```


---

## strona 140/141

```ini
[Desktop Entry]
Version=1.0
Name=Moja Aplikacja
Comment=Uruchamia aplikację Moja Aplikacja
Exec=/ścieżka/do/mojej_aplikacji
Icon=/ścieżka/do/ikony.png
Terminal=false
Type=Application
Categories=Utility;
```


## strona 141

```bash
sudo nano "/usr/share/applications/Moja Aplikacja.desktop"
sudo chmod +x "/usr/share/applications/Moja Aplikacja.desktop"
nano "~/.local/share/applications/Moja Aplikacja.desktop"
chmod +x "~/.local/share/applications/Moja Aplikacja.desktop"
```


---

## strona 142

```bash
sudo apt install alacarte
```


## strona 146

```bash
sudo dpkg -i <nazwa_pakietu.deb>
sudo aptitude install <nazwa_pakietu.deb>
sudo apt install <nazwa_pakietu>
```


## strona 147

```bash
sudo apt install xxx
```


## strona 148

```bash
sudo apt install apt-transport-https
```


## strona 149

```bash
sudo apt install apt-listbugs apt-listchanges apt-file apt-rdepends apt-show-versions unattended-upgrades needrestart
```


## strona 150

```bash
sudo nano /etc/apt/sources.list
```


---

## strona 150/151

```ini
deb http://deb.debian.org/debian/ bookworm non-free-firmware contrib non-free main
deb-src http://deb.debian.org/debian/ bookworm non-free-firmware contrib non-free main
deb http://security.debian.org/debian-security bookworm-security non-free-firmware contrib non-free main
deb-src http://security.debian.org/debian-security bookworm-security non-free-firmware contrib non-free main
deb http://deb.debian.org/debian/ bookworm-updates non-free-firmware contrib non-free main
deb-src http://deb.debian.org/debian/ bookworm-updates non-free-firmware contrib non-free main
```


---

## strona 151

```bash
sudo apt install software-properties-common
sudo add-apt-repository contrib
sudo add-apt-repository non-free
sudo add-apt-repository non-free-firmware
sudo apt install fasttrack-archive-keyring
```


## strona 152

```bash
sudo nano /etc/apt/sources.list
# Backports
deb http://deb.debian.org/debian bookworm-backports main
sudo apt update
sudo apt -t bookworm-backports install
```


## strona 153

```bash
sudo apt install extrepo
```


## strona 154

```bash
sudo extrepo search .
sudo extrepo search <słowo kluczowe>
```


## strona 155

```bash
sudo extrepo search vscodium
sudo extrepo enable <repozytorium>
sudo extrepo disable <repozytorium>
sudo extrepo update <repozytorium>
```


## strona 156

```bash
sudo apt install nala
sudo nala history
sudo nala history undo 1
sudo nala fetch
```


## strona 159

```bash
snap find <nazwa pakietu>
snap find signal-desktop
sudo snap install <nazwa pakietu>
sudo snap install signal-desktop
sudo snap remove <nazwa pakietu>
```


## strona 160

```bash
sudo snap remove signal-desktop
snap list
sudo apt install flatpak
```


## strona 161

```bash
sudo flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
sudo flatpak remote-add --if-not-exists fedora oci+https://registry.fedoraproject.org
```


## strona 162

```bash
sudo flatpak remote-add --if-not-exists elementaryos https://flatpak.elementary.io/repo.flatpakrepo
wget https://origin.ostree.endlessm.com/keys/eos-flatpak-keyring.gpg
sudo flatpak remote-add --gpg-import=eos-flatpak-keyring.gpg eos-apps https://ostree.endlessm.com/ostree/eos-apps
sudo flatpak remote-add --if-not-exists PureOS https://store.puri.sm/repo/stable/pureos.flatpakrepo
sudo flatpak install https://gitlab.com/projects261/firefox-esr-flatpak/-/raw/main/firefox-esr.flatpakref
```


## strona 163

```bash
sudo flatpak install https://gitlab.com/projects261/firefox-nightly-flatpak/-/raw/main/firefox-nightly.flatpakref
sudo flatpak install https://gitlab.com/projects261/thunderbird-nightly-flatpak/-/raw/main/thunderbird-nightly.flatpakref
flatpak search <nazwa pakietu>
flatpak search audacity
sudo flatpak install <repozytorium> <identyfikator programu>
sudo flatpak install flathub org.audacityteam.Audacity
```


## strona 164

```bash
sudo flatpak uninstall <identyfikator programu>
sudo flatpak uninstall org.audacityteam.Audacity
flatpak list
```


## strona 165

```bash
flatpak list --app --columns=application,size
flatpak list --runtime --columns=application,size
```


## strona 166

```bash
sudo flatpak uninstall --unused
sudo flatpak repair --system
sudo apt install ostree
```


## strona 167

```bash
sudo ostree prune --repo=/var/lib/flatpak/repo --refs-only
snap list --all
sudo snap set system refresh.retain=2
sudo du -sh /var/cache/snapd
sudo rm -rf /var/cache/snapd/*
```


## strona 168

```bash
chmod +x ./<nazwa_pliku_appimage.AppImage>
./<nazwa_pliku_appimage.AppImage>
```


## strona 170

```bash
sudo apt install gnome-software-plugin-snap gnome-software-plugin-flatpak
```


## strona 172

```bash
sudo systemctl start <nazwa_usługi>.service
sudo systemctl stop <nazwa_usługi>.service
sudo systemctl restart <nazwa_usługi>.service
sudo systemctl status <nazwa_usługi>.service
systemctl status cups.service
```


## strona 173

```bash
sudo systemctl enable <nazwa_usługi>.service
sudo systemctl enable cups.service
```


## strona 174

```bash
sudo systemctl disable <nazwa_usługi>.service
sudo systemctl disable cups.service
systemctl list-unit-files --type=service
```


## strona 175

```bash
systemctl list-units --type=service | grep -i <nazwa_usługi>
systemctl list-unit-files --type=service | grep -i <nazwa_usługi>
```


## strona 176

```bash
sudo nano /etc/apt/sources.list
```


## strona 177

```bash
sudo apt update
```


## strona 178

```bash
sudo apt update
```


## strona 179

```bash
sudo apt upgrade
sudo apt full-upgrade
sudo snap refresh
sudo flatpak update
```


## strona 180

```bash
cat /etc/debian_version
```


## strona 181

```bash
sudo apt update
sudo apt full-upgrade
sudo apt autoremove
sudo apt clean
sudo sed -i 's/bookworm/trixie/g' /etc/apt/sources.list
sudo apt update
sudo apt install debian-archive-keyring
```


## strona 182

```bash
sudo apt upgrade --without-new-pkgs
sudo apt full-upgrade
```


## strona 183

```bash
sudo reboot
cat /etc/debian_version
systemctl list-units --failed
```


## strona 184

```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades
```


## strona 185

```bash
sudo nano /etc/systemd/system/snap-update.service
```

```ini
[Unit]
Description=Automatyczna aktualizacja Snap

[Service]
ExecStart=/usr/bin/snap refresh

[Install]
WantedBy=multi-user.target
```

```bash
sudo nano /etc/systemd/system/snap-update.timer
```


## strona 186

```ini
[Unit]
Description=Harmonogram automatycznej aktualizacji Snap

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable snap-update.timer
sudo systemctl start snap-update.timer
sudo systemctl status snap-update.timer
```


## strona 187

```bash
sudo nano /etc/systemd/system/flatpak-update.service
```

```ini
[Unit]
Description=Automatyczna aktualizacja Flatpak

[Service]
ExecStart=/usr/bin/flatpak update -y

[Install]
WantedBy=multi-user.target
```

```bash
sudo nano /etc/systemd/system/flatpak-update.timer
```

```ini
[Unit]
Description=Harmonogram automatycznej aktualizacji Flatpak

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
```


## strona 188

```bash
sudo systemctl enable flatpak-update.timer
sudo systemctl start flatpak-update.timer
sudo systemctl status flatpak-update.timer
sudo apt search gnome-shell-extension
```


## strona 191

```bash
sudo apt install gnome-shell-extension-manager
```


## strona 193

```bash
gnome-extensions install --force <ścieżka_do_pliku_zip>
gnome-extensions install --force /home/lech/Pobrane/quick-settings-tweaks.v27/shell-extension.zip
sudo apt install firmware-linux firmware-linux-nonfree
```


## strona 194

```bash
sudo reboot
lsmod
```


## strona 195

```bash
lspci -v
lsusb
sudo dmesg | grep "0a5c"
sudo dmesg | grep firmware
```


## strona 196

```bash
sudo journalctl -k | grep firmware
sudo apt install inxi lshw
```


## strona 197

```bash
sudo inxi -G
sudo inxi -Fxz
```


## strona 198

```bash
sudo lshw
```


## strona 199

```bash
sudo lshw -C network | head -50
```


## strona 201

```bash
sudo reboot
```


## strona 202

```bash
dpkg --print-architecture
dpkg --print-foreign-architectures
sudo dpkg --add-architecture i386
dpkg --print-foreign-architectures
sudo apt update
```


## strona 203

```bash
sudo apt install libc6:i386 libglvnd-dev:i386 libx11-6:i386
```


## strona 204

```bash
sudo apt install libc6:i386 libglvnd-dev:i386 libx11-6:i386
sudo echo -e "blacklist nouveau\noptions nouveau modeset=0" | sudo tee /etc/modprobe.d/blacklist-nouveau.conf
```


## strona 205

```bash
sudo update-initramfs -u
sudo reboot
```


## strona 206

```bash
sudo apt install nvidia-detect
nvidia-detect
sudo apt install build-essential dkms linux-headers-$(uname -r)
```


## strona 207

```bash
sudo apt install -t bookworm-backports nvidia-driver-full nvidia-settings
```


## strona 208

```bash
sudo reboot
nvidia-smi
```


## strona 209

```bash
echo $XDG_SESSION_TYPE
ps -e | grep -E 'Xorg|wayland'
journalctl | grep Xorg
```


## strona 210

```bash
sudo apt install -t bookworm-backports vulkan-tools libvulkan1 nvidia-vulkan-icd
vulkaninfo | grep "GPU id"
vkcube
```


## strona 212

```bash
sudo apt install linux-headers-$(uname -r) build-essential libglvnd-dev pkg-config
```


## strona 213

```bash
systemctl get-default
sudo systemctl set-default multi-user.target
sudo reboot
cd ~/Pobrane
sudo chmod +x ./NVIDIA-Linux-x86_64-550.135.run
sudo ./NVIDIA-Linux-x86_64-550.135.run
```


## strona 215

```bash
sudo systemctl set-default graphical.target
sudo reboot
nvidia-smi
```


## strona 216

```bash
sudo apt install vulkan-tools
vulkaninfo
```


## strona 217

```bash
vkcube
sudo apt install mesa-utils mesa-vulkan-drivers libglx-mesa0 libgl1-mesa-dri
```


## strona 219

```bash
lspci -nn | grep -i vga
```


## strona 220

```bash
sudo apt install firmware-amd-graphics
sudo dmesg | grep amdgpu
lsmod | grep amdgpu
sudo reboot
lspci -k | grep -EA3 "VGA|3D"
sudo apt install -t bookworm-backports mesa-utils libglx-mesa0 libgl1-mesa-dri
```


## strona 221

```bash
glxinfo | grep "OpenGL renderer"
sudo apt install -t bookworm-backports vulkan-utils libvulkan1 mesa-vulkan-drivers
sudo apt install -t bookworm-backports vulkan-utils libvulkan1 amdvlk
vulkaninfo | grep "GPU id"
vkcube
```


## strona 223

```bash
sudo apt install apparmor apparmor-utils
```


## strona 224

```bash
sudo systemctl enable apparmor
sudo systemctl start apparmor
sudo apparmor_status
```


## strona 225

```bash
sudo aa-complain /etc/apparmor.d/usr.bin.evince
sudo aa-enforce /etc/apparmor.d/usr.bin.evince
```


## strona 226

```bash
sudo apt install apparmor-profiles*
dpkg -L apparmor-profiles
dpkg -L apparmor-profiles-extra
```


## strona 227

```bash
sudo aa-enforce /etc/apparmor.d/*
sudo which chromium
```


## strona 228

```bash
sudo apt install rsyslog
sudo tail -f /var/log/syslog
```


## strona 229

```bash
sudo tail -f /var/log/syslog | grep -i apparmor
sudo systemctl status rsyslog
```


## strona 230

```bash
sudo aa-genprof /usr/bin/chromium
```


## strona 231

```bash
ls -l /etc/apparmor.d/| grep chromium
sudo nano /etc/apparmor.d/usr.bin.chromium
```


## strona 232

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.chromium
sudo dmesg | grep DENIED
sudo journalctl -k | grep apparmor
```


## strona 236

```bash
sudo apt install clamav clamav-daemon
```


## strona 237

```bash
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
```


## strona 238

```bash
freshclam --version
systemctl enable clamav-freshclam
systemctl status clamav-freshclam
```


## strona 239

```bash
sudo clamscan -r /
```


## strona 240

```bash
sudo clamscan -r /ścieżka/do/katalogu
sudo clamscan -r --remove /ścieżka/do/katalogu
sudo clamscan -r -i -v -l /home/lech/clamav-infekcje /ścieżka/do/katalogu
```


## strona 241

```bash
sudo crontab -e
```

```cron
0 2 * * * /usr/bin/clamscan -r /ścieżka/do/skanowania --log=/var/log/clamav-scan.log
```

```bash
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-daemon
```


## strona 242

```bash
systemctl status clamav-daemon
sudo clamdscan --fdpass --verbose /ścieżka/do/katalogu
sudo clamdscan --fdpass --verbose /etc/
```


## strona 243

```bash
sudo clamdscan --fdpass --verbose /ścieżka/do/katalogu > clamscan.log 2>&1
sudo clamdscan --fdpass --verbose /etc/ > clamscan-$(date +%F-%H%M).log 2>&1
cat clamscan-2025-04-15-1322.log
clamconf
```


## strona 244

```bash
clamconf -g clamd.conf
```


## strona 245/246

```ini
# Skanowanie różnych typów plików
ScanMail yes
ScanArchive yes
ScanPDF yes
ScanOLE2 yes
ScanHTML yes
ScanPE yes
ScanELF yes
ScanSWF yes
ScanXMLDOCS yes
ScanHWP3 yes

# Informacje dodatkowe
ExtendedDetectionInfo yes
Bytecode yes
BytecodeSecurity TrustSigned
BytecodeTimeout 10000

# Ochrona heurystyczna
PhishingSignatures yes
PhishingScanURLs yes
HeuristicAlerts yes
HeuristicScanPrecedence yes

# Alerty o zagrożeniach ukrytych
AlertBrokenExecutables yes
AlertBrokenMedia yes
AlertEncryptedArchive yes
AlertEncryptedDoc yes
AlertOLE2Macros yes

# Ustalenie limitów
MaxScanSize 200M
MaxFileSize 100M
MaxRecursion 16
MaxFiles 10000
MaxScanTime 120000
MaxDirectoryRecursion 15

# Sprawdzanie bazy co wyznaczoną liczbę sekund
SelfCheck 600

# Wydajność
MaxThreads 10
MaxQueue 30
IdleTimeout 60
ConcurrentDatabaseReload yes
```


## strona 246

```bash
sudo systemctl restart restart clamav-daemon
sudo apt install clamtk
```


## strona 248

```bash
cd Pobrane/
chmod u+x ./eeau_x86_64.bin
sudo ./eeau_x86_64.bin
```


## strona 249

```bash
sudo apt install ./eea-11.1.3.0-ubuntu18.x86_64.deb
```


## strona 250

```bash
sudo /opt/eset/eea/sbin/lic -k XXXX-XXXX-XXXX-XXXX-XXXX
sudo /opt/eset/eea/sbin/lic -u adres@example.com
sudo /opt/eset/eea/sbin/lic -f /ścieżka/do/pliku/offline_license.lf
```


## strona 252

```bash
sudo apt install ufw
```


## strona 253

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw logging on
sudo ufw enable
sudo apt install gufw
```


## strona 255

```bash
sudo ufw reset
sudo ufw disable
sudo apt purge ufw
```


## strona 256

```bash
sudo systemctl enable nftables.service
sudo systemctl start nftables.service
sudo systemctl status nftables.service
sudo nano /etc/nftables.conf
```


---

## strona 256/257

```nft
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iifname lo accept;
        ct state established,related accept;
        # Odrzuć i zaloguj pakiety invalid (limit: max 5 wpisów na minutę)
        ct state invalid log prefix "nftables-invalid: " flags all limit rate 5/minute counter drop;
        # Zezwól na ICMP echo-request (ping) z ograniczeniem
        ip protocol icmp icmp type echo-request counter limit rate 1/second accept;
        ip6 nexthdr icmpv6 icmpv6 type echo-request counter limit rate 1/second accept;
        # Zaloguj i odrzuć pozostałe pakiety (limit: max 10 wpisów na minutę)
        log prefix "nftables-input-drop: " flags all limit rate 10/minute counter drop;
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
```


---

## strona 257

```bash
sudo -f /etc/nftables/nftables.conf
sudo nft list ruleset
```


---

## strona 258/259

```nft
sudo nano /etc/nftables.conf

#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        # Pozwól ruch na interfejsie localhost
        iifname lo accept;
        # Akceptuj ruch związany z istniejącymi połączeniami
        ct state established,related accept;
        # Odrzuć i zaloguj pakiety invalid (ogranicz ilość logów)
        ct state invalid log prefix "nftables-invalid: " flags all limit rate 5/minute counter drop;
        # Akceptuj ruch ICMP (ping) z ograniczeniem
        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } counter limit rate 10/second accept;
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded } counter limit rate 10/second accept;
        # Blokuj skanowanie portów (np. SYN, NULL, Xmas scans)
        tcp flags & (fin|syn|rst|psh|ack|urg) == syn limit rate 15/second accept;
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 log prefix "nftables-null-scan: " flags all limit rate 5/minute counter drop;
        tcp flags fin,psh,urg fin,psh,urg log prefix "nftables-xmas-scan: " flags all limit rate 5/minute counter drop;
        # Ochrona przed SYN flood
        tcp flags syn tcp option maxseg size set 1460 limit rate 25/second accept;
        # Drop dla pakietów wchodzących na zamknięte porty
        udp dport {0, 1, 7, 19, 37, 135, 445, 500, 1434} log prefix "nftables-bad-udp: " flags all limit rate 5/minute counter drop;
        # Drop fragmentowanych pakietów IP (bardzo rzadkie w normalnym ruchu, czasami ataki)
        ip frag-off & 0x1fff != 0 log prefix "nftables-fragments: " flags all limit rate 5/minute counter drop;
        ip6 frag frag-off & 0x1fff != 0 log prefix "nftables-ipv6-fragments: " flags all limit rate 5/minute counter drop;
        # Domyślne logowanie i drop pakietów niepasujących
        log prefix "nftables-input-drop: " flags all limit rate 10/minute counter drop;
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
```


---

## strona 259

```bash
sudo nft list ruleset
```


---

## strona 261

```bash
sudo journalctl -k | grep nftables
```


## strona 264

```bash
nano ~/.local/share/nautilus/scripts/moj_skrypt
```

```bash
#!/bin/bash
zenity --info --text="Witaj, świecie!"
```

```bash
chmod u+x ~/.local/share/nautilus/scripts/moj_skrypt
```


## strona 267

```bash
nano ~/.local/share/applications/moj_skrót.desktop
sudo nano /usr/share/applications/moj_skrót.desktop
```

```ini
[Desktop Entry]
Version=1.0
Name=Nazwa Aplikacji
Comment=Opis aplikacji
Exec=/pełna/ścieżka/do/aplikacji
Icon=/pełna/ścieżka/do/ikony
Terminal=false
Type=Application
Categories=Utility;Application;
```

```bash
chmod +x ~/.local/share/applications/moj_skrót.desktop
```


## strona 270

```bash
sudo apt remove firefox-esr
```


## strona 271

```bash
sudo flatpak install org.mozilla.firefox
sudo install -d -m 0755 /etc/apt/keyrings
wget -q https://packages.mozilla.org/apt/repo-signing-key.gpg -O- | sudo tee /etc/apt/keyrings/packages.mozilla.org.asc > /dev/null
gpg -n -q --import --import-options import-show /etc/apt/keyrings/packages.mozilla.org.asc | awk '/pub/{getline; gsub(/^ +| +$/,""); if($0 == "35BAA0B33E9EB396F59CA838C0BA5CE6DC6315A3") print "\nThe key fingerprint matches ("$0").\n"; else print "\nVerification failed: the fingerprint ("$0") does not match the expected one.\n"}'
```


## strona 272

```bash
echo "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main" | sudo tee -a /etc/apt/sources.list.d/mozilla.list > /dev/null
echo '
Package: *
Pin: origin packages.mozilla.org
Pin-Priority: 1000
' | sudo tee /etc/apt/preferences.d/mozilla
sudo apt update
sudo apt-get install firefox
```


## strona 274

```bash
cd Pobrane/
sudo dpkg -i google-chrome-stable_current_amd64.deb
```


## strona 275

```bash
sudo apt --fix-broken install
```


## strona 276

```bash
sudo flatpak install flathub org.chromium.Chromium
sudo snap install chromium
```


## strona 277

```bash
sudo apt install curl
```


## strona 278

```bash
curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc
echo "deb [arch=amd64] https://packages.microsoft.com/repos/edge stable main" | sudo tee /etc/apt/sources.list.d/microsoft-edge.list
sudo apt update
sudo apt install microsoft-edge-stable
```


## strona 279

```bash
sudo flatpak install flathub com.microsoft.Edge
```


## strona 280

```bash
curl -fSsL https://deb.opera.com/archive.key | gpg --dearmor | sudo tee /usr/share/keyrings/opera.gpg > /dev/null
echo deb [arch=amd64 signed-by=/usr/share/keyrings/opera.gpg] https://deb.opera.com/opera-stable/ stable non-free | sudo tee /etc/apt/sources.list.d/opera.list
sudo apt update
sudo apt install opera-stable
```


## strona 281

```bash
sudo curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg] https://brave-browser-apt-release.s3.brave.com/ stable main" | sudo tee /etc/apt/sources.list.d/brave-browser-release.list
```


## strona 282

```bash
sudo apt update
sudo apt install brave-browser
flatpak install flathub com.brave.Browser
```


## strona 285

```bash
sudo apt install evolution
```


## strona 291

```bash
sudo apt install thunderbird
```


## strona 293

```bash
sudo apt install keepassxc
```


## strona 299

```bash
sudo apt install libreoffice
sudo apt install libreoffice-core libreoffice-writer libreoffice-calc
```


## strona 301

```bash
sudo flatpak install flathub org.gimp.GIMP
```


## strona 302

```bash
systemd-analyze
systemd-analyze blame
```


## strona 303

```bash
systemd-analyze critical-chain
sudo systemctl disable cups.service
sudo apt install preload
```


## strona 304

```bash
sudo systemctl status preload
systemctl is-enabled preload
```


## strona 305

```bash
sudo apt install bleachbit
```


## strona 307

```bash
sudo apt install timeshift
```


## strona 310

```bash
sudo apt install deja-dup
```


## strona 312

```bash
sudo apt install tlp
```


## strona 313

```bash
sudo systemctl enable tlp
sudo systemctl start tlp
sudo tlp-stat
```


## strona 314

```bash
sudo nano /etc/default/tlp
sudo systemctl restart tlp
sudo tlp-stat -s
sudo tlp-stat
```


## strona 315

```bash
sudo apt install smartmontools
```


## strona 316

```bash
sudo apt install laptop-mode-tools
```


## strona 317

```bash
sudo nano /etc/laptop-mode/laptop-mode.conf
```


## strona 318

```bash
sudo systemctl enable laptop-mode
sudo systemctl start laptop-mode
systemctl status laptop-mode
sudo apt install unace unace-nonfree lzma arj rar unrar p7zip-rar
```


## strona 319

```bash
sudo apt install gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly gstreamer1.0-libav
sudo apt install libdvd-pkg
```


## strona 320

```bash
sudo dpkg-reconfigure libdvd-pkg
sudo apt install ntfs-3g btrfs-progs xfsprogs exfat-fuse exfatprogs fuseiso zfsutils-linux
```


## strona 321

```bash
sudo apt install ttf-mscorefonts-installer
apt search fonts-*
```


## strona 322

```bash
sudo apt install default-jdk
sudo nano /etc/default/grub
```


## strona 323

```bash
sudo update-grub
sudo apt remove gnome-games
```


## strona 324

```bash
sudo apt autoremove
sudo apt clean
sudo apt autoclean
sudo apt autoremove
```


## strona 325

```bash
sudo apt install dconf-editor
```


## strona 326

```bash
dconf-editor
dconf read /org/gnome/desktop/interface/enable-animations
dconf write /org/gnome/desktop/interface/enable-animations false
dconf list /org/gnome/desktop/
```


## strona 327

```bash
dconf reset /org/gnome/desktop/interface/enable-animations
dconf reset -f /
dconf dump / > dconf-backup.ini
dconf load / < dconf-backup.ini
dconf watch /org/gnome/desktop/interface/
```


## strona 328

```bash
dconf dump / > ~/00-moje_ustawienia
nano ~/00-moje_ustawienia
sudo mv ~/00-moje_ustawienia /etc/dconf/db/local.d/
sudo dconf update
```


## strona 329

```bash
dconf write /org/gnome/desktop/background/picture-uri "'file:///ścieżka/do/obrazu.jpg'"
dconf write /org/gnome/desktop/screensaver/picture-uri "' file:///ścieżka/do/obrazu.jpg'"
dconf write /org/gnome/desktop/interface/enable-animations false
dconf write /org/gnome/desktop/interface/enable-hot-corners false
dconf write /org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-timeout 3600
dconf write /org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type "'suspend'"
dconf write /org/gnome/desktop/interface/gtk-enable-primary-paste false
```


## strona 330

```bash
dconf write /org/gnome/desktop/interface/color-scheme "'prefer-dark'"
dconf write /org/gnome/desktop/interface/gtk-theme "'Adwaita-dark'"
dconf write /org/gnome/desktop/interface/enable-animations false
dconf write /org/gnome/desktop/input-sources/xkb-options "['caps:none']"
dconf write /org/gnome/desktop/input-sources/xkb-options "['ctrl:swapcaps']"
dconf write /org/gnome/settings-daemon/plugins/power/lid-close-ac-action "'nothing'"
dconf write /org/gnome/settings-daemon/plugins/power/lid-close-battery-action "'nothing'"
```


## strona 331

```bash
dconf write /org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type "'suspend'"
dconf write /org/gnome/nautilus/preferences/show-hidden-files true
dconf write /org/gnome/shell/enabled-extensions "[]"
dconf write /org/gnome/shell/enabled-extensions "['dash-to-dock@micxgx.gmail.com']"
dconf write /org/gnome/desktop/peripherals/touchpad/natural-scroll true
dconf write /org/gnome/desktop/peripherals/touchpad/disable-while-typing true
dconf write /org/gnome/gnome-screenshot/auto-save-directory "'~/Pobrane/Zrzuty"
dconf write /org/gnome/desktop/sound/event-sounds false
```


## strona 332

```bash
dconf write /org/gnome/desktop/interface/clock-format "'24h'"
sudo apt install wine wine64 wine32
```


## strona 333

```bash
sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key
sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/debian/dists/bookworm/winehq-bookworm.sources
```


## strona 334

```bash
sudo apt update
sudo apt install --install-recommends winehq-stable
wine winecfg
```


## strona 335

```bash
nano ~/.local/share/applications/wine-extension-exe.desktop
```


## strona 336

```ini
[Desktop Entry]
Name=Wine Windows Program Loader
Exec=wine start /unix %f
Type=Application
NoDisplay=true
StartupNotify=true
MimeType=application/x-ms-dos-executable
```

```bash
nano ~/.local/share/applications/mimeapps.list
```

```ini
[Default Applications]
application/x-ms-dos-executable=wine-extension-exe.desktop
```

```bash
sudo update-desktop-database
nautilus -q
```


## strona 337

```bash
wine <plik exe>
msiexec -i <plik msi>
wine uninstaller
```


## strona 338

```bash
sudo apt install winetricks
WINEPREFIX=~/.local/share/wineprefixes/<prefiks> winetricks
WINEPREFIX=~/.local/share/wineprefixes/<prefiks> winecfg
WINEPREFIX=~/.local/share/wineprefixes/<prefiks> wine program.exe
```


## strona 340

```bash
export WINEARCH=win32 WINEPREFIX=~/.local/share/wineprefixes/<prefiks>
winetricks
sudo flatpak install flathub com.usebottles.bottles
```


## strona 342

```bash
sudo apt install lutris
```


## strona 349

```bash
sudo apt install -y gcc make linux-headers-$(uname -r) libqt5core5a libqt5gui5 libqt5widgets5 libqt5opengl5 libqt5printsupport5 libqt5x11extras5 libqt5network5 libqt5dbus5
sudo apt install virtualbox
```


## strona 350

```bash
sudo apt install virtualbox-ext-pack
wget http://download.virtualbox.org/virtualbox/7.0.10/Oracle_VM_VirtualBox_Extension_Pack-7.0.10.vbox-extpack
```


## strona 351

```bash
sudo VBoxManage extpack install ./Oracle_VM_VirtualBox_Extension_Pack-7.0.10.vbox-extpack
curl -fsSL https://www.virtualbox.org/download/oracle_vbox_2016.asc|sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/vbox.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/vbox.gpg] https://download.virtualbox.org/virtualbox/debian bookworm contrib" | sudo tee /etc/apt/sources.list.d/virtualbox.list
```


## strona 352

```bash
sudo apt update
sudo apt install virtualbox-7.0
wget https://download.virtualbox.org/virtualbox/7.0.24/Oracle_VM_VirtualBox_Extension_Pack-7.0.24.vbox-extpack
```


## strona 353

```bash
sudo VBoxManage extpack install ./Oracle_VM_VirtualBox_Extension_Pack-7.0.24.vbox-extpack
rm -f Oracle_VM_VirtualBox_Extension_Pack-7.0.24.vbox-extpack
sudo VBoxManage extpack uninstall "Oracle VirtualBox Extension Pack"
```


## strona 354

```bash
lsmod | grep vboxdrv
sudo /sbin/vboxconfig
```


## strona 362

```bash
ls -l
sudo apt install build-essential dkms linux-headers-$(uname -r)
```


## strona 363

```bash
sudo bash ./VBoxLinuxAdditions.run
```


## strona 378

```bash
sudo cp ./*.ttf /usr/share/fonts
sudo cp ./*.ttf /usr/local/share/fonts
```


## strona 380

```bash
sudo fc-cache -fv
```


## strona 382

```bash
sudo ./install.sh
sudo cp -pR ~/Pobrane/Vimix-2k/Vimix /boot/grub/themes/
```


## strona 383

```bash
sudo nano /etc/default/grub
```

```ini
GRUB_THEME="/boot/grub/themes/Vimix/theme.txt"
```

```bash
ls /boot/grub/themes/Vimix/theme.txt
sudo update-grub
```


## strona 384

```bash
sudo reboot
vbeinfo
```


## strona 385

```bash
sudo nano /etc/default/grub
```

```ini
GRUB_GFXMODE=1600x1200
GRUB_GFXPAYLOAD_LINUX=keep
```

```bash
sudo update-grub
```


## strona 386

```bash
sudo reboot
dpkg -l | grep plymouth
```


## strona 387

```bash
sudo plymouth-set-default-theme
sudo plymouth-set-default-theme --list
sudo apt install plymouth-themes
```


## strona 388

```bash
sudo apt search plymouth*
sudo update-grub
```


## strona 389

```bash
sudo plymouth-set-default-theme bgrt
sudo update-initramfs -u
sudo plymouthd
sudo plymouth --show-splash
sudo plymouth quit
```


## strona 390

```bash
sudo apt install conky-all lua5.1
```


## strona 391

```bash
conky
```


## strona 392

```bash
cd ~/Pobrane/
mkdir -p ~/.config/conky
```


## strona 393

```bash
wget https://github.com/MX-Linux/mx-conky-data/archive/refs/heads/master.zip
unzip master.zip
mv mx-conky-data-master ~/.config/conky/
conky -c ~/.config/conky/mx-conky-data-master/MX-antiX/MX-antiX17
```


## strona 394

```bash
conky -c ~/.config/conky/mx-conky-data-master/MX-TopBar/conkyrc
killall conky
```


## strona 395

```bash
nano ~/.conky/conky-startup.sh
```

```bash
#!/bin/sh
if [ "$DESKTOP_SESSION" = "gnome" ]; then 
   sleep 20s
   killall conky
   cd "$HOME/.config/conky/mx-conky-data-master/MX-antiX/"
   conky -c "$HOME/.config/conky/mx-conky-data-master/MX-antiX/MX-antiX17" &
   cd "$HOME/.config/conky/mx-conky-data-master/MX-TopBar/"
   conky -c "$HOME/.config/conky/mx-conky-data-master/MX-TopBar/conkyrc" &
   exit 0
fi

conky -c "$HOME/.config/conky/mx-conky-data-master/MX-antiX/MX-antiX17" &
```


## strona 396

```bash
chmod +x ~/.conky/conky-startup.sh
nano ~/.config/autostart/conky.desktop
chmod +x ~/.config/autostart/conky.desktop
```


## strona 397

```bash
sudo apt install conky-all lua5.1
```


## strona 398

```bash
git clone https://github.com/zcot/conky-manager2.git
cd conky-manager2/
make
sudo make install
```


## strona 408

```bash
dmesg | grep -i nvidia
journalctl -k | grep -i nvidia
```


## strona 409

```bash
df -h
sudo blkid | grep home
```


## strona 410

```bash
sudo vgs
lvextend -L +5G /dev/debian-vg/home
sudo apt update
```


## strona 411

```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys <ID_klucza>
```


## strona 412

```bash
sudo lsblk
```


## strona 413

```bash
sudo fdisk -l
sudo blkid | grep sda1
```


## strona 414

```bash
sudo mount /dev/mapper/debian--vg-root /mnt/
sudo mount /dev/sda1 /mnt/boot/
sudo mount /dev/sda3 /mnt/boot/efi
sudo mount --bind /dev /mnt/dev/
sudo mount --bind /proc /mnt/proc/
sudo mount --bind /sys /mnt/sys/
sudo mount --bind /run /mnt/run/
mount
```


## strona 415

```bash
sudo chroot /mnt
grub-install /dev/sda
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian
update-grub
```


## strona 416

```bash
exit
sudo umount /mnt/run
sudo umount /mnt/sys
sudo umount /mnt/proc
sudo umount /mnt/dev
sudo umount /mnt/boot
sudo umount /mnt
sudo poweroff
```


## strona 417

```bash
sudo journalctl | grep apparmor
sudo aa-disable /etc/apparmor.d/<profil>
```

