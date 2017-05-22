#!/bin/bash

echo "--------------------------------- OCS Panels Installer for Debian -------------------------------"
echo "                             ALL SUPPORTED BY: ZONA VPS UNTUK RAKYAT                             "
echo "                     https://www.facebook.com/groups/preaker.bandung/                      "
#echo "                                    ALL SUPPORTED BY SELLER VPS                                   "
#echo "                               https://www.facebook.com/seller.vps.net                             "
echo "                    DEVELOPED BY ALIYA HAURA (fb.com/aliyahaura02, 089697708638)                     "
echo ""
echo ""
echo "Saya perlu mengajukan beberapa pertanyaan sebelum memulai setup"
echo "Anda dapat membiarkan pilihan default dan hanya tekan enter jika Anda setuju dengan pilihan tersebut"
echo ""
echo "Pertama saya perlu tahu password baru user root MySQL:"
read -p "Password baru: " -e -i sellervps DatabasePass
echo ""
echo "Terakhir, sebutkan Nama Database untuk OCS Panels"
echo "Tolong, gunakan satu kata saja, tidak ada karakter khusus selain Underscore (_)"
read -p "Nama Database: " -e -i OCS_PANEL DatabaseName
echo ""
echo "Oke, itu semua saya butuhkan. Kami siap untuk setup OCS Panels Anda sekarang"
read -n1 -r -p "Tekan sembarang tombol untuk melanjutkan..."

#apt-get update
apt-get update -y
apt-get install build-essential expect -y

apt-get install -y mysql-server

#mysql_secure_installation
so1=$(expect -c "
spawn mysql_secure_installation; sleep 3
expect \"\";  sleep 3; send \"\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect eof; ")
echo "$so1"
#\r
#Y
#pass
#pass
#Y
#Y
#Y
#Y

chown -R mysql:mysql /var/lib/mysql/
chmod -R 755 /var/lib/mysql/

apt-get install -y nginx php5 php5-fpm php5-cli php5-mysql php5-mcrypt
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.old
curl http://scripts.gapaiasa.com/OCSPanels/nginx.conf > /etc/nginx/nginx.conf
curl http://scripts.gapaiasa.com/OCSPanels/vps.conf > /etc/nginx/conf.d/vps.conf
#curl http://anekascript.anekavps.us:81/OCSPanels/nginx.conf > /etc/nginx/nginx.conf
#curl http://anekascript.anekavps.us:81/OCSPanels/vps.conf > /etc/nginx/conf.d/vps.conf
sed -i 's/cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /etc/php5/fpm/php.ini
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf

useradd -m vps
mkdir -p /home/vps/public_html
echo "<?php phpinfo() ?>" > /home/vps/public_html/info.php
chown -R www-data:www-data /home/vps/public_html
chmod -R g+rw /home/vps/public_html
service php5-fpm restart
service nginx restart

apt-get install -y git
cd /home/vps/public_html
git init
git remote add origin https://github.com/youree82/OcsPanels.git
git pull origin master

#mysql -u root -p
so2=$(expect -c "
spawn mysql -u root -p; sleep 3
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"CREATE DATABASE IF NOT EXISTS $DatabaseName;EXIT;\r\"
expect eof; ")
echo "$so2"
#pass
#CREATE DATABASE IF NOT EXISTS OCS_PANEL;EXIT;

chmod 777 /home/vps/public_html/config
chmod 777 /home/vps/public_html/config/config.ini
chmod 777 /home/vps/public_html/config/route.ini

clear
echo "Buka Browser, akses alamat http://$MYIP:81/ dan lengkapi data2 seperti dibawah ini!"
echo "Database:"
echo "- Database Host: localhost"
echo "- Database Name: $DatabaseName"
echo "- Database User: root"
echo "- Database Pass: $DatabasePass"
echo ""
echo "Admin Login:"
echo "- Username: sesuai keinginan"
echo "- Password Baru: sesuai keinginan"
echo "- Masukkan Ulang Password Baru: sesuai keinginan"
echo ""
echo "Klik Install dan tunggu proses selesai, lalu tutup Browser dan kembali lagi ke sini (Putty) dan kemudian tekan tombol [ENTER]!"

sleep 3
echo ""
read -p "Jika Step diatas sudah dilakukan, silahkan Tekan tombol [Enter] untuk melanjutkan..."
echo ""
read -p "Jika anda benar-benar yakin Step diatas sudah dilakukan, silahkan Tekan tombol [Enter] untuk melanjutkan..."
echo ""

sed -i '$ i\deb http://download.webmin.com/download/repository sarge contrib' /etc/apt/sources.list
sed -i '$ i\deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib' /etc/apt/sources.list
cd /root
wget http://www.webmin.com/jcameron-key.asc
apt-key add jcameron-key.asc
apt-get update
apt-get install -y webmin
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
service webmin restart

apt-get -y --force-yes -f install libxml-parser-perl

rm -R /home/vps/public_html/installation

cd
rm -f /root/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# info
clear
echo "=======================================================" | tee -a log-install.txt
echo "Silahkan login OCS Panels di http://$MYIP:81/" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "ALL SUPPORTED BY ZONA VPS UNTUK RAKYAT" | tee -a log-install.txt
echo "https://www.facebook.com/groups/Zona.VPS.Untuk.Rakyat/" | tee -a log-install.txt
#echo "ALL SUPPORTED BY ANEKA VPS" | tee -a log-install.txt
#echo "https://www.facebook.com/aneka.vps.us" | tee -a log-install.txt
echo "DEVELOPED BY YURI BHUANA (fb.com/youree82, 085815002021)" | tee -a log-install.txt
echo "Credit to Ade Cikiciew & Hariyanto Dwi Semangat" | tee -a log-install.txt
echo "Thanks to Original Creator Ade Cikiciew" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Log Instalasi --> /root/log-install.txt" | tee -a log-install.txt
#echo "" | tee -a log-install.txt
#echo "SILAHKAN REBOOT VPS ANDA !" | tee -a log-install.txt
echo "=======================================================" | tee -a log-install.txt
cd ~/
