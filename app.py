import eel
from requests import get
from csv import reader
from subprocess import run
from webbrowser import open as wbopen

# set folder 
eel.init('source')

# Removing Rules
@eel.expose
def remove_rule():
    rule = "netsh advfirewall firewall delete rule name='BadIP'"
    run(["Powershell", "-Command", rule])


# Adding Inbound Rule 
@eel.expose
def inbound_rule():
    response = get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv").text

    rule = "netsh advfirewall firewall delete rule name= 'BadIP'"
    run(["Powershell", "-Command", rule])

    mycsv = reader(filter(lambda x: not x.startswith("#"), response.splitlines()))
    for row in mycsv:
        ip = row[1]
        if(ip)!=("dst_ip"):
            print("Added Rule to block:", ip)
            rule = "netsh advfirewall firewall add rule name='BadIP' Dir=In Action=Block RemoteIP=" + ip  # Fill Dir= with (Out or In)
            run(["Powershell", "-Command", rule])

# Adding Outbound Rule 
@eel.expose
def outbound_rule():
    response = get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv").text

    rule = "netsh advfirewall firewall delete rule name= 'BadIP'"
    run(["Powershell", "-Command", rule])

    mycsv = reader(filter(lambda x: not x.startswith("#"), response.splitlines()))
    for row in mycsv:
        ip = row[1]
        if(ip)!=("dst_ip"):
            print("Added Rule to block:", ip)
            rule = "netsh advfirewall firewall add rule name='BadIP' Dir=Out Action=Block RemoteIP=" + ip  # Fill Dir= with (Out or In)
            run(["Powershell", "-Command", rule])

# Opening Github in external tab.
@eel.expose
def open_github():
    wbopen("https://www.github.com/akshayalix/Firewall")


eel.start('index.html', size=(700, 500), position=(750, 300))