import subprocess
import json
import re

def get_udp_endpoints():
    ps_cmd = 'Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess | ConvertTo-Json'
    res = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True)
    try:
        endpoints = json.loads(res.stdout)
        if isinstance(endpoints, dict):
            endpoints = [endpoints]
        return endpoints
    except Exception:
        return []

def get_process_map():
    ps_cmd = 'Get-Process | Select-Object Id, ProcessName | ConvertTo-Json'
    res = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True)
    try:
        procs = json.loads(res.stdout)
        if isinstance(procs, dict):
            procs = [procs]
        return {p['Id']: p['ProcessName'] for p in procs if 'Id' in p and 'ProcessName' in p}
    except Exception:
        return {}

if __name__ == '__main__':
    pmap = get_process_map()
    endpoints = get_udp_endpoints()
    print(f"Total UDP endpoints active: {len(endpoints)}")
    for ep in endpoints:
        port = ep.get('LocalPort')
        pid = ep.get('OwningProcess')
        pname = pmap.get(pid, 'Unknown')
        if port in [27015, 7777] or 'steam' in pname.lower() or 'marathon' in pname.lower():
            print(f"  Port {port:<6} -> PID {pid:<6} ({pname})")
