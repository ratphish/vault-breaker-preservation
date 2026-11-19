"""Remove only local Marathon preservation mappings; back up the hosts file first."""
from datetime import datetime
from pathlib import Path
import os
import re
import sys

hosts = Path(os.environ['SystemRoot']) / 'System32' / 'drivers' / 'etc' / 'hosts'
data = hosts.read_bytes()
pattern = re.compile(
    rb'^\s*127\.0\.0\.1\s+(?:(?:[a-z0-9-]+\.)*signon\.goliath\.prod\.(?:gravityshavings|deadorbit)\.net|goliath\.prod\.(?:gravityshavings|deadorbit)\.net|frontdoor-prod-client\.fd\.analytics\.prod\.deadorbit\.net)\s*(?:#.*)?(?:\r?\n)?$',
    re.IGNORECASE,
)
lines = data.splitlines(keepends=True)
removed = sum(bool(pattern.fullmatch(line)) for line in lines)
if not removed:
    print('No Marathon loopback redirects found.')
    sys.exit(0)
result = b''.join(line for line in lines if not pattern.fullmatch(line) and
                  line.strip() != b'# Marathon Preservation Local Redirections')
backup_dir = Path(r'D:\Marathon-preservation\backups')
backup_dir.mkdir(parents=True, exist_ok=True)
backup = backup_dir / ('hosts-before-removal-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.bak')
with backup.open('xb') as stream:
    stream.write(data)
try:
    with hosts.open('r+b') as stream:
        if stream.read() != data:
            raise RuntimeError('Hosts file changed during preparation; no changes written.')
        stream.seek(0)
        stream.write(result)
        stream.truncate()
except PermissionError:
    print(f'Administrator access required. Backup: {backup}')
    sys.exit(1)
if hosts.read_bytes() != result:
    raise RuntimeError(f'Verification failed; backup: {backup}')
print(f'Removed {removed} Marathon redirects. Backup: {backup}')
