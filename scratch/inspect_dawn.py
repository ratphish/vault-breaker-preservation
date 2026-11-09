with open(r'D:\Dawnv0.1.5.2\payload\steam_api64.dll', 'rb') as f:
    data = f.read()

target = b'"entitlements":'
pos = data.find(target)
if pos != -1:
    print(data[pos-1500:pos+3000].decode('latin1', errors='ignore'))
