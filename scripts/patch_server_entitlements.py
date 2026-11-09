path = r'D:\vault-breaker-preservation\scripts\marathon_server.py'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

target = """        # Entitlements submessage (eliminates invalid wire type 7 corruption!)
        entitlements_sub = ProtobufWriter()
        entitlements_sub.varint(1, 3065800)  # Marathon AppID"""

replacement = """        # Extract requested entitlements from client request Field 15
        client_entitlements = [3065800, 3760193537, 3760193538]
        try:
            req_idx = 0
            while req_idx < len(steam_ticket):
                tag = 0
                shift = 0
                while req_idx < len(steam_ticket):
                    b = steam_ticket[req_idx]
                    req_idx += 1
                    tag |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
                fnum = tag >> 3
                wtype = tag & 7
                if wtype == 0:
                    while req_idx < len(steam_ticket) and (steam_ticket[req_idx] & 0x80): req_idx += 1
                    req_idx += 1
                elif wtype == 1:
                    req_idx += 8
                elif wtype == 2:
                    length = 0
                    shift = 0
                    while req_idx < len(steam_ticket):
                        b = steam_ticket[req_idx]
                        req_idx += 1
                        length |= (b & 0x7F) << shift
                        if not (b & 0x80): break
                        shift += 7
                    val_bytes = steam_ticket[req_idx:req_idx+length]
                    req_idx += length
                    if fnum == 15:
                        v_i = 0
                        while v_i < len(val_bytes):
                            v_val = 0
                            v_shift = 0
                            while v_i < len(val_bytes):
                                vb = val_bytes[v_i]
                                v_i += 1
                                v_val |= (vb & 0x7F) << v_shift
                                if not (vb & 0x80): break
                                v_shift += 7
                            if v_val not in client_entitlements:
                                client_entitlements.append(v_val)
                elif wtype == 5:
                    req_idx += 4
        except Exception as e:
            server_log(f"[-] Error extracting client entitlements: {e}")

        # Entitlements submessage granting all requested & required entitlements
        entitlements_sub = ProtobufWriter()
        for ent_id in client_entitlements:
            entitlements_sub.varint(1, ent_id)
        server_log(f"[SignOn] Granted entitlements: {client_entitlements}")"""

if target in text:
    text = text.replace(target, replacement, 1)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    print("SUCCESS: Patched entitlements into marathon_server.py!")
else:
    print("ERROR: Target not found in marathon_server.py")
