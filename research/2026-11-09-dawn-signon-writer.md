# Dawn SignOn writer, release 0.1.5.2

The local Dawn package identifies its game build as Destiny 2 build 86657. Its x64 DLL has SHA-256 `88c75ac8f411215a87a6e62758f9dcc34fb4bab903ebdec074c2e08164acc7c8`. The probe invokes the writer at RVA `0x4BDD70` in Unicorn with synthetic keys, loopback, port 7777, and the three entitlement IDs seen in Marathon's November 9 request. The writer and its protobuf helpers execute from the DLL. The probe supplies memory, string-formatting and stack-cookie stubs. All values below describe the output for those inputs. [Probe](../scripts/probe_dawn_signon_writer.py) · [Writer disassembly](../scripts/dawn_signon_asm.txt)

| Field path | Dawn writer output | Marathon emulator at 8ca1e4f |
|---|---|---|
| 1 | Varint zero on success | Omitted |
| 2.1 through 2.4 | Byte lengths 16, 16, 16, 32. The first is zero-filled. The rest copy context bytes at offsets 0, 16, 32. | Byte lengths 16, 32, 32, 16 |
| 2.6 and 14 | Both equal the supplied IPv4 integer. The helper formats 0x7f000001 as 127.0.0.1. | On x86-64 Windows both equal 0x0100007f for loopback |
| 2.12 | Nested field 1 = 1, field 3 contains 16 bytes of 0x11, field 4 contains 16 bytes of 0x22 | Omitted |
| 2.14 through 2.16 | Three HTTP URLs with the IP rendered in dotted decimal, followed by /cfg_a/, /cfg_b/, /cfg_c/ | Omitted |
| 4.1, 4.2 | Both equal 1 | Membership ID, then 1 |
| 4.3 | Absent with context flag byte +0x5c clear. When set, the 29-byte blob includes length 16 at offset 8, sixteen input bytes, then four zero bytes. | Always present, with length 20 at offset 8 and twenty zeros |
| 6, 13 | Literal ASCII d2legacy and live | Build string and GOLRETAIL |
| 10 | One length-delimited message containing three occurrences of varint field 1, each preceded by byte 0x08 | Raw packed varints from request field 15 |

At writer RVA `0x4BE535`, Dawn emits key 8 before each granted ID. At `0x4BE5FC` through `0x4BE677`, it emits outer field 1 with value zero. Its helper at `0x4BEEA0` emits success field 12 and the three configuration URLs. The older hypothesis that key 8 corrupts the grant is incompatible with Dawn's writer. Marathon build 26136895 may implement a different reader. Neither the Destiny 2 writer nor the layout of Marathon's outbound request identifies the client-side branch that produces SQUIRREL. [Emulator](../scripts/marathon_server.py)

## Reproduce

Run in PowerShell from the repository root. The local Python tool directory contains pefile and Unicorn. The probe prints the length, hash, and decoded field list. Its synthetic session values are deterministic.

```powershell
$env:PYTHONPATH = 'D:/Marathon-preservation/tools/python'
python scripts/probe_dawn_signon_writer.py D:/Dawnv0.1.5.2/payload/steam_api64.dll
python scripts/probe_dawn_signon_writer.py D:/Dawnv0.1.5.2/payload/steam_api64.dll --config-key
```

The first call returned 279 bytes with SHA-256 `59b88c990b7756d569d9129c597159ca4286cff1dbe2387f13b6764c2eef2e2f`. The optional config key produced 310 bytes with SHA-256 `e9f68147b3a4066969325d1f45246898e959efb14e8773c20cb46bbc3358b176`.
