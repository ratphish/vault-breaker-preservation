# Preserved 248199 client reaches BAP connectivity

On November 18, 2026, the isolated preserved client passed the previous Marmot
package-registration failure and advanced to a loading screen. It subsequently
reported Centipede. Saved telemetry identifies the new failure as
`error.no_bap_connection` after approximately 20 seconds. Offline sign-in through
the home screen remains incomplete.

## Verified run

- Client PID 17060, backend PID 26044.
- Executable at `D:\Marathon-preservation\client-248199-retail-packages\Marathon.exe`,
  build `248199.26.10.21.2300.gol_retail.rc`.
- The isolated copy contains its original two unpatchable bootstrap packages and
  626 retail packages. All 626 package filenames, IDs, and header fingerprints
  matched the intact signed 248673 manifest during staging. Copies were verified
  against their sources by SHA-256.
- SignOn uses the recovered content-token candidate through
  `--bootstrap-token-file D:\Marathon-preservation\analysis\content-token-recovery-20261117\content-token-candidate.bin`.
- At 00:00:29 Eastern, the client fetched the 31,424-byte signed manifest with
  HTTP 200. Its SHA-256 is
  `b4645834c7a8874ed56733186627f3ee16e3cf8809f84bc1e926415f44d9f907`.
- SignOn field 4.3 records 100 and 101 advertise the local manifest URL and GUID
  `f5e5c169-9ebc-42c9-b4fb-d6b234c097a0`.
- At 00:00:32.942 Eastern, the proxy records
  `[TCP] connect(IPv4) to 1.0.0.127:7505 (socket=7400)`.
- At approximately 00:00:52.977 Eastern, telemetry requests cleanup with
  `error.no_bap_connection`, reason hash 4195836351.

The reduced telemetry and exact TCP observations are retained in
[the companion evidence file](2026-11-18-content-token-bap-evidence.json), with
SHA-256 hashes and full paths of the source telemetry files. Numeric telemetry
enums have their original representation. They should not be silently treated
as decimal bootflow state IDs.

## Why the token mattered

The backend's previous 16-byte token contained a NUL at offset 15. Native reader
key `0x007B620F` populates configuration offset `0x26C0`. Getter `0x30162BB0`
returns `config+0x2618`, which becomes R13 in `0x31047B90`. The call at
`0x31047C31` passes `R13+0xA8`, exactly `config+0x26C0`, to `0x31349F40`.

That function measures the string length and rejects lengths below 16 before
updating the registration input. On the vector path, `0x31349FBD` loads its first
16 bytes into XMM0. The writer at `0x1577ED94` adds the 16-byte constant at
`0x32D260F0`, and `0x1577ED9C` stores the result at `0x344BE188`.

The recovered candidate is a 16-character string from saved image RVA
`0x32D24A40`, referenced by a native initializer at `0x1EF7F112`. Its SHA-256 is
`fa9b1440694d928e219ca80cee5535b259a67c4bb40f4b05cd23b9e0dcc6c5da`.
Offline replay of the transform and native fingerprint calculation produced
`0x281141FD`, matching the patchable package headers at offset `0x128`.
The bootstrap control produced its expected `0xFB438DF4`.

Reproducible verification and the candidate remain in
`D:\Marathon-preservation\analysis\content-token-recovery-20261117`.
The candidate was recovered from native image data. No readable production
SignOn response was available to establish that it is the production wire token.
This run supplies evidence that it resolves the previous initialization barrier
for this isolated package combination.

## Earlier failures and limits

1. Signed 248673 manifest with original 248199 patchable packages produced
   Marmot with registration result -90 and three explicit package-open failures.
2. A reconstructed 625-entry inventory matching 248199 headers produced Turtle,
   `error.content_manifest_signature_failure`. It changed the signed payload.
3. The intact signed manifest and 626 matching retail packages, with the old
   token, produced Marmot with result -87. The native check at `0x318738A4`
   compares the header fingerprint against the computed value and selects -87
   on mismatch at `0x318738AC`.
4. The recovered token advanced the isolated client to BAP connectivity.

The default `config/bootstrap_token.bin` still contains the earlier value.
Reproduction requires the explicit candidate override until a separately
reviewed default change is made. The current backend serves the intact signed
manifest. The reconstructed manifest is retained as an unsuccessful experiment.

## Next investigation

Trace the IPv4 relay address serialized in SignOn and its native conversion to
the socket address. `1.0.0.127` is the byte reversal of intended loopback
`127.0.0.1`, making byte order a strong hypothesis. Verify the proxy logging
conversion and the actual Winsock argument before modifying serialization.
The address log alone does not establish that the socket used that destination.

Use offline evidence first, preserve the isolated client's outbound firewall
block, and continue without a debugger. Registration progress does not yet
establish gameplay compatibility between the 248199 executable and retail data.

## Git checkpoint scope

This checkpoint records the investigation and reduced evidence. The working
tree also contains extensive pre-existing implementation changes and untracked
artifacts. This documentation commit is not a complete runnable source snapshot.
