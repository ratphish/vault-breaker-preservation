# Native initialization ordering and configuration replay

The saved forced-state run establishes a proxy ordering defect independently
of the unresolved SignOn result. PID 31988 enters LocalSOS at
03:07:07.883 UTC, waits until 03:07:37.878, then forwards slot 3. The native
SignOn HTTP request starts at 03:07:38.151. The separate return-observer run
establishes that slot 3 (RVA 309c0620) returns before HTTP request initiation.
Waiting for HTTP inside this initializer delays the work needed before that
request. Returning zero when an earlier HTTP operation is complete can also
skip native initialization; that branch must not implement empty SOS actions.

`client_proxy/local_sos_actions.h` now forwards the original initializer exactly
once. It neither waits for HTTP nor substitutes success. A standalone native
regression test supplies pending and completed HTTP states with the local
empty-actions fixture present, and verifies argument, return, LastError and
errno preservation. The isolated candidate builds without observer flags at
`artifacts/local-sos-passthrough-20261113`; its manifest pins source and DLL
hashes. The candidate has NOT been deployed or run in Marathon.

The local backend was restarted as PID 7112 with its previous arguments,
including the existing bootstrap-token-file option and live settings directory.
The two recovered retail JSON files were added under their captured filenames.
Both `/GolRetail/direct_settings/...` URLs return HTTP 200 and byte-identical
bodies on loopback port 80. This repairs serving those known URLs, but does not
establish that the preserved client discovers or requests them. Existing empty
aliases, SignOn protobuf fields and the content manifest were not changed.

Validation: native initialization regression passed; 35 focused backend tests
passed; both active HTTP responses matched recorded SHA-256 values. All five
backend listeners belong to PID 7112. The outbound firewall block remains
enabled. Marathon stayed closed; deployed proxy SHA-256 remains
ba01f2fbf4175815883768e2efd7ff07e7c5c5d065b108b79c97eb7f928fefbf.

Active-backend verification and activation records are in
`D:\Marathon-preservation\analysis\backend-settings-replay-20261113-184653`.

## Remaining preservation dependency

The prior state-2 bypass exposed Termite, while task result 20 was already
pending. Neither this ordering correction nor HTTP replay proves that error
resolved. Do not clear result 20 or force later bootflow completion on this
evidence. A shim remains an acceptable preservation mechanism, but any new
state write must have its own identified object contract and controlled scope.

The reconstructed handler reads a distinct status object at RVA 367a1fe0;
state getter 2ffd3380 reads RVA 367a21d0 and result getter 2f52c9b0 can read
RVA 367a2228. The earlier publication context has ESI=3 and EBX=20. The
reconstructed selector-3 edge reaches 2fb02385 -> 309ed5e0, but the exact
producer of EBX=20 remains unverified. These are modeled code facts and a
historical runtime context, not a complete trace of one dynamic path.
