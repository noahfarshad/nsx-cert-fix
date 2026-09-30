# NSX certificate replacement

Replace expired NSX Manager API certificates, and delete a failed edge deployment when you name it. Plan is the default. Nothing is written without `--commit`.

License: GPL-3.0. Built and proved out for [essential.coach](https://essential.coach).
Full write-up: [When the NSX Manager Certificate Is Already Expired](https://essential.coach/nsx-manager-certificate-already-expired/).

This is the certificate follow-on, not the assessment. Read the managers first. Rotate after you know which certificates are expired.

## Run

```bash
export NSX_PASSWORD=...
python3 nsx_cert_fix.py --manager nsx.example.com
python3 nsx_cert_fix.py --manager nsx.example.com --commit
python3 nsx_cert_fix.py --manager nsx.example.com --delete-edges edge01,edge02 --commit
```

Each node's API certificate is applied one node at a time. The cluster VIP certificate is last. The API on a node is unavailable for about a minute while it applies. The data plane is not touched.

`--csr-dir` writes one CSR and key per name and stops. Have the CA sign them as server certificates, then `--import-dir` applies the signed files.

Certificate verification is off for these calls. The certificate you are about to replace is the one that would have been checked, and it is already expired. Keys land in a mode 700 directory. Keep them or delete them. Do not commit them.
