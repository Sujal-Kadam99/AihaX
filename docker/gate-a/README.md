# Gate A fixture harness

This is a **local-only positive-control fixture**, not the production scanner runner. It creates an internal-only Docker network with no host-published ports. It proves local DNS logging, connection capture, HTTP/HTTPS with normal certificate validation, and denial of all external egress from that network.

The test uses a fixed subnet (`172.30.77.0/24`), so run one instance at a time. Test private keys are generated locally and ignored by Git. Use a fresh run ID for each run.

```powershell
$env:AIHAX_CAMPAIGN_ID = 'gate-a-YYYYMMDD-NN'
python docker/gate-a/generate_certs.py
docker compose -f docker/gate-a/compose.yml -p aihax-gatea up -d
docker network inspect "aihax-gatea-$env:AIHAX_CAMPAIGN_ID"

docker exec aihax-gatea-scanner-1 curl --fail --silent --show-error http://fixture.gate.test/gate-a
docker exec aihax-gatea-scanner-1 curl --fail --silent --show-error --cacert /trust/ca.crt https://fixture.gate.test/gate-a
docker exec aihax-gatea-scanner-1 nmap -Pn -sT -p 80,443 fixture.gate.test
docker exec aihax-gatea-scanner-1 sh -lc 'strace -f -e trace=connect -o /evidence/blocked-egress.log curl --max-time 2 --silent --show-error http://203.0.113.5/'
docker stop aihax-gatea-capture-1
docker exec aihax-gatea-scanner-1 tcpdump -r /evidence/campaign.pcap -nn
docker logs aihax-gatea-resolver-1
docker compose -f docker/gate-a/compose.yml -p aihax-gatea down --remove-orphans
```

The bind-mounted evidence stays under `docker/gate-a/evidence` after `down`. The harness has **not** been wired into `ToolExecutionBoundary` or `campaign_worker`; the isolated network denies all external egress and does not prove authorization-scoped routing to a client target. Production subprocess execution stays blocked until that integration and its redirect/scope tests are implemented.
