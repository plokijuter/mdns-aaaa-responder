# mdns-aaaa-responder

**Stops the mDNS AAAA query storm caused by Amazon devices (Echo, Fire TV…) on networks where a PC has no IPv6.**
Windows and Linux. Single static binary, Go standard library only.

*Version française plus bas.*

## The problem

Some Amazon devices (observed: Echo Show; reported elsewhere: Fire TV Stick 4K Max, Fire TV Cube, Echo Dot)
ask for the IPv6 address (`AAAA` record) of a computer's `.local` name over mDNS. When that computer has
**no IPv6 address**, it correctly answers "no AAAA" (an NSEC record). The Amazon device ignores that answer
and asks again immediately — **thousands of packets per second** (up to 3,400/s measured), sent as multicast
to every device on the network. The whole Wi-Fi becomes unusable: cameras drop, phones lag, pings to the
router go to several seconds, while wired devices look fine.

A common way to end up with no IPv6: the **NordVPN client disables IPv6 on every network adapter** (Windows:
`Ipv6LeakBlocker` turns the `ms_tcpip6` binding back off within seconds if you re-enable it; Linux: it sets
`disable_ipv6`). See [NordSecurity/nordvpn-linux#1287](https://github.com/NordSecurity/nordvpn-linux/issues/1287).
The Amazon side is reported, without a fix, on the
[Amazon developer forum](https://community.amazondeveloper.com/t/possible-fire-os-networking-issue-repeated-mdns-aaaa-queries-2-600-mdns-packets-sec-can-overload-entire-local-networks/28820).

## What it does

It listens to mDNS on your LAN adapter and answers the looping `AAAA` questions for your computer's name with a
**link-local IPv6 address that exists on no adapter** (`fe80::aaaa` by default). The Amazon device caches the
answer and stops asking. It never touches the network configuration, so a VPN that forbids IPv6 has nothing
to undo.

Precautions, so the fake address stays out of the way:

- **Only loopers are answered.** A source that asks at least 5 times in 10 s (`-seuil`, `-fenetre`), or a
  device whose MAC address belongs to Amazon (read from the ARP table, 175 prefixes + 3 finer blocks from the
  Wireshark manufacturer database). A normal device asking once keeps the usual "no AAAA" answer.
- **Unicast first** for non-Amazon loopers (a deliberate deviation from RFC 6762 §6, which wants multicast), so
  the rest of the network does not see the address. If the source keeps looping, it falls back to multicast
  for one hour, with a **short TTL (120 s, `-ttl-repli`)**. Measured: Amazon devices ignore unicast answers,
  which is why they get multicast straight away.
- **At most one answer per second** per destination, so it can never feed the storm.
- QU questions get unicast; legacy queries (source port ≠ 5353) get the ID and question echoed, no cache-flush
  bit and a TTL ≤ 10 s (RFC 6762 §6.7). Only class IN or ANY is answered.
- **Steps aside** while a real `AAAA` for the name is published (including by the machine itself, multicast
  loopback is enabled for that), until its TTL expires (capped at 1 h) or it is withdrawn — and while the
  selected adapter itself has an IPv6 address. Only valid mDNS responses count: source port 5353, opcode and
  rcode 0, source on the selected link.
- **Only the selected link counts.** Packets whose source is outside the adapter's subnet are ignored; on
  Linux, `IP_MULTICAST_ALL` is turned off and the arrival interface of every packet is checked (`IP_PKTINFO`).
- All answers are sent with **IP TTL 255**, unicast included (RFC 6762 §11).
- Per-source state is bounded (4,096 sources) and forgotten after 2 h of silence.
- On start-up, and with `-retrait`, it sends a **goodbye** (TTL 0) that clears the fake address from caches.

Result on the network where it was written: from bursts of 700–1,100 questions every two minutes (and up to
3,400 packets/s before) down to 4–12 questions per minute.

## Usage

```
mdns-aaaa-responder -ip 192.168.1.10                     # this PC's IPv4 on the LAN (required)
                    [-nom mypc.local]                    # name to defend (default: hostname + .local)
                    [-ipv6 fe80::aaaa]                   # fake link-local address to announce
                    [-journal file.log] [-etat status.json]
mdns-aaaa-responder -ip 192.168.1.10 -retrait            # send the goodbye and exit
mdns-aaaa-responder -ip 192.168.1.10 -mac-de 192.168.1.20,192.168.1.21   # diagnostic: MAC + Amazon?
```

All options: `-h`. The log writes a one-line summary per minute when there is activity. `-etat` writes a small
JSON status file every 15–30 s (useful for a watchdog: if it is older than 3 minutes, the process is stuck).

### Windows

Run it as a scheduled task at start-up (SYSTEM), and allow inbound UDP 5353 for the program:

```powershell
$exe = 'C:\Tools\mdns-aaaa-responder.exe'
New-NetFirewallRule -DisplayName 'mdns-aaaa-responder (UDP 5353 in)' -Direction Inbound -Program $exe `
    -Protocol UDP -LocalPort 5353 -Action Allow -Profile Any
$a = New-ScheduledTaskAction -Execute $exe -Argument '-ip 192.168.1.10 -journal C:\Tools\mdns-aaaa-responder.log'
$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName MdnsAaaaResponder -Action $a -Trigger (New-ScheduledTaskTrigger -AtStartup) `
    -Settings $s -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest)
Start-ScheduledTask MdnsAaaaResponder
```

Uninstall: `Stop-ScheduledTask MdnsAaaaResponder`, run once with `-retrait`, then `Unregister-ScheduledTask` and
remove the firewall rule.

### Linux

It shares UDP 5353 with Avahi (`SO_REUSEADDR`). No root needed. Example systemd unit
(`/etc/systemd/system/mdns-aaaa-responder.service`):

```ini
[Unit]
Description=mDNS AAAA responder (stops Amazon AAAA query storms)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/mdns-aaaa-responder -ip 192.168.1.10
ExecStopPost=/usr/local/bin/mdns-aaaa-responder -ip 192.168.1.10 -retrait
Restart=always
DynamicUser=yes

[Install]
WantedBy=multi-user.target
```

## Build

```
go test ./...
GOOS=windows GOARCH=amd64 go build -o mdns-aaaa-responder.exe .
GOOS=linux   GOARCH=amd64 go build -o mdns-aaaa-responder .
GOOS=linux   GOARCH=arm64 go build -o mdns-aaaa-responder .   # Raspberry Pi 64-bit
```

Supported platforms: **Windows and Linux** (the ARP lookup used for Amazon detection exists only there).
Tested in production on Windows. On Linux: unit and socket tests (TTL, `IP_MULTICAST_ALL`, arrival interface),
a fuzz test of the DNS decoder, and an end-to-end mDNS test; coexistence with a running **Avahi daemon has not
been validated yet**. Code comments are in French.

## Limits

- It cannot fix the Amazon bug, only make the device stop asking. If your PC gets a real IPv6 address
  later (e.g. your VPN stops disabling IPv6), you no longer need it; it steps aside automatically meanwhile.
- In fallback/Amazon mode the fake address is multicast, so other devices may cache it while answers keep
  coming (TTL 120 s, renewed by each answer). It is link-local and unused; clients fall back to IPv4, but
  nothing guarantees how fast every client does.
- IPv4 multicast only (the devices also ask over IPv6 multicast, which a PC without IPv6 cannot receive; the
  IPv4 answer was enough in practice).

---

## Français

**Arrête la tempête de questions mDNS AAAA des appareils Amazon (Echo, Fire TV…) sur un réseau où un PC n'a pas
d'IPv6.** Windows et Linux, un seul binaire.

Certains appareils Amazon demandent l'adresse IPv6 du nom `.local` d'un PC. Si ce PC n'a pas d'IPv6 (cas
typique : le client NordVPN coupe l'IPv6 sur toutes les cartes), il répond « pas d'AAAA », réponse que
l'appareil ignore : il redemande aussitôt, des milliers de fois par seconde, et tout le Wi-Fi devient
inutilisable. Ce programme répond à ces appareils une adresse IPv6 lien-local fictive (`fe80::aaaa`), qu'ils
gardent en cache : la boucle s'arrête. Il ne modifie aucun réglage réseau.

Il ne répond qu'aux appareils qui bouclent (≥ 5 questions en 10 s) ou reconnus Amazon par leur adresse MAC,
au plus une fois par seconde, se retire si une vraie adresse IPv6 apparaît, et efface la fausse adresse des
caches au démarrage (`-retrait` pour le faire à la demande). Installation : voir les exemples Windows (tâche
planifiée SYSTEM + règle de pare-feu UDP 5353) et Linux (service systemd) ci-dessus. Seule option obligatoire :
`-ip`, l'adresse IPv4 du PC sur le réseau local.

## License

MIT — see [LICENSE](LICENSE).
