# Watchtower

Windows (10 LTSC, 10, 11) background tool that:

- **Defends against ARP spoofing** (including NetCut-style "cut-off" attacks): learns your gateway's
  real MAC, pins it as a static ARP entry, and alerts on forged ARP replies.
- **Auto-recovers dropped connections**: DNS flush and fallback to 1.1.1.1 / 8.8.8.8, DHCP renew,
  adapter restart. Disruptive steps only run when the connection is already dead, so live game
  sessions aren't interrupted.
- **Optional adapter tuning**: disables NIC power-saving and Energy-Efficient Ethernet (reversible).

> Status: early development.

## Requirements

- Windows 10 1809+ / Windows 11, administrator rights to install.
- [Npcap](https://npcap.com) for live ARP monitoring (without it Watchtower falls back to polling).

## Install

```
watchtower.exe install
watchtower.exe uninstall
```

## License

MIT
