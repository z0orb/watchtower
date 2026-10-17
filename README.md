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
- [Npcap](https://npcap.com) for live ARP-spoof detection and a safer first-time gateway check. Without it
  the gateway is still pinned, but forged packets aren't reported. Install Npcap before Watchtower, or
  restart the service afterwards (`sc stop Watchtower && sc start Watchtower`).

## Install

Download `watchtower.exe` from the [latest release](https://github.com/z0orb/watchtower/releases/latest) and
double-click it. It asks to install, Windows asks for administrator permission, and the tray icon appears.
Double-clicking a newer version later offers to update. To remove it, use **Settings › Apps › Watchtower ›
Uninstall**.

The exe isn't code-signed yet, so on a fresh download Windows SmartScreen may say "Windows protected your PC":
choose **More info › Run anyway**.

From an Administrator terminal instead:

```
watchtower.exe install     # copies itself to %ProgramFiles%\Watchtower, starts the service, adds the tray to startup
watchtower.exe uninstall   # removes it all, unpins the gateway, restores DNS and adapter settings
```

The tray icon shows the status and pops up alerts. Its menu has **Re-trust gateway** (use it only after replacing
your router), **Restore DNS**, **Optimize adapter** / **Revert tuning** (take effect after a reboot), **Do Not Disturb** (alerts are only logged;
turning it off shows one "N alerts while notifications were paused" toast) and **Open log**.
If the service stops, the tray starts it again; to turn protection off for good, use `uninstall`.
State and logs live in `%ProgramData%\Watchtower`.

## Build

```
GOOS=windows go build ./cmd/watchtower
go test ./...
```

## License

MIT
