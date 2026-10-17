# Changelog

All notable changes to Watchtower. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- If the service stops (killed, crashed past its restart limit, or stopped), the tray now starts it again
  within a minute instead of showing "The Watchtower service isn't running". `install` lets signed-in users
  start the service (not stop, reconfigure or delete it), so no admin prompt is needed. Run `install` again
  to get this on an existing installation.

## [0.1.2] - 2026-10-18

### Added
- **Do Not Disturb** in the tray menu: alert toasts are held and only logged. Turning it off shows one toast,
  "N alerts while notifications were paused", instead of every alert. It is off each time the tray starts.

### Changed
- Alerts held during fullscreen games and presentations are summarized the same way: a count, not a list.

## [0.1.1] - 2026-10-18

### Fixed
- Double-clicking `watchtower.exe` now opens the tray. Before, running it without arguments printed the usage
  and exited, so no tray icon appeared.
- Starting a second tray no longer adds a second icon; it shows a toast pointing to the running one
  (look under the ^ hidden icons).

### Changed
- Alert toasts are short: a title and one line, e.g. "Attack blocked — A device tried to impersonate your
  router." The full text is still written to the log.
- Shorter success toasts for Test protection, Optimize adapter and Revert tuning.

## [0.1.0] - 2026-10-17

First release.

- ARP-spoofing defense: pins the gateway's MAC with a static ARP entry, and a watchdog re-pins it if it changes.
- Live detection via Npcap: forged gateway replies, another device claiming your IP, ARP scans.
- Connection auto-recovery: DNS flush and public-DNS fallback (reverted when the router's DNS works again);
  DHCP renew and adapter restart only when the gateway and the internet are both unreachable.
- Tray: green/amber/red status icon, alert toasts (held during fullscreen games), Test protection,
  Re-trust gateway, Restore DNS, Optimize adapter / Revert tuning, Connection report, Open log.
- `install` / `uninstall` for the service and tray autostart.

[Unreleased]: https://github.com/z0orb/watchtower/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/z0orb/watchtower/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/z0orb/watchtower/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/z0orb/watchtower/releases/tag/v0.1.0
