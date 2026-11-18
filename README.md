# NetWarden

NetWarden is a network monitor and firewall for Windows. It shows what every app on your PC sends and receives, and lets you decide what is allowed.

- **Block all and ask.** Every app that tries to connect is blocked until you say yes. A pop-up near the clock asks you. In Beginner mode it asks **per app**; in Pro mode it asks **per address** (with one-click "allow the whole domain / whole app").
- **Block all except allowed apps.** Only the apps in your allowed groups (for example "Work" or "Browsers") can connect. Everything else is silently blocked and listed for you.
- **Block** an app, an address, a domain, or specific ports/protocols.
- **Pause** an app or the whole internet for a while. It's **allowed again automatically**.
- **Limit** upload speed, or how much data an app may use per day or month.
- **Runs in the background.** Once installed, it starts when you sign in, lives in the tray, and keeps enforcing your choices.

Switch between the **Beginner** and **Pro** interfaces at the top right of the window. The **Theme** button switches between **Classic 2000**, the default (a Windows 2000 look with grey 3D windows, navy title bars and green-on-black meters), **Classic 2000 dark** (the same look with charcoal windows and light text), and **Modern dark**. The permission pop-up follows the theme too. Apps are shown with their own program icon; apps without one (such as Windows services) get a coloured letter tile.

## Install (recommended)

1. Double-click **`Install NetWarden.bat`** and approve the administrator prompt.
2. Setup does the following:
   - copies NetWarden to `C:\Program Files\NetWarden`;
   - installs Python 3.12 for all users with winget if it's missing (or if it's only installed inside your user folder);
   - installs its dependencies;
   - registers a sign-in task that starts NetWarden in the background with admin rights, with no UAC prompt each time;
   - adds Start-menu and desktop shortcuts and an *Apps & features* entry;
   - starts NetWarden.
3. Look for the **shield icon** near the clock. Right-click it to switch modes, pause the internet, or quit. Click it to open the window.

To **uninstall**, go to Settings → Apps → NetWarden → Uninstall. This restores Windows Firewall's normal settings and removes everything NetWarden added.

## Updating

**Installed copy (one click).** NetWarden checks GitHub for a newer version at start-up and twice a day. When there is one, a notice appears in the window: click **Install update**. You can also check yourself under **Pro → Settings → Updates**. The update downloads the new version, runs its installer quietly, and restarts NetWarden. Your rules, groups, settings and usage history are kept. Nothing is installed without your click, and you can turn the automatic check off in the same place. In block-all mode, NetWarden briefly allows only its own connection to GitHub while it checks or downloads.

**Git clone.** Double-click **`update.bat`**. It runs `git pull` and then offers to install the new version on this PC.

### Publishing a new version (maintainers)

1. Commit your changes as usual.
2. Run **`release.bat`** (or `powershell -File release.ps1 2.2.0 "what changed"`). It bumps `__version__` in `netwarden/__init__.py`, commits, tags `v2.2.0` and pushes to `main`.
3. Installed copies offer the update within 12 hours, or right away with *Check now*.

The version number lives only in `netwarden/__init__.py`. An update is offered when the number on GitHub's `main` branch is higher than the installed one, so pushing code without bumping it doesn't trigger updates.

## Run without installing

- **`run.bat`**: runs from this folder with a console window. Closing the window stops it.
- **`demo.bat`**: demo mode with simulated apps and traffic. It needs no admin rights and changes nothing on your PC. Demo data is kept separately (`data\demo\`).

Only one NetWarden engine ever runs. If the installed copy is running, `run.bat` just opens its window.

## Emergency undo

**`cleanup.bat`** (also in the install folder) stops NetWarden, switches block-all mode off, puts back Windows Firewall's previous outbound setting, and removes every NetWarden rule and speed limit. It doesn't need Python.

## Safety nets

NetWarden refuses to quietly do things that could cut your PC off:

- **Risky changes need a second "Do it anyway" click.** This covers:
  - blocking or slowing a core Windows component (svchost, System, Defender, Windows Update, SmartScreen…);
  - blocking your router or DNS server;
  - blocking DNS/DHCP ports for all apps;
  - blocking huge address ranges (/8 or wider);
  - throttling the whole PC below 512 kbit/s;
  - a whole-PC data limit that blocks;
  - turning off or editing the "Windows essentials" group;
  - pausing or turning on block-all from a Remote Desktop session.
- **Timed blocks can't become permanent.** Every pause has a Windows task that removes it at the end time, even if NetWarden crashed or was killed.
- **"Block IP / host" asks** whether to block for just that app or all apps, and for 1 hour, 1 day, 1 week, or always. The default is the safest choice. Domain blocks forget addresses the domain hasn't used for 6 hours, so CDN servers shared with other sites don't stay blocked.
- **Block-all only engages once the Windows-essentials allow rules are really in place.** When you turn it off, the normal firewall policy is restored before any allow rule is removed. If restoring fails, the allow rules stay. If NetWarden finds block-all leftovers while its state says "off", it restores normal access.
- **Emergency reset** is in the Start menu ("NetWarden emergency reset"). It needs no Python and works even if NetWarden is broken.

If NetWarden is deleted without uninstalling while block-all was on, run this in an admin terminal to get the internet back:

```
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
```

## Protection modes

| Mode | What happens to an app you haven't allowed |
|---|---|
| **Normal** | It connects. Your own blocks, pauses and limits still apply. |
| **Block all: ask me** | It is blocked, and NetWarden asks you. Your answer becomes a firewall rule: allow/block this address, this domain, or the whole app, always or for 1 hour. *Later* asks again in 10 minutes. |
| **Only allowed apps** | It is blocked silently. Only apps in turned-on groups can connect. The attempts are listed in Pro → Permissions, where you can allow them with one click. |

**Groups.** The built-in **Windows essentials** group (Windows services and the kernel: DNS, DHCP, time, updates) and **My allowed apps** group exist from the start. You can create more groups in Pro → Permissions. Turning a group off blocks all of its apps at once.

## How it works

| Feature | Mechanism |
|---|---|
| Block-all | Windows Defender Firewall's **default outbound action is set to Block**, plus an *allow* rule for each app or address you approved. Because this is the firewall itself, it keeps protecting you even when NetWarden is closed or before you sign in. |
| Detecting "app X wants to connect" | NetWarden turns on Windows' *Filtering Platform Connection* failure auditing and subscribes to **Security event 5157** (connection blocked). Each event names the program, its process ID, and the destination address and port. |
| Pop-ups | A small always-on-top window (Tk) in the bottom-right corner. Because it runs in the elevated NetWarden process, other non-admin programs can't click "Allow" for you. |
| Connections, per-app traffic, DNS names | `psutil` and **WinDivert** (`pydivert`) in passive sniff mode. |
| Blocks / pauses | Firewall rules named `NetWarden_*`. Open TCP connections are reset so a block takes effect immediately. *Pause internet* also drops packets in the kernel. |
| Upload speed limits | Windows QoS policies. |
| Background / autostart | A Task Scheduler task at sign-in with *Run with highest privileges*. It runs `pythonw -m netwarden --background` (tray icon + pop-ups; log in `data\netwarden.log`). |
| Window | A local page served on `127.0.0.1` and protected by a per-session token. It opens in a chromeless Edge app window. The installed `data` folder (token, rules) is readable by Administrators only. |

## Good to know

- **Block-all stays on while NetWarden is closed.** That's what makes it a real firewall. Apps you haven't allowed can't connect, and nothing can ask you until NetWarden runs again. Switch to *Normal*, or run `cleanup.bat`, to undo it.
- **Apps usually retry by themselves** after you allow them. A browser page may need a refresh.
- **Pro mode asks per address**, and browsers contact many servers. Use *Allow domain* or *Allow app* in the pop-up for apps you trust.
- **Rules that already exist in Windows Firewall still count.** Some programs created their own *allow* rules at install time, and Windows has built-in core-networking rules. Apps covered by those can connect without asking. Check *Windows Defender Firewall → Advanced settings → Outbound rules* if an app connects that you didn't allow.
- **Auditing writes to the Security event log.** While block-all is on, every blocked connection is logged there, so that log fills up faster. NetWarden turns the auditing off again when you return to *Normal*.
- **Other limits:**
  - Upload speed limits apply to **uploads only**.
  - Blocking a domain blocks the IP addresses NetWarden knows for it, which can include shared CDN servers.
  - Some antivirus tools flag WinDivert. If that happens, per-app traffic counting turns off.
  - Timers, schedules and data limits only run while NetWarden is running. Once installed, that's always.

## Files

```
Install NetWarden.bat        installer (-> installer\install.ps1, uninstall.ps1)
run.bat / demo.bat / setup.bat
cleanup.bat / cleanup.ps1    emergency undo
update.bat                   git pull + reinstall (for a git clone)
release.bat / release.ps1    publish a new version (bump, tag, push)
netwarden/
  __main__.py   start-up, --background, --open launcher, single instance, logging
  engine.py     rules, timers, data caps, block-all policy, firewall/QoS reconcile
  lockdown.py   block-all modes, permission requests, answers, app groups
  agent.py      tray icon + permission pop-ups
  monitor.py    per-app / connection / endpoint statistics
  winapi.py     Windows Firewall, QoS, WinDivert, event-5157 watcher, TCP reset
  updater.py    update check + one-click install from GitHub
  icons.py      program icons for the window and pop-ups
  rules.py, dnsparse.py, server.py, sim.py, util.py
  web/          the window (Beginner + Pro)
```
