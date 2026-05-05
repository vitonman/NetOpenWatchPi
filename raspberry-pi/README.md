# Raspberry Pi GPIO Navigation

The Raspberry Pi can act as a small display and hardware control surface for
NetOpenWatchPi. The monitoring engine, API server, and frontend server still run
on the Windows host machine. The Pi opens the host frontend in Chromium and this
GPIO bridge converts physical controls into keyboard events for the web UI.

## Controls

- `MODE` button on GPIO 23 -> `M`
- `BACK` button on GPIO 24 -> `Escape`
- rotary encoder press on GPIO 22 -> `Enter`
- rotary encoder A/B on GPIO 17/27 -> `ArrowUp` / `ArrowDown`

## Dependencies

Install the Pi-side dependencies:

```bash
sudo apt update
sudo apt install -y python3-gpiozero python3-evdev
```

Load the Linux uinput module:

```bash
sudo modprobe uinput
```

For persistent loading after reboot, add `uinput` to `/etc/modules`.

## Manual Run

From the project directory on the Pi:

```bash
cd ~/NetOpenWatchPi/raspberry-pi
sudo python3 gpio_nav_bridge_uinput.py
```

## Autostart With systemd

Copy the service file:

```bash
sudo cp netopenwatchpi-gpio.service /etc/systemd/system/
```

If your project is not located at `/home/pi/NetOpenWatchPi`, update
`WorkingDirectory` and `ExecStart` in the service file before enabling it.

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable netopenwatchpi-gpio.service
sudo systemctl start netopenwatchpi-gpio.service
```

Check status and logs:

```bash
systemctl status netopenwatchpi-gpio.service
journalctl -u netopenwatchpi-gpio.service -f
```
