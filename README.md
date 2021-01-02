# DLink Device Tracker (HNAP)
Device Tracker for D-Link Routers/APs for Home Assistant using HNAP.
HNAP integration taken from https://github.com/LinuxChristian/pyW215

## Installation
Please use [HACS](https://github.com/hacs/integration "HACS")

## Example Config
```yaml
device_tracker:
  - platform: dlink_device_tracker
    host: 192.168.1.2 # ap
    username: admin
    password: !secret ap_password
```
