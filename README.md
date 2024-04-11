<p align="center">
  <img src="image/Kirasec_Wifi.png" alt="Kirasec Wifi">
</p>

# WifiDeAuth
# Wi-Fi Security Tools

This collection of Python scripts utilizes the Scapy library to perform various Wi-Fi network operations including scanning for access points and devices, capturing probe requests, and executing deauthentication attacks. These tools are designed for educational purposes and network security testing in authorized environments.

## Requirements

- A Linux-based system with wireless capabilities.
- Python 3.x installed.
- Scapy library installed.
- Pandas library installed.
- A network interface capable of monitor mode.

## Installation

1. Ensure Python 3.x is installed on your system. You can download it from the official website or install it using your distribution's package manager.
2. Install Scapy and Pandas using pip:

   ```
   pip install scapy pandas
   ```

3. Clone this repository or download the scripts directly to your local machine.

## Usage

### Access Point Scanner (`access_point_scanner.py`)

Scans for Wi-Fi access points and lists them with their BSSID, SSID, signal strength, channel, and encryption type.

```
sudo python access_point_scanner.py
```

### Deauthentication Test (`deauth_single_device_test.py`)

Sends deauthentication frames to disconnect a specific device from a network. Replace `your interface`, `test network`, and `test device` with the actual values.

```
sudo python deauth_single_device_test.py
```

### Deauthentication with Arguments (`deauth_with_arguments.py`)

Allows for command-line arguments to specify target and gateway MAC addresses for deauthentication.

```
sudo python deauth_with_arguments.py <target MAC> <gateway MAC> [options]
```

### Probe Request Scanner (`probeReqs.py`)

Captures and logs probe request packets sent by nearby Wi-Fi devices.

```
sudo python probeReqs.py
```

### Wi-Fi Scanner (`wifiscanner.py`)

Combines network and device scanning, then allows for deauthentication of selected devices.

```
sudo python wifiscanner.py
```

## Disclaimer

These tools are intended for educational and ethical testing purposes only. Unauthorized use of these tools against networks without explicit permission is illegal. The author assumes no liability for any misuse or damage.

## License

[MIT License](https://opensource.org/licenses/MIT)