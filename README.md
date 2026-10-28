# CodeAlpha Basic Network Sniffer

## About the Project

I developed this Basic Network Sniffer using Python and Scapy as part of the CodeAlpha Cybersecurity Internship. It captures live network packets and displays important packet information to help understand network communication.

## Features

- Captures live network packets.
- Displays source and destination IP addresses.
- Identifies TCP, UDP, DNS, ICMP, and other traffic.
- Displays packet length and a short payload preview.
- Exports captured packet details to a CSV file.
- Shows a summary of captured packets by protocol.

## Technologies Used

- Python
- Scapy
- Npcap
- CSV

## Requirements

- Python 3
- Npcap installed on Windows
- Visual Studio Code or another Python editor

## Installation

### 1. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

## How to Run

Run the following command in the project directory:

```powershell
python sniffer.py
```

Enter `0` to capture continuously or enter a positive number to limit the number of packets. Press `Ctrl+C` to stop continuous capture.

Run the program with the permissions required for packet capture.

## Output

Packet information is saved in:

`output/packets.csv`

Project screenshots are available in the `screenshots/` folder.

## Responsible Use

This tool is intended for educational purposes and authorized network analysis. Only capture traffic on networks you own or have permission to monitor. Avoid sharing sensitive packet data.

## Internship

**CodeAlpha Cybersecurity Internship**

**Task 1: Basic Network Sniffer**
