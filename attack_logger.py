import can
import csv

# Connect to SocketCAN interface vcan0
bus = can.interface.Bus(channel='vcan0', interface='socketcan')

print("[*] Listening on vcan0... Capturing traffic to 'attacked_dataset.csv'")
print("[!] Press Ctrl+C to stop capture when done.")

with open('attacked_dataset.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Arbitration_ID", "DLC", "Data"])

    try:
        while True:
            msg = bus.recv(1.0)
            if msg:
                data_hex = ' '.join(f'{b:02x}' for b in msg.data)
                writer.writerow([msg.timestamp, hex(msg.arbitration_id), msg.dlc, data_hex])
    except KeyboardInterrupt:
        print("\n[+] Data logging stopped. Saved to attacked_dataset.csv")
