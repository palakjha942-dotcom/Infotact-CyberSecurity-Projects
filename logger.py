import can
import csv
import time

def log_can_traffic():
    bus = can.interface.Bus(channel='vcan0', bustype='socketcan')
    csv_file = 'can_dataset.csv'

    print("[+] CAN Logger started listening on vcan0...")
    print(f"[+] Logging telemetry data to {csv_file} (Press Ctrl+C to stop)")

    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Timestamp', 'CAN_ID', 'DLC', 'Data_Hex', 'RPM', 'Speed'])

        try:
            while True:
                msg = bus.recv()
                if msg is not None:
                    timestamp = time.time()
                    can_id = hex(msg.arbitration_id)
                    dlc = msg.dlc
                    data_hex = msg.data.hex()

                    rpm = None
                    speed = None

                    if msg.arbitration_id == 0x120 and len(msg.data) >= 3:
                        rpm = (msg.data[0] << 8) | msg.data[1]
                        speed = msg.data[2]

                    writer.writerow([timestamp, can_id, dlc, data_hex, rpm, speed])
                    print(f"Logged -> ID: {can_id} | RPM: {rpm} | Speed: {speed} km/h")

        except KeyboardInterrupt:
            print("\n[!] Logging stopped. Dataset saved successfully!")

if __name__ == '__main__':
    log_can_traffic()
