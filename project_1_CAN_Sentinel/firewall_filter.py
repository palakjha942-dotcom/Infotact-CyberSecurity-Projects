import can

def run_firewall():
    bus = can.interface.Bus(channel='vcan0', interface='socketcan')
    print("[+] CAN-Sentinel Inline Firewall Active on vcan0.")
    print("[+] Rule 1: Drop ID 0x000 (DoS mitigation)")
    print("[+] Rule 2: Drop RPM > 8000 on ID 0x120 (Spoofing mitigation)")
    
    blocked_count = 0
    passed_count = 0
    
    try:
        while True:
            msg = bus.recv(1.0)
            if msg:
                arb_id = msg.arbitration_id
                is_malicious = False
                
                # Rule 1: DoS drop
                if arb_id == 0x000:
                    is_malicious = True
                    reason = "DoS Zero-ID Flooding"
                
                # Rule 2: RPM threshold drop
                if arb_id == 0x120 and len(msg.data) >= 2:
                    rpm_val = (msg.data[0] << 8) | msg.data[1]
                    if rpm_val > 8000:
                        is_malicious = True
                        reason = f"Extreme RPM Spoof ({rpm_val} RPM)"
                
                if is_malicious:
                    blocked_count += 1
                    print(f"[FIREWALL DROP] ID: {hex(arb_id)} blocked. Reason: {reason} | Total Dropped: {blocked_count}")
                else:
                    passed_count += 1
                    
    except KeyboardInterrupt:
        print("\n[+] Firewall stopped.")
        print(f"[+] Total Frames Processed -> Passed: {passed_count}, Dropped: {blocked_count}")

if __name__ == "__main__":
    run_firewall()
