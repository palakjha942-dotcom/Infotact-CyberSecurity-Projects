#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/raw.h>

int main() {
    int s;
    struct sockaddr_can addr;
    struct ifreq ifr;
    struct can_frame frame;

    if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
        perror("Socket creation failed");
        return 1;
    }

    strcpy(ifr.ifr_name, "vcan0");
    ioctl(s, SIOCGIFINDEX, &ifr);

    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        return 1;
    }

    printf("[+] ECU Simulator started on vcan0. Broadcasting RPM & Speed...\n");

    int rpm = 800;
    int speed = 0;

    while (1) {
        frame.can_id = 0x120;
        frame.can_dlc = 4;

        rpm = (rpm + 50 > 4500) ? 800 : rpm + 50;
        speed = (speed + 1 > 120) ? 0 : speed + 1;

        frame.data[0] = (rpm >> 8) & 0xFF;
        frame.data[1] = rpm & 0xFF;
        frame.data[2] = speed;
        frame.data[3] = 0x00;

        if (write(s, &frame, sizeof(struct can_frame)) != sizeof(struct can_frame)) {
            perror("Write error");
            break;
        }

        printf("Sent -> ID: 0x%03X | RPM: %d | Speed: %d km/h\n", frame.can_id, rpm, speed);
        usleep(100000);
    }

    close(s);
    return 0;
}

