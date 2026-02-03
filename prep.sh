#!/bin/bash

echo "Warning: prep.sh is deprecated. Please use --channel 8 and --set_interface=True when calling ESPythoNOW."

# Try method 1
ifconfig $1 down && \
iwconfig $1 mode monitor && \
ifconfig $1 up && \
iwconfig $1 channel $2

# If method 1 failed, try method 2
if [ $? -ne 0 ]; then
  iw dev $1 set type monitor
  iw dev $1 set channel $2
  ip link set $1 up
fi
