
iw dev $1 set type monitor
iw dev $1 set channel $2
ip link set $1 up
