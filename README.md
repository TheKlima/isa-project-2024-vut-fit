ISA (Network Applications and Network Administration) project, VUT FIT, Brno - **Monitoring DNS communication**<br>
Author: **Andrii Klymenko <xklyme00>**<br>
Date of the creation: **18.11.2024**

## Program's description

The program processes DNS packets on the selected
interface or from the specified _pcap_ file: it prints packet's information,
and logs encountered domain names and their translations to ipv4/ipv6 addresses
to the specified files.

## Program's limitations

The program assumes all packets it processes have
a standard **Ethernet** header (header type **DLT_EN10MB**). It also processes the only
DNS records which class is **Internet** (**IN**) (decimal value 1).

## Program's build

Firstly, unzip an archive _xklyme00.tar_ by executing command:
```sh
$ tar -xf xklyme00.tar
```

After that, you can build the program by running **make**:
```sh
$ make
```

The result of this command will be an executable file **dns-monitor** which can be run.

Examples of the program's run:
```sh
$ ./dns-monitor -p file.pcap
$ ./dns-monitor -i eth0 -t tfile -v
$ ./dns-monitor -p big.pcap -d dfile -t tfile
```

List of the submitted files:
- Source files
  - main.cpp
  - args.cpp
  - dns-header.cpp
  - dns-monitor.cpp
  - dns-monitor-exception.cpp
  - packet-writer.cpp
  - simple-packet-writer.cpp
  - verbose-packet-writer.cpp
- Header files
  - args.h
  - dns-header.h
  - dns-monitor.h
  - dns-monitor-exception.h
  - packet-writer.h
  - simple-packet-writer.h
  - verbose-packet-writer.h
- PCAP/PCAPNG files
  - many.pcapng
  - p.pcapng
  - v6.pcap
  - v61.pcapng
  - v62.pcap
  - wireshark2.pcap
- Testing outputs files
  - test_output1.jpg
  - test_output2.jpg
- Makefile
- manual.pdf
- README.md