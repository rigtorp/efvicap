# efvicap

*efvicap* is a packet capture tool for network adapters
from [Solarflare](http://solarflare.com/). It uses the ef_vi API for
direct access to DMA memory and can capture traffic intended for
applications accelerated with [OpenOnload](http://www.openonload.org/)

## Usage

```sh
usage: efvicap [-i iface] [-w file] [filters...]

  -i iface    Interface to capture packets from
  -w file     Write packets in pcap format to file
```

Using an empty filter captures all packets (requiers a SolarCapture
license).

## Example

Print info about all received packets:

```sh
$ efvicap -i eth0
```

Save packets to *out.pcap*:

```sh
$ efvicap -i eth0 -w out.pcap
```

Pipe packets to *tcpdump* and print only UDP packets:

```sh
$ efvicap -i eth0 -w - | tcpdump -r - udp
```

Save UDP packets sent to 230.0.0.1:5000 and 230.0.0.2:6000:

```sh
$ efvicap -i eth0 -w out.pcap 230.0.0.1:5000 230.0.0.2:6000
```

## Building & Installing

*efvicap* requires [CMake](https://cmake.org/) 3.6 or higher to build
and install.

Building:

```sh
$ cd efvicap
$ mkdir build
$ cd build
$ cmake ..
$ make
```

Installing:

```sh
$ make install
```

## TODO

- Hardware timestamping
- Multiple interfaces
- Separate thread for writing to disk
- Compression

## About

This project was created by [Erik Rigtorp](http://rigtorp.se)
<[erik@rigtorp.se](mailto:erik@rigtorp.se)>.
