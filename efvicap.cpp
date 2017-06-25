/*
Copyright (c) 2017 Erik Rigtorp <erik@rigtorp.se>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#include <etherfabric/memreg.h>
#include <etherfabric/pd.h>
#include <etherfabric/vi.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <array>
#include <atomic>
#include <csignal>
#include <cstring>
#include <iostream>
#include <pcap.h>
#include <sys/mman.h>
#include <system_error>
#include <unistd.h>
#include <vector>

// Per Solarflare documentation
constexpr size_t pktBufSize = 2048;

// Should be multiple of 8 according to Solarflare documentation
constexpr int refillBatchSize = 16;

// Huge page size for your platform
#if defined(__x86_64__) || defined(__i386__)
constexpr size_t hugePageSize = 2 * 1024 * 1024;
#endif

static std::ostream &operator<<(std::ostream &os, const in_addr addr) {
  std::array<char, INET_ADDRSTRLEN> str = {};
  inet_ntop(AF_INET, &addr, str.data(), str.size());
  os.write(str.data(), strnlen(str.data(), str.size()));
  return os;
}

static void printPacket(const void *buf, int /*len*/) {
  auto p = reinterpret_cast<const char *>(buf);
  auto eth = reinterpret_cast<const ether_header *>(p);
  if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
    auto ip = reinterpret_cast<const iphdr *>(p + sizeof(ether_header));
    if (ip->version == 4) {
      if (ip->protocol == IPPROTO_TCP) {
        auto tcp = reinterpret_cast<const tcphdr *>(p + sizeof(ether_header) +
                                                    sizeof(iphdr));
        std::cout << "ip tcp from " << in_addr{ip->saddr} << ":"
                  << ntohs(tcp->source) << " to " << in_addr{ip->daddr} << ":"
                  << ntohs(tcp->dest) << std::endl;
      } else if (ip->protocol == IPPROTO_UDP) {
        auto udp = reinterpret_cast<const udphdr *>(p + sizeof(ether_header) +
                                                    sizeof(iphdr));
        std::cout << "ip udp from " << in_addr{ip->saddr} << ":"
                  << ntohs(udp->source) << " to " << in_addr{ip->daddr} << ":"
                  << ntohs(udp->dest) << std::endl;
      } else {
        std::cout << "ip " << ip->protocol << std::endl;
      }
    }
  } else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
    std::cout << "arp" << std::endl;
  } else {
    std::cout << ntohs(eth->ether_type) << std::endl;
  }
}

std::atomic<bool> active = {true};

extern "C" void signalHandler(int /*signal*/) { active = false; }

int main(int argc, char *argv[]) {
  static const char usage[] =
      " [-i iface] [-w file] maddr\n"
      "\n"
      "  -i iface    Interface to capture packets from\n"
      "  -w file     Write packets in pcap format to file";

  std::string interface;
  std::string filename;
  int c = 0;
  while ((c = getopt(argc, argv, "i:w:")) != -1) {
    switch (c) {
    case 'i':
      interface = optarg;
      break;
    case 'w':
      filename = optarg;
      break;
    default:
      std::cerr << "usage: " << argv[0] << usage << std::endl;
      return 1;
    }
  }

  struct Filter {
    in_addr addr;
    in_port_t port;
  };
  std::vector<Filter> filters;
  for (int i = optind; i < argc; i++) {
    Filter filter = {};
    char *sep = strchr(argv[i], ':');
    if (sep) {
      *sep = 0;
      filter.port = htons(atoi(sep + 1));
    }
    if (inet_aton(argv[i], &filter.addr) == 0) {
      std::runtime_error("invalid address");
    }
    filters.push_back(filter);
  }

  std::signal(SIGINT, signalHandler);

  struct {
    // Resource handles
    ef_driver_handle dh;
    struct ef_pd pd;
    struct ef_vi vi;
    int rxPrefixLen;

    // DMA memory
    void *pktBufs;
    int nPktBufs;
    struct ef_memreg memreg;
    std::vector<int> freePktBufs;
    std::vector<ef_addr> pktBufAddrs;
  } res = {};

  if (ef_driver_open(&res.dh) < 0) {
    throw std::system_error(errno, std::generic_category(), "ef_driver_open");
  }
  if (ef_pd_alloc_by_name(&res.pd, res.dh, interface.c_str(), EF_PD_DEFAULT) <
      0) {
    throw std::system_error(errno, std::generic_category(),
                            "ef_pd_alloc_by_name");
  }
  enum ef_vi_flags vi_flags = EF_VI_FLAGS_DEFAULT;
  if (ef_vi_alloc_from_pd(&res.vi, res.dh, &res.pd, res.dh, -1, -1, 0, NULL, -1,
                          vi_flags) < 0) {
    throw std::system_error(errno, std::generic_category(),
                            "ef_vi_alloc_from_pd");
  }

  // Length of prefix before actual packet data
  res.rxPrefixLen = ef_vi_receive_prefix_len(&res.vi);

  // Allocate memory for DMA transfers. Try to get huge pages.
  res.nPktBufs = ef_vi_receive_capacity(&res.vi);
  const size_t bytesNeeded = res.nPktBufs * pktBufSize;
  // Round up to nearest huge page size
  const size_t bytesRounded = (bytesNeeded / hugePageSize + 1) * hugePageSize;
  res.pktBufs = mmap(NULL, bytesRounded, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
  if (res.pktBufs == MAP_FAILED) {
    std::cerr << "warning: failed to allocate hugepages for DMA buffers"
              << std::endl;
    posix_memalign(&res.pktBufs, 4096, bytesRounded);
  }

  // Register the memory for use with DMA
  if (ef_memreg_alloc(&res.memreg, res.dh, &res.pd, res.dh, res.pktBufs,
                      bytesRounded) < 0) {
    throw std::system_error(errno, std::generic_category(), "ef_memreg_alloc");
  }
  // Store the DMA address for each packet buffer
  for (int i = 0; i < res.nPktBufs; ++i) {
    res.pktBufAddrs.push_back(ef_memreg_dma_addr(&res.memreg, i * pktBufSize));
    res.freePktBufs.push_back(i);
  }

  // Fill the RX descriptor ring
  while (ef_vi_receive_space(&res.vi) > 0 && !res.freePktBufs.empty()) {
    const int pktBufId = res.freePktBufs.back();
    res.freePktBufs.resize(res.freePktBufs.size() - 1);
    ef_vi_receive_init(&res.vi, res.pktBufAddrs[pktBufId], pktBufId);
  }
  ef_vi_receive_push(&res.vi);

  for (auto filter : filters) {
    // Match multicast
    ef_filter_spec filter_spec;
    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
    if (filter.port == 0) {
      uint8_t mac[6] = {0x01,
                        0x00,
                        0x5e,
                        uint8_t(filter.addr.s_addr >> 8 & 0x7f),
                        uint8_t(filter.addr.s_addr >> 16 & 0xff),
                        uint8_t(filter.addr.s_addr >> 24 & 0xff)};
      if (ef_filter_spec_set_eth_local(&filter_spec, EF_FILTER_VLAN_ID_ANY,
                                       mac) < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "ef_filter_spec_set_port_sniff");
      }
    } else {
      if (ef_filter_spec_set_ip4_local(&filter_spec, IPPROTO_UDP,
                                       filter.addr.s_addr, filter.port) < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "ef_filter_spec_set_port_sniff");
      }
    }
    if (ef_vi_filter_add(&res.vi, res.dh, &filter_spec, NULL) < 0) {
      throw std::system_error(errno, std::generic_category(),
                              "ef_vi_filter_add");
    }
  }
  if (filters.empty()) {
    // Match all packets that also match another filter
    ef_filter_spec filter_spec;
    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
    if (ef_filter_spec_set_port_sniff(&filter_spec, 1) < 0) {
      throw std::system_error(errno, std::generic_category(),
                              "ef_filter_spec_set_port_sniff");
    }
    if (ef_vi_filter_add(&res.vi, res.dh, &filter_spec, NULL) < 0) {
      throw std::system_error(errno, std::generic_category(),
                              "ef_vi_filter_add");
    }
  }

  // Open pcap output
  pcap_t *pcap = nullptr;
  pcap_dumper_t *pcapDumper = nullptr;
  if (!filename.empty()) {
    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    pcapDumper = pcap_dump_open(pcap, filename.c_str());
    if (!pcapDumper) {
      throw std::runtime_error("pcap_dump_open: " +
                               std::string(pcap_geterr(pcap)));
    }
  }

  std::array<ef_event, 32> evs = {};
  while (active.load(std::memory_order_acquire)) {
    const int nev = ef_eventq_poll(&res.vi, evs.data(), evs.size());
    if (nev > 0) {
      for (int i = 0; i < nev; ++i) {
        switch (EF_EVENT_TYPE(evs[i])) {
        case EF_EVENT_TYPE_RX: {
          res.freePktBufs.push_back(EF_EVENT_RX_RQ_ID(evs[i]));
          if (EF_EVENT_RX_SOP(evs[i]) == 0 || EF_EVENT_RX_CONT(evs[i]) != 0) {
            // Ignore jumbo packets
            break;
          }
          const char *buf = (const char *)res.pktBufs +
                            pktBufSize * EF_EVENT_RX_RQ_ID(evs[i]) +
                            res.rxPrefixLen;
          const int bufLen = EF_EVENT_RX_BYTES(evs[i]) - res.rxPrefixLen;
          if (pcapDumper) {
            pcap_pkthdr pktHdr = {};
            pktHdr.caplen = bufLen;
            pktHdr.len = bufLen;
            gettimeofday(&pktHdr.ts, nullptr);
            pcap_dump(reinterpret_cast<u_char *>(pcapDumper), &pktHdr,
                      reinterpret_cast<const u_char *>(buf));
          } else {
            printPacket(buf, bufLen);
          }
          break;
        }
        default:
          throw std::runtime_error("ef_eventq_poll: unknown event type");
          break;
        }
      }
      // Refill the RX descriptor ring
      if (ef_vi_receive_space(&res.vi) > refillBatchSize &&
          res.freePktBufs.size() > refillBatchSize) {
        for (int i = 0; i < refillBatchSize; ++i) {
          const int pkt_buf_id =
              res.freePktBufs[res.freePktBufs.size() - refillBatchSize + i];
          ef_vi_receive_init(&res.vi, res.pktBufAddrs[pkt_buf_id], pkt_buf_id);
        }
        res.freePktBufs.resize(res.freePktBufs.size() - refillBatchSize);
        ef_vi_receive_push(&res.vi);
      }
    }
  }

  if (pcapDumper) {
    pcap_dump_close(pcapDumper);
    pcap_close(pcap);
  }

  return 0;
}
