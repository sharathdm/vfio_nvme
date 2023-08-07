# vfio_nvme

tested on x86 system with "intel_iommu=on iommu=pt" kernel command line


root@bapvecise025:~# lspci -v -s 03:00.0

03:00.0 Non-Volatile memory controller: Samsung Electronics Co Ltd NVMe SSD Controller SM981/PM981/PM983 (prog-if 02 [NVM Express])

        Subsystem: Samsung Electronics Co Ltd SSD 970 EVO Plus 1TB

        Flags: bus master, fast devsel, latency 0, IRQ 16, NUMA node 0, IOMMU group 8

        Memory at 4b200000 (64-bit, non-prefetchable) [size=16K]

        Capabilities: [40] Power Management version 3

        Capabilities: [50] MSI: Enable- Count=1/1 Maskable- 64bit+

        Capabilities: [70] Express Endpoint, MSI 00

        Capabilities: [b0] MSI-X: Enable+ Count=33 Masked-

        Capabilities: [100] Advanced Error Reporting

        Capabilities: [148] Device Serial Number 00-00-00-00-00-00-00-00

        Capabilities: [158] Power Budgeting <?>

        Capabilities: [168] Secondary PCI Express

        Capabilities: [188] Latency Tolerance Reporting

        Capabilities: [190] L1 PM Substates

        Kernel driver in use: nvme

        Kernel modules: nvme

 

root@root:~# echo 0000:03:00.0 > /sys/bus/pci/devices/0000:03:00.0/driver/unbind

root@root:~# echo 144d a808 > /sys/bus/pci/drivers/vfio-pci/new_id

root@root:~# ./a.out

Group fd = 4

20 3 9 5 0

region index =0

40 f 0 0 4000 0

region index =1

32 0 1 0 0 10000000000

region index =2

32 0 2 0 0 20000000000

region index =3

32 0 3 0 0 30000000000

region index =4

32 0 4 0 0 40000000000

region index =5

32 0 5 0 0 50000000000

region index =6

32 0 6 0 0 60000000000

region index =7

32 3 7 0 1000 70000000000

region index =8

32 0 8 0 0 0

irq index =0

16 7 0 1

irq index =1

16 9 1 1

irq index =2

16 9 2 33

irq index =3

16 9 3 1

irq index =4

16 9 4 1

Fd = 5

VFIO_GROUP_GET_DEV_ID = 15210

 

dump configuration space registers

a808144d

100002

1080200

10

4b200004

0

0

0

0

0

 

dump BAR0 space registers

3c033fff

30

10300

0

0

0

0

0

0

1f001f

1d54000

1

1d53000

1

0

0

0

CC 34f150

CSTS 1

 

dump BAR0 space registers

3c033fff

30

10300

0

0

460001

0

1

0

1f001f

0

0

1000

0

0

0

0

Enable MSIX Interrupts

identify controller

inside intr_thread_main

COMPLETION 0 0 1 11234

VID 14 4d

SSVID 14 4d

IEE 0 25 38

MTDS 9

SQES 66

CQES 44

NN 0 0 0 1

C_DB 1

 

identify namespace

COMPLETION 0 0 2 155aa

NSZE 0 0 0 0 1d 1c 59 70

NCAP 0 0 0 0 1d 1c 59 70

NUSE 0 0 0 0 6 fc 4 38

NLBAF 0

FLBAS 0

EUI 10 49 50 91 56 38 25 0

LBA format-0 0 9 0 0

LBA format-1 0 0 0 0

LBA format-2 0 0 0 0

C_DB 2

 

create io completion queue

COMPLETION 0 0 3 11234

C_DB 3

 

create io submission queue

COMPLETION 0 0 4 14321

C_DB 4

 

read block

INTR bytes_read = 8

COMPLETION 0 0 10001 1dada

C_DB_Q1 1

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 bb e2 ff 14 0 0 0 0

0 0 ee 0 0 0 1 0 0 0 ff 7 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

0 0 0 0 0 0 0 0 0 0 0 0 0 0 55 aa

 
/* optput of /proc/interrupts */
 

            CPU0       CPU1       CPU2       CPU3       CPU4       CPU5       CPU6       CPU7       CPU8       CPU9       CPU10      CPU11      CPU12      CPU13      CPU14      CPU15      CPU16      CPU17      CPU18      CPU19     

   0:         11          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-IO-APIC    2-edge      timer

   8:          0          0          0          0          0          1          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-IO-APIC    8-edge      rtc0

   9:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-IO-APIC    9-fasteoi   acpi

  14:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-IO-APIC   14-fasteoi   INT34C6:00

  16:          0          0          0          0     300000          0          0          0          0          5          0          0          0          0          0          0          0          0          0          0  IR-IO-APIC   16-fasteoi   i801_smbus

  17:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0        201          0          0          0          0  IR-IO-APIC   17-fasteoi   snd_hda_intel:card1

120:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  DMAR-MSI    0-edge      dmar0

121:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 16384-edge      PCIe PME, aerdrv

122:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 442368-edge      PCIe PME

123:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 450560-edge      PCIe PME, aerdrv, pcie-dpc

124:          0          0    4532075          0          0      12796          0        654          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 327680-edge      xhci_hcd

125:          0          0          0          0          0          0          0    1583477       9901          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 376832-edge      ahci[0000:00:17.0]

126:          0          0          0          0          0          0          0          0          0          0          4      66436          0          0          0          0          0          0          0          0  IR-PCI-MSI 520192-edge      eno1

128:          0          1          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 1572865-edge      vfio-msix[1](0000:03:00.0)
