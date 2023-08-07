/* reference from https://github.com/mmisono/vfio-e1000/blob/master/e1000.c */
#define _LARGEFILE64_SOURCE 
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/vfio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define TEST_INTR

#define CAP 0x0
#define VS 0x8
#define CC 0x14
#define CSTS 0x1c
#define AQA 0x24
#define ASQ 0x28
#define ACQ 0x30
#define S_DB 0x1000
#define C_DB 0x1004
#define S_DB_Q1 0x1008
#define C_DB_Q1 0x100c

#define BUF_SIZE 4096

#define IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + sizeof(int))
#define MAX_INTERRUPT_VECTORS 32
#define MSIX_IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + sizeof(int) * (MAX_INTERRUPT_VECTORS + 1))

#define PAGE_SHIFT 12
#define PAGEMAP_LENGTH 8

unsigned int *sub_v;
unsigned long sub_p;
unsigned int *comp_v;
unsigned long comp_p;
unsigned char *prp1_v;
unsigned long prp1_p;
unsigned char *prp2_v;
unsigned long prp2_p;

unsigned int *sub_v_q1;
unsigned long sub_p_q1;
unsigned int *comp_v_q1;
unsigned long comp_p_q1;

struct device {
    struct vfio_region_info regs[VFIO_PCI_NUM_REGIONS];
    struct vfio_irq_info irqs[VFIO_PCI_NUM_IRQS];
    void* mmio_addr;  // mmio address (BAR0);
} nvme_dev;

/**
 * Enable VFIO MSI interrupts.
 * @param device_fd The VFIO file descriptor.
 * @return The event file descriptor.
 */
int vfio_enable_msi(int device_fd) {
	printf("Enable MSI Interrupts");
	int ret_val=0;
	char irq_set_buf[IRQ_SET_BUF_LEN];
	int* fd_ptr;

	// setup event fd
	int event_fd = eventfd(0, 0);

	struct vfio_irq_set* irq_set = (struct vfio_irq_set*) irq_set_buf;
	irq_set->argsz = sizeof(irq_set_buf);
	irq_set->count = 1;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSI_IRQ_INDEX;
	irq_set->start = 0;
	fd_ptr = (int*) &irq_set->data;
	*fd_ptr = event_fd;

	if ((ret_val = ioctl(device_fd, VFIO_DEVICE_SET_IRQS, irq_set)) < 0) {
		printf("enable MSI interrupts: %s\n",strerror(errno));
        }                             

	return event_fd;
}

/**
 * Disable VFIO MSI interrupts.
 * @param device_fd The VFIO file descriptor.
 * @return 0 on success.
 */
int vfio_disable_msi(int device_fd) {
	printf("Disable MSI Interrupts");
	char irq_set_buf[IRQ_SET_BUF_LEN];

	struct vfio_irq_set* irq_set = (struct vfio_irq_set*) irq_set_buf;
	irq_set->argsz = sizeof(irq_set_buf);
	irq_set->count = 0;
	irq_set->flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSI_IRQ_INDEX;
	irq_set->start = 0;

	if(ioctl(device_fd, VFIO_DEVICE_SET_IRQS, irq_set) < 0)
	       printf("disable MSI interrupts");

	return 0;
}

/**
 * Enable VFIO MSI-X interrupts.
 * @param device_fd The VFIO file descriptor.
 * @return The event file descriptor.
 */
int vfio_enable_msix(int device_fd, uint32_t interrupt_vector) {
	printf("Enable MSIX Interrupts");
	char irq_set_buf[BUF_SIZE];
	struct vfio_irq_set* irq_set;
	int* fd_ptr;
	int ret=0;

	// setup event fd
	int event_fd = eventfd(0, 0);

	irq_set = (struct vfio_irq_set*) irq_set_buf;
	irq_set->argsz = sizeof(struct vfio_irq_set) + (sizeof(int) * interrupt_vector);
	if (!interrupt_vector) {
		interrupt_vector = 1;
	} else if (interrupt_vector > MAX_INTERRUPT_VECTORS)
		interrupt_vector = MAX_INTERRUPT_VECTORS + 1;

	irq_set->count = interrupt_vector;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
	/* interrupt for admin queue */
//	irq_set->start = 0;
        /* interrupt for io queue 1*/
	irq_set->start = 1;
	fd_ptr = (int*) &irq_set->data;
	fd_ptr[0] = event_fd;

	if((ret = ioctl(device_fd, VFIO_DEVICE_SET_IRQS, irq_set)) < 0 ) {
	       printf("enable MSIX interrupt failed %s\n",strerror(errno));
	}

	return event_fd;
}

/**
 * Disable VFIO MSI-X interrupts.
 * @param device_fd The VFIO file descriptor.
 * @return 0 on success.
 */
int vfio_disable_msix(int device_fd) {
	printf("Disable MSIX Interrupts");
	struct vfio_irq_set* irq_set;
	char irq_set_buf[BUF_SIZE];

	irq_set = (struct vfio_irq_set*) irq_set_buf;
	irq_set->argsz = sizeof(struct vfio_irq_set);
	irq_set->count = 0;
	irq_set->flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
	/* interrupt for admin queue */
//	irq_set->start = 0;
        /* interrupt for io queue 1*/
	irq_set->start = 1;

	if(ioctl(device_fd, VFIO_DEVICE_SET_IRQS, irq_set) < 0)
	       printf("disable MSIX interrupt failed %s\n",strerror(errno));

	return 0;
}

void * create_buffer(size_t buffer_size) {
        int i;
        void *buffer = NULL;
	 buffer = (void *)mmap(0, buffer_size, PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	return buffer;
}

void free_buffer(void *buffer, size_t len) {
	munmap(buffer, len);
}

#define BIT(n) (1ULL << (n))
static unsigned long virtual_to_physical(const void *vaddr) {
  unsigned long phy = 0;
  auto page_size = sysconf(_SC_PAGESIZE);
  int  fd        = open("/proc/self/pagemap", O_RDONLY);
  assert(fd != -1);

  int res = lseek64(fd, ((uintptr_t)vaddr / page_size) * PAGEMAP_LENGTH, SEEK_SET);
  assert(res != -1);

  res = read(fd, &phy, sizeof(unsigned long));
  assert(res == sizeof(unsigned long));

  close(fd);

  printf("phy = %lx\n",phy);

  assert((phy & BIT(63)) != 0);
  return (phy & 0x7fffffffffffffULL) * page_size
         + (unsigned long)vaddr % page_size;
}

static inline void write_u32(struct device* dev, int offset, uint32_t value) {
    __asm__ volatile("" : : : "memory");
    *((volatile uint32_t*)(dev->mmio_addr + offset)) = value;
}

static inline uint32_t read_u32(struct device* dev, int offset) {
    __asm__ volatile("" : : : "memory");
    return *((volatile uint32_t*)(dev->mmio_addr + offset));
}

static unsigned long get_iova(unsigned long virt_addr, ssize_t size) {
    static unsigned long _iova = 0;
#if defined(IDENTITY_MAP)
    // Use virtual address as IOVA
    // Note that some architecture only support 3-level page table (39-bit) and
    // cannot use virtual address as IOVA
    return virt_addr;
#elif defined(PHYSADDR_MAP)
    // Use physical address as IOVA
    return (u64)virt_to_phys(virt_addr);
#else
    // Assign IOVA from 0
    unsigned long ret = _iova;
    _iova += size;
    return ret;
#endif
}

void * intr_thread_main(void *arg) {
#define MAX_EVENT 3
    int ret;
    struct epoll_event events[MAX_EVENT];
    struct epoll_event ev;

   /* create epoll fd */
    int pfd = epoll_create(5);
    int i, num_event=0, bytes_read; 
    char read_buffer[BUF_SIZE];
    printf("inside intr_thread_main\n");

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLPRI ;
    ev.data.fd = *(int *)arg;

    if (epoll_ctl(pfd, EPOLL_CTL_ADD, *(int *)arg, &ev) < 0) {
        printf("epoll_ctl failed %s\n",strerror(errno));
    }

    if ((ret = epoll_wait(pfd, events, MAX_EVENT, 10000)) == -1) {
	    printf("epoll_wait failed %s\n",strerror(errno));
    } else if (ret == 0) {
	    printf("epoll_timeout\n");
    } else {
        for( i=0; i< ret; i++) {
	    bytes_read = read(events[i].data.fd, read_buffer, BUF_SIZE);
	    printf("INTR bytes_read = %d\n",bytes_read);
        }
    }
}

int main(){     
    char buf[BUF_SIZE];         
    int ret,group_fd, fd;  
    int iommu1, iommu2;
    char *buffer;
    unsigned int *temp=buf;
    struct vfio_region_info* bar0_info;
    unsigned long data;
    int event_fd;
    pthread_t intr_th_id;

    int container, group, device, i;
    struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
    struct vfio_iommu_type1_info iommu_info = { .argsz = sizeof(iommu_info) };
    struct vfio_iommu_type1_dma_map dma_map = { .argsz = sizeof(dma_map) };
    struct vfio_device_info device_info = { .argsz = sizeof(device_info) };    
    unsigned long page_frame_number;
    container = open("/dev/vfio/vfio",O_RDWR);        

    if(ioctl(container,VFIO_GET_API_VERSION)!=VFIO_API_VERSION){
        printf("Unknown api version: %m\n");    
    }   
    group_fd = open("/dev/vfio/8",O_RDWR);     printf("Group fd = %d\n", group_fd);
    ioctl(group_fd, VFIO_GROUP_GET_STATUS, &group_status);
    if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)){
        printf("Group not viable\n");
        return 1;
    }   
    ret = ioctl(group_fd, VFIO_GROUP_SET_CONTAINER,&container);     
    ret = ioctl(container,VFIO_SET_IOMMU,VFIO_TYPE1_IOMMU);         
    ioctl(container, VFIO_IOMMU_GET_INFO, &iommu_info);         

    fd = ioctl(group_fd,VFIO_GROUP_GET_DEVICE_FD,"0000:03:00.0");

    /* Test and setup the device */
ioctl(fd, VFIO_DEVICE_GET_INFO, &device_info);
printf("%d %x %d %d %x\n",device_info.argsz, device_info.flags, device_info.num_regions, device_info.num_irqs, device_info.cap_offset);

    for (i = 0; i < device_info.num_regions; i++) {

	nvme_dev.regs[i].argsz = sizeof(struct vfio_region_info); 
	nvme_dev.regs[i].index = i;
        printf("region index =%d\n", i);
	ioctl(fd, VFIO_DEVICE_GET_REGION_INFO, &nvme_dev.regs[i]);
	printf("%d %x %d %x %lx %lx \n", nvme_dev.regs[i].argsz, nvme_dev.regs[i].flags, nvme_dev.regs[i].index, nvme_dev.regs[i].cap_offset, nvme_dev.regs[i].size, nvme_dev.regs[i].offset);


	/* Setup mappings... read/write offsets, mmaps
	 * For PCI devices, config space is a region */
    }

    for (i = 0; i < device_info.num_irqs; i++) {
	struct vfio_irq_info irq = { .argsz = sizeof(irq) };

	irq.index = i;

	printf("irq index =%d\n", i);
	ioctl(fd, VFIO_DEVICE_GET_IRQ_INFO, &irq);
	printf("%d %x %d %d \n",irq.argsz, irq.flags, irq.index, irq.count);

	/* Setup IRQs... eventfds, VFIO_DEVICE_SET_IRQS */
    }


    printf("Fd = %d\n",fd);     
    printf("VFIO_GROUP_GET_DEV_ID = %lu\n",VFIO_GROUP_GET_DEVICE_FD);

    printf("\ndump configuration space registers\n");
    pread(fd, buf, 512, nvme_dev.regs[VFIO_PCI_CONFIG_REGION_INDEX].offset);
    for(i=0; i<10; i++)
        printf("%x \n",temp[i]);

    printf("\ndump BAR0 space registers\n");
    pread(fd, buf, 512, nvme_dev.regs[VFIO_PCI_BAR0_REGION_INDEX].offset);
    for(i=0; i<17; i++)
        printf("%x \n",temp[i]);

    bar0_info = &nvme_dev.regs[VFIO_PCI_BAR0_REGION_INDEX];
    nvme_dev.mmio_addr = mmap(NULL, bar0_info->size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, bar0_info->offset);

#if 0
	buffer = create_buffer(3*BUF_SIZE);
	buffer[0] = 0x55;
	buffer[4096] = 0x55;
	printf("buffer addr %lx\n", buffer);
	sub_v = buffer;
	comp_v = buffer+BUF_SIZE;
	prp1_v = buffer+BUF_SIZE;
	printf("VIRT %lx %lx %lx \n",sub_v,comp_v,prp1_v);
	sub_p = virtual_to_physical(sub_v);
	comp_p = virtual_to_physical(comp_v);
	prp1_p = virtual_to_physical(prp1_v);
	printf("PHYSICAL %lx %lx %lx \n",sub_p,comp_p,prp1_p);
#endif
	sub_v = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	comp_v = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	prp1_v = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	sub_v_q1 = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	comp_v_q1 = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    dma_map.vaddr = sub_v;
    dma_map.size = BUF_SIZE;
    dma_map.iova = get_iova(0, BUF_SIZE);
    dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
    ret = ioctl(container, VFIO_IOMMU_MAP_DMA, &dma_map);
    if (ret)
	    goto cleanup;
    sub_p = dma_map.iova;

    dma_map.vaddr = comp_v;
    dma_map.size = BUF_SIZE;
    dma_map.iova = get_iova(0, BUF_SIZE);
    dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
    ret = ioctl(container, VFIO_IOMMU_MAP_DMA, &dma_map);
    if (ret)
	    goto cleanup;
    comp_p = dma_map.iova;

    dma_map.vaddr = prp1_v;
    dma_map.size = BUF_SIZE;
    dma_map.iova = get_iova(0, BUF_SIZE);
    dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
    ret = ioctl(container, VFIO_IOMMU_MAP_DMA, &dma_map);
    if (ret)
	    goto cleanup;
    prp1_p = dma_map.iova;

    dma_map.vaddr = sub_v_q1;
    dma_map.size = BUF_SIZE;
    dma_map.iova = get_iova(0, BUF_SIZE);
    dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
    ret = ioctl(container, VFIO_IOMMU_MAP_DMA, &dma_map);
    if (ret)
	    goto cleanup;
    sub_p_q1 = dma_map.iova;

    dma_map.vaddr = comp_v_q1;
    dma_map.size = BUF_SIZE;
    dma_map.iova = get_iova(0, BUF_SIZE);
    dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
    ret = ioctl(container, VFIO_IOMMU_MAP_DMA, &dma_map);
    if (ret)
	    goto cleanup;
    comp_p_q1 = dma_map.iova;


	write_u32(&nvme_dev, AQA, 0x001F001F);
        write_u32(&nvme_dev, ASQ, sub_p);
        write_u32(&nvme_dev, ASQ+0x4, (sub_p>>32));
        write_u32(&nvme_dev, ACQ, comp_p);
        write_u32(&nvme_dev, ACQ+0x4, (comp_p>>32));

        data = read_u32(&nvme_dev, CC);
        data = ((4<<20) | (6<<16));
        write_u32(&nvme_dev, CC, temp);
        printf("CC %x \n",read_u32(&nvme_dev, CC));
        write_u32(&nvme_dev, CC, data|0x1);

        sleep(1);
        printf("CSTS %x \n",read_u32(&nvme_dev, CSTS));

    printf("\ndump BAR0 space registers\n");
    pread(fd, buf, 512, nvme_dev.regs[VFIO_PCI_BAR0_REGION_INDEX].offset);
    for(i=0; i<17; i++)
        printf("%x \n",temp[i]);

#ifdef TEST_INTR
    event_fd = vfio_enable_msix(fd, 1);
   ret = pthread_create(&intr_th_id, NULL, intr_thread_main, &event_fd);
#else
#endif

    printf("\nidentify controller\n");
    *sub_v = 0x12340006; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    *sub_v = (unsigned int)prp1_p; sub_v++;
    *sub_v = (unsigned int)(prp1_p >> 32); sub_v++;

    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    *sub_v = 0x1; sub_v++; /* controller data structure */

    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    write_u32(&nvme_dev, S_DB, 0x1);
    sleep(1);

    printf("COMPLETION %x %x %x %x\n",*comp_v, *(comp_v+1), *(comp_v+2), *(comp_v+3));
    comp_v +=4;

    printf("VID %x %x\n", *(prp1_v+1), *(prp1_v+0));
    printf("SSVID %x %x\n", *(prp1_v+3), *(prp1_v+2));
    printf("IEE %x %x %x\n", *(prp1_v+75), *(prp1_v+74), *(prp1_v+73));
    printf("MTDS %x\n", *(prp1_v+77));
    printf("SQES %x\n", *(prp1_v+512));
    printf("CQES %x\n", *(prp1_v+513));
    printf("NN %x %x %x %x\n",*(prp1_v+519), *(prp1_v+518), *(prp1_v+517), *(prp1_v+516));

    write_u32(&nvme_dev, C_DB, 0x1);
    printf("C_DB %x \n",read_u32(&nvme_dev, C_DB));

/* new command */
    printf("\nidentify namespace\n");
    *sub_v = 0x55aa0006; sub_v++;
    *sub_v = 0x1; sub_v++; /*namespace identifier*/
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    *sub_v = (unsigned int)prp1_p; sub_v++;
    *sub_v = (unsigned int)(prp1_p >> 32); sub_v++;

    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    *sub_v = 0x0; sub_v++; /*name space data structure*/

    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    write_u32(&nvme_dev, S_DB, 0x2);
    sleep(1);

    printf("COMPLETION %x %x %x %x\n",*comp_v, *(comp_v+1), *(comp_v+2), *(comp_v+3));
    comp_v +=4;

    printf("NSZE %x %x %x %x %x %x %x %x\n",*(prp1_v+7),*(prp1_v+6),*(prp1_v+5),*(prp1_v+4),*(prp1_v+3),*(prp1_v+2),*(prp1_v+1), *(prp1_v+0));
    printf("NCAP %x %x %x %x %x %x %x %x\n",*(prp1_v+15),*(prp1_v+14),*(prp1_v+13),*(prp1_v+12),*(prp1_v+11),*(prp1_v+10),*(prp1_v+9), *(prp1_v+8));
    printf("NUSE %x %x %x %x %x %x %x %x\n",*(prp1_v+23),*(prp1_v+22),*(prp1_v+21),*(prp1_v+20),*(prp1_v+19),*(prp1_v+18),*(prp1_v+17), *(prp1_v+16));
    printf("NLBAF %x\n", *(prp1_v+25));
    printf("FLBAS %x\n", *(prp1_v+26));
    printf("EUI %x %x %x %x %x %x %x %x\n",*(prp1_v+127),*(prp1_v+126),*(prp1_v+125),*(prp1_v+124),*(prp1_v+123),*(prp1_v+122),*(prp1_v+121), *(prp1_v+120));
    printf("LBA format-0 %x %x %x %x\n",*(prp1_v+131),*(prp1_v+130),*(prp1_v+129),*(prp1_v+128));
    printf("LBA format-1 %x %x %x %x\n",*(prp1_v+134),*(prp1_v+133),*(prp1_v+132),*(prp1_v+131));
    printf("LBA format-2 %x %x %x %x\n",*(prp1_v+138),*(prp1_v+137),*(prp1_v+136),*(prp1_v+135));

    write_u32(&nvme_dev, C_DB, 0x2);
    printf("C_DB %x \n",read_u32(&nvme_dev, C_DB));


/* new command */
    printf("\ncreate io completion queue\n");
    *sub_v = 0x12340005; sub_v++; /* create io completion queue */
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    *sub_v = (unsigned int)comp_p_q1; sub_v++;
    *sub_v = (unsigned int)(comp_p_q1 >> 32); sub_v++;

    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    *sub_v = 0xf0001; sub_v++; /* queuesize|queueident*/
#ifndef TEST_INTR
    *sub_v = 0x1; sub_v++; /* contigeous pages */
#else
    *sub_v = 0x10003; sub_v++; /*interrupt vector|interrupt enable|contigeous pages */
#endif
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    write_u32(&nvme_dev, S_DB, 0x3);
    sleep(1);

    printf("COMPLETION %x %x %x %x\n",*comp_v, *(comp_v+1), *(comp_v+2), *(comp_v+3));
    comp_v +=4;

    write_u32(&nvme_dev, C_DB, 0x3);
    printf("C_DB %x \n",read_u32(&nvme_dev, C_DB));

/* new command */
    printf("\ncreate io submission queue\n");
    *sub_v = 0x43210001; sub_v++; /* create io submission queue */
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    *sub_v = (unsigned int)sub_p_q1; sub_v++;
    *sub_v = (unsigned int)(sub_p_q1 >> 32); sub_v++;

    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    *sub_v = 0xf0001; sub_v++;  /* queuesize|queueident*/
    *sub_v = 0x10001; sub_v++; /* completion queue ident |contigeous pages */
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;
    *sub_v = 0x0; sub_v++;

    write_u32(&nvme_dev, S_DB, 0x4);
    sleep(1);

    printf("COMPLETION %x %x %x %x\n",*comp_v, *(comp_v+1), *(comp_v+2), *(comp_v+3));
    comp_v +=4;

    write_u32(&nvme_dev, C_DB, 0x4);
    printf("C_DB %x \n",read_u32(&nvme_dev, C_DB));

/* new command */
    printf("\nread block\n");
    *sub_v_q1 = 0xdada0002; sub_v_q1++; /* read */
    *sub_v_q1 = 0x1; sub_v_q1++;
    *sub_v_q1 = 0x0; sub_v_q1++;
    *sub_v_q1 = 0x0; sub_v_q1++;
    *sub_v_q1 = 0x0; sub_v_q1++;
    *sub_v_q1 = 0x0; sub_v_q1++;

    *sub_v_q1 = (unsigned int)prp1_p; sub_v_q1++;
    *sub_v_q1 = (unsigned int)(prp1_p >> 32); sub_v_q1++;

    *sub_v_q1 = 0x0; sub_v_q1++;
    *sub_v_q1 = 0x0; sub_v_q1++;

    *sub_v_q1 = 0x0; sub_v_q1++;  /* starting LBA low */
    *sub_v_q1 = 0x0; sub_v_q1++; /* starting LBA high */
    *sub_v_q1 = (0x0|(1<<30)); sub_v_q1++; /* number of logical blocks */
    *sub_v_q1 = 0x0; sub_v_q1++;
    *sub_v_q1 = 0x0; sub_v_q1++;
    *sub_v_q1 = 0x0; sub_v_q1++;

    write_u32(&nvme_dev, S_DB_Q1, 0x1);
    sleep(1);

    printf("COMPLETION %x %x %x %x\n",*comp_v_q1, *(comp_v_q1+1), *(comp_v_q1+2), *(comp_v_q1+3));
    comp_v_q1 +=4;

    write_u32(&nvme_dev, C_DB_Q1, 0x1);
    printf("C_DB_Q1 %x \n",read_u32(&nvme_dev, C_DB_Q1));

    for (i=0; i<32; i++) {
            printf("%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",*(prp1_v+(16*i)+0),*(prp1_v+(16*i)+1),*(prp1_v+(16*i)+2),*(prp1_v+(16*i)+3),*(prp1_v+(16*i)+4),*(prp1_v+(16*i)+5),*(prp1_v+(16*i)+6),*(prp1_v+(16*i)+7),*(prp1_v+(16*i)+8),*(prp1_v+(16*i)+9),*(prp1_v+(16*i)+10),*(prp1_v+(16*i)+11),*(prp1_v+(16*i)+12),*(prp1_v+(16*i)+13),*(prp1_v+(16*i)+14),*(prp1_v+(16*i)+15));
    }


    getchar();
#if 0
	if(buffer)
	    free_buffer(buffer, 3*BUF_SIZE);
#endif
#ifdef TEST_INTR
    pthread_join(intr_th_id, NULL);
    vfio_disable_msix(fd);
#endif
cleanup:
 munmap(sub_v, BUF_SIZE);
 munmap(comp_v, BUF_SIZE);
 munmap(prp1_v, BUF_SIZE);
 munmap(sub_v_q1, BUF_SIZE);
 munmap(comp_v_q1, BUF_SIZE);
    close(fd);
    close(container);
    close(group_fd);
    return 0;
}
