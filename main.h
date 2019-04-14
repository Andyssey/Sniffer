// #define DEBUG 1
FILE *logptr = NULL;
struct iface_packet {
    unsigned long inIpaddr;
    unsigned long count;
};

struct context {
    int size;
    int capacity;
    struct iface_packet *packet;
};
struct context *st=NULL;
void context_initialize()
{
    st->size = 0;
    st->capacity = 16;
    st->packet = calloc(sizeof(struct iface_packet),st->capacity);
}
void context_initialize_from_file()
{
    // printf("11111");
    fread(&st->size, sizeof(int), 1, logptr);
    fread(&st->capacity, sizeof(int), 1, logptr);
    st->packet = calloc(sizeof(struct iface_packet),st->capacity);
    int is = 0;
    is = fread(st->packet, sizeof(struct iface_packet), st->size, logptr);
}
void insert_new(unsigned long ip)
{
    /*If array is empty*/
    if (st->size == 0)
    {
        st->packet->inIpaddr = ip;
        st->packet->count = 1;
        st->size = 1;
    }

    /*Check if we need to resize the array.
    Lets double size each time we run out of allocated memory \
    so that we don't need to call realloc each time we have one more IP*/
    if (st->size + 1 > st->capacity)
    {
        st->capacity = st->capacity * 2;
        st->packet = realloc(st->packet, st->capacity * sizeof(struct iface_packet));
    }
    
    int i;
    for (i = st->size -1; (i>=0 && st->packet[i].inIpaddr > ip); i--)
    {
        st->packet[i+1] = st->packet[i];
    }
    st->packet[i+1].inIpaddr = ip;
    st->packet[i+1].count = 1;
    ++st->size;
}

int bin_search(unsigned long ip)
{
    if (st->size == 0)
    {
        return -1;
    }
    unsigned long start = 0; 
    unsigned long end = st->size;
    unsigned long mid = (start + end)/2;
    while (start < end)
    {
        if (st->packet[mid].inIpaddr == ip){
            return mid;
        } else if (st->packet[mid].inIpaddr < ip){
            start = mid+1;
        } else if (st->packet[mid].inIpaddr > ip)
        {   
            end = mid -1;
        }
        mid = (start + end)/2;
    }
    return -1;   
}
void next_packet(unsigned long ip)
{   
    int index = bin_search(ip);
    if (index != -1)
    {
        st->packet[index].count++; 
    }
    else 
    {
        insert_new(ip);
    }

}