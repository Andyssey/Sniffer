#define DEBUG 1
FILE *logptr = NULL;
struct iface_packet {
    long inIpaddr;
    long count;
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
    fread(&st->size, sizeof(int), 1, logptr);
    fread(&st->capacity, sizeof(int), 1, logptr);
    // st->size = sz;
    // st->capacity = cap;
    st->packet = calloc(sizeof(struct iface_packet),st->capacity);
    fread(&st->packet, sizeof(struct context), st->size, logptr);
}
void insert_new(unsigned long ip)
{
    /*If array is empty*/
    if (st->size == 0)
    {
        st->packet->inIpaddr = ip;
        st->packet->count = 1;
        st->size = 1;
        printf("ONE TIME PRINT: %lu\n",st->size);
        /*
        printf("DEBUG\n");
        printf("Addr is %lu\n",ip);
        printf("Amount of is %lu\n", st->packet->count);
        printf("Size is %d", st->size);
        */
    }
    /*Check for and number to insert after*/
    size_t index = -1;
    for (int i = 0; i < st->size; i++)
    {
        if(st->packet[i].inIpaddr > ip)
        {
            index = i;
            printf("Got an index funtion\n");
        }
    }
    /*Check if we need to resize the array.
    Lets double size each time we run out of allocated memory \
    so that we don't need to call realloc each time we have one more IP*/
    if (st->size + 1 > st->capacity)
    {
        st->capacity = st->capacity * 2;
        st->packet = realloc(st->packet, st->capacity * sizeof(struct iface_packet));
    }
    
    /*Just append to the end if there is no bigger index*/
    if (index == -1)
    {
        // printf("Index to the end\n");
        index = st->size;
        // st->packet[index].inIpaddr = ip;
        // st->packet[index].count = 1;
        // printf("Current size !!!!!!!! is %lu\n",st->size++);
        // st->size++;
    }
    else
    {
        for (int i = st->size; i > index; i--)
        {
            st->packet[i] = st->packet[i-1];
        }
        // st->packet[index].inIpaddr = ip;
        // st->packet[index].count = 1;
        // ++st->size;
    }
    st->packet[index].inIpaddr = ip;
    st->packet[index].count = 1;
    ++st->size;

}

int bin_search(unsigned long ip)
{
    unsigned long start = 0; 
    unsigned long end = st->size;
    unsigned long mid = (start + end)/2;
    while (start < end)
    {
        if (st->packet[mid].inIpaddr < ip){
            start = mid + 1;
        } else if (st->packet[mid].inIpaddr > ip){
            end = mid;
        } else {
            return mid;
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
        printf("Counter of the packet %lu\n", st->packet[index].count);
    }
    else 
    {
        insert_new(ip);
    }

}