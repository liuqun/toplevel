#include <stdio.h>
#include <ck_ring.h>

int main(void)
{
    const unsigned int MY_RING_SIZE = 256;
    ck_ring_t ring;

    ck_ring_init(&ring, MY_RING_SIZE);
    printf("get ring capacity = %u\n", ck_ring_capacity(&ring));
    return 0;
}
