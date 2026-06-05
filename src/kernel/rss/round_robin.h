#ifndef ROUND_ROBIN_H
#define ROUND_ROBIN_H

struct cpu_iterator {
    struct bpf_spin_lock semaphore;
    __u32 cpu;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct cpu_iterator);
    __uint(max_entries, 1);
} cpu_iterator_map SEC(".maps");

SEC("xdp")
int round_robin(struct xdp_md *xdp)
{
    struct cpu_iterator *iterator;
    __u32 cpu, idx, key = 0;

    iterator = bpf_map_lookup_elem(&cpu_iterator_map, &key);
    if (!iterator)
        return XDP_ABORTED;

    bpf_spin_lock(&iterator->semaphore);
    idx = iterator->cpu;

    if (++iterator->cpu == rss.cpu_count)
        iterator->cpu = 0;

    bpf_spin_unlock(&iterator->semaphore);

    cpu = rss_lookup_cpu(idx);
    return bpf_redirect_map(&BPFWG_RSS_CPU_MAP, cpu, XDP_ABORTED);
}


#endif
