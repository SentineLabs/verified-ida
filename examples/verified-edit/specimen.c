/* Harmless static-analysis fixture. Compilation is enough; do not execute it. */
__attribute__((noinline)) unsigned specimen_clamp(unsigned requested) {
    return requested > 512u ? 512u : requested;
}

int main(int argc, char **argv) {
    (void)argv;
    return (int)specimen_clamp((unsigned)argc);
}
