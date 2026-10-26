/*
Alex Renteria
abr92
proj3.c
10/24/2026

This
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void usage(char *program)
{
    fprintf(stderr,
            "Usage: %s [-p] [-c] [-n] "
            "[-r trace_file]\n",
            program);
}

int main(int argc, char *argv[]) {
    int opt;
    int mode = 0;
    char *trace_file = NULL;

    while ((opt = getopt(argc, argv, "pcnr:")) != -1) {
        switch (opt) {
        case 'p':
            if (mode != 0) {
                fprintf(stderr, "Error: multiple modes specified.\n");
                exit(1);
            }
            mode = 'p';
            break;

        case 'c':
            if (mode != 0) {
                fprintf(stderr, "Error: multiple modes specified.\n");
                exit(1);
            }
            mode = 'c';
            break;

        case 'n':
            if (mode != 0) {
                fprintf(stderr, "Error: multiple modes specified.\n");
                exit(1);
            }
            mode = 'n';
            break;

        case 'r':
            trace_file = optarg;
            break;

        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if (mode == 0) {
        fprintf(stderr, "Error: must specify -p, -c, -n, or -r.\n");
        exit(1);
    }

    if (trace_file == NULL) {
        fprintf(stderr, "Error: must give a trace file with -r.\n");
        exit(1);
    }

    if (mode == 'p')
        printf("Printing Mode");
        //forwardMode(table_filename);
    else if (mode == 'c')
        printf("Counting Mode");
        //dumpMode(packet_filename);
    else
        printf("NetFlow Mode");
        //simMode(table_filename, packet_filename);

    exit(0);
}