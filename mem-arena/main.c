#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>

#define ARENA_IMPLEMENTATION
#include "arena.h"

static Arena default_arena = {0};
static Arena temporary_arena = {0};
static Arena *context_arena = &default_arena;

void *context_alloc(size_t size)
{
    assert(context_arena);
    return arena_alloc(context_arena, size);
}

int main(void)
{

    char* first_str = "hello first";
    char* second_str = "hello second";

    uint8_t* first = (uint8_t*)context_alloc(256);
    uint8_t* second = (uint8_t*)context_alloc(512);

    memcpy(first, first_str, strlen(first_str));

    memcpy(second, second_str, strlen(second_str));

    context_arena = &temporary_arena;
    context_alloc(64);
    context_alloc(128);
    context_alloc(256);
    context_alloc(512);

    printf("first: %s\n", first);
    printf("second: %s\n", second);

    arena_free(&default_arena);
    arena_free(&temporary_arena);
    return 0;
}