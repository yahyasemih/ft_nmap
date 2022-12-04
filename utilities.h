//
// Created by Yahya Ez-zainabi on 12/04/22.
//

#ifndef UTILITIES_H
#define UTILITIES_H

#include <stdlib.h>

void    *ft_memcpy(void *dst, const void *src, size_t n);

void    ft_bzero(void *dst, size_t n);

int     ft_strcmp(const char *s1, const char *s2);

int     ft_strncmp(const char *s1, const char *s2, size_t n);

size_t  ft_strlen(const char *s);

int     ft_atoi(const char *s);

#endif
