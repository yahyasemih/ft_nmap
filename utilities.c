//
// Created by Yahya Ez-zainabi on 12/04/22.
//

#include "utilities.h"
#include <limits.h>

void    *ft_memcpy(void *dst, const void *src, size_t n) {
    char        *dest = (char *)dst;
    const char  *source = (char *)src;

    for (size_t i = 0; i < n; ++i) {
        dest[i] = source[i];
    }
    return dst;
}

void    ft_bzero(void *dst, size_t n) {
    char    *dest = (char *)dst;

    for (size_t i = 0; i < n; ++i) {
        dest[i] = 0;
    }
}

int     ft_strcmp(const char *s1, const char *s2) {
    size_t  i = 0;

    while (s1[i] && s2[i] && s1[i] == s2[i]) {
        ++i;
    }
    return s1[i] - s2[i];
}

int     ft_strncmp(const char *s1, const char *s2, size_t n) {
    size_t  i = 0;

    while (s1[i] && s2[i] && s1[i] == s2[i] && i < n) {
        ++i;
    }
    if (i == n) {
        return 0;
    } else {
        return s1[i] - s2[i];
    }
}

size_t  ft_strlen(const char *s) {
    size_t  i = 0;

    while (s[i]) {
        ++i;
    }
    return i;
}

int     ft_atoi(const char *s) {
    int64_t value = 0;
    int     sign = 1;
    size_t  i = 0;

    while (s[i] == ' ' || (s[i] >= '\n' && s[i] <= '\r')) {
        ++i;
    }
    if (s[i] == '+' || s[i] == '-') {
        if (s[i] == '-') {
            sign = -1;
        }
        ++i;
    }
    while (s[i] && s[i] >= '0' && s[i] <= '9') {
        if (value > value * 10 + s[i] - '0') {
            if (sign == 1) {
                return (int)LONG_MAX;
            } else {
                return (int)LONG_MIN;
            }
        }
        value = value * 10 + s[i] - '0';
        ++i;
    }
    return (value * sign);
}
