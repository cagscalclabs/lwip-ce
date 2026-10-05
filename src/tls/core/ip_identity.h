#ifndef TLS_IP_IDENTITY_H
#define TLS_IP_IDENTITY_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Strict dotted decimal: no abbreviated, octal, or hexadecimal addresses. */
static inline int tls_identity_ipv4(const char *s, uint8_t out[4])
{
    for (unsigned i = 0; i < 4; ++i)
    {
        unsigned value = 0, digits = 0;
        const char *start = s;
        while (*s >= '0' && *s <= '9')
        {
            value = value * 10 + (unsigned)(*s++ - '0');
            if (++digits > 3 || value > 255) return 0;
        }
        if (!digits || (digits > 1 && *start == '0')) return 0;
        out[i] = (uint8_t)value;
        if (i == 3) return *s == '\0';
        if (*s++ != '.') return 0;
    }
    return 0;
}

/* Return 4/16 for an IP literal, 0 for a DNS name, -1 for malformed IP
 * syntax. IPv6 is unbracketed and has no zone identifier (those belong to
 * endpoint/URI parsing, not a certificate identity). No allocation needed. */
static inline int tls_identity_ip(const char *s, uint8_t out[16])
{
    if (!s || !*s) return -1;
    if (!strchr(s, ':'))
    {
        if (tls_identity_ipv4(s, out)) return 4;
        /* Reject legacy numeric aliases accepted by some transport parsers,
         * rather than authenticating them as a DNS identity. */
        if (strspn(s, "0123456789abcdefABCDEFxX.") == strlen(s) &&
            ((s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ||
             strstr(s, ".0x") || strstr(s, ".0X"))) return -1;
        if (strspn(s, "0123456789.") == strlen(s) ||
            strchr(s, '[') || strchr(s, ']') || strchr(s, '%')) return -1;
        return 0;
    }

    size_t used = 0;
    int gap = -1;
    if (*s == ':')
    {
        if (s[1] != ':') return -1;
        gap = 0;
        s += 2;
    }
    while (*s)
    {
        const char *start = s;
        unsigned value = 0, digits = 0;
        while ((*s >= '0' && *s <= '9') ||
               (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F'))
        {
            unsigned d = (*s <= '9') ? (unsigned)(*s - '0') :
                         (*s >= 'a') ? (unsigned)(*s - 'a' + 10) :
                                       (unsigned)(*s - 'A' + 10);
            if (++digits > 4) return -1;
            value = (value << 4) | d;
            ++s;
        }
        if (*s == '.')
        {
            if (used > 12 || !tls_identity_ipv4(start, out + used)) return -1;
            used += 4;
            s += strlen(s);
            break;
        }
        if (!digits || used > 14) return -1;
        out[used++] = (uint8_t)(value >> 8);
        out[used++] = (uint8_t)value;
        if (!*s) break;
        if (*s++ != ':') return -1;
        if (*s == ':')
        {
            if (gap >= 0) return -1;
            gap = (int)used;
            ++s;
        }
        else if (!*s) return -1;
    }
    if (gap >= 0)
    {
        if (used >= 16) return -1; /* :: must replace at least one group. */
        size_t tail = used - (size_t)gap;
        memmove(out + 16 - tail, out + gap, tail);
        memset(out + gap, 0, 16 - used);
        return 16;
    }
    return used == 16 ? 16 : -1;
}
#endif
