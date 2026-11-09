/*
 * heartbleed.c -- CVE-2014-0160 as a verification target.
 *
 * The function tls1_process_heartbeat below is the body as it stands in
 * ssl/t1_lib.c of OpenSSL 1.0.1g, reproduced without modification, including
 * its comments, its brace style and the typo in the allocation comment. The
 * macros n2s and s2n are the definitions from ssl/ssl_locl.h of the same
 * release. Everything else in this file is scaffolding written to let the
 * function stand alone: reduced struct definitions holding the fields the
 * function reads, the three constants it uses, stub definitions of the four
 * routines it calls, and the property harness at the foot.
 *
 * Licence: the OpenSSL and SSLeay dual licence covers the reproduced material.
 *
*/
#include <string.h>     /* memcpy, called by the reproduced function */

/* --- scaffolding: the constants the function uses ------------------------- */

#define TLS1_RT_HEARTBEAT       24
#define TLS1_HB_REQUEST          1
#define TLS1_HB_RESPONSE         2

/* --- scaffolding: the fields of the OpenSSL structs the function reads ---- */

typedef struct ssl_st SSL;

typedef struct ssl3_record_st {
    unsigned char *data;
    unsigned int   length;
} SSL3_RECORD;

typedef struct ssl3_state_st {
    SSL3_RECORD rrec;
} SSL3_STATE;

struct ssl_st {
    int          version;
    SSL3_STATE  *s3;
    void       (*msg_callback)(int write_p, int version, int content_type,
                               const void *buf, unsigned long len,
                               SSL *ssl, void *arg);
    void        *msg_callback_arg;
    unsigned int tlsext_hb_seq;
    unsigned int tlsext_hb_pending;
};

/* --- verbatim from ssl/ssl_locl.h, OpenSSL 1.0.1f ------------------------- */

#define n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| \
			    (((unsigned int)(c[1]))    )),c+=2)
#define s2n(s,c)	((c[0]=(unsigned char)(((s)>> 8)&0xff), \
			  c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

/* --- scaffolding: stubs for the four routines the function calls ---------- */

/* A bump allocator over a static region large enough for the widest response
 * the function can construct, which is 1 + 2 + 65535 + 16 bytes. Sizing it so
 * allocation always succeeds keeps the unchecked return value of
 * OPENSSL_malloc in the reproduced code from masking the read being studied. */
#define ARENA_SIZE 70000
static unsigned char arena[ARENA_SIZE];
static unsigned int  arena_used;

static void *OPENSSL_malloc(unsigned int n)
{
    if (n > ARENA_SIZE - arena_used)
        return 0;
    unsigned char *p = &arena[arena_used];
    arena_used += n;
    return p;
}

static void OPENSSL_free(void *p)
{
    (void)p;
}

static int RAND_pseudo_bytes(unsigned char *buf, int num)
{
    for (int i = 0; i < num; i++)
        buf[i] = 0;
    return 1;
}

/* Records the length handed to the transport, read by P2. */
unsigned int g_write_length;
int          g_write_called;

static int ssl3_write_bytes(SSL *s, int type, const void *buf, int len)
{
    (void)s; (void)type; (void)buf;
    g_write_called = 1;
    g_write_length = (unsigned int)len;
    return len;
}

/* --- verbatim from ssl/t1_lib.c, OpenSSL 1.0.1g --------------------------- */

int
tls1_process_heartbeat(SSL *s)
	{
	unsigned char *p = &s->s3->rrec.data[0], *pl;
	unsigned short hbtype;
	unsigned int payload;
	unsigned int padding = 16; /* Use minimum padding */

	if (s->msg_callback)
		s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT,
			&s->s3->rrec.data[0], s->s3->rrec.length,
			s, s->msg_callback_arg);

	/* Read type and payload length first */
	if (1 + 2 + 16 > s->s3->rrec.length)
		return 0; /* silently discard */
	hbtype = *p++;
	n2s(p, payload);
	if (1 + 2 + payload + 16 > s->s3->rrec.length)
		return 0; /* silently discard per RFC 6520 sec. 4 */
	pl = p;

	if (hbtype == TLS1_HB_REQUEST)
		{
		unsigned char *buffer, *bp;
		int r;

		/* Allocate memory for the response, size is 1 bytes
		 * message type, plus 2 bytes payload length, plus
		 * payload, plus padding
		 */
		buffer = OPENSSL_malloc(1 + 2 + payload + padding);
		bp = buffer;

		/* Enter response type, length and copy payload */
		*bp++ = TLS1_HB_RESPONSE;
		s2n(payload, bp);
		memcpy(bp, pl, payload);
		bp += payload;
		/* Random padding */
		RAND_pseudo_bytes(bp, padding);

		r = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);

		if (r >= 0 && s->msg_callback)
			s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
				buffer, 3 + payload + padding,
				s, s->msg_callback_arg);

		OPENSSL_free(buffer);

		if (r < 0)
			return r;
		}
	else if (hbtype == TLS1_HB_RESPONSE)
		{
		unsigned int seq;

		/* We only send sequence numbers (2 bytes unsigned int),
		 * and 16 random bytes, so we just try to read the
		 * sequence number */
		n2s(pl, seq);

		if (payload == 18 && seq == s->tlsext_hb_seq)
			{
			s->tlsext_hb_seq++;
			s->tlsext_hb_pending = 0;
			}
		}

	return 0;
	}

/* --- the property ---------------------------------------------------------- */

/* P2: the heartbeat response is no longer than the record that requested it.
 * Returns 1 when the property holds of the record supplied. */
int check_response_no_longer_than_request(unsigned char *record_data,
                                          unsigned int   record_len)
{
    SSL3_STATE s3;
    SSL        ssl;

    s3.rrec.data   = record_data;
    s3.rrec.length = record_len;

    ssl.version           = 0x0303;
    ssl.s3                = &s3;
    ssl.msg_callback      = 0;
    ssl.msg_callback_arg  = 0;
    ssl.tlsext_hb_seq     = 0;
    ssl.tlsext_hb_pending = 0;

    arena_used     = 0;
    g_write_called = 0;
    g_write_length = 0;

    tls1_process_heartbeat(&ssl);

    return (g_write_called == 0) || (g_write_length <= record_len);
}
