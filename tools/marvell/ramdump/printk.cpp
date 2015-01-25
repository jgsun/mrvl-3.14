/*------------------------------------------------------------
(C) Copyright [2006-2008] Marvell International Ltd.
All Rights Reserved
------------------------------------------------------------*/

#include "rdp.h"

/* Enable STAND_ALONE for WIN printk.exe compilation
 * Linux compile-script already make with -DSTAND_ALONE
 */
//#define STAND_ALONE

#define VERSION_STRING "0.2"
/* Revision history:
 *  0.2: log_check() for alignment 4 or/and 8
 *       TAB is printable character
 *       Print format "dmesg" without PRINT_CONT_CHAR
 */

/* From kernel 3.10, file kernel/printk.c */
enum log_flags {
        LOG_NOCONS      = 1,    /* already flushed, do not print to console */
        LOG_NEWLINE     = 2,    /* text ended with a newline */
        LOG_PREFIX      = 4,    /* text started with a prefix */
        LOG_CONT        = 8,    /* text is a fragment of a continuation line */
};

struct log {
        u64 ts_nsec;            /* timestamp in nanoseconds */
        u16 len;                /* length of entire record */
        u16 text_len;           /* length of text buffer */
        u16 dict_len;           /* length of dictionary buffer */
        u8 facility;            /* syslog facility */
        u8 flags:5;             /* internal record flags */
        u8 level:3;             /* syslog level */
};

#define MAX_RECORD 1000
char buf[MAX_RECORD+sizeof(struct log)]; /* space for message text and the next log header */

static char *log_text(const struct log *msg)
{
        return buf;
}

/* optional key/value pair dictionary attached to the record */
static char *log_dict(const struct log *msg)
{
        return buf + msg->text_len;
}

static int log_check(const struct log *msg)
{
	int len;

	if ((msg->len - sizeof(*msg)) >= MAX_RECORD)
		return -1;

	len = sizeof(*msg) + msg->text_len + msg->dict_len;
	/* alignment of total len might be either 8  OR  4
	 * (depending upon CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	 * Fail only if both variants are failed
	 */
	if ((((len + 3) & ~3) != msg->len)
	 && (((len + 7) & ~7) != msg->len))
		return -1;
	return 0;
}

/* the function converting the records to pure text
 * and return the number of valid records found */
int convert_printk(FILE *fin, FILE *fout)
{
	/* See kernel/printk.c:devkmsg_read(), print_time() */
	struct log _msg;
	struct log *msg = &_msg;
	struct log *next = 0;
	u8 prev = 0;
	u32 ts_usec, ts_sec;
	char cont = '-';
	int i;
	u32 foffs = 0;
	int seq = 0;
	int len, bodylen, backed;

	while (!feof(fin)) {
		if (next)
			memcpy(msg, next, sizeof(*msg));
		else if (fread(msg, sizeof(*msg), 1, fin) != 1)
			goto done;
		next = 0;

		// Skip until header reads ok
		if (log_check(msg)) {
			fprintf(stderr, "Skipping to the next valid header from 0x%.8x...", foffs);
			do {
				foffs += sizeof(unsigned); //Good for both alignments - 4 and 8 bytes
				if (fseek(fin, foffs, SEEK_SET))
					goto done; /* eof */
				if (fread(msg, sizeof(*msg), 1, fin) != 1)
					goto done; /* eof */
			} while (log_check(msg));
			fprintf(stderr, "up to 0x%.8x\n", foffs);
		}

		bodylen = msg->len - sizeof(*msg);
		backed = 0;
		len = fread(&buf[0], sizeof(buf[0]), msg->len, fin);
		if (len < bodylen)
			for (i = len; i < bodylen; i++)
				buf[i] = '.';
		else {
			/* we read the next header: verify it to confirm the current one is consistent */
			for (i = 0; (i<bodylen) && log_check((struct log *)&buf[bodylen-i]); i+=sizeof(unsigned))
				;
			if (i && i<bodylen) {
				backed = 0;
				msg->len -= i;
				backed = (i >= msg->dict_len) ? msg->dict_len : i;
				msg->dict_len -= backed;
				i -= backed;
				msg->text_len -= i;
				backed += i;
				fseek(fin, -backed, SEEK_CUR);
				fprintf(stderr, "Backing up %u bytes at 0x%.8x\n", backed, foffs + msg->len);
			}
			next = (struct log *)&buf[msg->len - sizeof(*msg)];
		}
		seq++; /* keep track of the number of valid records found */
		foffs += msg->len;
		ts_sec = (u32)(msg->ts_nsec/1000000000);
		ts_usec = (u32)((msg->ts_nsec%1000000000)/1000);
        if (msg->flags & LOG_CONT && !(prev & LOG_CONT))
                cont = 'c';
        else if ((msg->flags & LOG_CONT) ||
                 ((prev & LOG_CONT) && !(msg->flags & LOG_PREFIX)))
                cont = '+';

#ifdef PRINT_CONT_CHAR
        fprintf(fout, "<%u> [%5u.%06u],%c;",
                      (msg->facility << 3) | msg->level,
                      ts_sec, ts_usec, cont);
#else
        fprintf(fout, "<%u> [%5u.%06u] ",
                      (msg->facility << 3) | msg->level,
                      ts_sec, ts_usec);
#endif
        prev = msg->flags;

        /* escape non-printable characters */
        for (i = 0; i < msg->text_len; i++) {
                unsigned char c = log_text(msg)[i];

                if (c!=0x0a && c!=0x09/*TAB*/&& !isprint(c))//c < ' ' || c >= 127 || c == '\\')
                        fprintf(fout, "\\x%02x", c);
                else
                        fprintf(fout, "%c", c);
        }
        fprintf(fout, "\n");

        if (msg->dict_len) {
                bool line = true;

                for (i = 0; i < msg->dict_len; i++) {
                        unsigned char c = log_dict(msg)[i];

                        if (line) {
                                fprintf(fout, " ");;
                                line = false;
                        }

                        if (c == '\0') {
                                fprintf(fout, "\n");
                                line = true;
                                continue;
                        }
                        if (c < ' ' || c >= 127 || c == '\\') {
                                fprintf(fout, "\\x%02x", c);
                                continue;
                        }

                        fprintf(fout, "%c", c);
                }
                fprintf(fout, "\n");
		}
	}
done:
	return seq;
}

#ifndef STAND_ALONE
int printk_parser(const char* inName, FILE *fin, const char *name, struct rdc_dataitem *rdi, int nw)
{
	FILE *fbin = 0;
	FILE *ftxt = 0;
	int ret = 0;

	char *binname = changeNameExt(inName, name);
	char *txtname = changeExt(binname, "txt");

	if (!binname || ((fbin = fopen(binname, "rb")) == NULL)) {
		fprintf(rdplog, "Failed to open input file %s\n", binname);
		goto bail;
	}

	if (!txtname || ((ftxt = fopen(txtname, "wt+")) == NULL)) {
		fprintf(rdplog, "Failed to open output file %s\n", txtname);
		goto bail;
	}

	ret = convert_printk(fbin, ftxt);
	if (!ret)
		fprintf(rdplog, "Printk Conversion failed at offset 0x%.8lx, wrong format: check if the input is pure text\n", ftell(fin));
	else
		fprintf(stderr, "\nDone, %d valid messages found\n", ret);

	/* ret = 0 mean 0 records found -> failure
	 * switching to regular convention: ret = 0 -> success */
	ret = !ret;

bail:
	if (fbin)
		fclose(fbin);
	if (ftxt) {
		fclose(ftxt);
		if (ret)
			unlink(txtname);
	}
	if (binname)
		free(binname);
	if (txtname)
		free(txtname);
	return ret;
}
#endif

#ifdef STAND_ALONE
int main(int argc, char* argv[])
{
	FILE* fin = 0;
	FILE* fout = 0;
	char* inName=0;
	char* outName=0;
	int ret = -1;

	fprintf(stderr,"Marvell printk converter, version %s\n", VERSION_STRING);
	if(argc<2)
	{
		fprintf(stderr,"USAGE: %s input-file-name\n", argv[0]);
		exit(1);
	}

	inName = argv[1];

	if(!(fin=fopen(inName,"rb")))
	{
		fprintf(stderr,"Cannot open input file \"%s\"\n", inName);
		exit(1);
	}

	if (strcmp(getExt(inName), "txt"))
		outName = changeExt(inName, "txt");
	else
		outName = changeExt(inName, "out.txt");

	if(!outName || (fout = fopen(outName, "wt"))==NULL)
	{
		fprintf(stderr, "Cannot open output file \"%s\"\n", outName?outName : "null");
		goto bail;
	}

	ret = convert_printk(fin, fout);
	if (!ret)
		fprintf(stderr, "\nConversion failed at offset 0x%.8lx, wrong format: check if the input is pure text\n", ftell(fin));
	else
		fprintf(stderr, "\nDone, %d valid messages found\n", ret);
	ret = !ret;
bail:
	if (fout) {
		fclose(fout);
		if (ret && outName)
			unlink(outName);
	}

	if (outName)
		free(outName);
	if (fin)
		fclose(fin);
	exit(ret);
	return ret;
}
#endif
