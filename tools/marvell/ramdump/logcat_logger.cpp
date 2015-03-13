/*------------------------------------------------------------
(C) Copyright [2006-2008] Marvell International Ltd.
All Rights Reserved
------------------------------------------------------------*/

#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))
#define seq_printf fprintf
#include "rdp.h"
#include "time.h"

#if defined(_MSC_VER)
/* We do not support MSVC above 6.0 and build for 64-bit */
#define __time32_t time_t
#define _localtime32 localtime
#endif

#define	LOGCAT_MAXBUFSIZE					4096
#define	LOGCAT_MAX_STRING_LEN				100

typedef struct logger_entry_t {
	u16 len;		/* length of the payload */
	u16 __pad;		/* no matter what, we get 2 bytes of padding */
	u32 pid;		/* generating process's pid */
	u32 tid;		/* generating process's tid */
	u32 sec;		/* seconds since Epoch */
	u32 nsec;		/* nanoseconds */
	u32 uid;
} logger_entry_t;

//...

static char buf[LOGCAT_MAXBUFSIZE + sizeof(logger_entry_t)];	/* space for message text and the next log header */

static int handle_print_log_entry(FILE * ftxt, char *buf, logger_entry_t * logger_entry)
{
	char line[LOGCAT_MAXBUFSIZE];
	int tag_size;
	int size, len;
	struct tm *ptm;
	char timeBuf[32];
	char tag_name[LOGCAT_MAX_STRING_LEN];
	char buf_name[LOGCAT_MAXBUFSIZE];
	int ret = 1;

#if defined(_MSC_VER)
	__time32_t timeObj;
	timeObj = (__time32_t) logger_entry->sec;
	ptm = _localtime32(&timeObj);
#else
	time_t timeObj;
	timeObj = (time_t) logger_entry->sec;
	ptm = localtime(&timeObj);
#endif

	if (ptm)
		strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", ptm);
	else
		strcpy(timeBuf, "00-00 00:00:00.000");
	memset(tag_name, 0, sizeof(tag_name));
	memset(buf_name, 0, sizeof(buf_name));

	//msg[1..17]= "SharedBufferStack" >size=strlen(SharedBufferStack) <-tag
	tag_size = strlen(&buf[1]);
	if (tag_size >= sizeof(tag_name))
		tag_size = sizeof(tag_name) - 1;
	strncpy(tag_name, &buf[1], tag_size);

	//msg[19..(0x76-17-3=98)]]= "waitForCon...again" <-msg      msg_len=0x76-17-3=98
	size = logger_entry->len - tag_size - 3;
	if (size >= sizeof(buf_name))
		size = sizeof(buf_name) - 1;
	memcpy(buf_name, &buf[2 + tag_size], size);

	memset(line, 0, sizeof(line));

	//09-18 16:30:55.453   590   638 D MobileDataStateTrackermobile: setPolicyDataEnable(enabled=true)
	sprintf(line, "%s.%03d PID=%5d, TID=%5d  %s: ",
		timeBuf, logger_entry->nsec / 1000000, logger_entry->pid, logger_entry->tid, tag_name);
	len = strlen(line);
	if (size > sizeof(line) - 1 - len)
		buf_name[sizeof(line) - 1 - len] = 0;
	sprintf(line + len, "%s", buf_name);

	//Remove last 0xa if exist
	if (line[strlen(line) - 1] == 0xa)
		line[strlen(line) - 1] = 0;
	//Replace 0xa with \\n to keep single line
	char *s = line;
	char newline[LOGCAT_MAXBUFSIZE];
	memset(newline, 0, sizeof(line));
	char *d = newline;

	while (*s) {
		if (*s == 0xd) {
			s++;
			continue;
		} else if (*s == 0xa) {
			strcat(d, "\\n");
			d++;
		} else
			*d = *s;
		s++;
		d++;
	}

	fprintf(ftxt, "%s\n", newline);

	return 0;
}

static int handle_print_logcat_log(FILE * fin, FILE * ftxt)
{
	logger_entry_t _msg;
	logger_entry_t *msg = &_msg;
	logger_entry_t *next = 0;
	u8 prev = 0;
	char cont = '-';
	int len;
	u32 foffs = 0;
	int seq = 0;
	int ret = 1;

	len = sizeof(*msg);

	while (!feof(fin)) {
		if (fread(msg, sizeof(*msg), 1, fin) != 1)
			break;

		// Skip until header reads ok
		if (msg->len >= LOGCAT_MAXBUFSIZE) {
			// Assume all logs area read
			//fprintf(stderr, "Error Len %d > %d",msg->len, LOGCAT_MAXBUFSIZE);
			break;
		}

		len = fread(&buf[0], sizeof(buf[0]), msg->len, fin);
		seq++;		/* keep track of the number of valid records found */

		//Handle Print
		handle_print_log_entry(ftxt, buf, msg);

	}

	fprintf(rdplog, "%d Records\n", seq);

	return 0;

}

int logcat_parser(const char *inName, FILE * fin, const char *name, struct rdc_dataitem *rdi, int nw)
{
	FILE *fbin = 0;
	FILE *ftxt = 0;
	int ret = 1;
	int res;
	char outnameTemp[LOGCAT_MAX_STRING_LEN];

	char *binname = changeNameExt(inName, name);
	char *txtname = changeExt(name, "txt");
	sprintf(outnameTemp, "logcat_%s", txtname);
	char *outname = changeNameExt(inName, outnameTemp);

	fprintf(rdplog, "logcat parser: %s ", inName);

	if (!binname || ((fbin = fopen(binname, "rb")) == NULL)) {
		fprintf(rdplog, "logcat Failed to open input file %s\n", binname);
		goto bail;
	}

	if (!outname || ((ftxt = fopen(outname, "wt+")) == NULL)) {
		fprintf(rdplog, "logcat Failed to open output file %s\n", txtname);
		goto bail;
	}

	res = handle_print_logcat_log(fbin, ftxt);

	if (!res)
		goto bail;

	ret = 0;

bail:
	if (binname)
		free(binname);
	if (txtname)
		free(txtname);
	if (outname)
		free(outname);
	if (fbin)
		fclose(fbin);
	if (ftxt)
		fclose(ftxt);
	return ret;

}
