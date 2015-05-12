#undef TRACE_SYSTEM
#define TRACE_SYSTEM i2c-pxa

#if !defined(_TRACE_I2C_CORE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_I2C_PXA_H

#include <linux/tracepoint.h>


TRACE_EVENT(i2c_pxa_xfer,
	TP_PROTO(unsigned int is_write, const char *bus, int addr, int len, char *data),

	TP_ARGS(is_write, bus, addr, len, data),

	TP_STRUCT__entry(
		__field(unsigned int,	is_write)
		__string(bus,		bus)
		__field(int,		addr)
		__field(int,		len)
		__string(data,		data)
	),
	TP_fast_assign(
		__entry->is_write = is_write;
		__assign_str(bus, bus)
		__entry->addr = addr;
		__entry->len = len;
		__assign_str(data, data)
	),
	TP_printk("%s,  %s, addr: %#02x, len: %#02x, data: %s",
		__entry->is_write ? "WR" : "RD", __get_str(bus),
		__entry->addr, __entry->len, __get_str(data))
);
/**
 * event tracer to print the data read
 */
TRACE_EVENT(i2c_pxa_xfer_read_data,
	TP_PROTO(int addr, char *data),
	TP_ARGS(addr, data),
	TP_STRUCT__entry(
	__field(int,		addr)
	__string(data,		data)
	),
	TP_fast_assign(
		__entry->addr = addr;
		__assign_str(data, data)
	),
	TP_printk("Read addr: %#x, data: %s", __entry->addr, __get_str(data))
);

/**
 * This trace event traces the failures of the i2c_pxa_xfer, so it only reports failure
 */
TRACE_EVENT(i2c_pxa_xfer_fail,
	TP_PROTO(unsigned int is_write),
	TP_ARGS(is_write),
	TP_STRUCT__entry(
	__field(unsigned int,	is_write)
	),
	TP_fast_assign(
		__entry->is_write = is_write;
	),
	TP_printk("%s failed", __entry->is_write ? "WR" : "RD")
);


#endif

/* This part must be outside protection */
#include <trace/define_trace.h>
