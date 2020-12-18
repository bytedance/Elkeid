/*
 * The kprobes linker script.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
SECTIONS {
	. = ALIGN(8);
	.__kprobes_template : {
		__start_kprobe_template = .;
		KEEP(*(.__kprobe_template))
		__stop_kprobe_template = .;

		. = ALIGN(8);
		__start_kretprobe_template = .;
		KEEP(*(.__kretprobe_template))
		__stop_kretprobe_template = .;

		. = ALIGN(8);
		__start_tracepoint_template = .;
		KEEP(*(.__tracepoint_template))
		__stop_tracepoint_template = .;

		. = ALIGN(8);
		__start_kprobe_initcall = .;
		KEEP(*(.__kprobe_initcall))
		__stop_kprobe_initcall = .;

		. = ALIGN(8);
		__start_print_event_class = .;
		KEEP(*(.__print_event_class))
		__stop_print_event_class = .;
	}
}
