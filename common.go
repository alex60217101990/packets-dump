/*
	Package main - transpiled by c2go version: v0.26.0 Erbium 2020-03-17

	If you have found any issues, please raise an issue at:
	https://github.com/elliotchance/c2go/
*/

package main

import "unsafe"

type __s8 int8
type __u8 uint8
type __s16 int16
type __u16 uint16
type __s32 int32
type __u32 uint32
type __s64 int64
type __u64 uint64
type __kernel_fd_set struct {
	fds_bits [16]uint32
}
type __kernel_sighandler_t func(int32)
type __kernel_key_t int32
type __kernel_mqd_t int32
type __kernel_old_uid_t uint16
type __kernel_old_gid_t uint16
type __kernel_old_dev_t uint32
type __kernel_long_t int32
type __kernel_ulong_t uint32
type __kernel_ino_t __kernel_ulong_t
type __kernel_mode_t uint32
type __kernel_pid_t int32
type __kernel_ipc_pid_t int32
type __kernel_uid_t uint32
type __kernel_gid_t uint32
type __kernel_suseconds_t __kernel_long_t
type __kernel_daddr_t int32
type __kernel_uid32_t uint32
type __kernel_gid32_t uint32
type __kernel_size_t __kernel_ulong_t
type __kernel_ssize_t __kernel_long_t
type __kernel_ptrdiff_t __kernel_long_t
type __kernel_fsid_t struct {
	val [2]int32
}
type __kernel_off_t __kernel_long_t
type __kernel_loff_t int64
type __kernel_time_t __kernel_long_t
type __kernel_time64_t int64
type __kernel_clock_t __kernel_long_t
type __kernel_timer_t int32
type __kernel_clockid_t int32
type __kernel_caddr_t *byte
type __kernel_uid16_t uint16
type __kernel_gid16_t uint16
type __le16 __u16
type __be16 __u16
type __le32 __u32
type __be32 __u32
type __le64 __u64
type __be64 __u64
type __sum16 __u16
type __wsum __u32
type __poll_t uint32
type context struct {
	data_start unsafe.Pointer
	data_end   unsafe.Pointer
	length     __u32
	nh_proto   __u32
	nh_offset  __u32
}
type Lpmv4Key struct {
	prefixlen __u32
	address   [4]__u8
}



type Lpmv6Key struct {
	prefixlen __u32
	address   [16]__u8
}
type port_type int32

const (
	source_port      port_type = 0
	destination_port           = 1
)

type port_protocol int32

const (
	tcp_port port_protocol = 0
	udp_port               = 1
)

type PortKey struct {
	type_ port_type
	proto port_protocol
	port  __u32
}
type counters struct {
	packets __u64
	bytes   __u64
}

func init() {
}
