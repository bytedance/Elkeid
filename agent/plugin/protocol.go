package plugin

import (
	"fmt"
	"io"
)

var (
	ErrInvalidLengthGrpc        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowGrpc          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupGrpc = fmt.Errorf("proto: unexpected end of group")
)

func readVarint(buf []byte) (int, int, error) {
	index := 0
	l := len(buf)
	varint := 0
	for shift := uint(0); ; shift += 7 {
		if shift >= 64 {
			return 0, 0, ErrIntOverflowGrpc
		}
		if index >= l {
			return 0, 0, io.ErrUnexpectedEOF
		}
		b := buf[index]
		index++
		varint |= int(b&0x7F) << shift
		if b < 0x80 {
			break
		}
	}
	return varint, index, nil
}
