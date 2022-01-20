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

func readVarint(r io.ByteReader) (int, int, error) {
	varint := 0
	eaten := 0
	for shift := uint(0); ; shift += 7 {
		if shift >= 64 {
			return 0, eaten, ErrIntOverflowGrpc
		}
		b, err := r.ReadByte()
		if err != nil {
			return 0, eaten, err
		}
		eaten++
		varint |= int(b&0x7F) << shift
		if b < 0x80 {
			break
		}
	}
	return varint, eaten, nil
}
