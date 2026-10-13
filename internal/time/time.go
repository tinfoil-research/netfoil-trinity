package time

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

const unixNTPEpochOffset = int64(2208988800)

type Packet struct {
	LeapIndicator byte
	VersionNumber byte
	Mode          byte

	Stratum   byte
	Poll      byte
	Precision int8

	RootDelaySeconds  uint16
	RootDelayFraction uint16

	RootDispersionSeconds  uint16
	RootDispersionFraction uint16

	ReferenceID string

	ReferenceTimestampSeconds  uint32
	ReferenceTimestampFraction uint32

	OriginTimestampSeconds  uint32
	OriginTimestampFraction uint32

	ReceiveTimestampSeconds  uint32
	ReceiveTimestampFraction uint32

	TransmitTimestampSeconds  uint32
	TransmitTimestampFraction uint32

	//ExtensionField
	//KeyIdentifier [4]byte
	//MessageDigest [8]byte
}

func (p *Packet) Print() {
	fmt.Printf("leap indicator %d\n", p.LeapIndicator)
	fmt.Printf("version number %d\n", p.VersionNumber)
	fmt.Printf("mode %d\n", p.Mode)
	fmt.Printf("stratum %d\n", p.Stratum)
	fmt.Printf("poll %d\n", p.Poll)
	fmt.Printf("precision %d\n", p.Precision)
	fmt.Printf("root delay %d %d\n", p.RootDelaySeconds, p.RootDelayFraction)
	fmt.Printf("root dispersion %d %d\n", p.RootDispersionSeconds, p.RootDispersionFraction)
	fmt.Printf("reference ID '%s'\n", p.ReferenceID)
	fmt.Printf("reference timestamp %d %d\n", p.ReferenceTimestampSeconds, p.ReferenceTimestampFraction)
	fmt.Printf("origin timestamp %d %d\n", p.OriginTimestampSeconds, p.OriginTimestampFraction)
	fmt.Printf("receive timestamp %d %d\n", p.ReceiveTimestampSeconds, p.ReceiveTimestampFraction)

	fmt.Printf("transmit timestamp %s %d %d\n", fromNTPTime(p.TransmitTimestampSeconds, p.TransmitTimestampFraction).String(), p.TransmitTimestampSeconds, p.TransmitTimestampFraction)
}

func Decode(data []byte) (*Packet, error) {
	buffer := bytes.NewBuffer(data)

	b, err := buffer.ReadByte()
	if err != nil {
		return nil, err
	}

	leapIndicator := (b >> 6) & 0x3
	versionNumber := (b >> 3) & 0x7
	mode := b & 0x7

	stratum, err := buffer.ReadByte()
	if err != nil {
		return nil, err
	}

	poll, err := buffer.ReadByte()
	if err != nil {
		return nil, err
	}

	precisionRaw, err := buffer.ReadByte()
	if err != nil {
		return nil, err
	}
	precision := int8(precisionRaw)

	rootDelaySeconds, rootDelayFraction, err := readNTPShortTime(buffer)
	if err != nil {
		return nil, err
	}

	rootDispersionSeconds, rootDispersionFraction, err := readNTPShortTime(buffer)
	if err != nil {
		return nil, err
	}

	referenceId, err := readReferenceId(buffer)
	if err != nil {
		return nil, err
	}

	referenceTimestampSeconds, referenceTimestampFraction, err := readNTPTime(buffer)
	if err != nil {
		return nil, err
	}

	originTimestampSeconds, originTimestampFraction, err := readNTPTime(buffer)
	if err != nil {
		return nil, err
	}

	receiveTimestampSeconds, receiveTimestampFraction, err := readNTPTime(buffer)
	if err != nil {
		return nil, err
	}

	transmitTimestampSeconds, transmitTimestampFraction, err := readNTPTime(buffer)
	if err != nil {
		return nil, err
	}

	return &Packet{
		LeapIndicator: leapIndicator,
		VersionNumber: versionNumber,
		Mode:          mode,

		Stratum:   stratum,
		Poll:      poll,
		Precision: precision,

		RootDelaySeconds:  rootDelaySeconds,
		RootDelayFraction: rootDelayFraction,

		RootDispersionSeconds:  rootDispersionSeconds,
		RootDispersionFraction: rootDispersionFraction,

		ReferenceID: referenceId,

		ReferenceTimestampSeconds:  referenceTimestampSeconds,
		ReferenceTimestampFraction: referenceTimestampFraction,

		OriginTimestampSeconds:  originTimestampSeconds,
		OriginTimestampFraction: originTimestampFraction,

		ReceiveTimestampSeconds:  receiveTimestampSeconds,
		ReceiveTimestampFraction: receiveTimestampFraction,

		TransmitTimestampSeconds:  transmitTimestampSeconds,
		TransmitTimestampFraction: transmitTimestampFraction,
	}, nil

}

func Encode(packet Packet) ([]byte, error) {
	initialBufferLength := 48
	buffer := bytes.NewBuffer(make([]byte, 0, initialBufferLength))

	b := byte(0)
	if packet.LeapIndicator > 3 {
		return nil, fmt.Errorf("leap indicator is too large")
	}
	b |= packet.LeapIndicator << 6

	if packet.VersionNumber > 7 {
		return nil, fmt.Errorf("version is too large")
	}
	b |= packet.VersionNumber << 3

	if packet.Mode > 7 {
		return nil, fmt.Errorf("mode is too large")
	}
	b |= packet.Mode

	buffer.WriteByte(b)

	buffer.WriteByte(packet.Stratum)
	buffer.WriteByte(packet.Poll)

	// TODO check
	buffer.WriteByte(byte(packet.Precision))

	err := writeNTPShortTime(buffer, packet.RootDelaySeconds, packet.RootDelayFraction)
	if err != nil {
		return nil, err
	}

	err = writeNTPShortTime(buffer, packet.RootDispersionSeconds, packet.RootDispersionFraction)
	if err != nil {
		return nil, err
	}

	// reference ID
	err = writeReferenceId(buffer, packet.ReferenceID)
	if err != nil {
		return nil, err
	}

	err = writeNTPTime(buffer, packet.ReferenceTimestampSeconds, packet.ReferenceTimestampFraction)
	if err != nil {
		return nil, err
	}

	err = writeNTPTime(buffer, packet.OriginTimestampSeconds, packet.OriginTimestampFraction)
	if err != nil {
		return nil, err
	}

	err = writeNTPTime(buffer, packet.ReceiveTimestampSeconds, packet.ReceiveTimestampFraction)
	if err != nil {
		return nil, err
	}

	err = writeNTPTime(buffer, packet.TransmitTimestampSeconds, packet.TransmitTimestampFraction)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func Now() (uint32, uint32) {
	return toNTPTime(time.Now())
}

func readReferenceId(buffer *bytes.Buffer) (string, error) {
	referenceIdRaw := make([]byte, 4)
	n, err := buffer.Read(referenceIdRaw)
	if err != nil {
		return "", err
	}
	if n != 4 {
		return "", fmt.Errorf("expected 4 bytes, got %d", n)
	}

	index := 3
	for ; index >= 0; index-- {
		if referenceIdRaw[index] != 0x00 {
			break
		}
	}

	return string(referenceIdRaw[:index+1]), nil
}

func writeReferenceId(buffer *bytes.Buffer, referenceId string) error {
	if len(referenceId) > 4 {
		return fmt.Errorf("reference ID is too long")
	}

	data := make([]byte, 4)
	for index := 0; index < len(referenceId); index++ {
		data[index] = referenceId[index]
	}

	for index := len(data); index < 4; index++ {
		data[index] = 0x00
	}

	n, err := buffer.Write(data)
	if err != nil {
		return err
	}
	if n != 4 {
		return fmt.Errorf("expected 4 bytes, got %d", n)
	}

	return nil
}

func readNTPShortTime(buffer *bytes.Buffer) (uint16, uint16, error) {
	var seconds uint16
	var fraction uint16

	err := binary.Read(buffer, binary.BigEndian, &seconds)
	if err != nil {
		return 0, 0, err
	}

	err = binary.Read(buffer, binary.BigEndian, &fraction)
	if err != nil {
		return 0, 0, err
	}

	return seconds, fraction, nil
}

func writeNTPShortTime(buffer *bytes.Buffer, seconds uint16, fraction uint16) error {
	err := binary.Write(buffer, binary.BigEndian, seconds)
	if err != nil {
		return err
	}

	err = binary.Write(buffer, binary.BigEndian, fraction)
	if err != nil {
		return err
	}

	return nil
}

func fromNTPShortTime(seconds uint16, fraction uint16) time.Time {
	nanoseconds := (int64(fraction) * 1e9) >> 16
	result := time.Unix(int64(seconds)-unixNTPEpochOffset, nanoseconds)

	return result
}

func toNTPShortTime(time time.Time) (uint16, uint16) {
	seconds := time.Unix() + unixNTPEpochOffset
	fraction := int64(time.Nanosecond()) << 16 / 1e9

	return uint16(seconds), uint16(fraction)
}

func fromNTPTime(seconds uint32, fraction uint32) time.Time {
	nanoseconds := (int64(fraction) * 1e9) >> 32
	result := time.Unix(int64(seconds)-unixNTPEpochOffset, nanoseconds)

	return result
}

func toNTPTime(time time.Time) (uint32, uint32) {
	seconds := time.Unix() + unixNTPEpochOffset
	fraction := int64(time.Nanosecond()) << 32 / 1e9

	return uint32(seconds), uint32(fraction)
}

func readNTPTime(buffer *bytes.Buffer) (uint32, uint32, error) {
	var seconds uint32
	var fraction uint32

	err := binary.Read(buffer, binary.BigEndian, &seconds)
	if err != nil {
		return 0, 0, err
	}

	err = binary.Read(buffer, binary.BigEndian, &fraction)
	if err != nil {
		return 0, 0, err
	}

	return seconds, fraction, nil
}

func writeNTPTime(buffer *bytes.Buffer, seconds uint32, fraction uint32) error {
	err := binary.Write(buffer, binary.BigEndian, seconds)
	if err != nil {
		return err
	}

	err = binary.Write(buffer, binary.BigEndian, fraction)
	if err != nil {
		return err
	}

	return nil
}

func readExtensions(buffer *bytes.Buffer) error {
	var fieldType uint16
	err := binary.Read(buffer, binary.BigEndian, &fieldType)
	if err != nil {
		return err
	}

	var length uint16
	err = binary.Read(buffer, binary.BigEndian, &length)
	if err != nil {
		return err
	}

	fmt.Printf("extension %d %d\n", fieldType, length)
	return nil
}
