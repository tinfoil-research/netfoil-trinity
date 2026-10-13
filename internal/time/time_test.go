package time

import (
	"testing"
	"time"
)

func TestNTPTime(t *testing.T) {
	t1 := time.Date(2026, 9, 1, 0, 0, 0, 123456789, time.UTC)

	seconds, fraction := toNTPTime(t1)

	t2 := fromNTPTime(seconds, fraction)

	if t1.Unix() != t2.Unix() {
		t.Fatalf("time mismatch: got %d; want %d", t1.Unix(), t2.Unix())
	}

	diff := int64(t1.Nanosecond()) - int64(t2.Nanosecond())
	diff = max(diff, -diff)
	nanoSecondThreshold := int64(1)

	if diff > nanoSecondThreshold {
		t.Fatalf("nanosecond difference too large: got %d; want at most %d", diff, nanoSecondThreshold)
	}
}

func TestNTPShortTime(t *testing.T) {
	t1 := time.Date(1900, 1, 1, 2, 3, 4, 123456789, time.UTC)

	seconds, fraction := toNTPShortTime(t1)

	t2 := fromNTPShortTime(seconds, fraction)

	if t1.Unix() != t2.Unix() {
		t.Fatalf("time mismatch: got %d; want %d", t1.Unix(), t2.Unix())
	}

	diff := int64(t1.Nanosecond()) - int64(t2.Nanosecond())
	diff = max(diff, -diff)
	nanoSecondThreshold := int64(13186)

	if diff > nanoSecondThreshold {
		t.Fatalf("nanosecond difference too large: got %d; want at most %d", diff, nanoSecondThreshold)
	}
}

func TestEncodeDecode(t *testing.T) {
	packet := Packet{
		LeapIndicator:              0,
		VersionNumber:              4,
		Mode:                       4,
		Stratum:                    2,
		Poll:                       0,
		Precision:                  -18,
		RootDelaySeconds:           0,
		RootDelayFraction:          2,
		RootDispersionSeconds:      0,
		RootDispersionFraction:     1,
		ReferenceID:                "XNT",
		ReferenceTimestampSeconds:  1,
		ReferenceTimestampFraction: 2,
		OriginTimestampSeconds:     3,
		OriginTimestampFraction:    4,
		ReceiveTimestampSeconds:    5,
		ReceiveTimestampFraction:   6,
		TransmitTimestampSeconds:   7,
		TransmitTimestampFraction:  8,
	}

	data, err := Encode(packet)
	if err != nil {
		t.Fatal(err)
	}

	decodedPacket, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}

	if packet.LeapIndicator != decodedPacket.LeapIndicator {
		t.Fatalf("LeapIndicator does not match")
	}

	if packet.VersionNumber != decodedPacket.VersionNumber {
		t.Fatalf("VersionNumber does not match")
	}

	if packet.Mode != decodedPacket.Mode {
		t.Fatalf("Mode does not match")
	}

	if packet.Stratum != decodedPacket.Stratum {
		t.Fatalf("Stratum does not match")
	}

	if packet.Poll != decodedPacket.Poll {
		t.Fatalf("Poll does not match")
	}

	if packet.Precision != decodedPacket.Precision {
		t.Fatalf("Precision does not match")
	}

	if packet.RootDelaySeconds != decodedPacket.RootDelaySeconds {
		t.Fatalf("RootDelaySeconds does not match")
	}

	if packet.RootDelayFraction != decodedPacket.RootDelayFraction {
		t.Fatalf("RootDelayFraction does not match")
	}

	if packet.RootDispersionSeconds != decodedPacket.RootDispersionSeconds {
		t.Fatalf("RootDispersionSeconds does not match")
	}

	if packet.RootDispersionFraction != decodedPacket.RootDispersionFraction {
		t.Fatalf("RootDispersionFraction does not match")
	}

	if packet.ReferenceID != decodedPacket.ReferenceID {
		t.Fatalf("ReferenceID does not match")
	}

	if packet.ReferenceTimestampSeconds != decodedPacket.ReferenceTimestampSeconds {
		t.Fatalf("ReferenceTimestampSeconds does not match")
	}

	if packet.ReferenceTimestampFraction != decodedPacket.ReferenceTimestampFraction {
		t.Fatalf("ReferenceTimestampFraction does not match")
	}

	if packet.OriginTimestampSeconds != decodedPacket.OriginTimestampSeconds {
		t.Fatalf("OriginTimestampSeconds does not match")
	}

	if packet.OriginTimestampFraction != decodedPacket.OriginTimestampFraction {
		t.Fatalf("OriginTimestampFraction does not match")
	}

	if packet.ReceiveTimestampSeconds != decodedPacket.ReceiveTimestampSeconds {
		t.Fatalf("ReceiveTimestampSeconds does not match")
	}

	if packet.ReceiveTimestampFraction != decodedPacket.ReceiveTimestampFraction {
		t.Fatalf("ReceiveTimestampFraction does not match")
	}

	if packet.TransmitTimestampSeconds != decodedPacket.TransmitTimestampSeconds {
		t.Fatalf("TransmitTimestampSeconds does not match")
	}

	if packet.TransmitTimestampFraction != decodedPacket.TransmitTimestampFraction {
		t.Fatalf("TransmitTimestampFraction does not match")
	}
}
