package firefox

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/enetx/g"
)

// Firefox implementation: https://github.com/mozilla/gecko-dev/blob/master/dom/html/HTMLFormSubmission.cpp#L355
func Boundary() g.String {
	// C++
	// mBoundary.AssignLiteral("----geckoformboundary");
	// mBoundary.AppendInt(mozilla::RandomUint64OrDie(), 16);
	// mBoundary.AppendInt(mozilla::RandomUint64OrDie(), 16);

	// prefix := "----geckoformboundary"
	// var num1, num2 uint64
	// binary.Read(rand.Reader, binary.BigEndian, &num1)
	// binary.Read(rand.Reader, binary.BigEndian, &num2)
	// return g.Sprintf("%s%x%x", prefix, num1, num2)

	////////////////////////////////////////////////////////////////////////////

	// C++
	// mBoundary.AssignLiteral("---------------------------");
	// mBoundary.AppendInt(static_cast<uint32_t>(mozilla::RandomUint64OrDie()));
	// mBoundary.AppendInt(static_cast<uint32_t>(mozilla::RandomUint64OrDie()));
	// mBoundary.AppendInt(static_cast<uint32_t>(mozilla::RandomUint64OrDie()));

	prefix := g.String("---------------------------")

	var builder g.Builder
	builder.WriteString(prefix)

	for range 3 {
		var b [4]byte
		rand.Read(b[:])
		builder.WriteString(g.Int(binary.LittleEndian.Uint32(b[:])).String())
	}

	return builder.String()
}
