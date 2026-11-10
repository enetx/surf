package firefox

import (
	"crypto/rand"
	"encoding/binary"
	"strconv"

	"github.com/enetx/g"
)

// Boundary follows Firefox's two unpadded hexadecimal random uint64 values.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/dom/html/HTMLFormSubmission.cpp#L362
func Boundary() g.String {
	var random [16]byte
	rand.Read(random[:])
	return g.String("----geckoformboundary" +
		strconv.FormatUint(binary.LittleEndian.Uint64(random[:8]), 16) +
		strconv.FormatUint(binary.LittleEndian.Uint64(random[8:]), 16))
}
