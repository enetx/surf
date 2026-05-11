package chrome

import (
	"crypto/rand"

	"github.com/enetx/g"
)

// Blink implementation: https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/platform/network/form_data_encoder.cc;drc=1d694679493c7b2f7b9df00e967b4f8699321093;l=130
// WebKit implementation: https://github.com/WebKit/WebKit/blob/main/Source/WebCore/platform/network/FormDataBuilder.cpp#L120
func Boundary() g.String {
	// C++
	// Vector<uint8_t> generateUniqueBoundaryString()
	// {
	//     Vector<uint8_t> boundary;
	//
	//     // The RFC 2046 spec says the alphanumeric characters plus the
	//     // following characters are legal for boundaries:  '()+_,-./:=?
	//     // However the following characters, though legal, cause some sites
	//     // to fail: (),./:=+
	//     // Note that our algorithm makes it twice as much likely for 'A' or 'B'
	//     // to appear in the boundary string, because 0x41 and 0x42 are present in
	//     // the below array twice.
	//     static constexpr std::array<char, 64> alphaNumericEncodingMap {
	//         0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
	//         0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
	//         0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
	//         0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
	//         0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
	//         0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
	//         0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33,
	//         0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42
	//     };
	//
	//     // Start with an informative prefix.
	//     append(boundary, "----WebKitFormBoundary");
	//
	//     // Append 16 random 7-bit ASCII alphanumeric characters.
	//     for (unsigned i = 0; i < 4; ++i) {
	//         unsigned randomness = cryptographicallyRandomNumber<unsigned>();
	//         boundary.append(alphaNumericEncodingMap[(randomness >> 24) & 0x3F]);
	//         boundary.append(alphaNumericEncodingMap[(randomness >> 16) & 0x3F]);
	//         boundary.append(alphaNumericEncodingMap[(randomness >> 8) & 0x3F]);
	//         boundary.append(alphaNumericEncodingMap[randomness & 0x3F]);
	//     }
	//
	//     return boundary;
	// }

	prefix := "----WebKitFormBoundary"

	alphaNumericEncodingMap := []byte{
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
		0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
		0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
		0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
		0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
		0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42,
	}

	boundary := []byte(prefix)

	for range 4 {
		randomBytes := make([]byte, 4)
		rand.Read(randomBytes)

		randomness := uint32(randomBytes[0])<<24 |
			uint32(randomBytes[1])<<16 |
			uint32(randomBytes[2])<<8 |
			uint32(randomBytes[3])

		boundary = append(boundary, alphaNumericEncodingMap[(randomness>>24)&0x3F])
		boundary = append(boundary, alphaNumericEncodingMap[(randomness>>16)&0x3F])
		boundary = append(boundary, alphaNumericEncodingMap[(randomness>>8)&0x3F])
		boundary = append(boundary, alphaNumericEncodingMap[randomness&0x3F])
	}

	return g.String(boundary)
}
