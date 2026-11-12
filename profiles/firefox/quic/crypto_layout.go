package quic

import (
	"slices"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
)

// InitialCryptoLayout follows Firefox 160's SNI slicing for the first QUIC
// ClientHello. It balances the CRYPTO data, sends the selected right-hand range
// before the left-hand range, and retains every byte's original stream offset.
// A missing or incomplete hostname leaves the engine's native layout unchanged.
// The engine calls this policy for each Initial packet with the remaining ranges
// and live plaintext limit and frame budget. It retains ownership of retransmission
// and subsequent handshake messages. Only the first returned group is sent now;
// the remaining ranges are reconsidered against the next packet's live budget.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/crypto.rs#L1650-L1773
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/sni.rs#L13-L71
func InitialCryptoLayout(info quic.InitialCryptoLayoutInfo) [][]quic.CryptoRange {
	if info.Length <= 0 || info.SNIOffset < 0 || info.SNILength <= 0 ||
		info.SNILength > info.Length || info.SNIOffset > info.Length-info.SNILength ||
		info.PacketSizeLimit <= 0 || info.FrameBudget < 4 || info.FrameBudget > info.PacketSizeLimit {
		return nil
	}

	mid := info.SNIOffset + info.SNILength/2
	if mid == 0 {
		return nil
	}
	unsent := slices.Clone(info.Remaining)
	for i, part := range unsent {
		if part.Offset < 0 || part.Length <= 0 || part.Length > info.Length ||
			part.Offset > info.Length-part.Length || i > 0 && unsent[i-1].Offset+unsent[i-1].Length > part.Offset {
			return nil
		}
	}
	remaining := info.FrameBudget
	var packet []quic.CryptoRange
	for len(unsent) > 0 {
		first := unsent[0]
		if first.Offset == 0 && info.SNIOffset+info.SNILength <= first.Length {
			left := quic.CryptoRange{Length: mid}
			right := quic.CryptoRange{Offset: mid, Length: first.Length - mid}
			count := 1 + (first.Length-1)/info.PacketSizeLimit
			limit := first.Length / count
			switch {
			case first.Length <= limit:
			case left.Length <= limit:
				skip := right.Length + left.Length - limit
				right.Offset += skip
				right.Length -= skip
			case right.Length <= limit:
				left.Length = limit - right.Length
			default:
				left.Length = limit / 2
				right.Length = limit / 2
			}
			a, aOK := initialCryptoChunk(right, remaining)
			if aOK {
				packet = append(packet, a)
				remaining -= initialCryptoChunkSize(a)
				unsent = omitInitialCryptoRange(unsent, a)
			}
			b, bOK := initialCryptoChunk(left, remaining)
			if bOK {
				packet = append(packet, b)
				remaining -= initialCryptoChunkSize(b)
				unsent = omitInitialCryptoRange(unsent, b)
			}
			if aOK && bOK || !aOK && !bOK {
				break
			}
			continue
		}
		part, ok := initialCryptoChunk(first, remaining)
		if !ok {
			break
		}
		packet = append(packet, part)
		remaining -= initialCryptoChunkSize(part)
		unsent = omitInitialCryptoRange(unsent, part)
	}
	if len(packet) == 0 {
		return nil
	}
	if len(unsent) == 0 {
		return [][]quic.CryptoRange{packet}
	}
	return [][]quic.CryptoRange{packet, unsent}
}

// initialCryptoChunk mirrors Neqo's two-step length estimate, including the
// length varint's change in width at a packet boundary.
func initialCryptoChunk(part quic.CryptoRange, budget int) (quic.CryptoRange, bool) {
	header := 1 + quicvarint.Len(uint64(part.Offset)) + 1
	if part.Length <= 0 || budget < header+1 {
		return quic.CryptoRange{}, false
	}
	length := min(part.Length, budget-header)
	header += quicvarint.Len(uint64(length)) - 1
	part.Length = min(part.Length, budget-header)
	return part, part.Length > 0
}

func initialCryptoChunkSize(part quic.CryptoRange) int {
	return 1 + quicvarint.Len(uint64(part.Offset)) + quicvarint.Len(uint64(part.Length)) + part.Length
}

func omitInitialCryptoRange(unsent []quic.CryptoRange, sent quic.CryptoRange) []quic.CryptoRange {
	remaining := make([]quic.CryptoRange, 0, len(unsent)+1)
	end := sent.Offset + sent.Length
	for _, part := range unsent {
		partEnd := part.Offset + part.Length
		if end <= part.Offset || sent.Offset >= partEnd {
			remaining = append(remaining, part)
			continue
		}
		if part.Offset < sent.Offset {
			remaining = append(remaining, quic.CryptoRange{Offset: part.Offset, Length: sent.Offset - part.Offset})
		}
		if end < partEnd {
			remaining = append(remaining, quic.CryptoRange{Offset: end, Length: partEnd - end})
		}
	}
	return remaining
}
