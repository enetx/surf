package echcapture

import (
	"bufio"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

type InnerRecord struct {
	OuterRandom []byte
	Inner       []byte
}

func ReadInnerKeyLog(reader io.Reader) ([]InnerRecord, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var result []InnerRecord
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] != "UTLS_ECH_INNER_CLIENT_HELLO" {
			continue
		}
		if len(fields) != 3 {
			return nil, errors.New("invalid inner ClientHello key-log record")
		}
		random, err := hex.DecodeString(fields[1])
		if err != nil || len(random) != 32 {
			return nil, errors.New("invalid outer random in key-log record")
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil {
			return nil, errors.New("invalid private ClientHello hex")
		}
		if _, err := ReadClientHello(raw); err != nil {
			return nil, err
		}
		result = append(result, InnerRecord{random, raw})
	}
	return result, scanner.Err()
}
