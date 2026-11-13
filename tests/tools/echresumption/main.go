// echresumption verifies private captured pairs and writes sanitized references.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/enetx/surf/tests/internal/echcapture"
)

func main() {
	input := flag.String("input", "", "private RawCapture JSON array")
	output := flag.String("out", "", "directory for new sanitized references")
	keylog := flag.String("keylog", "", "compare private inner key-log records with -reference")
	probeBrowser := flag.String("probe", "", "capture Surf: chrome or firefox")
	protocol := flag.String("protocol", "h3", "probe protocol: h2 or h3")
	early := flag.Bool("early", false, "explicitly enable HTTP/3 early data for the probe")
	racing := flag.Bool("racing", false, "race prepared TCP against HTTP/3 in the probe")
	dns := flag.String("dns", "", "optional DNS resolver host:port for the public capture probe")
	reference := flag.String("reference", "", "sanitized browser reference for comparison")
	record := flag.Int("record", 2, "one-based inner record to compare")
	flag.Parse()
	var err error
	if *probeBrowser != "" {
		err = probe(*probeBrowser, *protocol, *keylog, *early, *racing, *dns)
	} else if *keylog != "" {
		err = compare(*keylog, *reference, *record)
	} else {
		err = references(*input, *output)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func compare(keylog, reference string, record int) error {
	data, err := os.ReadFile(reference)
	if err != nil {
		return err
	}
	var ref echcapture.Reference
	if err := json.Unmarshal(data, &ref); err != nil {
		return err
	}
	f, err := os.Open(keylog)
	if err != nil {
		return err
	}
	defer f.Close()
	records, err := echcapture.ReadInnerKeyLog(f)
	if err != nil {
		return err
	}
	if record < 1 || record > len(records) {
		return errors.New("inner record is out of range")
	}
	family := strings.ToLower(strings.Split(ref.Browser, "/")[0])
	want, err := echcapture.StableFingerprint(ref.Inner, family, ref.Transport)
	if err != nil {
		return err
	}
	got, err := echcapture.StableFingerprint(records[record-1].Inner, family, ref.Transport)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(want, got) {
		fmt.Println("Stable inner fingerprint matches the native reference")
		return nil
	}
	result := struct{ Native, Surf *echcapture.Fingerprint }{want, got}
	data, err = json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return errors.New("stable inner fingerprint differs from the native reference")
}

func references(input, output string) error {
	if input == "" || output == "" {
		return errors.New("use -input PRIVATE_CAPTURE_JSON -out NEW_REFERENCE_DIRECTORY")
	}
	f, err := os.Open(input)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var captures []echcapture.RawCapture
	if err := decoder.Decode(&captures); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("capture input contains trailing JSON")
	}
	if len(captures) == 0 {
		return errors.New("capture array is empty")
	}
	type file struct {
		name string
		data []byte
	}
	var files []file
	counts := make(map[string]int)
	for i, capture := range captures {
		ref, err := echcapture.NewReference(capture)
		if err != nil {
			return fmt.Errorf("capture %d: %w", i, err)
		}
		family, version, ok := strings.Cut(ref.Browser, "/")
		if !ok || family != "Chrome" && family != "Firefox" {
			return errors.New("capture must identify Chrome or Firefox")
		}
		major, err := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
		if err != nil || major < 1 {
			return errors.New("invalid captured browser version")
		}
		prefix := fmt.Sprintf("%s-%d-%s", strings.ToLower(family), major, ref.Transport)
		counts[prefix]++
		data, err := json.MarshalIndent(ref, "", "  ")
		if err != nil {
			return err
		}
		files = append(files, file{fmt.Sprintf("%s-%d.json", prefix, counts[prefix]), append(data, '\n')})
	}
	if err := os.Mkdir(output, 0755); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(output)
		}
	}()
	for _, file := range files {
		f, err := os.OpenFile(filepath.Join(output, file.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(file.data)
		closeErr := f.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return err
		}
		fmt.Println("Verified and redacted:", file.name)
	}
	complete = true
	return nil
}
