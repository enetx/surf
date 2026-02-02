package surf

import (
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"path/filepath"

	"github.com/enetx/g"
)

// Multipart represents multipart form data with fields and files.
type Multipart struct {
	fields g.MapOrd[g.String, g.String]
	files  g.Slice[*MultipartFile]
	retry  bool
}

// MultipartFile represents a single file for multipart upload.
type MultipartFile struct {
	fieldName   g.String
	fileName    g.String
	contentType g.String
	file        *g.File
	reader      io.Reader
}

// NewMultipart creates a new empty Multipart object.
func NewMultipart() *Multipart {
	return &Multipart{
		fields: g.NewMapOrd[g.String, g.String](),
		files:  g.NewSlice[*MultipartFile](),
	}
}

// Field adds a form field to the multipart.
func (m *Multipart) Field(name, value g.String) *Multipart {
	m.fields.Insert(name, value)
	return m
}

// File adds a physical file to the multipart.
func (m *Multipart) File(fieldName g.String, file *g.File) *Multipart {
	f := &MultipartFile{
		fieldName: fieldName,
		fileName:  file.Name(),
		file:      file,
	}

	m.files.Push(f)
	return m
}

// FileReader adds a file from io.Reader to the multipart.
func (m *Multipart) FileReader(fieldName, fileName g.String, reader io.Reader) *Multipart {
	f := &MultipartFile{
		fieldName: fieldName,
		fileName:  fileName,
		reader:    reader,
	}

	m.files.Push(f)
	return m
}

// FileString adds a file from string content to the multipart.
func (m *Multipart) FileString(fieldName, fileName, content g.String) *Multipart {
	f := &MultipartFile{
		fieldName: fieldName,
		fileName:  fileName,
		reader:    content.Reader(),
	}

	m.files.Push(f)
	return m
}

// FileBytes adds a file from byte slice to the multipart.
func (m *Multipart) FileBytes(fieldName, fileName g.String, data g.Bytes) *Multipart {
	f := &MultipartFile{
		fieldName: fieldName,
		fileName:  fileName,
		reader:    data.Reader(),
	}

	m.files.Push(f)
	return m
}

// ContentType sets the content type for the last added file.
// Must be called immediately after File/FileReader/FileString/FileBytes.
func (m *Multipart) ContentType(ct g.String) *Multipart {
	if last := m.files.Last(); last.IsSome() {
		last.Some().contentType = ct
	}

	return m
}

// FileName overrides the filename for the last added file.
// Useful when you want a different name than the physical file.
func (m *Multipart) FileName(name g.String) *Multipart {
	if last := m.files.Last(); last.IsSome() {
		last.Some().fileName = name
	}

	return m
}

// Retry controls whether the multipart body should be buffered in memory
// to support retries on status codes (429, 503, 5xx, etc.).
//
// When set to true, the body is fully read into memory before sending,
// allowing the client to replay it on retry.
//
// Default: false (streaming mode, no status-code retry support).
//
// Recommended only for small requests (≤ 5–10 MB).
func (m *Multipart) Retry(enable bool) *Multipart {
	m.retry = enable
	return m
}

// prepareWriter writes the multipart data to a writer and returns the content type and write error.
func (m *Multipart) prepareWriter(boundary func() g.String) (io.ReadCloser, string, error) {
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	if boundary != nil {
		if err := writer.SetBoundary(boundary().Std()); err != nil {
			_ = pw.CloseWithError(err)
			_ = pr.Close()
			return nil, "", err
		}
	}

	go func() {
		err := func() error {
			for key, val := range m.fields.Iter() {
				part, err := writer.CreateFormField(key.Std())
				if err != nil {
					return err
				}

				if _, err := io.Copy(part, val.Reader()); err != nil {
					return err
				}
			}

			for file := range m.files.Iter() {
				var reader io.Reader

				if file.file != nil {
					res := file.file.Open()
					if res.IsErr() {
						return fmt.Errorf("cannot open file %q: %w", file.file.Name(), res.Err())
					}

					opened := res.Ok()
					defer opened.Close()

					reader = opened.Std()
				} else if file.reader != nil {
					reader = file.reader
				} else {
					return fmt.Errorf("multipart file %q has no content source", file.fileName.Std())
				}

				ct := file.contentType.Std()
				if ct == "" {
					ext := filepath.Ext(file.fileName.Std())
					ct = mime.TypeByExtension(ext)
					if ct == "" {
						ct = "application/octet-stream"
					}
				}

				disposition := fmt.Sprintf(
					`form-data; name="%s"; filename="%s"`,
					escapeQuotes(file.fieldName),
					escapeQuotes(file.fileName),
				)

				h := textproto.MIMEHeader{
					"Content-Disposition": {disposition},
					"Content-Type":        {ct},
				}

				part, err := writer.CreatePart(h)
				if err != nil {
					return err
				}

				if _, err := io.Copy(part, reader); err != nil {
					return err
				}
			}

			return writer.Close()
		}()

		pw.CloseWithError(err)
	}()

	return pr, writer.FormDataContentType(), nil
}

func escapeQuotes(s g.String) string { return s.ReplaceMulti(`\`, `\\`, `"`, `\"`).Std() }
