package surf

import (
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"path/filepath"
	"strings"
	"sync"

	"github.com/enetx/g"
)

// Multipart represents multipart form data with fields and files.
type Multipart struct {
	fields g.MapOrd[g.String, g.String]
	files  g.Slice[*MultipartFile]
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

// prepareWriter writes the multipart data to a writer and returns the content type and write error.
func (m *Multipart) prepareWriter(boundary func() g.String) (io.ReadCloser, string, *error) {
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	var (
		writeErr error
		once     sync.Once
	)

	if boundary != nil {
		if err := writer.SetBoundary(boundary().Std()); err != nil {
			pw.Close()
			pr.Close()
			writeErr = err
			return nil, "", &writeErr
		}
	}

	setWriteErr := func(err error) {
		if err != nil {
			once.Do(func() { writeErr = err })
		}
	}

	go func() {
		defer func() {
			setWriteErr(writer.Close())
			pw.Close()
		}()

		for key, value := range m.fields.Iter() {
			fw, err := writer.CreateFormField(key.Std())
			if err != nil {
				setWriteErr(err)
				return
			}

			if _, err := io.Copy(fw, value.Reader()); err != nil {
				setWriteErr(err)
				return
			}
		}

		for f := range m.files.Iter() {
			var reader io.Reader

			if f.file != nil {
				r := f.file.Open()
				if r.IsErr() {
					setWriteErr(fmt.Errorf("cannot open file %s: %w", f.file.Name(), r.Err()))
					return
				}

				file := r.Ok()
				defer file.Close()

				reader = file.Std()
			} else {
				reader = f.reader
			}

			fw, err := createFormFile(writer, f.fieldName.Std(), f.fileName.Std(), f.contentType.Std())
			if err != nil {
				setWriteErr(err)
				return
			}

			if _, err := io.Copy(fw, reader); err != nil {
				setWriteErr(err)
				return
			}
		}
	}()

	return pr, writer.FormDataContentType(), &writeErr
}

// createFormFile creates a form file with custom content type support.
func createFormFile(w *multipart.Writer, fieldName, fileName, contentType string) (io.Writer, error) {
	h := make(textproto.MIMEHeader)
	h.Set(
		"Content-Disposition",
		fmt.Sprintf(`form-data; name="%s"; filename="%s"`, escapeQuotes(fieldName), escapeQuotes(fileName)),
	)

	if contentType == "" {
		contentType = mime.TypeByExtension(filepath.Ext(fileName))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
	}

	h.Set("Content-Type", contentType)
	return w.CreatePart(h)
}

var quoteEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func escapeQuotes(s string) string { return quoteEscaper.Replace(s) }
