package main

import (
	"errors"
	"log"
	"net/url"
	"path"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/g/cmp"
	"github.com/enetx/g/pool"
	"github.com/enetx/surf"
)

func main() {
	const dURL = "https://jsoncompare.org/LearningContainer/SampleFiles/Video/MP4/Sample-Video-File-For-Testing.mp4"

	r := surf.NewClient().Head(dURL).Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	if r.Ok().Headers.Get("Accept-Ranges").Ne("bytes") {
		log.Fatal("Doesn't support header 'Accept-Ranges'.")
	}

	contentLength := r.Ok().Headers.Get("Content-Length").TryInt()
	if contentLength.IsErr() {
		log.Fatal(contentLength.Err())
	}

	var (
		tasks     = g.Int(10)
		chunkSize = contentLength.Ok() / tasks
		diff      = contentLength.Ok() % tasks
	)

	p := pool.New[*g.File]().Limit(10)

	for task := range tasks {
		min := chunkSize * task
		max := chunkSize * (task + 1)

		if task == tasks-1 {
			max += diff
		}

		p.Go(func() g.Result[*g.File] {
			headers := g.Map[g.String, g.String]{"Range": g.Format("bytes={}-{}", min, max-1)}

			r := surf.NewClient().
				Builder().
				Retry(10, time.Second*2).
				AddHeaders(headers).
				Build().
				Unwrap().
				Get(dURL).
				Do()

			if r.IsErr() {
				p.Cancel(r.Err())
				return g.Err[*g.File](r.Err())
			}

			tmpFile := g.NewFile("").CreateTemp("", task.String()+".")
			if tmpFile.IsErr() {
				p.Cancel(tmpFile.Err())
				return tmpFile
			}

			if err := r.Ok().Body.Dump(tmpFile.Ok().Path().Ok()); err != nil {
				p.Cancel(err)
				return g.Err[*g.File](err)
			}

			return tmpFile
		})
	}

	result := p.Wait().Collect()

	if err := p.Cause(); err != nil && !errors.Is(err, pool.ErrAllTasksDone) {
		log.Fatal(err)
	}

	result.SortBy(func(a, b g.Result[*g.File]) cmp.Ordering {
		an := a.Ok().Name().Split(".").Take(1).Collect()[0]
		bn := b.Ok().Name().Split(".").Take(1).Collect()[0]
		return an.Cmp(bn)
	})

	buffer := g.NewBuilder()

	result.Iter().ForEach(func(v g.Result[*g.File]) {
		defer v.Ok().Remove()
		buffer.WriteString(v.Ok().Read().Ok())
	})

	pURL, err := url.ParseRequestURI(dURL)
	if err != nil {
		log.Fatal(err)
	}

	g.NewFile(g.String(path.Base(pURL.Path))).Write(buffer.String())
}
