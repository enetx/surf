package main

import (
	"context"
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

	contentLength := r.Ok().Headers.Get("Content-Length").ToInt()
	if contentLength.IsErr() {
		log.Fatal(contentLength.Err())
	}

	var (
		tasks     = g.Int(10)
		chunkSize = contentLength.Ok() / tasks
		diff      = contentLength.Ok() % tasks
	)

	pool := pool.New[*g.File]().Limit(10)

	for task := range tasks {
		min := chunkSize * task
		max := chunkSize * (task + 1)

		if task == tasks-1 {
			max += diff
		}

		pool.Go(func() g.Result[*g.File] {
			headers := g.Map[g.String, g.String]{"Range": g.Format("bytes={}-{}", min, max-1)}

			r := surf.NewClient().
				Builder().
				Retry(10, time.Second*2).
				AddHeaders(headers).
				Build().
				Get(dURL).
				Do()

			if r.IsErr() {
				pool.Cancel(r.Err())
				return g.Err[*g.File](r.Err())
			}

			tmpFile := g.NewFile("").CreateTemp("", task.String()+".")
			if tmpFile.IsErr() {
				pool.Cancel(tmpFile.Err())
				return tmpFile
			}

			if err := r.Ok().Body.Dump(tmpFile.Ok().Path().Ok()); err != nil {
				pool.Cancel(err)
				return g.Err[*g.File](err)
			}

			return tmpFile
		})
	}

	result := pool.Wait().Collect()

	if err := pool.Cause(); err != nil && !errors.Is(err, context.Canceled) {
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
