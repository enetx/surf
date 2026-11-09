package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const scenarioHTML = `<!doctype html><meta charset=utf-8><link rel=icon href="data:,"><title>wire capture</title><body>running<script>
(async()=>{try{for(let n=0;n<9;n++){
 const headers={};if(n!==0&&n!==6)headers.authorization=n<3?'Bearer capture-fixed':'Bearer capture-changed';
 const r=await fetch('/step/'+n,{headers,credentials:'same-origin',cache:'no-store'});if(!r.ok)throw Error('step '+n+': '+r.status);await r.text();
}await fetch('/complete',{cache:'no-store'});document.body.dataset.done='true';document.title='complete';}
catch(e){document.title='failed';await fetch('/failed?message='+encodeURIComponent(String(e)));}})();
</script>`

type headerField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type observedRequest struct {
	Label       string        `json:"label"`
	Connection  string        `json:"connection"`
	Protocol    string        `json:"protocol"`
	Method      string        `json:"method"`
	Path        string        `json:"path"`
	Fields      []headerField `json:"fields"`
	HeaderBlock string        `json:"header_block_hex,omitempty"`
	StreamID    uint64        `json:"stream_id,omitempty"`
}

func (s *captureServer) response(path string) (http.Header, []byte) {
	h := http.Header{"Cache-Control": []string{"no-store"}, "Content-Type": []string{"text/plain"}}
	if strings.HasPrefix(path, "/scenario") {
		h.Set("Content-Type", "text/html")
		return h, []byte(scenarioHTML)
	}
	if path == "/step/0" {
		h["Set-Cookie"] = []string{"a=" + strings.Repeat("x", 17) + "; Path=/; Secure; HttpOnly", "b=" + strings.Repeat("y", 18) + "; Path=/; Secure; HttpOnly", "c=" + strings.Repeat("z", 200) + "; Path=/; Secure; HttpOnly"}
	}
	if path == "/step/4" {
		h["Set-Cookie"] = []string{"a=" + strings.Repeat("v", 18) + "; Path=/; Secure; HttpOnly"}
	}
	if path == "/step/0" && s.responseBytes > 0 {
		return h, []byte(strings.Repeat("d", s.responseBytes))
	}
	if path == "/complete" || strings.HasPrefix(path, "/failed") {
		s.mu.Lock()
		s.completed = true
		if strings.HasPrefix(path, "/failed") {
			s.failure = path
		}
		s.mu.Unlock()
	}
	return h, []byte("ok")
}

func (s *captureServer) nextTableSize(path string) (uint32, bool) {
	if !strings.HasPrefix(path, "/step/") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(path, "/step/"))
	if err != nil {
		return 0, false
	}
	stages := map[int]uint32{0: 4096, 1: 65536, 2: 65536, 3: 128, 4: 4096, 5: 0, 6: 4096}
	value, ok := stages[n]
	return value, ok
}

func (s *captureServer) record(req observedRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
	b, err := json.Marshal(req)
	if err == nil {
		_, err = fmt.Fprintln(s.records, string(b))
	}
	if err != nil {
		s.errors = append(s.errors, err.Error())
	}
}
