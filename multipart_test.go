package main

import (
	"bytes"
	"io"
	"mime/multipart"
	"os"
	"strings"
	"testing"
)

func testLimits() *Limits {
	return &Limits{MaxParts: 1000, MaxPartHeaderSize: 8192, MaxPartHeaders: 8, MaxNameLen: 1024, MaxFilenameLen: 1024, MaxCTypeLen: 255, DropNamePrefixes: []string{"PHP_SESSION"}}
}

func TestPHPContentDisposition(t *testing.T) {
	cases := []struct {
		cd                string
		name, filename    string
		hasName, hasFile  bool
	}{
		{`form-data; name="a"`, "a", "", true, false},
		{`form-data; name="a"; filename="b.txt"`, "a", "b.txt", true, true},
		{`form-data; name="a"; filename=""`, "a", "", true, true},
		{`form-data; name=a; filename=b`, "a", "b", true, true},
		{`form-data; name='a'`, "a", "", true, false},
		{`form-data; NAME="x"; FileName="y"`, "x", "y", true, true},
		{`form-data; name="a\"b"`, `a"b`, "", true, false},
		{`form-data; name="a\\b"`, `a\b`, "", true, false},
		{`form-data; name="C:\fakepath\x.txt"`, `C:\fakepath\x.txt`, "", true, false},
		{`form-data; name="a"b"`, `a"b`, "", true, false},
		{`form-data; name="pole[]"; filename="č ěš.png"`, "pole[]", "č ěš.png", true, true},
		{`form-data; name="a"; name="b"`, "b", "", true, false},
		{`  form-data;name="a";filename="b"`, "a", "b", true, true},
		{`form-data; name=`, "", "", true, false},
		{`attachment`, "", "", false, false},
		{`form-data; name="a; b"; filename="x;y.txt"`, "a; b", "x;y.txt", true, true},
		{`form-data; name="a%22b"`, "a%22b", "", true, false},
	}
	for _, c := range cases {
		n, hn, f, hf := phpContentDisposition(c.cd)
		if n != c.name || hn != c.hasName || f != c.filename || hf != c.hasFile {
			t.Errorf("%q: got name=%q(%v) filename=%q(%v), want %q(%v) %q(%v)", c.cd, n, hn, f, hf, c.name, c.hasName, c.filename, c.hasFile)
		}
	}
}

func TestQuoteRoundTrip(t *testing.T) {
	for _, v := range []string{"a", `a"b`, `a\b`, `a\"b`, `C:\x\y`, "č", "a; b", "", "x[]", `a\\b`} {
		cd := "form-data; name=" + quoteParam(v) + "; filename=" + quoteParam(v)
		n, hn, f, hf := phpContentDisposition(cd)
		if !hn || !hf || n != v || f != v {
			t.Errorf("round trip %q → %q: name=%q filename=%q", v, cd, n, f)
		}
	}
}

func TestPHPBoundary(t *testing.T) {
	cases := map[string]string{
		`multipart/form-data; boundary=----WebKitFormBoundaryabc`:         "----WebKitFormBoundaryabc",
		`multipart/form-data; boundary="----abc"`:                          "----abc",
		`multipart/form-data; charset=utf-8; boundary=xyz; foo=bar`:        "xyz",
		`multipart/form-data; BOUNDARY=UP`:                                 "UP",
		`multipart/form-data;boundary=a,b`:                                 "a",
		`multipart/form-data`:                                              "",
		`multipart/form-data; boundary=`:                                   "",
		`multipart/form-data; boundary="abc`:                               "",
	}
	for ct, want := range cases {
		b, err := phpBoundary(ct)
		if want == "" {
			if err == nil {
				t.Errorf("%q: expected an error, got %q", ct, b)
			}
			continue
		}
		if err != nil || b != want {
			t.Errorf("%q: got %q err=%v want %q", ct, b, err, want)
		}
	}
	if err := validBoundary(strings.Repeat("a", 71)); err == nil {
		t.Error("71 chars must be an error")
	}
	if err := validBoundary("ab cd "); err == nil {
		t.Error("trailing space must be an error")
	}
	if err := validBoundary("a\"b"); err == nil {
		t.Error("quote must be an error")
	}
	if err := validBoundary("----WebKitFormBoundary7MA4YWxkTrZu0gW"); err != nil {
		t.Error(err)
	}
}

func buildBody(t *testing.T, parts func(w *multipart.Writer)) (string, string) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	parts(w)
	w.Close()
	return b.String(), w.Boundary()
}

func TestProcessCanonical(t *testing.T) {
	body, bnd := buildBody(t, func(w *multipart.Writer) {
		w.WriteField("text", "příliš žluťoučký kůň\r\nline2")
		w.WriteField("pole[]", "1")
		w.WriteField("pole[]", "2")
		w.WriteField("PHP_SESSION_UPLOAD_PROGRESS", "x")
		fw, _ := w.CreateFormFile("soubor", "č ěš.bin")
		fw.Write([]byte{0, 1, 2, '\r', '\n', '-', '-'})
		fw, _ = w.CreateFormFile("prazdny", "")
		_ = fw
	})
	var out bytes.Buffer
	rep := processMultipart(strings.NewReader(body), bnd, &out, "NEWB", testLimits())
	if rep.Err != nil {
		t.Fatal(rep.Err)
	}
	if rep.Parts != 6 || rep.Files != 2 || len(rep.Dropped) != 1 || rep.Dropped[0] != "PHP_SESSION_UPLOAD_PROGRESS" {
		t.Fatalf("report: %+v", rep)
	}
	outStr := out.String()
	// the output must parse again and yield the same data
	mr := multipart.NewReader(strings.NewReader(outStr), "NEWB")
	var got []string
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(p)
		got = append(got, p.FormName()+"|"+p.FileName()+"|"+p.Header.Get("Content-Type")+"|"+string(data))
	}
	want := []string{
		"text||" + "|příliš žluťoučký kůň\r\nline2",
		"pole[]|||1", "pole[]|||2",
		"soubor|č ěš.bin|application/octet-stream|\x00\x01\x02\r\n--",
		"prazdny||application/octet-stream|",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(outStr, `filename=""`) {
		t.Error("empty filename must stay present")
	}
	if strings.Contains(outStr, "PHP_SESSION") {
		t.Error("upload progress field was not dropped")
	}
}

func TestProcessRejects(t *testing.T) {
	lim := testLimits()
	cases := map[string]string{
		"nested":    "--B\r\nContent-Disposition: form-data; name=\"x\"\r\nContent-Type: multipart/mixed; boundary=C\r\n\r\nabc\r\n--B--\r\n",
		"noname":    "--B\r\nContent-Disposition: form-data\r\n\r\nabc\r\n--B--\r\n",
		"nocd":      "--B\r\nContent-Type: text/plain\r\n\r\nabc\r\n--B--\r\n",
		"truncated": "--B\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nabc",
		"dupcd":     "--B\r\nContent-Disposition: form-data; name=\"x\"\r\nContent-Disposition: form-data; name=\"y\"\r\n\r\nabc\r\n--B--\r\n",
		"longname":  "--B\r\nContent-Disposition: form-data; name=\"" + strings.Repeat("a", 2000) + "\"\r\n\r\nabc\r\n--B--\r\n",
		"garbage":   "this is not multipart at all",
	}
	for name, body := range cases {
		var out bytes.Buffer
		rep := processMultipart(strings.NewReader(body), "B", &out, "N", lim)
		if rep.Err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	// an empty body is fine (0 parts)
	var out bytes.Buffer
	rep := processMultipart(strings.NewReader(""), "B", &out, "N", lim)
	if rep.Err != nil || rep.Parts != 0 || out.String() != "--N--\r\n" {
		t.Errorf("empty body: %+v %q", rep, out.String())
	}
	// LF instead of CRLF is tolerated by both Go and PHP
	rep = processMultipart(strings.NewReader("--B\nContent-Disposition: form-data; name=\"x\"\n\nabc\n--B--\n"), "B", &out, "N", lim)
	if rep.Err != nil || rep.Parts != 1 {
		t.Errorf("LF body: %+v", rep)
	}
	// part count limit
	lim.MaxParts = 2
	body, bnd := buildBody(t, func(w *multipart.Writer) {
		w.WriteField("a", "1")
		w.WriteField("b", "2")
		w.WriteField("c", "3")
	})
	rep = processMultipart(strings.NewReader(body), bnd, &out, "N", lim)
	if rep.Err == nil {
		t.Error("part limit does not work")
	}
}

func TestTooLarge(t *testing.T) {
	body, bnd := buildBody(t, func(w *multipart.Writer) {
		fw, _ := w.CreateFormFile("f", "big.bin")
		fw.Write(bytes.Repeat([]byte("x"), 100000))
	})
	lb := &limitedBody{r: strings.NewReader(body), left: 50000}
	var out bytes.Buffer
	rep := processMultipart(lb, bnd, &out, "N", testLimits())
	if rep.Err != errTooLarge {
		t.Errorf("expected errTooLarge, got %v", rep.Err)
	}
}

func TestGodebugHeaderLimit(t *testing.T) {
	os.Setenv("GODEBUG", "multipartmaxheaders=3")
	defer os.Unsetenv("GODEBUG")
	body := "--B\r\nContent-Disposition: form-data; name=\"x\"\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\nX-D: 4\r\n\r\nabc\r\n--B--\r\n"
	rep := processMultipart(strings.NewReader(body), "B", nil, "", testLimits())
	if rep.Err == nil {
		t.Error("GODEBUG multipartmaxheaders had no effect – header limits would not work")
	}
	os.Unsetenv("GODEBUG")
	rep = processMultipart(strings.NewReader(body), "B", nil, "", testLimits())
	if rep.Err != nil {
		t.Errorf("must pass after the limit is removed: %v", rep.Err)
	}
}

func TestIsMultipartLikePHP(t *testing.T) {
	yes := []string{"multipart/form-data; boundary=X", "multipart/form-data, boundary=X", "multipart/form-data boundary=X",
		"MULTIPART/Form-Data;boundary=X", "multipart/form-data;charset=utf-8;boundary=X", "multipart/form-data"}
	no := []string{"multipart/form-datax; boundary=X", "application/x-www-form-urlencoded", "multipart/mixed; boundary=X", "", "text/plain"}
	for _, ct := range yes {
		if !isMultipart(ct) {
			t.Errorf("%q must be multipart", ct)
		}
	}
	for _, ct := range no {
		if isMultipart(ct) {
			t.Errorf("%q must not be multipart", ct)
		}
	}
}
