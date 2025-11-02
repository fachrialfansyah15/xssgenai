package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const escapeLoop = 5

var (
	jsHexRe   = regexp.MustCompile(`\\x([0-9A-Fa-f]{2})`)
	jsUniRe   = regexp.MustCompile(`\\u([0-9A-Fa-f]{4})`)
	dataURIRe = regexp.MustCompile(`data:[^;,]+;base64,([A-Za-z0-9+/=]+)`)
	longB64Re = regexp.MustCompile(`([A-Za-z0-9+/=]{50,})`)
)

type request struct {
	ID       int    `json:"id"`
	Op       string `json:"op"`
	Haystack string `json:"haystack,omitempty"`
	Needle   string `json:"needle,omitempty"`
	Text     string `json:"text,omitempty"`
}

type response struct {
	ID     int         `json:"id"`
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	for scanner.Scan() {
		line := scanner.Bytes()
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			writeResp(writer, response{Error: err.Error()})
			continue
		}

		switch req.Op {
		case "contains":
			writeResp(writer, response{ID: req.ID, Result: containsUnescaped(req.Haystack, req.Needle)})
		case "decode":
			writeResp(writer, response{ID: req.ID, Result: decodeAll(req.Text)})
		default:
			writeResp(writer, response{ID: req.ID, Error: "unknown op"})
		}
	}

	if err := scanner.Err(); err != nil {
		writeResp(writer, response{Error: err.Error()})
	}
}

func writeResp(w *bufio.Writer, resp response) {
	data, _ := json.Marshal(resp)
	w.Write(data)
	w.WriteByte('\n')
	w.Flush()
}

func containsUnescaped(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	if strings.Contains(haystack, needle) {
		return true
	}
	return strings.Contains(decodeAll(haystack), needle)
}

func decodeAll(s string) string {
	if s == "" {
		return ""
	}

	for i := 0; i < escapeLoop; i++ {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}

	for i := 0; i < escapeLoop; i++ {
		unescaped := html.UnescapeString(s)
		if unescaped == s {
			break
		}
		s = unescaped
	}

	s = jsHexRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := jsHexRe.FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		val, err := strconv.ParseUint(sub[1], 16, 8)
		if err != nil {
			return m
		}
		return string(rune(val))
	})

	s = jsUniRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := jsUniRe.FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		val, err := strconv.ParseUint(sub[1], 16, 16)
		if err != nil {
			return m
		}
		return string(rune(val))
	})

	s = dataURIRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := dataURIRe.FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		decoded := tryBase64(sub[1])
		if decoded == sub[1] {
			return m
		}
		return strings.Replace(m, sub[1], decoded, 1)
	})

	s = longB64Re.ReplaceAllStringFunc(s, func(m string) string {
		decoded := tryBase64(m)
		if decoded == m {
			return m
		}
		if printable(decoded) {
			return decoded
		}
		return m
	})

	return s
}

func tryBase64(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(decoded)
}

func printable(s string) bool {
	for _, r := range s {
		if r < 32 && !strings.ContainsRune("\r\n\t", r) {
			return false
		}
	}
	return true
}
