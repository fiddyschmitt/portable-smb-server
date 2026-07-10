// Package openapi embeds the VFS provider contract and serves it over HTTP so
// that someone building a provider can fetch the spec (and browse it with
// Swagger UI) from a running portable-smb-server.
package openapi

import (
	_ "embed"
	"log"
	"net"
	"net/http"
)

//go:embed openapi.json
var spec []byte

// Spec returns the embedded OpenAPI document (JSON).
func Spec() []byte { return spec }

// Handler serves the spec at /openapi.json and a Swagger UI page at /.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(spec)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(swaggerUI))
	})
	return mux
}

// Serve starts an HTTP server on addr serving the spec and Swagger UI. It
// blocks until the server stops. It is safe to run alongside the SMB server.
func Serve(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("OpenAPI spec available at http://%s/ (raw: http://%s/openapi.json)", ln.Addr(), ln.Addr())
	return http.Serve(ln, Handler())
}

// swaggerUI renders the embedded spec with Swagger UI. It pulls the Swagger UI
// assets from a CDN, so it needs internet access to render; the raw spec at
// /openapi.json always works offline (for codegen or editor.swagger.io).
const swaggerUI = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>portable-smb-server VFS provider API</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => { window.ui = SwaggerUIBundle({ url: 'openapi.json', dom_id: '#swagger-ui' }); };
  </script>
</body>
</html>`
