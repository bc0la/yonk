# yonk

Golang simpleHTTPserver/http.server replacement with allowlists for enhanced OpSec.

Frustrations with OpSec and poor recommendations from certificate study guides inspired the creation of **yonk**.

For some examples of simpleHTTPservers gone wrong, refer to [My Blog Post](https://c0la.org/Blog/SimpleHTTPServer+-+Why+taking+the+time+do+things+right+is+worth+it).

Uses ssl by default

## Usage

```Usage:
  yonk [directory] [flags]

Flags:
  -a, --allowlist string   Comma-separated IPs or file with IPs (all allowed if omitted)
  -h, --help               help for yonk
  -s, --no-ssl             Disable SSL (serve over HTTP)
  -p, --port string        Port to listen on```
