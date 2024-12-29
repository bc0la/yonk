# yonk
golang simplehttpserver/http.server replacement with allowlists for better opsec
Frustrations with OpSec, bad recommendations from cert study guides, etc. made me do this.

Little writeup on all some of the bad http.server things out there on the interwebs:
https://c0la.org/Blog/SimpleHTTPServer+-+Why+taking+the+time+do+things+right+is+worth+it


Usage:
  yonk [directory] [flags]

Flags:
  -a, --allowlist string   Comma-separated IPs or file with IPs
  -h, --help               help for myserver
  -p, --port string        Port to listen on (default "8080")