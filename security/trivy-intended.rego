# Ignore vulnerabilities that are inherent to this image:
# kernel UAPI headers, shipped scanner binaries' deps, and pinned helpers.
# Secret path filters live in .trivyignore.yaml (Rego does not receive Result.Target).
# Trivy 0.70 evaluates this file as Rego v0.

package trivy

default ignore = false

# linux-libc-dev is kernel headers. The container does not run that kernel,
# and Ubuntu lists these CVEs as affected with no userspace fix.
ignore {
	input.Type == "vulnerability"
	input.PkgName == "linux-libc-dev"
}

# pdfkit 1.0.0 is the pinned PDF report helper; no fixed release exists.
ignore {
	input.Type == "vulnerability"
	contains(input.PkgName, "pdfkit")
}

# dirsearch ships a native Cargo.lock; we consume the Python tree, not those crates.
# Cargo findings often have an empty PkgPath, so match crate names too.
ignore {
	input.Type == "vulnerability"
	contains(input.PkgPath, "plugins/dirsearch/")
}

ignore {
	input.Type == "vulnerability"
	intended_dirsearch_crate[input.PkgName]
}

intended_dirsearch_crate := {
	"pyo3",
	"quinn-proto",
}

# ProjectDiscovery / ffuf / gobuster / gau / gowitness binaries from
# conf/go-tool-versions.conf. Advisories are in their vendored modules, not Kitelon.
ignore {
	input.Type == "vulnerability"
	intended_go_module[input.PkgName]
}

intended_go_module := {
	"github.com/antchfx/xpath",
	"github.com/buger/jsonparser",
	"github.com/ffuf/ffuf/v2",
	"github.com/getkin/kin-openapi",
	"github.com/go-git/go-billy/v5",
	"github.com/go-git/go-git/v5",
	"github.com/golang-jwt/jwt/v4",
	"github.com/golang-jwt/jwt/v5",
	"github.com/mholt/archiver",
	"github.com/mholt/archiver/v3",
	"github.com/quic-go/quic-go",
	"github.com/sirupsen/logrus",
	"github.com/valyala/fasthttp",
	"golang.org/x/crypto",
	"golang.org/x/mod",
	"golang.org/x/net",
	"golang.org/x/oauth2",
	"golang.org/x/text",
}
