package main

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/emicklei/dot"
	"github.com/miekg/dns"
)

// cd $GOPATH/src/github.com/d1ss0lv3/trust-trees-go
// go run main.go | dot -Tsvg  >| test.svg
// go run main.go | dot -Tsvg  >| generated/$(date +"%a%d%b%Y_%H.%M.%S").svg

var rootNS = getRandomRootDNS()

func main() {
	targets := []string{
		"adblock-data.brave.com",
		"mail.google.com",
		"example.com",
		"ledger.brave.com",
		"ticonsultores.biz.ni",
	}
	generateGraphsFor(targets[0])
}

func generateGraphsFor(targets ...string) {
	for _, target := range targets {
		err := generateGraphFor(target)
		if err != nil {
			panic(err)
		}
	}
}

func generateGraphFor(target string) error {
	// create and initialize a new graph:
	gph := dot.NewGraph(dot.Directed)
	gph.Attr("label", target+" DNS Trust Graph")
	gph.Attr("labelloc", "t")
	gph.Attr("pad", "3")
	gph.Attr("nodesep", "1")
	gph.Attr("ranksep", "5")
	gph.Attr("fontsize", "50")
	gph.Attr("concentrate", "true")

	queryType := dns.TypeA

	// create the graphical zero node, i.e. the randomly-chosen root DNS that
	// will be the first NS to be queried:
	zeroNode := gph.Node(rootNS)
	zeroNode.
		Attr("fillcolor", "blue").
		Attr("style", "filled").
		Attr("fontcolor", "white")

	{
		var authority string
		var parentNode dot.Node

		authority = rootNS
		parentNode = zeroNode

		goExplore(gph, parentNode, authority, target, queryType)
	}

	// output dot graph:
	fmt.Println(gph.String())
	return nil
}

func goExplore(
	g *dot.Graph,
	parentNode dot.Node,
	authority string,
	target string,
	queryType uint16,
) {
	for {
		debugf(
			"query: authority:%q, target:%q, queryType:%q\n",
			authority,
			target,
			dns.TypeToString[queryType],
		)
		res, err := Send(authority, target, queryType)
		if err != nil {
			if isErrNoSuchHost(err) {
				debug(authority, ": no such host")
				addErrorNode(g, parentNode, authority, "no such host")
				break
			} else {
				panic(err)
			}
		}

		hasNextAuthority := len(res.Ns) > 0
		debugf(
			"answer: isAuthoritative:%v, hasNextAuthority:%v\n",
			res.Authoritative,
			hasNextAuthority,
		)
		if hasNextAuthority {
			// given that we expect this call to get a non-authoritative answer,
			// let's extract the RR contained in the authority section:
			nextAuthorities := extractAllNS(res.Ns)

			// let's randomly choose the NS (from the authority list) for the next
			// query:
			randomNS := chooseRandomNS(nextAuthorities)
			authority = randomNS.Ns

			// link all NS to parent:
			for _, auth := range nextAuthorities {
				authorityNode := g.Node(auth.Ns)

				style := "dashed"
				//let's make it bold if the NS is gonna be used for the
				// next query:
				if auth.Ns == authority {
					style = "bold"
				}
				g.Edge(
					parentNode,
					authorityNode,
					rcodeLabel(target, res.MsgHdr.Rcode),
				).
					Attr("arrowhead", "vee").
					Attr("arrowtail", "inv").
					Attr("arrowsize", ".7").
					//
					Attr("fontname", "bold").
					Attr("fontsize", "7.0").
					Attr("style", style).
					Attr("fontcolor", RcodeToColor[res.MsgHdr.Rcode])
			}
		}

		noSuggestedNextAuthorities := hasNextAuthority == false
		if !res.Authoritative && noSuggestedNextAuthorities {
			debug(authority, "is not authoritative, but does not suggest who could be")
			// dead end:
			addErrorNode(g, parentNode, "DEAD END", authority+"is not authoritative, but does not suggest who could be")
			debug(spew.Sdump(res.Answer))
			// TODO: show eventual A or AAAA or CNAME records (i.e. non-authoritative answers)
			break
		}

		parentNode = g.Node(authority)
		if !res.Authoritative {
			debug(authority, "is not authoritative")
			continue
		} else {
			debug(authority, "is authoritative")
			parentNode.
				Attr("style", "filled").
				Attr("fillcolor", "#0099ff")

			var content string

			for _, ans := range res.Answer {
				switch answerElem := ans.(type) {
				case *dns.A:
					{
						content += fmt.Sprintf(
							"[A]%v\n",
							answerElem.A,
						)
					}
				case *dns.CNAME:
					{
						content += fmt.Sprintf(
							"[CNAME]%v\n",
							answerElem.Target,
						)
					}
				case *dns.AAAA:
					{
						content += fmt.Sprintf(
							"[AAAA]%v\n",
							answerElem.AAAA,
						)
					}
				}

			}
			resultNode := g.Node(content).
				Attr("style", "filled")
			g.Edge(
				parentNode,
				resultNode,
				rcodeLabel(target, res.MsgHdr.Rcode),
			).
				Attr("arrowhead", "vee").
				Attr("arrowtail", "inv").
				Attr("arrowsize", ".7").
				Attr("color", "#0099ff").
				//
				Attr("fontname", "bold").
				Attr("fontsize", "7.0").
				Attr("style", "bold").
				Attr("fontcolor", RcodeToColor[res.MsgHdr.Rcode])
			if cname, ok := hasCNAME(res.Answer); ok {
				debug("cname:", cname.Target)
				target = cname.Target
				authority = rootNS
				parentNode = resultNode
			} else {
				break
			}
		}
	}
}

func addErrorNode(g *dot.Graph, parentNode dot.Node, content string, label string) {
	errorNode := g.Node(content).
		Attr("style", "filled").
		Attr("fillcolor", "red")

	style := "dashed"

	g.Edge(
		parentNode,
		errorNode,
		label,
	).
		Attr("arrowhead", "vee").
		Attr("arrowtail", "inv").
		Attr("arrowsize", ".7").
		//
		Attr("fontname", "bold").
		Attr("fontsize", "7.0").
		Attr("style", style).
		Attr("fontcolor", "red")
}

func isErrNoSuchHost(e error) bool {
	return strings.Contains(e.Error(), "no such host")
}

func stripFinalDot(s string) string {
	return strings.TrimSuffix(s, ".")
}
func Send(server string, domain string, t uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	c := new(dns.Client)
	m.SetQuestion(dns.Fqdn(domain), t)

	// VERY IMPORTANT:
	m.RecursionDesired = true
	// NOTE: does not work in Italy (via VPN); the result returns directly the A and CNAME records even if asking the root servers.
	// NOTE: works in NL (via VPN).

	r, _, err := c.Exchange(m, stripFinalDot(server)+":"+"53")
	if err != nil {
		return nil, fmt.Errorf("error while exchanging DNS message: %s", err)
	}
	return r, nil
}

func randomInt(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}
func getRandomRootDNS() string {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		panic(err)
	}
	_ = config
	rootResolver := config.Servers[0]

	rootDomain := "."

	rootRes, err := Send(rootResolver, rootDomain, dns.TypeNS)
	if err != nil {
		panic(err)
	}
	rootServers := rootRes.Answer
	return rootServers[randomInt(0, len(rootServers)-1)].(*dns.NS).Ns
}

func extractAllNS(nsRR []dns.RR) []*dns.NS {
	var ns []*dns.NS
	for _, a := range nsRR {
		if _, ok := a.(*dns.NS); ok {
			ns = append(ns, a.(*dns.NS))
		}
	}
	return ns
}
func chooseRandomNS(ns []*dns.NS) *dns.NS {
	if len(ns) == 0 {
		return nil
	}
	return ns[randomInt(0, len(ns)-1)]
}

func hasCNAME(rr []dns.RR) (*dns.CNAME, bool) {
	var cname *dns.CNAME
	for i := range rr {
		a := rr[i]
		if _, ok := a.(*dns.CNAME); ok {
			cname = a.(*dns.CNAME)
		}
	}
	return cname, cname != nil
}

// RcodeToColor maps Rcodes to colors.
var RcodeToColor = map[int]string{
	dns.RcodeSuccess:        "green",
	dns.RcodeFormatError:    "orange",
	dns.RcodeServerFailure:  "red",
	dns.RcodeNameError:      "red", // TODO: maybe use another color to distinguish from dns.RcodeServerFailure?
	dns.RcodeNotImplemented: "red",
	dns.RcodeRefused:        "red",
	dns.RcodeYXDomain:       "purple", // See RFC 2136
	dns.RcodeYXRrset:        "purple",
	dns.RcodeNXRrset:        "purple",
	dns.RcodeNotAuth:        "purple",
	dns.RcodeNotZone:        "purple",
	dns.RcodeBadSig:         "purple", // Also known as dns.RcodeBadVers, see RFC 6891
	//	dns.RcodeBadVers:        "BADVERS",
	dns.RcodeBadKey:    "purple",
	dns.RcodeBadTime:   "purple",
	dns.RcodeBadMode:   "purple",
	dns.RcodeBadName:   "purple",
	dns.RcodeBadAlg:    "purple",
	dns.RcodeBadTrunc:  "purple",
	dns.RcodeBadCookie: "purple",
}

func debug(a ...interface{}) {
	fmt.Fprintln(os.Stderr, a...)
}

func debugf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
}

func rcodeLabel(domain string, rcode int) string {
	return fmt.Sprintf(
		//`<<I>` + domain + `?</I><BR/><FONT point-size="10">` + dns.RcodeToString[rcode] + `</FONT>>`,
		"%s -> %s",
		dns.Fqdn(domain),
		dns.RcodeToString[rcode],
	)
}
