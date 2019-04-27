package main

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/emicklei/dot"
	"github.com/miekg/dns"
)

// go run main.go | dot -Tsvg  >| test.svg
// go run main.go | dot -Tsvg  >| $(date +"%a%d%b%Y_%H.%M.%S").svg

func main() {

	//wantedDomain := "adblock-data.brave.com"
	wantedDomain := "mail.google.com"
	queryType := dns.TypeA

	root := getRandomRootDNS()
	g := dot.NewGraph(dot.Directed)
	g.Attr("label", wantedDomain+" DNS Trust Graph")
	g.Attr("labelloc", "t")
	g.Attr("pad", "3")
	g.Attr("nodesep", "1")
	g.Attr("ranksep", "5")
	g.Attr("fontsize", "50")
	g.Attr("concentrate", "true")

	zeroNode := g.Node(root)
	zeroNode.
		Attr("fillcolor", "blue").
		Attr("style", "filled").
		Attr("fontcolor", "white")

	{
		var res *dns.Msg
		var err error
		var authority string
		var authorityNode dot.Node
		var parentNode dot.Node

		authority = root
		parentNode = zeroNode

		for {
			debug("1:", authority, wantedDomain, queryType)
			res, err = Send(authority, wantedDomain, queryType)
			if err != nil {
				panic(err)
			}
			// given that we expect this call to get a non-authoritative answer,
			// let's extract the RR contained in the authority section:
			ns := getNS(res.Ns)

			// let's randomly choose the NS (from the authority list) for the next
			// query:
			authority = chooseRandomNS(ns).Ns

			// link all NS to parent:
			for _, auth := range ns {
				authorityNode = g.Node(auth.Ns)

				style := "dashed"
				//let's make it bold if the NS is gonna be used for the
				// next query:
				if auth.Ns == authority {
					style = "bold"
				}
				g.Edge(
					parentNode,
					authorityNode,
					rcodeLabel(wantedDomain, res.MsgHdr.Rcode),
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

			// let's send the query, and basically discard the response if it is nont authoritative
			// (`res` will be overwritten the the Send:1 in the next iteration of the loop):
			debug("2:", authority, wantedDomain, queryType)
			res, err = Send(authority, wantedDomain, queryType)
			if err != nil {
				panic(err)
			}
			parentNode = g.Node(authority)
			if !res.Authoritative {
				//fmt.Println(authority, "is not authoritative")
				continue
			} else {
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
						//TODO: add other types of RR
					}

				}
				resultNode := g.Node(content).Attr("style", "filled")
				g.Edge(
					parentNode,
					resultNode,
					rcodeLabel(wantedDomain, res.MsgHdr.Rcode),
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
					wantedDomain = cname.Target
					authority = root
					parentNode = resultNode
				} else {
					break
				}
			}
		}
	}

	//debug(g.String())
	fmt.Println(g.String())

	return
	di := dot.NewGraph(dot.Directed)
	outside := di.Node("Outside")

	// A
	clusterA := di.Subgraph("Cluster A", dot.ClusterOption{})
	insideOne := clusterA.Node("one")
	insideTwo := clusterA.Node("two")

	// B
	clusterB := di.Subgraph("Cluster B", dot.ClusterOption{})
	insideThree := clusterB.Node("three")
	insideFour := clusterB.Node("four")

	// edges
	outside.
		Edge(insideFour).
		Edge(insideOne).
		Edge(insideTwo).
		Edge(insideThree).
		Edge(outside)

	fmt.Println(di.String())
	return

	g = dot.NewGraph(dot.Directed)
	n1 := g.Node("coding")
	n2 := g.Node("testing a little").Box()

	g.Edge(n1, n2)
	g.Edge(n2, n1, "back", "forth", "whatever").Attr("color", "red")

	fmt.Println(g.String())
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

func getNS(nsRR []dns.RR) []*dns.NS {
	var ns []*dns.NS
	for _, a := range nsRR {
		if _, ok := a.(*dns.NS); ok {
			ns = append(ns, a.(*dns.NS))
		}
	}
	return ns
}
func chooseRandomNS(ns []*dns.NS) *dns.NS {
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

func rcodeLabel(domain string, rcode int) string {
	return fmt.Sprintf(
		//`<<I>` + domain + `?</I><BR/><FONT point-size="10">` + dns.RcodeToString[rcode] + `</FONT>>`,
		"%s -> %s",
		dns.Fqdn(domain),
		dns.RcodeToString[rcode],
	)
}
