package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
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
		"ticonsultores.biz.ni",
		"adblock-data.brave.com",
		"mail.google.com",
		"example.com",
		"ledger.brave.com",
	}
	generateGraphsFor(targets[4])
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

var (
	registry = map[string]bool{}
	mu       *sync.RWMutex
)

func init() {
	mu = &sync.RWMutex{}
}

func Has(id string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, has := registry[id]
	return has
}

func Add(id string) {
	mu.Lock()
	defer mu.Unlock()
	registry[id] = true
}

func goExplore(
	g *dot.Graph,
	parentNode dot.Node,
	authority string,
	target string,
	queryType uint16,
) {
	debugf(
		"query: authority:%q, target:%q, queryType:%q\n",
		authority,
		target,
		dns.TypeToString[queryType],
	)

	// send the query and get the response:
	res, err := Send(authority, target, queryType)
	if err != nil {
		if isErrNoSuchHost(err) {
			debugf("	%q: no such host\n", authority)
			addErrorNode(g, parentNode, authority, "no such host")
			return
		} else {
			panic(err)
		}
	}

	hasNextAuthority := len(res.Ns) > 0
	debugf(
		"	answer: isAuthoritative:%v, hasNextAuthority:%v\n",
		res.Authoritative,
		hasNextAuthority,
	)
	if !res.Authoritative && hasNextAuthority {
		// given that we expect this call to get a non-authoritative answer,
		// let's extract the RR contained in the authority section:
		nextAuthorities := extractNS(res.Ns)

		for authIndex := range nextAuthorities {
			style := "dashed"
			auth := nextAuthorities[authIndex]
			//let's make it bold if the NS is gonna be used for the
			// next query:
			authorityNode := g.Node(auth.Ns)

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

			id := fmt.Sprintf("%v:%v", auth.Ns, target)

			if !Has(id) {
				Add(id)
				goExplore(g, authorityNode, auth.Ns, target, queryType)
			}
		}

		return
	}

	noSuggestedNextAuthorities := hasNextAuthority == false
	if !res.Authoritative && noSuggestedNextAuthorities {
		debug(authority, "is not authoritative, but does not suggest who could be")
		// dead end:
		addErrorNode(g, parentNode, "DEAD END", authority+"is not authoritative, but does not suggest who could be next")
		debug(spew.Sdump(res.Answer))
		// TODO: show eventual A or AAAA or CNAME records (i.e. non-authoritative answers)
		return
	}

	if res.Authoritative {
		parentNode.
			Attr("style", "filled").
			Attr("fillcolor", "#0099ff")

		var content string

		Arecords := extractA(res.Answer)
		AAAArecords := extractAAAA(res.Answer)
		CNAMErecords := extractCNAME(res.Answer)

		adder := func(label string, val interface{}) string {
			return fmt.Sprintf(
				"[%s]%v\n",
				label,
				val,
			)
		}

		for _, v := range Arecords {
			content += adder("A", v.A)
		}
		for _, v := range AAAArecords {
			content += adder("AAAA", v.AAAA)
		}
		for _, v := range CNAMErecords {
			content += adder("CNAME", v.Target)
		}

		resultNode := g.Node(content).
			Attr("style", "filled")

		if len(CNAMErecords) == 0 {
			resultNode.
				Attr("fillcolor", "#00FF1F")
		}

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
			debug("	cname:", cname.Target)

			exists, err := DomainExists(cname.Target)
			if err != nil {
				panic(err)
			}
			if exists {
				resultNode.
					Attr("fillcolor", "#00FF1F")
			} else {
				resultNode.
					Attr("fillcolor", "#FF1000")
			}

			target = cname.Target
			authority = rootNS
			parentNode = resultNode

			goExplore(g, parentNode, authority, target, queryType)
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

var (
	dnsClient = new(dns.Client)
)

func Send(server string, domain string, t uint16) (*dns.Msg, error) {
	m := new(dns.Msg)

	m.SetQuestion(dns.Fqdn(domain), t)

	// VERY IMPORTANT:
	m.RecursionDesired = true
	// NOTE: does not work in Italy (via VPN); the result returns directly the A and CNAME records even if asking the root servers.
	// NOTE: works in NL (via VPN).

	r, _, err := dnsClient.Exchange(m, stripFinalDot(server)+":"+"53")
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

func extractNS(nsRR []dns.RR) []*dns.NS {
	var ns []*dns.NS
	for _, a := range nsRR {
		if _, ok := a.(*dns.NS); ok {
			ns = append(ns, a.(*dns.NS))
		}
	}

	sort.Slice(ns, func(i, j int) bool {
		return ns[i].Ns < ns[j].Ns
	})
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

func extractA(rr []dns.RR) []*dns.A {
	var Arecords []*dns.A
	for i := range rr {
		a := rr[i]
		if _, ok := a.(*dns.A); ok {
			Arecords = append(Arecords, a.(*dns.A))
		}
	}

	sort.Slice(Arecords, func(i, j int) bool {
		return bytes.Compare(Arecords[i].A, Arecords[j].A) < 0
	})
	return Arecords
}
func extractAAAA(rr []dns.RR) []*dns.AAAA {
	var AAAArecords []*dns.AAAA
	for i := range rr {
		a := rr[i]
		if _, ok := a.(*dns.AAAA); ok {
			AAAArecords = append(AAAArecords, a.(*dns.AAAA))
		}
	}

	sort.Slice(AAAArecords, func(i, j int) bool {
		return bytes.Compare(AAAArecords[i].AAAA, AAAArecords[j].AAAA) < 0
	})
	return AAAArecords
}
func extractCNAME(rr []dns.RR) []*dns.CNAME {
	var cname []*dns.CNAME
	for i := range rr {
		a := rr[i]
		if _, ok := a.(*dns.CNAME); ok {
			cname = append(cname, a.(*dns.CNAME))
		}
	}
	return cname
}

//  DomainExists tries to resolve the domains.
func DomainExists(domain string) (bool, error) {

	ips, err := net.LookupHost(domain)
	if err != nil {
		if isErrNoSuchHost(err) {
			return false, nil
		}
		return false, err
	}
	if len(ips) == 0 {
		return false, nil
	}

	return true, nil
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
