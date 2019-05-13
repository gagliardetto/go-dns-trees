package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/emicklei/dot"
	"github.com/gagliardetto/utils"
	"github.com/miekg/dns"
	"gopkg.in/pipe.v2"
)

// cd $GOPATH/src/github.com/d1ss0lv3/trust-trees-go
// go run main.go | dot -Tsvg  >| test.svg
// go run main.go | dot -Tsvg  >| generated/$(date +"%a%d%b%Y_%H.%M.%S").svg

var rootNS = getRandomRootDNS()

const (
	defaultDir = "generated"
)

var (
	outputDir string
)

func main() {
	targetFile := flag.String("tF", "", "/path/to/domain/list.txt")
	outputFolder := flag.String("of", defaultDir, "/path/to/output/folder")
	flag.Parse()

	// targets contains the list of target domains (sourced from the cli args and from list file)
	targets := flag.Args()

	{
		// create output folder (if not exists):
		outputDir = *outputFolder
		err := utils.CreateFolderIfNotExists(outputDir, 0640)
		if err != nil {
			panic(err)
		}
	}

	{
		// add targets from file:
		if targetFile != nil && *targetFile != "" {
			err := utils.ReadFileLinesAsString(*targetFile, func(target string) bool {
				targets = append(targets, target)
				return true
			})
			if err != nil {
				panic(err)
			}
		}
	}

	// args:
	// just nothing
	// --dF=/path/to/domain/list.txt
	// --folder=/path/to/output/folder
	targets1 := []string{
		"vapi.uber.com",
		"ticonsultores.biz.ni",
		"adblock-data.brave.com",
		"mail.google.com",
		"example.com",
		"ledger.brave.com",
	}
	targets2 := []string{
		"io.",
		"com.",
	}
	_ = targets1
	_ = targets2
	generateGraphsFor(targets...)
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
	debugf(
		"starting graphing %q...",
		target,
	)
	queryNum = 1
	registry = map[string]bool{}

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

	// time format for the filename:
	timeFormat := "Mon02Jan2006_15.04.05"

	// save graphs in the "./generated" folder
	dir := "generated"
	// format filename and destination:
	file := sanitizeFileNamePart(fmt.Sprintf("%s-%s.svg", target, time.Now().Format(timeFormat)))
	path := filepath.Join(dir, file)

	debugf(
		"generating graph for %q...",
		target,
	)
	// pipeline the dot file, svg, to final file:
	p := pipe.Line(
		pipe.Print(gph.String()),
		pipe.Exec("dot", "-Tsvg"),
		pipe.WriteFile(path, 0640),
	)
	err := pipe.Run(p)
	if err != nil {
		return err
	}

	debugf(
		"finished %q (saved to %s)\n\n",
		target,
		path,
	)
	return nil
}

var illegalFileNameCharacters = regexp.MustCompile(`[^[a-zA-Z0-9]-_]`)

func sanitizeFileNamePart(part string) string {
	part = strings.Replace(part, "/", "-", -1)
	part = illegalFileNameCharacters.ReplaceAllString(part, "")
	return part
}

var (
	queryNum int
	registry = map[string]bool{}
	mu       *sync.RWMutex
)

func init() {
	mu = &sync.RWMutex{}
}

func AlreadyFollowed(id string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, has := registry[id]
	return has
}

func MarkAsFollowed(id string) {
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
		"query#%v: authority:%q, target:%q",
		queryNum,
		authority,
		target,
	)
	queryNum++

	// send the query and get the response:
	res, err := Send(authority, target, queryType)
	if err != nil {
		if isErrNoSuchHost(err) {
			debugf("	%q: no such host: %v", authority, err)
			addErrorNode(g, parentNode, authority, "NO SUCH HOST")
			return
		} else if isErrIOTimeout(err) {
			debugf("	%q: I/O timeout: %v", authority, err)
			addErrorNode(g, parentNode, authority, "TIMEOUT")
			return
		} else {
			panic(err)
		}
	}

	hasNextAuthority := len(res.Ns) > 0
	debugf(
		"	 answer: isAuthoritative:%v, hasNextAuthority:%v",
		res.Authoritative,
		hasNextAuthority,
	)
	if !res.Authoritative && hasNextAuthority {
		// given that we expect this call to get a non-authoritative answer,
		// let's extract the RR contained in the authority section:
		nextAuthorities := extractNS(res.Ns)

		for authIndex := range nextAuthorities {
			auth := nextAuthorities[authIndex]
			style := "dashed"
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

			if !AlreadyFollowed(id) {
				MarkAsFollowed(id)
				goExplore(g, authorityNode, auth.Ns, target, queryType)
			}
		}

		return
	}

	noSuggestedNextAuthorities := hasNextAuthority == false
	if !res.Authoritative && noSuggestedNextAuthorities {
		//debug("	 %sis not authoritative, but does not suggest who could be", authority)
		// dead end:
		addErrorNode(g, parentNode, "DEAD END", authority+"is not authoritative, but does not suggest who could be next")
		//debug(spew.Sdump(res.Answer))
		// TODO: show eventual A or AAAA or CNAME records (i.e. non-authoritative answers)
		//return
	}

	var colorAuthoritativeOrNot string
	if res.Authoritative {
		colorAuthoritativeOrNot = "#0099ff"
	} else {
		colorAuthoritativeOrNot = "#FF8A00"
	}
	parentNode.
		Attr("style", "filled").
		Attr("fillcolor", colorAuthoritativeOrNot)

	Arecords := extractA(res.Answer)
	AAAArecords := extractAAAA(res.Answer)
	CNAMErecords := extractCNAME(res.Answer)

	noResults := len(Arecords) == 0 && len(AAAArecords) == 0 && len(CNAMErecords) == 0

	adder := func(label string, val interface{}) string {
		return fmt.Sprintf(
			"[%s]%v\n",
			label,
			val,
		)
	}

	if noResults {
		emptyResultNode := g.
			Node("EMPTY").
			Attr("style", "filled").
			Attr("fillcolor", "#FF1000")

		g.Edge(
			parentNode,
			emptyResultNode,
			rcodeLabel(target, res.MsgHdr.Rcode),
		).
			Attr("arrowhead", "vee").
			Attr("arrowtail", "inv").
			Attr("arrowsize", ".7").
			Attr("color", colorAuthoritativeOrNot).
			//
			Attr("fontname", "bold").
			Attr("fontsize", "7.0").
			Attr("style", "bold").
			Attr("fontcolor", RcodeToColor[res.MsgHdr.Rcode])
	} else {

		for _, v := range Arecords {
			AresultNode := g.
				Node(adder("A", v.A)).
				Attr("style", "filled").
				Attr("fillcolor", "#00FF1F")

			g.Edge(
				parentNode,
				AresultNode,
				rcodeLabel(target, res.MsgHdr.Rcode),
			).
				Attr("arrowhead", "vee").
				Attr("arrowtail", "inv").
				Attr("arrowsize", ".7").
				Attr("color", colorAuthoritativeOrNot).
				//
				Attr("fontname", "bold").
				Attr("fontsize", "7.0").
				Attr("style", "bold").
				Attr("fontcolor", RcodeToColor[res.MsgHdr.Rcode])
		}
		for _, v := range AAAArecords {
			AAAAresultNode := g.
				Node(adder("AAAA", v.AAAA)).
				Attr("style", "filled").
				Attr("fillcolor", "#00FF1F")

			g.Edge(
				parentNode,
				AAAAresultNode,
				rcodeLabel(target, res.MsgHdr.Rcode),
			).
				Attr("arrowhead", "vee").
				Attr("arrowtail", "inv").
				Attr("arrowsize", ".7").
				Attr("color", colorAuthoritativeOrNot).
				//
				Attr("fontname", "bold").
				Attr("fontsize", "7.0").
				Attr("style", "bold").
				Attr("fontcolor", RcodeToColor[res.MsgHdr.Rcode])
		}
		for _, v := range CNAMErecords {
			CNAMEresultNode := g.
				Node(adder("CNAME", v.Target)).
				Attr("style", "filled")

			g.Edge(
				parentNode,
				CNAMEresultNode,
				rcodeLabel(target, res.MsgHdr.Rcode),
			).
				Attr("arrowhead", "vee").
				Attr("arrowtail", "inv").
				Attr("arrowsize", ".7").
				Attr("color", colorAuthoritativeOrNot).
				//
				Attr("fontname", "bold").
				Attr("fontsize", "7.0").
				Attr("style", "bold").
				Attr("fontcolor", RcodeToColor[res.MsgHdr.Rcode])

			debug("	cname:", v.Target)

			exists, err := DomainExists(v.Target)
			if err != nil {
				panic(err)
			}
			if exists {
				CNAMEresultNode.
					Attr("fillcolor", "#00FF1F")
			} else {
				CNAMEresultNode.
					Attr("fillcolor", "#FF1000")
			}

			target = v.Target
			authority = rootNS
			parentNode = CNAMEresultNode

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
func isErrIOTimeout(e error) bool {
	return strings.Contains(e.Error(), "i/o timeout")
}
func stripFinalDot(s string) string {
	return strings.TrimSuffix(s, ".")
}

var (
	dnsClient = dns.Client{
		DialTimeout: time.Second * 10,
	}
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
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, a...))
}

func rcodeLabel(domain string, rcode int) string {
	return fmt.Sprintf(
		//`<<I>` + domain + `?</I><BR/><FONT point-size="10">` + dns.RcodeToString[rcode] + `</FONT>>`,
		"%s -> %s",
		dns.Fqdn(domain),
		dns.RcodeToString[rcode],
	)
}
