package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass"
	amassutils "github.com/OWASP/Amass/amass/utils"

	"github.com/emicklei/dot"
	. "github.com/gagliardetto/utils"
	"github.com/miekg/dns"
	"gopkg.in/pipe.v2"
)

// cd $GOPATH/src/github.com/d1ss0lv3/trust-trees-go
// go run main.go | dot -Tsvg  >| test.svg
// go run main.go | dot -Tsvg  >| generated/$(date +"%a%d%b%Y_%H.%M.%S").svg

var (
	// rootNS is the default (choosen randomly at startup) root NS
	// used all throughout the execution of this program:
	rootNS = getRandomRootDNS()
	// defaultDotComNS is the default NS used for the resolution of
	// .com domains:
	defaultDotComNS = getRandomDotComDNS()
)

const (
	// defaultDir is the default directory name where the
	// generated graphs will be saved to
	defaultDir    = "generated"
	asnTimeFormat = "Mon02Jan2006"
)
const (
	colorRed       = "#FF1000"
	colorGreen     = "#08CF20"
	colorSecondary = "#00710D"
	colorASN       = "#FF00DF"
)
const (
	// LevelTargetOnly means only the primary target will be explored.
	LevelTargetOnly = 1
	// LevelSecond means that the DNS of the primary target will become
	// secondary targets, and they will also be explored.
	LevelSecond = 2
)

var (
	// outputDir is the directory that will contain all the generated graphs
	outputDir string
)

// options:
var (
	// useOnlyDefaultNSForDotCom tells whether to use only one
	// default DNS for the resolution of .com domains.
	useOnlyDefaultNSForDotCom = true
	// explorationLevels tells whether to explore the paths to the
	// target host, or also explore the paths to the DNS of the target
	// (which means the DNS of the primary target become the secondary
	// targets)
	explorationLevels = LevelTargetOnly
)

func main() {

	targetFile := flag.String("f", "", "/path/to/domain/list.txt")
	ptrOutputDir := flag.String("oF", defaultDir, "/path/to/output/folder")
	goDeeper := flag.Bool("deeper", false, "also traverse the NS of the target as additional targets")
	ptrUseDefaultNsForCom := flag.Bool("one-com", true, "use only one default *.gtld-servers.net. NS (authoritative for com.) to avoid noise")
	flag.Parse()

	if goDeeper != nil && *goDeeper {
		explorationLevels = LevelSecond
	}

	if ptrUseDefaultNsForCom != nil {
		useOnlyDefaultNSForDotCom = *ptrUseDefaultNsForCom
	}

	// targets contains the list of target domains (sourced from the cli args and from list file)
	var targets []string
	targets = amassutils.UniqueAppend(targets, flag.Args()...)

	{
		// create output folder (if not exists):
		outputDir = *ptrOutputDir
		err := CreateFolderIfNotExists(outputDir, 0640)
		if err != nil {
			panic(err)
		}
	}

	{
		// add targets from file:
		if targetFile != nil && *targetFile != "" {
			err := ReadFileLinesAsString(*targetFile, func(target string) bool {
				targets = amassutils.UniqueAppend(targets, target)
				return true
			})
			if err != nil {
				panic(err)
			}
		}
	}

	generateGraphsFor(targets...)

	bellSound()
}

func bellSound() {
	fmt.Print("\007")
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
	registryOfFollowedPaths = map[string]bool{}
	registryOfNameServers = map[string]bool{}

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

		explore(gph, parentNode, authority, target, queryType, false)
	}

	{
		if explorationLevels > LevelTargetOnly {
			// skip root and .com ns
			skip := func(targetNS string) bool {
				return strings.HasSuffix(targetNS, ".gtld-servers.net.") || strings.HasSuffix(targetNS, ".root-servers.net.")
			}
			{
				debugf(
					"\nstarting graphing secondary targets:\n",
				)
				for secondaryTarget := range registryOfNameServers {
					if !skip(secondaryTarget) {
						debug(secondaryTarget)
					}
				}
				debug("\n")
			}
			var authority string
			var parentNode dot.Node

			authority = rootNS
			parentNode = zeroNode

			for targetNS := range registryOfNameServers {
				if !skip(targetNS) {
					explore(gph, parentNode, authority, targetNS, queryType, true)
				}
			}
		}
	}

	// save graphs in the "./generated" folder
	dir := "generated"

	// file format
	fileFormat := "svg"
	// format filename and destination:
	file := SanitizeFileNamePart(fmt.Sprintf(
		"%s-%s.%s",
		target,
		time.Now().Format(FilenameTimeFormat),
		fileFormat,
	))
	path := filepath.Join(dir, file)

	debugf(
		"generating graph for %q...",
		target,
	)
	// pipeline the dot graph, image data, to final file:
	p := pipe.Line(
		pipe.Print(gph.String()),
		pipe.Exec("dot", "-T"+fileFormat),
		pipe.WriteFile(path, 0640),
	)
	err := pipe.Run(p)
	if err != nil {
		return err
	}

	debugf(
		Lime("finished %q (saved to %s)\n\n"),
		target,
		path,
	)
	return nil
}

var (
	queryNum                int
	registryOfFollowedPaths = map[string]bool{}
	registryOfNameServers   = map[string]bool{}
	mu                      *sync.RWMutex
)

func init() {
	mu = &sync.RWMutex{}
}

func AlreadyFollowed(id string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, has := registryOfFollowedPaths[id]
	return has
}

func MarkAsFollowed(id string) {
	mu.Lock()
	defer mu.Unlock()
	registryOfFollowedPaths[id] = true
}
func constantTwoDigitSpace(i int) string {
	if i < 10 {
		return "0" + fmt.Sprint(i)
	}
	return fmt.Sprint(i)
}
func explore(
	g *dot.Graph,
	parentNode dot.Node,
	authority string,
	target string,
	queryType uint16,
	isSecondary bool,
) {
	registryOfNameServers[authority] = true
	debugf(
		"query#%v: authority:%q, target:%q",
		constantTwoDigitSpace(queryNum),
		authority,
		target,
	)
	queryNum++

	// send the query and get the response:
	res, err := Send(authority, target, queryType)
	if err != nil {

		if isErrNoSuchHost(err) {
			debugf(Red("	  %q: no such host: %v"), authority, err)
			addErrorNode(g, parentNode, authority, "NO SUCH HOST")
			return
		} else if isErrIOTimeout(err) {
			debugf(Red("	  %q: I/O timeout: %v"), authority, err)
			addErrorNode(g, parentNode, authority, "TIMEOUT")
			return
		} else {
			panic(err)
		}
	}

	hasNextAuthority := len(res.Ns) > 0
	debugf(
		"	  answer: isAuthoritative:%v, hasNextAuthority:%v",
		res.Authoritative,
		hasNextAuthority,
	)
	if !res.Authoritative && hasNextAuthority {
		nextAuthorities := extractNS(res.Ns)

		for authIndex := range nextAuthorities {
			auth := nextAuthorities[authIndex]

			isCom := strings.HasSuffix(auth.Ns, ".gtld-servers.net.")
			skipThis := isCom && auth.Ns != defaultDotComNS
			if useOnlyDefaultNSForDotCom && skipThis {
				continue
			}

			style := "dashed"
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

			pathID := fmt.Sprintf("%v:%v", auth.Ns, target)

			if !AlreadyFollowed(pathID) {
				MarkAsFollowed(pathID)
				explore(g, authorityNode, auth.Ns, target, queryType, isSecondary)
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
	const colorAuthoritative = "#0099ff"
	const colorNOTAuthoritative = "#FF8A00"
	if res.Authoritative {
		colorAuthoritativeOrNot = colorAuthoritative
	} else {
		colorAuthoritativeOrNot = colorNOTAuthoritative
	}
	parentNode.
		Attr("style", "filled").
		Attr("fillcolor", colorAuthoritativeOrNot)

	Arecords := extractA(res.Answer)
	AAAArecords := extractAAAA(res.Answer)
	CNAMErecords := extractCNAME(res.Answer)

	noResults := len(Arecords) == 0 && len(AAAArecords) == 0 && len(CNAMErecords) == 0

	rrFormatter := func(label string, val interface{}) string {
		return fmt.Sprintf(
			"[%s]%v\n",
			label,
			val,
		)
	}

	if noResults {
		emptyNodeText := "EMPTY"
		emptyResultNode := g.
			Node(emptyNodeText).
			Attr("style", "filled").
			Attr("fillcolor", colorRed)

		rrEdge(g,
			parentNode,
			emptyResultNode,
			rcodeLabel(target, res.MsgHdr.Rcode),
			colorAuthoritativeOrNot,
			RcodeToColor[res.MsgHdr.Rcode],
		)

	} else {

		for _, v := range Arecords {

			fillcolor := colorGreen
			if isSecondary {
				fillcolor = colorSecondary
			}
			AresultNode := g.
				Node(rrFormatter("A", v.A)).
				Attr("style", "filled").
				Attr("fillcolor", fillcolor)

			debug("	  A:", v.A)

			rrEdge(g,
				parentNode,
				AresultNode,
				rcodeLabel(target, res.MsgHdr.Rcode),
				colorAuthoritativeOrNot,
				RcodeToColor[res.MsgHdr.Rcode],
			)

			formatASN := func(asnInfo *amass.ASRecord) string {
				return Sf(
					"AS %s (%s)\nDESC: %s\nREGISTRY: %s\nALLOC: %s",
					strconv.Itoa(asnInfo.ASN),
					asnInfo.CC,
					asnInfo.Description,
					asnInfo.Registry,
					asnInfo.AllocationDate.Format(asnTimeFormat),
					//asnInfo.Netblocks,
				)
			}
			asn, cidr, _, err := amass.IPRequest(v.A.String())
			if err != nil {
				debugf(Red("	  %q: error getting IP info: %v"), v.A.String(), err)
			} else {

				cidrNode := g.
					Node(Sf("CIDR:%s", cidr.String())).
					Attr("style", "filled").
					Attr("fillcolor", colorASN)

				rrEdge(g,
					AresultNode,
					cidrNode,
					"",
					"grey",
					"white",
				)

				asnInfo, err := amass.ASNRequest(asn)
				if err != nil {
					debugf(Red("	  %q: error getting ASN info: %v"), v.A.String(), err)
				} else {

					ASNinfoNode := g.
						Node(formatASN(asnInfo)).
						Attr("style", "filled").
						Attr("fillcolor", colorASN)

					rrEdge(g,
						cidrNode,
						ASNinfoNode,
						"",
						"grey",
						"white",
					)
				}
			}
		}
		for _, v := range AAAArecords {
			AAAAresultNode := g.
				Node(rrFormatter("AAAA", v.AAAA)).
				Attr("style", "filled").
				Attr("fillcolor", colorGreen)

			debug("	  AAAA:", v.AAAA)

			rrEdge(g,
				parentNode,
				AAAAresultNode,
				rcodeLabel(target, res.MsgHdr.Rcode),
				colorAuthoritativeOrNot,
				RcodeToColor[res.MsgHdr.Rcode],
			)
		}
		for _, v := range CNAMErecords {
			CNAMEresultNode := g.
				Node(rrFormatter("CNAME", v.Target)).
				Attr("style", "filled")

			rrEdge(g,
				parentNode,
				CNAMEresultNode,
				rcodeLabel(target, res.MsgHdr.Rcode),
				colorAuthoritativeOrNot,
				RcodeToColor[res.MsgHdr.Rcode],
			)

			debug("	  CNAME:", v.Target)

			exists, err := DomainExists(v.Target)
			if err != nil {
				panic(err)
			}
			if exists {
				CNAMEresultNode.
					Attr("fillcolor", colorGreen)
			} else {
				CNAMEresultNode.
					Attr("fillcolor", colorRed)
			}

			target = v.Target
			authority = rootNS
			parentNode = CNAMEresultNode

			explore(g, parentNode, authority, target, queryType, isSecondary)
		}

	}
}

func rrEdge(
	gph *dot.Graph,
	parent dot.Node,
	child dot.Node,
	label string,
	color string,
	fontcolor string,
) {

	gph.Edge(
		parent,
		child,
		label,
	).
		Attr("arrowhead", "vee").
		Attr("arrowtail", "inv").
		Attr("arrowsize", ".7").
		Attr("color", color).
		//
		Attr("fontname", "bold").
		Attr("fontsize", "7.0").
		Attr("style", "bold").
		Attr("fontcolor", fontcolor)
}

func addErrorNode(g *dot.Graph, parentNode dot.Node, content string, label string) {
	errorNode := g.Node(content).
		Attr("style", "filled").
		Attr("fillcolor", colorRed)

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
		Attr("fontcolor", colorRed)
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

	var dnsReply *dns.Msg
	errs := Retry(3, time.Second, func() error {
		var err error
		dnsReply, _, err = dnsClient.Exchange(m, stripFinalDot(server)+":"+"53")
		return err
	})
	if errs != nil {
		return nil, fmt.Errorf("errors while exchanging DNS message:\n%s", formatErrorArray("	    ", errs))
	}
	return dnsReply, nil
}
func formatErrorArray(prefix string, errs []error) string {
	var res string
	for i, err := range errs {
		isLast := i == len(errs)-1

		newline := "\n"
		if isLast {
			newline = ""
		}
		res += Sf(
			"%s%v: %s%s",
			prefix,
			i+1,
			err,
			newline,
		)
	}
	return res
}

// Retry executes task; if it returns an error, it will retry executing the task the specified number of times before giving up.
func Retry(attempts int, sleep time.Duration, task func() error) []error {
	var errs []error
	for i := 1; i <= attempts; i++ {
		err := task()
		if err == nil {
			return nil
		}
		errs = append(errs, err)
		time.Sleep(sleep)
	}
	return errs
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
func getRandomDotComDNS() string {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		panic(err)
	}
	_ = config
	rootResolver := config.Servers[0]

	rootDomain := "com."

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
	dns.RcodeSuccess:        colorGreen,
	dns.RcodeFormatError:    "orange",
	dns.RcodeServerFailure:  colorRed,
	dns.RcodeNameError:      colorRed, // TODO: maybe use another color to distinguish from dns.RcodeServerFailure?
	dns.RcodeNotImplemented: colorRed,
	dns.RcodeRefused:        colorRed,
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
