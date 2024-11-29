package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-framestream"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

var SF = map[int]dnstap.SocketFamily{
	0: dnstap.SocketFamily_INET,
	1: dnstap.SocketFamily_INET6,
}

var SP = map[int]dnstap.SocketProtocol{
	0: dnstap.SocketProtocol_UDP,
	1: dnstap.SocketProtocol_TCP,
	2: dnstap.SocketProtocol_DOH,
	3: dnstap.SocketProtocol_DOT,
}

var TLD = map[int]string{
	0: "com",
	1: "org",
	2: "fr",
	3: "eu",
}

var DNSTYPE = map[int]uint16{
	0: dns.TypeA,
	1: dns.TypeAAAA,
	2: dns.TypeTXT,
	3: dns.TypeCNAME,
}

var DNSTYPE_STR = map[uint16]string{
	dns.TypeA:     "A",
	dns.TypeAAAA:  "AAAA",
	dns.TypeTXT:   "TXT",
	dns.TypeCNAME: "CNAME",
}

var QTYPE_STR = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"TXT":   dns.TypeTXT,
	"CNAME": dns.TypeCNAME,
}

var DNSTYPE_VAL = map[uint16]string{
	dns.TypeA:     "127.0.0.1",
	dns.TypeAAAA:  "::1",
	dns.TypeTXT:   "dnstapgenerator",
	dns.TypeCNAME: "generator.dnstap",
}

var DTYPEQR = map[int]dnstap.Message_Type{
	0: dnstap.Message_CLIENT_QUERY,
	1: dnstap.Message_FORWARDER_QUERY,
	2: dnstap.Message_RESOLVER_QUERY,
	3: dnstap.Message_AUTH_QUERY,
}

var DTYPERP = map[int]dnstap.Message_Type{
	0: dnstap.Message_CLIENT_RESPONSE,
	1: dnstap.Message_FORWARDER_RESPONSE,
	2: dnstap.Message_RESOLVER_RESPONSE,
	3: dnstap.Message_AUTH_RESPONSE,
}

var RCODES = map[int]int{
	0: dns.RcodeSuccess,
	1: dns.RcodeServerFailure,
	2: dns.RcodeRefused,
	3: dns.RcodeNameError, //nxdomain
}

func RandomInt(min int, max int) int {
	return (rand.Intn(max-min+1) + min)
}

func RandomItoa(min int, max int) string {
	num := (rand.Intn(max-min+1) + min)
	return strconv.Itoa(num)
}

func RandomString(min int, max int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	n := RandomInt(min, max)

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[RandomInt(1, len(letters)-1)]
	}
	return string(s)
}

func GenerateDnsQuestion(domainMinLength *int, domainMaxLength *int, qname string, qtype string) ([]byte, []byte, error) {
	dnsmsg := new(dns.Msg)

	var targetQname string
	var targetQtype uint16
	var targetQtypeStr string

	if len(qname) > 0 {
		targetQname = qname
	} else {
		randDomain := RandomString(*domainMinLength, *domainMaxLength)
		targetQname = fmt.Sprintf("%s.%s.", randDomain, TLD[RandomInt(0, 3)])
	}

	if len(qname) > 0 {
		targetQtype = QTYPE_STR[qtype]
		targetQtypeStr = qtype
	} else {
		targetQtype = DNSTYPE[RandomInt(0, 3)]
		targetQtypeStr = DNSTYPE_STR[targetQtype]
	}

	dnsmsg.SetQuestion(targetQname, targetQtype)

	dnsquestion, err := dnsmsg.Pack()
	if err != nil {
		return nil, nil, errors.New("dns question pack error")
	}

	rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", targetQname, targetQtypeStr, DNSTYPE_VAL[targetQtype]))
	if err == nil {
		dnsmsg.Answer = append(dnsmsg.Answer, rr)
	}
	dnsmsg.Rcode = RCODES[RandomInt(0, 3)]
	dnsanswer, err := dnsmsg.Pack()
	if err != nil {
		return nil, nil, errors.New("dns answer pack error")
	}

	return dnsquestion, dnsanswer, nil
}

func GenerateDnstap(dnsquery []byte, dnsreply []byte) (*dnstap.Dnstap, *dnstap.Dnstap) {

	//prepare dnstap query
	dt_query := &dnstap.Dnstap{}

	t := dnstap.Dnstap_MESSAGE
	dt_query.Identity = []byte("dnstap-generator")
	dt_query.Version = []byte("-")
	dt_query.Type = &t

	mtId := RandomInt(0, 3)

	now := time.Now()
	mt := DTYPEQR[mtId]
	sf := SF[RandomInt(0, 1)]
	sp := SP[RandomInt(0, 3)]

	tsec := uint64(now.Unix())
	tnsec := uint32(uint64(now.UnixNano()) - uint64(now.Unix())*1e9)

	rport := uint32(53)
	qport := uint32(RandomInt(10000, 60000))

	var queryIp string
	var responseIp string
	if sf == dnstap.SocketFamily_INET {
		queryIp = "127.0." + RandomItoa(1, 250) + "." + RandomItoa(1, 250)
		responseIp = "127.0." + RandomItoa(1, 250) + "." + RandomItoa(1, 250)
	} else {
		queryIp = "2001:" + RandomItoa(1, 250) + "::" + RandomItoa(1, 250)
		responseIp = "2001:" + RandomItoa(1, 250) + "::" + RandomItoa(1, 250)
	}

	msg := &dnstap.Message{Type: &mt}
	msg.SocketFamily = &sf
	msg.SocketProtocol = &sp
	msg.QueryAddress = net.ParseIP(queryIp)
	msg.QueryPort = &qport
	msg.ResponseAddress = net.ParseIP(responseIp)
	msg.ResponsePort = &rport

	msg.QueryMessage = dnsquery
	msg.QueryTimeSec = &tsec
	msg.QueryTimeNsec = &tnsec

	dt_query.Message = msg

	//prepare dnstap reply
	dt_reply := &dnstap.Dnstap{}

	dt_reply.Identity = []byte("dnstap-generator")
	dt_reply.Version = []byte("-")
	dt_reply.Type = &t

	now_reply := time.Now()
	mt_reply := DTYPERP[mtId]

	tsec_reply := uint64(now_reply.Unix())
	tnsec_reply := uint32(uint64(now_reply.UnixNano()) - uint64(now_reply.Unix())*1e9)

	msg_reply := &dnstap.Message{Type: &mt_reply}
	msg_reply.SocketFamily = &sf
	msg_reply.SocketProtocol = &sp
	msg_reply.QueryAddress = net.ParseIP(queryIp)
	msg_reply.QueryPort = &qport
	msg_reply.ResponseAddress = net.ParseIP(responseIp)
	msg_reply.ResponsePort = &rport

	msg_reply.ResponseMessage = dnsreply
	msg_reply.ResponseTimeSec = &tsec_reply
	msg_reply.ResponseTimeNsec = &tnsec_reply

	dt_reply.Message = msg_reply

	return dt_query, dt_reply
}

func Generator(wg *sync.WaitGroup, transport string, remoteIp *string, remotePort *int, numPacket *int, domainMinLength *int, domainMaxLength *int, qname, qtype string, noQueries bool, noReplies bool) {
	defer wg.Done()

	// connect
	remoteAddr := fmt.Sprintf("%s:%d", *remoteIp, *remotePort)
	conn, err := net.Dial(transport, remoteAddr)
	if err != nil {
		log.Fatalf("error: %s", err)
	}
	if conn != nil {

		// frame stream library
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
		if err := fs.InitSender(); err != nil {
			log.Fatalf("framestream init error: %s", err)
		} else {

			frame := &framestream.Frame{}
			count := 0
			start := time.Now()
			fmt.Println("Sending dnstap packet to remote", remoteAddr)
			for i := 1; i <= *numPacket; i++ {

				// generate dns message
				dnsquery, dnsreply, err := GenerateDnsQuestion(domainMinLength, domainMaxLength, qname, qtype)
				if err != nil {
					log.Fatalf("dns pack error %s", err)
				}

				// generate dnstap message
				dtquery, dtreply := GenerateDnstap(dnsquery, dnsreply)

				if !noQueries {
					// serialize to byte
					data, err := proto.Marshal(dtquery)
					if err != nil {
						log.Fatalf("dnstap proto marshal error %s", err)
					}

					// send query
					frame.Write(data)
					if err := fs.SendFrame(frame); err != nil {
						log.Fatalf("send frame error %s", err)
					}
					count++
				}

				if !noReplies {
					// serialize to byte
					data, err := proto.Marshal(dtreply)
					if err != nil {
						log.Fatalf("dnstap proto marshal error %s", err)
					}

					// send reply
					frame.Write(data)
					if err := fs.SendFrame(frame); err != nil {
						log.Fatalf("send frame error %s", err)
					}
					count++
				}

			}

			duration := time.Since(start)

			// print stats
			pps := float64(count) / duration.Seconds()
			fmt.Println("=======")
			fmt.Println("duration:", duration)
			fmt.Println("packet sent:", count)
			fmt.Println("pps:", pps)
			fmt.Println("=======")
		}

		conn.Close()
	}
}

func main() {

	rand.New(rand.NewSource(time.Now().UnixNano()))

	var numPacket = flag.Int("n", 1, "number of dnstap message to send")
	var numConn = flag.Int("c", 1, "number of connection")
	var transport = flag.String("t", "tcp", "transport to use")
	var remoteIp = flag.String("i", "127.0.0.1", "remote address of the dnstap receiver")
	var remotePort = flag.Int("p", 6000, "remote port of the dnstap receiver")
	var domainMaxLength = flag.Int("dmax", 60, "maximum domain length")
	var domainMinLength = flag.Int("dmin", 10, "minimum domain length")
	var qname = flag.String("qname", "", "qname to use")
	var qtype = flag.String("qtype", "", "qtype to use")
	var noQueries = flag.Bool("noqueries", false, "don't send dnstap queries")
	var noReplies = flag.Bool("noreplies", false, "don't send dnstap replies")

	// Handle command-line arguments.
	flag.Parse()

	var wg sync.WaitGroup
	for i := 1; i <= *numConn; i++ {
		wg.Add(1)
		go Generator(&wg, *transport, remoteIp, remotePort, numPacket, domainMinLength, domainMaxLength, *qname, *qtype, *noQueries, *noReplies)
	}
	wg.Wait()

}
