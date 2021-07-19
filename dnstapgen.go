package main

import (
	"bufio"
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

func RandomInt(min int, max int) int {
	return (rand.Intn(max-min+1) + min)
}

func RandomItoa(min int, max int) string {
	num := (rand.Intn(max-min+1) + min)
	return strconv.Itoa(num)
}

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[RandomInt(1, len(letters)-1)]
	}
	return string(s)
}

func GenerateDnsQuestion() ([]byte, []byte) {
	dnsmsg := new(dns.Msg)

	domain := RandomString(2)
	qtype := DNSTYPE[RandomInt(0, 3)]

	fqdn := fmt.Sprintf("%s.%s.", domain, TLD[RandomInt(0, 3)])

	dnsmsg.SetQuestion(fqdn, qtype)

	dnsquestion, err := dnsmsg.Pack()
	if err != nil {
		log.Fatalf("dns question pack error %s", err)
	}

	rr, err := dns.NewRR(fmt.Sprintf("%s %s 127.0.0.1", fqdn, DNSTYPE_STR[qtype]))
	if err == nil {
		dnsmsg.Answer = append(dnsmsg.Answer, rr)
	}
	dnsanswer, err := dnsmsg.Pack()
	if err != nil {
		log.Fatalf("dns answer pack error %s", err)
	}

	return dnsquestion, dnsanswer
}

func GenerateDnstap(dnsquery []byte, dnsreply []byte) (*dnstap.Dnstap, *dnstap.Dnstap) {

	//prepare dnstap query
	dt_query := &dnstap.Dnstap{}

	t := dnstap.Dnstap_MESSAGE
	dt_query.Identity = []byte("dnstap-generator")
	dt_query.Version = []byte("-")
	dt_query.Type = &t

	now := time.Now()
	mt := dnstap.Message_CLIENT_QUERY
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
	mt_reply := dnstap.Message_CLIENT_RESPONSE

	tsec_reply := uint64(now_reply.Unix())
	tnsec_reply := uint32(uint64(now_reply.UnixNano()) - uint64(now_reply.Unix())*1e9)

	msg_reply := &dnstap.Message{Type: &mt_reply}
	msg_reply.SocketFamily = &sf
	msg_reply.SocketProtocol = &sp
	msg_reply.QueryAddress = net.ParseIP(queryIp)
	msg_reply.QueryPort = &qport
	msg_reply.ResponseAddress = net.ParseIP(responseIp)
	msg_reply.ResponsePort = &rport

	msg_reply.QueryMessage = dnsreply
	msg_reply.QueryTimeSec = &tsec_reply
	msg_reply.QueryTimeNsec = &tnsec_reply

	dt_reply.Message = msg_reply

	return dt_query, dt_reply
}

func Generator(wg *sync.WaitGroup, remoteIp *string, remotePort *int, numPacket *int) {
	defer wg.Done()

	// connect
	remoteAddr := fmt.Sprintf("%s:%d", *remoteIp, *remotePort)
	conn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Fatalf("error: %s", err)
	}
	if conn != nil {
		fmt.Println("success - connected")

		// frame stream library
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
		if err := fs.InitSender(); err != nil {
			log.Fatalf("framestream init error: %s", err)
		} else {
			fmt.Println("framestream init success")

			frame := &framestream.Frame{}

			for i := 1; i <= *numPacket; i++ {

				// generate dns message
				dnsquery, dnsreply := GenerateDnsQuestion()
				if err != nil {
					log.Fatalf("dns pack error %s", err)
				}

				// generate dnstap message
				_, dtreply := GenerateDnstap(dnsquery, dnsreply)

				// serialize to byte
				data, err := proto.Marshal(dtreply)
				if err != nil {
					log.Fatalf("dnstap proto marshal error %s", err)
				}

				// send
				frame.Write(data)
				if err := fs.SendFrame(frame); err != nil {
					log.Fatalf("send frame error %s", err)
				}

				// serialize to byte
				//data, err = proto.Marshal(dtreply)
				//if err != nil {
				//	log.Fatalf("dnstap proto marshal error %s", err)
				//}

				// send
				//frame.Write(data)
				//if err := fs.SendFrame(frame); err != nil {
				//	log.Fatalf("send frame error %s", err)
				//}

			}

		}

		fmt.Printf("number of packet to send: %d\n", *numPacket)
		conn.Close()
		fmt.Println("closed")
	}
}
func main() {

	rand.Seed(time.Now().UnixNano())

	var numPacket = flag.Int("n", 1, "number of dnstap message to send")
	var numConn = flag.Int("c", 1, "number of connection")
	var remoteIp = flag.String("i", "127.0.0.1", "remote address of the dnstap receiver")
	var remotePort = flag.Int("p", 6000, "remote port of the dnstap receiver")

	// Handle command-line arguments.
	flag.Parse()

	var wg sync.WaitGroup
	for i := 1; i <= *numConn; i++ {
		wg.Add(1)
		go Generator(&wg, remoteIp, remotePort, numPacket)
	}
	wg.Wait()

	fmt.Println("terminated")
}
