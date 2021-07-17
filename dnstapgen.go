package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
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

func RandomInt(min int, max int) int {
	return (rand.Intn(max-min+1) + min)
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
	fqdn := fmt.Sprintf("%s.%s.", domain, TLD[RandomInt(0, 3)])
	dnsmsg.SetQuestion(fqdn, dns.TypeA)

	dnsquestion, err := dnsmsg.Pack()
	if err != nil {
		log.Fatalf("dns question pack error %s", err)
	}

	rr, err := dns.NewRR(fmt.Sprintf("%s A 127.0.0.1", fqdn))
	if err == nil {
		dnsmsg.Answer = append(dnsmsg.Answer, rr)
	}
	dnsanswer, err := dnsmsg.Pack()
	if err != nil {
		log.Fatalf("dns answer pack error %s", err)
	}

	return dnsquestion, dnsanswer
}

func GenerateDnstap(dt *dnstap.Dnstap) {

	dt.Reset()

	t := dnstap.Dnstap_MESSAGE
	dt.Identity = []byte("dnstap-generator")
	dt.Version = []byte("-")
	dt.Type = &t

	now := time.Now()
	mt := dnstap.Message_CLIENT_QUERY
	sf := SF[RandomInt(0, 1)]
	sp := SP[RandomInt(0, 3)]

	tsec := uint64(now.Second())
	tnsec := uint32(0)
	rport := uint32(1)
	qport := uint32(2)
	queryIp := "127.0.0.1"
	responseIp := "127.0.0.2"

	msg := &dnstap.Message{Type: &mt}
	msg.SocketFamily = &sf
	msg.SocketProtocol = &sp
	msg.QueryAddress = net.ParseIP(queryIp)
	msg.QueryPort = &qport
	msg.ResponseAddress = net.ParseIP(responseIp)
	msg.ResponsePort = &rport

	msg.QueryTimeSec = &tsec
	msg.QueryTimeNsec = &tnsec

	dt.Message = msg
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

			dt := &dnstap.Dnstap{}
			frame := &framestream.Frame{}

			for i := 1; i <= *numPacket; i++ {

				// generate dns message
				dnsquery, _ := GenerateDnsQuestion()
				if err != nil {
					log.Fatalf("dns pack error %s", err)
				}

				// generate dnstap message
				GenerateDnstap(dt)
				dt.Message.QueryMessage = dnsquery

				// serialize to byte
				data, err := proto.Marshal(dt)
				if err != nil {
					log.Fatalf("dnstap proto marshal error %s", err)
				}

				// send
				frame.Write(data)
				if err := fs.SendFrame(frame); err != nil {
					log.Fatalf("send frame error %s", err)
				}

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
