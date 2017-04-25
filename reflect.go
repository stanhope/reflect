// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Reflect is a small name server which sends back the IP address of its client, the
// recursive resolver.
// When queried for type A (resp. AAAA), it sends back the IPv4 (resp. v6) address.
// In the additional section the port number and transport are shown.
//
// Basic use pattern:
//
//	dig @localhost -p 8053 whoami.miek.nl A
//
//	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2157
//	;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
//	;; QUESTION SECTION:
//	;whoami.miek.nl.			IN	A
//
//	;; ANSWER SECTION:
//	whoami.miek.nl.		0	IN	A	127.0.0.1
//
//	;; ADDITIONAL SECTION:
//	whoami.miek.nl.		0	IN	TXT	"Port: 56195 (udp)"
//
// Similar services: whoami.ultradns.net, whoami.akamai.net. Also (but it
// is not their normal goal): rs.dns-oarc.net, porttest.dns-oarc.net,
// amiopen.openresolvers.org.
//
// Original version is from: Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>.
//
// Adapted to Go (i.e. completely rewritten) by Miek Gieben <miek@miek.nl>.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stanhope/dns"
)

var (
	printf     = flag.Bool("print", false, "print replies")
	compress   = flag.Bool("compress", false, "compress replies")
	tsig       = flag.String("tsig", "", "use MD5 hmac tsig: keyname:base64")
)

func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	var (
		v4  bool
		rr  dns.RR
		str string
		a   net.IP
	)

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress
	if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
		a = ip.IP
		v4 = a.To4() != nil
	}
	if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
		a = ip.IP
		v4 = a.To4() != nil
	}

	var qname = r.Question[0].String()
	var qname_end = strings.LastIndex(qname[1:len(qname)],".")
	var key = qname[1:(qname_end+2)]
	qname = key
	qname_info := fmt.Sprintf("QNAME: %s", key)

	if v4 {
		rr = &dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			A:   a.To4(),
		}
	} else {
		rr = &dns.AAAA{
			Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
			AAAA: a,
		}
	}

	edns_info := "EDNS:"
	vcn_info := "VCN:"
	id_info := fmt.Sprintf("ID: %d", r.Id)

	if o := r.IsEdns0(); o != nil {
		for _, s := range o.Option {
			switch e := s.(type) {
			case *dns.EDNS0_SUBNET:
				edns_info = fmt.Sprintf("EDNS: %s", e.Address.String())
			}
		}
	}
	if r.ProxyInfo != nil {
		vcn_info = fmt.Sprintf("VCN: %s", *r.ProxyInfo)
	}

	tPORT := &dns.TXT{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{str},
	}

	tQNAME := &dns.TXT{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{qname_info},
	}

	tEDNS := &dns.TXT{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{edns_info},
	}

	// Todo discover if there is another EDNS option
	tVCN_INFO := &dns.TXT{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{vcn_info},
	}

	tQCLASS := &dns.TXT{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{id_info},
	}

	switch r.Question[0].Qtype {
	case dns.TypeTXT:
		m.Answer = append(m.Answer, tPORT)
		m.Extra = append(m.Extra, rr)
	default:
		fallthrough
	case dns.TypeAAAA, dns.TypeA:
		m.Answer = append(m.Answer, rr)
		m.Extra = append(m.Extra, tQNAME)
		m.Extra = append(m.Extra, tPORT)
		m.Extra = append(m.Extra, tEDNS)
		m.Extra = append(m.Extra, tVCN_INFO)
		m.Extra = append(m.Extra, tQCLASS)
	}

	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
		} else {
			println("Status", w.TsigStatus().Error())
		}
	}
	if *printf {
		fmt.Printf("%v\n", m.String())
	}
	w.WriteMsg(m)
}

func serve(net, name, secret string) {
	switch name {
	case "":
		server := &dns.Server{Addr: ":8053", Net: net, TsigSecret: nil}
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	default:
		server := &dns.Server{Addr: ":8053", Net: net, TsigSecret: map[string]string{name: secret}}
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	}
}

func main() {
	var name, secret string
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1] // fqdn the name, which everybody forgets...
	}
	dns.HandleFunc(".", handleReflect)
	go serve("tcp", name, secret)
	go serve("udp", name, secret)
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
