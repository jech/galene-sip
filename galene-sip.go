package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jart/gosip/sdp"
	"github.com/jart/gosip/sip"
	"github.com/jart/gosip/util"
	"github.com/jech/gclient"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"

	"github.com/jech/galene-sip/opus"
)

var sipRegistrar, sipAddress, sipPassword string
var galeneURL, galeneUsername, galenePassword string
var insecure bool
var debug bool

func main() {
	var noRegister bool
	var sipUDPAddress string
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s group\n", os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.StringVar(&sipAddress, "sip", "sip:6002@localhost", "SIP address")
	flag.BoolVar(&noRegister, "no-sip-register", false,
		"don't attempt registration")
	flag.StringVar(&sipRegistrar, "sip-registrar", "", "SIP registrar")
	flag.StringVar(&sipPassword, "sip-password", "", "SIP password")
	flag.StringVar(&sipUDPAddress, "sip-udp-address", ":",
		"local SIP UDP adress")
	flag.StringVar(&galeneUsername, "username", "", "Galene username")
	flag.StringVar(&galenePassword, "password", "", "Galene password")
	flag.BoolVar(&insecure, "insecure", false,
		"don't check server certificates")
	flag.BoolVar(&debug, "debug", false, "enable tracing")
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	galeneURL = flag.Arg(0)

	if sipRegistrar == "" {
		a, err := sip.ParseURI([]byte(sipAddress))
		if err != nil {
			log.Fatalf("Parse registrar: %v", err)
		}
		r := sip.URI{
			Scheme: "sip",
			Host:   a.Host,
			Port:   a.Port,
		}
		sipRegistrar = r.String()
	}

	listenAddr, err := net.ResolveUDPAddr("udp", sipUDPAddress)
	if err != nil {
		log.Fatalf("Parse sipUDPAddress: %v", err)
	}

	sock, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		log.Fatalf("Create UDP socket: %v", err)
	}
	defer sock.Close()

	s, err := newSipServer(sock, sipAddress, sipRegistrar, sipPassword)
	if err != nil {
		log.Fatal("Create SIP connection: ", err)
	}

	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, syscall.SIGINT, syscall.SIGTERM)

	registerCallID := util.GenerateCallID()
	registerDone := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())

	if !noRegister {
		go registerLoop(ctx, s, registerCallID, registerDone)
	} else {
		close(registerDone)
	}

	go outOfDialogLoop(ctx, s)
	<-terminate
	cancel()

	// leave time for BYE requests to go out
	timer := time.NewTimer(450 * time.Millisecond)
	<-registerDone
	<-timer.C
}

func outOfDialogLoop(ctx context.Context, s *sipServer) {
	for {
		select {
		case m := <-s.outOfDialog.reqCh:
			msg := m.msg
			addr := m.addr
			if strings.EqualFold(msg.Method, "INVITE") {
				go func() {
					err := gotInvite(ctx, s, msg, addr)
					if err != nil {
						log.Printf("Invite: %v", err)
					}
				}()
			} else if strings.EqualFold(msg.Method, "OPTIONS") {
				to := msg.To.Copy()
				if to == nil {
					to = &sip.Addr{}
				}
				to.Param = &sip.Param{
					Name:  "tag",
					Value: util.GenerateTag(),
					Next:  to.Param,
				}
				optionsOk := &sip.Msg{
					Status: 200,
					To:     to,
				}
				s.sendReply(msg, optionsOk, addr)
			} else {
				log.Println("Unexpected message", msg.Method)
			}
		case m := <-s.outOfDialog.replyCh:
			log.Println("Unexpected reply", m.msg.CSeqMethod)
		case <-ctx.Done():
			break
		}
	}
}

func gotInvite(ctx context.Context, s *sipServer, invite *sip.Msg, inviteAddr *net.UDPAddr) error {
	fromTag, toTag := getTags(invite)
	if toTag != "" {
		return errors.New("got invite with to tag")
	}
	toTag = util.GenerateTag()

	reqCh, replyCh, err := s.startDialog(invite.CallID, fromTag, toTag)
	if err != nil {
		return err
	}
	defer s.endDialog(reqCh, replyCh)

	to := invite.To.Copy()
	to.Param = &sip.Param{
		Name:  "tag",
		Value: toTag,
		Next:  to.Param,
	}

	cseq := 1
	nextCSeq := func() int {
		c := cseq
		cseq++
		return c
	}

	contact, err := s.contact(inviteAddr)
	if err != nil {
		return err
	}

	fail := func(status int, err error, addr *net.UDPAddr) error {
		phrase := ""
		if err != nil {
			phrase = err.Error()
		}
		reply := &sip.Msg{
			Status:  status,
			Phrase:  phrase,
			To:      to,
			Contact: contact,
		}
		s.sendReplyReliably(ctx, invite, reply, addr, false, replyCh)
		return err
	}

	unsupported := checkRequire(invite.Require)
	if unsupported != "" {
		reply := &sip.Msg{
			Status:      420,
			To:          to,
			CSeqMethod:  "INVITE",
			Contact:     contact,
			Unsupported: unsupported,
		}
		s.sendReplyReliably(ctx,
			invite, reply, inviteAddr, false, reqCh,
		)
		return err
	}

	if invite.Request.User != s.addressURI.User {
		return fail(404, nil, inviteAddr)
	}

	offer, ok := invite.Payload.(*sdp.SDP)
	if !ok {
		return fail(501,
			errors.New("server offer not implemented yet"),
			inviteAddr,
		)
	}

	if offer.Audio == nil || offer.Audio.Proto != "RTP/AVP" {
		err := errors.New("no audio track")
		return fail(488, err, inviteAddr)
	}

	var pcmu, pcma sdp.Codec
	for _, codec := range offer.Audio.Codecs {
		if strings.EqualFold(codec.Name, "PCMU") &&
			codec.Rate == 8000 {
			pcmu = codec
		} else if strings.EqualFold(codec.Name, "PCMA") &&
			codec.Rate == 8000 {
			pcma = codec
		}
	}

	codec := pcmu
	if codec.Name == "" {
		codec = pcma
	}
	if codec.Name == "" {
		return fail(488, nil, inviteAddr)
	}

	rtpSock, rtcpSock, err := socketPair()
	if err != nil {
		return fail(500, err, inviteAddr)
	}
	defer func() {
		rtpSock.Close()
		rtcpSock.Close()
	}()

	laddr, err := s.localAddr(inviteAddr)
	if err != nil {
		return fail(500, err, inviteAddr)
	}

	localRTP := &net.UDPAddr{
		IP:   laddr.IP,
		Port: rtpSock.LocalAddr().(*net.UDPAddr).Port,
	}

	offerAddr, err := net.ResolveIPAddr("ip", offer.Addr)
	if err != nil {
		return fail(500, err, inviteAddr)
	}

	answer := sdp.New(
		localRTP,
		codec,
	)

	trying := sip.Msg{
		Status:  100,
		To:      to,
		Contact: contact,
	}

	s.sendReply(invite, &trying, inviteAddr)

	username := galeneUsername
	if username == "" {
		username = invite.From.Display
	}
	if username == "" {
		username = "SIP user"
	}

	client, upTrack, _, err := galeneJoin(ctx,
		galeneURL, username, galenePassword,
	)
	if err != nil {
		return fail(500, err, inviteAddr)
	}
	defer client.Close()

	okReply := &sip.Msg{
		Status:  200,
		To:      to,
		Contact: contact,
		Payload: answer,
	}

	_, _, err = s.sendReplyReliably(ctx,
		invite, okReply, inviteAddr, true, reqCh,
	)
	if err != nil {
		return err
	}

	bye := func() error {
		branch := invite.Via.Param.Get("branch")
		if branch == nil {
			return errors.New("couldn't find branch")
		}
		via := &sip.Via{
			Host: invite.Via.Host,
			Port: invite.Via.Port,
			Param: &sip.Param{
				Name:  "branch",
				Value: branch.Value,
				Next: &sip.Param{
					Name: "rport",
				},
			},
		}
		msg := &sip.Msg{
			Method:     "BYE",
			Request:    invite.Contact.Uri,
			From:       to,
			To:         invite.From,
			CallID:     invite.CallID,
			Via:        via,
			CSeq:       nextCSeq(),
			CSeqMethod: "BYE",
			Route:      invite.RecordRoute.Reversed(),
		}
		_, _, err := s.sendReliably(context.Background(),
			msg, inviteAddr, replyCh,
		)
		return err
	}

	done := make(chan struct{})
	defer close(done)

	var remoteRTP atomic.Value
	remoteRTP.Store(&net.UDPAddr{
		IP:   offerAddr.IP,
		Port: int(offer.Audio.Port),
	})

	ssrc := randomUint32()
	audio := audioBuffer{
		pcm: make([]int16, 48000/50*4),
	}
	go rptLoopSIP(
		rtpSock, rtcpSock, upTrack,
		ssrc, codec, &audio, &remoteRTP, done,
	)
	go rtpLoopGalene(rtpSock, rtcpSock,
		ssrc, codec, &audio, &remoteRTP, done,
	)

	cname := fmt.Sprintf("%v@%v",
		contact.Uri.User, contact.Uri.Host,
	)
	go rtcpReader(rtcpSock, ssrc, cname, &remoteRTP, done)
	go rtcpWriter(rtcpSock, ssrc, cname, &remoteRTP, done)
outer:
	for {
		select {
		case <-ctx.Done():
			bye()
			return ctx.Err()
		case m := <-reqCh:
			msg := m.msg
			addr := m.addr

			if strings.EqualFold(msg.Method, "BYE") {
				byeOk := &sip.Msg{
					Status:  200,
					Contact: contact,
				}
				s.sendReply(msg, byeOk, addr)
				return nil
			} else if strings.EqualFold(msg.Method, "INVITE") {
				fail := func(status int, phrase string) {
					reply := &sip.Msg{
						Status:  status,
						Phrase:  phrase,
						Contact: contact,
					}
					s.sendReply(msg, reply, addr)
				}
				offer, ok := msg.Payload.(*sdp.SDP)
				if !ok {
					fail(400, "couldn't parse SDP")
					continue outer
				}
				offerAddr, err :=
					net.ResolveIPAddr("ip", offer.Addr)
				if err != nil {
					log.Printf("ResolveIPAddr: %v", err)
				}
				remoteRTP.Store(&net.UDPAddr{
					IP:   offerAddr.IP,
					Port: int(offer.Audio.Port),
				})
				inviteOk := &sip.Msg{
					Status:  200,
					Contact: contact,
					Payload: answer,
				}
				s.sendReply(msg, inviteOk, addr)
			} else if strings.EqualFold(msg.Method, "ACK") ||
				strings.EqualFold(msg.Method, "CANCEL") {
				// nothing
			} else {
				resp := &sip.Msg{
					Status:  500,
					Contact: contact,
				}
				s.sendReply(msg, resp, addr)
			}
		case m := <-replyCh:
			log.Printf("Unexpected reply %v %v",
				m.msg.CSeqMethod, m.msg.Status)
		case e := <-client.EventCh:
			if e == nil {
				return bye()
			}
			switch e := e.(type) {
			case gclient.UserMessageEvent:
				if e.Kind == "error" || e.Kind == "warning" {
					log.Printf("Galene %v: %v",
						e.Kind, e.Value,
					)
				}
			case gclient.DownTrackEvent:
				go downTrackLoop(
					e.Track, e.Receiver, &audio,
				)
			case error:
				log.Printf("Galene: %v", e)
				return bye()
			}
		}
	}
}

func checkRequire(require string) string {
	rs := strings.Split(require, ",")
	for _, r := range rs {
		rr := strings.Trim(r, " \t\r\n")
		if rr != "" {
			return ""
		}
	}
	return require
}

func rptLoopSIP(rtpSock *net.UDPConn, rtcpSock *net.UDPConn, upTrack *webrtc.TrackLocalStaticRTP, ssrc uint32, codec sdp.Codec, audioBuf *audioBuffer, remoteRTP *atomic.Value, done <-chan struct{}) {
	encoder, err := opus.NewEncoder(codec.Rate, 1)
	if err != nil {
		log.Printf("Create Opus encoder: %v", err)
		return
	}
	defer encoder.Destroy()

	down := 48000 / codec.Rate
	lbuf := make([]int16, 1500)
	buf := make([]byte, 1500)
	send := func(p *rtp.Packet) error {
		n, err := decodeAudio(codec.Name, lbuf, p.Payload)
		if err != nil {
			return err
		}
		if n == 0 || isSilence(lbuf[:n]) {
			return nil
		}
		m, err := encoder.Encode(lbuf[:n], buf)
		if err != nil {
			return err
		}
		p2 := rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				SequenceNumber: p.SequenceNumber,
				Timestamp:      p.Timestamp * uint32(down),
				Marker:         p.Marker,
			},
			Payload: buf[:m],
		}
		return upTrack.WriteRTP(&p2)
	}

	// Opus is a stateful format, so we must encode packets in order.
	haveLastSeqno := false
	var lastSeqno uint16
	var buffered *rtp.Packet
	rtpBuf := make([]byte, 1500)
	for {
		n, _, err := rtpSock.ReadFrom(rtpBuf)
		if err != nil {
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-done:
				timer.Stop()
				return
			case <-timer.C:
				log.Printf("ReadRTP: %v", err)
				continue
			}
		}

		var p rtp.Packet
		err = p.Unmarshal(rtpBuf[:n])
		if err != nil {
			log.Printf("Unmarshal: %v", err)
			continue
		}
		var next *rtp.Packet
		if !haveLastSeqno {
			haveLastSeqno = true
			next = &p
		} else {
			delta := p.SequenceNumber - lastSeqno
			if delta == 0 || delta >= 0xFF00 {
				// late packet
				continue
			}
			if delta == 1 {
				// in-order packet
				next = &p
			} else if buffered == nil {
				buffered = p.Clone()
				continue
			} else {
				bdelta := buffered.SequenceNumber - lastSeqno
				if delta == bdelta {
					buffered = nil
					next = &p
				} else if delta < bdelta {
					next = &p
				} else {
					next = buffered
					buffered = p.Clone()
				}
			}

			lastSeqno = next.SequenceNumber
			err = send(next)
			if err != nil {
				log.Printf("Send: %v", err)
			}

			if buffered != nil {
				if buffered.SequenceNumber == lastSeqno+1 {
					lastSeqno = buffered.SequenceNumber
					err = send(buffered)
					if err != nil {
						log.Printf("Send: %v", err)
					}
					buffered = nil
				}
			}
		}
	}
}

func rtcpReader(rtcpSock *net.UDPConn, ssrc uint32, cname string, remoteRTP *atomic.Value, done <-chan struct{}) {
	buf := make([]byte, 1500)
	for {
		n, _, err := rtcpSock.ReadFrom(buf)
		if err != nil {
			return
		}
		_, err = rtcp.Unmarshal(buf[:n])
		if err != nil {
			log.Printf("Unmarshal RTCP: %v", err)
		}
	}
}

func rtcpWriter(rtcpSock *net.UDPConn, ssrc uint32, cname string, remoteRTP *atomic.Value, done <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		packets := make([]rtcp.Packet, 0)
		packets = append(packets, &rtcp.SenderReport{
			SSRC: ssrc,
		})
		items := []rtcp.SourceDescriptionItem{
			{
				Type: rtcp.SDESCNAME,
				Text: cname,
			},
		}
		packets = append(packets,
			&rtcp.SourceDescription{
				Chunks: []rtcp.SourceDescriptionChunk{
					{
						Source: ssrc,
						Items:  items,
					},
				},
			},
		)
		packet, err := rtcp.Marshal(packets)
		if err != nil {
			log.Printf("rtcp.Marshal: %v", err)
			continue
		}
		rtpAddr := remoteRTP.Load().(*net.UDPAddr)
		rtcpAddr := net.UDPAddr{
			IP:   rtpAddr.IP,
			Port: rtpAddr.Port + 1,
		}
		_, err = rtcpSock.WriteTo(packet, &rtcpAddr)
		if err != nil {
			log.Printf("Write RTCP: %v", err)
		}
		select {
		case <-ticker.C:
		case <-done:
			return
		}
	}
}

func rtpLoopGalene(rtpSock *net.UDPConn, rtcpSock *net.UDPConn, ssrc uint32, codec sdp.Codec, audio *audioBuffer, remoteRTP *atomic.Value, done <-chan struct{}) {
	spp := 48000 / 50          // samples par packet
	down := 48000 / codec.Rate // downsampling factor
	ulaw := make([]uint8, spp/down)
	begin := time.Now()

	pbuf := make([]byte, 1500)

	seqno := uint16(0)
	marker := true
	silence := 0

	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case now := <-ticker.C:
		again:
			t0, pcm := audio.Get(spp)
			if len(pcm) == 0 {
				continue
			}

			if silence < 30*48000 && isSilence(pcm) {
				silence += len(pcm)
				continue
			}
			if silence >= 24000 {
				marker = true
			}
			silence = 0

			n, err := encodeAudio(codec.Name, down, ulaw, pcm)
			if err != nil {
				log.Printf("encodeAudio: %v", err)
				continue
			}
			ts := uint32(t0.Sub(begin) / (time.Second / 48000))
			packet := rtp.Packet{
				Header: rtp.Header{
					Version:        2,
					SequenceNumber: seqno,
					Timestamp:      ts,
					Marker:         marker,
					SSRC:           ssrc,
					PayloadType:    codec.PT,
				},
				Payload: ulaw[:n],
			}
			m, err := packet.MarshalTo(pbuf)
			if err != nil {
				log.Printf("Marshal: %v", err)
				continue
			}
			to := remoteRTP.Load().(*net.UDPAddr)
			_, err = rtpSock.WriteTo(pbuf[:m], to)
			if err != nil {
				log.Printf("Write RTP: %v", err)
			} else {
				seqno++
				marker = false
			}

			t1 := t0.Add(time.Duration(len(pcm)) *
				(time.Second / 48000))
			delta := now.Sub(t1)
			if delta > time.Second ||
				delta < 20*time.Millisecond {
				audio.Shift(now)
			} else if delta > 50*time.Millisecond {
				now = time.Now()
				goto again
			}
		}
	}
}

type bufferedPacket struct {
	packet *rtp.Packet
}

func (b *bufferedPacket) peek() (bool, uint16, uint32) {
	if b.packet == nil {
		return false, 0, 0
	}
	return true, b.packet.SequenceNumber, b.packet.Timestamp
}

func (b *bufferedPacket) put(p *rtp.Packet) *rtp.Packet {
	old := b.packet
	b.packet = p
	return old
}

func (b *bufferedPacket) get() *rtp.Packet {
	return b.put(nil)
}

func downTrackLoop(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver, audio *audioBuffer) {
	go func(receiver *webrtc.RTPReceiver) {
		buf := make([]byte, 2048)
		for {
			_, _, err := receiver.Read(buf)
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Printf("Read RTCP: %v", err)
				time.Sleep(time.Second)
			}
		}
	}(receiver)

	decoder, err := opus.NewDecoder(48000, 1)
	if err != nil {
		log.Printf("NewDecoder: %v", err)
		return
	}
	defer decoder.Destroy()

	var begin time.Time
	var beginTS uint32
	const jiffy = time.Second / 48000

	buf := make([]byte, 1500)
	pcm := make([]int16, 48000/4)
	var packet rtp.Packet
	var buffered bufferedPacket
	var next struct {
		ok    bool
		seqno uint16
		ts    uint32
	}

	decode := func(p *rtp.Packet) error {
		tsDelta := p.Timestamp - beginTS
		t := begin.Add(time.Duration(tsDelta) * jiffy)

		n, err := decoder.Decode(p.Payload, pcm, false)
		if err != nil {
			return err
		}

		audio.Put(t, pcm[:n])
		next.ok = true
		next.seqno = p.SequenceNumber + 1
		next.ts = p.Timestamp + uint32(n)
		return nil
	}

	decodeFEC := func(p *rtp.Packet, samples int) error {
		tsDelta := p.Timestamp - uint32(samples) - beginTS
		t := begin.Add(time.Duration(tsDelta) * jiffy)

		n, err := decoder.Decode(p.Payload, pcm[:samples], true)
		if err != nil {
			return err
		}

		audio.Put(t, pcm[:n])
		next.ok = true
		next.seqno = p.SequenceNumber
		next.ts = p.Timestamp
		return nil
	}

	for {
		n, _, err := track.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read: %v", err)
				return
			}
			return
		}
		receiveTime := time.Now()
		err = packet.Unmarshal(buf[:n])
		if err != nil {
			log.Printf("Unmarshal: %v", err)
			continue
		}

		if packet.Marker || begin.Equal(time.Time{}) ||
			packet.Timestamp-beginTS >= 0x80000000 {
			begin = receiveTime
			beginTS = packet.Timestamp
		}

		fec := false
		if next.ok {
			delta := packet.SequenceNumber - next.seqno
			if delta >= 0xFF00 {
				// late packet, drop it
				continue
			}
			if delta == 0 {
				// in-order packet, fine
			} else if ok, _, _ := buffered.peek(); !ok {
				// one out-of-order packet
				buffered.put(packet.Clone())
				continue
			} else if delta == 1 {
				// two out-of-order packets, apply FEC
				fec = true
			} else {
				_, bs, _ := buffered.peek()
				bdelta := bs - next.seqno
				if bdelta == 1 {
					// apply FEC to the buffered packet
					fec = true
					next := buffered.put(packet.Clone())
					packet = *next
				} else {
					if debug {
						log.Printf("Packet drop, "+
							"delta=%v, bdelta=%v",
							delta, bdelta)
					}
					if delta == bdelta {
						// duplicate packet
						buffered.get()
					} else if delta > bdelta {
						next := buffered.put(
							packet.Clone(),
						)
						packet = *next
					}
				}
			}
		}

		if fec {
			err = decodeFEC(
				&packet, int(packet.Timestamp-next.ts),
			)
			if err != nil {
				log.Printf("DecodeFEC: %v", err)
			}
		}

		err = decode(&packet)
		if err != nil {
			log.Printf("Decode: %v", err)
			continue
		}

		if ok, bs, bts := buffered.peek(); ok {
			if bs == next.seqno && bts == next.ts {
				p := buffered.get()
				err := decode(p)
				if err != nil {
					log.Printf("Decode buffered: %v", err)
				}
			}
		}
	}
}

type joinedEvent struct {
	event  gclient.JoinedEvent
	track  *webrtc.TrackLocalStaticRTP
	sender *webrtc.RTPSender
	err    error
}

func galeneJoin(ctx context.Context, url, username, password string) (*gclient.Client, *webrtc.TrackLocalStaticRTP, *webrtc.RTPSender, error) {
	client := gclient.NewClient()

	if insecure {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client.SetHTTPClient(&http.Client{
			Transport: t,
		})

		d := *websocket.DefaultDialer
		d.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client.SetDialer(&d)
	}

	err := client.Connect(ctx, url)
	if err != nil {
		return nil, nil, nil, err
	}

	err = client.Join(ctx, url, username, password)
	if err != nil {
		return nil, nil, nil, err
	}

	for {
		select {
		case <-ctx.Done():
			client.Close()
			return nil, nil, nil, ctx.Err()
		case e := <-client.EventCh:
			if e == nil {
				return nil, nil, nil, io.EOF
			}
			switch e := e.(type) {
			case gclient.JoinedEvent:
				switch e.Kind {
				case "failed":
					client.Close()
					return nil, nil, nil, fmt.Errorf(
						"couldn't join: %v", e.Value,
					)
				case "join":
					client.Request(
						map[string][]string{
							"": {"audio"},
						},
					)
					track, sender, err :=
						galeneUpTrack(client)
					if err != nil {
						client.Close()
						return nil, nil, nil, err
					}
					return client, track, sender, nil
				}
			case gclient.UserMessageEvent:
				if e.Kind == "error" || e.Kind == "warning" {
					log.Printf("%v: %v", e.Kind, e.Value)
				}
			case error:
				return nil, nil, nil, err
			}
		}
	}
}

func galeneUpTrack(client *gclient.Client) (*webrtc.TrackLocalStaticRTP, *webrtc.RTPSender, error) {
	pc, err := webrtc.NewPeerConnection(*client.RTCConfiguration())
	if err != nil {
		return nil, nil, err
	}

	track, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: "audio/opus"},
		"audio", "galene-sip",
	)
	if err != nil {
		return nil, nil, err
	}

	sender, err := pc.AddTrack(track)
	if err != nil {
		return nil, nil, err
	}

	go func(sender *webrtc.RTPSender) {
		buf := make([]byte, 2048)
		for {
			_, _, err := sender.Read(buf)
			if err != nil {
				if err == io.EOF ||
					errors.Is(err, io.ErrClosedPipe) {
					return
				}
				log.Printf("Read RTCP: %v", err)
				time.Sleep(time.Second)
			}
		}
	}(sender)

	connected := make(chan struct{})
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		if state == webrtc.ICEConnectionStateConnected {
			close(connected)
		}
	})

	id := gclient.MakeId()
	err = client.NewUpConn(id, pc, "camera")
	if err != nil {
		pc.Close()
		return nil, nil, err
	}
	<-connected

	return track, sender, nil
}

func randomUint32() uint32 {
	s := make([]byte, 4)
	rand.Read(s)
	return uint32(s[0])<<24 | uint32(s[1])<<16 |
		uint32(s[2])<<8 | uint32(s[0])
}
