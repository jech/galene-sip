package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/icholy/digest"
	"github.com/jart/gosip/sip"
	"github.com/jart/gosip/util"
)

var ErrSIPTimeout = errors.New("SIP timeout")
var ErrSIPDialogTerminated = errors.New("SIP dialog terminated")

type dialogKey struct {
	callID    string
	remoteTag string
	localTag  string
}

type dialog struct {
	reqCh   chan *sipMsg
	replyCh chan *sipMsg
	cseq    int
}

type sipServer struct {
	sock               *net.UDPConn
	registrar, address string
	addressURI         *sip.URI
	password           string
	outOfDialog        dialog

	mu            sync.Mutex
	dialogs       map[dialogKey]*dialog
	authorization string
}

func newSipServer(sock *net.UDPConn, address, registrar, password string) (*sipServer, error) {
	addressURI, err := sip.ParseURI([]byte(address))
	if err != nil {
		return nil, err
	}

	s := &sipServer{
		sock:       sock,
		address:    address,
		addressURI: addressURI,
		registrar:  registrar,
		password:   password,
		outOfDialog: dialog{
			reqCh:   make(chan *sipMsg, 8),
			replyCh: make(chan *sipMsg, 8),
		},
		dialogs: make(map[dialogKey]*dialog),
	}
	go func() {
		err := s.readLoop()
		log.Printf("SIP reader loop terminated: %v", err)
	}()
	return s, nil
}

func (s *sipServer) send(msg *sip.Msg, to *net.UDPAddr) error {
	var b bytes.Buffer
	msg.Append(&b)
	if debug {
		fmt.Printf("%s\n", b.Bytes())
	}
	_, err := s.sock.WriteTo(b.Bytes(), to)
	return err
}

func fillReply(req, rep *sip.Msg) {
	if rep.Via == nil {
		rep.Via = req.Via
	}
	if rep.From == nil {
		rep.From = req.From
	}
	if rep.To == nil {
		rep.To = req.To
	}
	if rep.CallID == "" {
		rep.CallID = req.CallID
	}
	if rep.CSeq == 0 {
		rep.CSeq = req.CSeq
	}
	if rep.CSeqMethod == "" {
		rep.CSeqMethod = req.Method
	}
	if rep.RecordRoute == nil {
		rep.RecordRoute = req.RecordRoute
	}
}

func (s *sipServer) sendReply(req, rep *sip.Msg, to *net.UDPAddr) error {
	if req.IsResponse() {
		return errors.New("request is response")
	}
	if !rep.IsResponse() {
		return errors.New("response is request")
	}
	fillReply(req, rep)
	return s.send(rep, to)
}

// transcationMatch returns true if reply is either a reply to msg or an
// ACK, CANCEL, BYE or similar that acknowledges the reply to msg.
func transactionMatch(reply, msg *sip.Msg) bool {
	if reply.Via == nil || msg.Via == nil {
		return false
	}

	rbranch := reply.Via.Param.Get("branch")
	mbranch := reply.Via.Param.Get("branch")
	if rbranch == nil || mbranch == nil {
		return false
	}

	if rbranch.Value != mbranch.Value {
		return false
	}

	if reply.IsResponse() {
		if !strings.EqualFold(reply.CSeqMethod, msg.CSeqMethod) {
			return false
		}
	}

	return reply.CSeq == msg.CSeq
}

func (s *sipServer) sendReliably(ctx context.Context, msg *sip.Msg, to *net.UDPAddr, ch <-chan *sipMsg) (*sip.Msg, *net.UDPAddr, error) {
	t := 500 * time.Millisecond
	got100 := false
outer:
	for t < 20*time.Second {
		if !got100 {
			err := s.send(msg, to)
			if err != nil {
				return nil, nil, err
			}
		}

		timeout := time.NewTimer(t)
		for {
			select {
			case <-timeout.C:
				t = 2 * t
				continue outer
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case reply := <-ch:
				if !transactionMatch(reply.msg, msg) {
					continue
				}
				timeout.Stop()
				if reply.msg.Status < 200 {
					got100 = true
					continue
				}
				return reply.msg, reply.addr, nil
			}
		}
	}

	return nil, nil, ErrSIPTimeout
}

func (s *sipServer) sendReplyReliably(ctx context.Context, invite, msg *sip.Msg, to *net.UDPAddr, honourCancel bool, ch <-chan *sipMsg) (*sip.Msg, *net.UDPAddr, error) {
	if !strings.EqualFold(invite.Method, "INVITE") {
		return nil, nil, errors.New("method should be INVITE")
	}

	fillReply(invite, msg)

	t := 500 * time.Millisecond
outer:
	for t < 20*time.Second {
		err := s.send(msg, to)
		if err != nil {
			return nil, nil, err
		}

		timeout := time.NewTimer(t)
		for {
			select {
			case <-timeout.C:
				t = 2 * t
				continue outer
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case m2 := <-ch:
				if m2 == nil {
					return nil, nil, io.ErrUnexpectedEOF
				}
				msg2 := m2.msg
				addr2 := m2.addr
				if !transactionMatch(msg2, msg) {
					continue
				}
				if strings.EqualFold(
					msg2.Method, "ACK",
				) {
					return msg2, addr2, nil
				} else if honourCancel && strings.EqualFold(
					msg2.Method, "CANCEL",
				) {
					cancelOk := &sip.Msg{
						Status: 200,
					}
					s.sendReply(msg2, cancelOk, to)
					terminatedReply := &sip.Msg{
						Status: 487,
						To:     msg.To,
					}
					_, _, err := s.sendReplyReliably(
						ctx, invite, terminatedReply,
						to, false, ch,
					)
					if err != nil {
						return nil, nil, err
					}
					return nil, nil, ErrSIPDialogTerminated
				} else {
					// the peer sent us a request, but
					// we're not ready to start a new
					// transaction right now.  Drop
					// the request, the peer will
					// resend it.
					if debug {
						log.Printf(
							"Dropping request %v",
							msg2.Method,
						)
					}
				}
			}
		}
	}
	return nil, nil, ErrSIPTimeout
}

func getTags(msg *sip.Msg) (string, string) {
	fromTag := ""
	fTag := msg.From.Param.Get("tag")
	if fTag != nil {
		fromTag = fTag.Value
	}
	toTag := ""
	tTag := msg.To.Param.Get("tag")
	if tTag != nil {
		toTag = tTag.Value
	}
	return fromTag, toTag
}

func (s *sipServer) startDialog(callID, remoteTag, localTag string) (<-chan *sipMsg, <-chan *sipMsg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := dialogKey{
		callID:    callID,
		remoteTag: remoteTag,
		localTag:  localTag,
	}
	_, ok := s.dialogs[key]
	if ok {
		return nil, nil, errors.New("duplicate dialog")
	}
	d := dialog{
		reqCh:   make(chan *sipMsg, 8),
		replyCh: make(chan *sipMsg, 8),
		cseq:    -1,
	}
	s.dialogs[key] = &d
	return d.reqCh, d.replyCh, nil
}

func (s *sipServer) endDialog(reqCh, replyCh <-chan *sipMsg) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.dialogs {
		if v.reqCh == reqCh && v.replyCh == replyCh {
			delete(s.dialogs, k)
			return nil
		}
	}
	return os.ErrNotExist
}

type sipMsg struct {
	msg  *sip.Msg
	addr *net.UDPAddr
}

func (s *sipServer) findDialog(callID, remoteTag, localTag string) *dialog {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := dialogKey{
		callID:    callID,
		remoteTag: remoteTag,
		localTag:  localTag,
	}
	d, ok := s.dialogs[key]
	if ok {
		return d
	}

	key.remoteTag = ""
	d, ok = s.dialogs[key]
	if ok {
		delete(s.dialogs, key)
		key.remoteTag = remoteTag
		s.dialogs[key] = d
		return d
	}

	return nil
}

func tweakVia(msg *sip.Msg, from *net.UDPAddr) (*net.UDPAddr, error) {
	if msg.IsResponse() {
		return nil, errors.New("message is a reply")
	}
	via := msg.Via
	if via == nil {
		return nil, errors.New("message has no Via")
	}
	port := int(via.Port)
	if port == 0 {
		port = 5060
	}
	hostIP := net.ParseIP(via.Host) // nil if hostname

	// RFC 3581
	rport := via.Param.Get("rport")

	// RFC 3261 Section 18.2.1
	if !from.IP.Equal(hostIP) || rport != nil {
		via.Param = &sip.Param{
			Name:  "received",
			Value: from.IP.String(),
			Next:  via.Param,
		}
	}

	// RFC 3581
	if rport != nil {
		rport.Value = strconv.Itoa(from.Port)
	}

	// RFC 3261 Section 18.2.2
	if maddr := via.Param.Get("maddr"); maddr != nil {
		return nil, errors.New("multicast is not supported")
	}

	if received := via.Param.Get("received"); received != nil {
		a := net.ParseIP(received.Value)
		if a == nil {
			return nil, fmt.Errorf(
				"couldn't parse received %v", received,
			)
		}
		return &net.UDPAddr{
			IP:   a,
			Port: port,
		}, nil
	}

	a, err := net.ResolveIPAddr("ip", via.Host)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{
		IP:   a.IP,
		Port: port,
	}, nil
}

func (s *sipServer) readLoop() error {
	buf := make([]byte, 65536)
	for {
		n, f, err := s.sock.ReadFrom(buf)
		if err != nil {
			log.Println("Read:", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		from := f.(*net.UDPAddr)
		if debug {
			fmt.Printf("%s\n", buf[:n])
		}
		msg, err := sip.ParseMsg(buf[:n])
		if err != nil {
			log.Println("ParseMsg:", err)
			continue
		}
		remoteTag, localTag := getTags(msg)
		if msg.IsResponse() {
			remoteTag, localTag = localTag, remoteTag
		}

		var ch chan<- *sipMsg
		addr := from

		fail := func(status int, err error) {
			if msg.IsResponse() {
				log.Print("Called fail on response, " +
					"this shouldn't happen.")
				return
			}
			phrase := ""
			if err != nil {
				phrase = err.Error()
			}
			reply := &sip.Msg{
				Status: status,
				Phrase: phrase,
			}
			s.sendReply(msg, reply, addr)
		}

		if !msg.IsResponse() {
			a, err := tweakVia(msg, from)
			if err != nil {
				log.Printf("Tweak Via: %v", err)
				fail(500, err)
				continue
			}
			addr = a
		}
		d := s.findDialog(msg.CallID, remoteTag, localTag)
		if d != nil {
			ch = d.reqCh
			if msg.IsResponse() {
				ch = d.replyCh
			} else {
				if d.cseq >= 0 && d.cseq >= msg.CSeq {
					continue
				}
				d.cseq = msg.CSeq
			}
		} else {
			ch = s.outOfDialog.reqCh
			if msg.IsResponse() {
				ch = s.outOfDialog.replyCh
			}
		}
		if msg.IsResponse() {
			ch <- &sipMsg{
				msg:  msg,
				addr: addr,
			}
		} else {
			select {
			case ch <- &sipMsg{
				msg:  msg,
				addr: addr,
			}:
			default:
				// the peer has sent cap(ch) requests
				// before we had a chance to handle one.
				// Drop the new request, let the peer
				// resend it.
				log.Println("Dropped peer request")
			}
		}
	}
}

// localAddr returns the address that s will use for contacting dest
func (s *sipServer) localAddr(dest *net.UDPAddr) (*net.UDPAddr, error) {
	sock, err := net.DialUDP("udp", nil, dest)
	if err != nil {
		return nil, err
	}
	defer sock.Close()

	// IP from sock, port from s.sock
	return &net.UDPAddr{
		IP:   sock.LocalAddr().(*net.UDPAddr).IP,
		Port: s.sock.LocalAddr().(*net.UDPAddr).Port,
	}, nil
}

func (s *sipServer) contact(dest *net.UDPAddr) (*sip.Addr, error) {
	laddr, err := s.localAddr(dest)
	if err != nil {
		return nil, err
	}
	return &sip.Addr{
		Uri: &sip.URI{
			Host: laddr.IP.String(),
			Port: uint16(laddr.Port),
			User: s.addressURI.User,
		},
	}, nil
}

type AuthChallengeError struct {
	Challenge string
}

func (e AuthChallengeError) Error() string {
	return "unauthorized (with challenge)"
}

func (s *sipServer) register1(ctx context.Context, callId string, cseq *int, seconds int) (int, error) {
	registrar, err := sip.ParseURI([]byte(s.registrar))
	if err != nil {
		return 0, err
	}
	p := registrar.Port
	if p == 0 {
		p = 5060
	}
	registrarAddr, err := net.ResolveUDPAddr(
		"udp", net.JoinHostPort(registrar.Host, strconv.Itoa(int(p))),
	)

	contact, err := s.contact(registrarAddr)
	if err != nil {
		return 0, err
	}

	contact.Param = &sip.Param{
		Name:  "expires",
		Value: strconv.Itoa(seconds),
		Next:  contact.Param,
	}
	via := &sip.Via{
		Host: contact.Uri.Host,
		Port: contact.Uri.Port,
		Param: &sip.Param{
			Name:  "branch",
			Value: util.GenerateBranch(),
			Next: &sip.Param{
				Name: "rport",
			},
		},
	}

	requestURI := &sip.URI{
		Scheme: s.addressURI.Scheme,
		Host:   s.addressURI.Host,
		Port:   s.addressURI.Port,
	}

	fromTag := util.GenerateTag()
	from := &sip.Addr{Uri: s.addressURI}
	from.Param = &sip.Param{
		Name:  "tag",
		Value: fromTag,
		Next:  from.Param,
	}
	to := &sip.Addr{Uri: s.addressURI}
	reqCh, replyCh, err := s.startDialog(callId, "", fromTag)
	if err != nil {
		return 0, err
	}
	defer s.endDialog(reqCh, replyCh)
	register := &sip.Msg{
		Method:        sip.MethodRegister,
		Request:       requestURI,
		To:            to,
		Via:           via,
		From:          from,
		Contact:       contact,
		CallID:        callId,
		CSeq:          *cseq,
		CSeqMethod:    "REGISTER",
		Expires:       seconds,
		Authorization: s.authorization,
	}
	reply, _, err := s.sendReliably(ctx, register, registrarAddr, replyCh)
	*cseq++
	if err != nil {
		return 0, err
	}

	if reply.Status == 401 && reply.WWWAuthenticate != "" {
		return 0, AuthChallengeError{
			Challenge: reply.WWWAuthenticate,
		}
	} else if reply.Status > 299 {
		return 0, errors.New(reply.Phrase)
	} else {
		expires := reply.Expires
		if expires == 0 {
			expires = 3600
		}
		found := false
		c := reply.Contact
		for c != nil {
			if c.Uri.String() == contact.Uri.String() {
				found = true
				e := c.Param.Get("expires")
				if e != nil {
					ee, err := strconv.Atoi(e.Value)
					if err != nil {
						return 0, err
					} else if ee < expires {
						expires = ee
					}
				}
			}
			c = c.Next
		}
		if !found {
			expires = 0
		}
		return expires, nil
	}
}

func (s *sipServer) register(ctx context.Context, callId string, cseq *int, seconds int) (int, error) {
	secs, err := s.register1(ctx, callId, cseq, seconds)
	if err == nil {
		return secs, err
	}

	var cherr AuthChallengeError
	if errors.As(err, &cherr) {
		challenge, err := digest.ParseChallenge(cherr.Challenge)
		if err != nil {
			return 0, err
		}
		requestURI := &sip.URI{
			Scheme: s.addressURI.Scheme,
			Host:   s.addressURI.Host,
			Port:   s.addressURI.Port,
		}
		var creds *digest.Credentials
		creds, err = digest.Digest(challenge, digest.Options{
			Method:   "REGISTER",
			URI:      requestURI.String(),
			Username: s.addressURI.User,
			Password: s.password,
		})
		if err != nil {
			return 0, fmt.Errorf("compute digest: %w", err)
		}
		s.authorization = creds.String()
		return s.register1(ctx, callId, cseq, seconds)
	}

	return 0, err
}

func registerLoop(ctx context.Context, s *sipServer, callID string, registerDone chan<- struct{}) {
	var timeout time.Duration
	cseq := 1
outer:
	for {
		secs, err := s.register(ctx, callID, &cseq, 3600)
		if err != nil {
			log.Println("Register:", err)
			timeout = time.Minute
		} else {
			timeout = max(
				time.Duration(secs)*time.Second*2/3,
				time.Minute)
		}
		timer := time.NewTimer(timeout)
		select {
		case <-timer.C:
			continue
		case <-ctx.Done():
			timer.Stop()
			break outer
		}
	}

	// unregister uncoditionally, in case we're behind NAT and the
	// registrar returned some other contact.
	secs, err := s.register(context.Background(), callID, &cseq, 0)
	if err != nil || secs != 0 {
		log.Println("Unregister:", secs, err)
	}
	close(registerDone)
}

func socketPair() (*net.UDPConn, *net.UDPConn, error) {
	for i := 0; i < 100; i++ {
		rtp, err := net.ListenUDP("udp", &net.UDPAddr{})
		if err != nil {
			continue
		}
		rtpaddr := rtp.LocalAddr().(*net.UDPAddr)
		if rtpaddr.Port%2 != 0 {
			rtp.Close()
			continue
		}
		rtcp, err := net.ListenUDP("udp", &net.UDPAddr{
			Port: rtpaddr.Port + 1,
		})
		if err != nil {
			rtp.Close()
			continue
		}
		return rtp, rtcp, nil
	}
	return nil, nil, errors.New("couldn't create socket pair")
}
