



package smtpd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/mail"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axllent/mailpit/internal/smtpd/chaos"
)

var (

	Debug      = false
	rcptToRE   = regexp.MustCompile(`(?i)TO: ?<([^<>\v]+)>( |$)(.*)?`)
	mailFromRE = regexp.MustCompile(`(?i)FROM: ?<(|[^<>\v]+)>( |$)(.*)?`)


	mailFromSizeRE = regexp.MustCompile(`(?U)(^| |,)[Ss][Ii][Zz][Ee]=(.*)($|,| )`)
)



type Handler func(remoteAddr net.Addr, from string, to []string, data []byte) error



type MsgIDHandler func(remoteAddr net.Addr, from string, to []string, data []byte, username *string) (string, error)


type HandlerRcpt func(remoteAddr net.Addr, from string, to string) bool


type AuthHandler func(remoteAddr net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error)


var ErrServerClosed = errors.New("Server has been closed")




var errLineTooLong = errors.New("500 5.5.2 Line too long")




func ListenAndServe(addr string, handler Handler, appName string, hostname string) error {
	srv := &Server{Addr: addr, Handler: handler, AppName: appName, Hostname: hostname}
	return srv.ListenAndServe()
}




func ListenAndServeTLS(addr string, certFile string, keyFile string, handler Handler, appName string, hostname string) error {
	srv := &Server{Addr: addr, Handler: handler, AppName: appName, Hostname: hostname}
	err := srv.ConfigureTLS(certFile, keyFile)
	if err != nil {
		return err
	}
	return srv.ListenAndServe()
}

type maxSizeExceededError struct {
	limit int
}

func maxSizeExceeded(limit int) maxSizeExceededError {
	return maxSizeExceededError{limit}
}



func (err maxSizeExceededError) Error() string {
	return fmt.Sprintf("552 5.3.4 Requested mail action aborted: exceeded storage allocation (%d)", err.limit)
}


type LogFunc func(remoteIP, verb, line string)


type Server struct {
	Addr                     string
	AppName                  string
	AuthHandler              AuthHandler
	AuthMechs                map[string]bool
	AuthRequired             bool
	DisableReverseDNS        bool
	Handler                  Handler
	HandlerRcpt              HandlerRcpt
	Hostname                 string
	LogRead                  LogFunc
	LogWrite                 LogFunc
	MaxSize                  int
	MaxRecipients            int
	MsgIDHandler             MsgIDHandler
	IgnoreRejectedRecipients bool
	Timeout                  time.Duration
	TLSConfig                *tls.Config
	TLSListener              bool
	TLSRequired              bool
	Protocol                 string
	SocketPerm               fs.FileMode

	inShutdown   int32
	openSessions int32
	mu           sync.Mutex
	shutdownChan chan struct{}

	XClientAllowed []string
}


func (srv *Server) ConfigureTLS(certFile string, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	return nil
}




































func (srv *Server) ListenAndServe() error {
	if atomic.LoadInt32(&srv.inShutdown) != 0 {
		return ErrServerClosed
	}

	if srv.Addr == "" {
		srv.Addr = ":25"
	}
	if srv.AppName == "" {
		srv.AppName = "smtpd"
	}
	if srv.Hostname == "" {
		srv.Hostname, _ = os.Hostname()
	}
	if srv.Timeout == 0 {
		srv.Timeout = 5 * time.Minute
	}
	if srv.Protocol == "" {
		srv.Protocol = "tcp"
	}

	var ln net.Listener
	var err error


	if srv.TLSConfig != nil && srv.TLSListener {
		ln, err = tls.Listen(srv.Protocol, srv.Addr, srv.TLSConfig)
	} else {
		ln, err = net.Listen(srv.Protocol, srv.Addr)
	}

	if err != nil {
		return err
	}

	if srv.Protocol == "unix" {

		if err := os.Chmod(srv.Addr, srv.SocketPerm); err != nil {
			return err
		}
	}

	return srv.Serve(ln)
}


func (srv *Server) Serve(ln net.Listener) error {
	if atomic.LoadInt32(&srv.inShutdown) != 0 {
		return ErrServerClosed
	}

	defer func() { _ = ln.Close() }()

	for {

		select {
		case <-srv.getShutdownChan():
			return ErrServerClosed
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}

		session := srv.newSession(conn)
		atomic.AddInt32(&srv.openSessions, 1)
		go session.serve()
	}
}

type session struct {
	srv           *Server
	conn          net.Conn
	br            *bufio.Reader
	bw            *bufio.Writer
	remoteIP      string
	remoteHost    string
	remoteName    string
	xClient       string
	xClientADDR   string
	xClientNAME   string
	xClientTrust  bool
	tls           bool
	authenticated bool
	username      *string
}


func (srv *Server) newSession(conn net.Conn) (s *session) {
	s = &session{
		srv:  srv,
		conn: conn,
		br:   bufio.NewReaderSize(conn, 2048),
		bw:   bufio.NewWriter(conn),
	}


	s.remoteIP, _, _ = net.SplitHostPort(s.conn.RemoteAddr().String())
	if s.remoteIP == "" {
		s.remoteIP = "127.0.0.1"
	}
	if !s.srv.DisableReverseDNS {
		names, err := net.LookupAddr(s.remoteIP)
		if err == nil && len(names) > 0 {
			s.remoteHost = names[0]
		} else {
			s.remoteHost = "unknown"
		}
	} else {
		s.remoteHost = "unknown"
	}


	_, s.tls = s.conn.(*tls.Conn)

	for _, checkIP := range srv.XClientAllowed {
		if s.remoteIP == checkIP {
			s.xClientTrust = true
		}
	}
	return
}

func (srv *Server) getShutdownChan() <-chan struct{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.shutdownChan == nil {
		srv.shutdownChan = make(chan struct{})
	}

	return srv.shutdownChan
}

func (srv *Server) closeShutdownChan() {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.shutdownChan == nil {
		srv.shutdownChan = make(chan struct{})
	}

	select {
	case <-srv.shutdownChan:
	default:
		close(srv.shutdownChan)
	}
}


func (srv *Server) Close() error {
	atomic.StoreInt32(&srv.inShutdown, 1)
	srv.closeShutdownChan()
	return nil
}


func (srv *Server) Shutdown(ctx context.Context) error {
	atomic.StoreInt32(&srv.inShutdown, 1)
	srv.closeShutdownChan()



	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()

	for range 300 {

		if atomic.LoadInt32(&srv.openSessions) == 0 {
			break
		}

		select {
		case <-timer.C:
			timer.Reset(100 * time.Millisecond)
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	return nil
}


func (s *session) serve() {
	defer atomic.AddInt32(&s.srv.openSessions, -1)


	defer func(c net.Conn) { _ = c.Close() }(s.conn)

	var gotEHLO bool
	var from string
	var gotFROM bool
	var to []string
	var hasRejectedRecipients bool
	var buffer bytes.Buffer


	if s.srv.MaxRecipients == 0 {
		s.srv.MaxRecipients = 100
	}


	s.writef("220 %s %s ESMTP Service ready", s.srv.Hostname, s.srv.AppName)

loop:
	for {



		line, err := s.readLine()
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				s.writef("%s", err.Error())
				continue
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.writef("421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded", s.srv.Hostname, s.srv.AppName)
			}
			break
		}

		verb, args := s.parseLine(line)

		switch verb {
		case "HELO":
			s.remoteName = args
			s.writef("250 %s greets %s", s.srv.Hostname, s.remoteName)


			gotEHLO = true
			from = ""
			gotFROM = false
			to = nil
			hasRejectedRecipients = false
			buffer.Reset()
		case "EHLO":
			s.remoteName = args
			s.writef("%s", s.makeEHLOResponse())


			gotEHLO = true
			from = ""
			gotFROM = false
			to = nil
			hasRejectedRecipients = false
			buffer.Reset()
		case "MAIL":
			if s.srv.TLSConfig != nil && s.srv.TLSRequired && !s.tls {
				s.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			if s.srv.AuthHandler != nil && s.srv.AuthRequired && !s.authenticated {
				s.writef("530 5.7.0 Authentication required")
				break
			}
			if !gotEHLO {
				s.writef("503 5.5.1 Bad sequence of commands (HELO/EHLO required before MAIL)")
				break
			}
			if to != nil {
				s.writef("503 5.5.1 Bad sequence of commands (RSET/HELO/EHLO required before MAIL)")
				break
			}

			match, err := extractAndValidateAddress(mailFromRE, args)
			if match == nil {
				if err != nil {
					s.writef("%s", err.Error())
				} else {
					s.writef("501 5.5.4 Syntax error in parameters or arguments (invalid FROM parameter)")
				}
			} else {

				if fail, code := chaos.Config.Sender.Trigger(); fail {
					s.writef("%d Chaos sender error", code)
					break
				}


				if len(match[2]) > 0 {
					sizeMatch := mailFromSizeRE.FindStringSubmatch(match[3])
					if sizeMatch == nil {

						from = match[1]
						gotFROM = true
						s.writef("250 2.1.0 Ok")
					} else {

						size, err := strconv.Atoi(sizeMatch[2])
						if err != nil {
							s.writef("501 5.5.4 Syntax error in parameters or arguments (invalid SIZE parameter)")
						} else if s.srv.MaxSize > 0 && size > s.srv.MaxSize {
							err = maxSizeExceeded(s.srv.MaxSize)
							s.writef("%s", err.Error())
						} else {
							from = match[1]
							gotFROM = true
							s.writef("250 2.1.0 Ok")
						}
					}
				} else {
					from = match[1]
					gotFROM = true
					s.writef("250 2.1.0 Ok")
				}
			}

			to = nil
			hasRejectedRecipients = false
			buffer.Reset()
		case "RCPT":
			if s.srv.TLSConfig != nil && s.srv.TLSRequired && !s.tls {
				s.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			if s.srv.AuthHandler != nil && s.srv.AuthRequired && !s.authenticated {
				s.writef("530 5.7.0 Authentication required")
				break
			}
			if !gotFROM {
				s.writef("503 5.5.1 Bad sequence of commands (MAIL required before RCPT)")
				break
			}

			match, err := extractAndValidateAddress(rcptToRE, args)
			if match == nil {
				if err != nil {
					s.writef("%s", err.Error())
				} else {
					s.writef("501 5.5.4 Syntax error in parameters or arguments (invalid TO parameter)")
				}
			} else {

				if fail, code := chaos.Config.Recipient.Trigger(); fail {
					s.writef("%d Chaos recipient error", code)
					break
				}

				if len(to) >= s.srv.MaxRecipients {
					s.writef("452 4.5.3 Too many recipients")
				} else {
					accept := true
					if s.srv.HandlerRcpt != nil {
						accept = s.srv.HandlerRcpt(s.conn.RemoteAddr(), from, match[1])
					}
					if accept {
						to = append(to, match[1])
						s.writef("250 2.1.5 Ok")
					} else if s.srv.IgnoreRejectedRecipients {
						hasRejectedRecipients = true
						s.writef("250 2.1.5 Ok")
					} else {
						s.writef("550 5.1.0 Requested action not taken: mailbox unavailable")
					}
				}
			}
		case "DATA":
			if s.srv.TLSConfig != nil && s.srv.TLSRequired && !s.tls {
				s.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			if s.srv.AuthHandler != nil && s.srv.AuthRequired && !s.authenticated {
				s.writef("530 5.7.0 Authentication required")
				break
			}
			hasRecipients := len(to) > 0 || hasRejectedRecipients
			if !gotFROM || !hasRecipients {
				s.writef("503 5.5.1 Bad sequence of commands (MAIL & RCPT required before DATA)")
				break
			}

			s.writef("354 Start mail input; end with <CR><LF>.<CR><LF>")





			data, err := s.readData()
			if err != nil {
				switch err := err.(type) {
				case net.Error:
					if err.Timeout() {
						s.writef("421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded", s.srv.Hostname, s.srv.AppName)
					}
					break loop
				case maxSizeExceededError:
					s.writef("%s", err.Error())
					continue
				default:
					s.writef("451 4.3.0 Requested action aborted: local error in processing")
					continue
				}
			}


			buffer.Reset()
			if len(to) > 0 {
				buffer.Write(s.makeHeaders(to))
			}
			buffer.Write(data)


			if len(to) > 0 && s.srv.Handler != nil {
				err := s.srv.Handler(s.conn.RemoteAddr(), from, to, buffer.Bytes())
				if err != nil {
					checkErrFormat := regexp.MustCompile(`^([2-5][0-9]{2})[\s\-](.+)$`)
					if checkErrFormat.MatchString(err.Error()) {
						s.writef("%s", err.Error())
					} else {
						s.writef("451 4.3.5 Unable to process mail")
					}
					break
				}
				s.writef("250 2.0.0 Ok: queued")
			} else if len(to) > 0 && s.srv.MsgIDHandler != nil {
				msgID, err := s.srv.MsgIDHandler(s.conn.RemoteAddr(), from, to, buffer.Bytes(), s.username)
				if err != nil {
					checkErrFormat := regexp.MustCompile(`^([2-5][0-9]{2})[\s\-](.+)$`)
					if checkErrFormat.MatchString(err.Error()) {
						s.writef("%s", err.Error())
					} else {
						s.writef("451 4.3.5 Unable to process mail")
					}
					break
				}

				if msgID != "" {
					s.writef("250 2.0.0 Ok: queued as %s", msgID)
				} else {
					s.writef("250 2.0.0 Ok: queued")
				}
			} else {
				if hasRejectedRecipients && Debug {
					if s.srv.LogWrite != nil {
						s.srv.LogWrite(s.remoteIP, "DEBUG", "Message from sender silently dropped (rejected recipients)")
					} else {
						log.Printf("%s DEBUG Message from sender silently dropped (rejected recipients)", s.remoteIP)
					}
				}
				s.writef("250 2.0.0 Ok: queued")
			}


			from = ""
			gotFROM = false
			to = nil
			hasRejectedRecipients = false
			buffer.Reset()
		case "QUIT":
			s.writef("221 2.0.0 %s %s ESMTP Service closing transmission channel", s.srv.Hostname, s.srv.AppName)
			break loop
		case "RSET":
			if s.srv.TLSConfig != nil && s.srv.TLSRequired && !s.tls {
				s.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			s.writef("250 2.0.0 Ok")
			from = ""
			gotFROM = false
			to = nil
			hasRejectedRecipients = false
			buffer.Reset()
		case "NOOP":
			s.writef("250 2.0.0 Ok")
		case "XCLIENT":
			s.xClient = args
			if s.xClientTrust {
				xCArgs := strings.SplitSeq(args, " ")
				for xCArg := range xCArgs {
					xCParse := strings.Split(strings.TrimSpace(xCArg), "=")
					if len(xCParse) != 2 {
						continue
					}
					if strings.ToUpper(xCParse[0]) == "ADDR" && (net.ParseIP(xCParse[1]) != nil) {
						s.xClientADDR = xCParse[1]
					}
					if strings.ToUpper(xCParse[0]) == "NAME" && len(xCParse[1]) > 0 {
						if xCParse[1] != "[UNAVAILABLE]" {
							s.xClientNAME = xCParse[1]
						}
					}
				}
				if len(s.xClientADDR) > 7 {
					s.remoteIP = s.xClientADDR
					if len(s.xClientNAME) > 4 {
						s.remoteHost = s.xClientNAME
					} else {
						names, err := net.LookupAddr(s.remoteIP)
						if err == nil && len(names) > 0 {
							s.remoteHost = names[0]
						} else {
							s.remoteHost = "unknown"
						}
					}
				}
			}
			s.writef("250 2.0.0 Ok")
		case "HELP", "VRFY", "EXPN":

			s.writef("502 5.5.1 Command not implemented")
		case "STARTTLS":

			if args != "" {
				s.writef("501 5.5.2 Syntax error (no parameters allowed)")
				break
			}


			if s.srv.TLSConfig == nil {
				s.writef("502 5.5.1 Command not implemented")
				break
			}


			if s.tls {
				s.writef("503 5.5.1 Bad sequence of commands (TLS already in use)")
				break
			}

			s.writef("220 2.0.0 Ready to start TLS")


			tlsConn := tls.Server(s.conn, s.srv.TLSConfig)
			err := tlsConn.Handshake()
			if err != nil {
				s.writef("403 4.7.0 TLS handshake failed")
				break
			}


			s.conn = tlsConn
			s.br = bufio.NewReaderSize(s.conn, 2048)
			s.bw = bufio.NewWriter(s.conn)
			s.tls = true


			s.remoteName = ""
			from = ""
			gotFROM = false
			to = nil
			hasRejectedRecipients = false
			buffer.Reset()
		case "AUTH":
			if s.srv.TLSConfig != nil && s.srv.TLSRequired && !s.tls {
				s.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}

			if s.srv.AuthHandler == nil {
				s.writef("502 5.5.1 Command not implemented")
				break
			}


			if s.authenticated {
				s.writef("503 5.5.1 Bad sequence of commands (already authenticated for this session)")
				break
			}


			if gotFROM || len(to) > 0 {
				s.writef("503 5.5.1 Bad sequence of commands (AUTH not permitted during mail transaction)")
				break
			}


			authType, authArgs := s.parseLine(args)
			if authType == "" {
				s.writef("501 5.5.4 Malformed AUTH input (argument required)")
				break
			}


			allowedAuth := s.authMechs()
			if allowed, found := allowedAuth[authType]; !found || !allowed {
				s.writef("504 5.5.4 Unrecognized authentication type")
				break
			}


			if fail, code := chaos.Config.Authentication.Trigger(); fail {
				s.writef("%d Chaos authentication error", code)
				break
			}




			switch authType {
			case "PLAIN":
				s.authenticated, err = s.handleAuthPlain(authArgs)
			case "LOGIN":
				s.authenticated, err = s.handleAuthLogin(authArgs)
			case "CRAM-MD5":
				s.authenticated, err = s.handleAuthCramMD5()
			}

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					s.writef("421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded", s.srv.Hostname, s.srv.AppName)
					break loop
				}

				s.writef("%s", err.Error())
				break
			}

			if s.authenticated {
				s.writef("235 2.7.0 Authentication successful")
			} else {
				s.writef("535 5.7.8 Authentication credentials invalid")
			}
		default:

			s.writef("500 5.5.2 Syntax error, command unrecognized")
		}
	}
}


func (s *session) writef(format string, args ...any) {
	if s.srv.Timeout > 0 {
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.srv.Timeout))
	}

	line := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(s.bw, "%s\r\n", line)
	_ = s.bw.Flush()

	if Debug {
		verb := "WROTE"
		if s.srv.LogWrite != nil {
			s.srv.LogWrite(s.remoteIP, verb, line)
		} else {
			log.Println(s.remoteIP, verb, line)
		}
	}
}




func (s *session) readLine() (string, error) {
	if s.srv.Timeout > 0 {
		_ = s.conn.SetReadDeadline(time.Now().Add(s.srv.Timeout))
	}

	lineBytes, isPrefix, err := s.br.ReadLine()
	if err != nil {
		return "", err
	}

	if isPrefix {

		for isPrefix {
			_, isPrefix, err = s.br.ReadLine()
			if err != nil {
				return "", err
			}
		}
		return "", errLineTooLong
	}

	line := strings.TrimSpace(string(lineBytes))

	if Debug {
		verb := "READ"
		if s.srv.LogRead != nil {
			s.srv.LogRead(s.remoteIP, verb, line)
		} else {
			log.Println(s.remoteIP, verb, line)
		}
	}

	return line, nil
}


func (s *session) parseLine(line string) (verb string, args string) {
	if before, after, ok := strings.Cut(line, " "); ok {
		verb = strings.ToUpper(before)
		args = strings.TrimSpace(after)
	} else {
		verb = strings.ToUpper(line)
		args = ""
	}
	return verb, args
}


func (s *session) readData() ([]byte, error) {
	var data []byte
	for {
		if s.srv.Timeout > 0 {
			_ = s.conn.SetReadDeadline(time.Now().Add(s.srv.Timeout))
		}




		var line []byte
		for {
			fragment, err := s.br.ReadSlice('\n')
			line = append(line, fragment...)
			if err == nil {
				break
			}
			if err != bufio.ErrBufferFull {
				return nil, err
			}

			if s.srv.MaxSize > 0 && len(data)+len(line) > s.srv.MaxSize {
				_, _ = s.br.Discard(s.br.Buffered())
				return nil, maxSizeExceeded(s.srv.MaxSize)
			}
		}

		if bytes.Equal(line, []byte(".\r\n")) {
			break
		}

		if line[0] == '.' {
			line = line[1:]
		}

		if s.srv.MaxSize > 0 && len(data)+len(line) > s.srv.MaxSize {
			_, _ = s.br.Discard(s.br.Buffered())
			return nil, maxSizeExceeded(s.srv.MaxSize)
		}

		data = append(data, line...)
	}
	return data, nil
}



func (s *session) makeHeaders(to []string) []byte {
	var buffer bytes.Buffer
	if len(to) == 0 {
		return buffer.Bytes()
	}

	now := time.Now().Format("Mon, 2 Jan 2006 15:04:05 -0700 (MST)")
	fmt.Fprintf(&buffer, "Received: from %s (%s [%s])\r\n", s.remoteName, s.remoteHost, s.remoteIP)
	fmt.Fprintf(&buffer, "        by %s (%s) with SMTP\r\n", s.srv.Hostname, s.srv.AppName)
	fmt.Fprintf(&buffer, "        for <%s>; %s\r\n", to[0], now)
	return buffer.Bytes()
}




func (s *session) authMechs() (mechs map[string]bool) {
	mechs = map[string]bool{"LOGIN": s.tls, "PLAIN": s.tls, "CRAM-MD5": true}

	for mech := range mechs {
		allowed, found := s.srv.AuthMechs[mech]
		if found {
			mechs[mech] = allowed
		}
	}

	return
}


func (s *session) makeEHLOResponse() (response string) {
	response = fmt.Sprintf("250-%s greets %s\r\n", s.srv.Hostname, s.remoteName)


	response += fmt.Sprintf("250-SIZE %d\r\n", s.srv.MaxSize)


	if s.srv.TLSConfig != nil && !s.tls {
		response += "250-STARTTLS\r\n"
	}


	if s.srv.AuthHandler != nil {
		var mechs []string
		for mech, allowed := range s.authMechs() {
			if allowed {
				mechs = append(mechs, mech)
			}
		}
		if len(mechs) > 0 {
			response += "250-AUTH " + strings.Join(mechs, " ") + "\r\n"
		}
	}

	response += "250-ENHANCEDSTATUSCODES\r\n"



	response += "250-8BITMIME\r\n"
	response += "250 SMTPUTF8"
	return
}

func (s *session) handleAuthLogin(arg string) (bool, error) {
	var err error

	if arg == "" {
		s.writef("334 %s", base64.StdEncoding.EncodeToString([]byte("Username:")))
		arg, err = s.readLine()
		if err != nil {
			return false, err
		}
	}

	username, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}

	s.writef("334 %s", base64.StdEncoding.EncodeToString([]byte("Password:")))
	line, err := s.readLine()
	if err != nil {
		return false, err
	}

	password, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}


	authenticated, err := s.srv.AuthHandler(s.conn.RemoteAddr(), "LOGIN", username, password, nil)
	if authenticated {
		uname := string(username)
		s.username = &uname
	} else {
		s.username = nil
	}

	return authenticated, err
}

func (s *session) handleAuthPlain(arg string) (bool, error) {
	var err error


	if arg == "" {
		s.writef("334 ")
		arg, err = s.readLine()
		if err != nil {
			return false, err
		}
	}

	data, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}

	parts := bytes.Split(data, []byte{0})
	if len(parts) != 3 {
		return false, errors.New("501 5.5.2 Syntax error (unable to parse)")
	}


	authenticated, err := s.srv.AuthHandler(s.conn.RemoteAddr(), "PLAIN", parts[1], parts[2], nil)
	if authenticated {
		uname := string(parts[1])
		s.username = &uname
	} else {
		s.username = nil
	}

	return authenticated, err
}

func (s *session) handleAuthCramMD5() (bool, error) {
	shared := "<" + strconv.Itoa(os.Getpid()) + "." + strconv.Itoa(time.Now().Nanosecond()) + "@" + s.srv.Hostname + ">"

	s.writef("334 %s", base64.StdEncoding.EncodeToString([]byte(shared)))

	data, err := s.readLine()
	if err != nil {
		return false, err
	}

	if data == "*" {
		return false, errors.New("501 5.7.0 Authentication cancelled")
	}

	buf, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}

	fields := strings.Split(string(buf), " ")
	if len(fields) < 2 {
		return false, errors.New("501 5.5.2 Syntax error (unable to parse)")
	}


	authenticated, err := s.srv.AuthHandler(s.conn.RemoteAddr(), "CRAM-MD5", []byte(fields[0]), []byte(fields[1]), []byte(shared))

	return authenticated, err
}



func extractAndValidateAddress(re *regexp.Regexp, args string) ([]string, error) {
	match := re.FindStringSubmatch(args)
	if match == nil {
		return nil, nil
	}

	if strings.Contains(match[1], " ") {
		return nil, errors.New("553 5.1.3 The address is not a valid RFC 5321 address")
	}


	if match[1] != "" {
		a, err := mail.ParseAddress(match[1])
		if err != nil {
			return nil, errors.New("553 5.1.3 The address is not a valid RFC 5321 address")
		}






		if len(a.Address) > 1024 {
			return nil, errors.New("500 The address is too long")
		}
	}

	return match, nil
}
