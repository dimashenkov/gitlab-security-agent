
package smtpd

import (
	"bytes"
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strings"

	"github.com/axllent/mailpit/config"
	"github.com/axllent/mailpit/internal/auth"
	"github.com/axllent/mailpit/internal/logger"
	"github.com/axllent/mailpit/internal/shortuuid"
	"github.com/axllent/mailpit/internal/stats"
	"github.com/axllent/mailpit/internal/storage"
	"github.com/axllent/mailpit/internal/tools"
	"github.com/axllent/mailpit/server/websockets"
	"github.com/pkg/errors"
)

var (

	DisableReverseDNS bool

	warningResponse = regexp.MustCompile(`^4\d\d `)
	errorResponse   = regexp.MustCompile(`^5\d\d `)
)


func mailHandler(origin net.Addr, from string, to []string, data []byte, smtpUser *string) (string, error) {
	return SaveToDatabase(origin, from, to, data, smtpUser)
}


func SaveToDatabase(origin net.Addr, from string, to []string, data []byte, smtpUser *string) (string, error) {
	if !config.SMTPStrictRFCHeaders && bytes.Contains(data, []byte("\r\r\n")) {


		data = bytes.ReplaceAll(data, []byte("\r\r\n"), []byte("\r\n"))
	}

	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		logger.Log().Warnf("[smtpd] error parsing message: %s", err.Error())
		stats.LogSMTPRejected()
		return "", err
	}


	returnPath := strings.Trim(msg.Header.Get("Return-Path"), "<>")
	if returnPath != from {
		data, err = tools.SetMessageHeader(data, "Return-Path", "<"+from+">")
		if err != nil {
			return "", err
		}
	}

	messageID := strings.Trim(msg.Header.Get("Message-ID"), "<>")


	if messageID == "" {

		messageID = shortuuid.New() + "@mailpit"

		data = append([]byte("Message-ID: <"+messageID+">\r\n"), data...)
	} else if config.IgnoreDuplicateIDs {
		if storage.MessageIDExists(messageID) {
			logger.Log().Debugf("[smtpd] duplicate message found, ignoring %s", messageID)
			stats.LogSMTPIgnored()
			return "", nil
		}
	}


	if relayErr := autoRelayMessage(from, to, &data); relayErr != nil {
		logger.Log().Error(relayErr.Error())

		if config.SMTPRelayConfig.ForwardSMTPErrors {
			for {
				unwrappedErr := errors.Unwrap(relayErr)
				if unwrappedErr == nil {
					break
				}
				relayErr = unwrappedErr
			}
			return "", relayErr
		}
	}


	if forwardErr := autoForwardMessage(from, &data); forwardErr != nil {
		logger.Log().Error(forwardErr.Error())

		if config.SMTPForwardConfig.ForwardSMTPErrors {
			for {
				unwrappedErr := errors.Unwrap(forwardErr)
				if unwrappedErr == nil {
					break
				}
				forwardErr = unwrappedErr
			}
			return "", forwardErr
		}
	}


	emails, hasBccHeader := scanAddressesInHeader(msg.Header)

	missingAddresses := []string{}
	for _, a := range to {

		if _, err := mail.ParseAddress(a); err == nil {
			_, ok := emails[strings.ToLower(a)]
			if !ok {
				missingAddresses = append(missingAddresses, a)
			}
		} else {
			logger.Log().Warnf("[smtpd] ignoring invalid email address: %s", a)
		}
	}


	if len(missingAddresses) > 0 {
		bccVal := strings.Join(missingAddresses, ", ")
		if hasBccHeader {
			b := msg.Header.Get("Bcc")
			bccVal = ", " + b
		}

		data, err = tools.SetMessageHeader(data, "Bcc", bccVal)
		if err != nil {
			return "", err
		}

		logger.Log().Debugf("[smtpd] added missing addresses to Bcc header: %s", strings.Join(missingAddresses, ", "))
	}

	id, err := storage.Store(&data, smtpUser)
	if err != nil {
		logger.Log().Errorf("[db] error storing message: %s", err.Error())
		return "", err
	}

	stats.LogSMTPAccepted(len(data))

	data = nil

	subject := msg.Header.Get("Subject")
	logger.Log().Debugf("[smtpd] received (%s) from:%s subject:%q", cleanIP(origin), from, subject)

	return id, err
}

func authHandler(remoteAddr net.Addr, mechanism string, username []byte, password []byte, _ []byte) (bool, error) {
	allow := auth.SMTPCredentials.Match(string(username), string(password))
	if allow {
		logger.Log().Debugf("[smtpd] allow %s login:%q from:%s", mechanism, string(username), cleanIP(remoteAddr))
	} else {
		logger.Log().Warnf("[smtpd] deny %s login:%q from:%s", mechanism, string(username), cleanIP(remoteAddr))
	}

	return allow, nil
}


func authHandlerAny(remoteAddr net.Addr, mechanism string, username []byte, _ []byte, _ []byte) (bool, error) {
	logger.Log().Debugf("[smtpd] allow %s login %q from %s", mechanism, string(username), cleanIP(remoteAddr))

	return true, nil
}


func handlerRcpt(remoteAddr net.Addr, from string, to string) bool {
	if config.SMTPAllowedRecipientsRegexp == nil {
		return true
	}

	result := config.SMTPAllowedRecipientsRegexp.MatchString(to)

	if !result {
		logger.Log().Warnf("[smtpd] rejected message to %s from %s (%s)", to, from, cleanIP(remoteAddr))
		stats.LogSMTPRejected()
	}

	return result
}


func Listen() error {
	if config.SMTPAuthAllowInsecure {
		if auth.SMTPCredentials != nil {
			logger.Log().Info("[smtpd] enabling login authentication (insecure)")
		} else if config.SMTPAuthAcceptAny {
			logger.Log().Info("[smtpd] enabling any authentication (insecure)")
		}
	} else {
		if auth.SMTPCredentials != nil {
			logger.Log().Info("[smtpd] enabling login authentication")
		} else if config.SMTPAuthAcceptAny {
			logger.Log().Info("[smtpd] enabling any authentication")
		}
	}

	return listenAndServe(config.SMTPListen, mailHandler, authHandler)
}


func verbLogTranslator(verb string) string {
	if verb == "READ" {
		return "received"
	}

	return "response"
}

func listenAndServe(addr string, handler MsgIDHandler, authHandler AuthHandler) error {

	socketAddr, perm, isSocket := tools.UnixSocket(addr)

	Debug = true
	srv := &Server{
		Addr:                     addr,
		MsgIDHandler:             handler,
		HandlerRcpt:              handlerRcpt,
		AppName:                  "Mailpit",
		Hostname:                 "",
		AuthHandler:              nil,
		AuthRequired:             false,
		MaxRecipients:            config.SMTPMaxRecipients,
		IgnoreRejectedRecipients: config.SMTPIgnoreRejectedRecipients,
		DisableReverseDNS:        DisableReverseDNS,
		LogRead: func(remoteIP, verb, line string) {
			logger.Log().Debugf("[smtpd] %s (%s) %s", verbLogTranslator(verb), remoteIP, line)
		},
		LogWrite: func(remoteIP, verb, line string) {
			if warningResponse.MatchString(line) {
				logger.Log().Warnf("[smtpd] %s (%s) %s", verbLogTranslator(verb), remoteIP, line)
				websockets.BroadCastClientError("warning", "smtpd", remoteIP, line)
			} else if errorResponse.MatchString(line) {
				logger.Log().Errorf("[smtpd] %s (%s) %s", verbLogTranslator(verb), remoteIP, line)
				websockets.BroadCastClientError("error", "smtpd", remoteIP, line)
			} else {
				logger.Log().Debugf("[smtpd] %s (%s) %s", verbLogTranslator(verb), remoteIP, line)
			}
		},
	}

	if config.MaxMessageSize > 0 {
		srv.MaxSize = config.MaxMessageSize * 1024 * 1024
	}

	if config.Label != "" {
		srv.AppName = fmt.Sprintf("Mailpit (%s)", config.Label)
	}

	if config.SMTPAuthAllowInsecure {
		srv.AuthMechs = map[string]bool{
			"CRAM-MD5": false,
			"PLAIN":    true,
			"LOGIN":    true,
		}
	}

	if auth.SMTPCredentials != nil {
		srv.AuthMechs = map[string]bool{
			"CRAM-MD5": false,
			"PLAIN":    true,
			"LOGIN":    true,
		}
		srv.AuthHandler = authHandler
		srv.AuthRequired = true
	} else if config.SMTPAuthAcceptAny {
		srv.AuthMechs = map[string]bool{
			"CRAM-MD5": false,
			"PLAIN":    true,
			"LOGIN":    true,
		}
		srv.AuthHandler = authHandlerAny
	}

	if config.SMTPTLSCert != "" {
		srv.TLSRequired = config.SMTPRequireSTARTTLS
		srv.TLSListener = config.SMTPRequireTLS
		if err := srv.ConfigureTLS(config.SMTPTLSCert, config.SMTPTLSKey); err != nil {
			return err
		}
	}

	if isSocket {
		srv.Addr = socketAddr
		srv.Protocol = "unix"
		srv.SocketPerm = perm

		if err := tools.PrepareSocket(srv.Addr); err != nil {
			storage.Close()
			return err
		}


		storage.AddTempFile(srv.Addr)

		logger.Log().Infof("[smtpd] starting on %s", config.SMTPListen)
	} else {
		smtpType := "no encryption"

		if config.SMTPTLSCert != "" {
			if config.SMTPRequireTLS {
				smtpType = "SSL/TLS required"
			} else if config.SMTPRequireSTARTTLS {
				smtpType = "STARTTLS required"
			} else {
				smtpType = "STARTTLS optional"
				if !config.SMTPAuthAllowInsecure && auth.SMTPCredentials != nil {
					smtpType = "STARTTLS required"
				}
			}
		}

		logger.Log().Infof("[smtpd] starting on %s (%s)", config.SMTPListen, smtpType)
	}

	return srv.ListenAndServe()
}

func cleanIP(i net.Addr) string {
	parts := strings.Split(i.String(), ":")

	return parts[0]
}



func scanAddressesInHeader(h mail.Header) (map[string]bool, bool) {
	emails := make(map[string]bool)
	hasBccHeader := false

	if recipients, err := h.AddressList("To"); err == nil {
		for _, r := range recipients {
			emails[strings.ToLower(r.Address)] = true
		}
	}

	if recipients, err := h.AddressList("Cc"); err == nil {
		for _, r := range recipients {
			emails[strings.ToLower(r.Address)] = true
		}
	}

	recipients, err := h.AddressList("Bcc")
	if err == nil {
		for _, r := range recipients {
			emails[strings.ToLower(r.Address)] = true
		}

		hasBccHeader = true
	}

	return emails, hasBccHeader
}
