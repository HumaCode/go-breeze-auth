package breezeauth

import (
	"fmt"
	"io"
	"net/smtp"
	"os"
	"strings"
)

// Mailer interface abstracts notification delivery for resets and verification
type Mailer interface {
	SendPasswordReset(toEmail, resetURL, plainToken string) error
	SendEmailVerification(toEmail, verifyURL, plainToken string) error
}

// LogMailer prints nicely formatted email simulations to stdout or a custom writer
type LogMailer struct {
	Writer io.Writer
}

// NewLogMailer creates a console-based logger mailer
func NewLogMailer(writer ...io.Writer) *LogMailer {
	w := io.Writer(os.Stdout)
	if len(writer) > 0 && writer[0] != nil {
		w = writer[0]
	}
	return &LogMailer{Writer: w}
}

func (l *LogMailer) SendPasswordReset(toEmail, resetURL, plainToken string) error {
	separator := strings.Repeat("=", 64)
	msg := fmt.Sprintf("\n%s\n"+
		" [GO-BREEZE-AUTH] SIMULATED EMAIL: PASSWORD RESET\n"+
		"%s\n"+
		" To      : %s\n"+
		" Subject : Reset Your Password Notification\n"+
		" Link    : %s\n"+
		" Token   : %s\n"+
		"%s\n\n",
		separator, separator, toEmail, resetURL, plainToken, separator)

	_, err := fmt.Fprint(l.Writer, msg)
	return err
}

func (l *LogMailer) SendEmailVerification(toEmail, verifyURL, plainToken string) error {
	separator := strings.Repeat("=", 64)
	msg := fmt.Sprintf("\n%s\n"+
		" [GO-BREEZE-AUTH] SIMULATED EMAIL: VERIFY EMAIL ADDRESS\n"+
		"%s\n"+
		" To      : %s\n"+
		" Subject : Verify Email Address\n"+
		" Link    : %s\n"+
		" Token   : %s\n"+
		"%s\n\n",
		separator, separator, toEmail, verifyURL, plainToken, separator)

	_, err := fmt.Fprint(l.Writer, msg)
	return err
}

// SMTPConfig holds credentials for real SMTP delivery
type SMTPConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	FromEmail   string
	FromName    string
	RequireTLS  bool
}

// SMTPMailer delivers actual emails via standard net/smtp
type SMTPMailer struct {
	Config SMTPConfig
}

// NewSMTPMailer creates an SMTP mailer instance
func NewSMTPMailer(cfg SMTPConfig) *SMTPMailer {
	if cfg.FromName == "" {
		cfg.FromName = "Go Breeze Auth"
	}
	return &SMTPMailer{Config: cfg}
}

func (s *SMTPMailer) SendPasswordReset(toEmail, resetURL, plainToken string) error {
	subject := "Subject: Reset Your Password\r\n"
	from := fmt.Sprintf("From: %s <%s>\r\n", s.Config.FromName, s.Config.FromEmail)
	to := fmt.Sprintf("To: %s\r\n", toEmail)
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n"

	body := fmt.Sprintf(`
		<p>You requested a password reset for your account.</p>
		<p><a href="%s" style="display:inline-block;padding:10px 20px;background:#4F46E5;color:#fff;text-decoration:none;border-radius:5px;">Reset Password</a></p>
		<p>Or paste this link into your browser: %s</p>
		<p>Token: <code>%s</code></p>
		<p>If you did not request this, you can safely ignore this email.</p>
	`, resetURL, resetURL, plainToken)

	msg := []byte(from + to + subject + mime + body)
	addr := fmt.Sprintf("%s:%d", s.Config.Host, s.Config.Port)

	var auth smtp.Auth
	if s.Config.Username != "" || s.Config.Password != "" {
		auth = smtp.PlainAuth("", s.Config.Username, s.Config.Password, s.Config.Host)
	}

	return smtp.SendMail(addr, auth, s.Config.FromEmail, []string{toEmail}, msg)
}

func (s *SMTPMailer) SendEmailVerification(toEmail, verifyURL, plainToken string) error {
	subject := "Subject: Verify Email Address\r\n"
	from := fmt.Sprintf("From: %s <%s>\r\n", s.Config.FromName, s.Config.FromEmail)
	to := fmt.Sprintf("To: %s\r\n", toEmail)
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n"

	body := fmt.Sprintf(`
		<p>Please click the button below to verify your email address.</p>
		<p><a href="%s" style="display:inline-block;padding:10px 20px;background:#4F46E5;color:#fff;text-decoration:none;border-radius:5px;">Verify Email</a></p>
		<p>Or paste this link into your browser: %s</p>
		<p>Token: <code>%s</code></p>
	`, verifyURL, verifyURL, plainToken)

	msg := []byte(from + to + subject + mime + body)
	addr := fmt.Sprintf("%s:%d", s.Config.Host, s.Config.Port)

	var auth smtp.Auth
	if s.Config.Username != "" || s.Config.Password != "" {
		auth = smtp.PlainAuth("", s.Config.Username, s.Config.Password, s.Config.Host)
	}

	return smtp.SendMail(addr, auth, s.Config.FromEmail, []string{toEmail}, msg)
}

