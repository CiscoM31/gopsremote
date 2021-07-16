package gopsremote

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Authentication int

const (
	Basic Authentication = 1 << iota
	NTLM
	Kerberos
)

// WinRM client used for executing scripts
// TODO: Add support for NTLM and Kerberos, Only basic is supported for now
// TODO: Add support for certificate verification while initiating connections
type WinRMClient struct {
	// Target WSMAN url
	url string
	// Ip address/FQDN of the target windows machine
	ipAddress string
	// Username for authentication
	username string
	// Password for authentication
	password string
	// Authentication mechanism to be used
	// Currently only basic authentication is supported
	auth Authentication
	// HTTP Client for sending requests/responses
	client *http.Client
	// Maximum envelope size of the WinRM messages
	maxEnvelopeSize string
	// Locale of the windows machine
	locale           string
	operationTimeout string
	// port no of the WinRM listeners
	port int
}

// Creates a new WinRM client
func NewWinRMClient(ipAddress, username, password, maxEnvelopeSize, locale, operationTimeout string, port int, auth Authentication, proxy func(*http.Request) (*url.URL, error)) *WinRMClient {
	// TODO: Add validations for each of the arguments
	client := &WinRMClient{
		ipAddress:        ipAddress,
		username:         username,
		password:         password,
		auth:             auth,
		maxEnvelopeSize:  maxEnvelopeSize,
		locale:           locale,
		operationTimeout: operationTimeout,
		port:             port,
		url:              fmt.Sprintf("https://%s:%d/wsman", ipAddress, port),
		client: &http.Client{
			Transport: &http.Transport{
				Proxy: proxy,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig: &tls.Config{
					// #nosec
					InsecureSkipVerify: true,
				},
			},
		},
	}

	return client
}

func (w *WinRMClient) validate() error {
	if w.username == "" {
		return errors.New("username is empty")
	}
	if w.ipAddress == "" {
		return errors.New("ip address is empty")
	}
	// TODO: Add validations for ip address check
	if w.locale == "" {
		return errors.New("locale is empty")
	}
	// TODO: Change type of Max Envelope Size
	if w.maxEnvelopeSize == "" {
		return errors.New("max envelope size is empty")
	}
	// TODO: Change type of operation timeout
	if w.operationTimeout == "" {
		return errors.New("operation timeout is empty")
	}
	if w.password == "" {
		return errors.New("password is empty")
	}
	if w.port == 0 {
		return errors.New("port is empty")
	}
	// TODO: Add validations for authentication types
	return nil
}

// ExecuteCommand - Executes the command on the target
func (w *WinRMClient) ExecuteCommand(cmd string) (string, int, error) {
	err := w.validate()
	if err != nil {
		return "", 0, err
	}
	shellId, err := w.openShell()
	if err != nil {
		return "", 0, err
	}
	commandId, err := w.executeCommand(shellId, encodeCmd(cmd))
	defer w.closeShell(shellId)
	if err != nil {
		return "", 0, err
	}
	resp, exitCode, err := w.receive(shellId, commandId)
	if err != nil {
		return "", 0, err
	}
	return strings.TrimSpace(resp), exitCode, err
}

func encodeCmd(cmd string) string {
	newCmd := strings.Builder{}
	for _, b := range []byte(cmd) {
		newCmd.WriteString(string(b) + "\x00")
	}
	encodedCmd := base64.StdEncoding.EncodeToString([]byte(newCmd.String()))
	return "powershell.exe -EncodedCommand " + encodedCmd
}

// sendRequest - sends a WinRM request to the provided url and SOAP payload
func (w *WinRMClient) sendRequest(body *bytes.Buffer) (io.ReadCloser, error) {
	request, err := http.NewRequest(http.MethodPost, w.url, body)
	if err != nil {
		return nil, err
	}
	// TODO: Using basic authentication for now, change later
	request.SetBasicAuth(w.username, w.password)
	request.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	response, err := w.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%d\n%s", response.StatusCode, string(data))
	}
	return response.Body, nil
}

// openShell - Opens a WinRM shell on the given machine
func (w *WinRMClient) openShell() (string, error) {
	p := &PayloadBuilder{
		Url:              w.url,
		OperationTimeout: w.operationTimeout,
		Locale:           w.locale,
		MaxEnvelopeSize:  w.maxEnvelopeSize,
		OpType:           Create,
		MessageId:        uuid.NewString(),
	}
	payload, err := p.Execute()
	if err != nil {
		return "", err
	}
	body, err := w.sendRequest(payload)
	if err != nil {
		return "", err
	}
	defer body.Close()
	text, err := CaptureText(body, "Selector")
	if err != nil {
		return "", err
	}
	return text, nil
}

// ExecuteCommand - Executes the given script on the target machine
// Returns the command id of the newly created command
// TODO: base64 encode the command
func (w *WinRMClient) executeCommand(shellId, command string) (string, error) {
	p := &PayloadBuilder{
		Url:              w.url,
		OperationTimeout: w.operationTimeout,
		Locale:           w.locale,
		MaxEnvelopeSize:  w.maxEnvelopeSize,
		OpType:           Execute,
		MessageId:        uuid.NewString(),
		ShellId:          shellId,
		Command:          command,
	}
	payload, err := p.Execute()
	if err != nil {
		return "", err
	}
	body, err := w.sendRequest(payload)
	if err != nil {
		return "", err
	}
	defer body.Close()
	text, err := CaptureText(body, "CommandId")
	if err != nil {
		return "", err
	}
	return text, nil
}

// Read - Reads the output and error streams of the command with given id
// to completion
// TODO: Add timeout to this.
func (w *WinRMClient) receive(shellId, commandId string) (string, int, error) {
	for {
		p := &PayloadBuilder{
			Url:              w.url,
			OperationTimeout: w.operationTimeout,
			Locale:           w.locale,
			MaxEnvelopeSize:  w.maxEnvelopeSize,
			OpType:           Receive,
			MessageId:        uuid.NewString(),
			ShellId:          shellId,
			CommandId:        commandId,
		}
		payload, err := p.Execute()
		if err != nil {
			return "", 0, err
		}
		body, err := w.sendRequest(payload)
		if err != nil {
			return "", 0, err
		}
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		exitCode, isComplete, err := CaptureStreams(body, stdout, stderr)
		body.Close()
		if err != nil {
			return "", 0, err
		}
		if isComplete {
			output := ""
			if exitCode == "0" {
				output = stdout.String()
			} else {
				output, err = CaptureErrorMessages(stderr.String())
				if err != nil {
					return "", 0, err
				}
			}
			eCode, err := strconv.Atoi(exitCode)
			if err != nil {
				return "", 0, err
			}
			return output, eCode, nil
		}
	}
}

// Input - Sends the input to the given command
func (w *WinRMClient) input() error {
	return nil
}

// CloseShell - Closes the shell with the given id
func (w *WinRMClient) closeShell(shellId string) error {
	p := &PayloadBuilder{
		Url:              w.url,
		OperationTimeout: w.operationTimeout,
		Locale:           w.locale,
		MaxEnvelopeSize:  w.maxEnvelopeSize,
		OpType:           Delete,
		MessageId:        uuid.NewString(),
		ShellId:          shellId,
	}
	payload, err := p.Execute()
	if err != nil {
		return err
	}
	_, err = w.sendRequest(payload)
	if err != nil {
		return err
	}
	return nil
}

func CaptureAttribute(body io.Reader, tag, attr string) (string, error) {
	decoder := xml.NewDecoder(body)
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		switch d := token.(type) {
		case xml.StartElement:
			if d.Name.Local == tag {
				for _, a := range d.Attr {
					if a.Name.Local == attr {
						return a.Value, nil
					}
				}
			}

		}
	}
	return "", nil
}

func CaptureStreams(body io.Reader, stdout, stderr io.Writer) (string, bool, error) {
	decoder := xml.NewDecoder(body)
	var comp, exitCode string
	var isComplete bool
	for {
		if exitCode != "" {
			return exitCode, isComplete, nil
		}
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", false, err
		}
		switch d := token.(type) {
		case xml.StartElement:
			if d.Name.Local == "Stream" {
				for _, a := range d.Attr {
					if a.Name.Local == "Name" {
						if a.Value == "stdout" {
							comp = "stdout"
						} else if a.Value == "stderr" {
							comp = "stderr"
						}
					}
				}
			} else if d.Name.Local == "CommandState" {
				for _, a := range d.Attr {
					if a.Name.Local == "State" && a.Value == "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done" {
						isComplete = true
					}
				}
			} else if d.Name.Local == "ExitCode" {
				comp = "code"
			}
		case xml.CharData:
			switch comp {
			case "stdout":
				writeBase64Decode(d, stdout)
			case "stderr":
				writeBase64Decode(d, stderr)
			case "code":
				exitCode = strings.TrimSpace(string(d))
			}
			comp = ""
		}
	}
	return "", false, nil
}

// Decode content into base64 and writes to writer
func writeBase64Decode(b []byte, writer io.Writer) error {
	content, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return err
	}
	_, err = writer.Write(content)
	if err != nil {
		return err
	}
	return nil
}

func CaptureText(body io.Reader, tag string) (string, error) {
	decoder := xml.NewDecoder(body)
	found := false
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		switch d := token.(type) {
		case xml.StartElement:
			if d.Name.Local == tag {
				found = true
			}
		case xml.CharData:
			if found {
				return strings.TrimSpace(string(d)), nil
			}
		}
	}
	return "", nil
}

func CaptureErrorMessages(errorMessage string) (string, error) {
	index := strings.Index(errorMessage, "<Objs")
	if index == -1 {
		return errorMessage, nil
	}
	errorMessage = errorMessage[index:]
	decoder := xml.NewDecoder(strings.NewReader(errorMessage))
	builder := strings.Builder{}
	isError := false
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				return builder.String(), nil
			}
			return "", err
		}
		switch v := token.(type) {
		case xml.StartElement:
			if v.Name.Local == "S" {
				for _, a := range v.Attr {
					if a.Name.Local == "S" && a.Value == "Error" {
						isError = true
						break
					}
				}
			}
		case xml.CharData:
			if isError {
				builder.WriteString(strings.TrimSuffix(string(v), "_x000D__x000A_"))
				builder.WriteString("\n")
				isError = false
			}
		}
	}
}
