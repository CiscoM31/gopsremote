package gopsremote

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
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
func NewWinRMClient(ipAddress, username, password, maxEnvelopeSize, locale, operationTimeout string, port int, auth Authentication) *WinRMClient {
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
				Proxy: http.ProxyFromEnvironment,
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
func (w *WinRMClient) ExecuteCommand(cmd string) (string, error) {
	err := w.validate()
	if err != nil {
		return "", err
	}
	shellId, err := w.openShell()
	if err != nil {
		return "", err
	}
	// TODO: Pass the proper command after base64 encoding it
	resp, err := w.executeCommand(shellId, cmd)
	defer w.closeShell(shellId)
	if err != nil {
		return "", err
	}
	return resp, nil
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
	arr := strings.Split(text, ":")
	if len(arr) != 2 {
		return "", errors.New("invalid response")
	}
	return arr[1], nil
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
func (w *WinRMClient) recieve(shellId, commandId string) (string, int, error) {
	var cResp string
	var exitCode int
	for {
		p := &PayloadBuilder{
			Url:              w.url,
			OperationTimeout: w.operationTimeout,
			Locale:           w.locale,
			MaxEnvelopeSize:  w.maxEnvelopeSize,
			OpType:           Recieve,
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
		resp, err := CaptureText(body, "Stream")
		if err != nil {
			body.Close()
			return "", 0, err
		}
		cResp += resp
		state, err := CaptureAttribute(body, "CommandState", "State")
		if err != nil {
			body.Close()
			return "", 0, err
		}
		if state == "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done" {
			code, err := CaptureText(body, "ExitCode")
			body.Close()
			if err != nil {
				return "", 0, err
			}
			exitCode, err = strconv.Atoi(code)
			if err != nil {
				return "", 0, err
			}
			break
		}
	}

	return cResp, exitCode, nil
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

func CaptureText(body io.Reader, tag string) (string, error) {
	decoder := xml.NewDecoder(body)
	found := false
	for {
		token, err := decoder.Token()
		if err != nil {
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
