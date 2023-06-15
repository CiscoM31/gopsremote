package gopsremote

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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

	"github.com/Azure/go-ntlmssp"
	"github.com/google/uuid"
)

type Authentication int

const (
	Basic Authentication = 1 << iota
	NTLM
	Kerberos
)

const (
	WINRM_HTTP_PORT = 5985
	CHUNK           = 512
	SCRIPTSEPARATOR = "\n"
)

// WinRM client used for executing scripts
// TODO: Add support for NTLM and Kerberos, Only basic is supported for now
// TODO: Add support for certificate verification while initiating connections
type WinRMClient struct {
	// Target WSMAN url
	url string
	// Target Details
	endpointDetails
	// HTTP Client for sending requests/responses
	client *http.Client
	// Settings to be applied to the winrm session
	winrmSettings
}

// winrmSettings holds the set of configurable properties
// required to set up a winrm session
type winrmSettings struct {
	// Port no of the HTTPS winrm listeners
	port int
	// Maximum envelope size of the WinRM messages
	maxEnvelopeSize string
	// Locale of the windows machine
	locale string
	// operationTimeout of the WinRM operation
	operationTimeout string
	// Timeout of each HTTP call made
	timeout int
	// Whether the call is http or https
	isSecure bool
}

type getEndpointDetails func() endpointDetails

func Endpoint(ipAddress, username, password string, auth Authentication, proxy func(*http.Request) (*url.URL, error)) getEndpointDetails {
	return func() endpointDetails {
		return endpointDetails{
			ipAddress: ipAddress,
			username:  username,
			password:  password,
			auth:      auth,
			proxy:     proxy,
		}
	}
}

// endpointDetails holds the target windows machine credentials.
type endpointDetails struct {
	// Ip address/FQDN of the target windows machine
	ipAddress string
	// Username for authentication
	username string
	// Password for authentication
	password string
	// Authentication mechanism to be used
	// Currently only basic authentication is supported
	auth Authentication
	// Proxy function
	proxy func(*http.Request) (*url.URL, error)
}

type result struct {
	err      error
	exitCode int
	response string
}

type winrmSettingsOption func(winrmSettings) winrmSettings

func Timeout(timeout int) winrmSettingsOption {
	return func(ws winrmSettings) winrmSettings {
		ws.timeout = timeout
		return ws
	}
}

func Port(num int) winrmSettingsOption {
	return func(ws winrmSettings) winrmSettings {
		ws.port = num
		return ws
	}
}

func IsSecure(b bool) winrmSettingsOption {
	return func(ws winrmSettings) winrmSettings {
		ws.isSecure = b
		return ws
	}
}

func MaxEnvelopeSize(size string) winrmSettingsOption {
	return func(ws winrmSettings) winrmSettings {
		ws.maxEnvelopeSize = size
		return ws
	}
}

func Locale(locale string) winrmSettingsOption {
	return func(ws winrmSettings) winrmSettings {
		ws.locale = locale
		return ws
	}
}

func OperationTimeout(operationTimeout int) winrmSettingsOption {
	return func(ws winrmSettings) winrmSettings {
		ws.operationTimeout = convertToXsdDuration(operationTimeout)
		return ws
	}
}

// Converts the timeout in seconds to xsd duration format
func convertToXsdDuration(timeout int) string {
	// If not timeout is given default to 60s
	if timeout == 0 {
		timeout = 60
	}
	var hours, minutes, seconds int
	hours, minutes = timeout/3600, timeout%3600
	minutes, seconds = minutes/60, minutes%60
	d := "PT"
	if hours != 0 {
		d += strconv.Itoa(hours) + "H"
	}
	if minutes != 0 {
		d += strconv.Itoa(minutes) + "M"
	}
	if seconds != 0 {
		d += strconv.Itoa(seconds) + "S"
	}
	return d
}

var defaultWinrmSettings winrmSettings = winrmSettings{
	port:             5986,
	maxEnvelopeSize:  "153200",
	locale:           "en-US",
	operationTimeout: "PT60.000S",
	isSecure:         true,
}

// Creates a new WinRM client
func NewWinRMClient(details getEndpointDetails, options ...winrmSettingsOption) *WinRMClient {
	// TODO: Add validations for each of the arguments
	client := &WinRMClient{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).DialContext,
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
	client.endpointDetails = details()
	client.winrmSettings = defaultWinrmSettings
	for _, o := range options {
		client.winrmSettings = o(client.winrmSettings)
	}
	if client.isSecure {
		client.url = fmt.Sprintf("https://%s:%d/wsman", client.ipAddress, client.port)
	} else {
		client.url = fmt.Sprintf("http://%s:%d/wsman", client.ipAddress, client.port)
	}
	if client.endpointDetails.auth&NTLM == NTLM {
		client.client.Transport = ntlmssp.Negotiator{RoundTripper: client.client.Transport}
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
	defer w.closeShell(shellId)
	ctx := context.Background()
	if w.timeout != 0 {
		ctx, _ = context.WithTimeout(ctx, time.Second*time.Duration(w.timeout))
	}
	ch := make(chan result, 1)
	go func() {
		var response string
		var exitCode int
		var err error
		eCmd := encodeCmd(cmd)
		if len(eCmd) < 8000 {
			response, exitCode, err = w.executeSingleCmd(cmd, shellId)
		} else {
			response, exitCode, err = w.executeScript(cmd, shellId)
		}
		ch <- result{
			err:      err,
			exitCode: exitCode,
			response: response,
		}
	}()
	select {
	case <-ctx.Done():
		// Time limit has expired, return timeout error
		return "", -1, errors.New("timeout")
	case r := <-ch:
		return r.response, r.exitCode, r.err
	}
}

// executeScript - copies the given script to a temporary location on the target machine
// and passes it as input to the powershell.
func (w *WinRMClient) executeScript(script, shellId string) (string, int, error) {
	filename, err := w.copyToTempFile(shellId, script)
	if err != nil {
		return "", 0, err
	}
	defer w.executeSingleCmd("Remove-Item -Path '"+filename+"' -Force", shellId)
	commandId, err := w.execute(shellId, "powershell.exe -f \""+filename+"\"")
	if err != nil {
		return "", 0, err
	}
	resp, exitCode, err := w.receive(shellId, commandId)
	if err != nil {
		return "", 0, err
	}
	return strings.TrimSpace(resp), exitCode, err
}

// executeSingleCmd - Executes a single powershell command
// It is assumed that the command line size for the command to be executed is below 8192
func (w *WinRMClient) executeSingleCmd(cmd, shellId string) (string, int, error) {
	commandId, err := w.execute(shellId, "powershell.exe -EncodedCommand "+encodeCmd(cmd))
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
	return base64.StdEncoding.EncodeToString([]byte(newCmd.String()))
}

// copyToTempFile copies the script to a file in %temp% folder
// and returns the absolute path to file
func (w *WinRMClient) copyToTempFile(shellId, script string) (string, error) {
	// Creating the file
	createFileScript := `
	$path=$env:TEMP + '\%s'
	New-Item -Path $path -ItemType File | Out-Null
	echo $path
	`
	base64Decode := `
	function Decode-Base64
	{
		[CmdletBinding()]
		Param(
			[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
			[string] $Line
		)

		Process
		{
			$bytes = [System.Convert]::FromBase64String($Line)
			[System.Text.Encoding]::ASCII.GetString($bytes)
		}
	}
	`
	filename := uuid.New().String() + ".ps1"
	resp, exitCode, err := w.executeSingleCmd(fmt.Sprintf(createFileScript, filename), shellId)
	if err != nil {
		return "", err
	}
	if exitCode != 0 {
		return "", errors.New(resp)
	}
	filename = resp
	scriptsArray := strings.Split(script, SCRIPTSEPARATOR)
	for _, scp := range scriptsArray {
		if len(scp) < CHUNK {
			resp, exitCode, err = w.executeSingleCmd(fmt.Sprintf("%s\necho '%s' | Decode-Base64 | Out-File -FilePath %s -Append", base64Decode, base64.StdEncoding.EncodeToString([]byte(scp)), filename), shellId)
		} else {
			// Processing large script in chunks
			j := 0
			for j < len(scp) {
				if j+CHUNK < len(scp) {
					// -NoNewline is used to keep the chunks in a single line
					resp, exitCode, err = w.executeSingleCmd(fmt.Sprintf("%s\necho '%s' | Decode-Base64 | Out-File -FilePath %s -Append -NoNewline", base64Decode, base64.StdEncoding.EncodeToString([]byte(scp[j:j+CHUNK])), filename), shellId)
				} else {
					// For the last chunk of the script -NoNewline is avoided to keep the next script in a new line
					resp, exitCode, err = w.executeSingleCmd(fmt.Sprintf("%s\necho '%s' | Decode-Base64 | Out-File -FilePath %s -Append", base64Decode, base64.StdEncoding.EncodeToString([]byte(scp[j:])), filename), shellId)
				}
				j += CHUNK
			}
		}
		if err != nil {
			return "", err
		}
		if exitCode != 0 {
			return "", errors.New(resp)
		}
	}
	return filename, nil
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
		MessageId:        uuid.New().String(),
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

// execute - Executes the given script on the target machine
// Returns the command id of the newly created command
func (w *WinRMClient) execute(shellId, command string) (string, error) {
	p := &PayloadBuilder{
		Url:              w.url,
		OperationTimeout: w.operationTimeout,
		Locale:           w.locale,
		MaxEnvelopeSize:  w.maxEnvelopeSize,
		OpType:           Execute,
		MessageId:        uuid.New().String(),
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
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	for {
		p := &PayloadBuilder{
			Url:              w.url,
			OperationTimeout: w.operationTimeout,
			Locale:           w.locale,
			MaxEnvelopeSize:  w.maxEnvelopeSize,
			OpType:           Receive,
			MessageId:        uuid.New().String(),
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

// input - Writes to the stdin of the winrm process
func (w *WinRMClient) input(input, shellId, commandId string) error {
	p := &PayloadBuilder{
		Url:              w.url,
		OperationTimeout: w.operationTimeout,
		Locale:           w.locale,
		MaxEnvelopeSize:  w.maxEnvelopeSize,
		OpType:           Delete,
		MessageId:        uuid.New().String(),
		ShellId:          shellId,
		CommandId:        commandId,
		Input:            input,
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

// closeShell - Closes the shell with the given id
func (w *WinRMClient) closeShell(shellId string) error {
	p := &PayloadBuilder{
		Url:              w.url,
		OperationTimeout: w.operationTimeout,
		Locale:           w.locale,
		MaxEnvelopeSize:  w.maxEnvelopeSize,
		OpType:           Delete,
		MessageId:        uuid.New().String(),
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
