package gopsremote

import (
	"bytes"
	"fmt"
	"text/template"
)

// Global template used to generate payloads
var gTemplate *template.Template

// Templates are initialized during startup
// TODO: Calculate memory consumed by holding templates in memory
// TODO: Find out better way to handle potential errors during intialization
func init() {
	gTemplate, _ = template.New("payloadBuilder").Parse(body)
}

type RequestType int

const (
	Create = 1 << iota
	Execute
	Send
	Receive
	Delete
)

// Data structure to build the xml payloads from templates
type PayloadBuilder struct {
	// Format - https://{{ipaddress_or_fqdn}}:{{portno}}/wsman
	Url              string
	OperationTimeout string
	Locale           string
	MessageId        string
	ShellId          string
	CommandId        string
	Command          string
	Input            string
	MaxEnvelopeSize  string
	OpType           RequestType
}

func (p *PayloadBuilder) GetAction() string {
	switch p.OpType {
	case Create:
		return "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
	case Execute:
		return "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
	case Send:
		return "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"
	case Receive:
		return "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
	case Delete:
		return "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
	default:
		return ""
	}
}

func (p *PayloadBuilder) GenerateOptionSet() string {
	if p.OpType == Create {
		return `
    <wsman:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	    <wsman:Option Name="WINRS_NOPROFILE">FALSE</wsman:Option>
	    <wsman:Option Name="WINRS_CODEPAGE">65001</wsman:Option>
    </wsman:OptionSet>
    `
	} else if p.OpType == Execute {
		return `
    <wsman:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <wsman:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</wsman:Option>
      <wsman:Option Name="WINRS_SKIP_CMD_SHELL">FALSE</wsman:Option>
    </wsman:OptionSet>
    `
	}
	return ""
}

func (p *PayloadBuilder) GenerateSelectorSet() string {
	if p.OpType != Create {
		return fmt.Sprintf(`
    <wsman:SelectorSet xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
      <wsman:Selector Name="ShellId">%s</wsman:Selector>
    </wsman:SelectorSet>
    `, p.ShellId)
	}
	return ""
}

func (p *PayloadBuilder) GenerateBody() string {
	switch p.OpType {
	case Create:
		return `
    <s:Body>
      <rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
	      <rsp:InputStreams>stdin</rsp:InputStreams>
	      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
      </rsp:Shell>
    </s:Body>
    `
	case Execute:
		return fmt.Sprintf(`
    <s:Body>
      <rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
        <rsp:Command><![CDATA[%s]]></rsp:Command>
      </rsp:CommandLine>
    </s:Body>`, p.Command)
	case Send:
		return fmt.Sprintf(`
    <s:Body>
      <rsp:Send xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
        <rsp:Stream xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" Name="stdin" CommandId="%s">%s</rsp:Stream>
      </rsp:Send>
    </s:Body>`, p.CommandId, p.Input)
	case Receive:
		return fmt.Sprintf(`
    <s:Body>
      <rsp:Receive xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
        <rsp:DesiredStream CommandId="%s">stdout stderr</rsp:DesiredStream>
      </rsp:Receive>
    </s:Body>`, p.CommandId)
	case Delete:
		return "<s:Body/>"
	default:
		return ""
	}
}

func (p *PayloadBuilder) Execute() (*bytes.Buffer, error) {
	payload := &bytes.Buffer{}
	err := gTemplate.Execute(payload, p)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

var body = `
<?xml version="1.0" encoding="utf-8" ?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
<s:Header>
  <wsa:To>{{.Url}}</wsa:To>
  <wsa:ReplyTo>
    <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
  </wsa:ReplyTo>
  <wsman:ResourceURI xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
  <wsa:Action s:mustUnderstand="true">{{.GetAction}}</wsa:Action>
  <wsa:MessageID>uuid:{{.MessageId}}</wsa:MessageID>
  <wsman:Locale xml:lang="{{.Locale}}" s:mustUnderstand="false"/>
  {{.GenerateOptionSet}}
  {{.GenerateSelectorSet}}
</s:Header>
{{.GenerateBody}}
</s:Envelope>
`
