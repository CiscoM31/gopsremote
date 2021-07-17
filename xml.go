// The xml.go file contains functions to parse WinRM service's xml response.

package gopsremote

import (
	"encoding/base64"
	"encoding/xml"
	"io"
	"strings"
)

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
