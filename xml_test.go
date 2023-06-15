package gopsremote_test

import (
	"os"
	"testing"

	"github.com/CiscoM31/gopsremote"
	"github.com/google/uuid"
)

func BenchmarkExecute(b *testing.B) {
	for i := 0; i < b.N; i++ {
		p := &gopsremote.PayloadBuilder{
			OpType:           gopsremote.Execute,
			Url:              "https://172.25.168.38:5986/wsman",
			OperationTimeout: "PT.06",
			Locale:           "en-US",
			MessageId:        uuid.New().String(),
			ShellId:          uuid.New().String(),
			CommandId:        uuid.New().String(),
			Command:          "Get-Service",
			Input:            "del",
			MaxEnvelopeSize:  "1532600",
		}
		p.Execute()
	}
}

func TestCaptureText(t *testing.T) {
	file, err := os.Open("sample_responses/create_shell.xml")
	if err != nil {
		t.Error(err)
	}
	id, err := gopsremote.CaptureText(file, "Selector")
	if err != nil {
		t.Error(err)
	}
	if id != "uuid:C443F44F-28E4-486F-A5A1-12745F90CF5A" {
		t.Errorf("invalid shell id")
	}

	file, err = os.Open("sample_responses/execute_command.xml")
	if err != nil {
		t.Error(err)
	}
	id, err = gopsremote.CaptureText(file, "CommandId")
	if err != nil {
		t.Error(err)
	}
	if id != "77df7bb6-b5a0-4777-abd9-9823c0774074" {
		t.Errorf("invalid command id")
	}
}

func TestCaptureAttribute(t *testing.T) {
	f, err := os.Open("sample_responses/recieve_output.xml")
	if err != nil {
		t.Error(err)
	}
	attr, err := gopsremote.CaptureAttribute(f, "CommandState", "State")
	if err != nil {
		t.Error(err)
	}
	if attr != "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running" {
		t.Error("invalid attribute")
	}
}
