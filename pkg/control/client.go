package control

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

type ControlClient struct {
	socketPath string
}

func NewControlClient(socketPath string) *ControlClient {
	return &ControlClient{socketPath: socketPath}
}

func (c *ControlClient) SendRequest(req Request) (*Response, error) {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to firewall-agent at %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return &resp, nil
}

func (c *ControlClient) ApplyPolicyFile(filePath string) (*Response, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", filePath, err)
	}

	return c.SendRequest(Request{
		Command:    "apply_policy",
		PolicyYAML: string(data),
	})
}

func (c *ControlClient) GetStatus() (*Response, error) {
	return c.SendRequest(Request{
		Command: "get_status",
	})
}

func (c *ControlClient) DumpMaps() (*Response, error) {
	return c.SendRequest(Request{
		Command: "dump_maps",
	})
}
