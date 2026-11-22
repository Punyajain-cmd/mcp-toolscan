// Synthetic reproduction of the Kubeshark MCP CVE-2026-129236 pattern (CWE-88).
package main

import "os/exec"

func callStart(args map[string]any) {
	cmdArgs := []string{"tap"}
	if v, ok := args["pod_regex"].(string); ok && v != "" {
		cmdArgs = append(cmdArgs, v)
	}
	if v, ok := args["namespace"].(string); ok && v != "" {
		cmdArgs = append(cmdArgs, "-n", v)
	}
	cmd := exec.Command("kubeshark", cmdArgs...)
	_ = cmd.Start()
}
