package main

import "os/exec"

func callStop(args map[string]any) {
	cmdArgs := []string{"clean"}
	if v, ok := args["release_namespace"].(string); ok && v != "" {
		cmdArgs = append(cmdArgs, "-s", v)
	}
	_ = exec.Command("kubeshark", cmdArgs...).Run()
}
