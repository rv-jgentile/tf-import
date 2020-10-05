package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type LegacyState struct {
	// The Terraform version used to make the state.
	TerraformVersion string `json:"terraform_version,omitempty"`

	Modules []*StateModule `json:"modules,omitempty"`
}

type StateModule struct {
	Path      []string                   `json:"path,omitempty"`
	Resources map[string]*ModuleResource `json:"resources,omitempty"`
}

type ModuleResource struct {
	// The resource type, example: "aws_instance" for aws_instance.foo.
	Type string `json:"type,omitempty"`

	Primary      *ModulePrimary `json:"primary,omitempty"`
	ProviderName string         `json:"provider,omitempty"`

	// The addresses of the resources that this resource depends on.
	DependsOn []string `json:"depends_on,omitempty"`
}

type ModulePrimary struct {
	ID         string            `json:"id,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// State is the top-level representation of a Terraform state.
type State struct {
	// The Terraform version used to make the state.
	TerraformVersion string `json:"terraform_version,omitempty"`

	// All resources or data sources within this module.
	Resources []*StateResource `json:"resources,omitempty"`
}

type StateResource struct {
	Module string `json:"module,omitempty"`

	Each string `json:"each,omitempty"`

	// The resource mode.
	Mode string `json:"mode,omitempty"`

	// The resource type, example: "aws_instance" for aws_instance.foo.
	Type string `json:"type,omitempty"`

	// The resource name, example: "foo" for aws_instance.foo.
	Name string `json:"name,omitempty"`

	Instances []*StateInstance `json:"instances,omitempty"`

	ProviderName string `json:"provider,omitempty"`
}

type StateInstance struct {
	Index      int                    `json:"index_key,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`

	// The addresses of the resources that this resource depends on.
	DependsOn []string `json:"dependencies,omitempty"`
}

func main() {

	path := flag.String("state", "", "source file")
	tf11 := flag.Bool("legacy", false, "terraform 0.11 state")

	flag.Parse()

	if *path == "" {
		flag.Usage()
		os.Exit(1)
	}

	f, err := os.Open(*path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if *tf11 {
		var state *LegacyState
		if err := json.NewDecoder(f).Decode(&state); err != nil {
			panic(err)
		}

		_, err := legacy(state, os.Stdout)
		if err != nil {
			panic(err)
		}
		return
	}

	var state *State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		panic(err)
	}

	_, err = parse(state, os.Stdout)
	if err != nil {
		panic(err)
	}

}

func legacy(state *LegacyState, wr io.Writer) (n int, err error) {
	cmds := make([]string, 0)

	for _, r := range state.Modules {
		for key, instance := range r.Resources {
			if strings.HasPrefix(key, "data.") {
				continue
			}
			var path string
			if len(r.Path) > 1 {
				path = "module"
				for i, p := range r.Path {
					if i == 0 {
						continue
					}
					snakeCase := strings.Replace(p, "-", "_", -1)
					path = fmt.Sprintf("%s.%s.%s", path, snakeCase, key)
				}
			} else {
				path = fmt.Sprintf("%s", key)
			}

			cmds = append(cmds, fmt.Sprintf("terraform import %s %s\n", path, id(instance.Type, instance.Primary.Attributes)))

		}
	}

	sort.Strings(cmds)

	return wr.Write([]byte(fmt.Sprintf("%s", cmds)))
}

func id(typeName string, attrs map[string]string) string {

	switch typeName {

	case "aws_route":
		return fmt.Sprintf("%s_%s",
			attrs["route_table_id"],
			attrs["destination_cidr_block"])

	case "aws_route_table_association":
		return fmt.Sprintf("%s/%s",
			attrs["subnet_id"],
			attrs["route_table_id"])

	case "aws_iam_role_policy_attachment":
		return fmt.Sprintf("%s/%s",
			attrs["role"],
			attrs["policy_arn"])

	default:
		return fmt.Sprintf("%s", attrs["id"])
	}
}

func parse(state *State, wr io.Writer) (n int, err error) {
	cmds := make([]string, 0)

	for _, resource := range state.Resources {

		if resource.Mode != "managed" {
			continue
		}

		for _, instance := range resource.Instances {

			var path string
			if resource.Module != "" {
				path = fmt.Sprintf("%s.%s.%s", resource.Module, resource.Type, resource.Name)
			} else {
				path = fmt.Sprintf("%s.%s", resource.Type, resource.Name)
			}

			if resource.Each == "list" {
				path = fmt.Sprintf("'%s[%d]'", path, instance.Index)
			}

			cmds = append(cmds, fmt.Sprintf("terraform import %s %s\n", path, getID(resource.Type, instance.Attributes)))

		}
	}

	sort.Strings(cmds)

	return wr.Write([]byte(fmt.Sprintf("%s", cmds)))
}

func getID(typeName string, attrs map[string]interface{}) string {

	switch typeName {

	case "aws_route":
		return fmt.Sprintf("%s_%s",
			attrs["route_table_id"],
			attrs["destination_cidr_block"])

	case "aws_route_table_association":
		return fmt.Sprintf("%s/%s",
			attrs["subnet_id"],
			attrs["route_table_id"])

	case "aws_iam_role_policy_attachment":
		return fmt.Sprintf("%s/%s",
			attrs["role"],
			attrs["policy_arn"])

	case "aws_iam_user_policy_attachment":
		return fmt.Sprintf("%s/%s",
			attrs["user"],
			attrs["policy_arn"])

	case "aws_service_discovery_private_dns_namespace":
		return fmt.Sprintf("%s:%s",
			attrs["id"],
			attrs["vpc"])

	case "aws_lambda_permission":
		// FUNCTION_NAME/STATEMENT_ID or FUNCTION_NAME:QUALIFIER/STATEMENT_ID
		return fmt.Sprintf("%s/%s",
			attrs["function_name"],
			attrs["statement_id"])

	case "aws_cloudwatch_event_target":
		return fmt.Sprintf("%s/%s",
			attrs["rule"],
			attrs["target_id"])

	case "aws_security_group_rule":
		// TODO : cidr is a list of string

		if attrs["cidr_blocks"] == nil {
			return fmt.Sprintf("%s_%s_%s_%0.0f_%0.0f_%s",
				attrs["security_group_id"],
				attrs["type"],
				attrs["protocol"],
				attrs["from_port"],
				attrs["to_port"],
				"NO_CIDR")
		}

		if len(attrs["cidr_blocks"].([]interface{})) == 0 {
			var source string = "NO_SOURCE_SEC_GROUP"
			if value, ok := attrs["source_security_group_id"]; ok {
				source = value.(string)
			}
			return fmt.Sprintf("%s_%s_%s_%0.0f_%0.0f_%s",
				attrs["security_group_id"],
				attrs["type"],
				attrs["protocol"],
				attrs["from_port"],
				attrs["to_port"],
				source)
		}

		return fmt.Sprintf("%s_%s_%s_%0.0f_%0.0f_%s",
			attrs["security_group_id"],
			attrs["type"],
			attrs["protocol"],
			attrs["from_port"],
			attrs["to_port"],
			attrs["cidr_blocks"].([]interface{})[0])

	default:
		return fmt.Sprintf("%s", attrs["id"])
	}
}
