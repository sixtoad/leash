package engine

import (
	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
)

// builtinActions are every Action::"..." ID Leash defines: the requestable
// ones, the FileOpen group, and HttpRewrite (configuration, never requested).
var builtinActions = map[string]bool{
	ActionFileOpen:          true,
	ActionFileOpenReadOnly:  true,
	ActionFileOpenReadWrite: true,
	ActionProcessExec:       true,
	ActionNetworkConnect:    true,
	ActionMcpCall:           true,
	ActionHttpRewrite:       true,
}

// builtinResourceTypes are the resource entity types Leash's built-in
// requests carry (or their ancestors).
var builtinResourceTypes = map[string]bool{
	TypeFile:       true,
	TypeFilePrefix: true,
	TypeDir:        true,
	TypeHost:       true,
	TypeMCPTool:    true,
	TypeMCPServer:  true,
}

// IsBuiltinAction reports whether id is one of Leash's own Action::"..." IDs.
// A built-in policy naming any other ID can never match a request.
func IsBuiltinAction(id string) bool { return builtinActions[id] }

// IsBuiltinResourceType reports whether t is a resource type Leash's
// built-in requests can carry. A built-in policy comparing the resource to any
// other type can never match. Plugin policies (<Ns>::Action::"...") use their
// own, plugin-defined types and are not subject to this check.
func IsBuiltinResourceType(t string) bool { return builtinResourceTypes[t] }

// ResourceEntityTypes returns the entity types a policy compares its resource
// against: the resource scope (==, in, is, is ... in) and conditions of the
// form `resource == E`, `resource in E` / `resource in [E, ...]`,
// `resource is T` and `resource is T in E`. Duplicates are removed; order
// follows first appearance.
func ResourceEntityTypes(p *cedar.Policy) []string {
	pa := (*xast.Policy)(p.AST())
	var out []string
	seen := map[string]bool{}
	add := func(t types.EntityType) {
		s := string(t)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	switch s := pa.Resource.(type) {
	case xast.ScopeTypeEq:
		add(s.Entity.Type)
	case xast.ScopeTypeIn:
		add(s.Entity.Type)
	case xast.ScopeTypeIs:
		add(s.Type)
	case xast.ScopeTypeIsIn:
		add(s.Type)
		add(s.Entity.Type)
	}
	isResource := func(n xast.IsNode) bool {
		v, ok := n.(xast.NodeTypeVariable)
		return ok && string(v.Name) == "resource"
	}
	var literals func(n xast.IsNode)
	literals = func(n xast.IsNode) {
		switch x := n.(type) {
		case xast.NodeValue:
			var value func(v types.Value)
			value = func(v types.Value) {
				switch y := v.(type) {
				case types.EntityUID:
					add(y.Type)
				case types.Set:
					for e := range y.All() {
						value(e)
					}
				}
			}
			value(x.Value)
		case xast.NodeTypeSet:
			for _, e := range x.Elements {
				literals(e)
			}
		}
	}
	for _, c := range pa.Conditions {
		xast.Inspect(xast.NewNode(c.Body), func(n xast.IsNode) bool {
			switch x := n.(type) {
			case xast.NodeTypeEquals:
				if isResource(x.Left) {
					literals(x.Right)
				} else if isResource(x.Right) {
					literals(x.Left)
				}
			case xast.NodeTypeIn:
				if isResource(x.Left) {
					literals(x.Right)
				}
			case xast.NodeTypeIsIn:
				if isResource(x.Left) {
					add(x.EntityType)
					literals(x.Entity)
				}
			case xast.NodeTypeIs:
				if isResource(x.Left) {
					add(x.EntityType)
				}
			}
			return true
		})
	}
	return out
}
