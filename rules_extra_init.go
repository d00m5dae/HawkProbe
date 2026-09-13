package main

func init() {
	builtinRules = mergeBuiltinRules(builtinRules, buildExtraRules())
}
