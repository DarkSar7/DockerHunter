package regex

import (
	"regexp"
	"strings"

	"github.com/DarkSar7/DockerHunter/pkg/config"
	"github.com/DarkSar7/DockerHunter/pkg/types"
)

// GeneralPattern is the generic regex chosen to match secret assignments.
var GeneralPattern = regexp.MustCompile(`(?i)(\"|')?([a-z0-9_-]+)?((key|pass|user|username|pwd|credentials|auth|password|pwd|Ldap|Jenkins|ftp|dotfiles|JDBC|config|connectionstring|ssh|creds|secret|cred|access|Bearer|token|passwd|api|admin|private|bash|aws|s3|cookie)){1,}([a-z0-9 _[:space:]-]+)?(\"|')?(=>|=|:|,|\\+)(( )?(\"|'|return|{))?([a-z0-9 _[:space:]-=\.])+(( )?(\"|'|return|{))`)

// CompiledRules holds pre-compiled regex patterns for each signature rule.
type CompiledRules struct {
	Signatures []CompiledSignature
}

type CompiledSignature struct {
	Name string
	Re   *regexp.Regexp
}

func CompileRules(rules *config.RegexRules) *CompiledRules {
	cr := &CompiledRules{
		Signatures: []CompiledSignature{},
	}
	if rules == nil {
		return cr
	}
	for _, sig := range rules.Signatures {
		// Clean pattern value if multiline string block format
		patternStr := strings.TrimSpace(sig.Pattern.Value)
		re, err := regexp.Compile(patternStr)
		if err == nil {
			cr.Signatures = append(cr.Signatures, CompiledSignature{
				Name: sig.Pattern.Name,
				Re:   re,
			})
		}
	}
	return cr
}

// MatchRules checks if a candidate matches any signature validation rule.
func MatchRules(variable, value, context string, cr *CompiledRules) bool {
	if cr == nil || len(cr.Signatures) == 0 {
		return true // If no rules loaded, pass it through
	}

	for _, sig := range cr.Signatures {
		if sig.Re.MatchString(value) || sig.Re.MatchString(variable) || sig.Re.MatchString(context) {
			return true
		}
	}
	return false
}

// ExtractCandidates scans a context string (a line of code) and extracts secret candidates.
func ExtractCandidates(image, tag, file string, lineNum int, context string) []types.Candidate {
	locsList := GeneralPattern.FindAllStringSubmatchIndex(context, -1)
	if len(locsList) == 0 {
		return nil
	}

	var candidates []types.Candidate
	for _, locs := range locsList {
		if len(locs) < 26 {
			continue
		}

		start := locs[0]
		opStart, opEnd := locs[14], locs[15]
		closeStart := locs[24]

		if opStart == -1 || opEnd == -1 {
			continue
		}

		rawVar := context[start:opStart]
		variable := strings.Trim(rawVar, "\"' \t")

		var rawVal string
		if closeStart != -1 && closeStart > opEnd {
			rawVal = context[opEnd:closeStart]
		} else {
			rawVal = context[opEnd:]
		}
		value := strings.Trim(rawVal, "\"' \t")

		if value == "" {
			continue
		}

		candidates = append(candidates, types.Candidate{
			Image:    image,
			Tag:      tag,
			File:     file,
			Line:     lineNum,
			Variable: variable,
			Value:    value,
			Context:  strings.TrimSpace(context),
		})
	}
	return candidates
}
