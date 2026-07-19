package regex

import (
	"regexp"
	"strings"

	"dockerhunter/pkg/types"
)

// GeneralPattern is the generic regex chosen to match secret assignments.
var GeneralPattern = regexp.MustCompile(`(?i)(\"|')?([a-z0-9_-]+)?((key|pass|user|username|pwd|credentials|auth|password|pwd|Ldap|Jenkins|ftp|dotfiles|JDBC|config|connectionstring|ssh|creds|secret|cred|access|Bearer|token|passwd|api|admin|private|bash|aws|s3|cookie)){1,}([a-z0-9 _[:space:]-]+)?(\"|')?(=>|=|:|,|\\+)(( )?(\"|'|return|{))?([a-z0-9 _[:space:]-=\.])+(( )?(\"|'|return|{))`)

// ExtractCandidates scans a context string (a line of code) and extracts secret candidates.
func ExtractCandidates(image, tag, file string, lineNum int, context string) []types.Candidate {
	locsList := GeneralPattern.FindAllStringSubmatchIndex(context, -1)
	if len(locsList) == 0 {
		return nil
	}

	var candidates []types.Candidate
	for _, locs := range locsList {
		// Ensure we have at least 26 indices (13 groups) to prevent out-of-range panics
		if len(locs) < 26 {
			continue
		}

		start := locs[0]
		opStart, opEnd := locs[14], locs[15]
		closeStart := locs[24]

		if opStart == -1 || opEnd == -1 {
			continue
		}

		// Extract Variable from left of operator
		rawVar := context[start:opStart]
		variable := strings.Trim(rawVar, "\"' \t")

		// Extract Value from right of operator
		var rawVal string
		if closeStart != -1 && closeStart > opEnd {
			rawVal = context[opEnd:closeStart]
		} else {
			rawVal = context[opEnd:]
		}
		value := strings.Trim(rawVal, "\"' \t")

		// Skip empty or trivial values
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
