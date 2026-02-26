package sandbox

import (
	"errors"
	"sort"
)

const (
	ProfileNone      = "none"
	ProfileLocal     = "local"
	ProfileContainer = "container"
)

var profileOrder = map[string]int{
	ProfileNone:      0,
	ProfileLocal:     1,
	ProfileContainer: 2,
}

func NormalizeProfile(profile string) string {
	switch profile {
	case ProfileNone, ProfileLocal, ProfileContainer:
		return profile
	default:
		return ProfileNone
	}
}

func SelectProfile(obligations map[string]any, configured string) (string, error) {
	configured = NormalizeProfile(configured)
	required := requiredProfile(obligations)
	if profileOrder[required] > profileOrder[configured] {
		return ProfileNone, errors.New("sandbox profile required but not available")
	}
	if required == ProfileNone {
		return configured, nil
	}
	return required, nil
}

func requiredProfile(obligations map[string]any) string {
	value, ok := obligations["sandbox_mode"]
	if !ok {
		return ProfileNone
	}
	switch v := value.(type) {
	case string:
		return NormalizeProfile(v)
	case []any:
		options := make([]string, 0)
		for _, entry := range v {
			if s, ok := entry.(string); ok {
				options = append(options, NormalizeProfile(s))
			}
		}
		sort.Slice(options, func(i, j int) bool {
			return profileOrder[options[i]] > profileOrder[options[j]]
		})
		if len(options) > 0 {
			return options[0]
		}
	}
	return ProfileNone
}
