package version

import (
	"fmt"
	"runtime/debug"
)

var (
	Version   = "0.0.0"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type Info struct {
	Version   string
	Commit    string
	BuildDate string
	GoVersion string
}

func Current() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: "unknown",
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		info.GoVersion = buildInfo.GoVersion
		for _, setting := range buildInfo.Settings {
			switch setting.Key {
			case "vcs.revision":
				if info.Commit == "unknown" && setting.Value != "" {
					info.Commit = setting.Value
				}
			case "vcs.time":
				if info.BuildDate == "unknown" && setting.Value != "" {
					info.BuildDate = setting.Value
				}
			}
		}
	}
	return info
}

func (i Info) String() string {
	return fmt.Sprintf("version=%s commit=%s build_date=%s go=%s", i.Version, i.Commit, i.BuildDate, i.GoVersion)
}
