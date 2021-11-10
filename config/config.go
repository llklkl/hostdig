package config

type Config struct {
	DnsList []DnsListEntry `yaml:"dns_list"`

	HostsCfg []HostsFile `yaml:"hosts"`
}

type DnsListEntry struct {
	Type string `yaml:"type"`
	Path string `yaml:"path"`
}

type HostsFile struct {
	Path string `yaml:"path"`
}
