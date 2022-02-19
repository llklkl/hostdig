package cmd

import (
	"io/ioutil"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/spf13/cobra"

	"github.com/llklkl/hostdig/config"
)

func Test_replaceResult(t *testing.T) {
	hostsMap := map[string]string{
		"1.1.1.1": "aaa.com",
		"1.1.1.2": "bbb.com",
		"1.1.1.3": "ccc.com",
	}
	fileContent := `

# this is a comment1
# this is a comment2
# this is a comment3

# this is a comment3




   1.2.3.4 aaa.com      ccc.com ddd.com ## this is a comment
1.2.3.5 ccc.com ## this is a comment


	`
	tmpPath := "./test.txt"

	ioutil.WriteFile(tmpPath, []byte(fileContent), 0777)

	patches := gomonkey.ApplyFunc(hostdig, func(_ *config.Config, formater func(string, string)) {
		for ip, host := range hostsMap {
			formater(host, ip)
		}
	})
	defer patches.Reset()

	if err := replaceResult(&cobra.Command{}, tmpPath); err != nil {
		t.Errorf("replace failed, err: %v", err)
	}
}
