package bucket

import (
	"fmt"

	"github.com/hardenCN/trivy-db/pkg/types"
)

const separator = "::"

func Name(ecosystem types.Ecosystem, dataSource string) string {
	return fmt.Sprintf("%s%s%s", ecosystem, separator, dataSource)
}
