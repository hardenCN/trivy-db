package vulnsrc

import (
	"github.com/hardenCN/trivy-db/pkg/types"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/alma"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/alpine"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/amazon"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/azure"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/bitnami"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/bundler"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/chainguard"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/composer"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/debian"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/glad"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/govulndb"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/k8svulndb"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/node"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/nvd"
	oracleoval "github.com/hardenCN/trivy-db/pkg/vulnsrc/oracle-oval"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/photon"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/redhat"
	redhatoval "github.com/hardenCN/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/rocky"
	susecvrf "github.com/hardenCN/trivy-db/pkg/vulnsrc/suse-cvrf"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/hardenCN/trivy-db/pkg/vulnsrc/wolfi"
)

type VulnSrc interface {
	Name() types.SourceID
	Update(dir string) (err error)
}

var (
	// All holds all data sources
	All = []VulnSrc{
		// NVD
		nvd.NewVulnSrc(),

		// OS packages
		alma.NewVulnSrc(),
		alpine.NewVulnSrc(),
		redhat.NewVulnSrc(),
		redhatoval.NewVulnSrc(),
		debian.NewVulnSrc(),
		ubuntu.NewVulnSrc(),
		amazon.NewVulnSrc(),
		oracleoval.NewVulnSrc(),
		rocky.NewVulnSrc(),
		susecvrf.NewVulnSrc(susecvrf.SUSEEnterpriseLinux),
		susecvrf.NewVulnSrc(susecvrf.OpenSUSE),
		photon.NewVulnSrc(),
		azure.NewVulnSrc(azure.Azure),
		azure.NewVulnSrc(azure.Mariner),
		wolfi.NewVulnSrc(),
		chainguard.NewVulnSrc(),
		bitnami.NewVulnSrc(),

		k8svulndb.NewVulnSrc(),

		// Language-specific packages
		bundler.NewVulnSrc(),
		composer.NewVulnSrc(),
		node.NewVulnSrc(),
		ghsa.NewVulnSrc(),
		glad.NewVulnSrc(),
		govulndb.NewVulnSrc(), // For Go stdlib packages
	}
)
