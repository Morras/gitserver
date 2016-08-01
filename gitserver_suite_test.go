package gitserver_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestGitserver(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Gitserver Suite")
}
