package ldsoconf

import (
	"os"
	"testing"
	"github.com/stretchr/testify/require"
)

func Test_ParseLDSOConf_Simple(t *testing.T) {
	fsys := os.DirFS("testdata")
	dirs, err := ParseLDSOConf(fsys, "ld.so.conf.simple")
	require.NoError(t, err)
	require.Equal(t, 1, len(dirs))
	require.Equal(t, "/lib", dirs[0])
}

func Test_ParseLDSOConf_Glob(t *testing.T) {
	fsys := os.DirFS("testdata")
	dirs, err := ParseLDSOConf(fsys, "ld.so.conf.glob")
	require.NoError(t, err)
	require.Contains(t, dirs, "/a/libs")
	require.Contains(t, dirs, "/b/libs")
}
