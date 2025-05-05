package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	ldsocache "github.com/chainguard-dev/ldso-cache"
)

func main() {
	var rootdir string
	var cache string
	var config string

	flag.StringVar(&rootdir, "r", "/", "directory to use as root")
	flag.StringVar(&config, "f", "/etc/ld.so.conf", "config file")
	flag.StringVar(&cache, "C", "/etc/ld.so.cache", "cache file")
	flag.Parse()

	config = strings.TrimLeft(config, "/")

	root := os.DirFS(rootdir)
	libdirs, err := ldsocache.ParseLDSOConf(root, config)
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
	cacheFile, err := ldsocache.BuildCacheFileForDirs(root, libdirs)
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
	lsc, err := os.Create(cache)
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
	defer lsc.Close()
	err = cacheFile.Write(lsc)
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
	os.Exit(0)
}
