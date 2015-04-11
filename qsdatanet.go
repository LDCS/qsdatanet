// qsdatanet runs nmap to detect up/down status of network devices on a configured subnets, and produces csv-formatted file output
//
// This makes an enterprise csvfile-based ETL environment capable of network monitoring.
package main

import (
	"fmt"
	"github.com/LDCS/genutil"
	"github.com/LDCS/qcfg"
	"github.com/LDCS/qslinux/nmap"
	"github.com/LDCS/sflag"
)

var (
	opt = struct {
		Usage   string "wrapper for nmap functionality"
		Cfg     string "path to cfg file listing subnets		| ./ndm.cfg"
		Netlist string "List of ndm-defined subnets to nmap		| all"
		Odir    string "output directory (default is to use stdout)	|"
		Verbose bool   "verbosity | false"
	}{}
)

func main() {
	ostr := ""
	ostrVerbose := ""
	mybox := genutil.Hostname()
	sflag.Parse(&opt)
	if opt.Verbose {
		fmt.Println("\nStarting on ", mybox, "verbose=", opt.Verbose, "cfg=", opt.Cfg, "netlist=", opt.Netlist)
	}

	cfg := qcfg.NewCfg("cfg", opt.Cfg, true)

	subnetmap := map[string][]string{}
	lst := cfg.Str("net", "subnet", opt.Netlist, "")
	for _, item := range genutil.AnySplit(lst, ",") {
		subnetmap[item] = []string{
			cfg.Str("net", "subnet."+item, "subnet", ""),
			cfg.Str("net", "subnet."+item, "nmap-sP", ""),
			cfg.Str("net", "subnet."+item, "nmap-sT", ""),
		}
	}

	nmapmap := nmap.DoListNmapdata(subnetmap, opt.Verbose)
	if true {
		ostr += fmt.Sprintf("box,%s\n", nmap.Header())
		strs := genutil.SortedUniqueKeys(nmap.Keys_String2PtrNmapdata(&nmapmap))
		strsDone := map[string]bool{}
		for _, kk := range strs {
			strsDone[kk] = true
			nmap, _ := nmapmap[kk]
			ostr += fmt.Sprintf("%s,%s\n", mybox, nmap.Csv())
		}
	}
	ofile := ""
	switch {
	case opt.Odir == "":
		ofile = "/dev/stdout"
	default:
		ofile = opt.Odir + "/qsdatanet." + mybox + ".csv"
	}
	genutil.WriteStringToFile(ostrVerbose+ostr, ofile)
}
