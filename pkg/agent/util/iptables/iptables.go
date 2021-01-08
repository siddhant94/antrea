// +build !windows

// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog"
)

const (
	NATTable    = "nat"
	FilterTable = "filter"
	MangleTable = "mangle"
	RawTable    = "raw"

	AcceptTarget     = "ACCEPT"
	MasqueradeTarget = "MASQUERADE"
	MarkTarget       = "MARK"
	ConnTrackTarget  = "CT"
	NoTrackTarget    = "NOTRACK"

	PreRoutingChain  = "PREROUTING"
	ForwardChain     = "FORWARD"
	PostRoutingChain = "POSTROUTING"
	OutputChain      = "OUTPUT"

	waitSeconds              = 10
	waitIntervalMicroSeconds = 200000
)

// https://netfilter.org/projects/iptables/files/changes-iptables-1.6.2.txt:
// iptables-restore: support acquiring the lock.
var restoreWaitSupportedMinVersion = semver.Version{Major: 1, Minor: 6, Patch: 2}

// Syntax: iptables [-t <table-name>] <command> <chain-name> <parameter-1> <option-1> <parameter-n> <option-n>
type RuleInfo struct { //TODO: change name maybe, libnetwork uses similar
	Table, Chain, Command	string
	Params					[]string
}
var (
	commitBytes = "COMMIT"
	spaceBytes  = " "
)
type Client struct {
	ipts []*iptables.IPTables
	// restoreWaitSupported indicates whether iptables-restore (or ip6tables-restore) supports --wait flag.
	restoreWaitSupported bool
	// syncRules updates to store antrea modified/applied rules in iptables. Updates via AddToSyncRules()
	syncRules []RuleInfo
}

func New(enableIPV4, enableIPV6 bool) (*Client, error) {
	var ipts []*iptables.IPTables
	var restoreWaitSupported bool
	if enableIPV4 {
		ipt, err := iptables.New()
		if err != nil {
			return nil, fmt.Errorf("error creating IPTables instance: %v", err)
		}
		ipts = append(ipts, ipt)
		restoreWaitSupported = isRestoreWaitSupported(ipt)
	}
	if enableIPV6 {
		ip6t, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, fmt.Errorf("error creating IPTables instance for IPv6: %v", err)
		}
		ipts = append(ipts, ip6t)
		if !restoreWaitSupported {
			restoreWaitSupported = isRestoreWaitSupported(ip6t)
		}
	}
	return &Client{ipts: ipts, restoreWaitSupported: restoreWaitSupported}, nil
}

func isRestoreWaitSupported(ipt *iptables.IPTables) bool {
	major, minor, patch := ipt.GetIptablesVersion()
	version := semver.Version{Major: uint64(major), Minor: uint64(minor), Patch: uint64(patch)}
	return version.GE(restoreWaitSupportedMinVersion)
}

// ensureChain checks if target chain already exists, creates it if not.
func (c *Client) EnsureChain(table string, chain string) error {
	for idx := range c.ipts {
		ipt := c.ipts[idx]
		oriChains, err := ipt.ListChains(table)
		if err != nil {
			return fmt.Errorf("error listing existing chains in table %s: %v", table, err)
		}
		if contains(oriChains, chain) {
			return nil
		}
		if err := ipt.NewChain(table, chain); err != nil {
			return fmt.Errorf("error creating chain %s in table %s: %v", chain, table, err)
		}
		klog.V(2).Infof("Created chain %s in table %s", chain, table)
	}
	return nil
}

// ensureRule checks if target rule already exists, appends it if not.
func (c *Client) EnsureRule(table string, chain string, ruleSpec []string) error {
	for idx := range c.ipts {
		ipt := c.ipts[idx]
		exist, err := ipt.Exists(table, chain, ruleSpec...)
		if err != nil {
			return fmt.Errorf("error checking if rule %v exists in table %s chain %s: %v", ruleSpec, table, chain, err)
		}
		if exist {
			return nil
		}
		if err := ipt.Append(table, chain, ruleSpec...); err != nil {
			return fmt.Errorf("error appending rule %v to table %s chain %s: %v", ruleSpec, table, chain, err)
		}
	}
	klog.V(2).Infof("Appended rule %v to table %s chain %s", ruleSpec, table, chain)
	return nil
}

// Restore calls iptables-restore to restore iptables with the provided content.
// If flush is true, all previous contents of the respective tables will be flushed.
// Otherwise only involved chains will be flushed. Restore supports "ip6tables-restore" for IPv6.
func (c *Client) Restore(data []byte, flush bool, useIPv6 bool) error {
	var args []string
	if !flush {
		args = append(args, "--noflush")
	}
	iptablesCmd := "iptables-restore"
	if useIPv6 {
		iptablesCmd = "ip6tables-restore"
	}
	cmd := exec.Command(iptablesCmd, args...)
	cmd.Stdin = bytes.NewBuffer(data)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	// We acquire xtables lock for iptables-restore to prevent it from conflicting
	// with iptables/iptables-restore which might being called by kube-proxy.
	// iptables supports "--wait" option and go-iptables has enabled it.
	// iptables-restore doesn't support the option until 1.6.2. We use "-w" if the
	// detected version is greater than or equal to 1.6.2, otherwise we acquire the
	// file lock explicitly.
	// Note that we cannot just acquire the file lock explicitly for all cases because
	// iptables-restore will try acquiring the lock with or without "-w" provided since 1.6.2.
	if c.restoreWaitSupported {
		cmd.Args = append(cmd.Args, "-w", strconv.Itoa(waitSeconds), "-W", strconv.Itoa(waitIntervalMicroSeconds))
	} else {
		unlockFunc, err := Lock(XtablesLockFilePath, waitSeconds*time.Second)
		if err != nil {
			return err
		}
		defer unlockFunc()
	}
	if err := cmd.Run(); err != nil {
		klog.Errorf("Failed to execute %s: %v\nstdin:\n%s\nstderr:\n%s", iptablesCmd, err, data, stderr)
		return fmt.Errorf("error executing %s: %v", iptablesCmd, err)
	}
	return nil
}

// Save calls iptables-saves to dump chains and tables in iptables. Argument determines whether `-c`
// flag(include counters) will be used with iptables-save cmd.
func (c *Client) Save(countersFlag bool) ([]byte, error) {
	var output, data []byte
	var err error
	for idx := range c.ipts {
		var cmd string
		ipt := c.ipts[idx]
		switch ipt.Proto() {
		case iptables.ProtocolIPv6:
			cmd = "ip6tables-save"
		default:
			cmd = "iptables-save"
		}
		if countersFlag {
			data, err = exec.Command(cmd, "-c").CombinedOutput()
		} else {
			data, err = exec.Command(cmd).CombinedOutput()
		}
		if err != nil {
			return nil, err
		}
		output = append(output, data...)
	}
	return output, nil
}

func contains(chains []string, targetChain string) bool {
	for _, val := range chains {
		if val == targetChain {
			return true
		}
	}
	return false
}

func MakeChainLine(chain string) string {
	return fmt.Sprintf(":%s - [0:0]", chain)
}

func (c *Client) AddToSyncRules(r RuleInfo) {
	c.syncRules = append(c.syncRules, r)
}

func PrettyPrint(v interface{}) (err error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err == nil {
			fmt.Println(string(b))
	}
	return
}

func (c *Client) CheckIfAntreaRulesPresent() bool {
	// iptablesBuf := bytes.NewBuffer(nil)
	// iptData := iptablesBuf.Bytes()
	ipTablesData, err := c.Save(false)
	if err != nil {
		klog.Error("Error in querying iptables: %v",err)
		return false //TODO: return error also along with bool
	}
	// We parse for each table.
	// TODO: Dont parse all tables only those which have antrea rules while being set
	res := parseIPTablesSave(ipTablesData)
	PrettyPrint(res)

	// Loop through syncRules
	for _, val := range c.syncRules {
		
		klog.Info("Table: %s, Chain: %s, Rule: %v", val.Table, val.Chain, val.Params)
		if _, ok := res[val.Chain+"/"+val.Table]; !ok {
			klog.Infof("\nIptables SAVE data does not have rules for %s/%s\n", val.Chain, val.Command)
			continue //TODO: Change to return false
		}
		rules := res[val.Chain+"/"+val.Table]
		klog.Info("\nRules from Iptables SAVE:\n")
		klog.Infoln(rules)
		present := false
		for ix := range rules {
			present = sameStringSlice(strings.Split(rules[ix], " "), val.Params)
		}
		if present != true{
			continue //TODO: Change to return false
		}
		klog.Infoln("Found Rule")
		
	}
	return true
}

func parseIPTablesSave(data []byte) map[string][]string {
	chainsMap := make(map[string][]string)
	tableToChainMap := make(map[string][]string)
	tablePrefix := "*"
	bytesReader := bytes.NewReader(data)
	bufReader := bufio.NewReader(bytesReader)
	scanner := bufio.NewScanner(bufReader)
	klog.Infoln("Printing Scanner loop")
	// count := 0
	for scanner.Scan() {
		// if count == 4 { break }
		line := scanner.Text()
		// fmt.Println(line)
		// TODO: To separate IPv4 & v6, we would parse "Generated by" comment part.
		if line[0] == '#' || strings.HasPrefix(line, commitBytes) { //comments or COMMIT's from iptables-save
			continue
		}
		// Get to table line
		var tblName string
		//var rules []string
		if tableNameIndex := strings.Index(line, tablePrefix); tableNameIndex != -1 {
			// Found table line
			tblName = line[(tableNameIndex+1):]
			// count++
			// Reset rules []string. PS: Change into bytes buffer and call native Reset( method.
			continue
		} else if line[0] == ':' && len(line) > 1 { // i.e. is a chain line
			// We assume that the <line> contains space - chain lines have 3 fields,
			// space delimited. If there is no space, this line will panic.
			spaceIndex := strings.Index(line, spaceBytes)
			if spaceIndex == -1 {
				// TODO: Remove panic and handle error
				panic(fmt.Sprintf("Unexpected chain line in iptables-save output: %v", string(line)))
			}
			chain := line[1:spaceIndex]
			tableToChainMap[tblName] = append(tableToChainMap[tblName], chain)
			continue
			// TODO: Add logic to see if we need this chain, then only we'll parse
		} else if line[0] == '-' { // Rule line
			//TODO: Separate these into target source op etc
			// Refer: man iptables
			// COMMANDS: -A(append), -N (new chain), -X(delete)
			// -A has arguments Chain RuleSpec
			//cmd := line[0:2]
			segments := strings.SplitN(line, spaceBytes, 3) // assuming space
			//fmt.Printf("\nSegments: \nCmd: %s\nChain: %s\nRuleSpec: %v\n", segments[0], segments[1], segments[2])
			key := segments[1] + "/" + tblName
			chainsMap[key] = append(chainsMap[key], line)
		}
	}
	return chainsMap
}

func sameStringSlice(x, y []string) bool {
    if len(x) != len(y) {
        return false
    }
    // create a map of string -> int
    diff := make(map[string]int, len(x))
    for _, _x := range x {
        // 0 value for int is 0, so just increment a counter for the string
        diff[_x]++
    }
    for _, _y := range y {
        // If the string _y is not in diff bail out early
        if _, ok := diff[_y]; !ok {
            return false
        }
        diff[_y] -= 1
        if diff[_y] == 0 {
            delete(diff, _y)
        }
    }
    if len(diff) == 0 {
        return true
    }
    return false
}

// for _, rule := range c.syncRules {
// 	exist, err := ipt.Exists(rule.Table, rule.Chain, rule.Rule...)
// 	if err != nil {
// 		//TODO: Change to klog.Error
// 		fmt.Errorf("error checking if rule %v exists in table %s chain %s: %v", rule.Rule, rule.Table, rule.Chain, err)
// 		return false
// 	}
// 	if !exist {
// 		klog.Infof("Could not find rulespec in table %s chain %s: %v", rule.Table, rule.Chain, rule.Rule)
// 		return false
// 	}
// }