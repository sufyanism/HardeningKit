package audit

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Finding struct {
	ID string `json:"id"`
	Severity string `json:"severity"`
	Title string `json:"title"`
	Detail string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}
type Report struct {
	GeneratedAt string `json:"generated_at"`
	Hostname string `json:"hostname"`
	OS string `json:"os"`
	Arch string `json:"architecture"`
	Kernel string `json:"kernel,omitempty"`
	Duration string `json:"duration"`
	ChecksRun int `json:"checks_run"`
	Critical int `json:"critical"`
	High int `json:"high"`
	Medium int `json:"medium"`
	Low int `json:"low"`
	Findings []Finding `json:"findings"`
}
func Run(timeout time.Duration) Report {
	if timeout <= 0 { timeout = 3*time.Second }
	deadline := time.Now().Add(timeout)
	host, _ := os.Hostname()
	r := Report{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Hostname:host, OS:runtime.GOOS, Arch:runtime.GOARCH, Findings:[]Finding{}}
	check := func(fn func(*Report)) { if time.Now().Before(deadline) { r.ChecksRun++; fn(&r) } }
	check(checkKernel)
	check(checkSSH)
	check(checkFirewall)
	check(checkTmp)
	check(checkPorts)
	check(checkSUID)
	check(checkPackageSignal)
	for _, f := range r.Findings { switch f.Severity { case "CRITICAL": r.Critical++; case "HIGH": r.High++; case "MEDIUM": r.Medium++; case "LOW": r.Low++ } }
	return r
}
func add(r *Report,id,sev,title,detail,fix string) { r.Findings=append(r.Findings,Finding{id,sev,title,detail,fix}) }
func checkKernel(r *Report) {
	b,err:=os.ReadFile("/proc/sys/kernel/osrelease")
	if err==nil { r.Kernel=strings.TrimSpace(string(b)) }
	if runtime.GOOS!="linux" { add(r,"SYS-001","INFO","Non-Linux host","Linux-specific checks may not apply.","Run on Linux for the intended baseline."); return }
	if _,err=os.Stat("/etc/os-release"); err==nil { add(r,"SYS-002","INFO","Distribution metadata available","Found /etc/os-release.","") }
}
func checkSSH(r *Report) {
	var data []byte; var path string
	for _,p:=range []string{"/etc/ssh/sshd_config","/etc/sshd/sshd_config"} { if b,e:=os.ReadFile(p); e==nil { data=b; path=p; break } }
	if path=="" { add(r,"SSH-001","INFO","SSH config not found/readable","No standard sshd_config could be read; SSH may not be installed or permissions may be restricted.","Verify effective SSH settings if SSH is used."); return }
	root,password:="",""
	s:=bufio.NewScanner(strings.NewReader(string(data)))
	for s.Scan() { line:=strings.TrimSpace(s.Text()); if line==""||strings.HasPrefix(line,"#"){continue}; f:=strings.Fields(line); if len(f)<2{continue}; switch strings.ToLower(f[0]) {case "permitrootlogin":root=strings.ToLower(f[1]); case "passwordauthentication":password=strings.ToLower(f[1])} }
	if root==""||root=="yes" { add(r,"SSH-002","MEDIUM","SSH root-login setting needs review",path+" does not explicitly disable PermitRootLogin (main file only).","Review effective sshd settings; consider PermitRootLogin no.") } else { add(r,"SSH-003","INFO","SSH root-login directive appears restricted","Main file sets PermitRootLogin "+root+"; Include files are not evaluated.","") }
	if password=="yes" { add(r,"SSH-004","MEDIUM","SSH password authentication enabled","Main config sets PasswordAuthentication yes.","Consider key-based authentication and disabling passwords where appropriate.") } else if password=="no" { add(r,"SSH-005","INFO","SSH password authentication disabled in main config","Found PasswordAuthentication no; Include files are not evaluated.","") } else { add(r,"SSH-006","LOW","SSH password setting not explicit","No active PasswordAuthentication directive found in the main file.","Check effective settings with sshd -T.") }
}
func checkFirewall(r *Report) {
	for _,spec:=range [][]string{{"ufw","status"},{"firewall-cmd","--state"},{"nft","list","ruleset"}} {
		p,e:=exec.LookPath(spec[0]); if e!=nil {continue}
		out,err:=exec.Command(p,spec[1:]...).CombinedOutput(); x:=strings.ToLower(string(out))
		if spec[0]=="ufw"&&strings.Contains(x,"status: active"){add(r,"FW-001","INFO","UFW reports active","UFW reports an active firewall.","");return}
		if spec[0]=="firewall-cmd"&&strings.Contains(x,"running"){add(r,"FW-002","INFO","firewalld reports running","firewall-cmd reports running.","");return}
		if spec[0]=="nft"&&err==nil&&strings.Contains(x,"table"){add(r,"FW-003","INFO","nftables ruleset detected","A ruleset was returned; rule quality was not assessed.","");return}
	}
	add(r,"FW-004","LOW","Firewall status not confirmed","No supported active firewall could be confirmed; this does not prove a firewall is absent.","Verify host and network firewall policies.")
}
func checkTmp(r *Report) {
	for _,p:=range []string{"/tmp","/var/tmp"} { fi,e:=os.Stat(p); if e==nil&&fi.Mode().Perm()&0002!=0&&fi.Mode()&os.ModeSticky==0 { add(r,"PERM-001","HIGH","World-writable temp directory lacks sticky bit",p+" is world-writable without sticky bit.","Review and consider mode 1777 after validating impact.") } }
}
func checkPorts(r *Report) {
	f,e:=os.Open("/proc/net/tcp"); if e!=nil {add(r,"NET-001","INFO","TCP socket check unavailable","Could not read /proc/net/tcp.","Inspect sockets with ss -lntup.");return}; defer f.Close()
	s:=bufio.NewScanner(f); if s.Scan(){}; n:=0
	for s.Scan(){ fields:=strings.Fields(s.Text()); if len(fields)>3&&fields[3]=="0A"{n++} }
	add(r,"NET-002","INFO","IPv4 TCP listeners counted",itoa(n)+" LISTEN entries found in /proc/net/tcp; IPv6 and process ownership are not included.","Review listeners with ss -lntup.")
}
func checkSUID(r *Report) {
	n:=0
	for _,root:=range []string{"/usr/bin","/usr/sbin","/bin","/sbin"} { entries,e:=os.ReadDir(root); if e!=nil{continue}; for _,entry:=range entries { info,e:=entry.Info(); if e==nil&&info.Mode()&os.ModeSetuid!=0{n++} } }
	add(r,"PERM-002","INFO","SUID inventory sampled",itoa(n)+" SUID entries in common binary directories; not a complete filesystem scan.","Review unexpected SUID files against the distribution baseline.")
}
func checkPackageSignal(r *Report) {
	for _,p:=range []string{"/var/lib/apt/lists","/var/lib/dnf"} { if _,e:=os.Stat(p);e==nil {add(r,"PKG-001","INFO","Package manager metadata detected","Package freshness and installed updates are not queried by this scanner.","Use your distribution's package manager to check security updates.");return} }
	add(r,"PKG-002","INFO","Package freshness not checked","No supported package metadata signal detected.","Check security updates with the native package manager.")
}
func itoa(n int) string { if n==0{return "0"}; var b [20]byte; i:=len(b); for n>0{i--;b[i]=byte('0'+n%10);n/=10};return string(b[i:]) }
