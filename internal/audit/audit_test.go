package audit
import ("testing";"time")
func TestRunProducesReport(t *testing.T) {
	r:=Run(3*time.Second)
	if r.GeneratedAt==""||r.Hostname=="" {t.Fatal("expected timestamp and hostname")}
	if r.ChecksRun==0 {t.Fatal("expected checks")}
	if r.Findings==nil {t.Fatal("expected initialized findings")}
}
func TestAddFinding(t *testing.T) {
	r:=Report{}
	add(&r,"TEST","HIGH","Title","Detail","Fix")
	if len(r.Findings)!=1||r.Findings[0].Severity!="HIGH" {t.Fatal("finding not recorded")}
}
