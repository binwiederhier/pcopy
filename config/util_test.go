package config

import (
	"heckel.io/pcopy/test"
	"testing"
)

func TestExpandServerAddr_ExpandAllTheThings(t *testing.T) {
	actual := ExpandServerAddr("myhost")
	expected := "https://myhost:2586"
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

func TestExpandServerAddr_Expand4431(t *testing.T) {
	test.StrEquals(t, "https://myhost:4431", ExpandServerAddr("https://myhost:4431"))
}

func TestExpandServerAddr_ExpandProto(t *testing.T) {
	actual := ExpandServerAddr("myhost:1234")
	expected := "https://myhost:1234"
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

func TestExpandServerAddr_NoExpand(t *testing.T) {
	test.StrEquals(t, "http://myhost:1234", ExpandServerAddr("http://myhost:1234"))
}

func TestCollapseServerAddr_Collapse(t *testing.T) {
	actual := CollapseServerAddr("myhost:2586")
	expected := "myhost"
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

func TestCollapseServerAddr_NoCollapse(t *testing.T) {
	test.StrEquals(t, "myhost:1234", CollapseServerAddr("myhost:1234"))
}

func TestCollapseServerAddr_FullHTTPSURL(t *testing.T) {
	test.StrEquals(t, "myhost", CollapseServerAddr("https://myhost:2586"))
}

func TestCollapseServerAddr_FullHTTPSURL443(t *testing.T) {
	test.StrEquals(t, "myhost:443", CollapseServerAddr("https://myhost"))
}
