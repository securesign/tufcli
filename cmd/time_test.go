/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"testing"
	"time"
)

func TestParseRelativeTime_Positive(t *testing.T) {
	cases := []string{
		"in 7 days",
		"in 1 year",
		"in 3 months",
		"in 2 weeks",
		"in 24 hours",
	}
	for _, input := range cases {
		result, err := parseRelativeTime(input)
		if err != nil {
			t.Errorf("parseRelativeTime(%q) returned error: %v", input, err)
			continue
		}
		if result.Before(time.Now()) {
			t.Errorf("parseRelativeTime(%q) returned a past time: %v", input, result)
		}
	}
}

func TestParseRelativeTime_NegativeRejected(t *testing.T) {
	cases := []string{
		"in -7 days",
		"in -1 year",
		"in -3 months",
		"in -2 weeks",
		"in -24 hours",
		"in 0 days",
		"in -2h",
		"in 0h",
	}
	for _, input := range cases {
		_, err := parseRelativeTime(input)
		if err == nil {
			t.Errorf("parseRelativeTime(%q) should have returned an error for non-positive value", input)
		}
	}
}

func TestParseTime_RFC3339(t *testing.T) {
	input := "2030-01-01T00:00:00Z"
	result, err := parseTime(input)
	if err != nil {
		t.Fatalf("parseTime(%q) returned error: %v", input, err)
	}
	expected, _ := time.Parse(time.RFC3339, input)
	if !result.Equal(expected) {
		t.Errorf("parseTime(%q) = %v, want %v", input, result, expected)
	}
}

func TestParseTime_InvalidFormat(t *testing.T) {
	_, err := parseTime("not-a-time")
	if err == nil {
		t.Fatal("parseTime(\"not-a-time\") should have returned an error")
	}
}
