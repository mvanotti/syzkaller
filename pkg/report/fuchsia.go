// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

type fuchsia struct {
	kernelSrc string
	obj       string
	ignores   []*regexp.Regexp
}

var (
	zirconRIP          = regexp.MustCompile(` RIP: (0x[0-9a-f]+) `)
	zirconBT           = regexp.MustCompile(`^bt#[0-9]+: (0x[0-9a-f]+)`)
	zirconReportEnd    = []byte("Halted")
	zirconAssertFailed = []byte("ASSERT FAILED at")
	zirconLinePrefix   = regexp.MustCompile(`^\[\d+\.\d+\] \d+\.\d+> `)
	zirconUnrelated    = []*regexp.Regexp{
		regexp.MustCompile(`^$`),
		regexp.MustCompile(`stopping other cpus`),
		regexp.MustCompile(`^halting cpu`),
		regexp.MustCompile(`^dso: `),
		regexp.MustCompile(`^UPTIME: `),
		regexp.MustCompile(`^BUILDID `),
		regexp.MustCompile(`^Halting\.\.\.`),
	}
)

func ctorFuchsia(target *targets.Target, kernelSrc, kernelObj string,
	ignores []*regexp.Regexp) (Reporter, []string, error) {
	ctx := &fuchsia{
		ignores:   ignores,
		kernelSrc: kernelSrc,
	}
	if kernelObj != "" {
		ctx.obj = filepath.Join(kernelObj, target.KernelObject)
	}
	suppressions := []string{
		"fatal exception: process /tmp/syz-fuzzer", // OOM presumably
	}
	return ctx, suppressions, nil
}

func (ctx *fuchsia) ContainsCrash(output []byte) bool {
	return containsCrash(output, zirconOopses, ctx.ignores)
}

func (ctx *fuchsia) Parse(output []byte) *Report {
	// We symbolize here because zircon output does not contain even function names.
	symbolized := ctx.symbolize(output)
	rep := simpleLineParser(symbolized, zirconOopses, zirconStackParams, ctx.ignores)
	if rep == nil {
		return nil
	}
	rep.Output = output
	if report := ctx.shortenReport(rep.Report); len(report) != 0 {
		rep.Report = report
	}
	return rep
}

func (ctx *fuchsia) shortenReport(report []byte) []byte {
	out := new(bytes.Buffer)
	for s := bufio.NewScanner(bytes.NewReader(report)); s.Scan(); {
		line := zirconLinePrefix.ReplaceAll(s.Bytes(), nil)
		if matchesAny(line, zirconUnrelated) {
			continue
		}
		if bytes.Contains(line, zirconReportEnd) {
			break
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func tryReconstructLines(output []byte) []byte {
	out := new(bytes.Buffer)
	for s := bufio.NewScanner(bytes.NewReader(output)); s.Scan(); {
		line := s.Bytes()
		if bytes.Contains(line, zirconAssertFailed) && len(line) == 127 {
			// This is super hacky: but zircon splits the most important information in long assert lines
			// (and they are always long) into several lines in irreversible way. Try to restore full line.
			line = append([]byte{}, line...)
			if s.Scan() {
				line = append(line, s.Bytes()...)
			}
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func (ctx *fuchsia) symbolize(output []byte) []byte {
	output = tryReconstructLines(output)
	if ctx.kernelSrc == "" {
		return output
	}

	fxSymb := osutil.Command("scripts/fx", "symbolize")
	fxSymb.Stdin = bytes.NewReader(output)
	fxSymb.Dir = ctx.kernelSrc

	symbolized, err := osutil.Run(time.Minute, fxSymb)
	if err != nil {
		log.Logf(0, "fx symbolize failed: %v", err)
		// Return original un-symbolized output so people can still manually symbolize.
		return output
	}

	symbolized = []byte(strings.ReplaceAll(string(symbolized), ctx.kernelSrc, ""))
	return symbolized
}

func (ctx *fuchsia) Symbolize(rep *Report) error {
	// We symbolize in Parse because zircon stacktraces don't contain even function names.
	return nil
}

var zirconStackParams = &stackParams{
	frameRes: []*regexp.Regexp{
		compile(` RIP: 0x[0-9a-f]{8} +([a-zA-Z0-9_:~]+)`),
		compile(` RIP: \[ inline \] +([a-zA-Z0-9_:~]+)`),
		compile(`^bt#[0-9]+: 0x[0-9a-f]{8} +([a-zA-Z0-9_:~]+)`),
		compile(`^bt#[0-9]+: \[ inline \] +([a-zA-Z0-9_:~]+)`),
	},
	skipPatterns: []string{
		"^platform_halt$",
		"^exception_die$",
		"^_panic$",
	},
}

var zirconOopses = []*oops{
	{
		[]byte("ZIRCON KERNEL PANIC"),
		[]oopsFormat{
			{
				title: compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*ASSERT FAILED(?:.*\\n)+?.*bt#00:"),
				fmt:   "ASSERT FAILED in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
			{
				// Some debug asserts don't contain stack trace.
				title:        compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*ASSERT FAILED at \\(.+?\\): (.*)"),
				fmt:          "ASSERT FAILED: %[1]v",
				noStackTrace: true,
			},
			{
				title: compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*double fault, halting(?:.*\\n)+?.*bt#00:"),
				fmt:   "double fault in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
			{
				// Some double faults don't contain stack trace.
				title:        compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*double fault, halting"),
				fmt:          "double fault",
				noStackTrace: true,
			},
			{
				title: compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*Supervisor Page Fault exception, halting"),
				fmt:   "Supervisor Fault in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
			{
				title: compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*recursion in interrupt handler"),
				fmt:   "recursion in interrupt handler in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
			{
				title:        compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*KVM internal error"),
				fmt:          "KVM internal error",
				noStackTrace: true,
			},
			{
				title: compile("ZIRCON KERNEL PANIC"),
				fmt:   "KERNEL PANIC in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("recursion in interrupt handler"),
		[]oopsFormat{
			{
				title: compile("recursion in interrupt handler(?:.*\\n)+?.*(?:bt#00:|RIP:)"),
				fmt:   "recursion in interrupt handler in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
			{
				title:        compile("recursion in interrupt handler"),
				fmt:          "recursion in interrupt handler",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	// We should detect just "stopping other cpus" as some kernel crash rather then as "lost connection",
	// but if we add oops for "stopping other cpus", then it will interfere with other formats,
	// because "stopping other cpus" usually goes after "ZIRCON KERNEL PANIC", but sometimes before. Mess.
	//{
	//	[]byte("stopping other cpus"),
	//},
	{
		[]byte("welcome to Zircon"),
		[]oopsFormat{
			{
				title:        compile("welcome to Zircon"),
				fmt:          unexpectedKernelReboot,
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("KVM internal error"),
		[]oopsFormat{
			{
				title:        compile("KVM internal error"),
				fmt:          "KVM internal error",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("<== fatal exception"),
		[]oopsFormat{
			{
				title:        compile("<== fatal exception"),
				report:       compile("<== fatal exception: process ([a-zA-Z0-9_/-]+)"),
				fmt:          "fatal exception in %[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{
			compile("<== fatal exception: process .+?syz.+?\\["),
		},
	},
	{
		// Panics in Go services.
		[]byte("panic: "),
		[]oopsFormat{
			{
				title:        compile("panic: .*"),
				report:       compile("panic: (.*)(?:.*\\n)+?.* goroutine"),
				fmt:          "panic: %[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
}
