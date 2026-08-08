//go:build artxr0 && linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/transport/artx"
	"github.com/metacubex/mihomo/transport/vmess"
)

func main() {
	server := flag.String("server", "127.0.0.1:18081", "neutral TLS server")
	sni := flag.String("sni", "localhost", "TLS server name")
	fingerprint := flag.String("fingerprint", "chrome", "Mihomo client fingerprint")
	writes := flag.String("writes", "", "frozen comma-separated write partition")
	timeout := flag.Duration("timeout", 10*time.Second, "connection timeout")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal(errors.New("positional arguments are not accepted"))
	}
	writeSizes, err := parseWriteSizes(*writes)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp4", *server)
	if err != nil {
		fatal(err)
	}
	if err := artx.DialR0NeutralContext(ctx, raw, &vmess.TLSConfig{
		Host: *sni, SkipCertVerify: true, ClientFingerprint: *fingerprint,
	}, writeSizes); err != nil {
		fatal(err)
	}
	fmt.Printf("writes=%s total=%d status=accepted\n", *writes, sum(writeSizes))
}

func parseWriteSizes(value string) ([]int, error) {
	parts := strings.Split(value, ",")
	if value == "" || len(parts) > 2 {
		return nil, errors.New("--writes must contain one or two frozen sizes")
	}
	sizes := make([]int, len(parts))
	for index, part := range parts {
		size, err := strconv.Atoi(part)
		if err != nil || size < 1 {
			return nil, errors.New("--writes contains an invalid size")
		}
		sizes[index] = size
	}
	return sizes, nil
}

func sum(values []int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "artx-r0-neutral:", err)
	os.Exit(1)
}
